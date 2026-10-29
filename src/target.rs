//! Connexion du bastion vers une cible, avec la clé du serveur mémorisée à la première
//! connexion puis exigée ensuite.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use russh::{
    client,
    keys::{decode_secret_key, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate},
};
use serde_json::json;

use crate::{
    model::{self, Target},
    State,
};

pub enum Credentials {
    Password { user: String, password: String },
    Key { user: String, key: Box<PrivateKey> },
}

impl Credentials {
    pub fn user(&self) -> &str {
        match self {
            Credentials::Password { user, .. } | Credentials::Key { user, .. } => user,
        }
    }
}

/// Identifiants du coffre pour une cible en mode coffre.
pub fn vault_credentials(state: &State, target: &Target) -> Result<Credentials> {
    let user = target
        .account
        .clone()
        .ok_or_else(|| anyhow!("compte du coffre manquant pour {}", target.name))?;
    let sealed = target
        .secret
        .as_deref()
        .ok_or_else(|| anyhow!("secret du coffre manquant pour {}", target.name))?;
    let plain = state.keys.open(&target.secret_purpose(), sealed)?;
    let text = String::from_utf8(plain).map_err(|_| anyhow!("secret du coffre illisible"))?;
    Ok(match target.secret_kind.as_str() {
        "key" => Credentials::Key {
            user,
            key: Box::new(decode_secret_key(&text, None).map_err(|e| anyhow!("clé du coffre illisible : {e}"))?),
        },
        _ => Credentials::Password { user, password: text },
    })
}

pub enum ConnectError {
    /// Identifiants refusés par la cible : on peut redemander.
    Refused,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for ConnectError {
    fn from(e: anyhow::Error) -> Self {
        ConnectError::Other(e)
    }
}

impl From<russh::Error> for ConnectError {
    fn from(e: russh::Error) -> Self {
        ConnectError::Other(e.into())
    }
}

pub struct Client {
    pinned: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let public = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => PublicKey::new(cert.public_key().clone(), ""),
        };
        let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
        *self.seen.lock().unwrap() = Some(fingerprint.clone());
        Ok(self.pinned.as_deref().is_none_or(|p| p == fingerprint))
    }
}

pub type Handle = client::Handle<Client>;

pub async fn connect(state: &State, target: &Target, creds: &Credentials, actor: &str) -> Result<Handle, ConnectError> {
    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        ..Default::default()
    });
    let seen = Arc::new(Mutex::new(None));
    let client = Client {
        pinned: target.host_key.clone(),
        seen: seen.clone(),
    };
    let address = (target.host.as_str(), target.port as u16);
    let connected = tokio::time::timeout(std::time::Duration::from_secs(15), client::connect(config, address, client)).await;
    let seen = seen.lock().unwrap().clone();
    let mut handle = match connected {
        Err(_) => return Err(anyhow!("{} ne répond pas ({}:{})", target.name, target.host, target.port).into()),
        Ok(Err(e)) => {
            if let (Some(pinned), Some(seen)) = (&target.host_key, &seen) {
                if pinned != seen {
                    crate::audit::note(
                        &state.db,
                        actor,
                        "cible.empreinte_differente",
                        json!({ "cible": target.name, "attendue": pinned, "recue": seen }),
                    )
                    .await;
                    return Err(anyhow!(
                        "La clé du serveur {} a changé : connexion refusée. Un administrateur doit vérifier puis réinitialiser son empreinte.",
                        target.name
                    )
                    .into());
                }
            }
            return Err(anyhow!("connexion à {} impossible : {e}", target.name).into());
        }
        Ok(Ok(handle)) => handle,
    };
    if target.host_key.is_none() {
        if let Some(fp) = &seen {
            if model::pin_host_key(&state.db, target.id, fp).await? {
                crate::audit::note(
                    &state.db,
                    actor,
                    "cible.empreinte_memorisee",
                    json!({ "cible": target.name, "empreinte": fp }),
                )
                .await;
            }
        }
    }
    let ok = match creds {
        Credentials::Password { user, password } => handle.authenticate_password(user, password).await?.success(),
        Credentials::Key { user, key } => {
            let hash = handle.best_supported_rsa_hash().await?.flatten();
            handle
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new((**key).clone()), hash))
                .await?
                .success()
        }
    };
    if !ok {
        let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
        return Err(ConnectError::Refused);
    }
    Ok(handle)
}
