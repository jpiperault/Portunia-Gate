//! Connexion de la Gate vers une cible, avec la clé du serveur mémorisée à la première
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
        .ok_or_else(|| anyhow!(t!(format!("vault account missing for {}", target.name), format!("compte du coffre manquant pour {}", target.name))))?;
    let sealed = target
        .secret
        .as_deref()
        .ok_or_else(|| anyhow!(t!(format!("vault secret missing for {}", target.name), format!("secret du coffre manquant pour {}", target.name))))?;
    let plain = state.keys.open(&target.secret_purpose(), sealed)?;
    let text = String::from_utf8(plain).map_err(|_| anyhow!(t!("unreadable vault secret", "secret du coffre illisible")))?;
    Ok(match target.secret_kind.as_str() {
        "key" => Credentials::Key {
            user,
            key: Box::new(decode_secret_key(&text, None).map_err(|e| anyhow!(t!(format!("unreadable vault key: {e}"), format!("clé du coffre illisible : {e}"))))?),
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

/// Adresses de métadonnées des hébergeurs (AWS, Azure, GCP, Alibaba) : elles donnent les identifiants
/// de la machine. Une cible ne doit jamais y mener, même par un nom qui s'y résout.
fn metadata_address(ip: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match ip.to_canonical() {
        IpAddr::V4(v) => v == Ipv4Addr::new(169, 254, 169, 254) || v == Ipv4Addr::new(100, 100, 100, 200),
        IpAddr::V6(v) => v == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254),
    }
}

/// Adresses d'une cible, résolues une fois : la connexion se fait vers ce qui a été vérifié.
pub async fn addresses(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>> {
    let found: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| anyhow!("{}", t!(format!("{host}: name not found ({e})"), format!("{host} : nom introuvable ({e})"))))?
        .collect();
    if found.iter().any(|a| metadata_address(a.ip())) {
        anyhow::bail!("{}", t!(format!("{host}: cloud metadata address, refused"), format!("{host} : adresse de métadonnées de l'hébergeur, refusée")));
    }
    Ok(found)
}

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
    let address = addresses(&target.host, target.port as u16).await?;
    let connected = tokio::time::timeout(std::time::Duration::from_secs(15), client::connect(config, &address[..], client)).await;
    let seen = seen.lock().unwrap().clone();
    let mut handle = match connected {
        Err(_) => return Err(anyhow!(t!(format!("{} is not answering ({}:{})", target.name, target.host, target.port), format!("{} ne répond pas ({}:{})", target.name, target.host, target.port))).into()),
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
                    let name = &target.name;
                    return Err(anyhow!(t!(
                        format!("The key of server {name} has changed: connection refused. An administrator must check it then reset its fingerprint."),
                        format!("La clé du serveur {name} a changé : connexion refusée. Un administrateur doit vérifier puis réinitialiser son empreinte.")
                    ))
                    .into());
                }
            }
            return Err(anyhow!(t!(format!("cannot connect to {}: {e}", target.name), format!("connexion à {} impossible : {e}", target.name))).into());
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

/// Crée une clé ed25519 pour le compte du serveur, l'installe avec le mot de passe donné
/// une seule fois, puis vérifie qu'elle fonctionne. Renvoie la clé privée (texte OpenSSH).
pub async fn install_new_key(state: &State, target: &Target, account: &str, password: &str, actor: &str) -> Result<String> {
    use russh::keys::ssh_key::{private::Ed25519Keypair, LineEnding};
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&crate::keys::random::<32>()?));
    let public = key.public_key().to_openssh().map_err(|e| anyhow!("clé publique : {e}"))?;
    let line = format!(
        "{public} portunia-gate-{}",
        target.name.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "_")
    );
    let creds = Credentials::Password {
        user: account.to_string(),
        password: password.to_string(),
    };
    let handle = match connect(state, target, &creds, actor).await {
        Ok(h) => h,
        Err(ConnectError::Refused) => return Err(anyhow!(t!(format!("Password refused by {} for account {account}", target.name), format!("Mot de passe refusé par {} pour le compte {account}", target.name)))),
        Err(ConnectError::Other(e)) => return Err(e),
    };
    let mut channel = handle.channel_open_session().await?;
    let command = format!("umask 077; mkdir -p ~/.ssh && printf '%s\n' '{line}' >> ~/.ssh/authorized_keys");
    channel.exec(true, command.as_bytes()).await?;
    let mut status = None;
    while let Some(msg) = channel.wait().await {
        if let russh::ChannelMsg::ExitStatus { exit_status } = msg {
            status = Some(exit_status);
        }
    }
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
    if status != Some(0) {
        return Err(anyhow!(t!(format!("Cannot install the key on {} (code {status:?})", target.name), format!("Installation de la clé impossible sur {} (code {status:?})", target.name))));
    }
    let check = Credentials::Key {
        user: account.to_string(),
        key: Box::new(key.clone()),
    };
    match connect(state, target, &check, actor).await {
        Ok(h) => {
            let _ = h.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
        }
        Err(_) => {
            return Err(anyhow!(t!(
                format!("The key was added but {} refuses it (key authentication disabled?)", target.name),
                format!("La clé a été ajoutée mais {} la refuse (authentification par clé désactivée ?)", target.name)
            )))
        }
    }
    Ok(key.to_openssh(LineEnding::LF).map_err(|e| anyhow!("clé : {e}"))?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn metadonnees_refusees() {
        assert!(addresses("169.254.169.254", 80).await.is_err());
        assert!(addresses("::ffff:169.254.169.254", 80).await.is_err());
        assert!(addresses("127.0.0.1", 22).await.is_ok());
    }
}
