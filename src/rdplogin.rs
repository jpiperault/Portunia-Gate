//! Entrée RDP sans Portunia : un client RDP ordinaire (mstsc, Windows App, Remmina) se
//! connecte à la Gate avec, comme utilisateur, « compte%serveur » (ou « compte%serveur%123456 »
//! avec le code à usage unique) et, comme mot de passe, le mot de passe RDP du compte.
//!
//! La Gate joue le serveur Windows pour l'authentification réseau (NLA, CredSSP) : NTLM, nu
//! (FreeRDP, IronRDP) ou dans SPNEGO (mstsc). NTLM exige que le vérificateur connaisse le
//! mot de passe : d'où un mot de passe RDP dédié, gardé scellé par la Gate, distinct du mot de
//! passe du compte (haché, jamais relisible). Kerberos n'est pas proposé (la Gate n'est pas
//! dans un domaine). En SPNEGO, sspi est retouché (vendor/sspi/PORTUNIA.md) pour demander
//! l'identité au moment où elle arrive.
//!
//! `%` et non `@` : mstsc prend « a@b » pour un compte de domaine. C'est aussi la convention
//! du SSH de la Gate (`julien%web-01@gate`).

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Result};
use sspi::{
    credssp::{CredSspServer, CredentialsProxy, ServerError, ServerMode, ServerState, TsRequest},
    negotiate::{set_server_identity_lookup, NegotiateConfig},
    ntlm::NtlmConfig,
    AuthIdentity, Username,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Nouveau mot de passe RDP du compte (l'ancien ne vaut plus) ; à montrer une seule fois.
pub async fn new_password(state: &crate::State, user: &crate::model::User, actor: &str) -> Result<String> {
    let password = crate::auth::rdp_password()?;
    let sealed = state.keys.seal(&format!("rdp:{}", user.id), password.as_bytes())?;
    crate::model::set_rdp_password(&state.db, user.id, Some(sealed)).await?;
    crate::audit::note(&state.db, actor, "rdp_natif.mot_de_passe", serde_json::json!({ "compte": user.login, "action": "cree" })).await;
    Ok(password)
}

pub async fn remove_password(state: &crate::State, user: &crate::model::User, actor: &str) -> Result<()> {
    crate::model::set_rdp_password(&state.db, user.id, None).await?;
    crate::audit::note(&state.db, actor, "rdp_natif.mot_de_passe", serde_json::json!({ "compte": user.login, "action": "retire" })).await;
    Ok(())
}

/// Ce que l'utilisateur a tapé dans le champ « Utilisateur » du client RDP.
#[derive(Debug, PartialEq)]
pub struct Combo {
    pub login: String,
    pub target: String,
    pub code: Option<String>,
}

/// « compte%serveur » ou « compte%serveur%code » ; un domaine éventuel (« GATE\… ») est ignoré.
pub fn parse_combo(account: &str) -> Option<Combo> {
    let account = account.rsplit('\\').next().unwrap_or(account);
    let mut parts = account.split('%').map(str::trim);
    let login = parts.next().filter(|l| !l.is_empty())?.to_string();
    let target = parts.next().filter(|t| !t.is_empty())?.to_string();
    let code = parts.next().filter(|c| !c.is_empty()).map(str::to_string);
    if parts.next().is_some() {
        return None;
    }
    Some(Combo { login, target, code })
}

/// Mot de passe attendu pour le nom donné par le client ; `None` : refus (compte inconnu,
/// code faux, serveur non autorisé…). Appelée avant la vérification du mot de passe lui-même.
pub type Lookup = Box<dyn FnMut(&str) -> Option<String> + Send>;

/// La recherche et sa dernière réponse : NTLM nu et SPNEGO peuvent poser deux fois la même
/// question, qui ne doit compter qu'une fois (limite d'essais, journal).
struct Shared {
    lookup: Lookup,
    last: Option<(String, Option<String>)>,
}

fn ask(shared: &Mutex<Shared>, account: &str) -> Option<String> {
    let mut s = shared.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((name, answer)) = &s.last {
        if name == account {
            return answer.clone();
        }
    }
    let answer = (s.lookup)(account);
    s.last = Some((account.to_string(), answer.clone()));
    answer
}

struct LoginProxy {
    shared: Arc<Mutex<Shared>>,
}

impl CredentialsProxy for LoginProxy {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: &Username) -> std::io::Result<AuthIdentity> {
        let password = ask(&self.shared, username.account_name()).ok_or_else(|| std::io::Error::other("refused"))?;
        Ok(AuthIdentity { username: username.clone(), password: password.into() })
    }

    fn auth_data(&mut self) -> std::io::Result<Vec<AuthIdentity>> {
        Ok(Vec::new())
    }
}

/// Mécanisme du client, d'après son premier message : NTLM nu, sinon SPNEGO limité à NTLM.
fn server_mode(first: &TsRequest) -> ServerMode {
    if first.nego_tokens.as_deref().is_some_and(|t| t.starts_with(b"NTLMSSP\0")) {
        ServerMode::Ntlm(NtlmConfig::default())
    } else {
        ServerMode::Negotiate(NegotiateConfig::new(Box::new(NtlmConfig::default()), Some("ntlm,!kerberos,!pku2u".into()), "PORTUNIA-GATE".into()))
    }
}

/// Serveur NLA de la Gate pour un client.
struct Server {
    inner: CredSspServer<LoginProxy>,
    shared: Arc<Mutex<Shared>>,
}

impl Server {
    fn new(key: Vec<u8>, lookup: Lookup, first: &TsRequest) -> Result<Self> {
        let shared = Arc::new(Mutex::new(Shared { lookup, last: None }));
        let inner = CredSspServer::new(key, LoginProxy { shared: shared.clone() }, server_mode(first))?;
        Ok(Self { inner, shared })
    }

    /// Une étape ; la recherche SPNEGO est branchée le temps de l'étape (sur ce fil).
    fn step(&mut self, request: TsRequest) -> Result<ServerState, ServerError> {
        let shared = self.shared.clone();
        set_server_identity_lookup(Some(Box::new(move |user: &Username| {
            ask(&shared, user.account_name()).map(|password| AuthIdentity { username: user.clone(), password: password.into() })
        })));
        let result = self.inner.process(request).resolve_to_result();
        set_server_identity_lookup(None);
        result
    }
}

/// Message CredSSP complet du client ; ce qui suit reste dans `buf`.
async fn read_der(stream: &mut (impl AsyncRead + Unpin), buf: &mut Vec<u8>) -> Result<Vec<u8>> {
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(n) = crate::rdp::der_len(buf)?.filter(|&n| buf.len() >= n) {
            return Ok(buf.drain(..n).collect());
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!(t!("the client left during authentication", "le client est parti pendant l'authentification"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Authentification NLA du client auprès de la Gate. `key` : clé publique du certificat que la
/// Gate a présenté au client. Renvoie ce que le client a envoyé après (début de la session).
pub async fn accept(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), key: Vec<u8>, lookup: Lookup) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut request = TsRequest::from_buffer(&read_der(stream, &mut buf).await?)?;
    let mut server = Server::new(key, lookup, &request)?;
    loop {
        match server.step(request) {
            Ok(ServerState::ReplyNeeded(reply)) => {
                stream.write_all(&crate::rdp::encode(&reply)?).await?;
                request = TsRequest::from_buffer(&read_der(stream, &mut buf).await?)?;
            }
            Ok(ServerState::Finished(_)) => return Ok(buf),
            Err(e) => {
                if let Some(reply) = e.ts_request {
                    let _ = stream.write_all(&crate::rdp::encode(&reply)?).await;
                }
                return Err(anyhow!(t!(format!("authentication refused: {}", e.error), format!("authentification refusée : {}", e.error))));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sspi::{
        credssp::{ClientMode, ClientState, CredSspClient, CredSspMode},
        Credentials,
    };

    #[test]
    fn identifiant_combine() {
        assert_eq!(parse_combo("julien%srv-ad-01"), Some(Combo { login: "julien".into(), target: "srv-ad-01".into(), code: None }));
        assert_eq!(parse_combo("julien%10.0.3.10%123456"), Some(Combo { login: "julien".into(), target: "10.0.3.10".into(), code: Some("123456".into()) }));
        assert_eq!(parse_combo("GATE\\julien%srv"), Some(Combo { login: "julien".into(), target: "srv".into(), code: None }));
        assert_eq!(parse_combo("julien"), None);
        assert_eq!(parse_combo("julien%"), None);
        assert_eq!(parse_combo("%srv"), None);
        assert_eq!(parse_combo("a%b%c%d"), None);
    }

    /// Client NLA en mémoire (NTLM nu, ou SPNEGO comme mstsc) face à la Gate. Renvoie le nom
    /// accepté et le nombre de recherches faites (une par essai).
    fn nla(user: &str, password: &str, spnego: bool) -> (Option<String>, usize) {
        let key = vec![7u8; 270];
        let identity = AuthIdentity { username: Username::parse(user).unwrap(), password: password.to_string().into() };
        let mode = if spnego {
            ClientMode::Negotiate(NegotiateConfig::new(Box::new(NtlmConfig::default()), Some("ntlm,!kerberos,!pku2u".into()), "POSTE".into()))
        } else {
            ClientMode::Ntlm(NtlmConfig::default())
        };
        let mut client = CredSspClient::new(key.clone(), Credentials::AuthIdentity(identity), CredSspMode::WithCredentials, mode, "TERMSRV/gate".into()).unwrap();
        let asked = Arc::new(Mutex::new(0usize));
        let mut server: Option<Server> = None;
        let mut request = TsRequest::default();
        let mut seen = None;
        for _ in 0..8 {
            let to_server = match client.process(request).resolve_to_result() {
                Ok(ClientState::ReplyNeeded(r)) | Ok(ClientState::FinalMessage(r)) => r,
                Err(_) => break,
            };
            let to_server = TsRequest::from_buffer(&crate::rdp::encode(&to_server).unwrap()).unwrap();
            let s = server.get_or_insert_with(|| {
                let asked = asked.clone();
                let lookup: Lookup = Box::new(move |account: &str| {
                    *asked.lock().unwrap() += 1;
                    let c = parse_combo(account)?;
                    (c.login == "julien" && c.target == "srv").then(|| "Rdp-Mot-de-passe-1".to_string())
                });
                Server::new(key.clone(), lookup, &to_server).unwrap()
            });
            match s.step(to_server) {
                Ok(ServerState::ReplyNeeded(r)) => request = TsRequest::from_buffer(&crate::rdp::encode(&r).unwrap()).unwrap(),
                Ok(ServerState::Finished(id)) => {
                    seen = Some(id.username.account_name().to_string());
                    break;
                }
                Err(_) => break,
            }
        }
        let n = *asked.lock().unwrap();
        (seen, n)
    }

    #[test]
    fn nla_ntlm_et_spnego() {
        for spnego in [false, true] {
            assert_eq!(nla("julien%srv", "Rdp-Mot-de-passe-1", spnego), (Some("julien%srv".into()), 1), "spnego {spnego}");
            assert_eq!(nla("julien%srv", "mauvais", spnego).0, None, "spnego {spnego}");
            assert_eq!(nla("julien%autre", "Rdp-Mot-de-passe-1", spnego).0, None, "spnego {spnego}");
            // Domaine donné par le client (« GATE\… ») : accepté aussi.
            assert_eq!(nla("GATE\\julien%srv", "Rdp-Mot-de-passe-1", spnego).0.as_deref(), Some("julien%srv"), "spnego {spnego}");
        }
    }
}
