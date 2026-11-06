//! Passage Bureau à distance (RDCleanPath) pour les serveurs RDP en mode enregistré.
//!
//! Le client (navigateur du portail web, ou Portunia) ouvre une WebSocket et envoie une
//! demande RDCleanPath : son jeton à usage unique et le début de la connexion RDP (X.224).
//! La Gate vérifie le jeton et la règle, se connecte au serveur Windows, mène la
//! négociation chiffrée (TLS) avec lui en vérifiant son certificat (empreinte gardée à la
//! première connexion), puis renvoie ce certificat au client : l'authentification Windows
//! (NLA) se fait entre le client et le serveur, la Gate ne voit pas le mot de passe.
//! Ensuite il relaie la session dans les deux sens et l'enregistre.
//!
//! Mode coffre : la Gate mène elle-même l'authentification NLA (CredSSP, NTLM) avec le
//! serveur, avec le compte du coffre ; le client, lui, s'authentifie auprès de la Gate avec
//! son jeton à usage unique comme mot de passe. Le mot de passe Windows ne quitte jamais la
//! Gate. Le client voit le même certificat que le serveur présente (empreinte inchangée).
//!
//! Enregistrement : `<session>.rdpcap` dans le dossier des enregistrements, signé à la fin
//! comme les sessions SSH ; voir `rdpcap` pour ce qui est gardé.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::ws::{Message, WebSocket};
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use ironrdp_rdcleanpath::{DetectionResult, RDCleanPath, RDCleanPathPdu};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde_json::json;
use sspi::{
    credssp::{ClientMode, ClientState, CredSspClient, CredSspMode, CredSspServer, CredentialsProxy, ServerMode, ServerState, TsRequest},
    ntlm::NtlmConfig,
    AuthIdentity, Credentials, Username,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{audit, keys::sha256_hex, model, State};

/// D'où vient la demande : le portail web (sessions fermées avec le portail) ou Portunia.
pub enum Origin {
    /// Portail : la session web fixe la durée, et le jeton doit être celui de son compte.
    Portal { addr: String, user: Uuid, expires: DateTime<Utc>, idle: Duration },
    Portunia { addr: String },
    /// Entrée RDP native (mstsc, Remmina…) : voir `rdpnative`.
    Native,
}

/// Erreur renvoyée au client dans le protocole RDCleanPath, puis fermeture.
async fn refuse(socket: &mut WebSocket, pdu: RDCleanPathPdu) {
    if let Ok(der) = pdu.to_der() {
        let _ = socket.send(Message::Binary(der.into())).await;
    }
    let _ = socket.send(Message::Close(None)).await;
}

/// Accepte tout certificat pendant la négociation (le serveur Windows en a souvent un
/// auto-signé) ; la chaîne est contrôlée juste après par son empreinte.
#[derive(Debug)]
pub struct Capture(pub Arc<CryptoProvider>);

impl ServerCertVerifier for Capture {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Empreinte du certificat du serveur, au format des clés SSH gardées pour les cibles.
pub(crate) fn cert_fingerprint(der: &[u8]) -> String {
    let hex = sha256_hex(der).to_uppercase();
    let pairs: Vec<&str> = (0..hex.len()).step_by(2).map(|i| &hex[i..i + 2]).collect();
    format!("TLS:{}", pairs.join(":"))
}

/// Lit la demande RDCleanPath (elle peut arriver en plusieurs messages).
async fn read_request(socket: &mut WebSocket) -> Result<RDCleanPathPdu> {
    let mut buf = Vec::new();
    loop {
        match RDCleanPathPdu::detect(&buf) {
            DetectionResult::Detected { total_length, .. } if buf.len() >= total_length => {
                return Ok(RDCleanPathPdu::from_der(&buf[..total_length])?);
            }
            DetectionResult::Failed => bail!("demande RDCleanPath illisible"),
            _ => {}
        }
        if buf.len() > 64 * 1024 {
            bail!(t!("RDCleanPath request too long", "demande RDCleanPath trop longue"));
        }
        match tokio::time::timeout(Duration::from_secs(15), socket.recv()).await {
            Ok(Some(Ok(Message::Binary(b)))) => buf.extend_from_slice(&b),
            Ok(Some(Ok(_))) => {}
            _ => bail!(t!("no RDCleanPath request", "pas de demande RDCleanPath")),
        }
    }
}

/// Un paquet TPKT (4 octets d'en-tête, longueur sur 2 octets) : réponse X.224 du serveur,
/// demande X.224 ou première trame d'un poste natif. `max` : longueur acceptée.
pub(crate) async fn read_tpkt(tcp: &mut (impl AsyncRead + Unpin), max: usize) -> Result<Vec<u8>> {
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await?;
    if head[0] != 3 {
        bail!(t!("unexpected answer (not RDP)", "réponse inattendue (pas de RDP)"));
    }
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    if !(4..=max).contains(&len) {
        bail!(t!("TPKT packet with invalid length", "paquet TPKT de longueur invalide"));
    }
    let mut pdu = head.to_vec();
    pdu.resize(len, 0);
    tcp.read_exact(&mut pdu[4..]).await?;
    Ok(pdu)
}

// ---------- Coffre : authentification NLA menée par la Gate ----------

/// Protocoles de sécurité de la négociation X.224 : TLS, NLA et NLA étendu.
pub(crate) const SSL: u32 = 0x1;
pub(crate) const HYBRID: u32 = 0x2;
pub(crate) const HYBRID_EX: u32 = 0x8;

/// Protocole choisi par le serveur : TPKT (4 octets), X.224 CC (7), puis RDP_NEG_RSP (8).
pub(crate) fn selected_protocol(x224: &[u8]) -> Option<u32> {
    (x224.len() >= 19 && x224[11] == 0x02).then(|| u32::from_le_bytes([x224[15], x224[16], x224[17], x224[18]]))
}

/// Clé publique du certificat du serveur, liée à l'authentification CredSSP.
pub(crate) fn public_key(der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| anyhow!("certificat du serveur illisible : {e}"))?;
    Ok(cert.public_key().subject_public_key.data.to_vec())
}

/// Longueur totale d'un message DER (CredSSP), si son en-tête est complet.
pub(crate) fn der_len(buf: &[u8]) -> Result<Option<usize>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    if buf[0] != 0x30 {
        bail!(t!("CredSSP message expected", "message CredSSP attendu"));
    }
    if buf[1] & 0x80 == 0 {
        return Ok(Some(2 + buf[1] as usize));
    }
    let n = (buf[1] & 0x7f) as usize;
    if n == 0 || n > 3 {
        bail!(t!("CredSSP message with invalid length", "message CredSSP de longueur invalide"));
    }
    if buf.len() < 2 + n {
        return Ok(None);
    }
    let len = buf[2..2 + n].iter().fold(0usize, |a, &b| a << 8 | b as usize);
    if len > 64 * 1024 {
        bail!(t!("CredSSP message too long", "message CredSSP trop long"));
    }
    Ok(Some(2 + n + len))
}

/// Message CredSSP complet venu du serveur ; ce qui suit reste dans `buf`.
async fn server_der(tls: &mut (impl AsyncRead + Unpin), buf: &mut Vec<u8>) -> Result<Vec<u8>> {
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(n) = der_len(buf)?.filter(|&n| buf.len() >= n) {
            return Ok(buf.drain(..n).collect());
        }
        let n = tokio::time::timeout(Duration::from_secs(15), tls.read(&mut chunk)).await.map_err(|_| anyhow!(t!("the server no longer answers", "le serveur ne répond plus")))??;
        if n == 0 {
            bail!(t!("the server closed the connection during authentication", "le serveur a fermé la connexion pendant l'authentification"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Message CredSSP complet venu du client par la WebSocket ; ce qui suit reste dans `buf`.
async fn client_der(socket: &mut WebSocket, buf: &mut Vec<u8>) -> Result<Vec<u8>> {
    loop {
        if let Some(n) = der_len(buf)?.filter(|&n| buf.len() >= n) {
            return Ok(buf.drain(..n).collect());
        }
        match tokio::time::timeout(Duration::from_secs(30), socket.recv()).await {
            Ok(Some(Ok(Message::Binary(b)))) => buf.extend_from_slice(&b),
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => bail!(t!("the client left during authentication", "le client est parti pendant l'authentification")),
            Ok(Some(Ok(_))) => {}
            Err(_) => bail!(t!("the client no longer answers", "le client ne répond plus")),
        }
    }
}

pub(crate) fn encode(request: &TsRequest) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(usize::from(request.buffer_len()?));
    request.encode_ts_request(&mut out)?;
    Ok(out)
}

/// Authentification NLA auprès du serveur avec le compte du coffre (`DOMAINE\compte` ou
/// `compte@domaine`). Erreur : identifiants refusés, ou serveur muet.
async fn vault_login(tls: &mut (impl AsyncRead + tokio::io::AsyncWrite + Unpin), account: &str, password: String, host: &str, server_key: Vec<u8>, early: bool) -> Result<()> {
    let username = Username::parse(account).map_err(|e| anyhow!(t!(format!("vault account « {account} »: {e}"), format!("compte du coffre « {account} » : {e}"))))?;
    let identity = AuthIdentity { username, password: password.into() };
    let mut client = CredSspClient::new(server_key, Credentials::AuthIdentity(identity), CredSspMode::WithCredentials, ClientMode::Ntlm(NtlmConfig::default()), format!("TERMSRV/{host}"))?;
    let mut request = TsRequest::default();
    let mut buf = Vec::new();
    loop {
        let state = client.process(request).resolve_to_result().map_err(|e| anyhow!(t!(format!("the server refused the vault account: {e}"), format!("le serveur a refusé le compte du coffre : {e}"))))?;
        match state {
            ClientState::ReplyNeeded(next) => {
                tls.write_all(&encode(&next)?).await?;
                request = TsRequest::from_buffer(&server_der(tls, &mut buf).await?)?;
            }
            ClientState::FinalMessage(last) => {
                tls.write_all(&encode(&last)?).await?;
                break;
            }
        }
    }
    // NLA étendu : le serveur confirme l'autorisation en 4 octets (0 : accordée).
    if early {
        while buf.len() < 4 {
            let mut chunk = [0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(15), tls.read(&mut chunk)).await.map_err(|_| anyhow!(t!("the server no longer answers", "le serveur ne répond plus")))??;
            if n == 0 {
                bail!(t!("the server refused the vault account", "le serveur a refusé le compte du coffre"));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        if buf[..4] != [0, 0, 0, 0] {
            bail!(t!("the Windows server denies access to the vault account", "le serveur Windows refuse l'accès au compte du coffre"));
        }
        buf.drain(..4);
    }
    if !buf.is_empty() {
        bail!(t!("unexpected data from the server after authentication", "données inattendues du serveur après l'authentification"));
    }
    Ok(())
}

/// Le jeton à usage unique sert de mot de passe au client, quel que soit le nom donné.
struct TokenProxy {
    token: String,
}

impl CredentialsProxy for TokenProxy {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: &Username) -> std::io::Result<AuthIdentity> {
        Ok(AuthIdentity { username: username.clone(), password: self.token.clone().into() })
    }

    fn auth_data(&mut self) -> std::io::Result<Vec<AuthIdentity>> {
        let username = Username::new("portunia", None).map_err(std::io::Error::other)?;
        Ok(vec![AuthIdentity { username, password: self.token.clone().into() }])
    }
}

/// Authentification NLA du client auprès de la Gate (mot de passe : son jeton). Renvoie ce
/// que le client a déjà envoyé après (début de la session).
async fn token_login(socket: &mut WebSocket, token: &str, server_key: Vec<u8>, early: bool) -> Result<Vec<u8>> {
    let proxy = TokenProxy { token: token.to_string() };
    let mut server = CredSspServer::new(server_key, proxy, ServerMode::Ntlm(NtlmConfig::default()))?;
    let mut buf = Vec::new();
    loop {
        let request = TsRequest::from_buffer(&client_der(socket, &mut buf).await?)?;
        match server.process(request).resolve_to_result() {
            Ok(ServerState::ReplyNeeded(reply)) => socket.send(Message::Binary(encode(&reply)?.into())).await?,
            Ok(ServerState::Finished(_)) => break,
            Err(e) => {
                if let Some(reply) = e.ts_request {
                    let _ = socket.send(Message::Binary(encode(&reply)?.into())).await;
                }
                let _ = socket.send(Message::Close(None)).await;
                bail!(t!(format!("client authentication refused: {}", e.error), format!("authentification du client refusée : {}", e.error)));
            }
        }
    }
    if early {
        socket.send(Message::Binary(vec![0u8, 0, 0, 0].into())).await?;
    }
    Ok(buf)
}

/// Passage complet : demande, contrôles, connexion au serveur, relais enregistré.
pub async fn relay(state: Arc<State>, mut socket: WebSocket, origin: Origin) {
    let web = matches!(origin, Origin::Portal { .. });
    if web {
        state.web.active_inc();
    }
    if let Err(e) = run(&state, &mut socket, origin).await {
        tracing::warn!("{} {e:#}", t!("remote desktop:", "bureau à distance :"));
    }
    if web {
        state.web.active_dec();
    }
}

/// Pourquoi une connexion est refusée : dit au client RDCleanPath ; l'entrée native, elle,
/// ferme simplement la connexion (un client RDP n'affiche qu'une erreur générique).
pub(crate) enum Refusal {
    Http(u16),
    Wsa(u16),
    Tls(u8),
    General,
}

impl Refusal {
    fn pdu(&self) -> RDCleanPathPdu {
        match self {
            Refusal::Http(code) => RDCleanPathPdu::new_http_error(*code),
            Refusal::Wsa(code) => RDCleanPathPdu::new_wsa_error(*code),
            Refusal::Tls(code) => RDCleanPathPdu::new_tls_error(*code),
            Refusal::General => RDCleanPathPdu::new_general_error(),
        }
    }
}

pub(crate) type Refused = (Refusal, anyhow::Error);

fn general(e: anyhow::Error) -> Refused {
    (Refusal::General, e)
}

/// Connexion autorisée : qui, vers quel serveur, avec quels droits, depuis quelle adresse.
pub(crate) struct Allowed {
    pub user: model::User,
    pub target: model::Target,
    pub access: model::Access,
    pub addr: String,
}

/// Jeton à usage unique, compte, serveur et règle. `portal_user` : compte de la session web
/// (le jeton doit être le sien) ; `mode_ok` : modes que cette entrée accepte.
pub(crate) async fn authorize(db: &sqlx::PgPool, token: &str, addr: String, portal_user: Option<Uuid>, mode_ok: impl Fn(&model::Target) -> bool) -> Result<Allowed, Refused> {
    // Le jeton dit qui et vers quel serveur.
    let Some((user_id, target_id, real_addr)) = crate::api::take_ticket(db, token).await.map_err(general)? else {
        return Err((Refusal::Http(401), anyhow!(t!("invalid, expired or already used token", "jeton invalide, expiré ou déjà utilisé"))));
    };
    let addr = real_addr.unwrap_or(addr);
    let user = model::user_by_id(db, user_id).await.map_err(general)?.filter(|u| !u.disabled);
    let target = model::target_by_id(db, target_id).await.map_err(general)?;
    let (Some(user), Some(target)) = (user, target) else {
        return Err((Refusal::Http(403), anyhow!(t!("account or server deleted", "compte ou serveur supprimé"))));
    };
    if portal_user.is_some_and(|web_user| web_user != user.id) {
        audit::note(db, &user.login, "acces.refuse", json!({ "cible": target.name, "type": "rdp", "raison": "jeton d'un autre compte", "adresse": addr })).await;
        return Err((Refusal::Http(403), anyhow!(t!("token of another account", "jeton d'un autre compte"))));
    }
    let access = model::access(db, user.id, target.id).await.map_err(general)?;
    let Some(access) = access.filter(|_| target.is_rdp() && mode_ok(&target)) else {
        audit::note(db, &user.login, "acces.refuse", json!({ "cible": target.name, "type": "rdp", "adresse": addr })).await;
        return Err((Refusal::Http(403), anyhow!(t!(format!("{}: access denied", target.name), format!("{} : accès refusé", target.name)))));
    };
    Ok(Allowed { user, target, access, addr })
}

/// Pas d'enregistrement possible (disque plein) : pas de session, sauf en rebond.
pub(crate) async fn check_space(state: &State, a: &Allowed) -> Result<(), Refused> {
    if a.target.mode != "rebond" && !crate::live::can_record(state) {
        audit::note(&state.db, &a.user.login, "enregistrement.echec", json!({ "cible": a.target.name, "raison": "espace disque insuffisant", "adresse": a.addr })).await;
        return Err(general(anyhow!("{}", crate::live::no_space_message())));
    }
    Ok(())
}

/// Serveur Windows joint : négociation X.224 faite, TLS établi, certificat vérifié.
pub(crate) struct Opened {
    pub tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    /// Réponse X.224 du serveur (protocole choisi).
    pub x224: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    pub server: String,
}

impl Opened {
    /// Protocole de sécurité choisi par le serveur (0 : RDP ancien, 1 : TLS, 2 et 8 : NLA).
    pub fn protocol(&self) -> u32 {
        selected_protocol(&self.x224).unwrap_or(0)
    }

    pub fn nla(&self) -> bool {
        self.protocol() & (HYBRID | HYBRID_EX) != 0
    }
}

/// Connexion au serveur Windows avec cette demande X.224, négociation chiffrée, certificat
/// vérifié par son empreinte (gardée à la première connexion).
pub(crate) async fn open_server(db: &sqlx::PgPool, a: &Allowed, x224_request: &[u8]) -> Result<Opened, Refused> {
    let target = &a.target;
    let server = format!("{}:{}", target.host, target.port);
    let address = crate::target::addresses(&target.host, target.port as u16).await.map_err(|e| (Refusal::Wsa(10061), e))?;
    let mut tcp = match tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(&address[..])).await {
        Ok(Ok(t)) => t,
        _ => return Err((Refusal::Wsa(10061), anyhow!("{server} injoignable"))),
    };
    let _ = tcp.set_nodelay(true);
    tcp.write_all(x224_request).await.map_err(|e| general(e.into()))?;
    let x224 = read_tpkt(&mut tcp, 4096).await.context(t!("X.224 negotiation", "négociation X.224")).map_err(general)?;
    // Négociation refusée (RDP_NEG_FAILURE) : le serveur dit pourquoi.
    if x224.len() >= 19 && x224[11] == 0x03 {
        let why = match u32::from_le_bytes([x224[15], x224[16], x224[17], x224[18]]) {
            5 => t!("the server requires NLA", "le serveur exige NLA").to_string(),
            1 | 6 => t!("the server requires TLS", "le serveur exige TLS").to_string(),
            2 | 3 => t!("the server does not accept TLS", "le serveur n'accepte pas TLS").to_string(),
            code => t!(format!("negotiation refused (code {code})"), format!("négociation refusée (code {code})")).to_string(),
        };
        return Err(general(anyhow!("{} : {why}", target.name)));
    }

    // Négociation chiffrée avec le serveur, certificat vérifié par son empreinte.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| general(e.into()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Capture(provider)))
        .with_no_client_auth();
    let name = ServerName::try_from(target.host.clone()).map_err(|_| general(anyhow!(t!("invalid server address", "adresse du serveur invalide"))))?;
    let tls = match tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await {
        Ok(t) => t,
        Err(e) => return Err((Refusal::Tls(40), anyhow!(t!(format!("TLS negotiation with {server}: {e}"), format!("négociation TLS avec {server} : {e}"))))),
    };
    let chain: Vec<Vec<u8>> = tls.get_ref().1.peer_certificates().unwrap_or_default().iter().map(|c| c.to_vec()).collect();
    let Some(leaf) = chain.first() else {
        return Err(general(anyhow!(t!(format!("{server} presented no certificate"), format!("{server} n'a pas présenté de certificat")))));
    };
    let fingerprint = cert_fingerprint(leaf);
    match &target.host_key {
        None => {
            if model::pin_host_key(db, target.id, &fingerprint).await.map_err(general)? {
                audit::note(db, &a.user.login, "cible.empreinte_memorisee", json!({ "cible": target.name, "empreinte": fingerprint })).await;
            }
        }
        Some(known) if *known != fingerprint => {
            audit::note(db, &a.user.login, "cible.empreinte_differente", json!({ "cible": target.name, "attendue": known, "recue": fingerprint })).await;
            return Err(general(anyhow!(t!(
                format!("{}: the server's certificate has changed (expected {known}, received {fingerprint})", target.name),
                format!("{} : le certificat du serveur a changé (attendu {known}, reçu {fingerprint})", target.name)
            ))));
        }
        _ => {}
    }
    Ok(Opened { tls, x224, chain, server })
}

/// La Gate ouvre la session Windows (NLA) avec ce compte : celui du coffre, ou celui que
/// l'utilisateur a donné pour l'entrée native. Renvoie la clé publique du serveur.
pub(crate) async fn gate_login(db: &sqlx::PgPool, a: &Allowed, o: &mut Opened, account: &str, password: String) -> Result<Vec<u8>, Refused> {
    let target = &a.target;
    let event = if target.vaulted() { "cible.coffre_refuse" } else { "cible.identifiants_refuses" };
    if !o.nla() {
        audit::note(db, &a.user.login, event, json!({ "cible": target.name, "raison": "serveur sans NLA" })).await;
        return Err(general(anyhow!(t!(
            format!("{}: the server does not offer NLA, the Gate cannot sign in", target.name),
            format!("{} : le serveur ne propose pas NLA, la Gate ne peut pas ouvrir la session", target.name)
        ))));
    }
    let early = o.protocol() & HYBRID_EX != 0;
    let key = public_key(&o.chain[0]).map_err(general)?;
    if let Err(e) = vault_login(&mut o.tls, account, password, &target.host, key.clone(), early).await {
        audit::note(db, &a.user.login, event, json!({ "cible": target.name, "raison": e.to_string() })).await;
        return Err(general(anyhow!("{} : {e:#}", target.name)));
    }
    Ok(key)
}

/// Compte du coffre (mot de passe) de ce serveur, pour `gate_login`.
pub(crate) async fn vault_account(state: &State, a: &Allowed) -> Result<(String, String), Refused> {
    match crate::target::vault_credentials(state, &a.target) {
        Ok(crate::target::Credentials::Password { user, password }) => Ok((user, password)),
        other => {
            let e = match other {
                Err(e) => e,
                _ => anyhow!(t!("Remote Desktop: the vault keeps a password, not an SSH key", "Bureau à distance : le coffre garde un mot de passe, pas une clé SSH")),
            };
            audit::note(&state.db, &a.user.login, "cible.coffre_refuse", json!({ "cible": a.target.name, "raison": e.to_string() })).await;
            Err(general(anyhow!("{} : {e:#}", a.target.name)))
        }
    }
}

/// Enregistrement de la session (aucun en rebond).
pub(crate) async fn start_recording(state: &State, id: Uuid, a: &Allowed) -> Result<Option<crate::rdpcap::Tape>, Refused> {
    if a.target.mode == "rebond" {
        return Ok(None);
    }
    // Copie de fichiers : gardée si la règle l'autorise et si le réglage le demande.
    let keep_files = if a.access.files { file_copies_limit(state).await.map_err(general)? } else { 0 };
    let title = format!("{} → {}", a.user.login, a.target.name);
    match crate::rdpcap::Recorder::create(&state.config.recordings_dir(), id, &title, a.access.record_input, keep_files).and_then(crate::rdpcap::Recorder::spawn) {
        Ok(c) => Ok(Some(c)),
        Err(e) => {
            audit::note(&state.db, &a.user.login, "enregistrement.echec", json!({ "cible": a.target.name, "raison": e.to_string(), "adresse": a.addr })).await;
            Err(general(anyhow!("{} {id}: {e:#}", t!("RDP recording", "enregistrement RDP"))))
        }
    }
}

async fn run(state: &Arc<State>, socket: &mut WebSocket, origin: Origin) -> Result<()> {
    let db = &state.db;
    let request = match read_request(socket).await {
        Ok(r) => r,
        Err(e) => {
            refuse(socket, RDCleanPathPdu::new_general_error()).await;
            return Err(e);
        }
    };
    let Ok(RDCleanPath::Request { proxy_auth, x224_connection_request, .. }) = request.into_enum() else {
        refuse(socket, RDCleanPathPdu::new_general_error()).await;
        bail!("message RDCleanPath inattendu");
    };
    let (addr, portal_user) = match &origin {
        Origin::Portunia { addr } => (addr.clone(), None),
        Origin::Portal { addr, user, .. } => (format!("{addr} (web)"), Some(*user)),
        Origin::Native => bail!("entrée native sur le passage RDCleanPath"),
    };
    // Rebond depuis le navigateur : la Gate relaie sans enregistrer (Portunia, lui, passe par
    // un tunnel SSH de bout en bout).
    let web = portal_user.is_some();
    let prepared = async {
        let a = authorize(db, &proxy_auth, addr, portal_user, |t| t.mode == "enregistre" || t.vaulted() || (t.mode == "rebond" && web)).await?;
        check_space(state, &a).await?;
        let mut o = open_server(db, &a, x224_connection_request.as_bytes()).await?;
        // Coffre : la Gate s'authentifie auprès du serveur avant de répondre au client.
        let vault_key = if a.target.vaulted() {
            let (account, password) = vault_account(state, &a).await?;
            Some(gate_login(db, &a, &mut o, &account, password).await?)
        } else {
            None
        };
        let id = Uuid::new_v4();
        let capture = start_recording(state, id, &a).await?;
        Ok::<_, Refused>((a, o, vault_key, id, capture))
    };
    let (a, o, vault_key, id, capture) = match prepared.await {
        Ok(p) => p,
        Err((why, e)) => {
            refuse(socket, why.pdu()).await;
            return Err(e);
        }
    };
    let early = o.protocol() & HYBRID_EX != 0;
    let response = RDCleanPathPdu::new_response(o.server.clone(), o.x224.clone(), o.chain.clone())?.to_der()?;
    socket.send(Message::Binary(response.into())).await?;
    // Coffre : le client s'authentifie auprès de la Gate avec son jeton ; ce qu'il a envoyé
    // ensuite part vers le serveur comme le reste de la session.
    let mut pending = Vec::new();
    if let Some(key) = vault_key {
        match token_login(socket, &proxy_auth, key, early).await {
            Ok(rest) => pending = rest,
            Err(e) => {
                audit::note(db, &a.user.login, "acces.refuse", json!({ "cible": a.target.name, "type": "rdp", "raison": e.to_string(), "adresse": a.addr })).await;
                if let Some(c) = capture {
                    let _ = c.finish(state, id).await;
                }
                return Err(e);
            }
        }
    }
    let (tx, rx) = socket.split();
    relay_session(state, id, &a, &origin, capture, o.tls, ClientRx::Ws(rx), ClientTx::Ws(tx), pending).await
}

/// Côté poste : la WebSocket RDCleanPath, ou une connexion RDP native (TLS de la Gate).
pub(crate) type NativeTls = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

pub(crate) enum ClientRx<'a> {
    Ws(futures_util::stream::SplitStream<&'a mut WebSocket>),
    Native(tokio::io::ReadHalf<&'a mut NativeTls>),
}

pub(crate) enum ClientTx<'a> {
    Ws(futures_util::stream::SplitSink<&'a mut WebSocket, Message>),
    Native(tokio::io::WriteHalf<&'a mut NativeTls>),
}

impl ClientRx<'_> {
    /// Prochains octets du poste ; None : il est parti.
    async fn recv(&mut self, buf: &mut [u8]) -> Option<Vec<u8>> {
        match self {
            ClientRx::Ws(ws) => loop {
                match ws.next().await {
                    Some(Ok(Message::Binary(data))) => return Some(data.to_vec()),
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return None,
                    _ => {}
                }
            },
            ClientRx::Native(tls) => match tls.read(buf).await {
                Ok(0) | Err(_) => None,
                Ok(n) => Some(buf[..n].to_vec()),
            },
        }
    }
}

impl ClientTx<'_> {
    async fn send(&mut self, bytes: Vec<u8>) -> bool {
        match self {
            ClientTx::Ws(ws) => ws.send(Message::Binary(bytes.into())).await.is_ok(),
            ClientTx::Native(tls) => tls.write_all(&bytes).await.is_ok(),
        }
    }

    async fn close(&mut self) {
        match self {
            ClientTx::Ws(ws) => {
                let _ = ws.send(Message::Close(None)).await;
            }
            ClientTx::Native(tls) => {
                let _ = tls.shutdown().await;
            }
        }
    }
}

/// Session ouverte : relais dans les deux sens, enregistrement, journal. `pending` : octets
/// que le poste a déjà envoyés, à faire suivre en premier.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_session(
    state: &Arc<State>,
    id: Uuid,
    a: &Allowed,
    origin: &Origin,
    capture: Option<crate::rdpcap::Tape>,
    tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    mut client_rx: ClientRx<'_>,
    mut client_tx: ClientTx<'_>,
    pending: Vec<u8>,
) -> Result<()> {
    let db = &state.db;
    let (user, target, access) = (&a.user, &a.target, &a.access);
    let web = matches!(origin, Origin::Portal { .. });
    let jump = target.mode == "rebond";
    // Copie de fichiers : tracée si la règle l'autorise (et gardée, si le réglage le demande),
    // bloquée en ligne sinon.
    let guard = (!access.files).then(crate::rdpclip::Guard::default);
    let (mut from_server, mut from_client) = (guard.as_ref().map(|g| g.side(true)), guard.as_ref().map(|g| g.side(false)));
    let (mut tls_read, mut tls_write) = tokio::io::split(tls);
    if !pending.is_empty() {
        let bytes = match &mut from_client {
            Some(side) => side.filter(&pending).map_err(|why| anyhow!("{why}"))?,
            None => pending,
        };
        if !bytes.is_empty() {
            if let Some(c) = &capture {
                c.push(false, &bytes).await;
            }
            tls_write.write_all(&bytes).await?;
        }
    }

    // Session ouverte : relais et enregistrement.
    if jump {
        model::session_start(db, id, user.id, target.id, "rebond", "rdp (web)", &a.addr).await?;
        audit::note(db, &user.login, "rebond.ouvert", json!({ "session": id, "cible": target.name, "protocole": "rdp", "adresse": a.addr })).await;
    } else {
        model::session_start(db, id, user.id, target.id, "rdp", if target.vaulted() { "coffre" } else { "enregistré" }, &a.addr).await?;
        audit::note(
            db,
            &user.login,
            "session.ouverte",
            json!({ "session": id, "cible": target.name, "protocole": "rdp", "mode": target.mode, "adresse": a.addr }),
        )
        .await;
    }
    let started = Instant::now();
    let (_watch, mut cut) = state.live.watch(crate::live::Watched { user: user.id, login: &user.login, target: Some(target), web, recorded: !jump });
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    // Octets relayés (rebond : sans enregistrement pour les compter).
    let moved = AtomicU64::new(0);
    // Dernière saisie du poste, en millisecondes depuis le début de la session.
    let last_input = AtomicU64::new(0);
    let mut closing = state.web.subscribe();
    let reason: String = {
        // Les deux sens avancent chacun de leur côté : un poste lent à recevoir l'image ne
        // retarde pas ses propres clics vers le serveur, et inversement.
        let down = async {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match tls_read.read(&mut buf).await {
                    Ok(0) | Err(_) => return "serveur",
                    Ok(n) => {
                        let bytes = match &mut from_server {
                            Some(side) => match side.filter(&buf[..n]) {
                                Ok(b) => b,
                                Err(why) => return why,
                            },
                            None => buf[..n].to_vec(),
                        };
                        if bytes.is_empty() {
                            continue;
                        }
                        if let Some(c) = &capture {
                            if !c.push(true, &bytes).await {
                                return "enregistrement";
                            }
                        }
                        moved.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                        if !client_tx.send(bytes).await {
                            return "client";
                        }
                    }
                }
            }
        };
        let up = async {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let Some(data) = client_rx.recv(&mut buf).await else { return "client" };
                last_input.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                let bytes = match &mut from_client {
                    Some(side) => match side.filter(&data) {
                        Ok(b) => b,
                        Err(why) => return why,
                    },
                    None => data,
                };
                if bytes.is_empty() {
                    continue;
                }
                if let Some(c) = &capture {
                    if !c.push(false, &bytes).await {
                        return "enregistrement";
                    }
                }
                moved.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                if tls_write.write_all(&bytes).await.is_err() {
                    return "serveur";
                }
            }
        };
        tokio::pin!(down, up);
        loop {
            let side = tokio::select! {
                side = &mut down => side,
                side = &mut up => side,
                _ = closing.changed(), if web => break "administrateur".into(),
                why = cut.reason() => break why,
                _ = tick.tick() => {
                    if let Origin::Portal { expires, idle, .. } = origin {
                        if Utc::now() >= *expires {
                            break "session web expirée".into();
                        }
                        let quiet = started.elapsed().saturating_sub(Duration::from_millis(last_input.load(Ordering::Relaxed)));
                        if quiet >= *idle {
                            break "inactivité".into();
                        }
                    }
                    continue;
                }
            };
            if side == "enregistrement" {
                audit::note(db, &user.login, "enregistrement.echec", json!({ "session": id, "cible": target.name, "raison": "écriture impossible" })).await;
                break "enregistrement impossible".into();
            }
            break side.into();
        }
    };
    let _ = tls_write.shutdown().await;
    client_tx.close().await;

    let mut done = model::Finished { recording: None, sha256: None, signature: None, bytes: moved.load(Ordering::Relaxed) as i64 };
    let mut files = Vec::new();
    match capture.map(|c| c.finish(state, id)) {
        Some(finishing) => match finishing.await {
            Ok(c) => {
                done = model::Finished { recording: Some(c.path), sha256: Some(c.sha256), signature: Some(c.signature), bytes: c.bytes as i64 };
                files = c.files;
            }
            Err(e) => tracing::error!("{} {id}: {e:#}", t!("RDP recording", "enregistrement RDP")),
        },
        None => {}
    }
    let bytes = done.bytes;
    model::session_end(db, id, done).await?;
    if jump {
        audit::note(db, &user.login, "rebond.ferme", json!({ "session": id, "cible": target.name, "duree_s": started.elapsed().as_secs(), "octets": bytes, "fin": reason })).await;
        return Ok(());
    }
    model::session_index(db, id, access.record_input, "").await?;
    // Fichiers copiés : une ligne du journal chacun (sens, nom, taille, empreinte).
    for f in &files {
        let mut detail = f.clone();
        if let Some(map) = detail.as_object_mut() {
            map.remove("k");
            map.insert("session".into(), json!(id));
            map.insert("cible".into(), json!(target.name));
        }
        audit::note(db, &user.login, "fichier.copie", detail).await;
    }
    if !files.is_empty() {
        model::session_files(db, id, files.len() as i32).await?;
    }
    if let Some(blocked) = guard.as_ref().map(|g| g.blocked()).filter(|&n| n > 0) {
        audit::note(db, &user.login, "fichier.bloque", json!({ "session": id, "cible": target.name, "messages": blocked })).await;
    }
    audit::note(
        db,
        &user.login,
        "session.fermee",
        json!({ "session": id, "cible": target.name, "duree_s": started.elapsed().as_secs(), "octets": bytes, "fin": reason }),
    )
    .await;
    Ok(())
}

/// Copies de fichiers gardées par session (réglage « copies_fichiers_mo », en Mo ; 0 : aucune).
async fn file_copies_limit(state: &State) -> Result<u64> {
    let mb = model::setting(&state.db, "copies_fichiers_mo").await?.and_then(|v| v.as_u64()).unwrap_or(0);
    Ok(mb.min(10_240) * 1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocole_choisi() {
        // TPKT, X.224 CC, RDP_NEG_RSP : NLA étendu.
        let rsp = [3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0x1f, 8, 0, 8, 0, 0, 0];
        assert_eq!(selected_protocol(&rsp), Some(HYBRID_EX));
        // Échec de négociation (type 3) ou réponse sans négociation : pas de protocole.
        let mut fail = rsp;
        fail[11] = 3;
        assert_eq!(selected_protocol(&fail), None);
        assert_eq!(selected_protocol(&rsp[..11]), None);
    }

    /// Le client s'authentifie auprès de la Gate avec le jeton, refusé avec autre chose.
    fn nla_jeton(password: &str) -> bool {
        let key = vec![7u8; 270];
        let identity = AuthIdentity { username: Username::parse("portunia").unwrap(), password: password.to_string().into() };
        let mut client = CredSspClient::new(key.clone(), Credentials::AuthIdentity(identity), CredSspMode::WithCredentials, ClientMode::Ntlm(NtlmConfig::default()), "TERMSRV/srv".into()).unwrap();
        let mut server = CredSspServer::new(key, TokenProxy { token: "jeton-123".into() }, ServerMode::Ntlm(NtlmConfig::default())).unwrap();
        let mut request = TsRequest::default();
        for _ in 0..6 {
            let to_server = match client.process(request).resolve_to_result() {
                Ok(ClientState::ReplyNeeded(r)) | Ok(ClientState::FinalMessage(r)) => r,
                Err(_) => return false,
            };
            // Aller-retour par l'encodage, comme sur la WebSocket.
            let to_server = TsRequest::from_buffer(&encode(&to_server).unwrap()).unwrap();
            match server.process(to_server).resolve_to_result() {
                Ok(ServerState::ReplyNeeded(r)) => request = TsRequest::from_buffer(&encode(&r).unwrap()).unwrap(),
                Ok(ServerState::Finished(_)) => return true,
                Err(_) => return false,
            }
        }
        false
    }

    #[test]
    fn nla_avec_le_jeton() {
        assert!(nla_jeton("jeton-123"));
        assert!(!nla_jeton("autre"));
    }

    #[test]
    fn longueur_der() {
        assert_eq!(der_len(&[0x30]).unwrap(), None);
        assert_eq!(der_len(&[0x30, 5]).unwrap(), Some(7));
        assert_eq!(der_len(&[0x30, 0x82, 1]).unwrap(), None);
        assert_eq!(der_len(&[0x30, 0x82, 1, 0]).unwrap(), Some(4 + 256));
        assert!(der_len(&[3, 0, 0, 19]).is_err());
        assert!(der_len(&[0x30, 0x83, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn empreinte() {
        let fp = cert_fingerprint(b"certificat");
        assert!(fp.starts_with("TLS:") && fp.len() == 4 + 32 * 3 - 1);
    }
}
