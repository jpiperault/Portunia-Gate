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
//! Enregistrement : `<session>.rdpcap` dans le dossier des enregistrements, signé à la fin
//! comme les sessions SSH ; voir `rdpcap` pour ce qui est gardé.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::ws::{Message, WebSocket};
use chrono::{DateTime, Utc};
use ironrdp_rdcleanpath::{DetectionResult, RDCleanPath, RDCleanPathPdu};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{audit, keys::sha256_hex, model, State};

/// D'où vient la demande : le portail web (sessions fermées avec le portail) ou Portunia.
pub enum Origin {
    /// Portail : la session web fixe la durée, et le jeton doit être celui de son compte.
    Portal { addr: String, user: Uuid, expires: DateTime<Utc>, idle: Duration },
    Portunia { addr: String },
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
struct Capture(Arc<CryptoProvider>);

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
fn cert_fingerprint(der: &[u8]) -> String {
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

/// Réponse X.224 du serveur : un paquet TPKT (4 octets d'en-tête, longueur sur 2 octets).
async fn read_tpkt(tcp: &mut tokio::net::TcpStream) -> Result<Vec<u8>> {
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await?;
    if head[0] != 3 {
        bail!(t!("unexpected server answer (not RDP)", "réponse du serveur inattendue (pas de RDP)"));
    }
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    if !(4..=4096).contains(&len) {
        bail!(t!("X.224 answer with invalid length", "réponse X.224 de longueur invalide"));
    }
    let mut pdu = head.to_vec();
    pdu.resize(len, 0);
    tcp.read_exact(&mut pdu[4..]).await?;
    Ok(pdu)
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

    // Jeton à usage unique : il dit qui et vers quel serveur.
    let Some((user_id, target_id, real_addr)) = crate::api::take_ticket(db, &proxy_auth).await? else {
        refuse(socket, RDCleanPathPdu::new_http_error(401)).await;
        bail!(t!("invalid, expired or already used token", "jeton invalide, expiré ou déjà utilisé"));
    };
    let addr = real_addr.unwrap_or_else(|| match &origin {
        Origin::Portunia { addr } => addr.clone(),
        Origin::Portal { addr, .. } => format!("{addr} (web)"),
    });
    let user = model::user_by_id(db, user_id).await?.filter(|u| !u.disabled);
    let target = model::target_by_id(db, target_id).await?;
    let (Some(user), Some(target)) = (user, target) else {
        refuse(socket, RDCleanPathPdu::new_http_error(403)).await;
        bail!(t!("account or server deleted", "compte ou serveur supprimé"));
    };
    if matches!(&origin, Origin::Portal { user: web_user, .. } if *web_user != user.id) {
        audit::note(db, &user.login, "acces.refuse", json!({ "cible": target.name, "type": "rdp", "raison": "jeton d'un autre compte", "adresse": addr })).await;
        refuse(socket, RDCleanPathPdu::new_http_error(403)).await;
        bail!(t!("token of another account", "jeton d'un autre compte"));
    }
    let access = model::access(db, user.id, target.id).await?;
    let Some(access) = access.filter(|_| target.is_rdp() && target.mode == "enregistre") else {
        audit::note(db, &user.login, "acces.refuse", json!({ "cible": target.name, "type": "rdp", "adresse": addr })).await;
        refuse(socket, RDCleanPathPdu::new_http_error(403)).await;
        bail!(t!(format!("{}: access denied", target.name), format!("{} : accès refusé", target.name)));
    };

    if !crate::live::can_record(state) {
        audit::note(db, &user.login, "enregistrement.echec", json!({ "cible": target.name, "raison": "espace disque insuffisant", "adresse": addr })).await;
        refuse(socket, RDCleanPathPdu::new_general_error()).await;
        bail!("{}", crate::live::no_space_message());
    }

    // Connexion au serveur Windows, début de la négociation RDP.
    let server = format!("{}:{}", target.host, target.port);
    let mut tcp = match tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(server.as_str())).await {
        Ok(Ok(t)) => t,
        _ => {
            refuse(socket, RDCleanPathPdu::new_wsa_error(10061)).await;
            bail!("{server} injoignable");
        }
    };
    let _ = tcp.set_nodelay(true);
    tcp.write_all(x224_connection_request.as_bytes()).await?;
    let x224_response = read_tpkt(&mut tcp).await.context(t!("X.224 negotiation", "négociation X.224"))?;

    // Négociation chiffrée avec le serveur, certificat vérifié par son empreinte.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Capture(provider)))
        .with_no_client_auth();
    let name = ServerName::try_from(target.host.clone()).map_err(|_| anyhow!(t!("invalid server address", "adresse du serveur invalide")))?;
    let tls = match tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await {
        Ok(t) => t,
        Err(e) => {
            refuse(socket, RDCleanPathPdu::new_tls_error(40)).await;
            bail!(t!(format!("TLS negotiation with {server}: {e}"), format!("négociation TLS avec {server} : {e}")));
        }
    };
    let chain: Vec<Vec<u8>> = tls.get_ref().1.peer_certificates().unwrap_or_default().iter().map(|c| c.to_vec()).collect();
    let Some(leaf) = chain.first() else {
        refuse(socket, RDCleanPathPdu::new_general_error()).await;
        bail!(t!(format!("{server} presented no certificate"), format!("{server} n'a pas présenté de certificat")));
    };
    let fingerprint = cert_fingerprint(leaf);
    match &target.host_key {
        None => {
            if model::pin_host_key(db, target.id, &fingerprint).await? {
                audit::note(db, &user.login, "cible.empreinte_memorisee", json!({ "cible": target.name, "empreinte": fingerprint })).await;
            }
        }
        Some(known) if *known != fingerprint => {
            audit::note(db, &user.login, "cible.empreinte_differente", json!({ "cible": target.name, "attendue": known, "recue": fingerprint })).await;
            refuse(socket, RDCleanPathPdu::new_general_error()).await;
            bail!(t!(
                format!("{}: the server's certificate has changed (expected {known}, received {fingerprint})", target.name),
                format!("{} : le certificat du serveur a changé (attendu {known}, reçu {fingerprint})", target.name)
            ));
        }
        _ => {}
    }
    // Pas de session sans enregistrement.
    let id = Uuid::new_v4();
    let mut capture = match crate::rdpcap::Recorder::create(&state.config.recordings_dir(), id, &format!("{} → {}", user.login, target.name), access.record_input) {
        Ok(c) => c,
        Err(e) => {
            audit::note(db, &user.login, "enregistrement.echec", json!({ "cible": target.name, "raison": e.to_string(), "adresse": addr })).await;
            refuse(socket, RDCleanPathPdu::new_general_error()).await;
            bail!("{} {id}: {e:#}", t!("RDP recording", "enregistrement RDP"));
        }
    };
    let response = RDCleanPathPdu::new_response(server.clone(), x224_response, chain)?.to_der()?;
    socket.send(Message::Binary(response.into())).await?;

    // Session ouverte : relais et enregistrement.
    model::session_start(db, id, user.id, target.id, "rdp", "enregistré", &addr).await?;
    audit::note(
        db,
        &user.login,
        "session.ouverte",
        json!({ "session": id, "cible": target.name, "protocole": "rdp", "mode": target.mode, "adresse": addr }),
    )
    .await;
    let started = Instant::now();
    let web = matches!(origin, Origin::Portal { .. });
    let (_watch, mut cut) = state.live.watch(crate::live::Watched { user: user.id, login: &user.login, target: Some(&target), web, recorded: true });
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let mut last_input = Instant::now();
    let (mut tls_read, mut tls_write) = tokio::io::split(tls);
    let mut closing = state.web.subscribe();
    let mut buf = vec![0u8; 64 * 1024];
    let reason: String = loop {
        tokio::select! {
            n = tls_read.read(&mut buf) => match n {
                Ok(0) | Err(_) => break "serveur".into(),
                Ok(n) => {
                    capture.server(&buf[..n]);
                    if socket.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break "client".into();
                    }
                }
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Binary(data))) => {
                    last_input = Instant::now();
                    capture.client(&data);
                    if tls_write.write_all(&data).await.is_err() {
                        break "serveur".into();
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break "client".into(),
                _ => {}
            },
            _ = closing.changed(), if web => break "administrateur".into(),
            why = cut.reason() => break why,
            _ = tick.tick() => {
                if let Origin::Portal { expires, idle, .. } = &origin {
                    if Utc::now() >= *expires {
                        break "session web expirée".into();
                    }
                    if last_input.elapsed() >= *idle {
                        break "inactivité".into();
                    }
                }
            }
        }
        if capture.failed() {
            audit::note(db, &user.login, "enregistrement.echec", json!({ "session": id, "cible": target.name, "raison": "écriture impossible" })).await;
            break "enregistrement impossible".into();
        }
    };
    let _ = tls_write.shutdown().await;
    let _ = socket.send(Message::Close(None)).await;

    let mut done = model::Finished { recording: None, sha256: None, signature: None, bytes: 0 };
    match capture.finish(state, id) {
        Ok((path, sha, sig, bytes)) => done = model::Finished { recording: Some(path), sha256: Some(sha), signature: Some(sig), bytes: bytes as i64 },
        Err(e) => tracing::error!("{} {id}: {e:#}", t!("RDP recording", "enregistrement RDP")),
    }
    let bytes = done.bytes;
    model::session_end(db, id, done).await?;
    model::session_index(db, id, access.record_input, "").await?;
    audit::note(
        db,
        &user.login,
        "session.fermee",
        json!({ "session": id, "cible": target.name, "duree_s": started.elapsed().as_secs(), "octets": bytes, "fin": reason }),
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empreinte() {
        let fp = cert_fingerprint(b"certificat");
        assert!(fp.starts_with("TLS:") && fp.len() == 4 + 32 * 3 - 1);
    }
}
