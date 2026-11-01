//! Relais dédié : le portail web publié depuis une machine à part, en DMZ.
//!
//! Le relais reçoit les navigateurs en HTTPS et leur passe des connexions ouvertes par la Gate :
//! aucun flux ne va de la DMZ vers le réseau interne. Il ne contient ni coffre, ni comptes, ni
//! base, seulement le secret partagé avec la Gate et ses certificats ; il ne lit pas le HTTP,
//! que la Gate traite comme une requête de son portail, adresse réelle du visiteur comprise.
//!
//! Chaque connexion de la Gate est du TLS. Le certificat du relais est auto-signé : il est lié
//! au secret par une preuve mutuelle (HMAC sur deux aléas et l'empreinte du certificat), si
//! bien qu'une machine sans le secret ne peut pas se faire passer pour le relais, ni l'inverse.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use axum::{extract::ConnectInfo, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request};
use hyper_util::rt::{TokioIo, TokioTimer};
use ring::hmac;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{watch, Notify, Semaphore},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{keys, model, portal, State};

const PROTOCOL: u8 = 1;
const SETTING: &str = "portail_relais";

/// Connexions que la Gate garde prêtes sur chaque relais.
const WORKERS: u64 = 8;
const MAX_IDLE: usize = 32;
const RETRY: Duration = Duration::from_secs(5);
/// Une connexion inutilisée est refaite : un pare-feu peut l'avoir oubliée sans prévenir.
const IDLE: Duration = Duration::from_secs(45);
const HANDSHAKE: Duration = Duration::from_secs(10);
/// Temps accordé à une connexion de la Gate pour répondre, avant d'essayer la suivante.
const ACK: Duration = Duration::from_secs(2);
const WAIT_TUNNEL: Duration = Duration::from_secs(5);
const HEADERS: Duration = Duration::from_secs(10);
const MAX_BROWSERS: usize = 2048;
const MAX_PER_ADDRESS: usize = 64;
const MAX_PENDING_TUNNELS: usize = 64;

fn proof(secret: &[u8], label: &[u8], gate: &[u8], relay: &[u8], fingerprint: &[u8]) -> hmac::Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut ctx = hmac::Context::with_key(&key);
    for part in [b"portunia-gate-relais-v1:" as &[u8], label, gate, relay, fingerprint] {
        ctx.update(part);
    }
    ctx.sign()
}

fn check(secret: &[u8], label: &[u8], gate: &[u8], relay: &[u8], fingerprint: &[u8], tag: &[u8]) -> Result<()> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut message = b"portunia-gate-relais-v1:".to_vec();
    for part in [label, gate, relay, fingerprint] {
        message.extend_from_slice(part);
    }
    hmac::verify(&key, &message, tag).map_err(|_| anyhow!(t!("wrong relay secret", "secret du relais incorrect")))
}

/// Côté relais : prouve qu'il a le secret et vérifie que la Gate l'a aussi.
async fn greet<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, secret: &[u8], fingerprint: &[u8]) -> Result<()> {
    let mut hello = [0u8; 33];
    stream.read_exact(&mut hello).await?;
    if hello[0] != PROTOCOL {
        bail!(t!("relay protocol version differs: update the Gate and the relay", "version du protocole différente : mettez à jour la Gate et le relais"));
    }
    let gate = &hello[1..];
    let relay = keys::random::<32>()?;
    let version = env!("CARGO_PKG_VERSION").as_bytes();
    let mut out = relay.to_vec();
    out.extend_from_slice(proof(secret, b"relais", gate, &relay, fingerprint).as_ref());
    out.push(version.len() as u8);
    out.extend_from_slice(version);
    stream.write_all(&out).await?;
    stream.flush().await?;
    let mut tag = [0u8; 32];
    stream.read_exact(&mut tag).await?;
    check(secret, b"gate", gate, &relay, fingerprint, &tag)
}

/// Côté Gate : renvoie la version du relais une fois les deux preuves faites.
async fn hello<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, secret: &[u8], fingerprint: &[u8]) -> Result<String> {
    let gate = keys::random::<32>()?;
    let mut out = vec![PROTOCOL];
    out.extend_from_slice(&gate);
    stream.write_all(&out).await?;
    stream.flush().await?;
    let mut answer = [0u8; 64];
    stream.read_exact(&mut answer).await?;
    let (relay, tag) = answer.split_at(32);
    check(secret, b"relais", &gate, relay, fingerprint, tag)?;
    let mut size = [0u8; 1];
    stream.read_exact(&mut size).await?;
    let mut version = vec![0u8; size[0] as usize];
    stream.read_exact(&mut version).await?;
    stream.write_all(proof(secret, b"gate", &gate, relay, fingerprint).as_ref()).await?;
    stream.flush().await?;
    Ok(String::from_utf8_lossy(&version).into_owned())
}

fn tls_fingerprint(der: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, der).as_ref().to_vec()
}

// ---------- Machine du relais ----------

#[derive(Serialize, Deserialize)]
struct EdgeConfig {
    secret: String,
    public_listen: String,
    tunnel_listen: String,
}

fn edge_dir() -> PathBuf {
    let data: PathBuf = std::env::var_os("PORTUNIA_GATE_DATA_DIR").map(PathBuf::from).unwrap_or_else(|| "/var/lib/portunia-gate".into());
    data.join("relais")
}

fn replace_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let _ = std::fs::remove_file(path);
    keys::write_private(path, bytes)
}

fn install_certificate(dir: &Path, cert: &Path, key: &Path) -> Result<()> {
    let chain = std::fs::read(cert).with_context(|| t!(format!("reading {}", cert.display()), format!("lecture de {}", cert.display())))?;
    let secret = std::fs::read(key).with_context(|| t!(format!("reading {}", key.display()), format!("lecture de {}", key.display())))?;
    server_config_from(&chain, &secret, b"http/1.1").context(t!("invalid certificate", "certificat invalide"))?;
    replace_private(&dir.join("portail.crt"), &chain)?;
    replace_private(&dir.join("portail.key"), &secret)
}

/// Prépare cette machine comme relais. Rien ne part vers la Gate : c'est elle qui appellera.
pub fn enroll(code: &str, public_listen: &str, tunnel_listen: &str, name: &str, cert: Option<&Path>, key: Option<&Path>) -> Result<()> {
    let secret = decode_code(code)?;
    for listen in [public_listen, tunnel_listen] {
        listen.parse::<SocketAddr>().map_err(|_| anyhow!(t!(format!("invalid address: {listen}"), format!("adresse invalide : {listen}"))))?;
    }
    let dir = edge_dir();
    std::fs::create_dir_all(&dir)?;
    let config = EdgeConfig { secret: keys::hex(&secret), public_listen: public_listen.into(), tunnel_listen: tunnel_listen.into() };
    replace_private(&dir.join("relais.json"), serde_json::to_vec(&config)?.as_slice())?;
    if !dir.join("tunnel.crt").exists() {
        crate::tls::write_self_signed(&["portunia-gate-relais".to_string()], "Portunia Gate relay", &dir.join("tunnel.crt"), &dir.join("tunnel.key"))?;
    }
    match (cert, key) {
        (Some(c), Some(k)) => install_certificate(&dir, c, k)?,
        (None, None) if !dir.join("portail.crt").exists() => {
            crate::tls::write_self_signed(&[name.to_string()], name, &dir.join("portail.crt"), &dir.join("portail.key"))?;
        }
        (None, None) => {}
        _ => bail!(t!("give both the certificate and its key", "indiquez le certificat et sa clé")),
    }
    Ok(())
}

/// Remplace le certificat présenté aux navigateurs (service à redémarrer).
pub fn set_certificate(cert: &Path, key: &Path) -> Result<()> {
    install_certificate(&edge_dir(), cert, key)
}

fn server_config_from(chain: &[u8], key: &[u8], alpn: &[u8]) -> Result<Arc<rustls::ServerConfig>> {
    let certs = CertificateDer::pem_slice_iter(chain).collect::<std::result::Result<Vec<_>, _>>().map_err(|e| anyhow!("{e}"))?;
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|e| anyhow!("{e}"))?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(config))
}

/// Connexions de la Gate en attente d'un navigateur.
struct Pool<T> {
    idle: Mutex<Vec<T>>,
    ready: Notify,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Pool<T> {
    fn new() -> Self {
        Self { idle: Mutex::new(Vec::new()), ready: Notify::new() }
    }

    fn put(&self, tunnel: T) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() >= MAX_IDLE {
            idle.remove(0);
        }
        idle.push(tunnel);
        self.ready.notify_one();
    }

    /// Donne une connexion qui répond, et lui annonce l'adresse du visiteur.
    async fn take(&self, visitor: IpAddr) -> Option<T> {
        let line = format!("{visitor}\n");
        let deadline = tokio::time::Instant::now() + WAIT_TUNNEL;
        loop {
            // La plus récente d'abord : les anciennes ont pu être refermées par la Gate.
            let next = self.idle.lock().unwrap_or_else(|e| e.into_inner()).pop();
            match next {
                Some(mut tunnel) => {
                    let exchange = async {
                        tunnel.write_all(line.as_bytes()).await?;
                        tunnel.flush().await?;
                        tunnel.read_u8().await
                    };
                    if matches!(tokio::time::timeout(ACK, exchange).await, Ok(Ok(1))) {
                        return Some(tunnel);
                    }
                }
                None => {
                    if tokio::time::timeout_at(deadline, self.ready.notified()).await.is_err() {
                        return None;
                    }
                }
            }
        }
    }
}

const UNAVAILABLE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: 33\r\n\r\nPortal temporarily unavailable.\r\n\r\n";

#[derive(Clone, Default)]
struct Visitors(Arc<Mutex<HashMap<IpAddr, usize>>>);

struct Visit(Visitors, IpAddr);

impl Visitors {
    fn enter(&self, ip: IpAddr) -> Option<Visit> {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let count = map.entry(ip).or_insert(0);
        if *count >= MAX_PER_ADDRESS {
            return None;
        }
        *count += 1;
        Some(Visit(self.clone(), ip))
    }
}

impl Drop for Visit {
    fn drop(&mut self) {
        let mut map = self.0 .0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.1) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.1);
            }
        }
    }
}

async fn tunnels_listener<T>(listener: TcpListener, acceptor: TlsAcceptor, secret: Arc<Vec<u8>>, fingerprint: Arc<Vec<u8>>, pool: Arc<Pool<T>>) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static + From<tokio_rustls::server::TlsStream<TcpStream>>,
{
    let pending = Arc::new(Semaphore::new(MAX_PENDING_TUNNELS));
    loop {
        let (tcp, peer) = listener.accept().await?;
        let Ok(permit) = pending.clone().try_acquire_owned() else { continue };
        let (acceptor, secret, fingerprint, pool) = (acceptor.clone(), secret.clone(), fingerprint.clone(), pool.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tcp.set_nodelay(true);
            let shake = async {
                let mut tls = acceptor.accept(tcp).await?;
                greet(&mut tls, &secret, &fingerprint).await?;
                anyhow::Ok(tls)
            };
            match tokio::time::timeout(HANDSHAKE, shake).await {
                Ok(Ok(tls)) => pool.put(tls.into()),
                Ok(Err(e)) => tracing::warn!("{} {peer} : {e:#}", t!("Gate connection refused from", "connexion de Gate refusée depuis")),
                Err(_) => {}
            }
        });
    }
}

async fn browsers_listener<T>(listener: TcpListener, acceptor: TlsAcceptor, pool: Arc<Pool<T>>) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let open = Arc::new(Semaphore::new(MAX_BROWSERS));
    let visitors = Visitors::default();
    loop {
        let (tcp, peer) = listener.accept().await?;
        let ip = peer.ip().to_canonical();
        let (Ok(permit), Some(visit)) = (open.clone().try_acquire_owned(), visitors.enter(ip)) else { continue };
        let (acceptor, pool) = (acceptor.clone(), pool.clone());
        tokio::spawn(async move {
            let _held = (permit, visit);
            let _ = tcp.set_nodelay(true);
            let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE, acceptor.accept(tcp)).await else { return };
            match pool.take(ip).await {
                Some(mut tunnel) => {
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut tunnel).await;
                }
                None => {
                    let _ = tls.write_all(UNAVAILABLE).await;
                    let _ = tls.shutdown().await;
                }
            }
        });
    }
}

/// Le service du relais.
pub async fn serve_edge() -> Result<()> {
    let dir = edge_dir();
    let raw = std::fs::read(dir.join("relais.json")).context(t!("this machine is not a relay (run « portunia-gate edge enroll »)", "cette machine n'est pas un relais (lancez « portunia-gate edge enroll »)"))?;
    let config: EdgeConfig = serde_json::from_slice(&raw)?;
    let secret = Arc::new(decode_code(&config.secret)?);
    let tunnel_pem = std::fs::read(dir.join("tunnel.crt"))?;
    let tunnel_der = CertificateDer::from_pem_slice(&tunnel_pem).map_err(|e| anyhow!("{e}"))?;
    let fingerprint = Arc::new(tls_fingerprint(&tunnel_der));
    let tunnels = TlsAcceptor::from(server_config_from(&tunnel_pem, &std::fs::read(dir.join("tunnel.key"))?, b"portunia-gate-relais")?);
    let browsers = TlsAcceptor::from(server_config_from(&std::fs::read(dir.join("portail.crt"))?, &std::fs::read(dir.join("portail.key"))?, b"http/1.1")?);
    let pool = Arc::new(Pool::<tokio_rustls::server::TlsStream<TcpStream>>::new());
    let tunnel_port = TcpListener::bind(&config.tunnel_listen).await.with_context(|| config.tunnel_listen.clone())?;
    let public_port = TcpListener::bind(&config.public_listen).await.with_context(|| config.public_listen.clone())?;
    tracing::info!("{} https://{} ; {} {}", t!("relay listening on", "relais en écoute sur"), config.public_listen, t!("Gate connections on", "connexions de la Gate sur"), config.tunnel_listen);
    tokio::try_join!(tunnels_listener(tunnel_port, tunnels, secret, fingerprint, pool.clone()), browsers_listener(public_port, browsers, pool)).map(|_| ())
}

// ---------- Côté Gate ----------

/// Relais déclaré sur la Gate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub nom: String,
    pub adresse: String,
    /// Secret partagé, chiffré par le coffre.
    secret: String,
}

#[derive(Clone, Default)]
struct Link {
    idle: usize,
    version: String,
    error: Option<String>,
    seen: Option<DateTime<Utc>>,
}

/// État des liaisons avec les relais, affiché dans Portunia.
#[derive(Default)]
pub struct Links(Mutex<HashMap<String, Link>>);

impl Links {
    fn update(&self, id: &str, change: impl FnOnce(&mut Link)) {
        change(self.0.lock().unwrap_or_else(|e| e.into_inner()).entry(id.to_string()).or_default());
    }
}

pub async fn list(state: &State) -> Result<Vec<Entry>> {
    Ok(model::setting(&state.db, SETTING).await?.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default())
}

fn encode_code(secret: &[u8]) -> String {
    let hex = keys::hex(secret).to_uppercase();
    hex.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-")
}

fn decode_code(code: &str) -> Result<Vec<u8>> {
    let text: String = code.chars().filter(|c| *c != '-' && !c.is_whitespace()).collect();
    let bytes: Option<Vec<u8>> = (text.len() == 32 && text.is_ascii())
        .then(|| (0..32).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect())
        .flatten();
    bytes.ok_or_else(|| anyhow!(t!("invalid pairing code", "code d'appairage invalide")))
}

/// Déclare un relais. Renvoie le code à donner à `portunia-gate edge enroll`.
pub async fn add(state: &State, name: &str, address: &str) -> Result<(Entry, String)> {
    let (name, address) = (name.trim(), address.trim());
    if name.is_empty() || name.chars().count() > 64 {
        bail!(t!("Relay name: 1 to 64 characters", "Nom du relais : 1 à 64 caractères"));
    }
    let valid = address.rsplit_once(':').is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0));
    if !valid {
        bail!(t!("Relay address: host:port, e.g. 10.0.5.20:8447", "Adresse du relais : hôte:port, par ex. 10.0.5.20:8447"));
    }
    let mut all = list(state).await?;
    if all.iter().any(|r| r.nom == name) {
        bail!(t!("A relay already has this name", "Un relais porte déjà ce nom"));
    }
    let secret = keys::random::<16>()?;
    let id = Uuid::new_v4().to_string();
    let sealed = B64.encode(state.keys.seal(&format!("relais:{id}"), &secret)?);
    let entry = Entry { id, nom: name.to_string(), adresse: address.to_string(), secret: sealed };
    all.push(entry.clone());
    model::set_setting(&state.db, SETTING, json!(all)).await?;
    Ok((entry, encode_code(&secret)))
}

/// Retire un relais, désigné par son identifiant ou son nom. Renvoie son nom.
pub async fn remove(state: &State, key: &str) -> Result<Option<String>> {
    let mut all = list(state).await?;
    let Some(at) = all.iter().position(|r| r.id == key || r.nom == key) else { return Ok(None) };
    let gone = all.remove(at);
    if all.is_empty() && portal::exposure(state).mode == portal::Mode::Relay {
        bail!(t!("This is the last relay: first choose another exposure mode", "C'est le dernier relais : choisissez d'abord un autre mode d'exposition"));
    }
    model::set_setting(&state.db, SETTING, json!(all)).await?;
    state.relays.0.lock().unwrap_or_else(|e| e.into_inner()).remove(&gone.id);
    Ok(Some(gone.nom))
}

pub async fn report(state: &State) -> Result<Vec<Value>> {
    let links = state.relays.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Ok(list(state)
        .await?
        .iter()
        .map(|r| {
            let link = links.get(&r.id).cloned().unwrap_or_default();
            json!({ "id": r.id, "nom": r.nom, "adresse": r.adresse, "connecte": link.idle > 0, "pretes": link.idle, "version": link.version, "erreur": link.error, "vu": link.seen })
        })
        .collect())
}

fn client_config() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocoles TLS par défaut")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::rdp::Capture(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"portunia-gate-relais".to_vec()];
    Arc::new(config)
}

/// Ouvre une connexion vers le relais et attend qu'un navigateur la prenne.
/// Renvoie la connexion et l'adresse du visiteur, ou rien si elle est restée inutilisée.
async fn wait_visitor(address: &str, secret: &[u8], tls: &TlsConnector, idle: Duration, links: Option<(&Links, &str)>) -> Result<Option<(tokio_rustls::client::TlsStream<TcpStream>, IpAddr)>> {
    let shake = async {
        let tcp = TcpStream::connect(address).await?;
        let _ = tcp.set_nodelay(true);
        let mut stream = tls.connect(ServerName::try_from("portunia-gate-relais")?, tcp).await?;
        let der = stream.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| c.to_vec()).ok_or_else(|| anyhow!(t!("relay without certificate", "relais sans certificat")))?;
        let version = hello(&mut stream, secret, &tls_fingerprint(&der)).await?;
        anyhow::Ok((stream, version))
    };
    let (mut stream, version) = tokio::time::timeout(HANDSHAKE, shake).await.map_err(|_| anyhow!(t!("relay does not answer", "le relais ne répond pas")))??;
    if let Some((links, id)) = links {
        links.update(id, |l| {
            l.idle += 1;
            l.version = version;
            l.error = None;
            l.seen = Some(Utc::now());
        });
    }
    let waited = tokio::time::timeout(idle, async {
        let mut line = Vec::with_capacity(48);
        loop {
            let byte = stream.read_u8().await?;
            if byte == b'\n' {
                return anyhow::Ok(line);
            }
            if line.len() >= 64 {
                bail!(t!("invalid relay message", "message du relais invalide"));
            }
            line.push(byte);
        }
    })
    .await;
    if let Some((links, id)) = links {
        links.update(id, |l| l.idle = l.idle.saturating_sub(1));
    }
    let Ok(line) = waited else { return Ok(None) };
    let line = line?;
    let ip: IpAddr = std::str::from_utf8(&line)?.parse()?;
    stream.write_u8(1).await?;
    stream.flush().await?;
    Ok(Some((stream, ip)))
}

/// Traite une connexion du relais comme une connexion directe au portail.
async fn serve_portal<S>(stream: S, ip: IpAddr, router: Router)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let info = ConnectInfo(SocketAddr::new(ip, 0));
    let service = service_fn(move |mut request: Request<Incoming>| {
        request.extensions_mut().insert(info);
        router.clone().oneshot(request)
    });
    let connection = http1::Builder::new().timer(TokioTimer::new()).header_read_timeout(HEADERS).serve_connection(TokioIo::new(stream), service).with_upgrades();
    let _ = connection.await;
}

async fn worker(state: Arc<State>, entry: Entry, secret: Vec<u8>, index: u64, router: Router, mut stop: watch::Receiver<bool>) {
    let tls = TlsConnector::from(client_config());
    let idle = IDLE + Duration::from_secs(index * 3);
    loop {
        let round = wait_visitor(&entry.adresse, &secret, &tls, idle, Some((&state.relays, &entry.id)));
        tokio::select! {
            _ = stop.changed() => return,
            result = round => match result {
                Ok(Some((stream, ip))) => {
                    let (router, mut stop) = (router.clone(), stop.clone());
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = stop.changed() => {}
                            _ = serve_portal(stream, ip, router) => {}
                        }
                    });
                }
                Ok(None) => {}
                Err(e) => {
                    state.relays.update(&entry.id, |l| l.error = Some(format!("{e:#}")));
                    tokio::time::sleep(RETRY).await;
                }
            }
        }
    }
}

/// Tient les connexions vers les relais déclarés, tant que le portail est en mode relais.
pub async fn run(state: Arc<State>) -> Result<()> {
    let router = portal::relayed_router(state.clone());
    let mut running: HashMap<String, watch::Sender<bool>> = HashMap::new();
    loop {
        let wanted = match portal::exposure(&state).mode {
            portal::Mode::Relay => list(&state).await.unwrap_or_default(),
            _ => Vec::new(),
        };
        running.retain(|id, _| wanted.iter().any(|r| &r.id == id));
        for entry in wanted {
            if running.contains_key(&entry.id) {
                continue;
            }
            let opened = B64.decode(&entry.secret).map_err(anyhow::Error::from).and_then(|b| state.keys.open(&format!("relais:{}", entry.id), &b));
            let secret = match opened {
                Ok(secret) => secret,
                Err(e) => {
                    tracing::error!("{} {} : {e:#}", t!("relay", "relais"), entry.nom);
                    continue;
                }
            };
            let (stop, watching) = watch::channel(false);
            for index in 0..WORKERS {
                tokio::spawn(worker(state.clone(), entry.clone(), secret.clone(), index, router.clone(), watching.clone()));
            }
            running.insert(entry.id.clone(), stop);
        }
        tokio::time::sleep(RETRY).await;
    }
}

#[cfg(test)]
mod tests {
    use axum::routing::get;

    use super::*;

    #[test]
    fn code_d_appairage() {
        let secret = [0xAB; 16];
        let code = encode_code(&secret);
        assert_eq!(code.len(), 39);
        assert_eq!(decode_code(&code).unwrap(), secret);
        assert_eq!(decode_code(&code.to_lowercase()).unwrap(), secret);
        assert!(decode_code("ABCD").is_err());
        assert!(decode_code(&"é".repeat(16)).is_err());
    }

    #[tokio::test]
    async fn preuve_mutuelle() {
        let good = async |relay: &'static [u8], gate: &'static [u8], seen: &'static [u8]| {
            let (mut a, mut b) = tokio::io::duplex(1024);
            let side = tokio::spawn(async move { greet(&mut a, relay, b"empreinte").await });
            let answer = hello(&mut b, gate, seen).await;
            drop(b);
            (side.await.unwrap(), answer)
        };
        let (relay, gate) = good(b"secret", b"secret", b"empreinte").await;
        assert!(relay.is_ok());
        assert_eq!(gate.unwrap(), env!("CARGO_PKG_VERSION"));
        assert!(good(b"autre", b"secret", b"empreinte").await.1.is_err(), "un faux relais est refusé");
        assert!(good(b"secret", b"secret", b"interceptee").await.1.is_err(), "un autre certificat est refusé");
    }

    /// Relais complet sur la boucle locale, avec une fausse Gate : le navigateur reçoit la réponse
    /// de la Gate, qui voit son adresse ; un secret faux ne donne rien.
    #[tokio::test]
    async fn parcours_complet() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("portunia-gate-relais-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::tls::write_self_signed(&["localhost".to_string()], "essai", &dir.join("t.crt"), &dir.join("t.key")).unwrap();
        let pem = std::fs::read(dir.join("t.crt")).unwrap();
        let key = std::fs::read(dir.join("t.key")).unwrap();
        let der = CertificateDer::from_pem_slice(&pem).unwrap();
        let secret = Arc::new(b"0123456789abcdef".to_vec());
        let pool = Arc::new(Pool::<tokio_rustls::server::TlsStream<TcpStream>>::new());
        let tunnel_port = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let public_port = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (tunnel_at, public_at) = (tunnel_port.local_addr().unwrap().to_string(), public_port.local_addr().unwrap());
        let tunnels = TlsAcceptor::from(server_config_from(&pem, &key, b"portunia-gate-relais").unwrap());
        let browsers = TlsAcceptor::from(server_config_from(&pem, &key, b"http/1.1").unwrap());
        tokio::spawn(tunnels_listener(tunnel_port, tunnels, secret.clone(), Arc::new(tls_fingerprint(&der)), pool.clone()));
        tokio::spawn(browsers_listener(public_port, browsers, pool.clone()));

        let tls = TlsConnector::from(client_config());
        assert!(wait_visitor(&tunnel_at, b"mauvais-secret", &tls, IDLE, None).await.is_err());
        tokio::spawn({
            let (address, secret, tls) = (tunnel_at.clone(), secret.clone(), tls.clone());
            async move {
                let (stream, ip) = wait_visitor(&address, &secret, &tls, IDLE, None).await.unwrap().unwrap();
                let router = Router::new().route("/", get(|ConnectInfo(a): ConnectInfo<SocketAddr>| async move { format!("visiteur {}", a.ip()) }));
                serve_portal(stream, ip, router).await;
            }
        });

        let mut browser_tls = client_config().as_ref().clone();
        browser_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tcp = TcpStream::connect(public_at).await.unwrap();
        let mut browser = TlsConnector::from(Arc::new(browser_tls)).connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap();
        browser.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut text = String::new();
        let _ = browser.read_to_string(&mut text).await;
        assert!(text.contains("200 OK") && text.contains("visiteur 127.0.0.1"), "{text}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Le terminal du portail passe par une WebSocket : la montée de protocole doit traverser.
    #[tokio::test]
    async fn websocket_a_travers_le_relais() {
        use axum::{extract::WebSocketUpgrade, response::IntoResponse};
        async fn upgrade(ws: WebSocketUpgrade) -> impl IntoResponse {
            ws.on_upgrade(|_| async {})
        }
        let router = Router::new().route("/ws", get(upgrade));
        let (gate, mut browser) = tokio::io::duplex(4096);
        tokio::spawn(serve_portal(gate, "203.0.113.5".parse().unwrap(), router));
        browser
            .write_all(b"GET /ws HTTP/1.1
Host: x
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==

")
            .await
            .unwrap();
        let mut head = [0u8; 12];
        browser.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 101");
    }

    #[tokio::test]
    async fn plus_de_connexion_morte() {
        let pool = Pool::<tokio::io::DuplexStream>::new();
        let (dead, gone) = tokio::io::duplex(64);
        drop(gone);
        pool.put(dead);
        let (live, mut gate) = tokio::io::duplex(64);
        pool.put(live);
        tokio::spawn(async move {
            let mut line = [0u8; 10];
            gate.read_exact(&mut line).await.unwrap();
            gate.write_u8(1).await.unwrap();
            std::future::pending::<()>().await;
        });
        assert!(pool.take("127.0.0.1".parse().unwrap()).await.is_some());
    }

    #[test]
    fn un_visiteur_ne_prend_pas_tout() {
        let visitors = Visitors::default();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let held: Vec<_> = (0..MAX_PER_ADDRESS).map(|_| visitors.enter(ip).unwrap()).collect();
        assert!(visitors.enter(ip).is_none());
        assert!(visitors.enter("203.0.113.6".parse().unwrap()).is_some());
        drop(held);
        assert!(visitors.enter(ip).is_some());
    }
}
