//! Portail web : accès aux serveurs depuis un navigateur, sans Portunia. Le mode d'exposition
//! (Cloudflare, interne, HTTPS direct, proxy ou WAF, relais dédié) décide qui peut joindre le portail et d'où
//! vient l'adresse réelle du visiteur ; un en-tête n'est cru que venant d'une source déclarée.
//!
//! - Écoute HTTP locale pour Cloudflare Tunnel (PORTUNIA_GATE_PORTAL_LISTEN, 127.0.0.1:8445), et
//!   au besoin HTTPS pour le proxy Cloudflare (PORTUNIA_GATE_PORTAL_TLS_LISTEN), réservée aux
//!   adresses de Cloudflare.
//! - Connexion : mot de passe et code toujours, Turnstile si configuré, essais limités, compte
//!   membre du groupe choisi. Pas d'enrôlement ni de changement de mot de passe ici.
//! - Terminal : le portail se connecte au serveur SSH de la Gate lui-même, pour l'utilisateur,
//!   avec un jeton à usage unique ; règles, coffre, enregistrement et journal sont donc ceux
//!   de toutes les sessions. Le navigateur reçoit le terminal par WebSocket.
//! - Pas d'administration : elle se fait dans Portunia (Administrer › Réglages › Portail web).

use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, Query, State as AxState,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
// TCP_NODELAY sur chaque connexion : la frappe et la souris (terminal, Bureau à distance)
// partent sans attendre l'accusé de réception du paquet précédent.
use axum_server::accept::NoDelayAcceptor;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use chrono::{DateTime, Utc};
use russh::{
    client,
    keys::{HashAlg, PublicKey, PublicKeyOrCertificate},
    ChannelMsg,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::watch;
use uuid::Uuid;

use crate::{
    audit, auth,
    keys::{random, sha256_hex},
    model::{self, User},
    State,
};

pub const COOKIE: &str = "portunia_gate_portail";
/// Réponse propre à ce démarrage de la Gate : l'essai de l'adresse publique vérifie que c'est elle.
pub const PING_PATH: &str = "/.well-known/portunia-gate";
static INSTANCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn instance_id() -> &'static str {
    INSTANCE.get_or_init(|| Uuid::new_v4().to_string())
}

static SERVICE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Ce processus est le service, et non une commande d'administration.
pub fn set_service() {
    SERVICE.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub fn is_service() -> bool {
    SERVICE.load(std::sync::atomic::Ordering::Relaxed)
}

async fn ping() -> &'static str {
    instance_id()
}
/// Avertissement avant la fermeture pour inactivité.
const IDLE_WARNING: Duration = Duration::from_secs(90);

// ---------- Sessions web en cours ----------

/// Sessions de terminal ouvertes dans des navigateurs : nombre, et signal pour les fermer
/// toutes (portail désactivé, « Fermer toutes les sessions web »).
pub struct Live {
    close: watch::Sender<u64>,
    active: AtomicUsize,
}

impl Default for Live {
    fn default() -> Self {
        Self {
            close: watch::Sender::new(0),
            active: AtomicUsize::new(0),
        }
    }
}

impl Live {
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Ferme tous les terminaux web ouverts.
    pub fn close_all(&self) {
        self.close.send_modify(|g| *g += 1);
    }

    pub fn active_inc(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn active_dec(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Signal de fermeture, pour une session web qui commence.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.close.subscribe()
    }
}

// ---------- Réglages ----------

pub struct Settings {
    pub enabled: bool,
    pub url: String,
    pub group: String,
    pub hours: i64,
    pub idle_min: i64,
    pub clipboard: bool,
    /// Code toujours exigé, sauf exception posée sur le compte ; sinon, la politique du compte décide.
    pub code_always: bool,
    pub turnstile_site: String,
    pub turnstile_secret: Option<String>,
}

async fn text_setting(state: &State, key: &str, default: &str) -> Result<String> {
    Ok(model::setting(&state.db, key)
        .await?
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| default.into()))
}

pub async fn settings(state: &State) -> Result<Settings> {
    let get = |key: &'static str| async move { model::setting(&state.db, key).await };
    let secret = match get("portail_turnstile_secret").await?.and_then(|v| v.as_str().map(str::to_owned)) {
        Some(sealed) if !sealed.is_empty() => {
            let bytes = base64::engine::general_purpose::STANDARD.decode(sealed)?;
            Some(String::from_utf8(state.keys.open("reglage:turnstile", &bytes)?)?)
        }
        _ => None,
    };
    Ok(Settings {
        enabled: get("portail_actif").await?.and_then(|v| v.as_bool()).unwrap_or(false),
        url: text_setting(state, "portail_url", "").await?,
        group: text_setting(state, "portail_groupe", "Accès web").await?,
        hours: get("portail_duree_h").await?.and_then(|v| v.as_i64()).unwrap_or(1).clamp(1, 12),
        idle_min: get("portail_inactivite_min").await?.and_then(|v| v.as_i64()).unwrap_or(15).clamp(5, 240),
        clipboard: get("portail_presse_papiers").await?.and_then(|v| v.as_bool()).unwrap_or(true),
        code_always: get("portail_code_toujours").await?.and_then(|v| v.as_bool()).unwrap_or(true),
        turnstile_site: text_setting(state, "portail_turnstile_site", "").await?,
        turnstile_secret: secret,
    })
}

// ---------- Exposition ----------

/// Comment les navigateurs atteignent le portail.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Mode {
    #[default]
    Cloudflare,
    Internal,
    Direct,
    Proxy,
    /// Seul un relais dédié peut joindre le portail (voir relay.rs).
    Relay,
}

impl Mode {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "cloudflare" => Some(Self::Cloudflare),
            "interne" | "internal" => Some(Self::Internal),
            "direct" => Some(Self::Direct),
            "proxy" => Some(Self::Proxy),
            "relais" | "relay" => Some(Self::Relay),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Internal => "interne",
            Self::Direct => "direct",
            Self::Proxy => "proxy",
            Self::Relay => "relais",
        }
    }
}

pub const DEFAULT_HEADER: &str = "X-Forwarded-For";

/// Réglages d'exposition gardés en mémoire : lus à chaque requête, sans passer par la base.
#[derive(Clone, Debug, Default)]
pub struct Exposure {
    pub mode: Mode,
    /// Mode proxy : seules adresses admises, et seules à pouvoir donner l'adresse réelle.
    pub proxies: Vec<String>,
    /// Mode proxy : en-tête qui porte l'adresse réelle.
    pub header: String,
    /// Modes interne et direct : réseaux admis.
    pub networks: Vec<String>,
    /// Mode Cloudflare : voisins dont cloudflared peut venir, en plus de la machine elle-même.
    pub tunnel_peers: Vec<String>,
}

fn listed(list: &[String], ip: IpAddr) -> bool {
    list.iter().any(|c| in_cidr(ip, c))
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

impl Exposure {
    /// Cette adresse peut-elle joindre le portail ? `tls` : par l'écoute HTTPS.
    fn admits(&self, tls: bool, ip: IpAddr) -> bool {
        match self.mode {
            Mode::Cloudflare => !tls || from_cloudflare(ip),
            Mode::Proxy => listed(&self.proxies, ip),
            Mode::Relay => false,
            Mode::Direct => self.networks.is_empty() || listed(&self.networks, ip),
            Mode::Internal if self.networks.is_empty() => is_private(ip),
            Mode::Internal => listed(&self.networks, ip),
        }
    }

    /// Adresse réelle du navigateur : l'en-tête n'est cru que venant d'une source déclarée.
    fn real_ip(&self, tls: bool, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let found = match self.mode {
            Mode::Cloudflare if tls && from_cloudflare(peer) => cloudflare_ip(headers),
            Mode::Cloudflare if !tls && (peer.is_loopback() || listed(&self.tunnel_peers, peer)) => cloudflare_ip(headers),
            Mode::Proxy if listed(&self.proxies, peer) => forwarded_ip(headers, &self.header, &self.proxies),
            _ => None,
        };
        found.unwrap_or(peer)
    }
}

fn cloudflare_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers.get("cf-connecting-ip")?.to_str().ok()?.trim().parse().ok()
}

fn parse_ip(text: &str) -> Option<IpAddr> {
    let text = text.trim();
    // Certains proxys ajoutent le port (Azure Application Gateway).
    text.parse().ok().or_else(|| text.parse::<SocketAddr>().ok().map(|a| a.ip()))
}

/// Lu de droite à gauche : le visiteur peut écrire ce qu'il veut à gauche, seul ce que nos proxys
/// ont ajouté à droite est sûr. La première adresse qui n'est pas un proxy est la sienne.
fn forwarded_ip(headers: &HeaderMap, name: &str, proxies: &[String]) -> Option<IpAddr> {
    let values: Vec<&str> = headers.get_all(name).iter().filter_map(|v| v.to_str().ok()).collect();
    for item in values.iter().rev().flat_map(|v| v.rsplit(',')) {
        let ip = parse_ip(item)?;
        if !listed(proxies, ip) {
            return Some(ip);
        }
    }
    None
}

/// Adresses ou réseaux saisis, ramenés à la forme adresse/masque. Erreur : l'entrée refusée.
pub fn parse_networks(items: &[String]) -> std::result::Result<Vec<String>, String> {
    let mut out = Vec::new();
    for item in items.iter().flat_map(|i| i.split([',', ' ', '\n'])).map(str::trim).filter(|i| !i.is_empty()) {
        let (addr, bits) = item.split_once('/').map_or((item, None), |(a, b)| (a, Some(b)));
        let ip: IpAddr = addr.parse().map_err(|_| item.to_string())?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            None => max,
            Some(b) => b.parse::<u32>().ok().filter(|b| *b <= max).ok_or_else(|| item.to_string())?,
        };
        out.push(format!("{ip}/{bits}"));
    }
    Ok(out)
}

async fn read_exposure(state: &State) -> Result<Exposure> {
    let list = |value: Option<serde_json::Value>| -> Vec<String> {
        value.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default()
    };
    let mode = text_setting(state, "portail_mode", "cloudflare").await?;
    Ok(Exposure {
        mode: Mode::parse(&mode).unwrap_or_default(),
        proxies: list(model::setting(&state.db, "portail_proxys").await?),
        header: text_setting(state, "portail_entete", DEFAULT_HEADER).await?,
        networks: list(model::setting(&state.db, "portail_reseaux").await?),
        tunnel_peers: state.config.portal_tunnel_peers.clone(),
    })
}

pub async fn reload_exposure(state: &State) -> Result<()> {
    let fresh = read_exposure(state).await?;
    *state.exposure.write().unwrap_or_else(|e| e.into_inner()) = fresh;
    Ok(())
}

pub fn exposure(state: &State) -> Exposure {
    state.exposure.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Change l'exposition (ce qui est absent reste tel quel). Commun à Portunia et à la ligne de
/// commande. Renvoie l'état obtenu, ou le message à montrer.
pub async fn set_exposure(state: &State, mode: Option<&str>, proxies: Option<&[String]>, header: Option<&str>, networks: Option<&[String]>) -> Result<Exposure> {
    let mut next = read_exposure(state).await?;
    if let Some(text) = mode {
        next.mode = Mode::parse(text).ok_or_else(|| anyhow!(t!("Mode: cloudflare, internal, direct, proxy or relay", "Mode : cloudflare, interne, direct, proxy ou relais")))?;
    }
    if let Some(items) = proxies {
        next.proxies = parse_networks(items).map_err(|bad| anyhow!(t!(format!("Invalid address: {bad}"), format!("Adresse invalide : {bad}"))))?;
    }
    if let Some(items) = networks {
        next.networks = parse_networks(items).map_err(|bad| anyhow!(t!(format!("Invalid address: {bad}"), format!("Adresse invalide : {bad}"))))?;
    }
    if let Some(text) = header {
        next.header = text.trim().to_string();
    }
    if axum::http::HeaderName::from_bytes(next.header.as_bytes()).is_err() {
        bail!(t!("Invalid header name", "Nom d'en-tête invalide"));
    }
    if next.mode == Mode::Relay && crate::relay::list(state).await?.is_empty() {
        bail!(t!("Relay mode: first add a relay", "Mode relais : ajoutez d'abord un relais"));
    }
    if next.mode == Mode::Proxy && next.proxies.is_empty() {
        bail!(t!("Proxy mode: give at least one trusted proxy address", "Mode proxy : indiquez au moins une adresse de proxy de confiance"));
    }
    model::set_setting(&state.db, "portail_mode", json!(next.mode.id())).await?;
    model::set_setting(&state.db, "portail_proxys", json!(next.proxies)).await?;
    model::set_setting(&state.db, "portail_entete", json!(next.header)).await?;
    model::set_setting(&state.db, "portail_reseaux", json!(next.networks)).await?;
    reload_exposure(state).await?;
    Ok(next)
}

// ---------- Serveur ----------

struct Portal {
    state: Arc<State>,
    /// Écoute HTTPS, celle qui peut être ouverte au réseau.
    tls: bool,
    /// Connexion passée par un relais dédié : ConnectInfo porte déjà l'adresse du visiteur.
    relayed: bool,
}

type Ctx = AxState<Arc<Portal>>;

pub async fn run(state: Arc<State>) -> Result<()> {
    reload_exposure(&state).await?;
    // La ligne de commande écrit en base depuis un autre processus.
    let refresh = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if let Err(e) = reload_exposure(&refresh).await {
                tracing::error!("{} {e}", t!("portal:", "portail :"));
            }
        }
    });
    let http = state.config.portal_listen.parse::<SocketAddr>().map_err(|_| anyhow!(t!("invalid PORTUNIA_GATE_PORTAL_LISTEN", "PORTUNIA_GATE_PORTAL_LISTEN invalide")))?;
    let plain = router(state.clone(), false);
    tracing::info!("{} http://{http} (Cloudflare Tunnel)", t!("web portal listening on", "portail web en écoute sur"));
    let plain_task = async move {
        let mut server = axum_server::bind(http).acceptor(NoDelayAcceptor);
        crate::http::limit(&mut server);
        server.serve(plain.into_make_service_with_connect_info::<SocketAddr>()).await.map_err(anyhow::Error::from)
    };
    tokio::try_join!(plain_task, serve_https(state)).map(|_| ())
}

// ---------- Écoute HTTPS ----------

const HTTPS_SETTING: &str = "portail_https";
/// Nouvel essai d'une adresse qui n'a pas pu être ouverte.
const HTTPS_RETRY: Duration = Duration::from_secs(60);

/// Adresse de l'écoute HTTPS voulue, et si elle est fixée par le fichier de configuration
/// (PORTUNIA_GATE_PORTAL_TLS_LISTEN, qui l'emporte alors sur l'administration).
pub async fn https_address(state: &State) -> Result<(Option<String>, bool)> {
    if let Some(a) = &state.config.portal_tls_listen {
        return Ok((Some(a.clone()), true));
    }
    let saved = model::setting(&state.db, HTTPS_SETTING).await?.and_then(|v| v.as_str().map(str::to_owned)).filter(|s| !s.is_empty());
    Ok((saved, false))
}

/// « 8446 », « :8446 », « 10.0.5.4:8446 » ou « [::]:8446 » ; toutes les interfaces par défaut.
pub fn parse_listen(input: &str, taken: &[(&str, &str)]) -> Result<String> {
    let input = input.trim();
    let text = if input.chars().all(|c| c.is_ascii_digit()) { format!("0.0.0.0:{input}") } else if let Some(port) = input.strip_prefix(':') { format!("0.0.0.0:{port}") } else { input.to_string() };
    let addr: SocketAddr = text.parse().map_err(|_| anyhow!(t!("HTTPS address: a port, or address:port (e.g. 0.0.0.0:8446)", "Adresse HTTPS : un port, ou adresse:port (ex. 0.0.0.0:8446)")))?;
    if addr.port() == 0 {
        bail!(t!("HTTPS address: port missing", "Adresse HTTPS : port manquant"));
    }
    for (what, other) in taken {
        if other.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) == Some(addr.port()) {
            bail!("{} {what}", t!("Port already used by", "Port déjà pris par"));
        }
    }
    Ok(addr.to_string())
}

/// Règle (ou coupe, si vide) l'écoute HTTPS. Appliqué sous quelques secondes par le service.
pub async fn set_https(state: &State, input: &str) -> Result<Option<String>> {
    if state.config.portal_tls_listen.is_some() {
        bail!(t!(
            "HTTPS listening is set by PORTUNIA_GATE_PORTAL_TLS_LISTEN in the configuration file: change it there",
            "L'écoute HTTPS est fixée par PORTUNIA_GATE_PORTAL_TLS_LISTEN dans le fichier de configuration : changez-la là"
        ));
    }
    let c = &state.config;
    let value = if input.trim().is_empty() {
        None
    } else {
        Some(parse_listen(input, &[("SSH", c.ssh_listen.as_str()), ("API", c.api_listen.as_str()), (t!("the Cloudflare tunnel", "le tunnel Cloudflare"), c.portal_listen.as_str())])?)
    };
    model::set_setting(&state.db, HTTPS_SETTING, json!(value.clone().unwrap_or_default())).await?;
    Ok(value)
}

#[derive(Clone, Default)]
pub struct HttpsStatus {
    /// Adresse ouverte en ce moment.
    pub listening: Option<String>,
    pub error: Option<String>,
}

static HTTPS: std::sync::Mutex<HttpsStatus> = std::sync::Mutex::new(HttpsStatus { listening: None, error: None });

pub fn https_status() -> HttpsStatus {
    HTTPS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn set_https_status(listening: Option<String>, error: Option<String>) {
    *HTTPS.lock().unwrap_or_else(|e| e.into_inner()) = HttpsStatus { listening, error };
}

/// Message lisible pour une adresse qui ne s'ouvre pas.
fn bind_error(addr: &SocketAddr, e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied if addr.port() < 1024 => t!(
            format!("port {} reserved to the system: use a port from 1024 (e.g. 8446) and redirect 443 to it on the firewall or the box", addr.port()),
            format!("port {} réservé au système : prenez un port à partir de 1024 (ex. 8446) et redirigez-y le 443 sur le pare-feu ou la box", addr.port())
        )
        .to_string(),
        std::io::ErrorKind::AddrInUse => t!(format!("port {} already used on this server", addr.port()), format!("port {} déjà utilisé sur ce serveur", addr.port())).to_string(),
        std::io::ErrorKind::AddrNotAvailable => t!(format!("{} is not an address of this server", addr.ip()), format!("{} n'est pas une adresse de ce serveur", addr.ip())).to_string(),
        _ => e.to_string(),
    }
}

/// Ouvre l'écoute HTTPS ; rend la main une fois le port ouvert.
async fn start_https(state: &Arc<State>, address: &str) -> Result<(axum_server::Handle, tokio::task::JoinHandle<()>)> {
    let addr: SocketAddr = address.parse().map_err(|_| anyhow!("{} {address}", t!("invalid HTTPS address:", "adresse HTTPS invalide :")))?;
    // Le port est essayé d'abord : son erreur est plus parlante que celle du serveur.
    drop(std::net::TcpListener::bind(addr).map_err(|e| anyhow!(bind_error(&addr, &e)))?);
    // Certificat choisi à chaque connexion : il change sans rouvrir l'écoute.
    crate::cert::refresh(state).await?;
    let config = axum_server::tls_rustls::RustlsConfig::from_config(crate::cert::server_config()?);
    let handle = axum_server::Handle::new();
    let secure = router(state.clone(), true);
    let mut server = axum_server::bind_rustls(addr, config).handle(handle.clone()).map(|a| a.acceptor(NoDelayAcceptor));
    crate::http::limit(&mut server);
    let task = tokio::spawn(async move {
        if let Err(e) = server.serve(secure.into_make_service_with_connect_info::<SocketAddr>()).await {
            tracing::error!("{} {e}", t!("portal HTTPS:", "portail HTTPS :"));
            set_https_status(None, Some(bind_error(&addr, &e)));
        }
    });
    match tokio::time::timeout(Duration::from_secs(5), handle.listening()).await {
        Ok(Some(_)) => Ok((handle, task)),
        _ => {
            task.abort();
            bail!(https_status().error.unwrap_or_else(|| t!("the HTTPS listener does not start", "l'écoute HTTPS ne démarre pas").to_string()))
        }
    }
}

/// Garde l'écoute HTTPS conforme au réglage : ouverte, déplacée ou fermée sans redémarrer la Gate.
async fn serve_https(state: Arc<State>) -> Result<()> {
    let mut running: Option<(String, axum_server::Handle, tokio::task::JoinHandle<()>)> = None;
    let mut failed: Option<(String, tokio::time::Instant)> = None;
    loop {
        if let Err(e) = crate::cert::refresh(&state).await {
            tracing::error!("{} {e:#}", t!("portal certificate:", "certificat du portail :"));
        }
        let wanted = match https_address(&state).await {
            Ok((a, _)) => a,
            Err(_) => running.as_ref().map(|r| r.0.clone()),
        };
        let current = running.as_ref().map(|r| r.0.clone());
        let stopped = running.as_ref().is_some_and(|r| r.2.is_finished());
        if wanted != current || stopped {
            if let Some((old, handle, task)) = running.take() {
                handle.graceful_shutdown(Some(Duration::from_secs(5)));
                let _ = task.await;
                tracing::info!("{} https://{old}", t!("web portal no longer listening on", "portail web plus en écoute sur"));
            }
            if !stopped {
                set_https_status(None, None);
            }
            if let Some(addr) = wanted {
                let retry = failed.as_ref().is_none_or(|(a, at)| *a != addr || at.elapsed() >= HTTPS_RETRY);
                if retry {
                    match start_https(&state, &addr).await {
                        Ok((handle, task)) => {
                            tracing::info!("{} https://{addr}", t!("web portal listening on", "portail web en écoute sur"));
                            set_https_status(Some(addr.clone()), None);
                            failed = None;
                            running = Some((addr, handle, task));
                        }
                        Err(e) => {
                            tracing::error!("{} {e}", t!("portal HTTPS:", "portail HTTPS :"));
                            set_https_status(None, Some(e.to_string()));
                            failed = Some((addr, tokio::time::Instant::now()));
                        }
                    }
                }
            } else {
                failed = None;
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Portail servi sur les connexions d'un relais dédié.
pub fn relayed_router(state: Arc<State>) -> Router {
    build_router(Portal { state, tls: false, relayed: true })
}

fn router(state: Arc<State>, tls: bool) -> Router {
    build_router(Portal { state, tls, relayed: false })
}

fn build_router(portal: Portal) -> Router {
    let portal = Arc::new(portal);
    Router::new()
        .route("/", get(page_index))
        .route(PING_PATH, get(ping))
        .route("/session/{nom}", get(page_session))
        .route("/static/{fichier}", get(asset))
        .route("/api/etat", get(status))
        .route("/api/connexion", post(login))
        .route("/api/deconnexion", post(logout))
        .route("/api/serveurs", get(servers))
        .route("/ws/{nom}", get(terminal))
        .route("/bureau/{nom}", get(page_desktop))
        .route("/api/rdp/{nom}", post(desktop_ticket))
        .route("/ws-rdp", get(desktop))
        // Assistance à distance : téléchargement de Portunia Assist et relais (sans compte).
        .route("/assistance", get(page_assist))
        .route("/assistance/portunia-assistance.exe", get(assist_agent_file))
        .route("/assistance/relais", get(assist_agent))
        // Interfaces web : entrée, puis chemins du serveur ; une adresse inconnue du portail va
        // au serveur web ouvert dans ce navigateur.
        .route("/web/{nom}", get(web_open))
        .route("/web/{nom}/", any(web_root))
        .route("/web/{nom}/{*rest}", any(web_path))
        .fallback(web_fallback)
        .layer(middleware::from_fn_with_state(portal.clone(), guard))
        // Pages et messages dans la langue du sélecteur ou du navigateur.
        .layer(middleware::from_fn(crate::lang::middleware))
        .layer(middleware::from_fn(crate::http::deadline))
        .with_state(portal)
}

// ---------- Sécurité commune ----------

/// Adresses de Cloudflare (https://www.cloudflare.com/ips/).
const CLOUDFLARE: &[&str] = &[
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
];

fn in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((net, bits)) = cidr.split_once('/') else { return false };
    let (Ok(net), Ok(bits)) = (net.parse::<IpAddr>(), bits.parse::<u32>()) else { return false };
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

fn from_cloudflare(ip: IpAddr) -> bool {
    CLOUDFLARE.iter().any(|c| in_cidr(ip, c))
}

/// Adresse réelle du navigateur, selon le mode d'exposition.
fn client_ip(portal: &Portal, peer: SocketAddr, headers: &HeaderMap) -> String {
    if portal.relayed {
        return peer.ip().to_string();
    }
    exposure(&portal.state).real_ip(portal.tls, peer.ip().to_canonical(), headers).to_string()
}

/// En-têtes de sécurité sur toutes les réponses ; ce que le mode d'exposition n'admet pas est refusé.
async fn guard(AxState(portal): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: axum::extract::Request, next: Next) -> Response {
    if !portal.relayed && !exposure(&portal.state).admits(portal.tls, peer.ip().to_canonical()) {
        return (StatusCode::FORBIDDEN, t!("Access restricted", "Accès restreint")).into_response();
    }
    let mut res = next.run(req).await;
    // Page d'un serveur web relayé : ses propres règles de sécurité, pas celles du portail.
    if res.extensions().get::<crate::webproxy::Proxied>().is_some() {
        return res;
    }
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            // 'wasm-unsafe-eval' et data: : le client Bureau à distance (IronRDP) est un module
            // WebAssembly embarqué dans son script, chargé depuis une adresse data:.
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert("permissions-policy", HeaderValue::from_static("camera=(), microphone=(), geolocation=()"));
    // Le navigateur ne revient plus en HTTP (ignoré tant que la page arrive en HTTP simple).
    h.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

/// Requête d'écriture venue de la page elle-même (en-tête ajouté par son script, et même
/// origine que l'adresse publique si elle est réglée) : protège contre les envois croisés.
fn same_site(headers: &HeaderMap, public_url: &str) -> bool {
    if headers.get("x-portunia-gate").and_then(|v| v.to_str().ok()) != Some("portail") {
        return false;
    }
    match (headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()), public_url.trim_end_matches('/')) {
        (Some(origin), url) if !url.is_empty() => origin.trim_end_matches('/') == url,
        _ => true,
    }
}

fn err(status: StatusCode, text: &str) -> Response {
    (status, Json(json!({ "erreur": text }))).into_response()
}

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!("{} {e}", t!("portal:", "portail :"));
    err(StatusCode::INTERNAL_SERVER_ERROR, t!("Gate error", "Erreur de la Gate"))
}

// ---------- Pages et fichiers ----------

const INDEX: &str = include_str!("../portail/index.html");
const SESSION: &str = include_str!("../portail/session.html");
const DESKTOP: &str = include_str!("../portail/bureau.html");
const ASSIST: &str = include_str!("../portail/assistance.html");

/// Pages et scripts portent la version de la Gate dans les adresses de leurs fichiers
/// (`?v=__V__`) : après une mise à jour, le navigateur charge les nouveaux, pas ceux en cache.
fn versioned(text: &str) -> String {
    text.replace("__V__", env!("CARGO_PKG_VERSION"))
}

/// Page dans la langue de la requête : `__L__` devient « en » ou « fr », `{{English|Français}}`
/// le texte de cette langue.
fn localized(html: &str) -> String {
    let fr = crate::lang::is_fr();
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let Some(end) = rest[start..].find("}}") else { break };
        let inner = &rest[start + 2..start + end];
        let (en, fr_text) = inner.split_once('|').unwrap_or((inner, inner));
        out.push_str(if fr { fr_text } else { en });
        rest = &rest[start + end + 2..];
    }
    out.push_str(rest);
    out.replace("__L__", crate::lang::get().code())
}

fn page(html: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
            (header::VARY, "Cookie, Accept-Language"),
        ],
        localized(&versioned(html)),
    )
        .into_response()
}

/// Racine du portail. Ses propres pages y reviennent par « /?accueil ». « / » seul, demandé
/// depuis une page du site (lien, redirection en JavaScript : beaucoup d'applications sont en
/// « no-referrer ») alors qu'une interface web est ouverte : racine de cette interface.
/// Adresse tapée ou favori (`Sec-Fetch-Site: none`) : accueil du portail.
async fn page_index(st: Ctx, peer: ConnectInfo<SocketAddr>, req: axum::extract::Request) -> Response {
    if web_root_request(req.uri().query(), req.headers()) {
        return web_fallback(st, peer, req).await;
    }
    page(INDEX)
}

fn web_root_request(query: Option<&str>, headers: &HeaderMap) -> bool {
    if query.is_some_and(|q| q.split('&').any(|p| p == "accueil")) || crate::webproxy::cookie(headers, crate::webproxy::APP_COOKIE).is_none() {
        return false;
    }
    let site = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok());
    headers.contains_key(header::REFERER) || site == Some("same-origin")
}

async fn page_session(Path(_nom): Path<String>) -> Response {
    page(SESSION)
}

async fn page_assist() -> Response {
    page(ASSIST)
}

/// Portunia Assist, gardé par la Gate (téléchargé à l'activation de l'assistance).
async fn assist_agent_file(AxState(portal): Ctx) -> Response {
    let state = &portal.state;
    match crate::assist::settings(state).await {
        Ok(s) if s.enabled => {}
        _ => return err(StatusCode::NOT_FOUND, t!("Remote assistance is disabled", "Assistance à distance désactivée")),
    }
    match tokio::fs::read(crate::assist::agent_file(state)).await {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, HeaderValue::from_static("application/vnd.microsoft.portable-executable")),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => err(StatusCode::NOT_FOUND, t!("Program not available yet", "Programme pas encore disponible")),
    }
}

/// Relais : connexion de Portunia Assist (personne aidée, sans compte).
async fn assist_agent(AxState(portal): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    let addr = client_ip(&portal, peer, &headers);
    let state = portal.state.clone();
    let lang = crate::lang::get();
    ws.on_upgrade(move |socket| crate::lang::scope(lang, crate::assist::agent(state, socket, addr)))
}

async fn page_desktop(Path(_nom): Path<String>) -> Response {
    page(DESKTOP)
}

/// Version gzip d'une ressource, calculée à la première demande puis gardée.
async fn gzipped(name: &'static str, body: &'static [u8]) -> Option<&'static [u8]> {
    static DONE: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<&'static str, &'static [u8]>>> = std::sync::LazyLock::new(Default::default);
    if let Some(z) = DONE.lock().unwrap().get(name) {
        return Some(z);
    }
    let z = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::with_capacity(body.len() / 3), flate2::Compression::best());
        enc.write_all(body).ok()?;
        enc.finish().ok()
    })
    .await
    .ok()??;
    // Quelques fichiers fixes : gardés pour toute la vie du service.
    let z: &'static [u8] = DONE.lock().unwrap().entry(name).or_insert_with(|| Box::leak(z.into_boxed_slice()));
    Some(z)
}

async fn asset(Path(fichier): Path<String>, headers: HeaderMap) -> Response {
    let (kind, body): (&str, &'static [u8]) = match fichier.as_str() {
        "app.css" => ("text/css; charset=utf-8", include_bytes!("../portail/app.css")),
        "app.js" => ("text/javascript; charset=utf-8", include_bytes!("../portail/app.js")),
        "session.js" => ("text/javascript; charset=utf-8", include_bytes!("../portail/session.js")),
        "assistance.js" => ("text/javascript; charset=utf-8", include_bytes!("../portail/assistance.js")),
        "xterm.js" => ("text/javascript; charset=utf-8", include_bytes!("../portail/xterm.js")),
        "xterm.css" => ("text/css; charset=utf-8", include_bytes!("../portail/xterm.css")),
        "addon-fit.js" => ("text/javascript; charset=utf-8", include_bytes!("../portail/addon-fit.js")),
        // Ses imports portent aussi la version.
        "bureau.js" => {
            let text = versioned(include_str!("../portail/bureau.js"));
            return ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8"), (header::CACHE_CONTROL, "public, max-age=86400")], text).into_response();
        }
        "iron-remote-desktop.js" => ("text/javascript; charset=utf-8", include_bytes!("../portail/iron-remote-desktop.js")),
        "iron-remote-desktop-rdp.js" => ("text/javascript; charset=utf-8", include_bytes!("../portail/iron-remote-desktop-rdp.js")),
        "favicon.png" => ("image/png", include_bytes!("../portail/favicon.png")),
        "icone.png" => ("image/png", include_bytes!("../portail/icone.png")),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if kind.starts_with("image/") {
        return ([(header::CONTENT_TYPE, kind), (header::CACHE_CONTROL, "public, max-age=86400")], body).into_response();
    }
    // Adresses versionnées (?v=) : la version suivante de la Gate change l'adresse, le
    // navigateur peut garder celle-ci sans la redemander.
    let cache = "public, max-age=31536000, immutable";
    // Scripts et styles compressés (le client Bureau à distance passe de 6 Mo à environ 2).
    let gzip = headers.get(header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok()).is_some_and(|v| v.split(',').any(|e| e.trim().starts_with("gzip")));
    if gzip && body.len() > 16 * 1024 {
        let name: &'static str = match fichier.as_str() {
            "xterm.js" => "xterm.js",
            "iron-remote-desktop.js" => "iron-remote-desktop.js",
            "iron-remote-desktop-rdp.js" => "iron-remote-desktop-rdp.js",
            "app.css" => "app.css",
            _ => "",
        };
        if !name.is_empty() {
            if let Some(z) = gzipped(name, body).await {
                return (
                    [(header::CONTENT_TYPE, kind), (header::CACHE_CONTROL, cache), (header::CONTENT_ENCODING, "gzip"), (header::VARY, "Accept-Encoding")],
                    z,
                )
                    .into_response();
            }
        }
    }
    ([(header::CONTENT_TYPE, kind), (header::CACHE_CONTROL, cache), (header::VARY, "Accept-Encoding")], body).into_response()
}

// ---------- Session du navigateur ----------

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
}

struct WebSession {
    user: User,
    expires: DateTime<Utc>,
}

/// Session du navigateur : valable, pas expirée, compte actif et toujours dans le groupe.
async fn web_session(portal: &Portal, headers: &HeaderMap, s: &Settings) -> Result<Option<WebSession>> {
    let Some(token) = cookie_token(headers) else { return Ok(None) };
    let db = &portal.state.db;
    let row: Option<(Uuid, DateTime<Utc>, DateTime<Utc>)> =
        sqlx::query_as("SELECT user_id, expires_at, last_seen FROM web_sessions WHERE token_hash = $1")
            .bind(sha256_hex(token.as_bytes()))
            .fetch_optional(db)
            .await?;
    let Some((user_id, expires, last_seen)) = row else { return Ok(None) };
    let idle = Utc::now() - last_seen > chrono::Duration::minutes(s.idle_min);
    if expires < Utc::now() || idle || !s.enabled {
        sqlx::query("DELETE FROM web_sessions WHERE token_hash = $1").bind(sha256_hex(token.as_bytes())).execute(db).await?;
        return Ok(None);
    }
    let Some(user) = model::user_by_id(db, user_id).await?.filter(|u| !u.disabled) else { return Ok(None) };
    if !in_group(db, user.id, &s.group).await? {
        return Ok(None);
    }
    sqlx::query("UPDATE web_sessions SET last_seen = now() WHERE token_hash = $1")
        .bind(sha256_hex(token.as_bytes()))
        .execute(db)
        .await?;
    Ok(Some(WebSession { user, expires }))
}

pub(crate) async fn in_group(db: &sqlx::PgPool, user: Uuid, group: &str) -> Result<bool> {
    if group.trim().is_empty() {
        return Ok(false);
    }
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM group_members m JOIN groups g ON g.id = m.group_id WHERE m.user_id = $1 AND lower(g.name) = lower($2))",
    )
    .bind(user)
    .bind(group.trim())
    .fetch_one(db)
    .await?)
}

async fn status(AxState(portal): Ctx, headers: HeaderMap) -> Response {
    let result = async {
        let state = &portal.state;
        let s = settings(state).await?;
        let session = web_session(&portal, &headers, &s).await?;
        Ok::<_, anyhow::Error>(json!({
            "actif": s.enabled,
            "nom": text_setting(state, "nom", "Portunia Gate").await?,
            "banniere": text_setting(state, "banniere", crate::sshd::default_banner()).await?,
            "turnstile": (!s.turnstile_site.is_empty() && s.turnstile_secret.is_some()).then_some(s.turnstile_site.clone()),
            "presse_papiers": s.clipboard,
            "code_facultatif": !s.code_always,
            "inactivite_min": s.idle_min,
            "connecte": session.map(|w| json!({ "login": w.user.login, "expire": w.expires })),
        }))
    }
    .await;
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
struct LoginBody {
    login: String,
    mot_de_passe: String,
    code: String,
    #[serde(default)]
    turnstile: String,
}

/// Échec (déjà compté comme essai) : même message quel que soit le motif.
async fn failed(portal: &Portal, login: &str, ip: &str, why: &str) -> Response {
    audit::note(
        &portal.state.db,
        login,
        "portail.echec",
        json!({ "raison": why, "adresse": ip }),
    )
    .await;
    err(StatusCode::UNAUTHORIZED, t!("Wrong login, password or code", "Identifiant, mot de passe ou code incorrect"))
}

/// Vérification Turnstile auprès de Cloudflare.
async fn turnstile_ok(secret: &str, response: &str, ip: &str) -> bool {
    if response.is_empty() {
        return false;
    }
    let (secret, response, ip) = (secret.to_string(), response.to_string(), ip.to_string());
    tokio::task::spawn_blocking(move || {
        let answer = ureq::post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .timeout(Duration::from_secs(10))
            .send_form(&[("secret", secret.as_str()), ("response", response.as_str()), ("remoteip", ip.as_str())]);
        match answer.ok().and_then(|r| r.into_string().ok()) {
            Some(body) => serde_json::from_str::<Value>(&body).ok().and_then(|v| v["success"].as_bool()).unwrap_or(false),
            None => false,
        }
    })
    .await
    .unwrap_or(false)
}

async fn login(AxState(portal): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(body): Json<LoginBody>) -> Response {
    let ip = client_ip(&portal, peer, &headers);
    let result = async {
        let state = &portal.state;
        let s = settings(state).await?;
        if !s.enabled {
            return Ok(err(StatusCode::SERVICE_UNAVAILABLE, t!("Portal closed", "Portail fermé")));
        }
        if !same_site(&headers, &s.url) {
            return Ok(err(StatusCode::FORBIDDEN, t!("Request refused", "Requête refusée")));
        }
        let login = body.login.trim().to_string();
        if let crate::limits::Verdict::Blocked { first } = state.limits.attempt(&login, &ip) {
            if first {
                audit::note(&state.db, &login, "auth.bloquee", json!({ "methode": "portail", "adresse": ip })).await;
            }
            return Ok(err(StatusCode::TOO_MANY_REQUESTS, t!("Too many attempts: try again in a few minutes", "Trop d'essais : réessayez dans quelques minutes")));
        }
        if let Some(secret) = s.turnstile_secret.as_deref().filter(|_| !s.turnstile_site.is_empty()) {
            if !turnstile_ok(secret, &body.turnstile, &ip).await {
                return Ok(err(StatusCode::FORBIDDEN, t!("Anti-bot check failed: reload the page", "Vérification anti-robots échouée : rechargez la page")));
            }
        }
        let Some(user) = model::user_by_login(&state.db, &login).await?.filter(|u| !u.disabled) else {
            auth::burn_password(body.mot_de_passe.clone()).await;
            return Ok(failed(&portal, &login, &ip, "compte inconnu ou désactivé").await);
        };
        if !auth::check_password(user.password_hash.clone(), body.mot_de_passe.clone()).await {
            return Ok(failed(&portal, &login, &ip, "mot de passe incorrect").await);
        }
        // Une politique propre au compte décide (exception sans code, ou code imposé) ;
        // sans elle, le réglage du portail.
        let password_only = BTreeSet::from([auth::Factor::Password]);
        let need_code = match &user.auth_policy {
            Some(text) => !auth::Policy::parse(text)?.satisfied(&password_only),
            None => s.code_always,
        };
        // Première connexion et code perdu : pas depuis Internet.
        if user.must_change_password || (need_code && user.totp_secret.is_none()) {
            audit::note(&state.db, &login, "portail.echec", json!({ "raison": "première connexion ou code non enrôlé", "adresse": ip })).await;
            return Ok(err(
                StatusCode::FORBIDDEN,
                t!("First sign-in or code not enrolled: sign in with Portunia first, or contact your administrator", "Première connexion ou code non enrôlé : connectez-vous d'abord avec Portunia, ou adressez-vous à votre administrateur"),
            ));
        }
        if need_code {
            let secret = state.keys.open(&format!("totp:{}", user.id), user.totp_secret.as_deref().unwrap_or_default())?;
            let ok = match auth::totp_check(&secret, body.code.trim(), user.totp_last_step) {
                Some(step) => model::consume_totp_step(&state.db, user.id, step).await?,
                None => false,
            };
            if !ok {
                return Ok(failed(&portal, &login, &ip, "code incorrect ou déjà utilisé").await);
            }
        }
        if !in_group(&state.db, user.id, &s.group).await? {
            audit::note(&state.db, &login, "portail.echec", json!({ "raison": "hors du groupe du portail", "adresse": ip })).await;
            return Ok(err(StatusCode::FORBIDDEN, t!("This account has no access to the web portal", "Ce compte n'a pas accès au portail web")));
        }
        state.limits.success(&login, &ip);
        let token = B64URL.encode(random::<32>()?);
        let expires = Utc::now() + chrono::Duration::hours(s.hours);
        sqlx::query("DELETE FROM web_sessions WHERE expires_at < now()").execute(&state.db).await?;
        sqlx::query("INSERT INTO web_sessions (token_hash, user_id, expires_at, address) VALUES ($1, $2, $3, $4)")
            .bind(sha256_hex(token.as_bytes()))
            .bind(user.id)
            .bind(expires)
            .bind(&ip)
            .execute(&state.db)
            .await?;
        audit::note(&state.db, &user.login, "portail.connexion", json!({ "facteurs": if need_code { json!(["mot de passe", "code"]) } else { json!(["mot de passe"]) }, "adresse": ip })).await;
        let cookie = format!("{COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}", s.hours * 3600);
        Ok::<_, anyhow::Error>(
            (
                [(header::SET_COOKIE, cookie)],
                Json(json!({ "etat": "ok", "login": user.login, "expire": expires })),
            )
                .into_response(),
        )
    }
    .await;
    result.unwrap_or_else(internal)
}

async fn logout(AxState(portal): Ctx, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_token(&headers) {
        let _ = sqlx::query("DELETE FROM web_sessions WHERE token_hash = $1")
            .bind(sha256_hex(token.as_bytes()))
            .execute(&portal.state.db)
            .await;
    }
    (
        [(header::SET_COOKIE, format!("{COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"))],
        Json(json!({ "etat": "ok" })),
    )
        .into_response()
}

/// Peut s'ouvrir dans le navigateur : tout, sauf SSH en mode rebond (de bout en bout, il faut
/// Portunia). Bureau à distance en rebond : la Gate relaie sans enregistrer.
fn web_ready(t: &model::Target) -> Option<&'static str> {
    if !t.is_rdp() && t.mode == "rebond" {
        Some(t!("Only available with Portunia (end-to-end relay)", "Disponible seulement avec Portunia (relais de bout en bout)"))
    } else {
        None
    }
}

async fn servers(AxState(portal): Ctx, headers: HeaderMap) -> Response {
    let result = async {
        let state = &portal.state;
        let s = settings(state).await?;
        let Some(w) = web_session(&portal, &headers, &s).await? else {
            return Ok(err(StatusCode::UNAUTHORIZED, t!("Session expired", "Session expirée")));
        };
        let list: Vec<Value> = model::allowed_targets(&state.db, w.user.id)
            .await?
            .iter()
            .map(|t| {
                json!({
                    "nom": t.name, "dossier": t.folder, "protocole": t.protocole,
                    "mode": t.mode, "compte": t.account, "indisponible": web_ready(t),
                })
            })
            .collect();
        Ok::<_, anyhow::Error>(Json(json!({ "serveurs": list, "login": w.user.login, "expire": w.expires })).into_response())
    }
    .await;
    result.unwrap_or_else(internal)
}

// ---------- Terminal ----------

#[derive(Deserialize)]
struct Size {
    cols: Option<u32>,
    rows: Option<u32>,
}

async fn terminal(
    AxState(portal): Ctx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(nom): Path<String>,
    Query(size): Query<Size>,
    ws: WebSocketUpgrade,
) -> Response {
    let ip = client_ip(&portal, peer, &headers);
    let prepared = async {
        let state = &portal.state;
        let s = settings(state).await?;
        // Une page d'un autre site ne doit pas pouvoir ouvrir de terminal avec le cookie.
        if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default();
            let expected = s.url.trim_end_matches('/');
            let same = if expected.is_empty() { origin.ends_with(&format!("//{host}")) } else { origin.trim_end_matches('/') == expected };
            if !same {
                return Ok(Err(err(StatusCode::FORBIDDEN, t!("Origin refused", "Origine refusée"))));
            }
        }
        let Some(w) = web_session(&portal, &headers, &s).await? else {
            return Ok(Err(err(StatusCode::UNAUTHORIZED, t!("Session expired", "Session expirée"))));
        };
        let target = model::target_by_name(&state.db, &nom).await?.filter(|t| t.is_ssh() && web_ready(t).is_none());
        let Some(target) = target else {
            return Ok(Err(err(StatusCode::NOT_FOUND, t!("Server unavailable in the browser", "Serveur indisponible dans le navigateur"))));
        };
        if model::access(&state.db, w.user.id, target.id).await?.is_none() {
            return Ok(Err(err(StatusCode::FORBIDDEN, t!("Server not allowed at the moment", "Serveur non autorisé en ce moment"))));
        }
        let ticket = crate::api::issue_ticket(&state.db, w.user.id, target.id, Some(&format!("{ip} (web)"))).await?;
        Ok::<_, anyhow::Error>(Ok((w, target, ticket, s.idle_min)))
    }
    .await;
    let (w, target, ticket, idle_min) = match prepared {
        Ok(Ok(v)) => v,
        Ok(Err(r)) => return r,
        Err(e) => return internal(e),
    };
    let cols = size.cols.unwrap_or(120).clamp(20, 500);
    let rows = size.rows.unwrap_or(32).clamp(5, 200);
    // La tâche du WebSocket ne garde pas la langue de la requête : on la lui passe.
    let lang = crate::lang::get();
    ws.on_upgrade(move |socket| crate::lang::scope(lang, async move {
        let state = portal.state.clone();
        state.web.active.fetch_add(1, Ordering::Relaxed);
        let user = format!("{}%{}", w.user.login, target.name);
        let (_watch, cut) = state.live.watch(crate::live::Watched { user: w.user.id, login: &w.user.login, target: Some(&target), web: true, recorded: false });
        if let Err(e) = bridge(&state, socket, &user, &ticket, cols, rows, w.expires, idle_min, cut).await {
            tracing::warn!("{} {user}: {e:#}", t!("portal: terminal", "portail : terminal"));
        }
        state.web.active.fetch_sub(1, Ordering::Relaxed);
    }))
}

// ---------- Bureau à distance ----------

/// Origine de la page : la même que l'adresse publique (ou que l'hôte demandé si elle n'est pas réglée).
fn origin_ok(headers: &HeaderMap, public_url: &str) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else { return true };
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let expected = public_url.trim_end_matches('/');
    if expected.is_empty() {
        origin.ends_with(&format!("//{host}"))
    } else {
        origin.trim_end_matches('/') == expected
    }
}

/// Jeton à usage unique pour ouvrir un serveur Bureau à distance depuis la page : le client
/// RDP du navigateur le présente au passage (/ws-rdp).
async fn desktop_ticket(AxState(portal): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Path(nom): Path<String>) -> Response {
    let ip = client_ip(&portal, peer, &headers);
    let result = async {
        let state = &portal.state;
        let s = settings(state).await?;
        if !same_site(&headers, &s.url) {
            return Ok(err(StatusCode::FORBIDDEN, t!("Request refused", "Requête refusée")));
        }
        let Some(w) = web_session(&portal, &headers, &s).await? else {
            return Ok(err(StatusCode::UNAUTHORIZED, t!("Session expired", "Session expirée")));
        };
        let target = model::target_by_name(&state.db, &nom).await?.filter(|t| t.is_rdp() && web_ready(t).is_none());
        let Some(target) = target else {
            return Ok(err(StatusCode::NOT_FOUND, t!("Server unavailable in the browser", "Serveur indisponible dans le navigateur")));
        };
        let Some(access) = model::access(&state.db, w.user.id, target.id).await? else {
            return Ok(err(StatusCode::FORBIDDEN, t!("Server not allowed at the moment", "Serveur non autorisé en ce moment")));
        };
        let ticket = crate::api::issue_ticket(&state.db, w.user.id, target.id, Some(&format!("{ip} (web)"))).await?;
        // « fichiers » : la page propose la copie de fichiers (la Gate la bloque sinon).
        // « coffre » : la Gate ouvre la session Windows ; la page s'authentifie avec le jeton.
        Ok::<_, anyhow::Error>(Json(json!({ "jeton": ticket, "compte": target.account, "fichiers": access.files, "coffre": target.vaulted() })).into_response())
    }
    .await;
    result.unwrap_or_else(internal)
}

/// Passage RDCleanPath du client RDP du navigateur.
async fn desktop(AxState(portal): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    let addr = client_ip(&portal, peer, &headers);
    let s = match settings(&portal.state).await {
        Ok(s) if s.enabled => s,
        Ok(_) => return err(StatusCode::SERVICE_UNAVAILABLE, t!("Portal closed", "Portail fermé")),
        Err(e) => return internal(e),
    };
    if !origin_ok(&headers, &s.url) {
        return err(StatusCode::FORBIDDEN, t!("Origin refused", "Origine refusée"));
    }
    let session = match web_session(&portal, &headers, &s).await {
        Ok(Some(w)) => w,
        Ok(None) => return err(StatusCode::UNAUTHORIZED, t!("Session expired", "Session expirée")),
        Err(e) => return internal(e),
    };
    let state = portal.state.clone();
    let lang = crate::lang::get();
    let origin = crate::rdp::Origin::Portal {
        addr,
        user: session.user.id,
        expires: session.expires,
        idle: Duration::from_secs(s.idle_min as u64 * 60),
    };
    ws.on_upgrade(move |socket| crate::lang::scope(lang, crate::rdp::relay(state, socket, origin)))
}

/// Accepte seulement la clé de la Gate lui-même (connexion locale).
struct Local {
    expected: String,
}

impl client::Handler for Local {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let public = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => PublicKey::new(cert.public_key().clone(), ""),
        };
        Ok(public.fingerprint(HashAlg::Sha256).to_string() == self.expected)
    }
}

async fn send_json(socket: &mut WebSocket, value: Value) -> bool {
    socket.send(Message::Text(value.to_string().into())).await.is_ok()
}

/// Relie le navigateur au serveur SSH de la Gate : sortie du terminal en binaire, saisie et
/// commandes (taille, « je suis là ») en JSON.
#[allow(clippy::too_many_arguments)]
async fn bridge(state: &State, mut socket: WebSocket, user: &str, ticket: &str, cols: u32, rows: u32, expires: DateTime<Utc>, idle_min: i64, mut cut: crate::live::Cut) -> Result<()> {
    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let handler = Local { expected: state.keys.host_fingerprint() };
    let mut handle = tokio::time::timeout(Duration::from_secs(15), client::connect(config, ("127.0.0.1", state.config.ssh_local_port()), handler))
        .await
        .map_err(|_| anyhow!(t!("the Gate's SSH server is not answering", "le serveur SSH de la Gate ne répond pas")))??;
    if !handle.authenticate_password(user, ticket).await?.success() {
        send_json(&mut socket, json!({ "t": "ferme", "raison": t!("Access denied by the Gate", "Accès refusé par la Gate") })).await;
        return Ok(());
    }
    let channel = handle.channel_open_session().await?;
    channel.request_pty(true, "xterm-256color", cols, rows, 0, 0, &[]).await?;
    channel.request_shell(true).await?;
    let (mut reader, writer) = channel.split();

    let mut closing = state.web.close.subscribe();
    let idle = Duration::from_secs(idle_min as u64 * 60);
    let mut last_input = Instant::now();
    let mut warned = false;
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let reason: String = loop {
        tokio::select! {
            msg = reader.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if socket.send(Message::Binary(data.to_vec().into())).await.is_err() {
                        break "navigateur fermé".into();
                    }
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break t!("Session ended", "Session terminée").into(),
                _ => {}
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    let Ok(v) = serde_json::from_str::<Value>(text.as_str()) else { continue };
                    last_input = Instant::now();
                    warned = false;
                    match v["t"].as_str() {
                        Some("in") => {
                            let data = v["d"].as_str().unwrap_or_default();
                            writer.data(data.as_bytes()).await?;
                        }
                        Some("taille") => {
                            let (c, r) = (v["c"].as_u64().unwrap_or(80) as u32, v["r"].as_u64().unwrap_or(24) as u32);
                            writer.window_change(c.clamp(20, 500), r.clamp(5, 200), 0, 0).await?;
                        }
                        _ => {}
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break "navigateur fermé".into(),
                _ => {}
            },
            _ = closing.changed() => break t!("Session closed by the administrator", "Session fermée par l'administrateur").into(),
            why = cut.reason() => break why,
            _ = tick.tick() => {
                if Utc::now() >= expires {
                    break t!("Web session expired: sign in again", "Session web expirée : reconnectez-vous").into();
                }
                let quiet = last_input.elapsed();
                if quiet >= idle {
                    break t!("Session closed after a period of inactivity", "Session fermée après une période d'inactivité").into();
                }
                if !warned && quiet + IDLE_WARNING >= idle {
                    warned = true;
                    send_json(&mut socket, json!({ "t": "inactif", "s": (idle - quiet).as_secs() })).await;
                }
            }
        }
    };
    send_json(&mut socket, json!({ "t": "ferme", "raison": reason })).await;
    let _ = writer.eof().await;
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
    let _ = socket.send(Message::Close(None)).await;
    Ok(())
}

// ---------- Administration (appelée par l'API) ----------

/// Clé du secret Turnstile, chiffrée par le coffre de la Gate.
pub fn seal_turnstile(state: &State, secret: &str) -> Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(state.keys.seal("reglage:turnstile", secret.as_bytes())?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn racine_accueil_ou_interface_web() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.insert(*k, HeaderValue::from_static(v));
            }
            h
        };
        let app = ("cookie", "portunia_gate_web=mail");
        // Redirection de l'application en JavaScript, sans Referer : vers l'application.
        assert!(web_root_request(None, &headers(&[app, ("sec-fetch-site", "same-origin")])));
        assert!(web_root_request(None, &headers(&[app, ("referer", "https://gate/web/mail/login")])));
        // Accueil demandé par le portail, adresse tapée, ou aucune interface ouverte : portail.
        assert!(!web_root_request(Some("accueil"), &headers(&[app, ("sec-fetch-site", "same-origin")])));
        assert!(!web_root_request(None, &headers(&[app, ("sec-fetch-site", "none")])));
        assert!(!web_root_request(None, &headers(&[("sec-fetch-site", "same-origin")])));
    }

    #[tokio::test]
    async fn ressource_compressee() {
        let body: &'static [u8] = include_bytes!("../portail/iron-remote-desktop-rdp.js");
        let z = gzipped("iron-remote-desktop-rdp.js", body).await.unwrap();
        assert!(z.len() < body.len() / 2, "{} → {}", body.len(), z.len());
        let mut back = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(z), &mut back).unwrap();
        assert_eq!(back, body);
        // Deuxième demande : la même version gardée.
        assert!(std::ptr::eq(z, gzipped("iron-remote-desktop-rdp.js", body).await.unwrap()));
    }

    #[test]
    fn adresse_https() {
        let taken = [("SSH", "0.0.0.0:2222"), ("API", "0.0.0.0:8443")];
        assert_eq!(parse_listen("8446", &taken).unwrap(), "0.0.0.0:8446");
        assert_eq!(parse_listen(":8446", &taken).unwrap(), "0.0.0.0:8446");
        assert_eq!(parse_listen("10.0.5.4:8446", &taken).unwrap(), "10.0.5.4:8446");
        assert_eq!(parse_listen("[::]:443", &taken).unwrap(), "[::]:443");
        assert!(parse_listen("8443", &taken).is_err(), "port de l'API");
        assert!(parse_listen("bonjour", &taken).is_err());
        assert!(parse_listen("0.0.0.0:0", &taken).is_err());
    }

    #[test]
    fn adresses_cloudflare() {
        assert!(from_cloudflare("104.16.1.1".parse().unwrap()));
        assert!(from_cloudflare("2606:4700::1".parse().unwrap()));
        assert!(!from_cloudflare("192.168.1.10".parse().unwrap()));
        assert!(!from_cloudflare("8.8.8.8".parse().unwrap()));
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn with(name: &'static str, value: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.append(name, HeaderValue::from_static(value));
        h
    }

    fn behind_proxy() -> Exposure {
        Exposure { mode: Mode::Proxy, proxies: vec!["10.0.5.0/24".into()], header: DEFAULT_HEADER.into(), ..Default::default() }
    }

    #[test]
    fn en_tete_cloudflare_falsifie() {
        let e = Exposure::default();
        let h = with("cf-connecting-ip", "1.2.3.4");
        assert_eq!(e.real_ip(false, ip("127.0.0.1"), &h), ip("1.2.3.4"), "cloudflared sur la machine");
        assert_eq!(e.real_ip(false, ip("192.168.1.50"), &h), ip("192.168.1.50"), "un voisin du réseau privé n'est pas cru");
        assert_eq!(e.real_ip(true, ip("8.8.8.8"), &h), ip("8.8.8.8"));
        assert_eq!(e.real_ip(true, ip("104.16.1.1"), &h), ip("1.2.3.4"));
        let docker = Exposure { tunnel_peers: vec!["172.16.0.0/12".into()], ..Default::default() };
        assert_eq!(docker.real_ip(false, ip("172.18.0.4"), &h), ip("1.2.3.4"), "cloudflared en conteneur");
    }

    #[test]
    fn adresse_derriere_un_proxy() {
        let e = behind_proxy();
        let proxy = ip("10.0.5.10");
        let real = |v: &'static str| e.real_ip(false, proxy, &with("x-forwarded-for", v));
        assert_eq!(real("203.0.113.9"), ip("203.0.113.9"));
        assert_eq!(real("9.9.9.9, 203.0.113.9"), ip("203.0.113.9"), "la partie gauche est écrite par le visiteur");
        assert_eq!(real("203.0.113.9, 10.0.5.11"), ip("203.0.113.9"), "deux proxys à la suite");
        assert_eq!(real("203.0.113.9:51234"), ip("203.0.113.9"), "port ajouté par le proxy");
        assert_eq!(real("n'importe quoi"), proxy);
        assert_eq!(e.real_ip(false, proxy, &HeaderMap::new()), proxy);
        assert_eq!(e.real_ip(false, ip("203.0.113.1"), &with("x-forwarded-for", "1.1.1.1")), ip("203.0.113.1"), "hors liste, l'en-tête est ignoré");
        assert_eq!(e.real_ip(false, proxy, &with("cf-connecting-ip", "1.1.1.1")), proxy);
        let custom = Exposure { header: "X-Real-IP".into(), ..behind_proxy() };
        assert_eq!(custom.real_ip(false, proxy, &with("x-real-ip", "203.0.113.9")), ip("203.0.113.9"));
    }

    #[test]
    fn qui_peut_joindre_le_portail() {
        let cloudflare = Exposure::default();
        assert!(cloudflare.admits(false, ip("127.0.0.1")));
        assert!(!cloudflare.admits(true, ip("8.8.8.8")));
        let proxy = behind_proxy();
        assert!(proxy.admits(true, ip("10.0.5.10")));
        assert!(!proxy.admits(false, ip("127.0.0.1")));
        assert!(!proxy.admits(true, ip("10.0.6.1")));
        assert!(!Exposure { mode: Mode::Proxy, ..Default::default() }.admits(true, ip("10.0.5.10")), "liste vide : personne");
        let internal = Exposure { mode: Mode::Internal, ..Default::default() };
        assert!(internal.admits(true, ip("192.168.1.2")));
        assert!(!internal.admits(true, ip("8.8.8.8")));
        let restricted = Exposure { mode: Mode::Internal, networks: vec!["10.0.0.0/8".into()], ..Default::default() };
        assert!(!restricted.admits(true, ip("192.168.1.2")));
        assert!(!Exposure { mode: Mode::Relay, ..Default::default() }.admits(false, ip("127.0.0.1")), "mode relais : aucun accès direct");
        assert!(Exposure { mode: Mode::Direct, ..Default::default() }.admits(true, ip("8.8.8.8")));
        assert!(!Exposure { mode: Mode::Direct, networks: vec!["203.0.113.0/24".into()], ..Default::default() }.admits(true, ip("8.8.8.8")));
    }

    #[test]
    fn saisie_des_reseaux() {
        let parsed = parse_networks(&["10.0.5.10, 10.0.6.0/24".into(), "2001:db8::1".into()]).unwrap();
        assert_eq!(parsed, ["10.0.5.10/32", "10.0.6.0/24", "2001:db8::1/128"]);
        assert_eq!(parse_networks(&["10.0.0.0/33".into()]).unwrap_err(), "10.0.0.0/33");
        assert_eq!(parse_networks(&["proxy.lan".into()]).unwrap_err(), "proxy.lan");
    }

    #[test]
    fn adresses_versionnees() {
        let v = format!("?v={}", env!("CARGO_PKG_VERSION"));
        for text in [INDEX, SESSION, DESKTOP, include_str!("../portail/bureau.js")] {
            let served = versioned(text);
            assert!(served.contains(&v) && !served.contains("__V__"));
        }
    }

    #[test]
    fn cookie() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("a=1; portunia_gate_portail=abc; b=2"));
        assert_eq!(cookie_token(&h).as_deref(), Some("abc"));
    }
}

// ---------- Interfaces web ----------

/// Ouverture d'un serveur web : session du portail et règle vérifiées, puis ce navigateur
/// garde le nom du serveur (cookie) pour les chemins absolus de l'application.
async fn web_open(AxState(portal): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Path(nom): Path<String>) -> Response {
    let ip = client_ip(&portal, peer, &headers);
    let result = async {
        let state = &portal.state;
        let s = settings(state).await?;
        if !s.enabled {
            return Ok(err(StatusCode::SERVICE_UNAVAILABLE, t!("Portal closed", "Portail fermé")));
        }
        let Some(w) = web_session(&portal, &headers, &s).await? else {
            return Ok((StatusCode::FOUND, [(header::LOCATION, "/?accueil")]).into_response());
        };
        let target = model::target_by_name(&state.db, &nom).await?.filter(|t| t.is_web());
        let Some(target) = target else {
            return Ok(err(StatusCode::NOT_FOUND, t!("Server unavailable in the browser", "Serveur indisponible dans le navigateur")));
        };
        if !crate::webproxy::allowed(state, &w.user, &target).await? {
            audit::note(&state.db, &w.user.login, "acces.refuse", json!({ "cible": target.name, "type": "web", "adresse": format!("{ip} (web)") })).await;
            return Ok(err(StatusCode::FORBIDDEN, t!("Server not allowed at the moment", "Serveur non autorisé en ce moment")));
        }
        crate::webproxy::opened(state, &w.user, &target, &format!("{ip} (web)"), "portail").await;
        let cookie = format!("{}={}; Path=/; HttpOnly; Secure; SameSite=Lax", crate::webproxy::APP_COOKIE, target.name);
        Ok::<_, anyhow::Error>((StatusCode::FOUND, [(header::SET_COOKIE, cookie), (header::LOCATION, format!("/web/{}/", target.name))]).into_response())
    }
    .await;
    result.unwrap_or_else(internal)
}

async fn web_root(AxState(portal): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, Path(nom): Path<String>, req: axum::extract::Request) -> Response {
    let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    web_proxy(&portal, peer, &nom, format!("/{query}"), req).await
}

async fn web_path(AxState(portal): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, Path((nom, rest)): Path<(String, String)>, req: axum::extract::Request) -> Response {
    let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    web_proxy(&portal, peer, &nom, format!("/{rest}{query}"), req).await
}

/// Adresse inconnue du portail : chemin absolu du serveur web ouvert dans ce navigateur.
async fn web_fallback(AxState(portal): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: axum::extract::Request) -> Response {
    let Some(nom) = crate::webproxy::cookie(req.headers(), crate::webproxy::APP_COOKIE) else {
        return err(StatusCode::NOT_FOUND, t!("Page not found", "Page introuvable"));
    };
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    web_proxy(&portal, peer, &nom, path, req).await
}

async fn web_proxy(portal: &Portal, peer: SocketAddr, nom: &str, path: String, req: axum::extract::Request) -> Response {
    let headers = req.headers().clone();
    let ip = client_ip(portal, peer, &headers);
    let checked = async {
        let state = &portal.state;
        let s = settings(state).await?;
        if !s.enabled {
            return Ok(Err(err(StatusCode::SERVICE_UNAVAILABLE, t!("Portal closed", "Portail fermé"))));
        }
        let Some(w) = web_session(portal, &headers, &s).await? else {
            return Ok(Err((StatusCode::FOUND, [(header::LOCATION, "/?accueil")]).into_response()));
        };
        let target = model::target_by_name(&state.db, nom).await?.filter(|t| t.is_web());
        match target {
            Some(t) if crate::webproxy::allowed(state, &w.user, &t).await? => Ok(Ok((w.user, t))),
            _ => Ok(Err(err(StatusCode::FORBIDDEN, t!("Server not allowed at the moment", "Serveur non autorisé en ce moment")))),
        }
    }
    .await;
    let checked: anyhow::Result<Result<(User, model::Target), Response>> = checked;
    match checked {
        Ok(Ok((user, target))) => crate::webproxy::forward(&portal.state, &user, &target, req, &path, false, &format!("{ip} (web)")).await,
        Ok(Err(res)) => res,
        Err(e) => internal(e),
    }
}
