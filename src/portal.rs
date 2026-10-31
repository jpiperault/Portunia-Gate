//! Portail web : accès aux serveurs depuis un navigateur, sans Portunia, derrière Cloudflare.
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
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, Query, State as AxState,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
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

const COOKIE: &str = "portunia_gate_portail";
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
        turnstile_site: text_setting(state, "portail_turnstile_site", "").await?,
        turnstile_secret: secret,
    })
}

// ---------- Serveur ----------

struct Portal {
    state: Arc<State>,
    /// Échecs récents par compte et par adresse (10 minutes).
    failures: Mutex<HashMap<String, (u32, Instant)>>,
    /// L'écoute HTTPS ne répond qu'aux adresses de Cloudflare.
    cloudflare_only: bool,
}

type Ctx = AxState<Arc<Portal>>;

pub async fn run(state: Arc<State>) -> Result<()> {
    let http = state.config.portal_listen.parse::<SocketAddr>().map_err(|_| anyhow!(t!("invalid PORTUNIA_GATE_PORTAL_LISTEN", "PORTUNIA_GATE_PORTAL_LISTEN invalide")))?;
    let tls = match &state.config.portal_tls_listen {
        Some(a) => Some(a.parse::<SocketAddr>().map_err(|_| anyhow!(t!("invalid PORTUNIA_GATE_PORTAL_TLS_LISTEN", "PORTUNIA_GATE_PORTAL_TLS_LISTEN invalide")))?),
        None => None,
    };
    let plain = router(state.clone(), false);
    let listener = tokio::net::TcpListener::bind(http).await?;
    tracing::info!("{} http://{http} (Cloudflare Tunnel)", t!("web portal listening on", "portail web en écoute sur"));
    let plain_task = async move {
        axum::serve(listener, plain.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(anyhow::Error::from)
    };
    match tls {
        None => plain_task.await,
        Some(addr) => {
            let files = crate::tls::files(&state.config.data_dir);
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&files.cert, &files.key)
                .await
                .map_err(|e| anyhow!(t!(format!("portal certificate: {e}"), format!("certificat du portail : {e}"))))?;
            tracing::info!("{} https://{addr} (Cloudflare proxy)", t!("web portal listening on", "portail web en écoute sur"));
            let secure = router(state, true);
            let tls_task = async move {
                axum_server::bind_rustls(addr, config)
                    .serve(secure.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                    .map_err(anyhow::Error::from)
            };
            tokio::try_join!(plain_task, tls_task).map(|_| ())
        }
    }
}

fn router(state: Arc<State>, cloudflare_only: bool) -> Router {
    let portal = Arc::new(Portal {
        state,
        failures: Mutex::new(HashMap::new()),
        cloudflare_only,
    });
    Router::new()
        .route("/", get(page_index))
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
        .layer(middleware::from_fn_with_state(portal.clone(), guard))
        // Pages et messages dans la langue du sélecteur ou du navigateur.
        .layer(middleware::from_fn(crate::lang::middleware))
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

/// Adresse réelle du navigateur : l'en-tête de Cloudflare, cru seulement s'il arrive par le
/// tunnel (connexion locale ou réseau privé, cloudflared) ou depuis une adresse de Cloudflare.
fn client_ip(portal: &Portal, peer: SocketAddr, headers: &HeaderMap) -> String {
    let ip = peer.ip();
    let trusted = match ip {
        _ if portal.cloudflare_only => from_cloudflare(ip),
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    };
    if trusted {
        if let Some(real) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<IpAddr>().ok()) {
            return real.to_string();
        }
    }
    ip.to_string()
}

/// En-têtes de sécurité sur toutes les réponses ; l'écoute HTTPS refuse ce qui ne vient pas de Cloudflare.
async fn guard(AxState(portal): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: axum::extract::Request, next: Next) -> Response {
    if portal.cloudflare_only && !from_cloudflare(peer.ip()) {
        return (StatusCode::FORBIDDEN, t!("Access restricted to Cloudflare", "Accès réservé à Cloudflare")).into_response();
    }
    let mut res = next.run(req).await;
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

async fn page_index() -> Response {
    page(INDEX)
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

async fn asset(Path(fichier): Path<String>) -> Response {
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
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    // Adresses versionnées : un jour de cache sans risque de garder une ancienne version.
    ([(header::CONTENT_TYPE, kind), (header::CACHE_CONTROL, "public, max-age=86400")], body).into_response()
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

/// Échec : compté par compte et par adresse ; même message quel que soit le motif.
async fn failed(portal: &Portal, login: &str, ip: &str, why: &str) -> Response {
    {
        let mut f = portal.failures.lock().unwrap();
        for key in [format!("compte:{login}"), format!("adresse:{ip}")] {
            let e = f.entry(key).or_insert((0, Instant::now()));
            e.0 += 1;
            e.1 = Instant::now();
        }
    }
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
        {
            let mut f = portal.failures.lock().unwrap();
            f.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(600));
            let too_many = |key: String, max: u32| f.get(&key).is_some_and(|(n, _)| *n >= max);
            if too_many(format!("compte:{login}"), 5) || too_many(format!("adresse:{ip}"), 20) {
                return Ok(err(StatusCode::TOO_MANY_REQUESTS, t!("Too many attempts: try again in a few minutes", "Trop d'essais : réessayez dans quelques minutes")));
            }
        }
        if let Some(secret) = s.turnstile_secret.as_deref().filter(|_| !s.turnstile_site.is_empty()) {
            if !turnstile_ok(secret, &body.turnstile, &ip).await {
                return Ok(err(StatusCode::FORBIDDEN, t!("Anti-bot check failed: reload the page", "Vérification anti-robots échouée : rechargez la page")));
            }
        }
        let Some(user) = model::user_by_login(&state.db, &login).await?.filter(|u| !u.disabled) else {
            return Ok(failed(&portal, &login, &ip, "compte inconnu ou désactivé").await);
        };
        if !user.password_hash.as_deref().is_some_and(|h| auth::verify_password(h, &body.mot_de_passe)) {
            return Ok(failed(&portal, &login, &ip, "mot de passe incorrect").await);
        }
        // Première connexion et code perdu : pas depuis Internet.
        if user.must_change_password || user.totp_secret.is_none() {
            audit::note(&state.db, &login, "portail.echec", json!({ "raison": "première connexion ou code non enrôlé", "adresse": ip })).await;
            return Ok(err(
                StatusCode::FORBIDDEN,
                t!("First sign-in or code not enrolled: sign in with Portunia first, or contact your administrator", "Première connexion ou code non enrôlé : connectez-vous d'abord avec Portunia, ou adressez-vous à votre administrateur"),
            ));
        }
        let secret = state.keys.open(&format!("totp:{}", user.id), user.totp_secret.as_deref().unwrap_or_default())?;
        let ok = match auth::totp_check(&secret, body.code.trim(), user.totp_last_step) {
            Some(step) => model::consume_totp_step(&state.db, user.id, step).await?,
            None => false,
        };
        if !ok {
            return Ok(failed(&portal, &login, &ip, "code incorrect ou déjà utilisé").await);
        }
        if !in_group(&state.db, user.id, &s.group).await? {
            audit::note(&state.db, &login, "portail.echec", json!({ "raison": "hors du groupe du portail", "adresse": ip })).await;
            return Ok(err(StatusCode::FORBIDDEN, t!("This account has no access to the web portal", "Ce compte n'a pas accès au portail web")));
        }
        {
            let mut f = portal.failures.lock().unwrap();
            f.remove(&format!("compte:{login}"));
        }
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
        audit::note(&state.db, &user.login, "portail.connexion", json!({ "facteurs": ["mot de passe", "code"], "adresse": ip })).await;
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

/// Peut s'ouvrir dans le navigateur : SSH, hors mode rebond (de bout en bout, il faut Portunia).
fn web_ready(t: &model::Target) -> Option<&'static str> {
    if t.is_rdp() && t.mode == "coffre" {
        Some(t!("Remote Desktop in vault mode: coming soon in the browser", "Bureau à distance en mode coffre : bientôt dans le navigateur"))
    } else if t.mode == "rebond" {
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
        let target = model::target_by_name(&state.db, &nom).await?.filter(|t| !t.is_rdp() && web_ready(t).is_none());
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
        if let Err(e) = bridge(&state, socket, &user, &ticket, cols, rows, w.expires, idle_min).await {
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
        if model::access(&state.db, w.user.id, target.id).await?.is_none() {
            return Ok(err(StatusCode::FORBIDDEN, t!("Server not allowed at the moment", "Serveur non autorisé en ce moment")));
        }
        let ticket = crate::api::issue_ticket(&state.db, w.user.id, target.id, Some(&format!("{ip} (web)"))).await?;
        Ok::<_, anyhow::Error>(Json(json!({ "jeton": ticket, "compte": target.account })).into_response())
    }
    .await;
    result.unwrap_or_else(internal)
}

/// Passage RDCleanPath du client RDP du navigateur.
async fn desktop(AxState(portal): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    let addr = client_ip(&portal, peer, &headers);
    let url = match settings(&portal.state).await {
        Ok(s) if s.enabled => s.url,
        Ok(_) => return err(StatusCode::SERVICE_UNAVAILABLE, t!("Portal closed", "Portail fermé")),
        Err(e) => return internal(e),
    };
    if !origin_ok(&headers, &url) {
        return err(StatusCode::FORBIDDEN, t!("Origin refused", "Origine refusée"));
    }
    let state = portal.state.clone();
    let lang = crate::lang::get();
    ws.on_upgrade(move |socket| crate::lang::scope(lang, crate::rdp::relay(state, socket, crate::rdp::Origin::Portal { addr })))
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
async fn bridge(state: &State, mut socket: WebSocket, user: &str, ticket: &str, cols: u32, rows: u32, expires: DateTime<Utc>, idle_min: i64) -> Result<()> {
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

/// État du tunnel Cloudflare : la page « /ready » des métriques de cloudflared.
pub async fn tunnel_status(state: &State) -> &'static str {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let probe = async {
        let mut tcp = tokio::net::TcpStream::connect(state.config.tunnel_metrics.as_str()).await?;
        tcp.write_all(b"GET /ready HTTP/1.0\r\nHost: localhost\r\n\r\n").await?;
        let mut buf = [0u8; 64];
        let n = tcp.read(&mut buf).await?;
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf[..n]).contains(" 200 "))
    };
    match tokio::time::timeout(Duration::from_secs(2), probe).await {
        Ok(Ok(true)) => "relie",
        Ok(Ok(false)) => "deconnecte",
        _ => "absent",
    }
}

/// Clé du secret Turnstile, chiffrée par le coffre de la Gate.
pub fn seal_turnstile(state: &State, secret: &str) -> Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(state.keys.seal("reglage:turnstile", secret.as_bytes())?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adresses_cloudflare() {
        assert!(from_cloudflare("104.16.1.1".parse().unwrap()));
        assert!(from_cloudflare("2606:4700::1".parse().unwrap()));
        assert!(!from_cloudflare("192.168.1.10".parse().unwrap()));
        assert!(!from_cloudflare("8.8.8.8".parse().unwrap()));
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
