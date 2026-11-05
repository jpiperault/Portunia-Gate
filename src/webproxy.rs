//! Interfaces web derrière la Gate (serveurs `http` ou `https` : vCenter, iDRAC, pare-feu…).
//!
//! La Gate relaie chaque requête vers le serveur, après avoir vérifié le compte et sa règle
//! (contrôle refait au plus toutes les 30 secondes), et note au journal chaque page ouverte
//! (`web.page`). Les en-têtes sont réécrits pour que l'application se croie appelée
//! directement : `Host`, `Origin` et `Referer` vers le serveur ; `Location` et les cookies
//! vers la Gate. Les cookies propres à la Gate ne partent jamais vers le serveur. Les
//! WebSocket (consoles, rafraîchissements) passent aussi.
//!
//! Deux entrées :
//! - le portail web : `/web/<nom>/…`, puis toute adresse inconnue du portail tant que le
//!   cookie `portunia_gate_web` désigne ce serveur (les applications appellent souvent des
//!   chemins absolus) ;
//! - Portunia : un jeton à usage unique ouvre `/web/entree` sur le port de l'API, qui donne
//!   une clé de session (cookie) valable 8 heures ; toute adresse hors de `/api/` va alors au
//!   serveur. Portunia y accède par un relais local (http://127.0.0.1:port).
//!
//! Le certificat d'un serveur https est vérifié par son empreinte, gardée à la première
//! connexion, comme pour le Bureau à distance.

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Result};
use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri},
};
use hyper_util::rt::TokioIo;
use serde_json::json;
use uuid::Uuid;

use crate::{
    audit,
    model::{self, Target, User},
    State,
};

/// Cookie du portail : nom du serveur web ouvert dans ce navigateur.
pub const APP_COOKIE: &str = "portunia_gate_web";
/// Cookie du port de l'API : clé de session web donnée à Portunia, suivi du port du relais
/// local (les cookies de 127.0.0.1 sont communs à tous ses ports).
pub const KEY_COOKIE: &str = "portunia_gate_web_cle";

/// Nom du cookie de clé pour cette requête : un par relais local de Portunia.
pub fn key_cookie_name(headers: &HeaderMap) -> String {
    let port = headers.get(header::HOST).and_then(|h| h.to_str().ok()).and_then(|h| h.rsplit_once(':')).map(|(_, p)| p).filter(|p| p.chars().all(|c| c.is_ascii_digit()));
    match port {
        Some(p) => format!("{KEY_COOKIE}_{p}"),
        None => KEY_COOKIE.into(),
    }
}
/// Durée d'une session web ouverte depuis Portunia.
const KEY_LIFETIME: Duration = Duration::from_secs(8 * 3600);
/// Délai entre deux contrôles de la règle pour un même compte et un même serveur.
const RECHECK: Duration = Duration::from_secs(30);

/// Réponse venue du serveur relayé : le portail n'y met pas sa politique de sécurité.
#[derive(Clone, Copy)]
pub struct Proxied;

struct WebKey {
    user: Uuid,
    target: Uuid,
    expires: Instant,
}

static KEYS: LazyLock<Mutex<HashMap<String, WebKey>>> = LazyLock::new(Mutex::default);
/// Dernier contrôle réussi de (compte, serveur).
static CHECKED: LazyLock<Mutex<HashMap<(Uuid, Uuid), Instant>>> = LazyLock::new(Mutex::default);

/// Nouvelle clé de session web (Portunia) pour ce compte et ce serveur.
pub fn new_key(user: Uuid, target: Uuid) -> Result<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let key = URL_SAFE_NO_PAD.encode(crate::keys::random::<32>()?);
    let mut keys = KEYS.lock().unwrap();
    keys.retain(|_, k| k.expires > Instant::now());
    keys.insert(key.clone(), WebKey { user, target, expires: Instant::now() + KEY_LIFETIME });
    Ok(key)
}

/// Compte et serveur d'une clé encore valable.
pub fn key_owner(key: &str) -> Option<(Uuid, Uuid)> {
    KEYS.lock().unwrap().get(key).filter(|k| k.expires > Instant::now()).map(|k| (k.user, k.target))
}

/// Valeur d'un cookie de la requête.
pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

/// Le compte a toujours une règle active vers ce serveur (contrôle gardé 30 secondes).
pub async fn allowed(state: &State, user: &User, target: &Target) -> Result<bool> {
    if user.disabled || !target.is_web() {
        return Ok(false);
    }
    let key = (user.id, target.id);
    if CHECKED.lock().unwrap().get(&key).is_some_and(|at| at.elapsed() < RECHECK) {
        return Ok(true);
    }
    let ok = model::access(&state.db, user.id, target.id).await?.is_some();
    let mut checked = CHECKED.lock().unwrap();
    if ok {
        checked.insert(key, Instant::now());
    } else {
        checked.remove(&key);
    }
    Ok(ok)
}

/// Adresse d'origine du serveur, telle qu'il la connaît (« https://10.0.0.5:8443 »).
fn origin(target: &Target) -> String {
    let default = if target.protocole == "https" { 443 } else { 80 };
    if target.port == default {
        format!("{}://{}", target.protocole, target.host)
    } else {
        format!("{}://{}:{}", target.protocole, target.host, target.port)
    }
}

fn host_header(target: &Target) -> String {
    let default = if target.protocole == "https" { 443 } else { 80 };
    if target.port == default {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    }
}

const HOP: &[&str] = &["connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"];

/// En-têtes qui ne doivent pas atteindre le serveur : ceux du relais, de Cloudflare, et
/// l'adresse du visiteur (le serveur ne voit que la Gate).
fn dropped_upstream(name: &HeaderName) -> bool {
    let n = name.as_str();
    HOP.contains(&n) || n.starts_with("cf-") || n.starts_with("x-forwarded-") || n == "forwarded" || n == "x-real-ip" || n == "cdn-loop" || n == "x-portunia-gate"
}

/// Cookies de la requête sans ceux de la Gate (tous ceux qui commencent par « portunia_gate_ »).
fn strip_own_cookies(value: &str) -> String {
    value
        .split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty() && !c.starts_with("portunia_gate_"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// `Set-Cookie` du serveur, valable pour la Gate : sans `Domain` ; relais en http simple
/// (Portunia, 127.0.0.1) : sans `Secure`, et `SameSite=None` devient `Lax`.
fn rewrite_cookie(value: &str, plain: bool) -> String {
    value
        .split(';')
        .map(str::trim)
        .filter(|p| !p.to_ascii_lowercase().starts_with("domain="))
        .filter(|p| !(plain && p.eq_ignore_ascii_case("secure")))
        .map(|p| if plain && p.eq_ignore_ascii_case("samesite=none") { "SameSite=Lax" } else { p })
        .collect::<Vec<_>>()
        .join("; ")
}

/// `Location` vers le serveur lui-même : ramenée à un chemin de la Gate. `prefix` :
/// « /web/<nom> » dans le portail, pour qu'une redirection vers « / » (après la connexion
/// à l'application, souvent) ne tombe pas sur l'accueil du portail ; vide pour Portunia.
fn rewrite_location(value: &str, origin: &str, prefix: &str) -> String {
    let path = match value.strip_prefix(origin) {
        Some(rest) if rest.is_empty() => "/",
        Some(rest) if rest.starts_with('/') || rest.starts_with('?') => rest,
        // Chemin absolu, mais pas « //hôte » (autre serveur).
        None if value.starts_with('/') && !value.starts_with("//") => value,
        _ => return value.into(),
    };
    if prefix.is_empty() || path.starts_with(&format!("{prefix}/")) {
        return path.into();
    }
    match path.strip_prefix('?') {
        Some(query) => format!("{prefix}/?{query}"),
        None => format!("{prefix}{path}"),
    }
}

/// Origine ou page d'appel réécrite vers le serveur (contrôles anti-CSRF des applications).
fn rewrite_referer(value: &str, origin: &str) -> String {
    match value.split_once("://").and_then(|(_, rest)| rest.find('/').map(|i| &rest[i..])) {
        Some(path) => format!("{origin}{path}"),
        None => origin.to_string(),
    }
}

/// Connexion au serveur : TCP, puis TLS avec son certificat vérifié par son empreinte.
async fn connect(state: &State, user: &User, target: &Target) -> Result<Box<dyn Io>> {
    let addresses = crate::target::addresses(&target.host, target.port as u16).await?;
    let tcp = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(&addresses[..]))
        .await
        .map_err(|_| anyhow!(t!(format!("{} unreachable (timed out)", target.name), format!("{} injoignable (délai dépassé)", target.name))))??;
    let _ = tcp.set_nodelay(true);
    if target.protocole != "https" {
        return Ok(Box::new(tcp));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::rdp::Capture(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from(target.host.clone()).map_err(|_| anyhow!(t!("invalid server address", "adresse du serveur invalide")))?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.map_err(|e| anyhow!("TLS {} : {e}", target.name))?;
    let leaf = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| c.to_vec()).ok_or_else(|| anyhow!(t!("the server presented no certificate", "le serveur n'a pas présenté de certificat")))?;
    let fingerprint = crate::rdp::cert_fingerprint(&leaf);
    match &target.host_key {
        None => {
            if model::pin_host_key(&state.db, target.id, &fingerprint).await? {
                audit::note(&state.db, &user.login, "cible.empreinte_memorisee", json!({ "cible": target.name, "empreinte": fingerprint })).await;
            }
        }
        Some(known) if *known != fingerprint => {
            audit::note(&state.db, &user.login, "cible.empreinte_differente", json!({ "cible": target.name, "attendue": known, "recue": fingerprint })).await;
            bail!(t!(
                format!("{}: the server's certificate has changed (expected {known}, received {fingerprint})", target.name),
                format!("{} : le certificat du serveur a changé (attendu {known}, reçu {fingerprint})", target.name)
            ));
        }
        _ => {}
    }
    Ok(Box::new(tls))
}

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static> Io for T {}

fn page(status: StatusCode, text: &str) -> Response<Body> {
    let mut res = Response::new(Body::from(format!("<!doctype html><meta charset=\"utf-8\"><title>Portunia Gate</title><p style=\"font:15px system-ui;margin:40px\">{}</p>", text.replace('<', "&lt;"))));
    *res.status_mut() = status;
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    res
}

/// Relaie la requête vers le serveur (`path` : chemin et paramètres côté serveur).
/// `plain` : le navigateur parle en http simple (relais local de Portunia).
pub async fn forward(state: &State, user: &User, target: &Target, mut req: Request<Body>, path: &str, plain: bool, client_addr: &str) -> Response<Body> {
    match relay(state, user, target, &mut req, path, plain, client_addr).await {
        Ok(res) => res,
        Err(e) => {
            tracing::warn!("{} {}: {e:#}", t!("web interface", "interface web"), target.name);
            page(StatusCode::BAD_GATEWAY, &format!("{} : {e}", target.name))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay(state: &State, user: &User, target: &Target, req: &mut Request<Body>, path: &str, plain: bool, client_addr: &str) -> Result<Response<Body>> {
    let origin = origin(target);
    // Portail (http chiffré) : chemins de l'application sous /web/<nom> ; Portunia : à la racine.
    let prefix = if plain { String::new() } else { format!("/web/{}", target.name) };
    let upgrade = req.headers().get(header::UPGRADE).cloned();
    let client_upgrade = upgrade.as_ref().map(|_| hyper::upgrade::on(&mut *req));
    let mut out = Request::builder().method(req.method().clone()).uri(path.parse::<Uri>().map_err(|_| anyhow!("adresse invalide"))?);
    for (name, value) in req.headers() {
        if dropped_upstream(name) || name == header::HOST {
            continue;
        }
        let value = match name.as_str() {
            "cookie" => HeaderValue::from_str(&strip_own_cookies(value.to_str().unwrap_or_default()))?,
            "origin" => HeaderValue::from_str(&origin)?,
            "referer" => HeaderValue::from_str(&rewrite_referer(value.to_str().unwrap_or_default(), &origin))?,
            _ => value.clone(),
        };
        if name == header::COOKIE && value.is_empty() {
            continue;
        }
        out = out.header(name, value);
    }
    out = out.header(header::HOST, host_header(target));
    if let Some(u) = &upgrade {
        out = out.header(header::CONNECTION, "upgrade").header(header::UPGRADE, u.clone());
    }
    // Page ouverte (et non image, script ou appel d'API) : notée au journal.
    let document = req.headers().get("sec-fetch-dest").and_then(|v| v.to_str().ok()) == Some("document")
        || (req.headers().get("sec-fetch-dest").is_none() && req.headers().get(header::ACCEPT).and_then(|v| v.to_str().ok()).is_some_and(|a| a.starts_with("text/html")));
    if document && req.method() == axum::http::Method::GET {
        let shown = path.split('?').next().unwrap_or(path);
        audit::note(&state.db, &user.login, "web.page", json!({ "cible": target.name, "chemin": shown, "adresse": client_addr })).await;
    }
    let body = std::mem::replace(req.body_mut(), Body::empty());
    let out = out.body(body)?;

    let io = connect(state, user, target).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let mut res = sender.send_request(out).await?;

    // WebSocket : une fois acceptée des deux côtés, les octets passent tels quels.
    if res.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade) = client_upgrade {
            let server_upgrade = hyper::upgrade::on(&mut res);
            tokio::spawn(async move {
                if let (Ok(client), Ok(server)) = (client_upgrade.await, server_upgrade.await) {
                    let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(client), &mut TokioIo::new(server)).await;
                }
            });
        }
    }

    let (parts, incoming) = res.into_parts();
    let mut response = Response::new(Body::new(incoming));
    *response.status_mut() = parts.status;
    for (name, value) in &parts.headers {
        if HOP.contains(&name.as_str()) && parts.status != StatusCode::SWITCHING_PROTOCOLS {
            continue;
        }
        let value = match name.as_str() {
            "location" => HeaderValue::from_str(&rewrite_location(value.to_str().unwrap_or_default(), &origin, &prefix))?,
            "set-cookie" => HeaderValue::from_str(&rewrite_cookie(value.to_str().unwrap_or_default(), plain))?,
            // Le serveur relayé ne doit pas imposer HTTPS à 127.0.0.1 (relais de Portunia).
            "strict-transport-security" if plain => continue,
            _ => value.clone(),
        };
        response.headers_mut().append(name, value);
    }
    response.extensions_mut().insert(Proxied);
    Ok(response)
}

/// Première ouverture depuis un compte : notée au journal.
pub async fn opened(state: &State, user: &User, target: &Target, client_addr: &str, via: &str) {
    audit::note(&state.db, &user.login, "web.ouvert", json!({ "cible": target.name, "adresse": client_addr, "via": via })).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_de_la_gate_retires() {
        assert_eq!(strip_own_cookies("a=1; portunia_gate_web=vc; portunia_gate_portail=x; b=2"), "a=1; b=2");
        assert_eq!(strip_own_cookies("portunia_gate_web_cle_53211=k"), "");
    }

    #[test]
    fn cookies_du_serveur() {
        assert_eq!(rewrite_cookie("s=1; Domain=vc.local; Path=/; Secure; SameSite=None", false), "s=1; Path=/; Secure; SameSite=None");
        assert_eq!(rewrite_cookie("s=1; Domain=vc.local; Path=/; Secure; SameSite=None", true), "s=1; Path=/; SameSite=Lax");
    }

    #[test]
    fn redirections() {
        // Portunia : chemins à la racine.
        assert_eq!(rewrite_location("https://10.0.0.5/ui/", "https://10.0.0.5", ""), "/ui/");
        assert_eq!(rewrite_location("https://10.0.0.5", "https://10.0.0.5", ""), "/");
        assert_eq!(rewrite_location("https://autre/ui/", "https://10.0.0.5", ""), "https://autre/ui/");
        assert_eq!(rewrite_location("/ui/", "https://10.0.0.5", ""), "/ui/");
        // Portail : sous /web/<nom>, y compris « / » après la connexion à l'application.
        let p = "/web/mail";
        assert_eq!(rewrite_location("/", "https://10.0.0.5", p), "/web/mail/");
        assert_eq!(rewrite_location("https://10.0.0.5", "https://10.0.0.5", p), "/web/mail/");
        assert_eq!(rewrite_location("https://10.0.0.5/ui/?a=1", "https://10.0.0.5", p), "/web/mail/ui/?a=1");
        assert_eq!(rewrite_location("https://10.0.0.5?a=1", "https://10.0.0.5", p), "/web/mail/?a=1");
        assert_eq!(rewrite_location("/web/mail/x", "https://10.0.0.5", p), "/web/mail/x");
        assert_eq!(rewrite_location("//autre/x", "https://10.0.0.5", p), "//autre/x");
        assert_eq!(rewrite_location("https://autre/ui/", "https://10.0.0.5", p), "https://autre/ui/");
        assert_eq!(rewrite_location("login.php", "https://10.0.0.5", p), "login.php");
        assert_eq!(rewrite_referer("https://acces.acme.fr/web/vc/ui/?x=1", "https://10.0.0.5"), "https://10.0.0.5/web/vc/ui/?x=1");
    }
}
