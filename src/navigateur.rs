//! Navigation depuis le portail web (0.53) : une sortie web ouverte dans un onglet du portail.
//!
//! Le navigateur tourne sur la Gate, mais pas dans son service : `portunia-gate navigateur`
//! (service portunia-gate-navigateur, compte `_portunia_gate_nav`, sans aucun réseau à lui)
//! lance un Chromium sans écran par session, dans un profil jeté à la fin. Chromium ne voit
//! qu'un proxy SOCKS5 tenu par ce service ; chaque connexion repart vers la Gate par un socket
//! local (`/run/portunia-gate/sortie.sock`) avec le jeton de la session, et la Gate applique le
//! filtre de la cible exactement comme pour Portunia (egress.rs) : domaines, ports, réseaux
//! internes toujours refusés, résolution sur la Gate, sites au journal.
//!
//! La Gate pilote ce Chromium par le protocole DevTools (CDP), relayé par le service sur le
//! socket de contrôle (`/run/portunia-gate-navigateur/navigateur.sock`) : elle reçoit l'image
//! de la page (JPEG) et la passe à l'onglet du portail, qui renvoie souris, clavier, adresse
//! et taille. Rien n'est réencodé, rien n'est enregistré : le journal garde les sites, comme
//! pour la sortie web de Portunia. Téléchargements et envois de fichiers sont refusés.

// Sous Windows (tests seulement), la partie Linux manque : le reste paraît inutilisé.
#![cfg_attr(not(unix), allow(dead_code))]

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, LazyLock, Mutex,
    },
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot},
};

use crate::{egress, model::Target};

/// Socket de contrôle du service du navigateur.
const CONTROL_SOCKET: &str = "/run/portunia-gate-navigateur/navigateur.sock";
/// Socket de la sortie web, tenu par la Gate.
const EGRESS_SOCKET: &str = "/run/portunia-gate/sortie.sock";
/// Compte du service du navigateur : seul autorisé (avec root) sur le socket de la sortie web.
const WORKER_USER: &str = "_portunia_gate_nav";
/// Compte de la Gate : seul autorisé (avec root) sur le socket de contrôle.
const GATE_USER: &str = "_portunia_gate";
/// Navigateurs ouverts en même temps par défaut (PORTUNIA_GATE_NAVIGATEURS_MAX).
const DEFAULT_MAX: usize = 5;
/// Taille d'un message DevTools : une image JPEG en base64 tient largement.
const MAX_MESSAGE: usize = 32 * 1024 * 1024;
/// Texte collé : au-delà, coupé.
const MAX_PASTE: usize = 100_000;

fn control_path() -> PathBuf {
    std::env::var_os("PORTUNIA_GATE_NAVIGATEUR_SOCKET").map(PathBuf::from).unwrap_or_else(|| CONTROL_SOCKET.into())
}

fn egress_path() -> PathBuf {
    std::env::var_os("PORTUNIA_GATE_SORTIE_SOCKET").map(PathBuf::from).unwrap_or_else(|| EGRESS_SOCKET.into())
}

fn max_browsers() -> usize {
    std::env::var("PORTUNIA_GATE_NAVIGATEURS_MAX").ok().and_then(|v| v.parse().ok()).filter(|n| *n > 0).unwrap_or(DEFAULT_MAX)
}

/// Le service du navigateur est-il installé et lancé sur cette Gate ?
pub fn available() -> bool {
    cfg!(unix) && control_path().exists()
}

// ---------- Ce que tape l'utilisateur ----------

/// Adresse tapée dans la barre : http(s) seulement ; un nom (« exemple.fr/page ») devient
/// https ; une phrase devient une recherche. `None` : rien, ou un autre schéma (file:,
/// chrome:, javascript:…), refusé.
pub fn address(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() || text.len() > 4096 {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return (!text.contains(char::is_whitespace)).then(|| text.to_string());
    }
    if lower.contains("://") || lower.starts_with("about:") || lower.starts_with("javascript:") || lower.starts_with("data:") || lower.starts_with("file:") || lower.starts_with("chrome") {
        return None;
    }
    let host = text.split(['/', '?', '#']).next().unwrap_or_default();
    if !text.contains(char::is_whitespace) && host.contains('.') && !host.starts_with('.') && !host.ends_with('.') {
        return Some(format!("https://{text}"));
    }
    Some(format!("https://duckduckgo.com/?q={}", encode(text)))
}

fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 3);
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Taille de la page : celle de l'onglet, dans des bornes raisonnables.
pub fn size(width: u32, height: u32) -> (u32, u32) {
    (width.clamp(320, 3840), height.clamp(240, 2160))
}

/// Touches de modification (Alt 1, Ctrl 2, Méta 4, Maj 8) : seulement celles-là.
fn mods(v: &Value) -> i64 {
    v["m"].as_i64().unwrap_or(0) & 15
}

fn short(v: &Value, key: &str) -> Option<String> {
    let s = v[key].as_str()?;
    (s.chars().count() <= 32).then(|| s.to_string())
}

/// Évènement souris de l'onglet → paramètres de `Input.dispatchMouseEvent`.
fn mouse(v: &Value, (w, h): (u32, u32)) -> Option<Value> {
    let kind = match v["e"].as_str()? {
        "bas" => "mousePressed",
        "haut" => "mouseReleased",
        "bouge" => "mouseMoved",
        _ => return None,
    };
    let button = match v["b"].as_i64() {
        Some(0) => "left",
        Some(1) => "middle",
        Some(2) => "right",
        _ => "none",
    };
    let x = v["x"].as_f64()?.clamp(0.0, w as f64);
    let y = v["y"].as_f64()?.clamp(0.0, h as f64);
    Some(json!({
        "type": kind, "x": x, "y": y, "modifiers": mods(v),
        "button": if kind == "mouseMoved" { "none" } else { button },
        "buttons": v["bs"].as_i64().unwrap_or(0) & 7,
        "clickCount": v["n"].as_i64().unwrap_or(if kind == "mouseMoved" { 0 } else { 1 }).clamp(0, 3),
    }))
}

/// Molette → `Input.dispatchMouseEvent` de type mouseWheel.
fn wheel(v: &Value, (w, h): (u32, u32)) -> Option<Value> {
    let x = v["x"].as_f64()?.clamp(0.0, w as f64);
    let y = v["y"].as_f64()?.clamp(0.0, h as f64);
    Some(json!({
        "type": "mouseWheel", "x": x, "y": y, "modifiers": mods(v),
        "deltaX": v["dx"].as_f64().unwrap_or(0.0).clamp(-10000.0, 10000.0),
        "deltaY": v["dy"].as_f64().unwrap_or(0.0).clamp(-10000.0, 10000.0),
    }))
}

/// Touche → `Input.dispatchKeyEvent`. Une touche qui écrit un caractère (sans Ctrl ni Méta)
/// porte son texte ; Entrée écrit un retour chariot.
fn key(v: &Value) -> Option<Value> {
    let down = match v["e"].as_str()? {
        "bas" => true,
        "haut" => false,
        _ => return None,
    };
    let key = short(v, "key")?;
    let code = short(v, "code").unwrap_or_default();
    let m = mods(v);
    let kc = v["kc"].as_i64().unwrap_or(0).clamp(0, 255);
    let text = if !down || m & 6 != 0 {
        String::new()
    } else if key == "Enter" {
        "\r".into()
    } else if key.chars().count() == 1 {
        key.clone()
    } else {
        String::new()
    };
    let kind = match (down, text.is_empty()) {
        (false, _) => "keyUp",
        (true, false) => "keyDown",
        (true, true) => "rawKeyDown",
    };
    Some(json!({
        "type": kind, "key": key, "code": code, "modifiers": m,
        "windowsVirtualKeyCode": kc, "nativeVirtualKeyCode": kc,
        "autoRepeat": v["rep"].as_bool().unwrap_or(false),
        "text": text, "unmodifiedText": text,
    }))
}

// ---------- Protocole DevTools (CDP) ----------

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>>;

/// Client DevTools sur un flux de messages JSON séparés par un octet nul (`--remote-debugging-pipe`).
struct Cdp {
    out: mpsc::Sender<Vec<u8>>,
    next: AtomicU64,
    pending: Pending,
}

impl Cdp {
    /// Démarre la lecture et l'écriture ; les évènements arrivent dans le récepteur rendu.
    fn start<R, W>(read: R, write: W) -> (Arc<Cdp>, mpsc::Receiver<Value>)
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (out, mut outgoing) = mpsc::channel::<Vec<u8>>(256);
        let (events_tx, events) = mpsc::channel::<Value>(256);
        let pending: Pending = Arc::default();
        tokio::spawn(async move {
            let mut write = write;
            while let Some(mut msg) = outgoing.recv().await {
                msg.push(0);
                if write.write_all(&msg).await.is_err() {
                    break;
                }
            }
        });
        let reader_pending = pending.clone();
        tokio::spawn(async move {
            let mut read = read;
            let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
            let mut chunk = vec![0u8; 64 * 1024];
            'outer: loop {
                let n = match read.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
                while let Some(end) = buf.iter().position(|b| *b == 0) {
                    let msg: Vec<u8> = buf.drain(..=end).collect();
                    let Ok(v) = serde_json::from_slice::<Value>(&msg[..msg.len() - 1]) else { continue };
                    if let Some(id) = v["id"].as_u64() {
                        if let Some(tx) = reader_pending.lock().unwrap().remove(&id) {
                            let result = match v.get("error") {
                                Some(e) => Err(anyhow!("{}", e["message"].as_str().unwrap_or("DevTools"))),
                                None => Ok(v["result"].clone()),
                            };
                            let _ = tx.send(result);
                        }
                    } else if events_tx.send(v).await.is_err() {
                        break 'outer;
                    }
                }
                if buf.len() > MAX_MESSAGE {
                    break;
                }
            }
            // Flux fermé : les appels en attente échouent.
            reader_pending.lock().unwrap().clear();
        });
        (Arc::new(Cdp { out, next: AtomicU64::new(1), pending }), events)
    }

    fn message(&self, id: u64, session: Option<&str>, method: &str, params: Value) -> Vec<u8> {
        let mut msg = json!({ "id": id, "method": method, "params": params });
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        msg.to_string().into_bytes()
    }

    /// Appel avec réponse attendue.
    async fn call(&self, session: Option<&str>, method: &str, params: Value) -> Result<Value> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        self.out.send(self.message(id, session, method, params)).await.map_err(|_| anyhow!(t!("the browser has stopped", "le navigateur s'est arrêté")))?;
        match tokio::time::timeout(Duration::from_secs(20), rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => bail!(t!("the browser has stopped", "le navigateur s'est arrêté")),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                bail!(t!(format!("the browser is not answering ({method})"), format!("le navigateur ne répond pas ({method})")))
            }
        }
    }

    /// Envoi sans attendre la réponse (souris, clavier, accusés d'image).
    async fn send(&self, session: Option<&str>, method: &str, params: Value) -> bool {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.out.send(self.message(id, session, method, params)).await.is_ok()
    }
}

// ---------- Entrée de la sortie web (côté Gate) ----------

/// Navigation en cours, retrouvée par son jeton quand le service du navigateur ouvre une connexion.
struct Registered {
    nav: Arc<egress::Navigation>,
    target: Arc<Mutex<Target>>,
    /// L'utilisateur a demandé une page : avant, ce que Chromium ouvre de lui-même est refusé
    /// sans être noté (le journal ne garde que ce que l'utilisateur a voulu ouvrir).
    asked: Arc<AtomicBool>,
    /// Passe à vrai à la fin de la session : ses connexions encore ouvertes se coupent (sinon
    /// elles attendraient que le site ferme, et la session resterait ouverte au journal).
    stop: tokio::sync::watch::Receiver<bool>,
}

/// Services de Chromium pour lui-même (mises à jour de composants, suggestions) : refusés par le
/// service du navigateur sans même demander à la Gate. Les options de lancement en coupent la
/// plupart ; ceux-là partent quand même avec un profil neuf.
const CHROMIUM_OWN: &[&str] = &[
    "update.googleapis.com",
    "edgedl.me.gvt1.com",
    "redirector.gvt1.com",
    "optimizationguide-pa.googleapis.com",
    "clientservices.googleapis.com",
    "content-autofill.googleapis.com",
    "safebrowsing.googleapis.com",
];

fn chromium_own(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    CHROMIUM_OWN.iter().any(|h| host == *h)
}

static SESSIONS: LazyLock<Mutex<HashMap<String, Registered>>> = LazyLock::new(Mutex::default);
static OPEN: AtomicUsize = AtomicUsize::new(0);

/// Demande du service du navigateur : jeton de la session, site et port.
#[derive(Deserialize)]
struct Ask {
    jeton: String,
    hote: String,
    port: u16,
}

/// Une connexion de Chromium vers un site : même filtre que la sortie web de Portunia. Rend la
/// réponse à écrire (« ok » ou « non <raison> ») et, si c'est ok, de quoi relayer.
type Relayed = (Arc<egress::Navigation>, egress::Opened, tokio::net::TcpStream, tokio::sync::watch::Receiver<bool>);

async fn open_site(ask: &Ask) -> (String, Option<Relayed>) {
    let found = SESSIONS.lock().unwrap().get(&ask.jeton).map(|r| (r.nav.clone(), r.target.lock().unwrap().clone(), r.asked.load(Ordering::SeqCst), r.stop.clone()));
    let Some((nav, target, asked, stop)) = found else {
        return ("non session inconnue".into(), None);
    };
    if !asked {
        return ("non aucune page demandée".into(), None);
    }
    if let Some(why) = nav.closed() {
        return (format!("non {why}"), None);
    }
    let site = ask.hote.trim_end_matches('.').to_ascii_lowercase();
    if let Some(why) = egress::refusal(&target, &site, ask.port as u32) {
        nav.refused(&site, ask.port as u32, why).await;
        return (format!("non {why}"), None);
    }
    let Some(opened) = nav.enter(&site) else {
        return ("non trop de connexions".into(), None);
    };
    let addresses = match egress::resolve(&site, ask.port).await {
        Ok(a) => a,
        Err(why) => {
            nav.refused(&site, ask.port as u32, why).await;
            return (format!("non {why}"), None);
        }
    };
    match egress::connect(&addresses).await {
        Ok(tcp) => ("ok".into(), Some((nav, opened, tcp, stop))),
        Err(_) => ("non injoignable".into(), None),
    }
}

/// Attend la fin de la session (le récepteur passe à vrai) ; jamais si l'émetteur disparaît sans.
async fn stopped(stop: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        let done = *stop.borrow_and_update();
        if done {
            return;
        }
        if stop.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Relaie jusqu'à ce qu'un des deux côtés ferme, la coupure de la navigation ou la fin de la
/// session ; rend les octets passés (comptés au fur et à mesure, même en cas de coupure).
async fn relay<A, B>(a: A, b: B, cut: &mut crate::live::Cut, stop: &mut tokio::sync::watch::Receiver<bool>) -> u64
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let (mut abuf, mut bbuf) = (vec![0u8; 32 * 1024], vec![0u8; 32 * 1024]);
    let mut total = 0u64;
    loop {
        tokio::select! {
            r = ar.read(&mut abuf) => match r {
                Ok(n) if n > 0 => {
                    if bw.write_all(&abuf[..n]).await.is_err() {
                        break;
                    }
                    total += n as u64;
                }
                _ => break,
            },
            r = br.read(&mut bbuf) => match r {
                Ok(n) if n > 0 => {
                    if aw.write_all(&bbuf[..n]).await.is_err() {
                        break;
                    }
                    total += n as u64;
                }
                _ => break,
            },
            _ = cut.reason() => break,
            _ = stopped(stop) => break,
        }
    }
    let _ = aw.shutdown().await;
    let _ = bw.shutdown().await;
    total
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;

    use tokio::{io::AsyncBufReadExt, net::UnixListener};

    use super::*;

    /// Identifiant système d'un compte (lu dans /etc/passwd).
    pub fn uid_of(name: &str) -> Option<u32> {
        let text = std::fs::read_to_string("/etc/passwd").ok()?;
        text.lines().find_map(|l| {
            let mut f = l.split(':');
            (f.next()? == name).then_some(())?;
            f.next()?;
            f.next()?.parse().ok()
        })
    }

    /// Le processus à l'autre bout est-il root, ce processus-ci, ou ce compte ?
    pub fn peer_allowed(stream: &tokio::net::UnixStream, account: &str) -> bool {
        let Ok(cred) = stream.peer_cred() else { return false };
        let uid = cred.uid();
        uid == 0 || uid == unsafe { libc::geteuid() } || uid_of(account) == Some(uid)
    }

    /// Une ligne de texte (au plus `max` octets) lue au début d'un flux.
    pub async fn read_line<R: AsyncRead + Unpin>(read: &mut tokio::io::BufReader<R>, max: usize) -> Result<String> {
        let mut line = Vec::new();
        let fut = async {
            let mut limited = (&mut *read).take(max as u64);
            limited.read_until(b'\n', &mut line).await
        };
        tokio::time::timeout(Duration::from_secs(15), fut).await.map_err(|_| anyhow!("délai dépassé"))??;
        if !line.ends_with(b"\n") {
            bail!("ligne incomplète");
        }
        Ok(String::from_utf8_lossy(&line).trim().to_string())
    }

    /// Socket de la sortie web : le service du navigateur y ouvre une connexion par site.
    pub async fn serve_egress() -> Result<()> {
        let path = egress_path();
        let Some(dir) = path.parent().filter(|d| d.is_dir()) else {
            tracing::info!("{}", t!("portal browsing: no /run/portunia-gate folder, egress socket not opened", "navigation du portail : pas de dossier /run/portunia-gate, socket de sortie non ouvert"));
            return Ok(());
        };
        let _ = dir;
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        // Ouvert à tous les comptes : le compte appelant est vérifié, et il faut le jeton d'une session.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
        tracing::info!("{} {}", t!("portal browsing: egress socket", "navigation du portail : socket de sortie"), path.display());
        loop {
            let (stream, _) = listener.accept().await?;
            if !peer_allowed(&stream, WORKER_USER) {
                continue;
            }
            tokio::spawn(async move {
                let mut reader = tokio::io::BufReader::new(stream);
                let Ok(line) = read_line(&mut reader, 2048).await else { return };
                let Ok(ask) = serde_json::from_str::<Ask>(&line) else { return };
                let (answer, opened) = open_site(&ask).await;
                let mut stream = reader.into_inner();
                if stream.write_all(format!("{answer}\n").as_bytes()).await.is_err() {
                    return;
                }
                if let Some((nav, opened, tcp, mut stop)) = opened {
                    let mut cut = nav.cut();
                    let bytes = relay(stream, tcp, &mut cut, &mut stop).await;
                    opened.done(bytes);
                }
            });
        }
    }

    /// Connexion au service du navigateur : un Chromium neuf, piloté par le flux rendu.
    pub async fn launch(token: &str, (w, h): (u32, u32)) -> Result<tokio::net::UnixStream> {
        let path = control_path();
        let stream = tokio::time::timeout(Duration::from_secs(5), tokio::net::UnixStream::connect(&path))
            .await
            .map_err(|_| anyhow!(t!("the browser service is not answering", "le service du navigateur ne répond pas")))?
            .map_err(|e| anyhow!(t!(format!("browser service unavailable ({e})"), format!("service du navigateur indisponible ({e})"))))?;
        let head = json!({ "jeton": token, "largeur": w, "hauteur": h, "langue": crate::lang::get().code() });
        let mut reader = tokio::io::BufReader::new(stream);
        reader.get_mut().write_all(format!("{head}\n").as_bytes()).await?;
        let answer = tokio::time::timeout(Duration::from_secs(30), read_line(&mut reader, 4096))
            .await
            .map_err(|_| anyhow!(t!("the browser does not start (timed out)", "le navigateur ne démarre pas (délai dépassé)")))??;
        if answer != "ok" {
            bail!("{}", answer.strip_prefix("non ").unwrap_or(&answer).to_string());
        }
        if !reader.buffer().is_empty() {
            bail!("réponse inattendue du service du navigateur");
        }
        Ok(reader.into_inner())
    }
}

/// Socket de la sortie web pour les navigateurs du portail (lancé avec la Gate).
pub async fn serve_egress() -> Result<()> {
    #[cfg(unix)]
    return unix::serve_egress().await;
    #[cfg(not(unix))]
    Ok(())
}

// ---------- Session de navigation du portail ----------

/// Ce dont une session a besoin, préparé par le portail (droits déjà vérifiés).
pub struct Opening {
    pub user: uuid::Uuid,
    pub login: String,
    pub target: Target,
    pub addr: String,
    /// Empreinte du cookie de la session web : sa fin ferme le navigateur.
    pub portal: String,
    pub expires: chrono::DateTime<chrono::Utc>,
    pub idle: Duration,
    pub idle_warning: Duration,
    pub size: (u32, u32),
    pub url: Option<String>,
}

/// Ce que la session envoie à l'onglet et en reçoit (le WebSocket du portail).
pub enum ToTab {
    Json(Value),
    Image(Vec<u8>),
}

/// Session complète : du lancement de Chromium à sa fermeture. `from_tab` reçoit les messages
/// JSON de l'onglet ; `to_tab` lui envoie images et messages ; `closing` : sessions web fermées
/// par l'administrateur. Rend la raison de la fermeture.
pub async fn session(state: Arc<crate::State>, o: Opening, mut from_tab: mpsc::Receiver<Value>, to_tab: mpsc::Sender<ToTab>, mut closing: tokio::sync::watch::Receiver<u64>) -> String {
    if OPEN.fetch_add(1, Ordering::SeqCst) >= max_browsers() {
        OPEN.fetch_sub(1, Ordering::SeqCst);
        return t!("Too many browsers open on the Gate: try again in a moment", "Trop de navigateurs ouverts sur la Gate : réessayez dans un moment").into();
    }
    let token = match crate::keys::random::<32>() {
        Ok(b) => b.iter().map(|x| format!("{x:02x}")).collect::<String>(),
        Err(e) => {
            OPEN.fetch_sub(1, Ordering::SeqCst);
            return e.to_string();
        }
    };
    let reason = match egress::Navigation::start(state.clone(), o.user, &o.login, &o.target, &format!("{} (web)", o.addr), Some(o.portal.clone())).await {
        Ok(nav) => {
            let target = Arc::new(Mutex::new(o.target.clone()));
            let asked = Arc::new(AtomicBool::new(false));
            let (stop_tx, stop) = tokio::sync::watch::channel(false);
            SESSIONS.lock().unwrap().insert(token.clone(), Registered { nav: nav.clone(), target: target.clone(), asked: asked.clone(), stop });
            let r = drive(&state, &o, &token, &nav, &target, &asked, &mut from_tab, &to_tab, &mut closing).await;
            SESSIONS.lock().unwrap().remove(&token);
            // Connexions encore ouvertes : coupées, la session se ferme au journal tout de suite.
            let _ = stop_tx.send(true);
            match r {
                Ok(why) => why,
                Err(e) => format!("{}{e:#}", t!("Browser stopped: ", "Navigateur arrêté : ")),
            }
        }
        Err(e) => e.to_string(),
    };
    OPEN.fetch_sub(1, Ordering::SeqCst);
    reason
}

#[allow(clippy::too_many_arguments)]
async fn drive(
    state: &Arc<crate::State>,
    o: &Opening,
    token: &str,
    nav: &Arc<egress::Navigation>,
    target: &Arc<Mutex<Target>>,
    asked: &Arc<AtomicBool>,
    from_tab: &mut mpsc::Receiver<Value>,
    to_tab: &mpsc::Sender<ToTab>,
    closing: &mut tokio::sync::watch::Receiver<u64>,
) -> Result<String> {
    #[cfg(not(unix))]
    {
        let _ = (state, o, token, nav, target, asked, from_tab, to_tab, closing);
        bail!(t!("the portal browser needs a Linux Gate", "le navigateur du portail demande une Gate sous Linux"))
    }
    #[cfg(unix)]
    {
        let stream = unix::launch(token, o.size).await?;
        let (read, write) = stream.into_split();
        let (cdp, mut events) = Cdp::start(read, write);
        Browser::new(cdp, o.size, asked.clone()).run(state, o, nav, target, &mut events, from_tab, to_tab, closing).await
    }
}

/// Chromium piloté pour un onglet du portail : une seule page visible.
struct Browser {
    cdp: Arc<Cdp>,
    size: (u32, u32),
    /// Page montrée et sa session DevTools.
    page: String,
    session: String,
    asked: Arc<AtomicBool>,
}

impl Browser {
    fn new(cdp: Arc<Cdp>, size: (u32, u32), asked: Arc<AtomicBool>) -> Self {
        Browser { cdp, size, page: String::new(), session: String::new(), asked }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        self.cdp.call(Some(&self.session), method, params).await
    }

    async fn send(&self, method: &str, params: Value) -> bool {
        self.cdp.send(Some(&self.session), method, params).await
    }

    async fn screencast(&self) -> Result<()> {
        let (w, h) = self.size;
        self.call("Emulation.setDeviceMetricsOverride", json!({ "width": w, "height": h, "deviceScaleFactor": 1, "mobile": false })).await?;
        self.call("Page.startScreencast", json!({ "format": "jpeg", "quality": 70, "maxWidth": w, "maxHeight": h, "everyNthFrame": 1 })).await?;
        Ok(())
    }

    /// Première page, réglages (téléchargements refusés, envoi de fichiers bloqué), puis l'image.
    async fn open(&mut self) -> Result<()> {
        let cdp = &self.cdp;
        cdp.call(None, "Target.setDiscoverTargets", json!({ "discover": true })).await?;
        let mut page = None;
        for _ in 0..50 {
            let list = cdp.call(None, "Target.getTargets", json!({})).await?;
            page = list["targetInfos"].as_array().and_then(|l| l.iter().find(|t| t["type"] == "page").and_then(|t| t["targetId"].as_str().map(str::to_string)));
            if page.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let page = match page {
            Some(p) => p,
            None => cdp.call(None, "Target.createTarget", json!({ "url": "about:blank" })).await?["targetId"].as_str().unwrap_or_default().to_string(),
        };
        let attached = cdp.call(None, "Target.attachToTarget", json!({ "targetId": page, "flatten": true })).await?;
        self.session = attached["sessionId"].as_str().ok_or_else(|| anyhow!("DevTools : pas de session"))?.to_string();
        self.page = page;
        cdp.call(None, "Browser.setDownloadBehavior", json!({ "behavior": "deny" })).await?;
        self.call("Page.enable", json!({})).await?;
        self.call("Page.setInterceptFileChooserDialog", json!({ "enabled": true })).await?;
        self.screencast().await
    }

    /// Sans attendre : la réponse ne vient qu'une fois le site joint (ou refusé), parfois tard.
    async fn navigate(&self, url: &str) {
        self.asked.store(true, Ordering::SeqCst);
        self.send("Page.navigate", json!({ "url": url })).await;
    }

    async fn history(&self, step: i64) -> Result<()> {
        let h = self.call("Page.getNavigationHistory", json!({})).await?;
        let index = h["currentIndex"].as_i64().unwrap_or(0) + step;
        if let Some(entry) = h["entries"].as_array().and_then(|e| e.get(usize::try_from(index).ok()?)) {
            self.send("Page.navigateToHistoryEntry", json!({ "entryId": entry["id"] })).await;
        }
        Ok(())
    }

    /// Adresse et titre de la page montrée, pour la barre de l'onglet.
    async fn refresh(&self, to_tab: &mpsc::Sender<ToTab>) {
        if let Ok(r) = self.cdp.call(None, "Target.getTargetInfo", json!({ "targetId": self.page })).await {
            let info = &r["targetInfo"];
            let _ = to_tab.send(ToTab::Json(json!({ "t": "page", "url": info["url"], "titre": info["title"] }))).await;
        }
    }

    /// Texte sélectionné dans la page (ou dans le champ de saisie actif).
    async fn selection(&self) -> Result<String> {
        let expr = "(() => { const a = document.activeElement; \
            if (a && (a.tagName === 'INPUT' || a.tagName === 'TEXTAREA') && typeof a.selectionStart === 'number') return a.value.slice(a.selectionStart, a.selectionEnd); \
            return String(getSelection()); })()";
        let r = self.call("Runtime.evaluate", json!({ "expression": expr, "returnByValue": true })).await?;
        Ok(r["result"]["value"].as_str().unwrap_or_default().chars().take(MAX_PASTE).collect())
    }

    /// Message de l'onglet. Faux : l'onglet demande la fermeture.
    async fn from_tab(&mut self, v: Value, to_tab: &mpsc::Sender<ToTab>) -> Result<bool> {
        match v["t"].as_str().unwrap_or_default() {
            "souris" => {
                if let Some(p) = mouse(&v, self.size) {
                    self.send("Input.dispatchMouseEvent", p).await;
                }
            }
            "molette" => {
                if let Some(p) = wheel(&v, self.size) {
                    self.send("Input.dispatchMouseEvent", p).await;
                }
            }
            "touche" => {
                if let Some(p) = key(&v) {
                    self.send("Input.dispatchKeyEvent", p).await;
                }
            }
            "coller" => {
                let text: String = v["texte"].as_str().unwrap_or_default().chars().take(MAX_PASTE).collect();
                if !text.is_empty() {
                    self.send("Input.insertText", json!({ "text": text })).await;
                }
            }
            "copier" => {
                let text = self.selection().await.unwrap_or_default();
                let _ = to_tab.send(ToTab::Json(json!({ "t": "copie", "texte": text }))).await;
            }
            "aller" => match address(v["url"].as_str().unwrap_or_default()) {
                Some(url) => self.navigate(&url).await,
                None => {
                    let _ = to_tab.send(ToTab::Json(json!({ "t": "message", "texte": t!("Only http and https addresses open here.", "Seules les adresses http et https s'ouvrent ici.") }))).await;
                }
            },
            "retour" => self.history(-1).await?,
            "avancer" => self.history(1).await?,
            "recharger" => {
                self.send("Page.reload", json!({})).await;
            }
            "arreter" => {
                self.send("Page.stopLoading", json!({})).await;
            }
            "taille" => {
                let s = size(v["l"].as_u64().unwrap_or(1280) as u32, v["h"].as_u64().unwrap_or(800) as u32);
                if s != self.size {
                    self.size = s;
                    let _ = self.call("Page.stopScreencast", json!({})).await;
                    self.screencast().await?;
                }
            }
            "fermer" => return Ok(false),
            _ => {}
        }
        Ok(true)
    }

    /// Évènement de Chromium. `Some(raison)` : la session s'arrête.
    async fn event(&mut self, ev: Value, to_tab: &mpsc::Sender<ToTab>, popups: &mut Vec<String>) -> Option<String> {
        let method = ev["method"].as_str().unwrap_or_default();
        let p = &ev["params"];
        let ours = ev["sessionId"].as_str() == Some(self.session.as_str());
        match method {
            "Page.screencastFrame" if ours => {
                use base64::{engine::general_purpose::STANDARD, Engine};
                let image = p["data"].as_str().and_then(|d| STANDARD.decode(d).ok());
                // L'onglet reçoit l'image avant l'accusé : Chromium attend ainsi un onglet lent.
                if let Some(image) = image {
                    if to_tab.send(ToTab::Image(image)).await.is_err() {
                        return Some("onglet fermé".into());
                    }
                }
                self.send("Page.screencastFrameAck", json!({ "sessionId": p["sessionId"] })).await;
            }
            // Page chargée ou changée : adresse et titre à jour dans la barre de l'onglet.
            "Page.loadEventFired" | "Page.navigatedWithinDocument" if ours => self.refresh(to_tab).await,
            "Page.frameNavigated" if ours && p["frame"]["parentId"].is_null() => self.refresh(to_tab).await,
            "Page.javascriptDialogOpening" if ours => {
                let kind = p["type"].as_str().unwrap_or_default();
                self.send("Page.handleJavaScriptDialog", json!({ "accept": true, "promptText": "" })).await;
                if kind != "beforeunload" {
                    let text: String = p["message"].as_str().unwrap_or_default().chars().take(500).collect();
                    let _ = to_tab.send(ToTab::Json(json!({ "t": "message", "texte": text }))).await;
                }
            }
            "Page.fileChooserOpened" if ours => {
                let _ = to_tab.send(ToTab::Json(json!({ "t": "message", "texte": t!("Sending files is not allowed from this browser.", "L'envoi de fichiers n'est pas permis dans ce navigateur.") }))).await;
            }
            "Page.downloadWillBegin" | "Browser.downloadWillBegin" => {
                let _ = to_tab.send(ToTab::Json(json!({ "t": "message", "texte": t!("Downloads are not allowed from this browser.", "Les téléchargements ne sont pas permis dans ce navigateur.") }))).await;
            }
            "Target.targetCreated" | "Target.targetInfoChanged" => {
                let info = &p["targetInfo"];
                let id = info["targetId"].as_str().unwrap_or_default();
                if info["type"] != "page" {
                    return None;
                }
                let url = info["url"].as_str().unwrap_or_default();
                if id == self.page {
                    let _ = to_tab.send(ToTab::Json(json!({ "t": "page", "url": url, "titre": info["title"] }))).await;
                } else {
                    // Nouvel onglet ou fenêtre : son adresse s'ouvre dans la page montrée.
                    if !popups.iter().any(|x| x == id) {
                        popups.push(id.to_string());
                    }
                    if url.starts_with("http://") || url.starts_with("https://") {
                        popups.retain(|x| x != id);
                        let _ = self.cdp.send(None, "Target.closeTarget", json!({ "targetId": id })).await;
                        self.navigate(url).await;
                    }
                }
            }
            "Target.targetDestroyed" if p["targetId"].as_str() == Some(self.page.as_str()) => return Some(t!("The page was closed", "La page a été fermée").into()),
            "Target.detachedFromTarget" if p["sessionId"].as_str() == Some(self.session.as_str()) => return Some(t!("The page was closed", "La page a été fermée").into()),
            "Inspector.targetCrashed" if ours => {
                let _ = to_tab.send(ToTab::Json(json!({ "t": "message", "texte": t!("The page crashed: reloading.", "La page a planté : rechargement.") }))).await;
                self.send("Page.reload", json!({})).await;
            }
            _ => {}
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        mut self,
        state: &Arc<crate::State>,
        o: &Opening,
        nav: &Arc<egress::Navigation>,
        target: &Arc<Mutex<Target>>,
        events: &mut mpsc::Receiver<Value>,
        from_tab: &mut mpsc::Receiver<Value>,
        to_tab: &mpsc::Sender<ToTab>,
        closing: &mut tokio::sync::watch::Receiver<u64>,
    ) -> Result<String> {
        self.open().await?;
        let _ = to_tab.send(ToTab::Json(json!({ "t": "pret", "l": self.size.0, "h": self.size.1 }))).await;
        if let Some(url) = &o.url {
            self.navigate(url).await;
        }
        let mut cut = nav.cut();
        let mut popups: Vec<String> = Vec::new();
        let mut last_input = tokio::time::Instant::now();
        let mut warned = false;
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut checked = tokio::time::Instant::now();
        let reason = loop {
            tokio::select! {
                ev = events.recv() => match ev {
                    Some(ev) => {
                        if let Some(why) = self.event(ev, to_tab, &mut popups).await {
                            break why;
                        }
                    }
                    None => break t!("The browser has stopped", "Le navigateur s'est arrêté").into(),
                },
                msg = from_tab.recv() => match msg {
                    Some(v) => {
                        last_input = tokio::time::Instant::now();
                        warned = false;
                        if !self.from_tab(v, to_tab).await? {
                            break t!("Browser closed", "Navigateur fermé").into();
                        }
                    }
                    None => break "onglet fermé".into(),
                },
                _ = closing.changed() => break t!("Session closed by the administrator", "Session fermée par l'administrateur").into(),
                why = cut.reason() => break why,
                _ = tick.tick() => {
                    if chrono::Utc::now() >= o.expires {
                        break t!("Web session expired: sign in again", "Session web expirée : reconnectez-vous").into();
                    }
                    let quiet = last_input.elapsed();
                    if quiet >= o.idle {
                        break t!("Session closed after a period of inactivity", "Session fermée après une période d'inactivité").into();
                    }
                    if !warned && quiet + o.idle_warning >= o.idle {
                        warned = true;
                        let _ = to_tab.send(ToTab::Json(json!({ "t": "inactif", "s": (o.idle - quiet).as_secs() }))).await;
                    }
                    // Filtre modifié ou option retirée : pris en compte sous 30 secondes.
                    if checked.elapsed() >= Duration::from_secs(30) {
                        checked = tokio::time::Instant::now();
                        match crate::model::target_by_id(&state.db, o.target.id).await {
                            Ok(Some(t)) if t.is_egress() && t.sortie_portail => *target.lock().unwrap() = t,
                            Ok(_) => break t!("Browsing from the portal is no longer allowed for this server", "La navigation depuis le portail n'est plus permise pour ce serveur").into(),
                            Err(_) => {}
                        }
                    }
                }
            }
        };
        Ok(reason)
    }
}

// ---------- Service du navigateur (compte _portunia_gate_nav) ----------

/// `portunia-gate navigateur` : attend les demandes de la Gate, un Chromium par demande.
pub async fn serve_worker() -> Result<()> {
    #[cfg(unix)]
    return worker::serve().await;
    #[cfg(not(unix))]
    bail!(t!("the browser service needs Linux", "le service du navigateur demande Linux"))
}

/// Proxy SOCKS5 (côté service) : lit la demande de Chromium, rend le site et le port.
async fn socks_request<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<(String, u16)> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        bail!("SOCKS5 attendu");
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 0xFF]).await?;
        bail!("authentification SOCKS non prise en charge");
    }
    s.write_all(&[5, 0]).await?;
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != 5 || req[1] != 1 {
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("commande SOCKS non prise en charge");
    }
    let host = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let len = s.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            s.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| anyhow!("nom SOCKS invalide"))?
        }
        4 => {
            let mut ip = [0u8; 16];
            s.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => bail!("type d'adresse SOCKS inconnu"),
    };
    let port = s.read_u16().await?;
    Ok((host, port))
}

/// Réponse SOCKS5 : 0 réussi, 2 refusé par les règles, 4 hôte injoignable, 1 autre échec.
fn socks_reply(code: u8) -> [u8; 10] {
    [5, code, 0, 1, 0, 0, 0, 0, 0, 0]
}

/// Code SOCKS pour la réponse de la Gate.
fn socks_code(answer: &str) -> u8 {
    match answer {
        "ok" => 0,
        a if a.contains("injoignable") || a.contains("introuvable") => 4,
        a if a.starts_with("non ") => 2,
        _ => 1,
    }
}

/// Options de Chromium : profil à part, tout par le proxy, rien en dehors (ni DNS, ni QUIC,
/// ni WebRTC direct), aucun service de Google, pas de son.
fn chromium_args(profile: &std::path::Path, proxy_port: u16, (w, h): (u32, u32), lang: &str, no_sandbox: bool) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--headless=new".into(),
        "--remote-debugging-pipe".into(),
        format!("--user-data-dir={}", profile.display()),
        format!("--proxy-server=socks5://127.0.0.1:{proxy_port}"),
        "--proxy-bypass-list=<-loopback>".into(),
        "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".into(),
        "--disable-quic".into(),
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        // Aucun appel de Chromium pour lui-même (mises à jour, statistiques, suggestions) : tout ce
        // qui sort est noté comme visité par l'utilisateur.
        "--disable-background-networking".into(),
        "--disable-component-update".into(),
        "--disable-client-side-phishing-detection".into(),
        "--disable-component-extensions-with-background-pages".into(),
        "--disable-domain-reliability".into(),
        "--safebrowsing-disable-auto-update".into(),
        "--no-pings".into(),
        "--allow-browser-signin=false".into(),
        "--disable-sync".into(),
        "--disable-extensions".into(),
        "--disable-default-apps".into(),
        "--disable-breakpad".into(),
        "--disable-crash-reporter".into(),
        "--disable-features=Translate,MediaRouter,DialMediaRouteProvider,NetworkTimeServiceQuerying,OptimizationHints,OptimizationHintsFetching,OptimizationGuideModelDownloading,OptimizationTargetPrediction,AutofillServerCommunication,CertificateTransparencyComponentUpdater,InterestFeedContentSuggestions,PrivacySandboxSettings4,SafeBrowsingEnhancedProtection".into(),
        "--metrics-recording-only".into(),
        "--password-store=basic".into(),
        "--use-mock-keychain".into(),
        "--mute-audio".into(),
        "--disable-dev-shm-usage".into(),
        "--disable-gpu".into(),
        format!("--window-size={w},{h}"),
        format!("--lang={}", if lang == "fr" { "fr-FR" } else { "en-US" }),
    ];
    if no_sandbox {
        args.push("--no-sandbox".into());
    }
    args.push("about:blank".into());
    args
}

#[cfg(unix)]
mod worker {
    use std::{os::unix::fs::PermissionsExt, os::unix::process::CommandExt, process::Stdio};

    use tokio::{
        io::AsyncBufReadExt,
        net::{TcpListener, UnixListener, UnixStream},
    };

    use super::{unix::*, *};

    /// Sessions ouvertes par ce service, au plus.
    const MAX_SESSIONS: usize = 32;
    static SESSIONS_OPEN: AtomicUsize = AtomicUsize::new(0);

    #[derive(Deserialize)]
    struct Head {
        jeton: String,
        largeur: u32,
        hauteur: u32,
        #[serde(default)]
        langue: String,
    }

    fn chromium() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("PORTUNIA_GATE_CHROMIUM") {
            return Some(PathBuf::from(p));
        }
        // Le programme lui-même d'abord : le script /usr/bin/chromium de Debian ajoute les options de
        // /etc/chromium.d (clés d'API de Google, extensions installées à distance).
        ["/usr/lib/chromium/chromium", "/usr/lib/chromium-browser/chromium-browser", "/opt/google/chrome/chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome-stable"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
    }

    pub async fn serve() -> Result<()> {
        let browser = chromium().ok_or_else(|| anyhow!(t!("Chromium not found: apt install chromium", "Chromium introuvable : apt install chromium")))?;
        let path = control_path();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
        let no_sandbox = std::env::var("PORTUNIA_GATE_NAVIGATEUR_SANS_BAC_A_SABLE").is_ok_and(|v| v == "1");
        if no_sandbox {
            tracing::warn!("{}", t!("Chromium runs without its sandbox (PORTUNIA_GATE_NAVIGATEUR_SANS_BAC_A_SABLE=1)", "Chromium tourne sans son bac à sable (PORTUNIA_GATE_NAVIGATEUR_SANS_BAC_A_SABLE=1)"));
        }
        tracing::info!("{} {} ({})", t!("browser service listening on", "service du navigateur en écoute sur"), path.display(), browser.display());
        loop {
            let (stream, _) = listener.accept().await?;
            if !peer_allowed(&stream, GATE_USER) {
                tracing::warn!("{}", t!("connection refused: not the Gate", "connexion refusée : ce n'est pas la Gate"));
                continue;
            }
            if SESSIONS_OPEN.fetch_add(1, Ordering::SeqCst) >= MAX_SESSIONS {
                SESSIONS_OPEN.fetch_sub(1, Ordering::SeqCst);
                let mut s = stream;
                let _ = s.write_all(b"non trop de navigateurs\n").await;
                continue;
            }
            let browser = browser.clone();
            tokio::spawn(async move {
                if let Err(e) = one(stream, &browser, no_sandbox).await {
                    tracing::warn!("{} {e:#}", t!("browser:", "navigateur :"));
                }
                SESSIONS_OPEN.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }

    /// Paire de tubes pour `--remote-debugging-pipe` : Chromium lit le descripteur 3 et écrit le 4.
    fn pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
        use std::os::fd::FromRawFd;
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            bail!("pipe2: {}", std::io::Error::last_os_error());
        }
        Ok(unsafe { (std::os::fd::OwnedFd::from_raw_fd(fds[0]), std::os::fd::OwnedFd::from_raw_fd(fds[1])) })
    }

    /// Une session : proxy, Chromium, relais du protocole DevTools, puis tout est effacé.
    async fn one(stream: UnixStream, browser: &std::path::Path, no_sandbox: bool) -> Result<()> {
        use std::os::fd::AsRawFd;
        let mut reader = tokio::io::BufReader::new(stream);
        let head: Head = serde_json::from_str(&read_line(&mut reader, 4096).await?)?;
        let size = size(head.largeur, head.hauteur);
        let proxy = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = proxy.local_addr()?.port();
        let profile = std::env::temp_dir().join(format!("portunia-navigateur-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&profile)?;
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o700))?;
        let ((cmd_read, cmd_write), (out_read, out_write)) = (pipe()?, pipe()?);
        let (child_in, child_out) = (cmd_read.as_raw_fd(), out_write.as_raw_fd());
        let mut command = std::process::Command::new(browser);
        command
            .args(chromium_args(&profile, proxy_port, size, &head.langue, no_sandbox))
            .env("HOME", &profile)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(child_in, 3) < 0 || libc::dup2(child_out, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let spawned = command.spawn();
        drop(cmd_read);
        drop(out_write);
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&profile);
                let mut s = reader.into_inner();
                let _ = s.write_all(format!("non Chromium ne démarre pas ({e})\n").as_bytes()).await;
                return Err(e.into());
            }
        };
        let pid = child.id() as i32;
        // Dernières lignes de Chromium : au journal du service s'il s'arrête mal.
        let tail: Arc<Mutex<Vec<String>>> = Arc::default();
        if let Some(err) = child.stderr.take() {
            let tail = tail.clone();
            std::thread::spawn(move || {
                use std::io::BufRead;
                for line in std::io::BufReader::new(err).lines().map_while(Result::ok) {
                    let mut t = tail.lock().unwrap();
                    t.push(line);
                    if t.len() > 20 {
                        t.remove(0);
                    }
                }
            });
        }
        let to_chromium = tokio::net::unix::pipe::Sender::from_owned_fd(cmd_write)?;
        let from_chromium = tokio::net::unix::pipe::Receiver::from_owned_fd(out_read)?;
        let mut stream = reader.into_inner();
        stream.write_all(b"ok\n").await?;
        let (mut gate_read, mut gate_write) = stream.into_split();
        let token = head.jeton;
        let proxying = async move {
            loop {
                let Ok((conn, _)) = proxy.accept().await else { break };
                let token = token.clone();
                tokio::spawn(async move {
                    let _ = proxy_one(conn, &token).await;
                });
            }
        };
        let mut to_chromium = to_chromium;
        let mut from_chromium = from_chromium;
        tokio::select! {
            _ = tokio::io::copy(&mut gate_read, &mut to_chromium) => {}
            _ = tokio::io::copy(&mut from_chromium, &mut gate_write) => {}
            _ = proxying => {}
        }
        // Fin : Chromium et ses processus, puis le profil.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let status = tokio::task::spawn_blocking(move || child.wait()).await;
        let _ = std::fs::remove_dir_all(&profile);
        if let Ok(Ok(s)) = status {
            if !s.success() && s.code().is_some() {
                tracing::warn!("Chromium : {s} — {}", tail.lock().unwrap().join(" | "));
            }
        }
        Ok(())
    }

    /// Une connexion de Chromium : demandée à la Gate avec le jeton de la session.
    async fn proxy_one(mut conn: tokio::net::TcpStream, token: &str) -> Result<()> {
        let (host, port) = socks_request(&mut conn).await?;
        if chromium_own(&host) {
            conn.write_all(&socks_reply(2)).await?;
            return Ok(());
        }
        let gate = match UnixStream::connect(egress_path()).await {
            Ok(g) => g,
            Err(e) => {
                conn.write_all(&socks_reply(1)).await?;
                bail!("sortie web indisponible : {e}");
            }
        };
        let mut reader = tokio::io::BufReader::new(gate);
        let ask = json!({ "jeton": token, "hote": host, "port": port });
        reader.get_mut().write_all(format!("{ask}\n").as_bytes()).await?;
        let mut answer = String::new();
        tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut answer)).await.map_err(|_| anyhow!("délai dépassé"))??;
        let code = socks_code(answer.trim());
        conn.write_all(&socks_reply(code)).await?;
        if code != 0 {
            return Ok(());
        }
        let leftover = reader.buffer().to_vec();
        let mut gate = reader.into_inner();
        if !leftover.is_empty() {
            conn.write_all(&leftover).await?;
        }
        let _ = tokio::io::copy_bidirectional(&mut conn, &mut gate).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adresses_tapees() {
        assert_eq!(address("https://example.com/a b"), None);
        assert_eq!(address("https://example.com/x?y=1").as_deref(), Some("https://example.com/x?y=1"));
        assert_eq!(address("HTTP://Example.com").as_deref(), Some("HTTP://Example.com"));
        assert_eq!(address("example.com/page").as_deref(), Some("https://example.com/page"));
        assert_eq!(address("file:///etc/passwd"), None);
        assert_eq!(address("chrome://settings"), None);
        assert_eq!(address("javascript:alert(1)"), None);
        assert_eq!(address("about:blank"), None);
        assert_eq!(address("data:text/html,x"), None);
        assert_eq!(address("ftp://x.org"), None);
        assert_eq!(address("   "), None);
        assert_eq!(address("météo à Nantes").as_deref(), Some("https://duckduckgo.com/?q=m%C3%A9t%C3%A9o+%C3%A0+Nantes"));
        assert_eq!(address("localhost").as_deref(), Some("https://duckduckgo.com/?q=localhost"));
    }

    #[test]
    fn evenements_de_l_onglet() {
        let s = (1000, 800);
        let m = mouse(&json!({ "t": "souris", "e": "bas", "x": 5000, "y": -3, "b": 2, "bs": 2, "n": 2, "m": 255 }), s).unwrap();
        assert_eq!(m["type"], "mousePressed");
        assert_eq!(m["x"], 1000.0);
        assert_eq!(m["y"], 0.0);
        assert_eq!(m["button"], "right");
        assert_eq!(m["clickCount"], 2);
        assert_eq!(m["modifiers"], 15);
        let mv = mouse(&json!({ "e": "bouge", "x": 1, "y": 2, "b": 0 }), s).unwrap();
        assert_eq!(mv["button"], "none");
        assert!(mouse(&json!({ "e": "autre", "x": 1, "y": 2 }), s).is_none());
        let a = key(&json!({ "e": "bas", "key": "a", "code": "KeyA", "kc": 65, "m": 0 })).unwrap();
        assert_eq!((a["type"].as_str(), a["text"].as_str()), (Some("keyDown"), Some("a")));
        let ctrl = key(&json!({ "e": "bas", "key": "a", "code": "KeyA", "kc": 65, "m": 2 })).unwrap();
        assert_eq!((ctrl["type"].as_str(), ctrl["text"].as_str()), (Some("rawKeyDown"), Some("")));
        let enter = key(&json!({ "e": "bas", "key": "Enter", "code": "Enter", "kc": 13 })).unwrap();
        assert_eq!(enter["text"], "\r");
        let up = key(&json!({ "e": "haut", "key": "a" })).unwrap();
        assert_eq!(up["type"], "keyUp");
        assert!(key(&json!({ "e": "bas", "key": "x".repeat(40) })).is_none());
        let w = wheel(&json!({ "x": 10, "y": 10, "dx": 0, "dy": 1e9 }), s).unwrap();
        assert_eq!(w["deltaY"], 10000.0);
        assert_eq!(size(10, 99999), (320, 2160));
    }

    #[test]
    fn options_de_chromium() {
        let a = chromium_args(std::path::Path::new("/tmp/p"), 4321, (1280, 800), "fr", false);
        assert!(a.contains(&"--proxy-server=socks5://127.0.0.1:4321".to_string()));
        assert!(a.contains(&"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".to_string()));
        assert!(a.contains(&"--proxy-bypass-list=<-loopback>".to_string()));
        assert!(a.contains(&"--disable-quic".to_string()));
        assert!(a.contains(&"--lang=fr-FR".to_string()));
        assert!(!a.iter().any(|x| x == "--no-sandbox"));
        assert!(chromium_args(std::path::Path::new("/tmp/p"), 1, (1, 1), "en", true).iter().any(|x| x == "--no-sandbox"));
        assert_eq!(socks_code("ok"), 0);
        assert_eq!(socks_code("non domaine bloqué"), 2);
        assert_eq!(socks_code("non injoignable"), 4);
        assert_eq!(socks_code("??"), 1);
        assert!(chromium_own("Update.GoogleAPIs.com."));
        assert!(!chromium_own("accounts.google.com"));
        assert!(!chromium_own("www.google.com"));
    }

    #[tokio::test]
    async fn relais_coupe_a_la_fin() {
        let (mut client, a) = tokio::io::duplex(1024);
        let (b, mut site) = tokio::io::duplex(1024);
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let (_guard, mut cut) = crate::live::Registry::default().watch(crate::live::Watched {
            user: uuid::Uuid::nil(), login: "x", target: None, web: false, recorded: false, session: None, portal: None,
        });
        let task = tokio::spawn(async move { relay(a, b, &mut cut, &mut rx).await });
        client.write_all(b"GET").await.unwrap();
        let mut got = [0u8; 3];
        site.read_exact(&mut got).await.unwrap();
        site.write_all(b"OK!!").await.unwrap();
        let mut back = [0u8; 4];
        client.read_exact(&mut back).await.unwrap();
        // Le site garde sa connexion ouverte : la fin de la session la coupe quand même.
        tx.send(true).unwrap();
        let total = tokio::time::timeout(Duration::from_secs(2), task).await.expect("relais toujours ouvert").unwrap();
        assert_eq!(total, 7);
    }

    #[tokio::test]
    async fn demande_socks() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move { socks_request(&mut server).await });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut r = [0u8; 2];
        client.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 0]);
        let mut req = vec![5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        assert_eq!(task.await.unwrap().unwrap(), ("example.com".to_string(), 443));
    }

    #[tokio::test]
    async fn protocole_devtools() {
        let (ours, theirs) = tokio::io::duplex(1 << 16);
        let (read, write) = tokio::io::split(ours);
        let (cdp, mut events) = Cdp::start(read, write);
        let (mut t_read, mut t_write) = tokio::io::split(theirs);
        let fake = tokio::spawn(async move {
            // Chromium factice : un évènement, puis la réponse à l'appel 1.
            let mut buf = Vec::new();
            let mut b = [0u8; 1];
            loop {
                t_read.read_exact(&mut b).await.unwrap();
                if b[0] == 0 {
                    break;
                }
                buf.push(b[0]);
            }
            let asked: Value = serde_json::from_slice(&buf).unwrap();
            assert_eq!(asked["method"], "Page.navigate");
            assert_eq!(asked["sessionId"], "S");
            t_write.write_all(b"{\"method\":\"Page.loadEventFired\",\"params\":{}}\0").await.unwrap();
            t_write.write_all(format!("{{\"id\":{},\"result\":{{\"frameId\":\"F\"}}}}\0", asked["id"]).as_bytes()).await.unwrap();
            t_write.write_all(b"{\"id\":99,\"error\":{\"message\":\"x\"}}\0").await.unwrap();
        });
        let r = cdp.call(Some("S"), "Page.navigate", json!({ "url": "https://example.com" })).await.unwrap();
        assert_eq!(r["frameId"], "F");
        assert_eq!(events.recv().await.unwrap()["method"], "Page.loadEventFired");
        fake.await.unwrap();
    }
}
