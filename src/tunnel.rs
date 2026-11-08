//! Tunnel Cloudflare géré par la Gate : rien à installer en root. La Gate télécharge cloudflared
//! (empreinte vérifiée), le lance sous son propre compte et le relance s'il s'arrête. Elle suit les
//! versions publiées par Cloudflare et passe à la dernière quand personne n'est connecté.
//! Le jeton du tunnel est chiffré par le coffre et passé par l'environnement, jamais en argument.

use crate::{model, portal, State};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use chrono::{DateTime, Timelike, Utc};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// Version de cloudflared livrée avec la Gate (la plus ancienne qu'elle lance), et empreintes
/// publiées par Cloudflare pour celle-ci. Les suivantes arrivent par la mise à jour automatique.
pub const VERSION: &str = "2026.10.7";
const BINARIES: &[(&str, &str, &str)] = &[
    ("x86_64", "cloudflared-linux-amd64", "1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872"),
    ("aarch64", "cloudflared-linux-arm64", "3df43aedc9ff291d1735b5cb576cb97e0b157488796db2e32b28aecabb445775"),
];
/// Métriques du cloudflared de la Gate ; celui d'installer.sh ou de Docker garde le 20241.
const METRICS: &str = "127.0.0.1:20242";
const SETTING: &str = "portail_tunnel_jeton";
const PURPOSE: &str = "reglage:tunnel";
/// Délai d'attente entre deux relances, doublé à chaque échec.
const RETRY_MIN: u64 = 5;
const RETRY_MAX: u64 = 120;

// ---------- Jeton ----------

/// Ce qu'on peut montrer d'un jeton : jamais son secret.
#[derive(Debug, PartialEq)]
pub struct Token {
    pub account: String,
    pub tunnel: String,
}

/// Lit un jeton collé seul ou dans la commande d'installation de Cloudflare (« … --token eyJ… »).
pub fn parse(input: &str) -> Result<(String, Token)> {
    let bad = || anyhow!(t!("This does not look like a Cloudflare tunnel token.", "Ce jeton ne ressemble pas à un jeton de tunnel Cloudflare."));
    let token = input
        .split(|c: char| !(c.is_ascii_alphanumeric() || "+/=_-".contains(c)))
        .filter(|w| w.starts_with("eyJ"))
        .max_by_key(|w| w.len())
        .ok_or_else(bad)?;
    let trimmed = token.trim_end_matches('=');
    let raw = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|_| bad())?;
    let v: Value = serde_json::from_slice(&raw).map_err(|_| bad())?;
    let field = |k: &str| v[k].as_str().map(str::to_owned).filter(|s| !s.is_empty());
    let (Some(account), Some(tunnel), Some(_)) = (field("a"), field("t"), field("s")) else { return Err(bad()) };
    if !account.chars().all(|c| c.is_ascii_hexdigit()) || uuid::Uuid::parse_str(&tunnel).is_err() {
        return Err(bad());
    }
    Ok((token.to_string(), Token { account, tunnel }))
}

/// Jeton enregistré (déchiffré), s'il y en a un.
pub async fn token(state: &State) -> Result<Option<String>> {
    let Some(sealed) = model::setting(&state.db, SETTING).await?.and_then(|v| v.as_str().map(str::to_owned)).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::STANDARD.decode(sealed)?;
    Ok(Some(String::from_utf8(state.keys.open(PURPOSE, &bytes)?)?))
}

/// Enregistre (ou efface, si vide) le jeton. Rend ce qu'on peut en montrer.
pub async fn set_token(state: &State, input: &str) -> Result<Option<Token>> {
    if input.trim().is_empty() {
        model::set_setting(&state.db, SETTING, json!("")).await?;
        return Ok(None);
    }
    let (token, info) = parse(input)?;
    let sealed = base64::engine::general_purpose::STANDARD.encode(state.keys.seal(PURPOSE, token.as_bytes())?);
    model::set_setting(&state.db, SETTING, json!(sealed)).await?;
    Ok(Some(info))
}

// ---------- État ----------

#[derive(Clone)]
struct Status {
    /// arrete, telechargement, demarrage, relie, deconnecte, erreur
    state: &'static str,
    error: Option<String>,
    since: Option<DateTime<Utc>>,
    connections: u32,
}

static STATUS: Mutex<Status> = Mutex::new(Status { state: "arrete", error: None, since: None, connections: 0 });

fn status() -> Status {
    STATUS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn set_status(state: &'static str, error: Option<String>, connections: u32) {
    let mut s = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    if s.state != state {
        s.since = Some(Utc::now());
    }
    s.state = state;
    s.error = error;
    s.connections = connections;
}

/// Page « /ready » des métriques de cloudflared : connexions prêtes vers Cloudflare.
pub async fn probe(addr: &str) -> Option<u32> {
    let ask = async {
        let mut tcp = tokio::net::TcpStream::connect(addr).await?;
        tcp.write_all(b"GET /ready HTTP/1.0\r\nHost: localhost\r\n\r\n").await?;
        let mut buf = Vec::new();
        tcp.take(4096).read_to_end(&mut buf).await?;
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).into_owned())
    };
    let text = tokio::time::timeout(Duration::from_secs(2), ask).await.ok()?.ok()?;
    let ready = text.split_once("\"readyConnections\":").and_then(|(_, rest)| {
        rest.trim_start().split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
    });
    Some(if text.starts_with("HTTP/1.") && text.contains(" 200 ") { ready.unwrap_or(1).max(1) } else { 0 })
}

/// État résumé pour l'onglet : relie, deconnecte ou absent.
pub async fn summary(state: &State) -> &'static str {
    let managed = token(state).await.ok().flatten().is_some();
    let n = if managed { (status().state == "relie").then_some(1).or(Some(0)) } else { probe(&state.config.tunnel_metrics).await };
    match n {
        Some(n) if n > 0 => "relie",
        Some(_) => "deconnecte",
        None => "absent",
    }
}

/// Tout ce que l'onglet montre du tunnel géré.
pub async fn report(state: &State) -> Result<Value> {
    let saved = token(state).await?;
    let info = saved.as_deref().and_then(|t| parse(t).ok()).map(|(_, i)| i);
    let s = status();
    let port = state.config.portal_listen.rsplit(':').next().unwrap_or("8445").to_string();
    // Un cloudflared installé à côté (installer.sh, Docker) répond sur l'autre port de métriques.
    let other = if saved.is_none() { probe(&state.config.tunnel_metrics).await } else { None };
    let up = upgrade().clone();
    let system = state.config.cloudflared.is_some();
    let installed = if system { None } else { chosen(state).await.ok().map(|(v, _)| v) };
    let version = running().or(installed);
    let dispo = up.latest.clone().filter(|l| version.as_deref().is_some_and(|v| crate::update::newer(l, v)));
    Ok(json!({
        "jeton_defini": saved.is_some(),
        "tunnel_id": info.as_ref().map(|i| i.tunnel.clone()),
        "etat": s.state,
        "erreur": s.error,
        "depuis": s.since,
        "connexions": s.connections,
        "version": version,
        "version_dispo": dispo,
        "maj_auto": auto(state).await,
        "maj_verifiee": up.checked,
        "maj_erreur": up.error,
        "maj_prete": up.ready.map(|(v, _)| v),
        "maj_systeme": system,
        "service": format!("http://localhost:{port}"),
        "externe": other.is_some(),
        "externe_relie": other.is_some_and(|n| n > 0),
    }))
}

// ---------- Programme ----------

fn dir(state: &State) -> PathBuf {
    state.config.data_dir.join("cloudflared")
}

/// Fichier publié par Cloudflare pour cette machine, et son empreinte dans la version livrée.
fn asset() -> Result<(&'static str, &'static str)> {
    let arch = std::env::consts::ARCH;
    BINARIES
        .iter()
        .find(|(a, _, _)| *a == arch)
        .filter(|_| cfg!(target_os = "linux"))
        .map(|&(_, name, sum)| (name, sum))
        .ok_or_else(|| anyhow!(t!("no cloudflared for this system: set PORTUNIA_GATE_CLOUDFLARED", "pas de cloudflared pour ce système : réglez PORTUNIA_GATE_CLOUDFLARED")))
}

/// Version à lancer et son empreinte : la dernière installée par une mise à jour, sinon celle
/// livrée avec la Gate.
async fn chosen(state: &State) -> Result<(String, String)> {
    let (_, sum) = asset()?;
    let saved = model::setting(&state.db, INSTALLED).await?.unwrap_or(Value::Null);
    if let (Some(v), Some(s)) = (saved["version"].as_str(), saved["sha256"].as_str()) {
        if crate::update::newer(v, VERSION) {
            return Ok((v.to_string(), s.to_string()));
        }
    }
    Ok((VERSION.to_string(), sum.to_string()))
}

/// cloudflared prêt à lancer, et sa version : celui donné par PORTUNIA_GATE_CLOUDFLARED (version
/// vide : le système le tient à jour), sinon la version choisie, téléchargée une fois et vérifiée.
async fn binary(state: &State) -> Result<(PathBuf, String)> {
    if let Some(path) = &state.config.cloudflared {
        return Ok((path.clone(), String::new()));
    }
    let (name, _) = asset()?;
    let (version, sum) = chosen(state).await?;
    let dest = dir(state).join(format!("cloudflared-{version}"));
    if let Ok(bytes) = tokio::fs::read(&dest).await {
        if crate::keys::sha256_hex(&bytes) == sum {
            return Ok((dest, version));
        }
    }
    set_status("telechargement", None, 0);
    let bytes = download(&version, name, &sum).await?;
    let dest = store(state, &version, &bytes).await?;
    crate::audit::note(&state.db, "systeme", "portail.cloudflared", json!({ "version": version, "sha256": sum })).await;
    Ok((dest, version))
}

/// Télécharge une version publiée de cloudflared et vérifie son empreinte.
async fn download(version: &str, name: &str, sum: &str) -> Result<Vec<u8>> {
    let url = format!("https://github.com/cloudflare/cloudflared/releases/download/{version}/{name}");
    let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let resp = ureq::get(&url).timeout(Duration::from_secs(300)).call()?;
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(resp.into_reader(), 256 * 1024 * 1024), &mut out)?;
        Ok(out)
    })
    .await?
    .context(t!("cannot download cloudflared from GitHub", "téléchargement de cloudflared depuis GitHub impossible"))?;
    anyhow::ensure!(
        crate::keys::sha256_hex(&bytes) == sum,
        t!("the downloaded cloudflared does not have the expected fingerprint", "le cloudflared téléchargé n'a pas l'empreinte attendue")
    );
    Ok(bytes)
}

/// Range un cloudflared vérifié et retire les autres versions (celle qui tourne continue jusqu'à
/// sa relance : Linux garde le fichier ouvert).
async fn store(state: &State, version: &str, bytes: &[u8]) -> Result<PathBuf> {
    let name = format!("cloudflared-{version}");
    let dest = dir(state).join(&name);
    tokio::fs::create_dir_all(dir(state)).await?;
    let tmp = dest.with_extension("tmp");
    tokio::fs::write(&tmp, bytes).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700)).await?;
    }
    tokio::fs::rename(&tmp, &dest).await?;
    if let Ok(mut entries) = tokio::fs::read_dir(dir(state)).await {
        while let Ok(Some(e)) = entries.next_entry().await {
            let other = e.file_name().to_string_lossy().into_owned();
            if other.starts_with("cloudflared-") && other != name {
                let _ = tokio::fs::remove_file(e.path()).await;
            }
        }
    }
    Ok(dest)
}

// ---------- Mises à jour ----------

/// Version installée par une mise à jour : { version, sha256, date }.
const INSTALLED: &str = "portail_tunnel_cloudflared";
/// Mise à jour automatique : oui par défaut.
const AUTO: &str = "portail_tunnel_maj_auto";
/// Demande de mise à jour immédiate (Portunia, ligne de commande) : { n, par }.
const ORDER: &str = "portail_tunnel_maj_ordre";
const LATEST: &str = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest";
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
/// Prête depuis plus longtemps, une mise à jour passe la nuit même avec des sessions ouvertes.
const WAIT_MAX: i64 = 24 * 3600;
const NIGHT: std::ops::Range<u32> = 3..5;

#[derive(Clone)]
struct Upgrade {
    latest: Option<String>,
    checked: Option<DateTime<Utc>>,
    error: Option<String>,
    /// Version installée, pas encore lancée, et depuis quand.
    ready: Option<(String, DateTime<Utc>)>,
    /// Demandée par un administrateur : lancée sans attendre.
    now: bool,
}

static UPGRADE: Mutex<Upgrade> = Mutex::new(Upgrade { latest: None, checked: None, error: None, ready: None, now: false });
/// Version du cloudflared lancé par la Gate.
static RUNNING: Mutex<Option<String>> = Mutex::new(None);
static WAKE: std::sync::LazyLock<tokio::sync::Notify> = std::sync::LazyLock::new(tokio::sync::Notify::new);

fn upgrade() -> std::sync::MutexGuard<'static, Upgrade> {
    UPGRADE.lock().unwrap_or_else(|e| e.into_inner())
}

fn running() -> Option<String> {
    RUNNING.lock().unwrap_or_else(|e| e.into_inner()).clone().filter(|v| !v.is_empty())
}

pub async fn auto(state: &State) -> bool {
    model::setting(&state.db, AUTO).await.ok().flatten().and_then(|v| v.as_bool()).unwrap_or(true)
}

pub async fn set_auto(state: &State, on: bool) -> Result<()> {
    model::set_setting(&state.db, AUTO, json!(on)).await
}

/// Mise à jour demandée maintenant : la Gate vérifie, installe et relance sans attendre.
pub async fn ask_upgrade(state: &State, by: &str) -> Result<()> {
    let n = model::setting(&state.db, ORDER).await?.and_then(|v| v["n"].as_i64()).unwrap_or(0) + 1;
    model::set_setting(&state.db, ORDER, json!({ "n": n, "par": by })).await?;
    WAKE.notify_one();
    Ok(())
}

async fn order(state: &State) -> i64 {
    model::setting(&state.db, ORDER).await.ok().flatten().and_then(|v| v["n"].as_i64()).unwrap_or(0)
}

/// Dernière version de cloudflared et empreinte de `name`, lues dans la fiche GitHub de la
/// version. GitHub la donne deux fois (fichier et notes de Cloudflare) : les deux doivent concorder.
fn latest_from(v: &Value, name: &str) -> Result<(String, String)> {
    anyhow::ensure!(v["draft"] != json!(true) && v["prerelease"] != json!(true), "pre-release");
    let tag = v["tag_name"]
        .as_str()
        .filter(|t| t.chars().all(|c| c.is_ascii_digit() || c == '.') && crate::update::parse_version(t).is_some())
        .ok_or_else(|| anyhow!(t!("unexpected cloudflared version", "version de cloudflared inattendue")))?;
    let digest = v["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["name"] == json!(name))
        .and_then(|a| a["digest"].as_str())
        .and_then(|d| d.strip_prefix("sha256:"))
        .filter(|d| d.len() == 64 && d.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow!("{} {name}", t!("no fingerprint published for", "aucune empreinte publiée pour")))?;
    let line = format!("{name}: {digest}");
    anyhow::ensure!(
        v["body"].as_str().unwrap_or_default().lines().any(|l| l.trim() == line),
        t!("the fingerprints published by Cloudflare do not match", "les empreintes publiées par Cloudflare ne concordent pas")
    );
    Ok((tag.to_string(), digest.to_lowercase()))
}

fn fetch_latest(name: &str) -> Result<(String, String)> {
    let v = ureq::get(LATEST)
        .set("Accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(20))
        .call()
        .context(t!("cannot reach GitHub to check cloudflared", "GitHub injoignable pour vérifier cloudflared"))?
        .into_string()?;
    let v: Value = serde_json::from_str(&v)?;
    latest_from(&v, name)
}

/// Vérifie la dernière version et l'installe si la Gate le doit. `asked` : demande d'un administrateur.
async fn check_upgrade(state: &State, asked: bool) -> Result<()> {
    let (name, _) = asset()?;
    let (latest, sum) = tokio::task::spawn_blocking(move || fetch_latest(name)).await??;
    {
        let mut u = upgrade();
        u.latest = Some(latest.clone());
        u.checked = Some(Utc::now());
        u.error = None;
    }
    let (current, _) = chosen(state).await?;
    if crate::update::newer(&latest, &current) {
        if !asked && !auto(state).await {
            return Ok(());
        }
        let bytes = download(&latest, name, &sum).await?;
        store(state, &latest, &bytes).await?;
        model::set_setting(&state.db, INSTALLED, json!({ "version": latest, "sha256": sum, "date": Utc::now() })).await?;
        crate::audit::note(&state.db, "systeme", "portail.cloudflared", json!({ "version": latest, "avant": current, "sha256": sum, "auto": !asked })).await;
        tracing::info!("cloudflared {latest} {}", t!("installed, started when nobody is connected", "installé, lancé quand personne n'est connecté"));
        upgrade().ready = Some((latest, Utc::now()));
    }
    if asked {
        upgrade().now = true;
    }
    Ok(())
}

/// Suit les versions de cloudflared : toutes les 6 heures tant que la Gate sert un tunnel, et à la
/// demande d'un administrateur.
async fn upgrades(state: Arc<State>) {
    let mut seen = order(&state).await;
    let mut next = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let wait = next.min(tokio::time::Instant::now() + Duration::from_secs(30));
        tokio::select! {
            _ = tokio::time::sleep_until(wait) => {}
            _ = WAKE.notified() => {}
        }
        let n = order(&state).await;
        let asked = n != seen;
        seen = n;
        let due = tokio::time::Instant::now() >= next;
        if !asked && !due {
            continue;
        }
        if due {
            next = tokio::time::Instant::now() + CHECK_EVERY;
        }
        if state.config.cloudflared.is_some() || (!asked && token(&state).await.ok().flatten().is_none()) {
            continue;
        }
        if let Err(e) = check_upgrade(&state, asked).await {
            let msg = format!("{e:#}");
            tracing::warn!("cloudflared : {msg}");
            upgrade().error = Some(msg);
            next = next.min(tokio::time::Instant::now() + Duration::from_secs(3600));
        }
    }
}

/// Faut-il relancer cloudflared sur la version installée ? Tout de suite si un administrateur l'a
/// demandé, sinon quand aucune session n'est ouverte, ou la nuit après un jour d'attente.
fn restart_due(state: &State, version: &str) -> bool {
    let u = upgrade();
    let Some((ready, since)) = &u.ready else { return false };
    if version.is_empty() || ready == version {
        return false;
    }
    if u.now || (state.live.sessions().is_empty() && state.web.active() == 0) {
        return true;
    }
    let late = (Utc::now() - *since).num_seconds() >= WAIT_MAX && NIGHT.contains(&chrono::Local::now().hour());
    if late {
        state.live.notify_all(t!(
            "The Gate's Cloudflare tunnel restarts for an update: connections from outside are cut for a few seconds.",
            "Le tunnel Cloudflare de la Gate redémarre pour une mise à jour : les connexions de l'extérieur sont coupées quelques secondes."
        ));
    }
    late
}

/// Jeton à servir maintenant : en mode Cloudflare seulement.
async fn wanted(state: &State) -> Result<Option<String>> {
    if portal::exposure(state).mode != portal::Mode::Cloudflare {
        return Ok(None);
    }
    token(state).await
}

/// Ligne utile d'un journal de cloudflared, sans la date.
fn log_message(line: &str) -> Option<String> {
    let (_, rest) = line.split_once(" ERR ").or_else(|| line.split_once(" FTL "))?;
    Some(rest.trim().chars().take(300).collect())
}

/// Lance cloudflared et le surveille. Rend Ok quand il faut l'arrêter (jeton ou mode changés).
async fn supervise(state: &State, token: &str) -> Result<()> {
    let (bin, version) = binary(state).await?;
    set_status("demarrage", None, 0);
    let home = dir(state);
    tokio::fs::create_dir_all(&home).await?;
    let mut child = tokio::process::Command::new(&bin)
        .args(["tunnel", "--no-autoupdate", "--metrics", METRICS, "--loglevel", "info", "run"])
        .env_clear()
        .env("HOME", &home)
        .env("TUNNEL_TOKEN", token)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            // Dossier de données monté « noexec » (certains LXC, durcissements) : le programme
            // téléchargé ne peut pas s'y lancer. Le cloudflared du système, lui, le peut.
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                t!(
                    " (folder mounted noexec? install cloudflared in /usr/bin and set PORTUNIA_GATE_CLOUDFLARED=/usr/bin/cloudflared in the configuration file)",
                    " (dossier monté noexec ? installez cloudflared dans /usr/bin et ajoutez PORTUNIA_GATE_CLOUDFLARED=/usr/bin/cloudflared au fichier de configuration)"
                )
            } else {
                ""
            };
            anyhow!("{} {}: {e}{hint}", t!("cannot start", "démarrage impossible de"), bin.display())
        })?;
    let last = Arc::new(Mutex::new(None::<String>));
    if let Some(err) = child.stderr.take() {
        let last = last.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::debug!(target: "cloudflared", "{line}");
                if let Some(msg) = log_message(&line) {
                    *last.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg);
                }
            }
        });
    }
    *RUNNING.lock().unwrap_or_else(|e| e.into_inner()) = Some(version.clone());
    {
        let mut u = upgrade();
        if u.ready.as_ref().is_some_and(|(v, _)| *v == version) {
            u.ready = None;
            u.now = false;
        }
    }
    let started = tokio::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    loop {
        tokio::select! {
            exit = child.wait() => {
                let why = last.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| format!("{:?}", exit));
                bail!("{} {why}", t!("cloudflared stopped:", "cloudflared s'est arrêté :"));
            }
            _ = tick.tick() => {
                if wanted(state).await.ok().flatten().as_deref() != Some(token) {
                    let _ = child.kill().await;
                    set_status("arrete", None, 0);
                    return Ok(());
                }
                if restart_due(state, &version) {
                    tracing::info!("cloudflared {version} : {}", t!("restarted on the new version", "relancé sur la nouvelle version"));
                    let _ = child.kill().await;
                    return Ok(());
                }
                let n = probe(METRICS).await.unwrap_or(0);
                let error = last.lock().unwrap_or_else(|e| e.into_inner()).clone();
                if n > 0 {
                    set_status("relie", None, n);
                } else if started.elapsed() > Duration::from_secs(30) {
                    set_status("deconnecte", error, 0);
                }
            }
        }
    }
}

pub async fn run(state: Arc<State>) -> Result<()> {
    // Le mode enregistré avant tout : ne pas lancer le tunnel d'une Gate exposée autrement.
    let _ = portal::reload_exposure(&state).await;
    tokio::spawn(upgrades(state.clone()));
    let mut wait = RETRY_MIN;
    loop {
        match wanted(&state).await {
            Ok(Some(token)) => match supervise(&state, &token).await {
                Ok(()) => wait = RETRY_MIN,
                Err(e) => {
                    let msg = format!("{e:#}");
                    tracing::warn!("tunnel Cloudflare : {msg}");
                    set_status("erreur", Some(msg), 0);
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                    wait = (wait * 2).min(RETRY_MAX);
                    continue;
                }
            },
            Ok(None) => {
                set_status("arrete", None, 0);
                wait = RETRY_MIN;
            }
            Err(e) => set_status("erreur", Some(format!("{e:#}")), 0),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// ---------- Essai de bout en bout ----------

/// Appelle l'adresse publique comme le ferait un navigateur et vérifie que c'est bien cette Gate
/// qui répond, à travers Cloudflare.
pub async fn check(state: &State) -> Result<Value> {
    let url = portal::settings(state).await?.url;
    if url.is_empty() {
        return Ok(json!({ "ok": false, "message": t!("Fill in the public address first.", "Renseignez d'abord l'adresse publique.") }));
    }
    let target = format!("{url}{}", portal::PING_PATH);
    // Lancée en ligne de commande, la vérification attend l'identifiant du service, pas le sien.
    let expected = crate::model::setting(&state.db, crate::live::SNAPSHOT)
        .await?
        .and_then(|s| s["instance"].as_str().map(str::to_owned))
        .filter(|_| !crate::portal::is_service())
        .unwrap_or_else(|| portal::instance_id().to_string());
    let answer = tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new().redirects(0).timeout(Duration::from_secs(15)).build();
        match agent.get(&target).call() {
            Ok(r) => {
                let status = r.status();
                let location = r.header("location").unwrap_or_default().to_string();
                (status, location, r.into_string().unwrap_or_default())
            }
            Err(ureq::Error::Status(code, r)) => (code, String::new(), r.into_string().unwrap_or_default()),
            Err(e) => (0, String::new(), e.to_string()),
        }
    })
    .await?;
    let (code, location, body) = answer;
    let (ok, message) = match code {
        200 if body.trim() == expected => (true, t!("This Gate answers at the public address.", "Cette Gate répond à l'adresse publique.").to_string()),
        200 => (false, t!("Another machine answers at this address: check the tunnel's route (Routes tab).", "Une autre machine répond à cette adresse : vérifiez la route du tunnel (onglet Routes).").to_string()),
        301..=308 if location.contains("cloudflareaccess.com") => (
            true,
            t!("The address is protected by Cloudflare Access: the Gate cannot look further, which is expected.", "L'adresse est protégée par Cloudflare Access : la Gate ne peut pas voir au-delà, c'est normal.").to_string(),
        ),
        530 => (false, t!("Cloudflare does not reach the tunnel: is it connected?", "Cloudflare ne joint pas le tunnel : est-il relié ?").to_string()),
        502 | 503 | 504 => (
            false,
            t!("Cloudflare reaches the tunnel but not the portal: in the tunnel's route, the Service URL must be ", "Cloudflare joint le tunnel mais pas le portail : dans la route du tunnel, la Service URL doit être ").to_string()
                + &format!("http://localhost:{}", state.config.portal_listen.rsplit(':').next().unwrap_or("8445")),
        ),
        0 => (false, format!("{} {body}", t!("Address unreachable:", "Adresse injoignable :"))),
        c => (false, format!("{} {c}", t!("Unexpected answer:", "Réponse inattendue :"))),
    };
    Ok(json!({ "ok": ok, "message": message, "code": code }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Jeton fabriqué pour l'essai (format de Cloudflare : JSON a/t/s en base64).
    fn sample() -> String {
        let json = r#"{"a":"0123456789abcdef0123456789abcdef","t":"6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b","s":"c2VjcmV0LWRlLWVzc2Fp"}"#;
        base64::engine::general_purpose::STANDARD.encode(json)
    }

    #[test]
    fn jeton_seul_ou_dans_la_commande() {
        let token = sample();
        let (t1, info) = parse(&token).unwrap();
        assert_eq!(t1, token);
        assert_eq!(info.tunnel, "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b");
        let (t2, _) = parse(&format!("sudo cloudflared service install {token}\n")).unwrap();
        assert_eq!(t2, token);
        let (t3, _) = parse(&format!("cloudflared.exe tunnel run --token {token}")).unwrap();
        assert_eq!(t3, token);
    }

    #[test]
    fn jeton_refuse() {
        assert!(parse("").is_err());
        assert!(parse("bonjour").is_err());
        assert!(parse(&base64::engine::general_purpose::STANDARD.encode(r#"{"a":"x","t":"y"}"#)).is_err());
        let bad_tunnel = base64::engine::general_purpose::STANDARD.encode(r#"{"a":"abcd","t":"pas-un-uuid","s":"x"}"#);
        assert!(parse(&bad_tunnel).is_err());
    }

    #[test]
    fn derniere_version() {
        let sum = "1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872";
        let release = |tag: &str, digest: &str, body: &str| {
            json!({ "tag_name": tag, "draft": false, "prerelease": false, "body": body,
                    "assets": [{ "name": "cloudflared-linux-amd64", "digest": format!("sha256:{digest}") }] })
        };
        let body = format!("### SHA256 Checksums:\n```\ncloudflared-linux-amd64: {sum}\ncloudflared-linux-arm64: 3df4\n```");
        assert_eq!(latest_from(&release("2026.10.7", sum, &body), "cloudflared-linux-amd64").unwrap(), ("2026.10.7".to_string(), sum.to_string()));
        // Empreintes qui ne concordent pas, fichier absent, version étrange : refusés.
        assert!(latest_from(&release("2026.10.7", &"0".repeat(64), &body), "cloudflared-linux-amd64").is_err());
        assert!(latest_from(&release("2026.10.7", sum, &body), "cloudflared-linux-arm64").is_err());
        assert!(latest_from(&release("2026.10.7/../x", sum, &body), "cloudflared-linux-amd64").is_err());
        let mut pre = release("2026.11.0", sum, &body);
        pre["prerelease"] = json!(true);
        assert!(latest_from(&pre, "cloudflared-linux-amd64").is_err());
    }

    #[test]
    fn journal() {
        assert_eq!(
            log_message("2026-11-02T10:00:00Z ERR Couldn't start tunnel error=\"Unauthorized: Invalid tunnel secret\"").as_deref(),
            Some("Couldn't start tunnel error=\"Unauthorized: Invalid tunnel secret\"")
        );
        assert_eq!(log_message("2026-11-02T10:00:00Z INF Registered tunnel connection"), None);
    }

    #[tokio::test]
    async fn metriques() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            for body in ["{\"status\":200,\"readyConnections\":4}", "{\"status\":503,\"readyConnections\":0}"] {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf).await;
                let code = if body.contains("200") { "200 OK" } else { "503 Service Unavailable" };
                let _ = s.write_all(format!("HTTP/1.0 {code}\r\n\r\n{body}").as_bytes()).await;
            }
        });
        assert_eq!(probe(&addr).await, Some(4));
        assert_eq!(probe(&addr).await, Some(0));
        assert_eq!(probe("127.0.0.1:1").await, None);
    }
}
