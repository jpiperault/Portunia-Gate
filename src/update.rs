//! Mise à jour de la Gate (0.39) : dernière version publiée, demande (tout de suite ou
//! programmée, avec un préavis aux utilisateurs connectés), puis exécution par un service
//! système à part, en root : `portunia-gate-update.service`, déclenché par
//! `portunia-gate-update.path` dès que la demande apparaît.
//!
//! Le service root : télécharge le nouveau paquet et celui de la version installée (pour le
//! retour) et vérifie leur empreinte SHA-256 publiée ; sauvegarde la base (pg_dump) ; installe ;
//! attend que la nouvelle version ait démarré et réponde. Sinon, retour en arrière automatique :
//! ancien paquet réinstallé, base restaurée, Gate relancée.
//!
//! La Gate, sans droits, n'écrit que la demande (`<données>/mise-a-jour/demande.json`). Le
//! service root la lit sans suivre de lien, la supprime, et n'accepte qu'un numéro de version
//! plus récent que celui installé : une Gate compromise ne peut ni faire installer autre chose
//! qu'un paquet publié, ni revenir à une version ancienne. Son avancement est écrit dans
//! /var/lib/portunia-gate-update/etat.json, lisible par la Gate et par Portunia.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{audit, config::Config, model, notify, State};

/// Dossier du service root : avancement, paquets, sauvegarde de la base.
pub const RUN_DIR: &str = "/var/lib/portunia-gate-update";
const PATH_UNIT: &str = "/usr/lib/systemd/system/portunia-gate-update.path";
const SERVICE_USER: &str = "_portunia_gate";
const DEFAULT_SOURCE: &str = "https://github.com/jpiperault/Portunia-Gate-releases/releases";
/// Réglage : mise à jour programmée.
const PLANNED: &str = "mise_a_jour_programmee";
/// Réglage : dernière exécution déjà notée au journal.
const NOTED: &str = "mise_a_jour_notee";
/// Réglage : dernière version disponible déjà signalée aux administrateurs.
const ANNOUNCED: &str = "mise_a_jour_signalee";
/// Préavis aux utilisateurs connectés.
pub const NOTICE_MINUTES: i64 = 5;
/// Attente du démarrage de la nouvelle version.
const START_WAIT: Duration = Duration::from_secs(180);
const CHECK_EVERY: i64 = 6 * 3600;

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// Adresse des versions publiées (PORTUNIA_GATE_UPDATE_URL : miroir, ou essai).
fn source() -> String {
    std::env::var("PORTUNIA_GATE_UPDATE_URL").ok().map(|s| s.trim().trim_end_matches('/').to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| DEFAULT_SOURCE.into())
}

// ---------- Versions ----------

pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim().trim_start_matches('v');
    let v = v.split('-').next()?;
    let mut it = v.split('.');
    let out = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?);
    it.next().is_none().then_some(out)
}

/// Version demandée pour une mise à jour : exactement « a.b.c » (1 à 4 chiffres chacun, « v »
/// devant toléré), rendue sous sa forme canonique. Elle sert à construire l'adresse et le nom du
/// paquet : rien d'autre (suffixe, chemin, « .. ») ne doit pouvoir y passer.
pub fn strict_version(v: &str) -> Option<String> {
    let v = v.trim().strip_prefix('v').unwrap_or(v.trim());
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty() || p.len() > 4 || !p.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let n: Vec<u64> = parts.iter().map(|p| p.parse().unwrap_or(0)).collect();
    Some(format!("{}.{}.{}", n[0], n[1], n[2]))
}

/// `a` est plus récente que `b`.
pub fn newer(a: &str, b: &str) -> bool {
    matches!((parse_version(a), parse_version(b)), (Some(x), Some(y)) if x > y)
}

/// Version du paquet daté dans SHA256SUMS (« portunia-gate_0.39.0-1_amd64.deb »).
fn version_from_sums(sums: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let name = line.split_whitespace().nth(1)?.trim_start_matches('*');
        let middle = name.strip_prefix("portunia-gate_")?.strip_suffix("_amd64.deb")?;
        let v = middle.split('-').next()?;
        parse_version(v).map(|_| v.to_string())
    })
}

/// Empreinte publiée d'un fichier dans SHA256SUMS.
fn sum_of(sums: &str, file: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let sum = parts.next()?;
        (parts.next()?.trim_start_matches('*') == file && sum.len() == 64).then(|| sum.to_lowercase())
    })
}

fn get(url: &str, limit: u64) -> Result<Vec<u8>> {
    let resp = ureq::get(url)
        .set("User-Agent", concat!("portunia-gate/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(300))
        .call()
        .map_err(|e| anyhow!("{url} : {e}"))?;
    let mut out = Vec::new();
    resp.into_reader().take(limit).read_to_end(&mut out)?;
    Ok(out)
}

/// Dernière version publiée (requête bloquante).
pub fn fetch_latest() -> Result<String> {
    let sums = String::from_utf8_lossy(&get(&format!("{}/latest/download/SHA256SUMS", source()), 64 * 1024)?).into_owned();
    version_from_sums(&sums).ok_or_else(|| anyhow!(t!("no package in the published SHA256SUMS", "aucun paquet dans le SHA256SUMS publié")))
}

#[derive(Clone, Serialize)]
pub struct Latest {
    pub version: Option<String>,
    pub verifie_le: DateTime<Utc>,
    pub erreur: Option<String>,
}

static LATEST: Mutex<Option<Latest>> = Mutex::new(None);

/// Dernière version connue ; vérifiée de nouveau après 6 heures, ou tout de suite si `force`.
pub async fn latest(force: bool) -> Latest {
    if let Some(l) = LATEST.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        if !force && (Utc::now() - l.verifie_le).num_seconds() < CHECK_EVERY {
            return l;
        }
    }
    let found = tokio::task::spawn_blocking(fetch_latest).await.map_err(|e| anyhow!("{e}")).and_then(|r| r);
    let l = match found {
        Ok(v) => Latest { version: Some(v), verifie_le: Utc::now(), erreur: None },
        Err(e) => Latest { version: None, verifie_le: Utc::now(), erreur: Some(format!("{e:#}")) },
    };
    *LATEST.lock().unwrap_or_else(|e| e.into_inner()) = Some(l.clone());
    l
}

// ---------- Mode d'installation ----------

/// « paquet » (Debian), « docker », ou « autre » (compilée à la main).
pub fn mode() -> &'static str {
    if Path::new("/.dockerenv").exists() || std::env::var_os("PORTUNIA_GATE_DOCKER").is_some() {
        "docker"
    } else if std::env::current_exe().map(|p| p.starts_with("/usr/lib/portunia-gate")).unwrap_or(false) {
        "paquet"
    } else {
        "autre"
    }
}

/// Pourquoi la Gate ne peut pas se mettre à jour toute seule ; rien : elle le peut.
pub fn not_possible() -> Option<String> {
    match mode() {
        "docker" => Some(t!("Docker installation: update from the server with « sudo bash installer.sh update ».", "Installation Docker : mettez à jour depuis le serveur avec « sudo bash installer.sh mise-a-jour ».").into()),
        "autre" => Some(t!("This Gate was not installed from the Debian package: update it as it was installed.", "Cette Gate n'a pas été installée par le paquet Debian : mettez-la à jour comme elle a été installée.").into()),
        _ if !Path::new(PATH_UNIT).exists() => Some(t!("The update service is missing: reinstall once with « sudo bash installer.sh update ».", "Le service de mise à jour manque : réinstallez une fois avec « sudo bash installer.sh mise-a-jour ».").into()),
        _ => None,
    }
}

// ---------- Demande ----------

#[derive(Serialize, Deserialize, Clone)]
pub struct Request {
    pub id: String,
    pub version: String,
    pub par: String,
    /// Sans retour possible (paquet de la version actuelle introuvable) : ligne de commande seulement.
    #[serde(default)]
    pub sans_retour: bool,
}

pub fn request_path(data_dir: &Path) -> PathBuf {
    data_dir.join("mise-a-jour").join("demande.json")
}

fn write_request(data_dir: &Path, r: &Request) -> Result<()> {
    let path = request_path(data_dir);
    std::fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(r)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Planned {
    pub version: String,
    pub a: DateTime<Utc>,
    pub prevenir: bool,
    pub par: String,
    #[serde(default)]
    pub prevenu: bool,
    #[serde(default)]
    pub sans_retour: bool,
}

pub async fn planned(state: &State) -> Result<Option<Planned>> {
    Ok(model::setting(&state.db, PLANNED).await?.and_then(|v| serde_json::from_value(v).ok()))
}

async fn clear_planned(state: &State) -> Result<()> {
    sqlx::query("DELETE FROM settings WHERE key = $1").bind(PLANNED).execute(&state.db).await?;
    Ok(())
}

/// Demande une mise à jour vers `version`, à la date `at` (rien : tout de suite). Avec préavis,
/// les utilisateurs connectés sont prévenus 5 minutes avant (une demande « tout de suite »
/// part alors dans 5 minutes).
pub async fn plan(state: &State, version: &str, at: Option<DateTime<Utc>>, notice: bool, by: &str, no_rollback: bool) -> Result<Planned> {
    if let Some(why) = not_possible() {
        bail!(why);
    }
    let Some(version) = strict_version(version) else {
        bail!(t!(format!("Invalid version « {version} »: expected 1.2.3"), format!("Version « {version} » invalide : forme 1.2.3 attendue")));
    };
    let version = version.as_str();
    if !newer(version, CURRENT) {
        bail!(t!(format!("Version {version} is not newer than the installed one ({CURRENT})."), format!("La version {version} n'est pas plus récente que celle installée ({CURRENT}).")));
    }
    if progress().is_some_and(|p| p.resultat == "en_cours") {
        bail!(t!("An update is already under way.", "Une mise à jour est déjà en cours."));
    }
    let now = Utc::now();
    let mut at = at.unwrap_or(now);
    if at < now {
        at = now;
    }
    if at > now + chrono::Duration::days(30) {
        bail!(t!("Date too far: 30 days at most.", "Date trop lointaine : 30 jours au plus."));
    }
    if notice && at < now + chrono::Duration::minutes(NOTICE_MINUTES) {
        at = now + chrono::Duration::minutes(NOTICE_MINUTES);
    }
    let p = Planned { version: version.to_string(), a: at, prevenir: notice, par: by.to_string(), prevenu: false, sans_retour: no_rollback };
    if !notice && at <= now + chrono::Duration::seconds(5) {
        launch(state, &p).await?;
        clear_planned(state).await?;
    } else {
        model::set_setting(&state.db, PLANNED, serde_json::to_value(&p)?).await?;
        audit::log(&state.db, by, "mise_a_jour.programmee", json!({ "version": version, "a": at, "prevenir": notice })).await?;
    }
    Ok(p)
}

/// Annule une mise à jour programmée ; faux : il n'y en avait pas.
pub async fn cancel(state: &State, by: &str) -> Result<bool> {
    let Some(p) = planned(state).await? else { return Ok(false) };
    clear_planned(state).await?;
    audit::log(&state.db, by, "mise_a_jour.annulee", json!({ "version": p.version, "a": p.a })).await?;
    Ok(true)
}

async fn launch(state: &State, p: &Planned) -> Result<()> {
    let r = Request { id: uuid::Uuid::new_v4().to_string(), version: p.version.clone(), par: p.par.clone(), sans_retour: p.sans_retour };
    write_request(&state.config.data_dir, &r).with_context(|| t!("writing the update request", "écriture de la demande de mise à jour"))?;
    audit::log(&state.db, &p.par, "mise_a_jour.lancee", json!({ "id": r.id, "de": CURRENT, "vers": p.version })).await?;
    Ok(())
}

// ---------- Avancement (écrit par le service root) ----------

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Progress {
    pub id: String,
    pub de: String,
    pub vers: String,
    pub par: String,
    pub debut: Option<DateTime<Utc>>,
    pub fin: Option<DateTime<Utc>>,
    /// telechargement, sauvegarde, installation, demarrage, retour, fini.
    pub etape: String,
    /// en_cours, reussie, retour_arriere, echec.
    pub resultat: String,
    pub message: String,
    pub journal: Vec<String>,
}

pub fn progress() -> Option<Progress> {
    let text = std::fs::read_to_string(Path::new(RUN_DIR).join("etat.json")).ok()?;
    serde_json::from_str(&text).ok()
}

/// Ce que l'état de la Gate montre de la mise à jour.
pub async fn summary(state: &State, force: bool) -> Result<Value> {
    let l = latest(force).await;
    let available = l.version.as_deref().is_some_and(|v| newer(v, CURRENT));
    Ok(json!({
        "actuelle": CURRENT,
        "derniere": l.version,
        "disponible": available,
        "verifie_le": l.verifie_le,
        "erreur_verification": l.erreur,
        "notes": l.version.as_ref().map(|v| format!("{}/tag/v{v}", source())),
        "mode": mode(),
        "impossible": not_possible(),
        "commande": if mode() == "docker" { "sudo bash installer.sh update" } else { "sudo portunia-gate update apply" },
        "programmee": planned(state).await?,
        "execution": progress(),
        "preavis_min": NOTICE_MINUTES,
    }))
}

// ---------- Tâche de fond du service ----------

/// Le service a démarré et répond : noté pour le service de mise à jour, qui attend ce signe.
pub fn mark_started(data_dir: &Path) {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let body = json!({ "version": CURRENT, "a": secs }).to_string();
    let path = data_dir.join("demarrage.json");
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, &path)).is_err() {
        tracing::warn!("{}", t!("cannot write demarrage.json", "écriture de demarrage.json impossible"));
    }
}

pub async fn run(state: Arc<State>) -> Result<()> {
    let mut last_check = 0i64;
    let started = std::time::Instant::now();
    let mut browser_checked = false;
    loop {
        if let Err(e) = tick(&state, &mut last_check).await {
            tracing::warn!("{} {e:#}", t!("update:", "mise à jour :"));
        }
        if let Err(e) = browser_tick(&state, started, &mut browser_checked).await {
            tracing::warn!("{} {e:#}", t!("portal browser:", "navigateur du portail :"));
        }
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
}

/// Réglage : dernière action du navigateur du portail déjà notée au journal.
const BROWSER_NOTED: &str = "navigateur_note";

async fn browser_tick(state: &Arc<State>, started: std::time::Instant, checked: &mut bool) -> Result<()> {
    if let Some(p) = browser_progress().filter(|p| p.resultat != "en_cours" && !p.id.is_empty()) {
        let noted = model::setting(&state.db, BROWSER_NOTED).await?.and_then(|v| v.as_str().map(str::to_owned));
        if noted.as_deref() != Some(p.id.as_str()) {
            model::set_setting(&state.db, BROWSER_NOTED, json!(p.id)).await?;
            let event = if p.resultat == "reussie" { "navigateur.pret" } else { "navigateur.echec" };
            let event = if p.action == "arreter" && p.resultat == "reussie" { "navigateur.arrete" } else { event };
            audit::note(&state.db, &p.par, event, json!({ "id": p.id, "action": p.action, "message": p.message })).await;
        }
    }
    // Une minute après le démarrage (nouvelle version) : un navigateur du portail déjà en service
    // à qui manquent des programmes (vidéo et son de la 0.54) est complété par le service root,
    // une fois par jour au plus si l'installation échoue.
    if *checked || started.elapsed() < Duration::from_secs(60) || mode() != "paquet" || not_possible().is_some() {
        return Ok(());
    }
    *checked = true;
    if !browser_running() || browser_missing().is_empty() || browser_request_path(&state.config.data_dir).exists() {
        return Ok(());
    }
    let recent = browser_progress().is_some_and(|p| p.action == "completer" && p.fin.is_some_and(|f| Utc::now() - f < chrono::Duration::hours(24)));
    if recent {
        return Ok(());
    }
    let r = request_browser(&state.config.data_dir, "completer", "systeme")?;
    audit::note(&state.db, "systeme", "navigateur.demande", json!({ "id": r.id, "action": "completer", "manquants": browser_missing() })).await;
    Ok(())
}

async fn tick(state: &Arc<State>, last_check: &mut i64) -> Result<()> {
    // Résultat d'une exécution, noté une fois (la nouvelle version le voit après son démarrage).
    if let Some(p) = progress().filter(|p| p.resultat != "en_cours" && !p.id.is_empty()) {
        let noted = model::setting(&state.db, NOTED).await?.and_then(|v| v.as_str().map(str::to_owned));
        if noted.as_deref() != Some(p.id.as_str()) {
            model::set_setting(&state.db, NOTED, json!(p.id)).await?;
            let event = match p.resultat.as_str() {
                "reussie" => "mise_a_jour.reussie",
                "retour_arriere" => "mise_a_jour.retour_arriere",
                _ => "mise_a_jour.echec",
            };
            audit::note(&state.db, "systeme", event, json!({ "id": p.id, "de": p.de, "vers": p.vers, "message": p.message })).await;
            let (title, text) = match p.resultat.as_str() {
                "reussie" => (t!(format!("Gate updated to {}", p.vers), format!("Gate mise à jour en {}", p.vers)), t!(format!("The Gate went from {} to {}.", p.de, p.vers), format!("La Gate est passée de {} à {}.", p.de, p.vers))),
                "retour_arriere" => (t!(format!("Update to {} rolled back", p.vers), format!("Mise à jour en {} annulée", p.vers)), t!(format!("Version {} did not start: version {} and its database were restored. {}", p.vers, p.de, p.message), format!("La version {} n'a pas démarré : la version {} et sa base ont été remises. {}", p.vers, p.de, p.message))),
                _ => (t!(format!("Update to {} failed", p.vers), format!("Échec de la mise à jour en {}", p.vers)), p.message.clone()),
            };
            let to = notify::group_emails(state, None).await.unwrap_or_default();
            notify::send(state.clone(), notify::Notice { event, title, text, detail: json!({ "de": p.de, "vers": p.vers, "resultat": p.resultat }), to });
        }
    }
    // Mise à jour programmée : préavis, puis lancement.
    if let Some(mut p) = planned(state).await? {
        let now = Utc::now();
        let minutes = (p.a - now).num_minutes().max(0);
        if p.prevenir && !p.prevenu && now >= p.a - chrono::Duration::minutes(NOTICE_MINUTES) {
            state.live.notify_all(&t!(
                format!("The Gate will be updated in {} min: your session will be cut for about a minute.", minutes.max(1)),
                format!("La Gate sera mise à jour dans {} min : votre session sera coupée environ une minute.", minutes.max(1))
            ));
            p.prevenu = true;
            model::set_setting(&state.db, PLANNED, serde_json::to_value(&p)?).await?;
        }
        if now >= p.a {
            clear_planned(state).await?;
            if p.prevenir {
                state.live.notify_all(t!("The Gate is being updated now: your session will be cut.", "La Gate est mise à jour maintenant : votre session va être coupée."));
            }
            if let Err(e) = launch(state, &p).await {
                audit::note(&state.db, "systeme", "mise_a_jour.echec", json!({ "vers": p.version, "message": format!("{e:#}") })).await;
            }
        }
    }
    // Nouvelle version : signalée une fois aux administrateurs.
    let now = Utc::now().timestamp();
    if now - *last_check >= CHECK_EVERY {
        *last_check = now;
        let l = latest(true).await;
        if let Some(v) = l.version.filter(|v| newer(v, CURRENT)) {
            let said = model::setting(&state.db, ANNOUNCED).await?.and_then(|x| x.as_str().map(str::to_owned));
            if said.as_deref() != Some(v.as_str()) {
                model::set_setting(&state.db, ANNOUNCED, json!(v)).await?;
                audit::note(&state.db, "systeme", "mise_a_jour.disponible", json!({ "version": v })).await;
                let to = notify::group_emails(state, None).await.unwrap_or_default();
                notify::send(state.clone(), notify::Notice {
                    event: "mise_a_jour.disponible",
                    title: t!(format!("Gate {v} available"), format!("Gate {v} disponible")),
                    text: t!(format!("Version {v} of Portunia Gate is available (installed: {CURRENT}). Portunia › Gate status, or « sudo portunia-gate update apply »."), format!("La version {v} de Portunia Gate est disponible (installée : {CURRENT}). Portunia › État de la Gate, ou « sudo portunia-gate update apply ».")),
                    detail: json!({ "version": v, "installee": CURRENT }),
                    to,
                });
            }
        }
    }
    Ok(())
}

// ---------- Service root ----------

struct Runner {
    p: Progress,
    path: PathBuf,
}

impl Runner {
    fn save(&self) {
        let tmp = self.path.with_extension("tmp");
        let ok = serde_json::to_vec_pretty(&self.p).map_err(std::io::Error::other).and_then(|b| std::fs::write(&tmp, b)).and_then(|_| {
            set_mode(&tmp, 0o644);
            std::fs::rename(&tmp, &self.path)
        });
        if let Err(e) = ok {
            eprintln!("etat.json : {e}");
        }
    }

    fn step(&mut self, etape: &str, line: String) {
        println!("{line}");
        self.p.etape = etape.into();
        self.p.journal.push(format!("{} {line}", chrono::Local::now().format("%H:%M:%S")));
        self.save();
    }

    fn line(&mut self, line: String) {
        println!("{line}");
        self.p.journal.push(format!("{} {line}", chrono::Local::now().format("%H:%M:%S")));
        self.save();
    }
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// Lit la demande sans suivre de lien et la supprime.
fn take_request(data_dir: &Path) -> Result<Request> {
    let path = request_path(data_dir);
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(&path).with_context(|| format!("{}", path.display()));
    let _ = std::fs::remove_file(&path);
    let file = file?;
    let meta = file.metadata()?;
    anyhow::ensure!(meta.is_file() && meta.len() <= 4096, "demande invalide");
    let mut text = String::new();
    file.take(4096).read_to_string(&mut text)?;
    let r: Request = serde_json::from_str(&text).context("demande illisible")?;
    anyhow::ensure!(!r.id.is_empty() && r.id.len() <= 64 && r.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'), "identifiant de demande invalide");
    anyhow::ensure!(r.par.len() <= 64 && !r.par.chars().any(char::is_control), "auteur de la demande invalide");
    anyhow::ensure!(strict_version(&r.version).as_deref() == Some(r.version.as_str()), "version invalide");
    Ok(r)
}

fn download_checked(version: &str, dest: &Path) -> Result<()> {
    anyhow::ensure!(strict_version(version).as_deref() == Some(version), "version invalide");
    let base = format!("{}/download/v{version}", source());
    let sums = String::from_utf8_lossy(&get(&format!("{base}/SHA256SUMS"), 64 * 1024)?).into_owned();
    let expected = sum_of(&sums, "portunia-gate_amd64.deb").ok_or_else(|| anyhow!(t!(format!("no portunia-gate_amd64.deb in the SHA256SUMS of {version}"), format!("pas de portunia-gate_amd64.deb dans le SHA256SUMS de la {version}"))))?;
    let deb = get(&format!("{base}/portunia-gate_amd64.deb"), 256 * 1024 * 1024)?;
    let actual = crate::keys::sha256_hex(&deb);
    if actual != expected {
        bail!(t!(format!("package {version} altered (different SHA-256 checksum)"), format!("paquet {version} altéré (empreinte SHA-256 différente)")));
    }
    std::fs::write(dest, &deb)?;
    set_mode(dest, 0o644);
    Ok(())
}

/// Lance une commande ; renvoie sa sortie (fin) ou une erreur avec ce qu'elle a dit.
fn sh(cmd: &mut Command) -> Result<String> {
    let out = cmd.output().with_context(|| format!("{cmd:?}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    let tail: Vec<&str> = text.lines().rev().take(15).collect::<Vec<_>>().into_iter().rev().collect();
    let tail = tail.join("\n");
    if !out.status.success() {
        bail!("{} ({}) : {tail}", cmd.get_program().to_string_lossy(), out.status);
    }
    Ok(tail)
}

fn install(deb: &Path) -> Result<()> {
    sh(Command::new("apt-get")
        .args(["install", "-y", "-q", "--allow-downgrades", "-o", "Dpkg::Options::=--force-confold"])
        .arg(deb)
        .env("DEBIAN_FRONTEND", "noninteractive"))
    .map(|_| ())
}

fn dump(config: &Config, dest: &Path) -> Result<()> {
    let file = std::fs::File::create(dest)?;
    set_mode(dest, 0o600);
    let status = Command::new("runuser")
        .args(["-u", SERVICE_USER, "--", "pg_dump", "-Fc", "--dbname"])
        .arg(&config.database_url)
        .current_dir("/")
        .stdout(file)
        .stderr(Stdio::inherit())
        .status()?;
    anyhow::ensure!(status.success(), "pg_dump ({status})");
    anyhow::ensure!(std::fs::metadata(dest)?.len() > 0, "sauvegarde vide");
    Ok(())
}

fn restore(config: &Config, from: &Path) -> Result<()> {
    let file = std::fs::File::open(from)?;
    sh(Command::new("runuser")
        .args(["-u", SERVICE_USER, "--", "pg_restore", "--clean", "--if-exists", "--no-owner", "--single-transaction", "--dbname"])
        .arg(&config.database_url)
        .current_dir("/")
        .stdin(file))
    .map(|_| ())
}

/// Attend que la Gate `version` ait démarré (après `since`) et passé son premier contrôle.
fn wait_started(data_dir: &Path, version: &str, since: u64) -> bool {
    let deadline = std::time::Instant::now() + START_WAIT;
    while std::time::Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(data_dir.join("demarrage.json")) {
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                if v["version"].as_str() == Some(version) && v["a"].as_u64().is_some_and(|a| a >= since) {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    false
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Dernières erreurs du service depuis `since` (secondes Unix) : ce qu'a dit la nouvelle version.
fn journal_tail(since: u64) -> String {
    let text = sh(Command::new("journalctl").args(["-u", "portunia-gate", "--since", &format!("@{since}"), "-n", "40", "--no-pager", "-o", "cat"])).unwrap_or_default();
    let errors: Vec<&str> = text.lines().filter(|l| l.contains("Error") || l.contains("Erreur") || l.contains("ERROR") || l.contains("panicked")).collect();
    errors.iter().rev().take(3).rev().copied().collect::<Vec<_>>().join(" | ")
}

/// `portunia-gate update run` : exécuté par portunia-gate-update.service (root).
pub fn run_root(config: &Config) -> Result<()> {
    #[cfg(unix)]
    anyhow::ensure!(unsafe { libc::geteuid() } == 0, t!("run by portunia-gate-update.service (root) only", "lancé par portunia-gate-update.service (root) seulement"));
    let dir = Path::new(RUN_DIR);
    std::fs::create_dir_all(dir)?;
    set_mode(dir, 0o755);
    // Une seule exécution à la fois.
    let lock = dir.join("verrou");
    if lock.exists() && std::fs::metadata(&lock).and_then(|m| m.modified()).ok().and_then(|m| m.elapsed().ok()).is_some_and(|age| age < Duration::from_secs(2 * 3600)) {
        let _ = std::fs::remove_file(request_path(&config.data_dir));
        bail!(t!("an update is already under way", "une mise à jour est déjà en cours"));
    }
    std::fs::write(&lock, std::process::id().to_string())?;
    let result = if request_path(&config.data_dir).exists() { run_locked(config, dir) } else { Ok(()) };
    // Navigateur du portail (0.55) : installer, compléter ou arrêter, à la demande de la Gate.
    let browser = if browser_request_path(&config.data_dir).exists() { run_browser(config, dir) } else { Ok(()) };
    let _ = std::fs::remove_file(&lock);
    result.and(browser)
}

// ---------- Navigateur du portail (0.55) ----------
//
// La Gate demande (navigateur.json, à côté de la demande de mise à jour) ; le service root
// exécute une action d'une liste fermée, sans argument : « activer » installe Chromium, Xvfb,
// ffmpeg et PulseAudio (paquets Debian, liste fixe) et démarre portunia-gate-navigateur ;
// « completer » fait de même seulement s'il est déjà activé (après une mise à jour) ;
// « arreter » l'arrête et le désactive. Une Gate compromise ne peut rien demander d'autre.

const BROWSER_ACTIONS: [&str; 3] = ["activer", "completer", "arreter"];
const BROWSER_UNIT: &str = "portunia-gate-navigateur.service";
/// Programmes du navigateur du portail, et le paquet Debian de chacun.
const BROWSER_PROGRAMS: [(&str, &[&str], &str); 4] = [
    ("chromium", &["/usr/lib/chromium/chromium", "/usr/bin/chromium"], "chromium"),
    ("xvfb", &["/usr/bin/Xvfb"], "xvfb"),
    ("ffmpeg", &["/usr/bin/ffmpeg"], "ffmpeg"),
    ("pulseaudio", &["/usr/bin/pulseaudio"], "pulseaudio"),
];

#[derive(Serialize, Deserialize, Clone)]
pub struct BrowserRequest {
    pub id: String,
    pub action: String,
    pub par: String,
}

pub fn browser_request_path(data_dir: &Path) -> PathBuf {
    data_dir.join("mise-a-jour").join("navigateur.json")
}

/// Programmes absents (noms de paquets).
fn browser_missing() -> Vec<&'static str> {
    BROWSER_PROGRAMS.iter().filter(|(_, paths, _)| !paths.iter().any(|p| Path::new(p).exists())).map(|(_, _, pkg)| *pkg).collect()
}

/// Le service du navigateur tourne (son socket existe).
fn browser_running() -> bool {
    Path::new("/run/portunia-gate-navigateur/navigateur.sock").exists()
}

/// Demande au service root (sans droits : la Gate n'écrit que ce fichier).
pub fn request_browser(data_dir: &Path, action: &str, by: &str) -> Result<BrowserRequest> {
    if let Some(why) = not_possible() {
        bail!(why);
    }
    anyhow::ensure!(BROWSER_ACTIONS.contains(&action), "action inconnue");
    if browser_progress().is_some_and(|p| p.resultat == "en_cours") {
        bail!(t!("The portal browser is already being installed or stopped.", "Le navigateur du portail est déjà en cours d'installation ou d'arrêt."));
    }
    let r = BrowserRequest { id: uuid::Uuid::new_v4().to_string(), action: action.into(), par: by.into() };
    let path = browser_request_path(data_dir);
    std::fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(&r)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(r)
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct BrowserProgress {
    pub id: String,
    pub action: String,
    pub par: String,
    pub debut: Option<DateTime<Utc>>,
    pub fin: Option<DateTime<Utc>>,
    /// en_cours, reussie, echec.
    pub resultat: String,
    pub message: String,
    pub journal: Vec<String>,
}

pub fn browser_progress() -> Option<BrowserProgress> {
    let text = std::fs::read_to_string(Path::new(RUN_DIR).join("navigateur.json")).ok()?;
    serde_json::from_str(&text).ok()
}

/// Ce que Portunia montre du navigateur du portail.
pub fn browser_status() -> Value {
    let programs: serde_json::Map<String, Value> = BROWSER_PROGRAMS.iter().map(|(name, paths, _)| (name.to_string(), json!(paths.iter().any(|p| Path::new(p).exists())))).collect();
    let missing = browser_missing();
    json!({
        "en_service": browser_running(),
        "programmes": programs,
        "video": missing.is_empty(),
        "manquants": missing,
        "impossible": not_possible(),
        "execution": browser_progress(),
    })
}

fn take_browser_request(data_dir: &Path) -> Result<BrowserRequest> {
    let path = browser_request_path(data_dir);
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(&path).with_context(|| format!("{}", path.display()));
    let _ = std::fs::remove_file(&path);
    let file = file?;
    let meta = file.metadata()?;
    anyhow::ensure!(meta.is_file() && meta.len() <= 4096, "demande invalide");
    let mut text = String::new();
    file.take(4096).read_to_string(&mut text)?;
    let r: BrowserRequest = serde_json::from_str(&text).context("demande illisible")?;
    anyhow::ensure!(!r.id.is_empty() && r.id.len() <= 64 && r.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'), "identifiant de demande invalide");
    anyhow::ensure!(r.par.len() <= 64 && !r.par.chars().any(char::is_control), "auteur de la demande invalide");
    anyhow::ensure!(BROWSER_ACTIONS.contains(&r.action.as_str()), "action inconnue");
    Ok(r)
}

struct BrowserRunner {
    p: BrowserProgress,
    path: PathBuf,
}

impl BrowserRunner {
    fn line(&mut self, line: String) {
        println!("{line}");
        self.p.journal.push(format!("{} {line}", chrono::Local::now().format("%H:%M:%S")));
        let tmp = self.path.with_extension("tmp");
        if let Ok(b) = serde_json::to_vec_pretty(&self.p) {
            if std::fs::write(&tmp, b).is_ok() {
                set_mode(&tmp, 0o644);
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
}

fn apt_install(packages: &[&str], recommends: bool) -> Result<String> {
    let mut cmd = Command::new("apt-get");
    cmd.args(["install", "-y", "-q"]);
    if !recommends {
        cmd.arg("--no-install-recommends");
    }
    sh(cmd.args(packages).env("DEBIAN_FRONTEND", "noninteractive"))
}

fn run_browser(config: &Config, dir: &Path) -> Result<()> {
    let r = take_browser_request(&config.data_dir)?;
    let mut run = BrowserRunner {
        p: BrowserProgress { id: r.id.clone(), action: r.action.clone(), par: r.par.clone(), debut: Some(Utc::now()), resultat: "en_cours".into(), ..Default::default() },
        path: dir.join("navigateur.json"),
    };
    // État « en cours » visible tout de suite dans Portunia.
    run.line(t!(format!("Request « {} » from {}", r.action, r.par), format!("Demande « {} » de {}", r.action, r.par)).into());
    let outcome = browser_action(&r.action, &mut run);
    run.p.fin = Some(Utc::now());
    match outcome {
        Ok(message) => {
            run.p.resultat = "reussie".into();
            run.p.message = message;
        }
        Err(e) => {
            run.p.resultat = "echec".into();
            run.p.message = format!("{e:#}");
        }
    }
    let line = format!("→ {} : {}", run.p.resultat, run.p.message);
    run.line(line);
    Ok(())
}

fn browser_action(action: &str, run: &mut BrowserRunner) -> Result<String> {
    let enabled = Command::new("systemctl").args(["is-enabled", "--quiet", BROWSER_UNIT]).status().is_ok_and(|s| s.success());
    if action == "arreter" {
        run.line(t!("Stopping the portal browser", "Arrêt du navigateur du portail").into());
        sh(Command::new("systemctl").args(["disable", "--now", BROWSER_UNIT]))?;
        return Ok(t!("Portal browser stopped: web egress opens from Portunia only.", "Navigateur du portail arrêté : la sortie web ne s'ouvre plus que depuis Portunia.").into());
    }
    if action == "completer" && !enabled {
        return Ok(t!("Portal browser not enabled: nothing to do.", "Navigateur du portail non activé : rien à faire.").into());
    }
    let missing = browser_missing();
    if !missing.is_empty() {
        run.line(t!(format!("Installing {}", missing.join(", ")), format!("Installation de {}", missing.join(", "))).into());
        // Index des paquets à jour d'abord : un index ancien ne trouve plus les versions publiées.
        let _ = sh(Command::new("apt-get").args(["update", "-q"]).env("DEBIAN_FRONTEND", "noninteractive"));
        if missing.contains(&"chromium") {
            apt_install(&["chromium"], true).context(t!("installing Chromium", "installation de Chromium"))?;
        }
        let rest: Vec<&str> = missing.iter().copied().filter(|p| *p != "chromium").collect();
        if !rest.is_empty() {
            if let Err(e) = apt_install(&rest, false) {
                run.line(t!(format!("Video and sound unavailable ({e:#}): pictures of the page only."), format!("Vidéo et son indisponibles ({e:#}) : images de la page seulement.")).into());
            }
        }
    }
    let _ = sh(Command::new("systemctl").arg("daemon-reload"));
    run.line(t!("Starting the browser service", "Démarrage du service du navigateur").into());
    sh(Command::new("systemctl").args(["enable", BROWSER_UNIT]))?;
    // Nouveaux programmes : le service les cherche à son démarrage (les navigations en cours se ferment).
    let verb = if missing.is_empty() { "start" } else { "restart" };
    sh(Command::new("systemctl").args([verb, BROWSER_UNIT]))?;
    for _ in 0..20 {
        if browser_running() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    anyhow::ensure!(browser_running(), "{}", t!("the browser service does not start: journalctl -u portunia-gate-navigateur", "le service du navigateur ne démarre pas : journalctl -u portunia-gate-navigateur"));
    let left = browser_missing();
    Ok(if left.is_empty() {
        t!("Portal browser ready, with video and sound.", "Navigateur du portail prêt, avec la vidéo et le son.").into()
    } else {
        t!(format!("Portal browser ready, pictures of the page only (missing: {}).", left.join(", ")), format!("Navigateur du portail prêt, images de la page seulement (manquent : {}).", left.join(", "))).into()
    })
}

fn run_locked(config: &Config, dir: &Path) -> Result<()> {
    let r = take_request(&config.data_dir)?;
    let mut run = Runner {
        p: Progress { id: r.id.clone(), de: CURRENT.into(), vers: r.version.clone(), par: r.par.clone(), debut: Some(Utc::now()), resultat: "en_cours".into(), ..Default::default() },
        path: dir.join("etat.json"),
    };
    let outcome = attempt(config, dir, &r, &mut run);
    run.p.fin = Some(Utc::now());
    run.p.etape = "fini".into();
    match outcome {
        Ok(Done::Updated) => {
            run.p.resultat = "reussie".into();
            run.p.message = t!(format!("Portunia Gate {} is running.", r.version), format!("Portunia Gate {} est en service.", r.version)).into();
            // Ne garde que les fichiers de cette exécution (retour manuel encore possible).
            for e in std::fs::read_dir(dir)?.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let keep = name == format!("portunia-gate_{}.deb", r.version) || name == format!("portunia-gate_{CURRENT}.deb") || name == format!("base-avant-{}.dump", r.version);
                if (name.ends_with(".deb") || name.ends_with(".dump")) && !keep {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        Ok(Done::RolledBack(why)) => {
            run.p.resultat = "retour_arriere".into();
            run.p.message = why;
        }
        Err(e) => {
            run.p.resultat = "echec".into();
            run.p.message = format!("{e:#}");
        }
    }
    let line = format!("→ {} : {}", run.p.resultat, run.p.message);
    run.line(line);
    Ok(())
}

enum Done {
    Updated,
    RolledBack(String),
}

fn attempt(config: &Config, dir: &Path, r: &Request, run: &mut Runner) -> Result<Done> {
    anyhow::ensure!(strict_version(&r.version).as_deref() == Some(r.version.as_str()), "version invalide");
    if !newer(&r.version, CURRENT) {
        bail!(t!(format!("version {} refused: not newer than {CURRENT}", r.version), format!("version {} refusée : pas plus récente que la {CURRENT}", r.version)));
    }
    run.step("telechargement", t!(format!("Downloading {} and checking its SHA-256 checksum", r.version), format!("Téléchargement de la {} et vérification de son empreinte SHA-256", r.version)).into());
    let new_deb = dir.join(format!("portunia-gate_{}.deb", r.version));
    download_checked(&r.version, &new_deb)?;
    let old_deb = dir.join(format!("portunia-gate_{CURRENT}.deb"));
    let rollback = if r.sans_retour {
        run.line(t!("Without rollback (requested).", "Sans retour en arrière (demandé).").into());
        false
    } else {
        run.line(t!(format!("Downloading {CURRENT} for the rollback"), format!("Téléchargement de la {CURRENT} pour le retour en arrière")).into());
        download_checked(CURRENT, &old_deb).map_err(|e| {
            anyhow!(t!(
                format!("package of the installed version unavailable, so no rollback possible: nothing was changed ({e:#}). On the server: sudo portunia-gate update apply --no-rollback"),
                format!("paquet de la version installée introuvable, donc pas de retour en arrière possible : rien n'a été changé ({e:#}). Sur le serveur : sudo portunia-gate update apply --no-rollback")
            ))
        })?;
        true
    };
    run.step("sauvegarde", t!("Backing up the database", "Sauvegarde de la base").into());
    let backup = dir.join(format!("base-avant-{}.dump", r.version));
    dump(config, &backup).context(t!("database backup", "sauvegarde de la base"))?;
    run.line(t!(format!("Backup: {} ({} KB)", backup.display(), std::fs::metadata(&backup).map(|m| m.len() / 1024).unwrap_or(0)), format!("Sauvegarde : {} ({} Ko)", backup.display(), std::fs::metadata(&backup).map(|m| m.len() / 1024).unwrap_or(0))).into());

    run.step("installation", t!(format!("Installing {}", r.version), format!("Installation de la {}", r.version)).into());
    let since = now_secs();
    let installed = install(&new_deb);
    let why = match installed {
        Err(e) => format!("{} {e:#}", t!("installation:", "installation :")),
        Ok(()) => {
            // Le paquet relance la Gate ; s'il ne l'a pas fait (arrêtée), on la démarre.
            let _ = sh(Command::new("systemctl").args(["start", "portunia-gate.service"]));
            run.step("demarrage", t!(format!("Waiting for {} to start", r.version), format!("Attente du démarrage de la {}", r.version)).into());
            if wait_started(&config.data_dir, &r.version, since) {
                run.line(t!(format!("{} started and answers.", r.version), format!("La {} a démarré et répond.", r.version)).into());
                return Ok(Done::Updated);
            }
            let tail = journal_tail(since);
            format!("{} {tail}",t!(format!("version {} did not start within {} s.", r.version, START_WAIT.as_secs()), format!("la version {} n'a pas démarré en {} s.", r.version, START_WAIT.as_secs())))
        }
    };
    run.line(why.clone());
    if !rollback {
        bail!("{why} {}", t!(format!("No rollback: backup kept in {}.", backup.display()), format!("Pas de retour en arrière : sauvegarde gardée dans {}.", backup.display())));
    }
    run.step("retour", t!(format!("Rollback to {CURRENT}"), format!("Retour à la {CURRENT}")).into());
    let _ = sh(Command::new("systemctl").args(["stop", "portunia-gate.service"]));
    install(&old_deb).context(t!("reinstalling the previous package", "réinstallation de l'ancien paquet"))?;
    run.line(t!("Previous package reinstalled; restoring the database", "Ancien paquet réinstallé ; restauration de la base").into());
    restore(config, &backup).context(t!("restoring the database", "restauration de la base"))?;
    let since = now_secs();
    sh(Command::new("systemctl").args(["start", "portunia-gate.service"]))?;
    if !wait_started(&config.data_dir, CURRENT, since) {
        bail!("{why} — {}", t!(format!("and version {CURRENT} does not start again either: journalctl -u portunia-gate"), format!("et la version {CURRENT} ne redémarre pas non plus : journalctl -u portunia-gate")));
    }
    Ok(Done::RolledBack(why))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v0.39.0"), Some((0, 39, 0)));
        assert_eq!(parse_version("0.39.0-1"), Some((0, 39, 0)));
        assert_eq!(parse_version("0.39"), None);
        assert_eq!(parse_version("0.39.0.1"), None);
        // A3 : seule la forme exacte passe vers l'adresse du paquet.
        assert_eq!(strict_version("v0.49.0").as_deref(), Some("0.49.0"));
        assert_eq!(strict_version(" 1.02.3 ").as_deref(), Some("1.2.3"));
        for bad in ["99.0.0-/../../evil/repo/releases/download/v1", "99.0.0-1", r"99.0.0\..\x","1.2", "1.2.3.4", "12345.0.0", "1.2.x", "", "+1.2.3", "1. 2.3"] {
            assert_eq!(strict_version(bad), None, "{bad}");
        }
        assert!(newer("0.40.0", "0.39.9"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("0.39.0", "0.39.0"));
        assert!(!newer("0.38.1", "0.39.0"));
        assert!(!newer("x", "0.1.0"));
    }

    #[test]
    fn sha256sums() {
        let sums = "aa  installer.sh\n".to_string()
            + &"b".repeat(64)
            + "  portunia-gate_0.39.0-1_amd64.deb\n"
            + &"c".repeat(64)
            + "  portunia-gate_amd64.deb\n";
        assert_eq!(version_from_sums(&sums).as_deref(), Some("0.39.0"));
        assert_eq!(sum_of(&sums, "portunia-gate_amd64.deb"), Some("c".repeat(64)));
        assert_eq!(sum_of(&sums, "installer.sh"), None, "empreinte trop courte");
        assert_eq!(version_from_sums("x  portunia-gate_amd64.deb"), None);
    }
}
