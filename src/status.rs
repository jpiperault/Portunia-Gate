//! État de la Gate (0.39) : santé, matériel, services, stockage, activité, intégrité du
//! journal, mise à jour. Le service mesure chaque minute et garde 24 heures d'historique en
//! mémoire (un point toutes les 5 minutes) pour les courbes de Portunia ; la ligne de commande
//! (`portunia-gate status`) mesure l'instant présent.
//!
//! Conservation des enregistrements : au-delà de `conservation_jours` (0 : toujours gardés),
//! les fichiers des sessions terminées sont supprimés chaque heure ; la session reste dans
//! la liste, avec son empreinte, et la suppression est notée au journal.
//! Disque plein à plus de 85 % : alerte aux administrateurs, une fois par jour au plus.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{audit, model, notify, update, State};

const SAMPLE: Duration = Duration::from_secs(60);
/// Un point d'historique toutes les 5 mesures, 24 heures gardées.
const POINT_EVERY: u32 = 5;
const POINTS: usize = 288;
pub const DISK_WARN: f64 = 85.0;
pub const DISK_ERROR: f64 = 95.0;
/// Réglage : jours de conservation des enregistrements (0 : toujours).
pub const RETENTION: &str = "conservation_jours";
const DISK_ALERTED: &str = "alerte_disque_le";

#[derive(Clone, Serialize)]
pub struct Point {
    pub t: i64,
    pub cpu: f32,
    pub mem: f32,
    pub disque: f32,
    /// Octets des enregistrements.
    pub enreg: u64,
}

#[derive(Clone, Serialize)]
pub struct Storage {
    pub octets: u64,
    pub fichiers: u64,
    pub plus_ancien: Option<DateTime<Utc>>,
    pub mesure: DateTime<Utc>,
}

#[derive(Clone, Serialize)]
struct Journal {
    ok: bool,
    evenements: i64,
    verifie_le: DateTime<Utc>,
    erreur: Option<String>,
}

#[derive(Default)]
struct Live {
    started: Option<DateTime<Utc>>,
    cpu: Option<f32>,
    net: Option<(f64, f64)>,
    history: VecDeque<Point>,
    storage: Option<Storage>,
    journal: Option<Journal>,
}

static LIVE: Mutex<Option<Live>> = Mutex::new(None);

fn with_live<T>(f: impl FnOnce(&mut Live) -> T) -> T {
    let mut guard = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(Live::default))
}

// ---------- Mesures du système ----------

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// (inactif, total) depuis /proc/stat.
fn cpu_times() -> Option<(u64, u64)> {
    let text = read("/proc/stat")?;
    let v: Vec<u64> = text.lines().next()?.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    (v.len() >= 4).then(|| (v[3] + v.get(4).copied().unwrap_or(0), v.iter().sum()))
}

fn cpu_percent(a: (u64, u64), b: (u64, u64)) -> Option<f32> {
    let total = b.1.checked_sub(a.1)?;
    let idle = b.0.checked_sub(a.0)?;
    (total > 0).then(|| (100.0 * (total.saturating_sub(idle)) as f64 / total as f64) as f32)
}

/// Octets reçus et envoyés, toutes interfaces sauf lo.
fn net_bytes() -> Option<(u64, u64)> {
    let text = read("/proc/net/dev")?;
    let mut rx = 0;
    let mut tx = 0;
    for line in text.lines().skip(2) {
        let (name, rest) = line.split_once(':')?;
        if name.trim() == "lo" {
            continue;
        }
        let f: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if f.len() >= 9 {
            rx += f[0];
            tx += f[8];
        }
    }
    Some((rx, tx))
}

/// (total, utilisée) en octets.
pub fn memory() -> Option<(u64, u64)> {
    let text = read("/proc/meminfo")?;
    let field = |name: &str| text.lines().find(|l| l.starts_with(name)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u64>().ok());
    let total = field("MemTotal:")? * 1024;
    let available = field("MemAvailable:")? * 1024;
    Some((total, total.saturating_sub(available)))
}

/// (total, libre pour le compte de service) du disque qui porte ce dossier.
pub fn disk(dir: &Path) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        (unsafe { libc::statvfs(path.as_ptr(), &mut s) } == 0).then(|| (s.f_blocks as u64 * s.f_frsize as u64, s.f_bavail as u64 * s.f_frsize as u64))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        None
    }
}

fn disk_percent(d: Option<(u64, u64)>) -> Option<f64> {
    d.filter(|d| d.0 > 0).map(|(total, free)| 100.0 * total.saturating_sub(free) as f64 / total as f64)
}

fn uptime_secs() -> Option<u64> {
    read("/proc/uptime")?.split_whitespace().next()?.parse::<f64>().ok().map(|s| s as u64)
}

fn load() -> Option<Vec<f64>> {
    let text = read("/proc/loadavg")?;
    Some(text.split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect())
}

fn os_name() -> Option<String> {
    let text = read("/etc/os-release")?;
    text.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")).map(|v| v.trim_matches('"').to_string())
}

/// Taille, nombre et plus ancien des enregistrements (et copies de fichiers).
pub fn walk(dir: &Path) -> Storage {
    let mut octets = 0;
    let mut fichiers = 0;
    let mut oldest: Option<std::time::SystemTime> = None;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let Ok(meta) = e.metadata() else { continue };
            if meta.is_dir() {
                stack.push(e.path());
            } else if meta.is_file() {
                octets += meta.len();
                fichiers += 1;
                if let Ok(m) = meta.modified() {
                    oldest = Some(oldest.map_or(m, |o| o.min(m)));
                }
            }
        }
    }
    Storage { octets, fichiers, plus_ancien: oldest.map(DateTime::<Utc>::from), mesure: Utc::now() }
}

/// Heure synchronisée : Some(vrai/faux), ou None si on ne sait pas (Docker, pas de systemd).
fn clock_synced() -> Option<bool> {
    if Path::new("/run/systemd/timesync/synchronized").exists() {
        return Some(true);
    }
    let out = std::process::Command::new("timedatectl").args(["show", "-p", "NTPSynchronized", "--value"]).output().ok()?;
    match String::from_utf8_lossy(&out.stdout).trim() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

// ---------- Tâche de fond ----------

pub async fn run(state: Arc<State>) -> Result<()> {
    with_live(|l| l.started = Some(Utc::now()));
    let mut prev_cpu = cpu_times();
    let mut prev_net = net_bytes();
    let mut prev_at = std::time::Instant::now();
    let mut n: u32 = 0;
    let mut acc = (0f32, 0u32);
    // Première mesure rapide, puis chaque minute.
    let mut wait = Duration::from_secs(3);
    loop {
        tokio::time::sleep(wait).await;
        wait = SAMPLE;
        let cpu_now = cpu_times();
        let net_now = net_bytes();
        let secs = prev_at.elapsed().as_secs_f64().max(1.0);
        prev_at = std::time::Instant::now();
        let cpu = prev_cpu.zip(cpu_now).and_then(|(a, b)| cpu_percent(a, b));
        let net = prev_net.zip(net_now).map(|(a, b)| (b.0.saturating_sub(a.0) as f64 / secs, b.1.saturating_sub(a.1) as f64 / secs));
        prev_cpu = cpu_now;
        prev_net = net_now;
        with_live(|l| {
            l.cpu = cpu.or(l.cpu);
            l.net = net.or(l.net);
        });
        if let Some(c) = cpu {
            acc = (acc.0 + c, acc.1 + 1);
        }
        // Enregistrements mesurés toutes les 15 minutes (et au démarrage).
        if n % 15 == 0 {
            let dir = state.config.recordings_dir();
            if let Ok(s) = tokio::task::spawn_blocking(move || walk(&dir)).await {
                with_live(|l| l.storage = Some(s));
            }
        }
        // Chaîne du journal vérifiée toutes les 6 heures (la première fois après 2 minutes).
        if n % 360 == 2 {
            let j = match audit::verify(&state.db).await {
                Ok(Ok(count)) => Journal { ok: true, evenements: count, verifie_le: Utc::now(), erreur: None },
                Ok(Err(broken)) => Journal { ok: false, evenements: 0, verifie_le: Utc::now(), erreur: Some(broken) },
                Err(e) => Journal { ok: false, evenements: 0, verifie_le: Utc::now(), erreur: Some(format!("{e:#}")) },
            };
            if !j.ok {
                audit::note(&state.db, "systeme", "journal.altere", json!({ "erreur": j.erreur })).await;
            }
            with_live(|l| l.journal = Some(j));
        }
        // Conservation des enregistrements : chaque heure.
        if n % 60 == 1 {
            if let Err(e) = purge(&state, "systeme").await {
                tracing::warn!("{} {e:#}", t!("recordings retention:", "conservation des enregistrements :"));
            }
        }
        let disk_pct = disk_percent(disk(&state.config.data_dir));
        if n % POINT_EVERY == 0 {
            let mem = memory().map(|(t, u)| if t > 0 { (100.0 * u as f64 / t as f64) as f32 } else { 0.0 }).unwrap_or(0.0);
            let point = Point {
                t: Utc::now().timestamp(),
                cpu: if acc.1 > 0 { acc.0 / acc.1 as f32 } else { cpu.unwrap_or(0.0) },
                mem,
                disque: disk_pct.unwrap_or(0.0) as f32,
                enreg: with_live(|l| l.storage.as_ref().map(|s| s.octets).unwrap_or(0)),
            };
            acc = (0.0, 0);
            with_live(|l| {
                l.history.push_back(point);
                while l.history.len() > POINTS {
                    l.history.pop_front();
                }
            });
        }
        if let Some(pct) = disk_pct.filter(|p| *p >= DISK_WARN) {
            disk_alert(&state, pct).await;
        }
        n = n.wrapping_add(1);
    }
}

async fn disk_alert(state: &Arc<State>, pct: f64) {
    let last = model::setting(&state.db, DISK_ALERTED).await.ok().flatten().and_then(|v| v.as_i64()).unwrap_or(0);
    let now = Utc::now().timestamp();
    if now - last < 24 * 3600 {
        return;
    }
    let _ = model::set_setting(&state.db, DISK_ALERTED, json!(now)).await;
    let free = disk(&state.config.data_dir).map(|d| d.1).unwrap_or(0);
    audit::note(&state.db, "systeme", "disque.presque_plein", json!({ "pourcent": pct.round(), "libre": free })).await;
    let to = notify::group_emails(state, None).await.unwrap_or_default();
    let gb = free as f64 / 1e9;
    notify::send(state.clone(), notify::Notice {
        event: "disque.presque_plein",
        title: t!(format!("Gate disk {pct:.0} % full"), format!("Disque de la Gate plein à {pct:.0} %")),
        text: t!(
            format!("The Gate's disk is {pct:.0} % full ({gb:.1} GB free). Below {} MB free, recorded sessions are refused. Set the retention of recordings (Portunia › Gate status, or « portunia-gate setting recording_days 180 ») or enlarge the disk.", state.config.min_free_mb),
            format!("Le disque de la Gate est plein à {pct:.0} % ({gb:.1} Go libres). Sous {} Mo libres, les sessions enregistrées sont refusées. Réglez la conservation des enregistrements (Portunia › État de la Gate, ou « portunia-gate setting recording_days 180 ») ou agrandissez le disque.", state.config.min_free_mb)
        ),
        detail: json!({ "pourcent": pct.round(), "libre": free }),
        to,
    });
}

// ---------- Conservation des enregistrements ----------

pub async fn retention_days(state: &State) -> Result<i64> {
    Ok(model::setting(&state.db, RETENTION).await?.and_then(|v| v.as_i64()).unwrap_or(0).clamp(0, 36500))
}

/// Supprime les enregistrements des sessions terminées depuis plus de `conservation_jours`.
/// Renvoie (sessions, octets).
pub async fn purge(state: &State, actor: &str) -> Result<(u64, u64)> {
    let days = retention_days(state).await?;
    if days == 0 {
        return Ok((0, 0));
    }
    let root = state.config.recordings_dir();
    let mut sessions = 0u64;
    let mut bytes = 0u64;
    loop {
        let rows: Vec<(uuid::Uuid, String)> = sqlx::query_as(
            "SELECT id, recording FROM sessions WHERE recording IS NOT NULL AND ended_at IS NOT NULL AND ended_at < now() - make_interval(days => $1::int) ORDER BY ended_at LIMIT 500",
        )
        .bind(days as i32)
        .fetch_all(&state.db)
        .await?;
        if rows.is_empty() {
            break;
        }
        for (id, recording) in rows {
            let path = PathBuf::from(&recording);
            // Seulement sous le dossier des enregistrements.
            if path.starts_with(&root) && !recording.contains("..") {
                bytes += remove_recording(&path);
            }
            sqlx::query("UPDATE sessions SET recording = NULL, texte = NULL WHERE id = $1").bind(id).execute(&state.db).await?;
            sessions += 1;
        }
    }
    if sessions > 0 {
        audit::log(&state.db, actor, "enregistrement.purge", json!({ "sessions": sessions, "octets": bytes, "jours": days })).await?;
        if let Ok(s) = tokio::task::spawn_blocking(move || walk(&root)).await {
            with_live(|l| l.storage = Some(s));
        }
    }
    Ok((sessions, bytes))
}

/// Fichier d'enregistrement et copies de fichiers (« <session>-fichiers ») ; octets libérés.
fn remove_recording(path: &Path) -> u64 {
    let mut freed = 0;
    if let Ok(m) = std::fs::metadata(path) {
        if std::fs::remove_file(path).is_ok() {
            freed += m.len();
        }
    }
    if let Some(stem) = path.file_stem() {
        let copies = path.with_file_name(format!("{}-fichiers", stem.to_string_lossy()));
        if copies.is_dir() {
            freed += walk(&copies).octets;
            let _ = std::fs::remove_dir_all(&copies);
        }
    }
    freed
}

// ---------- Rapport ----------

fn service(id: &str, nom: &str, etat: &str, detail: String) -> Value {
    json!({ "id": id, "nom": nom, "etat": etat, "detail": detail })
}

fn duration_text(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, secs % 86400 / 3600, secs % 3600 / 60);
    if d > 0 {
        t!(format!("{d} d {h} h"), format!("{d} j {h} h"))
    } else if h > 0 {
        format!("{h} h {m:02}")
    } else {
        format!("{m} min")
    }
}

/// État complet. `service` : appelé par le service (mesures en mémoire) ; sinon, par la ligne
/// de commande, qui mesure l'instant présent.
pub async fn report(state: &State, service_side: bool, check_update: bool) -> Result<Value> {
    let db = &state.db;
    let (started, mut cpu, net, history, storage, journal) = with_live(|l| (l.started, l.cpu, l.net, l.history.iter().cloned().collect::<Vec<_>>(), l.storage.clone(), l.journal.clone()));
    let storage = match storage {
        Some(s) => s,
        None => {
            let dir = state.config.recordings_dir();
            tokio::task::spawn_blocking(move || walk(&dir)).await?
        }
    };
    if cpu.is_none() {
        let a = cpu_times();
        tokio::time::sleep(Duration::from_millis(400)).await;
        cpu = a.zip(cpu_times()).and_then(|(a, b)| cpu_percent(a, b));
    }
    let mem = memory();
    let dsk = disk(&state.config.data_dir);
    let disk_pct = disk_percent(dsk);
    let uptime = uptime_secs();
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    let mut services = Vec::new();
    let mut alerts: Vec<String> = Vec::new();
    let mut level = 0u8; // 0 ok, 1 alerte, 2 erreur
    let mut raise = |l: u8, text: String, alerts: &mut Vec<String>| {
        level = level.max(l);
        alerts.push(text);
    };

    // La Gate elle-même.
    let since = started.map(|s| (Utc::now() - s).num_seconds().max(0) as u64);
    services.push(service("gate", "Portunia Gate", "ok", match since {
        Some(s) => t!(format!("{} · running for {}", update::CURRENT, duration_text(s)), format!("{} · en service depuis {}", update::CURRENT, duration_text(s))),
        None => update::CURRENT.to_string(),
    }));

    // Base de données.
    let base: Result<(String, i64), sqlx::Error> = sqlx::query_as("SELECT split_part(version(), ' ', 2), pg_database_size(current_database())").fetch_one(db).await;
    let db_bytes = match &base {
        Ok((v, size)) => {
            services.push(service("base", &format!("PostgreSQL {}", v.split('.').next().unwrap_or(v)), "ok", format!("{} · {v}", human(*size as u64))));
            *size as u64
        }
        Err(e) => {
            services.push(service("base", "PostgreSQL", "erreur", e.to_string()));
            raise(2, t!("Database unreachable", "Base de données injoignable").into(), &mut alerts);
            0
        }
    };

    // Certificat du portail web.
    let cert = if service_side { crate::cert::current() } else { crate::cert::inspect(state).await.ok() };
    if let Some(c) = cert {
        let days = c.days_left();
        let (etat, detail) = if c.auto_signe {
            ("ok", t!(format!("self-signed · {days} days left"), format!("auto-signé · reste {days} jours")))
        } else if days < 0 {
            raise(2, t!("Web portal certificate expired", "Certificat du portail web expiré").into(), &mut alerts);
            ("erreur", t!("expired".to_string(), "expiré".to_string()))
        } else if days <= crate::cert::WARN_DAYS {
            raise(1, t!(format!("Web portal certificate expires in {days} days"), format!("Le certificat du portail web expire dans {days} jours")), &mut alerts);
            ("alerte", t!(format!("expires in {days} days"), format!("expire dans {days} jours")))
        } else {
            ("ok", t!(format!("{days} days left · {}", c.source), format!("reste {days} jours · {}", c.source)))
        };
        services.push(service("certificat", t!("HTTPS certificate", "Certificat HTTPS"), etat, detail));
    }

    // Relais dédiés du portail.
    if service_side {
        for r in crate::relay::report(state).await.unwrap_or_default() {
            let up = r["connecte"] == json!(true);
            let name = r["nom"].as_str().unwrap_or("?").to_string();
            if !up {
                raise(1, t!(format!("Relay {name} not connected"), format!("Relais {name} non connecté")), &mut alerts);
            }
            services.push(service("relais", &t!(format!("Relay {name}"), format!("Relais {name}")), if up { "ok" } else { "alerte" }, if up { t!("connected", "connecté").into() } else { r["erreur"].as_str().unwrap_or(t!("not connected", "non connecté")).to_string() }));
        }
    }

    // Heure.
    match clock_synced() {
        Some(true) => services.push(service("heure", t!("Clock (NTP)", "Heure (NTP)"), "ok", t!("synchronised", "synchronisée").into())),
        Some(false) => {
            raise(1, t!("Clock not synchronised: codes and certificates may fail", "Heure non synchronisée : codes et certificats peuvent échouer").into(), &mut alerts);
            services.push(service("heure", t!("Clock (NTP)", "Heure (NTP)"), "alerte", t!("not synchronised", "non synchronisée").into()));
        }
        None => {}
    }

    // Notifications.
    if let Ok(n) = notify::settings(state).await {
        let mut channels = Vec::new();
        if n.mail_ready() {
            channels.push(t!("e-mail", "courriel"));
        }
        if !n.teams_url.is_empty() {
            channels.push("Teams");
        }
        if !n.webhook_url.is_empty() {
            channels.push("webhook");
        }
        services.push(if channels.is_empty() {
            service("notifications", "Notifications", "info", t!("not set: alerts are not sent", "non réglées : les alertes ne partent pas").into())
        } else {
            service("notifications", "Notifications", "ok", channels.join(", "))
        });
    }

    // Durcissement du serveur.
    let hardening_text = tokio::fs::read_to_string(state.config.data_dir.join("durcissement.json")).await.ok();
    let h = crate::api::hardening_report(hardening_text.as_deref().filter(|t| t.len() < 64 * 1024), Utc::now());
    if h["actif"] == json!(true) {
        let alerts_h = h["alertes"].as_array().map(|a| a.len()).unwrap_or(0);
        if alerts_h > 0 {
            raise(1, t!("Server hardening: see the Hardening section", "Durcissement du serveur : voir la section Durcissement").into(), &mut alerts);
        }
        services.push(service("durcissement", t!("Hardening", "Durcissement"), if alerts_h > 0 { "alerte" } else { "ok" }, if alerts_h > 0 { t!(format!("{alerts_h} alert(s)"), format!("{alerts_h} alerte(s)")) } else { t!("active", "actif").into() }));
    } else if update::mode() == "paquet" {
        services.push(service("durcissement", t!("Hardening", "Durcissement"), "info", t!("not hardened (installer.sh harden)", "non durci (installer.sh durcir)").into()));
    }

    // Disque.
    if let Some(p) = disk_pct {
        if p >= DISK_ERROR {
            raise(2, t!(format!("Disk {p:.0} % full"), format!("Disque plein à {p:.0} %")), &mut alerts);
        } else if p >= DISK_WARN {
            raise(1, t!(format!("Disk {p:.0} % full"), format!("Disque plein à {p:.0} %")), &mut alerts);
        }
    }

    // Rythme de remplissage : sur l'historique (6 h au moins), sinon depuis le plus ancien enregistrement.
    let per_day = match (history.first(), history.last()) {
        (Some(a), Some(b)) if b.t - a.t >= 6 * 3600 => Some(b.enreg.saturating_sub(a.enreg) as f64 * 86400.0 / (b.t - a.t) as f64),
        _ => storage.plus_ancien.map(|o| {
            let days = ((Utc::now() - o).num_seconds() as f64 / 86400.0).max(1.0);
            storage.octets as f64 / days
        }),
    };
    let full_in = dsk.zip(per_day).filter(|(_, r)| *r > 1.0).map(|((_, free), r)| (free.saturating_sub(state.config.min_free_bytes()) as f64 / r).floor() as i64);
    if let Some(d) = full_in.filter(|d| *d < 14) {
        raise(1, t!(format!("Disk full in about {d} days at the current rate"), format!("Disque plein dans environ {d} jours au rythme actuel")), &mut alerts);
    }

    // Journal.
    if let Some(j) = journal.as_ref().filter(|j| !j.ok) {
        raise(2, t!(format!("Audit log tampered with: {}", j.erreur.clone().unwrap_or_default()), format!("Journal d'audit altéré : {}", j.erreur.clone().unwrap_or_default())), &mut alerts);
    }

    // Activité.
    let open = if service_side {
        state.live.sessions().len() as i64
    } else {
        sqlx::query_scalar("SELECT count(*) FROM sessions WHERE ended_at IS NULL AND started_at > now() - interval '2 days'").fetch_one(db).await.unwrap_or(0)
    };
    let today: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE started_at >= date_trunc('day', now())").fetch_one(db).await.unwrap_or(0);
    let refused: i64 = sqlx::query_scalar("SELECT count(*) FROM audit WHERE at > now() - interval '24 hours' AND event IN ('acces.refuse', 'auth.echec', 'auth.bloquee')").fetch_one(db).await.unwrap_or(0);
    let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM approvals WHERE status = 'attente'").fetch_one(db).await.unwrap_or(0);

    let up = update::summary(state, check_update).await?;
    if up["disponible"] == json!(true) {
        services.push(service("mise_a_jour", t!("Update", "Mise à jour"), "info", t!(format!("{} available", up["derniere"].as_str().unwrap_or("?")), format!("{} disponible", up["derniere"].as_str().unwrap_or("?")))));
    }
    if let Some(p) = update::progress().filter(|p| p.resultat == "echec" || p.resultat == "retour_arriere") {
        if p.fin.is_some_and(|f| (Utc::now() - f).num_hours() < 24) {
            raise(1, t!(format!("Update to {} not done: {}", p.vers, p.message), format!("Mise à jour en {} non faite : {}", p.vers, p.message)), &mut alerts);
        }
    }

    let nom = crate::api::setting_str(state, "nom", "Portunia Gate").await?;
    let niveau = ["ok", "alerte", "erreur"][level as usize];
    Ok(json!({
        "nom": nom,
        "version": update::CURRENT,
        "mode": update::mode(),
        "niveau": niveau,
        "alertes": alerts,
        "hote": read("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()),
        "systeme": os_name(),
        "noyau": read("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string()),
        "demarree_le": started,
        "machine_depuis_s": uptime,
        "cpu": { "coeurs": cores, "pourcent": cpu, "charge": load() },
        "memoire": mem.map(|(total, used)| json!({ "total": total, "utilisee": used })),
        "disque": dsk.map(|(total, free)| json!({ "chemin": state.config.data_dir, "total": total, "libre": free, "pourcent": disk_pct })),
        "reseau": net.map(|(rx, tx)| json!({ "recu_s": rx, "envoye_s": tx })),
        "historique": history,
        "services": services,
        "stockage": {
            "enregistrements": storage,
            "base_octets": db_bytes,
            "par_jour": per_day,
            "plein_dans_jours": full_in,
            "conservation_jours": retention_days(state).await?,
            "minimum_libre_mo": state.config.min_free_mb,
        },
        "activite": { "sessions_ouvertes": open, "sessions_jour": today, "refus_24h": refused, "approbations_attente": waiting },
        "journal": journal,
        "mise_a_jour": up,
    }))
}

pub fn human(bytes: u64) -> String {
    let b = bytes as f64;
    let (v, unit) = if b >= 1e12 {
        (b / 1e12, t!("TB", "To"))
    } else if b >= 1e9 {
        (b / 1e9, t!("GB", "Go"))
    } else if b >= 1e6 {
        (b / 1e6, t!("MB", "Mo"))
    } else if b >= 1e3 {
        (b / 1e3, t!("KB", "Ko"))
    } else {
        return t!(format!("{bytes} B"), format!("{bytes} o"));
    };
    format!("{v:.1} {unit}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesures() {
        assert_eq!(cpu_percent((100, 1000), (150, 1100)), Some(50.0));
        assert_eq!(cpu_percent((100, 1000), (100, 1000)), None);
        assert_eq!(disk_percent(Some((200, 50))), Some(75.0));
        assert_eq!(disk_percent(Some((0, 0))), None);
        assert!(human(1_500_000_000).starts_with("1.5"));
    }

    /// PostgreSQL refuse un fichier qui commence par une marque d'ordre des octets (BOM) :
    /// la 0.39.0 ne démarrait plus à cause de la migration 0015.
    #[test]
    fn migrations_sans_bom() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let bytes = std::fs::read(e.path()).unwrap();
            assert!(!bytes.starts_with(&[0xEF, 0xBB, 0xBF]), "BOM dans {}", e.path().display());
        }
    }

    #[test]
    fn suppression_d_un_enregistrement() {
        let dir = std::env::temp_dir().join(format!("portunia-gate-conservation-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("2026/01/s1-fichiers")).unwrap();
        std::fs::write(dir.join("2026/01/s1.rdpcap"), vec![0u8; 100]).unwrap();
        std::fs::write(dir.join("2026/01/s1-fichiers/001-a.txt"), vec![0u8; 20]).unwrap();
        std::fs::write(dir.join("2026/01/s2.cast"), vec![0u8; 7]).unwrap();
        assert_eq!(walk(&dir).octets, 127);
        assert_eq!(remove_recording(&dir.join("2026/01/s1.rdpcap")), 120);
        let left = walk(&dir);
        assert_eq!((left.octets, left.fichiers), (7, 1));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
