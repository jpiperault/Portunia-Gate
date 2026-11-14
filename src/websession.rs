//! Sessions web : ce qu'un compte fait dans une interface web relayée par la Gate.
//!
//! Une session par compte et par serveur : elle s'ouvre à la première requête et se ferme après
//! `IDLE` sans requête, quand l'accès prend fin (règle retirée, portail fermé, compte coupé) ou
//! quand un administrateur la coupe. Elle a sa ligne dans les sessions (type `web`) et son
//! journal d'actions `<session>.weblog`, signé à la fermeture comme les autres enregistrements.
//!
//! Format : une ligne d'en-tête JSON (`"format": "portunia-gate-web-v1"`), puis une ligne par
//! action : `{"t": secondes, "k": "page" | "envoi" | "websocket" | "coffre", "methode",
//! "chemin", "statut"}`. Le chemin est gardé sans ses paramètres (`?…`), le corps des requêtes
//! jamais : mots de passe et données saisies ne sont pas écrits. Les images, scripts et appels
//! de lecture (GET hors pages) ne sont pas notés.

use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    audit,
    keys::sha256_hex,
    live,
    model::{self, Target, User},
    State,
};

/// Sans requête pendant ce temps, la session web se ferme.
pub const IDLE: Duration = Duration::from_secs(15 * 60);
const SWEEP: Duration = Duration::from_secs(30);
/// Au-delà, les chemins ne sont plus ajoutés à l'index de recherche.
const INDEX_MAX: usize = 32 * 1024;

struct Active {
    id: Uuid,
    login: String,
    target: String,
    started: Instant,
    last: Instant,
    path: PathBuf,
    out: BufWriter<File>,
    actions: u64,
    failed: bool,
    /// Chemins vus, pour la recherche dans l'Audit.
    index: String,
    _guard: live::Guard,
    cut: live::Cut,
}

static ACTIVE: LazyLock<Mutex<HashMap<(Uuid, Uuid), Active>>> = LazyLock::new(Mutex::default);

/// Nature d'une requête, pour le journal d'actions ; `None` : rien à noter.
pub fn kind(method: &axum::http::Method, document: bool, upgrade: bool) -> Option<&'static str> {
    use axum::http::Method;
    if upgrade {
        Some("websocket")
    } else if document {
        Some("page")
    } else if ![Method::GET, Method::HEAD, Method::OPTIONS].contains(method) {
        Some("envoi")
    } else {
        None
    }
}

/// Chemin sans paramètres, pour le journal.
pub fn shown(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

/// Une requête arrive : ouvre la session si besoin. `Err(raison)` : la session a été coupée
/// ou ne peut pas être enregistrée, la requête est refusée.
pub async fn touch(state: &State, user: &User, target: &Target, client_addr: &str, portal: bool) -> std::result::Result<(), String> {
    let key = (user.id, target.id);
    {
        let mut all = ACTIVE.lock().unwrap();
        if let Some(a) = all.get_mut(&key) {
            if let Some(why) = a.cut.closed() {
                return Err(why);
            }
            a.last = Instant::now();
            return Ok(());
        }
    }
    if !live::can_record(state) {
        return Err(live::no_space_message().to_string());
    }
    let id = Uuid::new_v4();
    let created = async {
        model::session_start(&state.db, id, user.id, target.id, "web", "web", client_addr).await?;
        let now = chrono::Utc::now();
        let dir = state.config.recordings_dir().join(now.format("%Y/%m").to_string());
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{id}.weblog"));
        let mut out = BufWriter::new(File::create(&path)?);
        writeln!(out, "{}", json!({ "format": "portunia-gate-web-v1", "session": id, "compte": user.login, "serveur": target.name, "debut": now }))?;
        out.flush()?;
        // Chemin connu dès l'ouverture : la session en cours se relit déjà dans l'Audit.
        model::session_recording(&state.db, id, &path.display().to_string()).await?;
        Ok::<_, anyhow::Error>((path, out))
    }
    .await;
    let (path, out) = match created {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("{} {}: {e:#}", t!("web session not recorded", "session web non enregistrée"), target.name);
            return Err(t!("The Gate cannot record this session", "La Gate ne peut pas enregistrer cette session").to_string());
        }
    };
    let (guard, cut) = state.live.watch(live::Watched { user: user.id, login: &user.login, target: Some(target), web: portal, recorded: true, session: Some(id), portal: None });
    let now = Instant::now();
    let active = Active { id, login: user.login.clone(), target: target.name.clone(), started: now, last: now, path, out, actions: 0, failed: false, index: String::new(), _guard: guard, cut };
    // Deux premières requêtes en même temps : la seconde session, inutile, est fermée aussitôt.
    let extra = {
        let mut all = ACTIVE.lock().unwrap();
        if all.contains_key(&key) {
            Some(active)
        } else {
            all.insert(key, active);
            None
        }
    };
    match extra {
        Some(a) => finish(state, a, t!("duplicate", "doublon")).await,
        None => audit::note(&state.db, &user.login, "web.session_ouverte", json!({ "session": id, "cible": target.name, "adresse": client_addr })).await,
    }
    Ok(())
}

/// Note une action de la session ouverte (voir `kind`).
pub fn action(user: Uuid, target: Uuid, k: &str, method: &str, path: &str, status: u16) {
    let mut all = ACTIVE.lock().unwrap();
    let Some(a) = all.get_mut(&(user, target)) else { return };
    let t = (a.started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0;
    let path = shown(path);
    let line = json!({ "t": t, "k": k, "methode": method, "chemin": path, "statut": status });
    a.failed |= writeln!(a.out, "{line}").and_then(|_| a.out.flush()).is_err();
    a.actions += 1;
    if a.index.len() < INDEX_MAX && !a.index.split('\n').any(|p| p == path) {
        a.index.push_str(path);
        a.index.push('\n');
    }
}

/// Ferme, signe et note la fin d'une session.
async fn finish(state: &State, mut a: Active, why: &str) {
    let _ = a.out.flush();
    let result = async {
        let content = std::fs::read(&a.path)?;
        let sha = sha256_hex(&content);
        use base64::Engine;
        let sig = base64::engine::general_purpose::STANDARD.encode(state.keys.sign(crate::recording::signature_message(a.id, &sha).as_bytes()));
        model::session_end(&state.db, a.id, model::Finished { recording: Some(a.path.display().to_string()), sha256: Some(sha), signature: Some(sig), bytes: content.len() as i64 }).await?;
        model::session_index(&state.db, a.id, false, &a.index).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(e) = result {
        tracing::warn!("{} {}: {e:#}", t!("web session not closed properly", "session web mal fermée"), a.target);
    }
    audit::note(
        &state.db,
        &a.login,
        "web.session_fermee",
        json!({ "session": a.id, "cible": a.target, "duree_s": a.started.elapsed().as_secs(), "actions": a.actions, "fin": why, "incomplet": a.failed }),
    )
    .await;
}

/// Ferme les sessions inactives ou coupées ; au démarrage, clôt celles d'un service arrêté.
pub async fn run(state: Arc<State>) -> Result<()> {
    // Fin brutale du service : ces sessions restent lisibles, sans signature (interrompues). Les
    // navigations (sortie web) ne survivent pas non plus à un redémarrage (0.53.1).
    sqlx::query("UPDATE sessions SET ended_at = now() WHERE kind IN ('web', 'navigation') AND ended_at IS NULL").execute(&state.db).await?;
    let mut tick = tokio::time::interval(SWEEP);
    loop {
        tick.tick().await;
        let ended: Vec<(Active, String)> = {
            let mut all = ACTIVE.lock().unwrap();
            let keys: Vec<_> = all
                .iter()
                .filter_map(|(k, a)| match a.cut.closed() {
                    Some(why) => Some((*k, why)),
                    None if a.last.elapsed() >= IDLE => Some((*k, t!("inactivity", "inactivité").to_string())),
                    None => None,
                })
                .collect();
            keys.into_iter().filter_map(|(k, why)| all.remove(&k).map(|a| (a, why))).collect()
        };
        for (a, why) in ended {
            finish(&state, a, &why).await;
        }
    }
}

/// Lit un journal d'actions : en-tête, actions, durée (temps de la dernière action).
pub fn read(raw: &[u8]) -> Result<(Value, Vec<Value>, f64)> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.lines();
    let header: Value = serde_json::from_str(lines.next().unwrap_or_default())?;
    if header["format"] != "portunia-gate-web-v1" {
        anyhow::bail!("format de journal web inconnu");
    }
    let actions: Vec<Value> = lines.filter_map(|l| serde_json::from_str(l).ok()).collect();
    let duration = actions.iter().filter_map(|a| a["t"].as_f64()).fold(0.0, f64::max);
    Ok((header, actions, duration))
}

/// Recherche dans les chemins : moment de la première action qui contient le texte, et ce chemin.
pub fn find(content: &str, needle: &str) -> Option<(f64, String)> {
    let needle = needle.to_lowercase();
    content.lines().skip(1).filter_map(|l| serde_json::from_str::<Value>(l).ok()).find_map(|a| {
        let path = a["chemin"].as_str()?;
        path.to_lowercase().contains(&needle).then(|| (a["t"].as_f64().unwrap_or(0.0), format!("{} {path}", a["methode"].as_str().unwrap_or_default())))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn actions_notees() {
        assert_eq!(kind(&Method::GET, true, false), Some("page"));
        assert_eq!(kind(&Method::GET, false, false), None, "image, script ou lecture d'API");
        assert_eq!(kind(&Method::POST, false, false), Some("envoi"));
        assert_eq!(kind(&Method::DELETE, false, false), Some("envoi"));
        assert_eq!(kind(&Method::OPTIONS, false, false), None);
        assert_eq!(kind(&Method::GET, false, true), Some("websocket"));
        assert_eq!(shown("/login?user=a&pw=b"), "/login");
    }

    #[test]
    fn relecture_du_journal() {
        let raw = b"{\"format\":\"portunia-gate-web-v1\",\"serveur\":\"vcenter\"}\n{\"t\":1.5,\"k\":\"page\",\"methode\":\"GET\",\"chemin\":\"/\",\"statut\":200}\n{\"t\":4.25,\"k\":\"envoi\",\"methode\":\"POST\",\"chemin\":\"/api/vm\",\"statut\":201}\n";
        let (header, actions, duration) = read(raw).unwrap();
        assert_eq!(header["serveur"], "vcenter");
        assert_eq!(actions.len(), 2);
        assert_eq!(duration, 4.25);
        assert!(read(b"{\"format\":\"autre\"}\n").is_err());
        let found = find(std::str::from_utf8(raw).unwrap(), "API/VM").unwrap();
        assert_eq!(found, (4.25, "POST /api/vm".to_string()));
        assert!(find(std::str::from_utf8(raw).unwrap(), "absent").is_none());
    }
}
