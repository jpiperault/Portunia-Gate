//! Sessions en cours : chacune s'inscrit ici et se ferme dès que son accès n'est plus valable
//! (compte désactivé ou supprimé, règle retirée, expirée ou hors de ses horaires, portail
//! fermé, serveur supprimé) ou que l'espace disque manque pour l'enregistrer.
//!
//! Les droits sont revérifiés toutes les 30 secondes, et tout de suite après un changement
//! fait par l'API. Une commande d'administration, processus à part, attend le tour suivant.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::Result;
use serde_json::json;
use tokio::sync::{watch, Notify};
use uuid::Uuid;

use crate::{audit, model, State};

const SWEEP: Duration = Duration::from_secs(30);

/// Compteur que `portal close-sessions` et `portal off` font avancer : le service ferme alors
/// les terminaux web ouverts.
pub const PORTAL_CLOSE: &str = "portail_fermeture";

/// Compteur que `portal acme` fait avancer : le service vérifie alors le certificat Let's Encrypt.
pub const ACME_WAKE: &str = "acme_reveil";

/// État en direct du service (tunnel, écoute HTTPS, Let's Encrypt…), écrit à chaque tour pour
/// les commandes d'administration, qui ne le voient pas autrement.
pub const SNAPSHOT: &str = "etat_service";

struct Entry {
    user: Uuid,
    login: String,
    target: Option<(Uuid, String)>,
    web: bool,
    recorded: bool,
    cut: watch::Sender<Option<String>>,
}

#[derive(Default)]
pub struct Registry {
    next: AtomicU64,
    entries: Arc<Mutex<HashMap<u64, Entry>>>,
    wake: Notify,
    low_disk: AtomicBool,
    /// Derniers ordres de la ligne de commande vus : compteur de fermeture du portail + 1
    /// (0 : pas encore lu), assistance ouverte (0 : pas encore lue, 1 : fermée, 2 : ouverte).
    portal_close: AtomicI64,
    assist_on: AtomicU8,
    /// Derniers ordres de fermeture de comptes et de réveil de Let's Encrypt vus, + 1.
    cut_seen: AtomicI64,
    acme_seen: AtomicI64,
}

/// Ce que l'on inscrit : une connexion (sans serveur) ou une session vers un serveur.
pub struct Watched<'a> {
    pub user: Uuid,
    pub login: &'a str,
    pub target: Option<&'a model::Target>,
    /// Ouverte depuis le portail : dépend aussi du portail et de son groupe.
    pub web: bool,
    /// Enregistrée : se ferme si le disque se remplit.
    pub recorded: bool,
}

/// Inscription, retirée quand elle est lâchée.
pub struct Guard {
    id: u64,
    entries: Arc<Mutex<HashMap<u64, Entry>>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.entries.lock().unwrap().remove(&self.id);
    }
}

/// Signal de fermeture d'une session, avec sa raison.
pub struct Cut(watch::Receiver<Option<String>>);

impl Cut {
    /// La raison de la fermeture ; `None` si l'inscription a été retirée sans fermeture.
    pub async fn wait(&mut self) -> Option<String> {
        loop {
            if let Some(why) = self.0.borrow_and_update().clone() {
                return Some(why);
            }
            if self.0.changed().await.is_err() {
                return None;
            }
        }
    }

    /// Raison de la fermeture si elle a déjà été demandée (sans attendre).
    pub fn closed(&self) -> Option<String> {
        self.0.borrow().clone()
    }

    /// Pour un `select!` : n'aboutit que sur une vraie fermeture.
    pub async fn reason(&mut self) -> String {
        match self.wait().await {
            Some(why) => why,
            None => std::future::pending().await,
        }
    }
}

impl Registry {
    pub fn watch(&self, w: Watched<'_>) -> (Guard, Cut) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (cut, rx) = watch::channel(None);
        let entry = Entry {
            user: w.user,
            login: w.login.to_string(),
            target: w.target.map(|t| (t.id, t.name.clone())),
            web: w.web,
            recorded: w.recorded,
            cut,
        };
        self.entries.lock().unwrap().insert(id, entry);
        (Guard { id, entries: self.entries.clone() }, Cut(rx))
    }

    /// Ferme tout ce que le compte a d'ouvert (mot de passe ou code réinitialisé).
    pub fn cut_user(&self, user: Uuid, why: &str) {
        for entry in self.entries.lock().unwrap().values().filter(|e| e.user == user) {
            entry.cut.send_replace(Some(why.to_string()));
        }
    }

    /// Un droit vient de changer : revérifie sans attendre.
    pub fn recheck(&self) {
        self.wake.notify_one();
    }
}

/// Espace libre pour le compte de service sur ce disque ; inconnu hors Unix.
pub fn free_bytes(dir: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
        let done = unsafe { libc::statvfs(path.as_ptr(), &mut stats) };
        (done == 0).then(|| stats.f_bavail as u64 * stats.f_frsize as u64)
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        None
    }
}

fn enough(free: Option<u64>, minimum: u64) -> bool {
    free.is_none_or(|f| f >= minimum)
}

/// Assez de place pour ouvrir une session enregistrée ?
pub fn can_record(state: &State) -> bool {
    enough(free_bytes(&state.config.data_dir), state.config.min_free_bytes())
}

pub fn no_space_message() -> &'static str {
    t!("Not enough disk space to record: session refused. Tell an administrator.", "Espace disque insuffisant pour enregistrer : session refusée. Prévenez un administrateur.")
}

/// Pourquoi ce compte ne peut plus garder cette session, s'il y a une raison.
async fn revoked(state: &State, user: Uuid, target: Option<Uuid>, web: bool, portal: &crate::portal::Settings) -> Result<Option<&'static str>> {
    let db = &state.db;
    if !model::user_by_id(db, user).await?.is_some_and(|u| !u.disabled) {
        return Ok(Some(t!("Your account has been disabled: connection closed.", "Votre compte a été désactivé : connexion fermée.")));
    }
    if let Some(id) = target {
        let exists = model::target_by_id(db, id).await?.is_some();
        if !exists || model::access(db, user, id).await?.is_none() {
            return Ok(Some(t!("Your access to this server has ended: session closed.", "Votre accès à ce serveur a pris fin : session fermée.")));
        }
    }
    if web && (!portal.enabled || !crate::portal::in_group(db, user, &portal.group).await?) {
        return Ok(Some(t!("Your web portal access has ended: session closed.", "Votre accès au portail web a pris fin : session fermée.")));
    }
    Ok(None)
}

async fn sweep(state: &State) -> Result<()> {
    let list: Vec<(u64, Uuid, String, Option<(Uuid, String)>, bool, bool)> = state
        .live
        .entries
        .lock()
        .unwrap()
        .iter()
        .map(|(id, e)| (*id, e.user, e.login.clone(), e.target.clone(), e.web, e.recorded))
        .collect();

    let free = free_bytes(&state.config.data_dir);
    let minimum = state.config.min_free_bytes();
    let low = !enough(free, minimum);
    if low != state.live.low_disk.swap(low, Ordering::Relaxed) {
        let event = if low { "disque.presque_plein" } else { "disque.place_retrouvee" };
        audit::note(&state.db, "systeme", event, json!({ "libre_mo": free.map(|f| f / (1024 * 1024)), "minimum_mo": minimum / (1024 * 1024) })).await;
        if low {
            tracing::error!("{}", t!("Disk almost full: recorded sessions are refused", "Disque presque plein : les sessions enregistrées sont refusées"));
        }
    }
    // Sous la moitié du minimum, les sessions enregistrées en cours s'arrêtent aussi.
    let critical = !enough(free, minimum / 2);

    if list.is_empty() {
        return Ok(());
    }
    let portal = crate::portal::settings(state).await?;
    let mut answers: HashMap<(Uuid, Option<Uuid>, bool), Option<&'static str>> = HashMap::new();
    let mut noted: HashSet<(String, Option<Uuid>)> = HashSet::new();
    for (id, user, login, target, web, recorded) in list {
        let key = (user, target.as_ref().map(|t| t.0), web);
        let why = match answers.get(&key) {
            Some(why) => *why,
            None => {
                let why = revoked(state, user, key.1, web, &portal).await?;
                answers.insert(key, why);
                why
            }
        };
        let why = why.or_else(|| (critical && recorded).then(no_space_message));
        let Some(why) = why else { continue };
        if let Some(entry) = state.live.entries.lock().unwrap().get(&id) {
            entry.cut.send_replace(Some(why.to_string()));
        }
        if noted.insert((login.clone(), target.as_ref().map(|t| t.0))) {
            audit::note(&state.db, &login, "session.coupee", json!({ "cible": target.map(|t| t.1), "raison": why })).await;
        }
    }
    Ok(())
}

/// Ordres donnés en ligne de commande, processus à part : appliqués ici, à chaque tour.
async fn console_orders(state: &Arc<State>) -> Result<()> {
    let close = model::setting(&state.db, PORTAL_CLOSE).await?.and_then(|v| v.as_i64()).unwrap_or(0) + 1;
    let seen = state.live.portal_close.swap(close, Ordering::Relaxed);
    if seen != 0 && seen != close {
        state.web.close_all();
    }
    let on = crate::assist::settings(state).await?.enabled;
    let seen = state.live.assist_on.swap(if on { 2 } else { 1 }, Ordering::Relaxed);
    if seen != 0 && (seen == 2) != on {
        if on {
            // Le programme de la personne aidée, servi par la page de téléchargement.
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::assist::fetch_agent(state).await {
                    tracing::warn!("{} {e:#}", t!("Portunia Assistance download:", "téléchargement de Portunia Assistance :"));
                }
            });
        } else {
            state.assist.close_all();
        }
    }
    // Langue choisie avec « setting language » : le serveur SSH et les journaux la suivent.
    let tag = model::setting(&state.db, "langue").await?.and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
    crate::lang::set_process(crate::lang::Lang::from_tag(&tag).unwrap_or_else(crate::lang::from_env));
    // Mot de passe ou code réinitialisé : les sessions ouvertes du compte se ferment.
    let cuts = model::setting(&state.db, model::ORDER_CUT).await?.unwrap_or(serde_json::Value::Null);
    let n = cuts["n"].as_i64().unwrap_or(0) + 1;
    let seen = state.live.cut_seen.swap(n, Ordering::Relaxed);
    if seen != 0 {
        for order in cuts["comptes"].as_array().into_iter().flatten() {
            let id = order["compte"].as_str().and_then(|s| Uuid::parse_str(s).ok());
            if let (Some(id), true) = (id, order["n"].as_i64().unwrap_or(0) + 1 > seen) {
                state.live.cut_user(id, t!("Your sign-in was reset by an administrator", "Votre connexion a été réinitialisée par un administrateur"));
            }
        }
    }
    let wake = model::setting(&state.db, ACME_WAKE).await?.and_then(|v| v.as_i64()).unwrap_or(0) + 1;
    let seen = state.live.acme_seen.swap(wake, Ordering::Relaxed);
    if seen != 0 && seen != wake {
        crate::acme::wake(true);
    }
    let https = crate::portal::https_status();
    let native = crate::rdpnative::status();
    let snapshot = json!({
        "date": chrono::Utc::now(),
        "instance": crate::portal::instance_id(),
        "tunnel": crate::tunnel::report(state).await?,
        "https": { "ouverte": https.listening, "erreur": https.error },
        "rdp_natif": { "ouverte": native.listening, "erreur": native.error },
        "acme": crate::acme::report(state).await?,
        "terminaux_web": state.web.active(),
        "assistance_en_attente": state.assist.waiting_count(),
    });
    model::set_setting(&state.db, SNAPSHOT, snapshot).await?;
    Ok(())
}

pub async fn run(state: Arc<State>) -> Result<()> {
    let mut tick = tokio::time::interval(SWEEP);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = state.live.wake.notified() => {}
        }
        if let Err(e) = console_orders(&state).await {
            tracing::error!("{} {e:#}", t!("applying console orders:", "application des ordres de la console :"));
        }
        if let Err(e) = sweep(&state).await {
            tracing::error!("{} {e:#}", t!("checking open sessions:", "vérification des sessions ouvertes :"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watched(login: &str) -> Watched<'_> {
        Watched { user: Uuid::nil(), login, target: None, web: false, recorded: false }
    }

    #[tokio::test]
    async fn fermeture_transmise() {
        let registry = Registry::default();
        let (_guard, mut cut) = registry.watch(watched("alice"));
        for e in registry.entries.lock().unwrap().values() {
            e.cut.send_replace(Some("fin".into()));
        }
        assert_eq!(cut.wait().await.as_deref(), Some("fin"));
        assert_eq!(cut.reason().await, "fin", "la raison reste lisible");
    }

    #[tokio::test]
    async fn inscription_retiree() {
        let registry = Registry::default();
        let (guard, mut cut) = registry.watch(watched("alice"));
        assert_eq!(registry.entries.lock().unwrap().len(), 1);
        drop(guard);
        assert!(registry.entries.lock().unwrap().is_empty());
        assert_eq!(cut.wait().await, None, "pas de fermeture, juste une fin");
    }

    #[test]
    fn seuil_disque() {
        assert!(enough(None, 10), "espace inconnu : pas de refus");
        assert!(enough(Some(10), 10));
        assert!(!enough(Some(9), 10));
    }
}
