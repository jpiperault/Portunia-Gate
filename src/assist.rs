//! Relais de Portunia Assist (assistance à distance).
//!
//! La personne aidée ouvre Portunia Assist, qui se connecte ici (WebSocket, adresse publique du
//! portail, sans compte) et reçoit une « place » de 3 chiffres ; son programme y ajoute 6 chiffres
//! secrets pour former le code qu'elle dicte. Le dépanneur, compte du bastion membre du groupe
//! autorisé, se connecte depuis Portunia avec la place. Le relais met les deux en relation puis
//! transmet les messages tels quels : ils sont chiffrés de bout en bout à partir du code entier,
//! que le relais ne connaît pas (voir assist-proto dans Portunia).
//!
//! Coupé par défaut ; l'administrateur l'active dans Portunia (Administrer › Assistance).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use axum::extract::ws::{Message, WebSocket};

use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::{audit, model, State};

/// Place réservée à une personne aidée qui attend son dépanneur.
struct Waiting {
    /// Le dépanneur arrive : sa WebSocket, son nom affiché et son compte.
    tx: oneshot::Sender<(WebSocket, String, String)>,
    since: Instant,
    addr: String,
}

/// Places en attente, et sessions en cours (pour les fermer d'un coup).
#[derive(Default)]
pub struct Rooms {
    waiting: Mutex<HashMap<String, Waiting>>,
    /// Coupure de toutes les sessions (relais désactivé).
    closing: Mutex<Option<tokio::sync::watch::Sender<u64>>>,
    /// Connexions récentes par adresse (anti-abus).
    recent: Mutex<HashMap<String, Vec<Instant>>>,
}

impl Rooms {
    fn closing(&self) -> tokio::sync::watch::Receiver<u64> {
        let mut c = self.closing.lock().unwrap();
        c.get_or_insert_with(|| tokio::sync::watch::channel(0).0).subscribe()
    }

    /// Ferme toutes les sessions et libère les places (relais coupé).
    pub fn close_all(&self) {
        self.waiting.lock().unwrap().clear();
        if let Some(tx) = self.closing.lock().unwrap().as_ref() {
            tx.send_modify(|n| *n += 1);
        }
    }

    pub fn waiting_count(&self) -> usize {
        self.waiting.lock().unwrap().len()
    }

    /// Au plus `max` connexions en 10 minutes depuis cette adresse.
    fn allow(&self, addr: &str, max: usize) -> bool {
        let mut recent = self.recent.lock().unwrap();
        recent.retain(|_, v| {
            v.retain(|t| t.elapsed() < Duration::from_secs(600));
            !v.is_empty()
        });
        let list = recent.entry(addr.to_string()).or_default();
        if list.len() >= max {
            return false;
        }
        list.push(Instant::now());
        true
    }
}

/// Réglages de l'assistance.
pub struct Settings {
    pub enabled: bool,
    pub group: String,
    pub hours: i64,
}

pub async fn settings(state: &State) -> Result<Settings> {
    let get = |k: &'static str| model::setting(&state.db, k);
    Ok(Settings {
        enabled: get("assistance_actif").await?.and_then(|v| v.as_bool()).unwrap_or(false),
        group: get("assistance_groupe").await?.and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_else(|| "Dépanneurs".into()),
        hours: get("assistance_duree_h").await?.and_then(|v| v.as_i64()).unwrap_or(4).clamp(1, 12),
    })
}

/// Combien de temps une place attend son dépanneur.
const WAIT: Duration = Duration::from_secs(30 * 60);

async fn send_json(socket: &mut WebSocket, v: Value) -> bool {
    socket.send(Message::Text(v.to_string().into())).await.is_ok()
}

/// Personne aidée : place, attente du dépanneur, puis relais.
pub async fn agent(state: Arc<State>, mut socket: WebSocket, addr: String) {
    let s = match settings(&state).await {
        Ok(s) if s.enabled => s,
        _ => {
            send_json(&mut socket, json!({ "type": "erreur", "message": t!("Assistance is disabled on this bastion", "L'assistance est désactivée sur ce bastion") })).await;
            return;
        }
    };
    if !state.assist.allow(&addr, 20) {
        send_json(&mut socket, json!({ "type": "erreur", "message": t!("Too many attempts: try again in a few minutes", "Trop d'essais : réessayez dans quelques minutes") })).await;
        return;
    }
    // Place libre : 3 chiffres tirés au hasard (le verrou est rendu avant toute attente).
    let reserved = {
        let mut waiting = state.assist.waiting.lock().unwrap();
        waiting.retain(|_, w| w.since.elapsed() < WAIT && !w.tx.is_closed());
        (waiting.len() < 900).then(|| {
            let place = loop {
                let p = format!("{:03}", uuid::Uuid::new_v4().as_u128() % 1000);
                if !waiting.contains_key(&p) {
                    break p;
                }
            };
            let (tx, rx) = oneshot::channel();
            waiting.insert(place.clone(), Waiting { tx, since: Instant::now(), addr: addr.clone() });
            (place, rx)
        })
    };
    let Some((place, rx)) = reserved else {
        send_json(&mut socket, json!({ "type": "erreur", "message": t!("Relay busy: try again in a few minutes", "Relais occupé : réessayez dans quelques minutes") })).await;
        return;
    };
    if !send_json(&mut socket, json!({ "type": "place", "place": place, "attente_s": WAIT.as_secs() })).await {
        state.assist.waiting.lock().unwrap().remove(&place);
        return;
    }
    // Attente du dépanneur ; la personne peut fermer le programme entre-temps.
    let paired = tokio::select! {
        r = rx => r.ok(),
        _ = tokio::time::sleep(WAIT) => None,
        _ = wait_closed(&mut socket) => None,
    };
    state.assist.waiting.lock().unwrap().remove(&place);
    let Some((helper, who, login)) = paired else { return };
    if !send_json(&mut socket, json!({ "type": "relie", "depanneur": who })).await {
        return;
    }
    relay(state, socket, helper, &login, &addr, s.hours).await;
}

/// Attend la fermeture (ou une erreur) de la WebSocket, en ignorant les messages.
async fn wait_closed(socket: &mut WebSocket) {
    while let Some(Ok(m)) = socket.recv().await {
        if matches!(m, Message::Close(_)) {
            break;
        }
    }
}

/// Dépanneur : rejoint la place demandée. `who` est le nom montré à la personne aidée.
pub async fn helper(state: Arc<State>, mut socket: WebSocket, login: String, who: String, place: String) {
    let waiting = state.assist.waiting.lock().unwrap().remove(&place);
    let Some(w) = waiting.filter(|w| w.since.elapsed() < WAIT) else {
        audit::note(&state.db, &login, "assistance.place_inconnue", json!({ "place": place })).await;
        send_json(&mut socket, json!({ "type": "erreur", "message": t!("Unknown or expired code: ask for the code again", "Code inconnu ou expiré : redemandez le code") })).await;
        return;
    };
    if !send_json(&mut socket, json!({ "type": "relie", "adresse": w.addr })).await {
        return;
    }
    audit::note(&state.db, &login, "assistance.ouverte", json!({ "place": place, "adresse": w.addr })).await;
    let _ = w.tx.send((socket, who, login));
}

/// Transmet les messages binaires dans les deux sens, jusqu'à la fin ou la durée maximale.
async fn relay(state: Arc<State>, mut agent: WebSocket, mut helper: WebSocket, login: &str, addr: &str, hours: i64) {
    let started = Instant::now();
    let mut closing = state.assist.closing();
    let mut bytes = 0u64;
    let limit = tokio::time::sleep(Duration::from_secs(hours as u64 * 3600));
    tokio::pin!(limit);
    let reason = loop {
        tokio::select! {
            m = agent.recv() => match m {
                Some(Ok(Message::Binary(b))) => {
                    bytes += b.len() as u64;
                    if helper.send(Message::Binary(b)).await.is_err() { break "depanneur"; }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break "personne aidee",
                _ => {}
            },
            m = helper.recv() => match m {
                Some(Ok(Message::Binary(b))) => {
                    bytes += b.len() as u64;
                    if agent.send(Message::Binary(b)).await.is_err() { break "personne aidee"; }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break "depanneur",
                _ => {}
            },
            _ = closing.changed() => break "relais coupe",
            _ = &mut limit => break "duree maximale",
        }
    };
    let _ = agent.send(Message::Close(None)).await;
    let _ = helper.send(Message::Close(None)).await;
    audit::note(
        &state.db,
        login,
        "assistance.fermee",
        json!({ "adresse": addr, "duree_s": started.elapsed().as_secs(), "octets": bytes, "fin": reason }),
    )
    .await;
}

/// Le dépanneur peut-il lancer une assistance ? (relais actif et membre du groupe)
pub async fn can_help(state: &State, user: uuid::Uuid) -> Result<bool> {
    let s = settings(state).await?;
    Ok(s.enabled && crate::portal::in_group(&state.db, user, &s.group).await?)
}

// ---------- Programme de la personne aidée ----------

/// Où le bastion garde Portunia Assist (servi par la page de téléchargement).
pub fn agent_file(state: &State) -> std::path::PathBuf {
    state.config.data_dir.join("assist").join("portunia-assist.exe")
}

const RELEASES: &str = "https://github.com/jpiperault/Portunia-releases/releases/latest/download";

/// Télécharge la dernière version de Portunia Assist (et vérifie son empreinte SHA-256 publiée).
pub async fn fetch_agent(state: Arc<State>) -> Result<()> {
    let dest = agent_file(&state);
    let (exe, sums) = tokio::task::spawn_blocking(|| -> Result<(Vec<u8>, String)> {
        let get = |name: &str| -> Result<Vec<u8>> {
            let resp = ureq::get(&format!("{RELEASES}/{name}")).timeout(Duration::from_secs(120)).call()?;
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut std::io::Read::take(resp.into_reader(), 64 * 1024 * 1024), &mut out)?;
            Ok(out)
        };
        Ok((get("portunia-assist.exe")?, String::from_utf8_lossy(&get("portunia-assist.exe.sha256")?).into_owned()))
    })
    .await??;
    let expected = sums.split_whitespace().next().unwrap_or_default().to_lowercase();
    let actual = crate::keys::sha256_hex(&exe);
    anyhow::ensure!(expected == actual, "empreinte de portunia-assist.exe différente de celle publiée");
    std::fs::create_dir_all(dest.parent().unwrap())?;
    let tmp = dest.with_extension("tmp");
    std::fs::write(&tmp, &exe)?;
    std::fs::rename(&tmp, &dest)?;
    audit::note(&state.db, "systeme", "assistance.programme", json!({ "sha256": actual, "octets": exe.len() })).await;
    Ok(())
}
