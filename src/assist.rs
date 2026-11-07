//! Relais de Portunia Assist (assistance à distance).
//!
//! La personne aidée ouvre Portunia Assist, qui se connecte ici (WebSocket, adresse publique du
//! portail, sans compte) et reçoit une « place » de 3 chiffres ; son programme y ajoute 6 chiffres
//! secrets pour former le code qu'elle dicte. Le dépanneur, compte de la Gate membre du groupe
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

/// Le dépanneur qui rejoint une place : sa WebSocket, son nom affiché, son compte, son jeton de reprise.
struct Helper {
    socket: WebSocket,
    who: String,
    login: String,
    user: uuid::Uuid,
    token: String,
}

/// Place réservée à une personne aidée qui attend son dépanneur.
struct Waiting {
    /// Le dépanneur arrive.
    tx: oneshot::Sender<Helper>,
    since: Instant,
    addr: String,
}

/// Places en attente, et sessions en cours (pour les fermer d'un coup).
#[derive(Default)]
pub struct Rooms {
    waiting: Mutex<HashMap<String, Waiting>>,
    /// Sessions coupées par le réseau, en attente du retour des deux côtés.
    parked: Mutex<Vec<Parked>>,
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
        self.parked.lock().unwrap().clear();
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

/// Places en attente au plus pour une même adresse : quelques adresses ne bloquent pas le relais.
const MAX_WAITING_PER_ADDRESS: usize = 3;

/// Combien de temps une place attend son dépanneur.
const WAIT: Duration = Duration::from_secs(30 * 60);

/// Combien de temps une session coupée par le réseau attend le retour des deux côtés.
const RESUME_FOR: Duration = Duration::from_secs(120);

async fn send_json(socket: &mut WebSocket, v: Value) -> bool {
    socket.send(Message::Text(v.to_string().into())).await.is_ok()
}

/// Personne aidée : place, attente du dépanneur, puis relais. Avec `resume`, elle revient après
/// une coupure du réseau (jeton de reprise reçu à la mise en relation).
pub async fn agent(state: Arc<State>, mut socket: WebSocket, addr: String, resume: Option<String>) {
    if let Some(token) = resume {
        rejoin(state, socket, &token, None).await;
        return;
    }
    let s = match settings(&state).await {
        Ok(s) if s.enabled => s,
        _ => {
            send_json(&mut socket, json!({ "type": "erreur", "message": t!("Assistance is disabled on this Gate", "L'assistance est désactivée sur cette Gate") })).await;
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
        let mine = crate::limits::address_key(&addr);
        let held = waiting.values().filter(|w| crate::limits::address_key(&w.addr) == mine).count();
        (waiting.len() < 900 && held < MAX_WAITING_PER_ADDRESS).then(|| {
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
    let Some(helper) = paired else { return };
    let agent_token = uuid::Uuid::new_v4().simple().to_string();
    if !send_json(&mut socket, json!({ "type": "relie", "depanneur": helper.who, "reprise": agent_token })).await {
        return;
    }
    let session = Session {
        agent_token,
        helper_token: helper.token,
        user: helper.user,
        login: helper.login,
        addr,
        hours: s.hours,
        started: Instant::now(),
        bytes: 0,
    };
    run(state, session, socket, helper.socket).await;
}

/// Attend la fermeture (ou une erreur) de la WebSocket, en ignorant les messages.
async fn wait_closed(socket: &mut WebSocket) {
    while let Some(Ok(m)) = socket.recv().await {
        if matches!(m, Message::Close(_)) {
            break;
        }
    }
}

/// Dépanneur : rejoint la place demandée. `who` est le nom montré à la personne aidée. Avec
/// `resume`, il revient après une coupure du réseau.
pub async fn helper(state: Arc<State>, mut socket: WebSocket, login: String, user: uuid::Uuid, who: String, place: String, resume: Option<String>) {
    if let Some(token) = resume {
        rejoin(state, socket, &token, Some(user)).await;
        return;
    }
    let waiting = state.assist.waiting.lock().unwrap().remove(&place);
    let Some(w) = waiting.filter(|w| w.since.elapsed() < WAIT) else {
        audit::note(&state.db, &login, "assistance.place_inconnue", json!({ "place": place })).await;
        send_json(&mut socket, json!({ "type": "erreur", "message": t!("Unknown or expired code: ask for the code again", "Code inconnu ou expiré : redemandez le code") })).await;
        return;
    };
    let token = uuid::Uuid::new_v4().simple().to_string();
    if !send_json(&mut socket, json!({ "type": "relie", "adresse": w.addr, "reprise": token })).await {
        return;
    }
    audit::note(&state.db, &login, "assistance.ouverte", json!({ "place": place, "adresse": w.addr })).await;
    let _ = w.tx.send(Helper { socket, who, login, user, token });
}

/// Une assistance en cours : les deux côtés, et de quoi la reprendre après une coupure.
struct Session {
    agent_token: String,
    helper_token: String,
    user: uuid::Uuid,
    login: String,
    addr: String,
    hours: i64,
    started: Instant,
    bytes: u64,
}

/// Session coupée qui attend le retour des deux côtés.
struct Parked {
    session: Session,
    since: Instant,
    agent: Option<WebSocket>,
    helper: Option<WebSocket>,
}

/// Relaie la session ; après une coupure du réseau, la met de côté le temps que les deux
/// reviennent (jetons de reprise), sinon la note comme fermée.
async fn run(state: Arc<State>, mut session: Session, agent: WebSocket, helper: WebSocket) {
    match relay(&state, &mut session, agent, helper).await {
        End::Done(reason) => closed(&state, &session, reason).await,
        End::Lost => {
            audit::note(&state.db, &session.login, "assistance.coupure", json!({ "adresse": session.addr })).await;
            let agent_token = session.agent_token.clone();
            state.assist.parked.lock().unwrap().push(Parked { session, since: Instant::now(), agent: None, helper: None });
            // Personne n'est revenu à temps : fermée.
            let st = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(RESUME_FOR).await;
                let gone = {
                    let mut parked = st.assist.parked.lock().unwrap();
                    parked.iter().position(|p| p.session.agent_token == agent_token).map(|i| parked.remove(i))
                };
                if let Some(p) = gone {
                    closed(&st, &p.session, "coupure").await;
                }
            });
        }
    }
}

/// Retour d'un côté après une coupure : quand l'autre est là aussi, la session reprend.
async fn rejoin(state: Arc<State>, socket: WebSocket, token: &str, helper_user: Option<uuid::Uuid>) {
    let mut socket = Some(socket);
    let ready = {
        let mut parked = state.assist.parked.lock().unwrap();
        parked.retain(|p| p.since.elapsed() < RESUME_FOR);
        let found = parked.iter().position(|p| match helper_user {
            Some(u) => p.session.helper_token == token && p.session.user == u,
            None => p.session.agent_token == token,
        });
        match found {
            None => None,
            Some(i) => {
                let p = &mut parked[i];
                if helper_user.is_some() {
                    p.helper = socket.take();
                } else {
                    p.agent = socket.take();
                }
                if p.agent.is_some() && p.helper.is_some() {
                    Some(Ok(parked.remove(i)))
                } else {
                    Some(Err(()))
                }
            }
        }
    };
    match ready {
        None => {
            let Some(mut socket) = socket else { return };
            send_json(&mut socket, json!({ "type": "erreur", "message": t!("The assistance can no longer resume: start a new one", "L'assistance ne peut plus reprendre : recommencez-en une") })).await;
        }
        // L'autre côté n'est pas encore revenu : sa WebSocket attend dans la session mise de côté.
        Some(Err(())) => {}
        Some(Ok(p)) => {
            let (Some(mut agent), Some(mut helper)) = (p.agent, p.helper) else { return };
            if !send_json(&mut agent, json!({ "type": "repris" })).await || !send_json(&mut helper, json!({ "type": "repris" })).await {
                closed(&state, &p.session, "coupure").await;
                return;
            }
            audit::note(&state.db, &p.session.login, "assistance.reprise", json!({ "adresse": p.session.addr, "coupure_s": p.since.elapsed().as_secs() })).await;
            Box::pin(run(state, p.session, agent, helper)).await;
        }
    }
}

enum End {
    /// Fin voulue (ou durée maximale, relais coupé…), avec la raison notée au journal.
    Done(&'static str),
    /// Réseau coupé d'un côté : reprise possible.
    Lost,
}

/// Transmet les messages dans les deux sens (binaires : le flux chiffré ; texte : la reprise),
/// jusqu'à la fin ou la durée maximale. Après une coupure, l'autre côté n'est pas fermé
/// proprement : il voit la coupure et revient avec son jeton.
async fn relay(state: &State, session: &mut Session, mut agent: WebSocket, mut helper: WebSocket) -> End {
    // Compte du dépanneur désactivé : la session se ferme.
    let (_watch, mut cut) = state.live.watch(crate::live::Watched { user: session.user, login: &session.login, target: None, web: false, recorded: false, session: None });
    let mut closing = state.assist.closing();
    let left = Duration::from_secs(session.hours as u64 * 3600).saturating_sub(session.started.elapsed());
    let limit = tokio::time::sleep(left);
    tokio::pin!(limit);
    let reason = loop {
        tokio::select! {
            m = agent.recv() => match m {
                Some(Ok(m @ (Message::Binary(_) | Message::Text(_)))) => {
                    session.bytes += match &m { Message::Binary(b) => b.len(), Message::Text(t) => t.len(), _ => 0 } as u64;
                    if helper.send(m).await.is_err() { return End::Lost; }
                }
                Some(Ok(Message::Close(_))) => break "personne aidee",
                None | Some(Err(_)) => return End::Lost,
                _ => {}
            },
            m = helper.recv() => match m {
                Some(Ok(m @ (Message::Binary(_) | Message::Text(_)))) => {
                    session.bytes += match &m { Message::Binary(b) => b.len(), Message::Text(t) => t.len(), _ => 0 } as u64;
                    if agent.send(m).await.is_err() { return End::Lost; }
                }
                Some(Ok(Message::Close(_))) => break "depanneur",
                None | Some(Err(_)) => return End::Lost,
                _ => {}
            },
            _ = closing.changed() => break "relais coupe",
            _ = cut.reason() => break "compte desactive",
            _ = &mut limit => break "duree maximale",
        }
    };
    let _ = agent.send(Message::Close(None)).await;
    let _ = helper.send(Message::Close(None)).await;
    End::Done(reason)
}

async fn closed(state: &State, session: &Session, reason: &str) {
    audit::note(
        &state.db,
        &session.login,
        "assistance.fermee",
        json!({ "adresse": session.addr, "duree_s": session.started.elapsed().as_secs(), "octets": session.bytes, "fin": reason }),
    )
    .await;
}

/// Le dépanneur peut-il lancer une assistance ? (relais actif et membre du groupe)
pub async fn can_help(state: &State, user: uuid::Uuid) -> Result<bool> {
    let s = settings(state).await?;
    Ok(s.enabled && crate::portal::in_group(&state.db, user, &s.group).await?)
}

// ---------- Programme de la personne aidée ----------

/// Où la Gate garde Portunia Assist (servi par la page de téléchargement).
pub fn agent_file(state: &State) -> std::path::PathBuf {
    state.config.data_dir.join("assist").join("portunia-assistance.exe")
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
        Ok((get("portunia-assistance.exe")?, String::from_utf8_lossy(&get("portunia-assistance.exe.sha256")?).into_owned()))
    })
    .await??;
    let expected = sums.split_whitespace().next().unwrap_or_default().to_lowercase();
    let actual = crate::keys::sha256_hex(&exe);
    anyhow::ensure!(expected == actual, "empreinte de portunia-assistance.exe différente de celle publiée");
    std::fs::create_dir_all(dest.parent().unwrap())?;
    let tmp = dest.with_extension("tmp");
    std::fs::write(&tmp, &exe)?;
    std::fs::rename(&tmp, &dest)?;
    audit::note(&state.db, "systeme", "assistance.programme", json!({ "sha256": actual, "octets": exe.len() })).await;
    Ok(())
}
