//! Entrée RDP native (port 3390 par défaut, fermée tant que l'administrateur ne l'ouvre pas) :
//! mstsc, Remmina, FreeRDP ou Windows App se connectent à la Gate avec un fichier .rdp à
//! usage unique préparé par Portunia. Le jeton voyage dans « loadbalanceinfo », que ces
//! clients envoient dès la première trame (demande X.224), avant tout chiffrement : la Gate
//! sait alors qui se connecte et vers quel serveur.
//!
//! - Rebond : la Gate retire le jeton puis laisse passer la connexion telle quelle (chiffrement
//!   et authentification Windows de bout en bout, rien n'est enregistré).
//! - Coffre : la Gate ouvre la session Windows (NLA) avec le compte du coffre.
//! - Enregistré : pareil, avec les identifiants Windows que l'utilisateur a donnés à Portunia
//!   en préparant le fichier (gardés en mémoire le temps du jeton, jamais sur disque) ; sans
//!   identifiants, seulement si le serveur accepte une connexion sans NLA (l'utilisateur les
//!   tape alors dans l'écran de connexion de Windows).
//!
//! Sans fichier .rdp (Gate 0.34) : l'utilisateur tape « compte%serveur » (ou
//! « compte%serveur%code ») et son mot de passe RDP ; la Gate vérifie le tout par NLA
//! (voir rdplogin.rs), puis continue comme en coffre ou en enregistré.
//!
//! Dans ces deux derniers modes, le poste négocie avec la Gate un TLS simple, sans NLA, avec le
//! certificat de l'API. Sa première trame (MCS Connect Initial) annonce le protocole qu'il croit
//! négocié : la Gate y met celui choisi avec le serveur, sinon Windows coupe. Ensuite elle
//! relaie et enregistre exactement comme le passage RDCleanPath.

use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, LazyLock, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Result};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use serde_json::json;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use uuid::Uuid;

use crate::{
    audit,
    auth::{self, Factor},
    keys::sha256_hex,
    model,
    rdp::{self, Allowed, ClientRx, ClientTx, Origin, HYBRID, HYBRID_EX, SSL},
    rdplogin,
    State,
};

/// Début de « loadbalanceinfo » dans les fichiers .rdp de Portunia.
pub const TOKEN_PREFIX: &str = "portunia-gate:";

pub const MODES: [&str; 3] = ["rebond", "coffre", "enregistre"];

/// Réglages de l'entrée native (Portunia › Administrer › RDP natif, ou `portunia-gate rdp`).
pub struct Settings {
    pub enabled: bool,
    pub port: u16,
    /// Adresse publique écrite dans les fichiers .rdp (« hôte » ou « hôte:port ») ; vide :
    /// l'adresse de la Gate que connaît Portunia, avec `port`.
    pub address: String,
    /// Modes de serveur accessibles par cette entrée.
    pub modes: Vec<String>,
    /// Validité du fichier .rdp (jeton à usage unique), en secondes.
    pub ticket_s: i64,
}

impl Settings {
    pub fn allows(&self, mode: &str) -> bool {
        self.modes.iter().any(|m| m == mode)
    }
}

pub async fn settings(state: &State) -> Result<Settings> {
    let get = |k: &'static str| model::setting(&state.db, k);
    let modes = match get("rdp_natif_modes").await? {
        Some(v) => v.as_array().map(|l| l.iter().filter_map(|m| m.as_str()).filter(|m| MODES.contains(m)).map(str::to_owned).collect()).unwrap_or_default(),
        None => MODES.iter().map(|m| m.to_string()).collect(),
    };
    Ok(Settings {
        enabled: get("rdp_natif_actif").await?.and_then(|v| v.as_bool()).unwrap_or(false),
        port: get("rdp_natif_port").await?.and_then(|v| v.as_u64()).and_then(|p| u16::try_from(p).ok()).filter(|&p| p > 0).unwrap_or(3390),
        address: get("rdp_natif_adresse").await?.and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default(),
        modes,
        ticket_s: get("rdp_natif_jeton_s").await?.and_then(|v| v.as_i64()).unwrap_or(120).clamp(30, 600),
    })
}

/// Adresse publique valable : « hôte » ou « hôte:port », sans schéma ni chemin.
pub fn check_address(address: &str) -> Result<()> {
    let a = address.trim();
    if a.is_empty() {
        return Ok(());
    }
    let (host, port) = match a.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, Some(p)),
        _ => (a, None),
    };
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '[' | ']' | ':')) || port.is_some_and(|p| p.parse::<u16>().map_or(true, |p| p == 0)) {
        bail!(t!(format!("invalid address: {a} (host or host:port)"), format!("adresse invalide : {a} (hôte ou hôte:port)")));
    }
    Ok(())
}

// ---------- Identifiants Windows du mode enregistré ----------

/// Identifiants donnés à Portunia pour un jeton, gardés en mémoire jusqu'à son usage ou son
/// expiration ; clé : empreinte du jeton.
static CREDENTIALS: LazyLock<Mutex<HashMap<String, (String, String, Instant)>>> = LazyLock::new(Default::default);

pub fn keep_credentials(ticket: &str, account: String, password: String, ttl: Duration) {
    let mut map = CREDENTIALS.lock().unwrap_or_else(|e| e.into_inner());
    map.retain(|_, (_, _, until)| *until > Instant::now());
    map.insert(sha256_hex(ticket.as_bytes()), (account, password, Instant::now() + ttl));
}

fn take_credentials(ticket: &str) -> Option<(String, String)> {
    let mut map = CREDENTIALS.lock().unwrap_or_else(|e| e.into_inner());
    map.remove(&sha256_hex(ticket.as_bytes())).filter(|(_, _, until)| *until > Instant::now()).map(|(a, p, _)| (a, p))
}

// ---------- Écoute ----------

#[derive(Clone, Default)]
pub struct Status {
    /// Adresse ouverte en ce moment.
    pub listening: Option<String>,
    pub error: Option<String>,
}

static STATUS: Mutex<Status> = Mutex::new(Status { listening: None, error: None });

pub fn status() -> Status {
    STATUS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn set_status(listening: Option<String>, error: Option<String>) {
    *STATUS.lock().unwrap_or_else(|e| e.into_inner()) = Status { listening, error };
}

/// Connexions pas encore authentifiées (jeton pas encore lu) au plus : quelques curieux ne
/// bloquent pas l'entrée.
const PENDING_MAX: usize = 64;

/// Adresse d'écoute : `PORTUNIA_GATE_RDP_BIND` (0.0.0.0 par défaut) et le port réglé.
fn bind_address(port: u16) -> String {
    let ip = std::env::var("PORTUNIA_GATE_RDP_BIND").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| "0.0.0.0".into());
    if ip.contains(':') && !ip.starts_with('[') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

/// Garde l'écoute conforme au réglage : ouverte, déplacée ou fermée sans redémarrer la Gate.
pub async fn run(state: Arc<State>) -> Result<()> {
    let mut running: Option<(String, tokio::task::JoinHandle<()>)> = None;
    let mut failed: Option<(String, Instant)> = None;
    let pending = Arc::new(Semaphore::new(PENDING_MAX));
    loop {
        let wanted = match settings(&state).await {
            Ok(s) => s.enabled.then(|| bind_address(s.port)),
            Err(_) => running.as_ref().map(|r| r.0.clone()),
        };
        let current = running.as_ref().map(|r| r.0.clone());
        if wanted != current {
            if let Some((old, task)) = running.take() {
                task.abort();
                tracing::info!("{} {old}", t!("native RDP no longer listening on", "RDP natif plus en écoute sur"));
                set_status(None, None);
            }
            if let Some(addr) = wanted {
                let retry = failed.as_ref().is_none_or(|(a, at)| *a != addr || at.elapsed() >= Duration::from_secs(60));
                if retry {
                    match TcpListener::bind(&addr).await {
                        Ok(listener) => {
                            tracing::info!("{} {addr}", t!("native RDP listening on", "RDP natif en écoute sur"));
                            set_status(Some(addr.clone()), None);
                            failed = None;
                            let (state, pending) = (state.clone(), pending.clone());
                            running = Some((addr, tokio::spawn(accept(state, listener, pending))));
                        }
                        Err(e) => {
                            let text = match e.kind() {
                                std::io::ErrorKind::AddrInUse => t!(format!("{addr} already used on this server"), format!("{addr} déjà utilisé sur ce serveur")).to_string(),
                                std::io::ErrorKind::PermissionDenied => t!(format!("{addr}: port reserved to the system, take one from 1024"), format!("{addr} : port réservé au système, prenez-en un à partir de 1024")).to_string(),
                                _ => format!("{addr} : {e}"),
                            };
                            tracing::error!("{} {text}", t!("native RDP:", "RDP natif :"));
                            set_status(None, Some(text));
                            failed = Some((addr, Instant::now()));
                        }
                    }
                }
            } else {
                failed = None;
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn accept(state: Arc<State>, listener: TcpListener, pending: Arc<Semaphore>) {
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let Ok(permit) = pending.clone().try_acquire_owned() else {
            drop(tcp);
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            if let Err(e) = handle(&state, tcp, peer, permit).await {
                tracing::warn!("{} {peer}: {e:#}", t!("native RDP", "RDP natif"));
            }
        });
    }
}

// ---------- Demande X.224 du poste ----------

/// Demande X.224 du poste : jeton et protocoles demandés (bloc RDP_NEG_REQ, s'il y en a un).
#[derive(Debug, PartialEq)]
struct Request {
    token: Option<String>,
    neg: Option<[u8; 8]>,
}

impl Request {
    fn protocols(&self) -> u32 {
        self.neg.map_or(0, |n| u32::from_le_bytes([n[4], n[5], n[6], n[7]]))
    }
}

/// TPKT (4 octets), X.224 CR (7), puis une ligne terminée par CRLF (« loadbalanceinfo » ou
/// « Cookie: mstshash=… »), puis RDP_NEG_REQ (8 octets) et d'éventuels blocs suivants.
fn parse_request(cr: &[u8]) -> Result<Request> {
    if cr.len() < 11 || cr[5] != 0xE0 {
        bail!(t!("not an RDP connection request", "pas une demande de connexion RDP"));
    }
    let mut rest = &cr[11..];
    let mut token = None;
    if !rest.is_empty() && rest[0] != 0x01 {
        let Some(end) = rest.windows(2).position(|w| w == b"\r\n") else { bail!(t!("RDP request without end of line", "demande RDP sans fin de ligne")) };
        let line = String::from_utf8_lossy(&rest[..end]);
        token = line.strip_prefix(TOKEN_PREFIX).map(str::to_owned);
        rest = &rest[end + 2..];
    }
    let neg = (rest.len() >= 8 && rest[0] == 0x01).then(|| rest[..8].try_into().unwrap());
    Ok(Request { token, neg })
}

/// Demande X.224 envoyée au serveur : sans jeton, avec ces protocoles (ou ceux du poste).
fn build_request(neg: Option<[u8; 8]>) -> Vec<u8> {
    let mut x224 = vec![0xE0, 0, 0, 0, 0, 0];
    if let Some(n) = neg {
        x224.extend_from_slice(&n);
    }
    let mut out = vec![3, 0, 0, 0, x224.len() as u8];
    out.extend_from_slice(&x224);
    let len = out.len() as u16;
    out[2..4].copy_from_slice(&len.to_be_bytes());
    out
}

fn neg_request(protocols: u32) -> [u8; 8] {
    let p = protocols.to_le_bytes();
    [0x01, 0, 8, 0, p[0], p[1], p[2], p[3]]
}

/// Réponse X.224 du serveur, reprise pour le poste avec ce protocole choisi.
fn client_answer(server_x224: &[u8], protocol: u32) -> Option<Vec<u8>> {
    if rdp::selected_protocol(server_x224).is_none() {
        return None;
    }
    let mut out = server_x224[..19].to_vec();
    out[15..19].copy_from_slice(&protocol.to_le_bytes());
    out[2..4].copy_from_slice(&19u16.to_be_bytes());
    out[4] = 14;
    Some(out)
}

/// Première trame du poste (MCS Connect Initial) : le protocole qu'il croit négocié devient
/// celui choisi avec le serveur. Bloc CS_CORE (type 0xC001, version 0x0008000x), champ
/// serverSelectedProtocol à l'octet 212. false : bloc absent ou trop court (client ancien).
///
/// Le pipeline graphique RDP 8 (RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL, 0x0100 dans
/// earlyCapabilityFlags, octet 144) est retiré : la session étant enregistrée, Windows doit
/// envoyer l'image en mises à jour classiques, que la relecture sait décoder (l'image par le
/// canal dynamique « Microsoft::Windows::RDS::Graphics » donnait un écran noir à la relecture).
fn patch_selected_protocol(pdu: &mut [u8], protocol: u32) -> bool {
    let mut i = 0;
    while i + 8 <= pdu.len() {
        if pdu[i] == 0x01 && pdu[i + 1] == 0xC0 && pdu[i + 5] == 0x00 && pdu[i + 6] == 0x08 && pdu[i + 7] == 0x00 {
            let len = u16::from_le_bytes([pdu[i + 2], pdu[i + 3]]) as usize;
            if len >= 216 && i + len <= pdu.len() {
                pdu[i + 212..i + 216].copy_from_slice(&protocol.to_le_bytes());
                pdu[i + 145] &= !0x01;
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Certificat présenté aux postes : celui de l'API (relu à chaque connexion : il peut changer).
fn tls_acceptor(state: &State) -> Result<tokio_rustls::TlsAcceptor> {
    let files = crate::tls::files(&state.config.data_dir);
    let chain = std::fs::read(&files.cert)?;
    let key = std::fs::read(&files.key)?;
    let certs = CertificateDer::pem_slice_iter(&chain).collect::<std::result::Result<Vec<_>, _>>().map_err(|e| anyhow!("{e}"))?;
    let key = PrivateKeyDer::from_pem_slice(&key).map_err(|e| anyhow!("{e}"))?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

// ---------- Une connexion ----------

async fn handle(state: &Arc<State>, mut tcp: TcpStream, peer: SocketAddr, permit: tokio::sync::OwnedSemaphorePermit) -> Result<()> {
    let db = &state.db;
    let cr = tokio::time::timeout(Duration::from_secs(15), rdp::read_tpkt(&mut tcp, 1024))
        .await
        .map_err(|_| anyhow!(t!("no RDP request", "pas de demande RDP")))??;
    let request = parse_request(&cr)?;
    let Some(token) = request.token.clone() else {
        return login_entry(state, tcp, peer, permit, &request).await;
    };
    let s = settings(state).await?;
    let addr = format!("{} (natif)", peer.ip());
    let credentials = take_credentials(&token);
    let a = rdp::authorize(db, &token, crate::api::Usage::RdpNative, addr, None, |t| s.allows(&t.mode)).await.map_err(|(_, e)| e)?;
    drop(permit);
    rdp::check_space(state, &a).await.map_err(|(_, e)| e)?;
    if a.target.mode == "rebond" {
        return jump(state, a, tcp, &request).await;
    }

    // La Gate au milieu : elle négocie avec le serveur, puis avec le poste.
    if request.protocols() & SSL == 0 {
        audit::note(db, &a.user.login, "acces.refuse", json!({ "cible": a.target.name, "type": "rdp natif", "raison": "client sans TLS", "adresse": a.addr })).await;
        bail!(t!("the RDP client does not offer TLS", "le client RDP ne propose pas TLS"));
    }
    // Sans identifiants (mode enregistré), seulement un serveur qui accepte TLS sans NLA.
    let account = match (a.target.vaulted(), credentials) {
        (true, _) => Some(rdp::vault_account(state, &a).await.map_err(|(_, e)| e)?),
        (false, c) => c,
    };
    let wanted = if account.is_some() { SSL | HYBRID | HYBRID_EX } else { SSL };
    let mut o = match rdp::open_server(db, &a, &build_request(Some(neg_request(wanted)))).await {
        Ok(o) => o,
        Err((_, e)) => {
            // Mode enregistré sans identifiants : le serveur exige sans doute NLA.
            let hint = if account.is_none() { " (identifiants Windows à donner dans Portunia)" } else { "" };
            audit::note(db, &a.user.login, "acces.refuse", json!({ "cible": a.target.name, "type": "rdp natif", "raison": format!("{e:#}{hint}"), "adresse": a.addr })).await;
            return Err(e);
        }
    };
    if let Some((account, password)) = account {
        if o.nla() || a.target.vaulted() {
            rdp::gate_login(db, &a, &mut o, &account, password).await.map_err(|(_, e)| e)?;
        }
    }
    let protocol = o.protocol();
    let answer = client_answer(&o.x224, SSL).ok_or_else(|| anyhow!(t!("unexpected server answer", "réponse du serveur inattendue")))?;
    tcp.write_all(&answer).await?;
    let mut client = tokio::time::timeout(Duration::from_secs(15), tls_acceptor(state)?.accept(tcp))
        .await
        .map_err(|_| anyhow!(t!("the RDP client did not finish TLS", "le client RDP n'a pas fini la négociation TLS")))??;
    let mut first = tokio::time::timeout(Duration::from_secs(30), rdp::read_tpkt(&mut client, 64 * 1024))
        .await
        .map_err(|_| anyhow!(t!("the RDP client no longer answers", "le client RDP ne répond plus")))??;
    if !patch_selected_protocol(&mut first, protocol) {
        tracing::warn!("{}", t!("native RDP: client data without the negotiated protocol (old client?)", "RDP natif : données du client sans le protocole négocié (client ancien ?)"));
    }
    let id = Uuid::new_v4();
    let capture = rdp::start_recording(state, id, &a).await.map_err(|(_, e)| e)?;
    let (rx, tx) = tokio::io::split(&mut client);
    rdp::relay_session(state, id, &a, &Origin::Native, capture, o.tls, ClientRx::Native(rx), ClientTx::Native(tx), first).await
}

// ---------- Sans Portunia : « compte%serveur » et mot de passe RDP ----------

/// Qui se connecte et vers quoi, trouvé pendant l'authentification NLA.
struct Found {
    user: model::User,
    target: model::Target,
    access: model::Access,
    /// Pas du code à usage unique, consommé une fois le mot de passe vérifié.
    totp_step: Option<i64>,
}

/// Réponse X.224 de la Gate elle-même, avec ce protocole choisi.
fn confirm(protocol: u32) -> Vec<u8> {
    let mut out = vec![3, 0, 0, 19, 14, 0xD0, 0, 0, 0x12, 0x34, 0, 0x02, 0x03, 8, 0];
    out.extend_from_slice(&protocol.to_le_bytes());
    out
}

/// Clé publique du certificat présenté aux postes (liée à l'authentification NLA).
fn gate_public_key(state: &State) -> Result<Vec<u8>> {
    let files = crate::tls::files(&state.config.data_dir);
    let chain = std::fs::read(&files.cert)?;
    let leaf = CertificateDer::pem_slice_iter(&chain).next().ok_or_else(|| anyhow!(t!("empty API certificate", "certificat de l'API vide")))?.map_err(|e| anyhow!("{e}"))?;
    rdp::public_key(&leaf)
}

/// Compte, code et serveur tapés dans le client ; le mot de passe RDP attendu si tout va.
async fn resolve(state: &State, account: &str, ip: &str, s: &Settings) -> Option<(Found, String)> {
    let db = &state.db;
    let refuse = |login: String, target: String, why: &'static str| async move {
        audit::note(db, &login, "acces.refuse", json!({ "cible": target, "type": "rdp natif", "raison": why, "adresse": format!("{ip} (natif)") })).await;
    };
    let Some(c) = rdplogin::parse_combo(account) else {
        refuse(account.chars().take(64).collect(), String::new(), "identifiant sans « %serveur »").await;
        return None;
    };
    if let crate::limits::Verdict::Blocked { first } = state.limits.attempt(&c.login, ip) {
        if first {
            refuse(c.login.clone(), c.target.clone(), "trop d'essais").await;
        }
        return None;
    }
    let Some(user) = model::user_by_login(db, &c.login).await.ok().flatten().filter(|u| !u.disabled) else {
        refuse(c.login.clone(), c.target.clone(), "compte inconnu ou désactivé").await;
        return None;
    };
    let Some((sealed, _)) = model::rdp_password(db, user.id).await.ok().flatten() else {
        refuse(c.login.clone(), c.target.clone(), "pas de mot de passe RDP").await;
        return None;
    };
    let password = state.keys.open(&format!("rdp:{}", user.id), &sealed).ok().and_then(|p| String::from_utf8(p).ok())?;
    // Code à usage unique : exigé sauf si la politique du compte se contente d'un mot de passe.
    let needs_code = !user.policy(db).await.ok()?.satisfied(&BTreeSet::from([Factor::Password]));
    let totp_step = match (&c.code, &user.totp_secret) {
        (Some(code), Some(secret)) => {
            let secret = state.keys.open(&format!("totp:{}", user.id), secret).ok()?;
            let Some(step) = auth::totp_check(&secret, code, user.totp_last_step) else {
                refuse(c.login.clone(), c.target.clone(), "code faux").await;
                return None;
            };
            Some(step)
        }
        (Some(_), None) => {
            refuse(c.login.clone(), c.target.clone(), "code donné, mais aucun code enrôlé").await;
            return None;
        }
        (None, _) if needs_code => {
            refuse(c.login.clone(), c.target.clone(), "code manquant (compte%serveur%code)").await;
            return None;
        }
        (None, _) => None,
    };
    // Serveur : par son nom, sinon par son adresse, parmi ceux autorisés en ce moment.
    let targets = model::allowed_targets(db, user.id).await.ok()?;
    let target = targets.iter().find(|t| t.name.eq_ignore_ascii_case(&c.target)).or_else(|| targets.iter().find(|t| t.host.eq_ignore_ascii_case(&c.target))).cloned();
    let Some(target) = target.filter(|t| t.is_rdp()) else {
        refuse(c.login.clone(), c.target.clone(), "serveur Windows inconnu ou non autorisé").await;
        return None;
    };
    // Rebond : chiffrement de bout en bout, impossible une fois la Gate authentifiée à la place du serveur.
    if target.mode == "rebond" || !s.allows(&target.mode) {
        refuse(c.login.clone(), target.name.clone(), "mode non ouvert à cette entrée (rebond : fichier .rdp de Portunia)").await;
        return None;
    }
    let access = model::access(db, user.id, target.id).await.ok().flatten()?;
    Some((Found { user, target, access, totp_step }, password))
}

/// Première trame du poste, peut-être déjà en partie lue avec la fin de l'authentification.
async fn read_first(client: &mut (impl AsyncRead + Unpin), leftover: Vec<u8>) -> Result<Vec<u8>> {
    let mut chained = std::io::Cursor::new(leftover).chain(&mut *client);
    let pdu = tokio::time::timeout(Duration::from_secs(30), rdp::read_tpkt(&mut chained, 64 * 1024))
        .await
        .map_err(|_| anyhow!(t!("the RDP client no longer answers", "le client RDP ne répond plus")))??;
    let (cursor, _) = chained.into_inner();
    if (cursor.position() as usize) < cursor.get_ref().len() {
        bail!(t!("unexpected data from the RDP client", "données inattendues du client RDP"));
    }
    Ok(pdu)
}

/// Connexion sans fichier .rdp : la Gate négocie TLS et NLA avec le poste en son nom, puis
/// ouvre le serveur comme en coffre (compte du coffre) ou en enregistré (sans NLA vers le
/// serveur : l'utilisateur ouvre sa session Windows dans l'écran de connexion).
async fn login_entry(state: &Arc<State>, mut tcp: TcpStream, peer: SocketAddr, permit: tokio::sync::OwnedSemaphorePermit, request: &Request) -> Result<()> {
    let db = &state.db;
    let ip = peer.ip().to_string();
    if request.protocols() & (HYBRID | HYBRID_EX) == 0 {
        bail!(t!(
            "connection without a Portunia .rdp file and without NLA: the RDP client must use NLA (user « account%server »)",
            "connexion sans fichier .rdp de Portunia et sans NLA : le client RDP doit utiliser NLA (utilisateur « compte%serveur »)"
        ));
    }
    let s = settings(state).await?;
    tcp.write_all(&confirm(HYBRID)).await?;
    let key = gate_public_key(state)?;
    let mut client = tokio::time::timeout(Duration::from_secs(15), tls_acceptor(state)?.accept(tcp))
        .await
        .map_err(|_| anyhow!(t!("the RDP client did not finish TLS", "le client RDP n'a pas fini la négociation TLS")))??;
    let found: Arc<Mutex<Option<Found>>> = Arc::default();
    let lookup: rdplogin::Lookup = {
        let (state, found, ip) = (state.clone(), found.clone(), ip.clone());
        Box::new(move |account: &str| {
            let result = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(resolve(&state, account, &ip, &s)));
            result.map(|(f, password)| {
                *found.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
                password
            })
        })
    };
    let leftover = match tokio::time::timeout(Duration::from_secs(60), rdplogin::accept(&mut client, key, lookup)).await {
        Ok(result) => result?,
        Err(_) => bail!(t!("the RDP client did not finish authenticating", "le client RDP n'a pas fini de s'authentifier")),
    };
    let Some(f) = found.lock().unwrap_or_else(|e| e.into_inner()).take() else {
        bail!(t!("authentication without an account", "authentification sans compte"));
    };
    // Mot de passe vérifié : erreurs oubliées, code consommé (une seule fois).
    state.limits.success(&f.user.login, &ip);
    let addr = format!("{ip} (natif)");
    if let Some(step) = f.totp_step {
        if !model::consume_totp_step(db, f.user.id, step).await? {
            audit::note(db, &f.user.login, "acces.refuse", json!({ "cible": f.target.name, "type": "rdp natif", "raison": "code déjà utilisé", "adresse": addr })).await;
            bail!(t!("code already used", "code déjà utilisé"));
        }
    }
    drop(permit);
    let a = Allowed { user: f.user, target: f.target, access: f.access, addr };
    rdp::check_space(state, &a).await.map_err(|(_, e)| e)?;
    let account = if a.target.vaulted() { Some(rdp::vault_account(state, &a).await.map_err(|(_, e)| e)?) } else { None };
    let wanted = if account.is_some() { SSL | HYBRID | HYBRID_EX } else { SSL };
    let mut o = match rdp::open_server(db, &a, &build_request(Some(neg_request(wanted)))).await {
        Ok(o) => o,
        Err((_, e)) => {
            let hint = if account.is_none() { " (mode enregistré : le serveur doit accepter une connexion sans NLA, sinon passez-le en coffre)" } else { "" };
            audit::note(db, &a.user.login, "acces.refuse", json!({ "cible": a.target.name, "type": "rdp natif", "raison": format!("{e:#}{hint}"), "adresse": a.addr })).await;
            return Err(e);
        }
    };
    if let Some((account, password)) = account {
        rdp::gate_login(db, &a, &mut o, &account, password).await.map_err(|(_, e)| e)?;
    }
    let mut first = read_first(&mut client, leftover).await?;
    if !patch_selected_protocol(&mut first, o.protocol()) {
        tracing::warn!("{}", t!("native RDP: client data without the negotiated protocol (old client?)", "RDP natif : données du client sans le protocole négocié (client ancien ?)"));
    }
    let id = Uuid::new_v4();
    let capture = rdp::start_recording(state, id, &a).await.map_err(|(_, e)| e)?;
    let (rx, tx) = tokio::io::split(&mut client);
    rdp::relay_session(state, id, &a, &Origin::Native, capture, o.tls, ClientRx::Native(rx), ClientTx::Native(tx), first).await
}

/// Rebond : la demande part au serveur sans le jeton, puis tout passe tel quel.
async fn jump(state: &Arc<State>, a: Allowed, mut client: TcpStream, request: &Request) -> Result<()> {
    let db = &state.db;
    let (user, target) = (&a.user, &a.target);
    let address = crate::target::addresses(&target.host, target.port as u16).await?;
    let mut server = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&address[..])).await {
        Ok(Ok(t)) => t,
        _ => bail!("{}:{} injoignable", target.host, target.port),
    };
    let _ = server.set_nodelay(true);
    server.write_all(&build_request(request.neg)).await?;
    let id = Uuid::new_v4();
    model::session_start(db, id, user.id, target.id, "rebond", "rdp (natif)", &a.addr).await?;
    audit::note(db, &user.login, "rebond.ouvert", json!({ "session": id, "cible": target.name, "protocole": "rdp", "adresse": a.addr })).await;
    let started = Instant::now();
    let (_watch, mut cut) = state.live.watch(crate::live::Watched { user: user.id, login: &user.login, target: Some(target), web: false, recorded: false, session: Some(id), portal: None });
    // Chaque sens compte ses octets : un poste qui coupe brutalement ne les efface pas.
    let moved = AtomicU64::new(0);
    let reason = {
        let (mut client_read, mut client_write) = client.split();
        let (mut server_read, mut server_write) = server.split();
        tokio::select! {
            _ = pump(&mut client_read, &mut server_write, &moved) => "client".to_string(),
            _ = pump(&mut server_read, &mut client_write, &moved) => "serveur".to_string(),
            why = cut.reason() => why,
        }
    };
    let _ = server.shutdown().await;
    let _ = client.shutdown().await;
    let bytes = moved.load(Ordering::Relaxed);
    model::session_end(db, id, model::Finished { recording: None, sha256: None, signature: None, bytes: bytes as i64 }).await?;
    audit::note(db, &user.login, "rebond.ferme", json!({ "session": id, "cible": target.name, "duree_s": started.elapsed().as_secs(), "octets": bytes, "fin": reason })).await;
    Ok(())
}

/// Copie dans un sens jusqu'à la fin de la connexion (ou une erreur), en comptant les octets.
async fn pump(from: &mut (impl AsyncRead + Unpin), to: &mut (impl AsyncWrite + Unpin), moved: &AtomicU64) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).await.is_err() {
                    return;
                }
                moved.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Demande comme l'envoie mstsc avec « loadbalanceinfo » : ligne, puis RDP_NEG_REQ.
    fn mstsc_request(line: &str, protocols: u32) -> Vec<u8> {
        let mut x224 = vec![0xE0, 0, 0, 0, 0, 0];
        x224.extend_from_slice(line.as_bytes());
        x224.extend_from_slice(b"\r\n");
        x224.extend_from_slice(&neg_request(protocols));
        let mut out = vec![3, 0, 0, 0, x224.len() as u8];
        out.extend_from_slice(&x224);
        let len = out.len() as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        out
    }

    #[test]
    fn demande_avec_jeton() {
        let r = parse_request(&mstsc_request("portunia-gate:hj1_abc", SSL)).unwrap();
        assert_eq!(r.token.as_deref(), Some("hj1_abc"));
        assert_eq!(r.protocols(), SSL);
        // Cookie ordinaire : pas de jeton, protocoles lus quand même.
        let r = parse_request(&mstsc_request("Cookie: mstshash=julien", SSL | HYBRID)).unwrap();
        assert_eq!(r.token, None);
        assert_eq!(r.protocols(), SSL | HYBRID);
        // Sans ligne ni négociation.
        let r = parse_request(&build_request(None)).unwrap();
        assert_eq!(r, Request { token: None, neg: None });
        assert!(parse_request(&[3, 0, 0, 7, 2, 0xF0, 0x80]).is_err());
    }

    #[test]
    fn demande_au_serveur_sans_jeton() {
        let out = build_request(Some(neg_request(SSL | HYBRID | HYBRID_EX)));
        assert_eq!(out.len(), 19);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 19);
        assert_eq!(out[4] as usize, out.len() - 5);
        let r = parse_request(&out).unwrap();
        assert_eq!(r.token, None);
        assert_eq!(r.protocols(), SSL | HYBRID | HYBRID_EX);
    }

    #[test]
    fn reponse_au_poste() {
        let server = [3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0x1f, 8, 0, 8, 0, 0, 0];
        let answer = client_answer(&server, SSL).unwrap();
        assert_eq!(rdp::selected_protocol(&answer), Some(SSL));
        assert_eq!(answer[12], 0x1f);
        let mut failure = server;
        failure[11] = 3;
        assert!(client_answer(&failure, SSL).is_none());
    }

    #[test]
    fn protocole_corrige() {
        // Bloc CS_CORE de 216 octets, entouré d'autres données.
        let mut core = vec![0u8; 216];
        core[0..4].copy_from_slice(&[0x01, 0xC0, 216, 0]);
        core[4..8].copy_from_slice(&[0x0C, 0x00, 0x08, 0x00]);
        core[212..216].copy_from_slice(&SSL.to_le_bytes());
        // earlyCapabilityFlags de xfreerdp 3 (GFX annoncé).
        core[144..146].copy_from_slice(&0x0FB2u16.to_le_bytes());
        let mut pdu = vec![9u8; 40];
        pdu.extend_from_slice(&core);
        pdu.extend_from_slice(&[0x02, 0xC0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(patch_selected_protocol(&mut pdu, HYBRID_EX));
        assert_eq!(u32::from_le_bytes(pdu[40 + 212..40 + 216].try_into().unwrap()), HYBRID_EX);
        assert_eq!(u16::from_le_bytes(pdu[40 + 144..40 + 146].try_into().unwrap()), 0x0EB2, "GFX retiré, le reste gardé");
        // Bloc trop court (client ancien) : rien n'est touché.
        let mut short = core[..200].to_vec();
        short[2] = 200;
        assert!(!patch_selected_protocol(&mut short, HYBRID_EX));
    }

    #[test]
    fn reponse_de_la_gate() {
        let c = confirm(HYBRID);
        assert_eq!(c.len(), 19);
        assert_eq!(u16::from_be_bytes([c[2], c[3]]), 19);
        assert_eq!(rdp::selected_protocol(&c), Some(HYBRID));
    }

    #[tokio::test]
    async fn premiere_trame_apres_l_authentification() {
        // Début de la trame déjà lu avec l'authentification, la suite sur la connexion.
        let pdu = [3u8, 0, 0, 7, 2, 0xF0, 0x80];
        let mut rest: &[u8] = &pdu[3..];
        assert_eq!(read_first(&mut rest, pdu[..3].to_vec()).await.unwrap(), pdu);
        // Rien de lu d'avance.
        let mut all: &[u8] = &pdu;
        assert_eq!(read_first(&mut all, Vec::new()).await.unwrap(), pdu);
    }

    #[test]
    fn identifiants_en_memoire() {
        keep_credentials("hj1_x", "ACME\\julien".into(), "secret".into(), Duration::from_secs(60));
        assert_eq!(take_credentials("hj1_x"), Some(("ACME\\julien".into(), "secret".into())));
        // À usage unique.
        assert_eq!(take_credentials("hj1_x"), None);
        keep_credentials("hj1_y", "a".into(), "b".into(), Duration::from_secs(0));
        assert_eq!(take_credentials("hj1_y"), None);
    }

    #[test]
    fn adresses() {
        assert!(check_address("").is_ok());
        assert!(check_address("gate.acme.fr").is_ok());
        assert!(check_address("gate.acme.fr:3390").is_ok());
        assert!(check_address("https://gate").is_err());
        assert!(check_address("gate:0").is_err());
        assert!(check_address("gate acme").is_err());
    }
}
