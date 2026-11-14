//! Sortie web (0.48) : Portunia navigue sur Internet par la Gate.
//!
//! Portunia ouvre un proxy SOCKS5 sur le PC, relié au SSH de la Gate par « login%cible » ;
//! chaque connexion du navigateur arrive ici en canal « direct-tcpip » avec un nom de domaine.
//! La cible de sortie porte son filtre (domaines autorisés et bloqués, ports) ; la Gate résout
//! le nom elle-même et refuse toute adresse interne (sinon la sortie web atteindrait les
//! serveurs du réseau sans passer par leurs règles). Une session « navigation » par connexion :
//! le journal garde une ligne par site (connexions, octets), pas une par requête.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Result};
use serde_json::json;
use uuid::Uuid;

use crate::{
    audit,
    live::{self, Cut, Watched},
    model::{self, Target},
    State,
};

/// Connexions ouvertes en même temps par une navigation (un navigateur en ouvre une dizaine par site).
pub const MAX_OPEN: usize = 256;
/// Sites retenus pour le résumé d'une session ; au-delà, comptés ensemble.
const MAX_SITES: usize = 500;
/// Domaines dans une liste : assez pour une liste d'autorisation d'entreprise.
const MAX_DOMAINS: usize = 200;

// ---------- Filtre ----------

/// Liste de domaines tapée par l'administrateur (virgules, espaces ou lignes) : mise en forme
/// « a.com,b.org ». « *.a.com » vaut « a.com » : un domaine couvre toujours ses sous-domaines.
pub fn domains(text: &str) -> Result<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let d = raw.trim().trim_start_matches("*.").trim_matches('.').to_ascii_lowercase();
        if d.is_empty() {
            continue;
        }
        let ok = d.parse::<IpAddr>().is_ok()
            || (d.len() <= 253 && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')));
        if !ok {
            bail!(t!(format!("Invalid domain: {raw}"), format!("Domaine invalide : {raw}")));
        }
        if !out.contains(&d) {
            out.push(d);
        }
    }
    if out.len() > MAX_DOMAINS {
        bail!(t!(format!("{MAX_DOMAINS} domains at most"), format!("{MAX_DOMAINS} domaines au plus")));
    }
    Ok(out.join(","))
}

/// Ports permis : « 80,443 », ou « * » pour tous.
pub fn ports(text: &str) -> Result<String> {
    let text = text.trim();
    if text == "*" {
        return Ok("*".into());
    }
    let mut out: Vec<u16> = Vec::new();
    for raw in text.split(|c: char| c == ',' || c.is_whitespace()).filter(|p| !p.is_empty()) {
        let p: u16 = raw.parse().ok().filter(|p| *p > 0).ok_or_else(|| anyhow!(t!(format!("Invalid port: {raw}"), format!("Port invalide : {raw}"))))?;
        if !out.contains(&p) {
            out.push(p);
        }
    }
    if out.is_empty() {
        bail!(t!("Give at least one port (80,443), or * for all", "Indiquez au moins un port (80,443), ou * pour tous"));
    }
    Ok(out.iter().map(u16::to_string).collect::<Vec<_>>().join(","))
}

/// Le domaine `host` est-il couvert par la liste (lui-même ou un sous-domaine) ?
fn listed(list: &str, host: &str) -> bool {
    list.split(',').filter(|d| !d.is_empty()).any(|d| host == d || host.strip_suffix(d).is_some_and(|rest| rest.ends_with('.')))
}

/// Pourquoi la cible refuse ce site (avant résolution) ; `None` : permis.
pub fn refusal(target: &Target, host: &str, port: u32) -> Option<&'static str> {
    if listed(&target.sortie_bloques, host) {
        return Some("domaine bloqué");
    }
    if !target.sortie_domaines.is_empty() && !listed(&target.sortie_domaines, host) {
        return Some("domaine hors de la liste");
    }
    let port_ok = target.sortie_ports == "*" || target.sortie_ports.split(',').any(|p| p.parse::<u32>().ok() == Some(port));
    if !port_ok {
        return Some("port non permis");
    }
    None
}

/// Adresse joignable depuis Internet. Tout le reste (boucle locale, réseaux privés, lien local,
/// CGNAT, multicast, documentation, IPv4 dans IPv6…) est refusé.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_unspecified()
                || a.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xFE) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x0064 && s[1] == 0xff9b)
                || s[0] == 0x2002
                || s[..6].iter().all(|x| *x == 0))
        }
    }
}

/// Résout le nom sur la Gate et garde les adresses ; une seule adresse interne suffit à refuser
/// (un nom piégé qui mélange les deux). La connexion se fait sur ces adresses-là, sans nouvelle
/// résolution.
pub async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, &'static str> {
    let found = tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host((host, port))).await;
    let list: Vec<SocketAddr> = match found {
        Ok(Ok(it)) => it.collect(),
        _ => return Err("nom introuvable"),
    };
    if list.is_empty() {
        return Err("nom introuvable");
    }
    if list.iter().any(|a| !is_public(a.ip())) {
        return Err("réseau interne");
    }
    Ok(list)
}

/// Connexion au site, sur les adresses déjà vérifiées.
pub async fn connect(addresses: &[SocketAddr]) -> Result<tokio::net::TcpStream> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addresses))
        .await
        .map_err(|_| anyhow!(t!("site unreachable (timed out)", "site injoignable (délai dépassé)")))??;
    let _ = tcp.set_nodelay(true);
    Ok(tcp)
}

// ---------- Session de navigation ----------

#[derive(Default, Clone)]
struct Seen {
    connexions: u32,
    octets: u64,
    refusees: u32,
}

/// Une navigation : ouverte à la première connexion du navigateur, fermée avec la connexion
/// SSH de Portunia (résumé au journal et dans la liste des sessions).
pub struct Navigation {
    state: Arc<State>,
    pub id: Uuid,
    login: String,
    target: String,
    addr: String,
    started: Instant,
    sites: Mutex<BTreeMap<String, Seen>>,
    others: Mutex<Seen>,
    open: AtomicUsize,
    cut: Mutex<Cut>,
    _guard: live::Guard,
}

impl Navigation {
    pub async fn start(state: Arc<State>, user: Uuid, login: &str, target: &Target, addr: &str) -> Result<Arc<Navigation>> {
        let id = Uuid::new_v4();
        model::session_start(&state.db, id, user, target.id, "navigation", "navigation", addr).await?;
        audit::note(&state.db, login, "navigation.ouverte", json!({ "session": id, "cible": target.name, "adresse": addr })).await;
        let (guard, cut) = state.live.watch(Watched { user, login, target: Some(target), web: false, recorded: false, session: Some(id) });
        Ok(Arc::new(Navigation {
            state,
            id,
            login: login.to_string(),
            target: target.name.clone(),
            addr: addr.to_string(),
            started: Instant::now(),
            sites: Mutex::new(BTreeMap::new()),
            others: Mutex::new(Seen::default()),
            open: AtomicUsize::new(0),
            cut: Mutex::new(cut),
            _guard: guard,
        }))
    }

    /// Signal de coupure (Audit › En direct, droit retiré, compte désactivé).
    pub fn cut(&self) -> Cut {
        self.cut.lock().unwrap().follow()
    }

    pub fn closed(&self) -> Option<String> {
        self.cut.lock().unwrap().closed()
    }

    fn with_site(&self, host: &str, f: impl FnOnce(&mut Seen)) {
        let mut sites = self.sites.lock().unwrap();
        if let Some(seen) = sites.get_mut(host) {
            return f(seen);
        }
        if sites.len() < MAX_SITES {
            f(sites.entry(host.to_string()).or_default());
        } else {
            f(&mut self.others.lock().unwrap());
        }
    }

    /// Site refusé : noté au journal la première fois seulement (le navigateur réessaie souvent).
    pub async fn refused(&self, host: &str, port: u32, why: &str) {
        let mut first = false;
        self.with_site(host, |s| {
            first = s.refusees == 0;
            s.refusees += 1;
        });
        if first {
            audit::note(
                &self.state.db,
                &self.login,
                "navigation.refusee",
                json!({ "session": self.id, "cible": self.target, "site": format!("{host}:{port}"), "raison": why, "adresse": self.addr }),
            )
            .await;
        }
    }

    /// Une connexion de plus en cours vers ce site ; `None` si la navigation en a déjà trop d'ouvertes.
    pub fn enter(self: &Arc<Self>, host: &str) -> Option<Opened> {
        if self.open.fetch_add(1, Ordering::SeqCst) >= MAX_OPEN {
            self.open.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Opened { nav: self.clone(), host: host.to_string() })
    }
}

/// Connexion en cours vers un site ; ses octets sont ajoutés au site à la fin.
pub struct Opened {
    nav: Arc<Navigation>,
    host: String,
}

impl Opened {
    /// Connexion menée à son terme (site joint) : comptée avec ses octets.
    pub fn done(self, bytes: u64) {
        self.nav.with_site(&self.host, |s| {
            s.connexions += 1;
            s.octets += bytes;
        });
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        self.nav.open.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Résumé : sites par octets décroissants, pour le journal et la liste des sessions.
fn summary(sites: &BTreeMap<String, Seen>) -> Vec<(String, Seen)> {
    let mut list: Vec<(String, Seen)> = sites.iter().map(|(h, s)| (h.clone(), s.clone())).collect();
    list.sort_by(|a, b| b.1.octets.cmp(&a.1.octets).then(b.1.connexions.cmp(&a.1.connexions)).then(a.0.cmp(&b.0)));
    list
}

impl Drop for Navigation {
    fn drop(&mut self) {
        let sites = summary(&self.sites.lock().unwrap());
        let others = self.others.lock().unwrap().clone();
        let total: u64 = sites.iter().map(|(_, s)| s.octets).sum::<u64>() + others.octets;
        let visited: Vec<&str> = sites.iter().filter(|(_, s)| s.connexions > 0).map(|(h, _)| h.as_str()).collect();
        let mut detail = visited.iter().take(20).copied().collect::<Vec<_>>().join(", ");
        if visited.len() > 20 {
            detail.push_str(&format!(" (+{})", visited.len() - 20));
        }
        if detail.is_empty() {
            detail = "navigation".into();
        }
        let journal: Vec<_> = sites
            .iter()
            .take(100)
            .map(|(h, s)| json!({ "site": h, "connexions": s.connexions, "octets": s.octets, "refusees": s.refusees }))
            .collect();
        let (state, id, login, target, duration) = (self.state.clone(), self.id, self.login.clone(), self.target.clone(), self.started.elapsed().as_secs());
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        rt.spawn(async move {
            let db = &state.db;
            let _ = model::session_detail(db, id, &detail).await;
            let _ = model::session_end(db, id, model::Finished { recording: None, sha256: None, signature: None, bytes: total as i64 }).await;
            audit::note(
                db,
                &login,
                "navigation.fermee",
                json!({
                    "session": id, "cible": target, "duree_s": duration, "octets": total,
                    "sites": journal, "autres_sites": others.connexions + others.refusees,
                }),
            )
            .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(allow: &str, block: &str, ports: &str) -> Target {
        Target {
            id: Uuid::nil(),
            name: "internet".into(),
            folder: String::new(),
            host: "internet".into(),
            port: 443,
            mode: "enregistre".into(),
            account: None,
            secret_kind: "none".into(),
            secret: None,
            host_key: None,
            protocole: "sortie".into(),
            web_connexion: "auto".into(),
            description: String::new(),
            sortie_domaines: domains(allow).unwrap(),
            sortie_bloques: domains(block).unwrap(),
            sortie_ports: super::ports(ports).unwrap(),
        }
    }

    #[test]
    fn listes_de_domaines() {
        assert_eq!(domains(" *.Microsoft.com, github.com\nexample.org. ;github.com").unwrap(), "microsoft.com,github.com,example.org");
        assert_eq!(domains("").unwrap(), "");
        assert_eq!(domains("10.0.0.1").unwrap(), "10.0.0.1");
        assert!(domains("bad_domain.com").is_err());
        assert!(domains("a..b").is_err());
        assert_eq!(ports("443, 80 443").unwrap(), "443,80");
        assert_eq!(ports(" * ").unwrap(), "*");
        assert!(ports("0").is_err());
        assert!(ports("").is_err());
        assert!(ports("http").is_err());
    }

    #[test]
    fn filtre_de_la_cible() {
        let all = target("", "", "80,443");
        assert_eq!(refusal(&all, "www.youtube.com", 443), None);
        assert_eq!(refusal(&all, "www.youtube.com", 22), Some("port non permis"));
        let some = target("microsoft.com, github.com", "evil.github.com", "443");
        assert_eq!(refusal(&some, "github.com", 443), None);
        assert_eq!(refusal(&some, "api.github.com", 443), None);
        assert_eq!(refusal(&some, "evil.github.com", 443), Some("domaine bloqué"));
        assert_eq!(refusal(&some, "x.evil.github.com", 443), Some("domaine bloqué"));
        // Un suffixe qui n'est pas un sous-domaine ne compte pas.
        assert_eq!(refusal(&some, "notgithub.com", 443), Some("domaine hors de la liste"));
        assert_eq!(refusal(&some, "github.com.pirate.net", 443), Some("domaine hors de la liste"));
        assert_eq!(refusal(&target("", "", "*"), "a.b", 8443), None);
    }

    #[test]
    fn adresses_internes_refusees() {
        for ip in [
            "10.1.2.3", "172.16.0.1", "192.168.91.40", "127.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1",
            "192.0.0.8", "198.18.0.1", "::1", "::", "fe80::1", "fd00::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2002:a00:1::1", "::10.0.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "142.250.74.238", "2a00:1450:4007:80c::200e", "::ffff:8.8.8.8"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn resolution_vers_l_interne_refusee() {
        assert_eq!(resolve("127.0.0.1", 443).await, Err("réseau interne"));
        assert_eq!(resolve("localhost", 80).await, Err("réseau interne"));
        assert_eq!(resolve("192.168.1.1", 80).await, Err("réseau interne"));
        assert_eq!(resolve("nom-inexistant.invalid", 80).await, Err("nom introuvable"));
    }

    #[test]
    fn resume_par_octets() {
        let mut sites = BTreeMap::new();
        sites.insert("a.com".to_string(), Seen { connexions: 3, octets: 10, refusees: 0 });
        sites.insert("b.com".to_string(), Seen { connexions: 1, octets: 500, refusees: 0 });
        sites.insert("c.com".to_string(), Seen { connexions: 0, octets: 0, refusees: 4 });
        let s = summary(&sites);
        assert_eq!(s.iter().map(|(h, _)| h.as_str()).collect::<Vec<_>>(), ["b.com", "a.com", "c.com"]);
    }
}
