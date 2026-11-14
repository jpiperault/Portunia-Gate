//! Limites contre les essais en série, communes au SSH, à l'API et au portail web.
//!
//! - Essais de connexion : comptés avant toute vérification, par compte depuis une adresse (5),
//!   par adresse (20) et par compte toutes adresses confondues (30), sur 10 minutes. Une
//!   tentative sans erreur est pardonnée. Un essai refusé n'allonge pas l'attente, et un
//!   attaquant isolé ne bloque pas le compte de quelqu'un d'autre sur son adresse.
//! - Connexions SSH pas encore authentifiées : plafond par adresse et plafond global.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(600);
const MAX_PAIR: u32 = 5;
const MAX_ADDRESS: u32 = 20;
const MAX_ACCOUNT: u32 = 30;
const MAX_PENDING_PER_ADDRESS: usize = 16;
/// Connexions non authentifiées venues de la boucle locale (portail, cloudflared) ou du tunnel
/// Cloudflare : un plafond chacune, plus large qu'une adresse mais pas sans limite (B12).
const MAX_PENDING_SHARED: usize = 64;
const MAX_PENDING: usize = 512;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    /// Refusé ; `first` : premier refus de cette période, à inscrire au journal.
    Blocked { first: bool },
}

struct Count {
    n: u32,
    since: Instant,
    noted: bool,
}

#[derive(Default)]
pub struct Limiter {
    counts: Mutex<HashMap<String, Count>>,
    pending: Arc<Mutex<HashMap<String, usize>>>,
}

/// Une adresse IPv6 compte pour son réseau /64 : un poste en dispose de milliards.
pub fn address_key(ip: &str) -> String {
    match ip.parse::<IpAddr>().map(|a| a.to_canonical()) {
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Ok(v4) => v4.to_string(),
        Err(_) => ip.chars().take(64).collect(),
    }
}

fn keys(login: &str, ip: &str) -> [String; 3] {
    let login: String = login.trim().to_lowercase().chars().take(64).collect();
    let address = address_key(ip);
    [format!("paire:{login}\n{address}"), format!("adresse:{address}"), format!("compte:{login}")]
}

impl Limiter {
    /// À appeler avant de vérifier quoi que ce soit : l'essai compte déjà, ce qui vaut aussi
    /// pour des essais lancés en même temps.
    pub fn attempt(&self, login: &str, ip: &str) -> Verdict {
        let keys = keys(login, ip);
        let mut counts = self.counts.lock().unwrap();
        counts.retain(|_, c| c.since.elapsed() < WINDOW);
        for (key, max) in keys.iter().zip([MAX_PAIR, MAX_ADDRESS, MAX_ACCOUNT]) {
            if let Some(c) = counts.get_mut(key).filter(|c| c.n >= max) {
                let first = !c.noted;
                c.noted = true;
                return Verdict::Blocked { first };
            }
        }
        for key in keys {
            counts.entry(key).or_insert(Count { n: 0, since: Instant::now(), noted: false }).n += 1;
        }
        Verdict::Allowed
    }

    /// L'essai n'était pas une erreur (étape suivante de la connexion).
    pub fn forgive(&self, login: &str, ip: &str) {
        let mut counts = self.counts.lock().unwrap();
        for key in keys(login, ip) {
            if let Some(c) = counts.get_mut(&key) {
                c.n = c.n.saturating_sub(1);
            }
        }
    }

    /// Connexion réussie : efface les erreurs de ce compte depuis cette adresse.
    pub fn success(&self, login: &str, ip: &str) {
        let [pair, address, account] = keys(login, ip);
        let mut counts = self.counts.lock().unwrap();
        let Some(mine) = counts.remove(&pair).map(|c| c.n) else { return };
        for key in [address, account] {
            if let Some(c) = counts.get_mut(&key) {
                c.n = c.n.saturating_sub(mine);
            }
        }
    }

    /// Place pour une connexion pas encore authentifiée ; `None` : plafond atteint. Les
    /// connexions locales (portail, surveillance) ne comptent pas.
    pub fn connection(&self, ip: IpAddr) -> Option<Slot> {
        if ip.to_canonical().is_loopback() {
            return self.shared("boucle-locale");
        }
        let key = address_key(&ip.to_string());
        let mut pending = self.pending.lock().unwrap();
        if pending.values().sum::<usize>() >= MAX_PENDING || pending.get(&key).is_some_and(|n| *n >= MAX_PENDING_PER_ADDRESS) {
            return None;
        }
        *pending.entry(key.clone()).or_default() += 1;
        Some(Slot { pending: self.pending.clone(), key: Some(key) })
    }
}

impl Limiter {
    /// Place pour une entrée partagée par beaucoup (boucle locale, tunnel Cloudflare).
    pub fn shared(&self, name: &str) -> Option<Slot> {
        let key = format!("~{name}");
        let mut pending = self.pending.lock().unwrap();
        if pending.get(&key).is_some_and(|n| *n >= MAX_PENDING_SHARED) {
            return None;
        }
        *pending.entry(key.clone()).or_default() += 1;
        Some(Slot { pending: self.pending.clone(), key: Some(key) })
    }
}

/// Rendue quand la connexion est authentifiée ou fermée.
pub struct Slot {
    pending: Arc<Mutex<HashMap<String, usize>>>,
    key: Option<String>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let Some(key) = &self.key else { return };
        let mut pending = self.pending.lock().unwrap();
        if let Some(n) = pending.get_mut(key) {
            *n -= 1;
            if *n == 0 {
                pending.remove(key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill(l: &Limiter, login: &str, ip: &str, n: u32) {
        for _ in 0..n {
            assert_eq!(l.attempt(login, ip), Verdict::Allowed);
        }
    }

    #[test]
    fn paire_bloquee_sans_gener_les_autres() {
        let l = Limiter::default();
        fill(&l, "alice", "198.51.100.1", 5);
        assert_eq!(l.attempt("ALICE", "198.51.100.1"), Verdict::Blocked { first: true });
        assert_eq!(l.attempt("alice", "198.51.100.1"), Verdict::Blocked { first: false });
        assert_eq!(l.attempt("alice", "198.51.100.2"), Verdict::Allowed, "le vrai titulaire garde l'accès");
    }

    #[test]
    fn plafond_par_adresse_et_par_compte() {
        let l = Limiter::default();
        for i in 0..20 {
            assert_eq!(l.attempt(&format!("compte{i}"), "198.51.100.1"), Verdict::Allowed);
        }
        assert!(matches!(l.attempt("autre", "198.51.100.1"), Verdict::Blocked { .. }));
        let l = Limiter::default();
        for i in 0..30 {
            assert_eq!(l.attempt("alice", &format!("198.51.100.{i}")), Verdict::Allowed);
        }
        assert!(matches!(l.attempt("alice", "203.0.113.9"), Verdict::Blocked { .. }));
    }

    #[test]
    fn ipv6_compte_par_reseau() {
        let l = Limiter::default();
        for i in 0..5 {
            assert_eq!(l.attempt("alice", &format!("2001:db8:1:2::{i:x}")), Verdict::Allowed);
        }
        assert!(matches!(l.attempt("alice", "2001:db8:1:2:ffff::1"), Verdict::Blocked { .. }));
        assert_eq!(l.attempt("alice", "2001:db8:1:3::1"), Verdict::Allowed);
    }

    #[test]
    fn pardon_et_reussite() {
        let l = Limiter::default();
        for _ in 0..20 {
            assert_eq!(l.attempt("alice", "198.51.100.1"), Verdict::Allowed);
            l.forgive("alice", "198.51.100.1");
        }
        fill(&l, "alice", "198.51.100.1", 4);
        l.success("alice", "198.51.100.1");
        fill(&l, "alice", "198.51.100.1", 5);
    }

    #[test]
    fn places_rendues() {
        let l = Limiter::default();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let slots: Vec<Slot> = (0..MAX_PENDING_PER_ADDRESS).map(|_| l.connection(ip).unwrap()).collect();
        assert!(l.connection(ip).is_none());
        assert!(l.connection("127.0.0.1".parse().unwrap()).is_some(), "connexion locale libre");
        drop(slots);
        assert!(l.connection(ip).is_some());
        assert!(l.pending.lock().unwrap().is_empty(), "plus rien en attente");
    }
}
