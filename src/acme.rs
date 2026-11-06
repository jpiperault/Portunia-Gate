//! Certificat du portail obtenu et renouvelé par Let's Encrypt (ACME), réglé depuis
//! l'administration. Deux vérifications : TLS-ALPN-01 sur l'écoute HTTPS (le 443 public y est
//! redirigé) ou DNS-01 par l'API Cloudflare (rien d'ouvert sur Internet, noms génériques permis).

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Notify;

use crate::{audit, cert, model, State};

const SETTING: &str = "portail_acme";
const PURPOSE_TOKEN: &str = "reglage:acme-cloudflare";
const PURPOSE_ACCOUNT: &str = "reglage:acme-compte";
/// Renouvellement 30 jours avant l'échéance (les certificats durent 90 jours, ou moins).
const RENEW_DAYS: i64 = 30;
/// Après un échec, nouvel essai automatique (Let's Encrypt limite les échecs par heure).
const RETRY_AFTER: chrono::Duration = chrono::Duration::hours(6);
const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";
pub const TERMS: &str = "https://letsencrypt.org/repository/";

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub actif: bool,
    pub domaines: Vec<String>,
    #[serde(default)]
    pub email: String,
    /// « tls-alpn » ou « dns-cloudflare ».
    pub methode: String,
    /// Autorité d'essai de Let's Encrypt (certificat non reconnu par les navigateurs).
    #[serde(default)]
    pub essai: bool,
    /// Jeton de l'API Cloudflare, chiffré par le coffre.
    #[serde(default)]
    cloudflare: String,
    /// Compte ACME, chiffré par le coffre, et l'annuaire où il a été créé.
    #[serde(default)]
    compte: String,
    #[serde(default)]
    compte_annuaire: String,
}

impl Config {
    fn directory(&self) -> &'static str {
        if self.essai {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        }
    }
}

pub async fn config(state: &State) -> Result<Config> {
    Ok(model::setting(&state.db, SETTING)
        .await?
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default())
}

async fn save(state: &State, c: &Config) -> Result<()> {
    model::set_setting(&state.db, SETTING, serde_json::to_value(c)?).await
}

fn seal(state: &State, purpose: &str, text: &str) -> Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(state.keys.seal(purpose, text.as_bytes())?))
}

fn open(state: &State, purpose: &str, sealed: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(sealed)?;
    Ok(String::from_utf8(state.keys.open(purpose, &bytes)?)?)
}

/// Nom DNS valide ; « *.domaine » seulement par DNS-01.
pub fn parse_domain(input: &str, wildcard_ok: bool) -> Result<String> {
    let d = input.trim().trim_end_matches('.').to_ascii_lowercase();
    let bare = d.strip_prefix("*.").unwrap_or(&d);
    if d.starts_with("*.") && !wildcard_ok {
        bail!(t!(
            "« *.domain » (wildcard) needs the DNS-01 check through Cloudflare",
            "« *.domaine » (générique) demande la vérification DNS-01 par Cloudflare"
        ));
    }
    let labels: Vec<&str> = bare.split('.').collect();
    let ok = labels.len() >= 2
        && bare.len() <= 253
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && !labels.last().is_some_and(|l| l.chars().all(|c| c.is_ascii_digit()));
    if !ok {
        bail!("{} {input}", t!("invalid domain name:", "nom de domaine invalide :"));
    }
    Ok(d)
}

pub struct Update {
    pub actif: bool,
    pub domaines: Vec<String>,
    pub email: String,
    pub methode: String,
    pub essai: bool,
    /// Vide : l'efface ; absent : le garde.
    pub cloudflare_jeton: Option<String>,
}

/// Enregistre le réglage ; le service demande le certificat dans la foulée.
pub async fn update(state: &State, u: Update) -> Result<Config> {
    let mut c = config(state).await?;
    if !["tls-alpn", "dns-cloudflare"].contains(&u.methode.as_str()) {
        bail!(t!("Check: tls-alpn or dns-cloudflare", "Vérification : tls-alpn ou dns-cloudflare"));
    }
    let dns = u.methode == "dns-cloudflare";
    let mut domains = Vec::new();
    for d in &u.domaines {
        if d.trim().is_empty() {
            continue;
        }
        let d = parse_domain(d, dns)?;
        if !domains.contains(&d) {
            domains.push(d);
        }
    }
    if u.actif && domains.is_empty() {
        bail!(t!("Give at least one domain name", "Indiquez au moins un nom de domaine"));
    }
    if domains.len() > 20 {
        bail!(t!("20 domain names at most", "20 noms de domaine au plus"));
    }
    let email = u.email.trim().to_string();
    if !email.is_empty() && (!email.contains('@') || email.contains(char::is_whitespace)) {
        bail!(t!("Invalid email address", "Adresse e-mail invalide"));
    }
    if let Some(token) = &u.cloudflare_jeton {
        c.cloudflare = if token.trim().is_empty() {
            String::new()
        } else {
            seal(state, PURPOSE_TOKEN, token.trim())?
        };
    }
    if u.actif && dns && c.cloudflare.is_empty() {
        bail!(t!(
            "DNS-01: give a Cloudflare API token (Zone › DNS › Edit)",
            "DNS-01 : indiquez un jeton d'API Cloudflare (Zone › DNS › Edit)"
        ));
    }
    if u.actif && cert::is_fixed() {
        bail!(t!(
            "The portal certificate is set by PORTUNIA_GATE_PORTAL_TLS_CERT in the configuration file: remove it to use Let's Encrypt",
            "Le certificat du portail est fixé par PORTUNIA_GATE_PORTAL_TLS_CERT dans le fichier de configuration : retirez-le pour utiliser Let's Encrypt"
        ));
    }
    if c.email != email {
        // Le compte garde son contact : un nouveau compte porte la nouvelle adresse.
        c.compte.clear();
    }
    c.actif = u.actif;
    c.domaines = domains;
    c.email = email;
    c.methode = u.methode;
    c.essai = u.essai;
    save(state, &c).await?;
    if c.actif {
        wake(true);
    } else {
        set_status("inactif", None);
    }
    Ok(c)
}

/// Coupe le renouvellement (certificat importé à la main, ou retour à l'auto-signé).
pub async fn disable(state: &State) -> Result<()> {
    let mut c = config(state).await?;
    if c.actif {
        c.actif = false;
        save(state, &c).await?;
    }
    set_status("inactif", None);
    Ok(())
}

// ---------- État ----------

#[derive(Serialize, Clone, Default)]
struct Status {
    /// inactif, en_attente, en_cours, obtenu, erreur.
    etat: String,
    etape: Option<String>,
    erreur: Option<String>,
    derniere: Option<DateTime<Utc>>,
    prochaine: Option<DateTime<Utc>>,
}

static STATUS: Mutex<Option<Status>> = Mutex::new(None);
static WAKE: Notify = Notify::const_new();
static FORCE: AtomicBool = AtomicBool::new(false);

fn with_status(f: impl FnOnce(&mut Status)) {
    let mut guard = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(Status::default));
}

fn set_status(etat: &str, erreur: Option<String>) {
    with_status(|s| {
        s.etat = etat.into();
        s.erreur = erreur;
        s.etape = None;
    });
}

fn step(text: &str) {
    tracing::info!("Let's Encrypt : {text}");
    with_status(|s| s.etape = Some(text.into()));
}

/// Demande une vérification tout de suite ; `force` renouvelle même un certificat valable.
pub fn wake(force: bool) {
    if force {
        FORCE.store(true, Ordering::SeqCst);
    }
    WAKE.notify_one();
}

pub async fn report(state: &State) -> Result<Value> {
    let c = config(state).await?;
    let status = STATUS.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_default();
    Ok(json!({
        "actif": c.actif,
        "domaines": c.domaines,
        "email": c.email,
        "methode": if c.methode.is_empty() { "tls-alpn" } else { c.methode.as_str() },
        "essai": c.essai,
        "cloudflare_defini": !c.cloudflare.is_empty(),
        "etat": if c.actif { if status.etat.is_empty() { "en_attente" } else { status.etat.as_str() } } else { "inactif" },
        "etape": status.etape,
        "erreur": status.erreur,
        "derniere": status.derniere,
        "prochaine": status.prochaine,
        "conditions": TERMS,
    }))
}

// ---------- Service ----------

/// Obtient puis renouvelle le certificat tant que Let's Encrypt est activé.
pub async fn run(state: Arc<State>) -> Result<()> {
    // Laisse l'écoute HTTPS s'ouvrir avant un premier essai.
    let mut wait = Duration::from_secs(20);
    let mut failed_at: Option<DateTime<Utc>> = None;
    loop {
        let _ = tokio::time::timeout(wait, WAKE.notified()).await;
        wait = Duration::from_secs(3600);
        let forced = FORCE.swap(false, Ordering::SeqCst);
        let c = match config(&state).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Let's Encrypt : {e:#}");
                continue;
            }
        };
        if !c.actif {
            set_status("inactif", None);
            continue;
        }
        let current = cert::current();
        let from_acme = cert::stored_source(&state).await.ok().flatten().as_deref() == Some("acme");
        let names_match = current.as_ref().is_some_and(|i| {
            let mut a = i.noms.clone();
            let mut b = c.domaines.clone();
            a.sort();
            b.sort();
            a == b
        });
        let renew_at = current.as_ref().map(|i| i.expire - chrono::Duration::days(RENEW_DAYS));
        // Passage de l'autorité d'essai à la vraie, ou l'inverse.
        let staging_changed = current.as_ref().is_some_and(|i| i.emetteur.contains("STAGING") != c.essai);
        let due = !from_acme || !names_match || staging_changed || renew_at.is_none_or(|at| at <= Utc::now());
        if !forced && !due {
            with_status(|s| {
                s.etat = "obtenu".into();
                s.erreur = None;
                s.prochaine = renew_at;
            });
            continue;
        }
        if !forced && failed_at.is_some_and(|at| Utc::now() - at < RETRY_AFTER) {
            continue;
        }
        with_status(|s| {
            s.etat = "en_cours".into();
            s.erreur = None;
            s.derniere = Some(Utc::now());
        });
        let result = obtain(&state, &c).await;
        cert::clear_challenges();
        match result {
            Ok(info) => {
                failed_at = None;
                tracing::info!(
                    "Let's Encrypt : {} {} ({} {})",
                    t!("certificate obtained for", "certificat obtenu pour"),
                    info.noms.join(", "),
                    t!("expires", "expire le"),
                    info.expire.format("%Y-%m-%d")
                );
                audit::note(
                    &state.db,
                    "portunia-gate",
                    "portail.acme_obtenu",
                    json!({ "noms": info.noms, "expire": info.expire, "essai": c.essai }),
                )
                .await;
                let _ = cert::refresh(&state).await;
                with_status(|s| {
                    s.etat = "obtenu".into();
                    s.etape = None;
                    s.prochaine = Some(info.expire - chrono::Duration::days(RENEW_DAYS));
                });
            }
            Err(e) => {
                failed_at = Some(Utc::now());
                let text = format!("{e:#}");
                tracing::error!("Let's Encrypt : {text}");
                audit::note(
                    &state.db,
                    "portunia-gate",
                    "portail.acme_echec",
                    json!({ "noms": c.domaines, "erreur": text }),
                )
                .await;
                with_status(|s| {
                    s.etat = "erreur".into();
                    s.etape = None;
                    s.erreur = Some(text);
                    s.prochaine = Some(Utc::now() + RETRY_AFTER);
                });
            }
        }
    }
}

fn acme_error(e: instant_acme::Error) -> anyhow::Error {
    match e {
        instant_acme::Error::Api(p) => anyhow!("{}", p.detail.unwrap_or_else(|| p.r#type.unwrap_or_default())),
        other => anyhow!("{other}"),
    }
}

async fn account(state: &State, c: &Config) -> Result<Account> {
    let directory = c.directory();
    if !c.compte.is_empty() && c.compte_annuaire == directory {
        let creds: AccountCredentials = serde_json::from_str(&open(state, PURPOSE_ACCOUNT, &c.compte)?)?;
        return Account::builder()
            .map_err(acme_error)?
            .from_credentials(creds)
            .await
            .map_err(acme_error);
    }
    step(t!("creating the ACME account", "création du compte ACME"));
    let contact = format!("mailto:{}", c.email);
    let contacts: Vec<&str> = if c.email.is_empty() { vec![] } else { vec![contact.as_str()] };
    let (account, creds) = Account::builder()
        .map_err(acme_error)?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.to_string(),
            None,
        )
        .await
        .map_err(acme_error)?;
    let mut saved = config(state).await?;
    saved.compte = seal(state, PURPOSE_ACCOUNT, &serde_json::to_string(&creds)?)?;
    saved.compte_annuaire = directory.to_string();
    save(state, &saved).await?;
    Ok(account)
}

async fn obtain(state: &State, c: &Config) -> Result<cert::Info> {
    let dns = c.methode == "dns-cloudflare";
    if !dns && crate::portal::https_status().listening.is_none() {
        bail!(t!(
            "TLS-ALPN-01: open HTTPS listening first, and redirect port 443 of the public address to it",
            "TLS-ALPN-01 : ouvrez d'abord l'écoute HTTPS, et redirigez-y le port 443 de l'adresse publique"
        ));
    }
    let token = if dns {
        Some(open(state, PURPOSE_TOKEN, &c.cloudflare)?)
    } else {
        None
    };
    let account = account(state, c).await?;
    step(t!("ordering the certificate", "commande du certificat"));
    let identifiers: Vec<Identifier> = c.domaines.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await.map_err(acme_error)?;
    let mut records: Vec<(String, String)> = Vec::new();
    let result = async {
        let mut authorizations = order.authorizations();
        loop {
            let Some(authz) = authorizations.next().await else { break };
            let mut authz = authz.map_err(acme_error)?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => bail!("{} {other:?}", t!("authorization:", "autorisation :")),
            }
            let kind = if dns { ChallengeType::Dns01 } else { ChallengeType::TlsAlpn01 };
            let mut challenge = authz
                .challenge(kind)
                .ok_or_else(|| anyhow!(t!("check not offered by the authority", "vérification non proposée par l'autorité")))?;
            let name = match challenge.identifier().identifier {
                Identifier::Dns(d) => d.clone(),
                _ => bail!(t!("unsupported identifier", "identifiant non pris en charge")),
            };
            let key_auth = challenge.key_authorization();
            if let Some(token) = &token {
                step(&format!("{} _acme-challenge.{name}", t!("DNS record", "enregistrement DNS")));
                let (zone, id, record) = cloudflare_add(token, &name, &key_auth.dns_value()).await?;
                records.push((zone, id));
                wait_dns(&record, &key_auth.dns_value()).await;
            } else {
                cert::add_challenge(&name, key_auth.digest().as_ref())?;
            }
            step(&format!(
                "{} {name}",
                t!("check by Let's Encrypt:", "vérification par Let's Encrypt :")
            ));
            challenge.set_ready().await.map_err(acme_error)?;
        }
        let status = order
            .poll_ready(
                &RetryPolicy::new()
                    .initial_delay(Duration::from_secs(2))
                    .timeout(Duration::from_secs(180)),
            )
            .await
            .map_err(acme_error)?;
        if status != OrderStatus::Ready {
            bail!(challenge_errors(&mut order)
                .await
                .unwrap_or_else(|| format!("{} {status:?}", t!("order:", "commande :"))));
        }
        step(t!("issuing the certificate", "émission du certificat"));
        let key = order.finalize().await.map_err(acme_error)?;
        let chain = order
            .poll_certificate(&RetryPolicy::new().timeout(Duration::from_secs(120)))
            .await
            .map_err(acme_error)?;
        Ok((chain, key))
    }
    .await;
    if let Some(token) = &token {
        for (zone, id) in &records {
            if let Err(e) = cloudflare_delete(token, zone, id).await {
                tracing::warn!(
                    "Let's Encrypt : {} {e:#}",
                    t!("DNS record not removed:", "enregistrement DNS non retiré :")
                );
            }
        }
    }
    let (chain, key) = match result {
        Ok(v) => v,
        Err(e) => {
            // Le refus de l'autorité dit pourquoi (pare-feu, DNS…) mieux que l'état de la commande.
            if let Some(why) = challenge_errors(&mut order).await {
                bail!(why);
            }
            return Err(e);
        }
    };
    cert::store(state, "acme", &chain, &key).await
}

/// Motifs de refus des vérifications, par nom.
async fn challenge_errors(order: &mut instant_acme::Order) -> Option<String> {
    let mut errors = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(Ok(authz)) = authorizations.next().await {
        let name = authz.identifier().to_string();
        for ch in &authz.challenges {
            if let Some(p) = &ch.error {
                errors.push(format!("{name} : {}", p.detail.clone().unwrap_or_default()));
            }
        }
    }
    (!errors.is_empty()).then(|| errors.join(" ; "))
}

// ---------- Cloudflare DNS ----------

pub(crate) fn cloudflare_call(token: &str, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).build();
    let req = agent
        .request(method, &format!("{CLOUDFLARE_API}{path}"))
        .set("Authorization", &format!("Bearer {token}"));
    let resp = match body {
        Some(b) => req.set("Content-Type", "application/json").send_string(&b.to_string()),
        None => req.call(),
    };
    let (code, value): (u16, Value) = match resp {
        Ok(r) => (r.status(), json_of(r)),
        Err(ureq::Error::Status(code, r)) => (code, json_of(r)),
        Err(e) => bail!("Cloudflare : {e}"),
    };
    if value["success"].as_bool() != Some(true) {
        let detail = value["errors"][0]["message"].as_str().unwrap_or_default().to_string();
        if code == 401 || code == 403 {
            bail!(
                "{} ({detail})",
                t!(
                    "Cloudflare refuses the token: it needs Zone › DNS › Edit on this zone (and Account › Cloudflare Tunnel › Edit to publish tunnel routes)",
                    "Cloudflare refuse le jeton : il lui faut Zone › DNS › Edit sur cette zone (et Account › Cloudflare Tunnel › Edit pour publier des routes du tunnel)"
                )
            );
        }
        bail!("Cloudflare ({code}) : {detail}");
    }
    Ok(value)
}

fn json_of(r: ureq::Response) -> Value {
    r.into_string()
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null)
}

/// Zone Cloudflare qui porte ce nom : le plus long suffixe trouvé.
pub(crate) fn zone_for(token: &str, name: &str) -> Result<String> {
    let labels: Vec<&str> = name.split('.').collect();
    for i in 0..labels.len().saturating_sub(1) {
        let candidate = labels[i..].join(".");
        let found = cloudflare_call(token, "GET", &format!("/zones?name={candidate}"), None)?;
        if let Some(id) = found["result"][0]["id"].as_str() {
            return Ok(id.to_string());
        }
    }
    bail!(
        "{} {name}",
        t!(
            "no Cloudflare zone visible with this token for",
            "aucune zone Cloudflare visible avec ce jeton pour"
        )
    )
}

async fn cloudflare_add(token: &str, name: &str, value: &str) -> Result<(String, String, String)> {
    let (token, name, value) = (token.to_string(), name.to_string(), value.to_string());
    tokio::task::spawn_blocking(move || {
        let zone = zone_for(&token, &name)?;
        let record = format!("_acme-challenge.{name}");
        let created = cloudflare_call(
            &token,
            "POST",
            &format!("/zones/{zone}/dns_records"),
            Some(json!({ "type": "TXT", "name": record, "content": value, "ttl": 60, "comment": "Portunia Gate (Let's Encrypt)" })),
        )?;
        let id = created["result"]["id"]
            .as_str()
            .ok_or_else(|| anyhow!("Cloudflare : réponse inattendue"))?
            .to_string();
        Ok((zone, id, record))
    })
    .await?
}

async fn cloudflare_delete(token: &str, zone: &str, id: &str) -> Result<()> {
    let (token, path) = (token.to_string(), format!("/zones/{zone}/dns_records/{id}"));
    tokio::task::spawn_blocking(move || cloudflare_call(&token, "DELETE", &path, None).map(|_| ())).await?
}

/// Attend que l'enregistrement soit visible (DNS public de Cloudflare), deux minutes au plus.
async fn wait_dns(record: &str, value: &str) {
    tokio::time::sleep(Duration::from_secs(5)).await;
    let url = format!("https://cloudflare-dns.com/dns-query?name={record}&type=TXT");
    let wanted = format!("\"{value}\"");
    for _ in 0..24 {
        let url = url.clone();
        let seen = tokio::task::spawn_blocking(move || {
            ureq::get(&url)
                .set("Accept", "application/dns-json")
                .timeout(Duration::from_secs(10))
                .call()
                .ok()
                .map(json_of)
        })
        .await
        .ok()
        .flatten();
        if seen.is_some_and(|v| {
            v["Answer"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x["data"].as_str() == Some(wanted.as_str())))
        }) {
            return;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_de_domaine() {
        assert_eq!(parse_domain(" Portail.Example.COM. ", false).unwrap(), "portail.example.com");
        assert_eq!(parse_domain("*.example.com", true).unwrap(), "*.example.com");
        assert!(parse_domain("*.example.com", false).is_err());
        for bad in ["localhost", "10.0.0.1", "a..b.com", "-a.example.com", "exa mple.com", ""] {
            assert!(parse_domain(bad, true).is_err(), "{bad}");
        }
    }
}
