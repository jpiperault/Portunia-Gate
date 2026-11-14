//! Accès de l'extérieur par Cloudflare, en TCP : le tunnel de la Gate publie l'API, le SSH et le
//! RDP natif sous trois noms d'hôte ; sur le poste, cloudflared (lancé par Portunia, ou par
//! l'utilisateur) les ramène sur un port local. Le chiffrement reste de bout en bout (TLS de
//! l'API vérifié par son empreinte, SSH, TLS et NLA du RDP) : Cloudflare ne voit que des octets
//! chiffrés. Un tunnel HTTP ne suffit pas : Cloudflare refuse les méthodes de RD Gateway et ne
//! transporte pas le SSH.
//!
//! Les noms d'hôte se déclarent à la main dans Cloudflare, ou par la Gate avec un jeton d'API
//! Cloudflare donné pour l'occasion (jamais gardé) : routes du tunnel et enregistrements DNS.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{model, State};

const SETTING: &str = "acces_cloudflare";

/// Noms d'hôte publiés (vide : rien de publié pour ce service).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Hosts {
    #[serde(default)]
    pub api: String,
    #[serde(default)]
    pub ssh: String,
    #[serde(default)]
    pub rdp: String,
}

impl Hosts {
    pub fn is_empty(&self) -> bool {
        self.api.is_empty() && self.ssh.is_empty() && self.rdp.is_empty()
    }

    fn named(&self) -> Vec<(&'static str, &str)> {
        [("api", self.api.as_str()), ("ssh", self.ssh.as_str()), ("rdp", self.rdp.as_str())].into_iter().filter(|(_, h)| !h.is_empty()).collect()
    }
}

/// Nom d'hôte DNS valable, en minuscules (« https:// » et « / » final tolérés). Vide : aucun.
pub fn check_host(input: &str) -> Result<String> {
    let h = input.trim().trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').to_ascii_lowercase();
    if h.is_empty() {
        return Ok(h);
    }
    let ok = h.len() <= 253
        && h.contains('.')
        && h.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    if !ok {
        bail!("{} {h}", t!("Invalid host name:", "Nom d'hôte invalide :"));
    }
    Ok(h)
}

pub async fn hosts(state: &State) -> Result<Hosts> {
    Ok(model::setting(&state.db, SETTING).await?.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default())
}

/// Enregistre les noms d'hôte (déjà publiés dans Cloudflare, à la main ou par `publish`).
pub async fn set_hosts(state: &State, wanted: &Hosts) -> Result<Hosts> {
    let next = Hosts { api: check_host(&wanted.api)?, ssh: check_host(&wanted.ssh)?, rdp: check_host(&wanted.rdp)? };
    let named = next.named();
    for (i, (_, a)) in named.iter().enumerate() {
        if named[i + 1..].iter().any(|(_, b)| a == b) {
            bail!("{} {a}", t!("Same host name used twice:", "Même nom d'hôte utilisé deux fois :"));
        }
    }
    model::set_setting(&state.db, SETTING, serde_json::to_value(&next)?).await?;
    Ok(next)
}

fn port_of(listen: &str, default: u16) -> u16 {
    listen.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(default)
}

/// Service local de chaque nom d'hôte, tel que cloudflared le joint sur la Gate.
async fn services(state: &State, hosts: &Hosts) -> Result<Vec<(String, String)>> {
    let rdp_port = crate::rdpnative::settings(state).await?.port;
    Ok(hosts
        .named()
        .into_iter()
        .map(|(what, host)| {
            let port = match what {
                "api" => port_of(&state.config.api_listen, 8443),
                // Écoute SSH dédiée : les connexions par Cloudflare y sont comptées à part (B12).
                "ssh" => port_of(&state.config.ssh_cloudflare_listen, 2224),
                _ => rdp_port,
            };
            (host.to_string(), format!("tcp://localhost:{port}"))
        })
        .collect())
}

/// Routes du tunnel : les nôtres remplacent celles des mêmes noms d'hôte, les autres restent
/// (le portail en particulier), et la règle finale sans nom d'hôte reste la dernière.
pub fn merge_ingress(current: &Value, ours: &[(String, String)]) -> Vec<Value> {
    let rules: Vec<Value> = current.as_array().cloned().unwrap_or_default();
    let mut kept: Vec<Value> = Vec::new();
    let mut fallback = json!({ "service": "http_status:404" });
    for rule in rules {
        match rule["hostname"].as_str() {
            None | Some("") => fallback = rule,
            Some(h) if ours.iter().any(|(o, _)| o == h) => {}
            Some(_) => kept.push(rule),
        }
    }
    kept.extend(ours.iter().map(|(h, s)| json!({ "hostname": h, "service": s, "originRequest": {} })));
    kept.push(fallback);
    kept
}

/// Publie les noms d'hôte dans le tunnel géré par la Gate et dans le DNS, avec un jeton d'API
/// Cloudflare (Account › Cloudflare Tunnel › Edit, Zone › DNS › Edit) qui n'est pas gardé.
/// Rend ce qui a été fait, ligne par ligne.
pub async fn publish(state: &State, api_token: &str, wanted: &Hosts) -> Result<(Hosts, Vec<String>)> {
    let hosts = Hosts { api: check_host(&wanted.api)?, ssh: check_host(&wanted.ssh)?, rdp: check_host(&wanted.rdp)? };
    if hosts.is_empty() {
        bail!(t!("Give at least one host name", "Indiquez au moins un nom d'hôte"));
    }
    let tunnel_token = crate::tunnel::token(state).await?.ok_or_else(|| {
        anyhow!(t!(
            "The Cloudflare tunnel is not run by the Gate: declare the host names by hand in Cloudflare (TCP routes), then save them here",
            "Le tunnel Cloudflare n'est pas lancé par la Gate : déclarez les noms d'hôte à la main dans Cloudflare (routes TCP), puis enregistrez-les ici"
        ))
    })?;
    let (_, info) = crate::tunnel::parse(&tunnel_token)?;
    let ours = services(state, &hosts).await?;
    let token = api_token.trim().to_string();
    let target = format!("{}.cfargotunnel.com", info.tunnel);
    let done = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
        let mut done = Vec::new();
        let path = format!("/accounts/{}/cfd_tunnel/{}/configurations", info.account, info.tunnel);
        let current = crate::acme::cloudflare_call(&token, "GET", &path, None)?;
        let mut config = current["result"]["config"].clone();
        if !config.is_object() {
            config = json!({});
        }
        config["ingress"] = Value::Array(merge_ingress(&config["ingress"], &ours));
        crate::acme::cloudflare_call(&token, "PUT", &path, Some(json!({ "config": config })))?;
        for (host, service) in &ours {
            done.push(format!("{host} → {service}"));
        }
        for (host, _) in &ours {
            let zone = crate::acme::zone_for(&token, host)?;
            let found = crate::acme::cloudflare_call(&token, "GET", &format!("/zones/{zone}/dns_records?name={host}"), None)?;
            let records = found["result"].as_array().cloned().unwrap_or_default();
            if records.iter().any(|r| r["type"] == "CNAME" && r["content"].as_str() == Some(target.as_str())) {
                done.push(format!("{host} : {}", t!("DNS already set", "DNS déjà en place")));
                continue;
            }
            if let Some(r) = records.first() {
                // Jamais d'écrasement d'un enregistrement existant : il sert peut-être ailleurs.
                bail!(
                    "{host} : {} ({} {})",
                    t!("a DNS record already exists for this name; remove it in Cloudflare or choose another name", "un enregistrement DNS existe déjà pour ce nom ; supprimez-le dans Cloudflare ou choisissez un autre nom"),
                    r["type"].as_str().unwrap_or("?"),
                    r["content"].as_str().unwrap_or("?")
                );
            }
            let body = json!({ "type": "CNAME", "name": host, "content": target, "proxied": true, "comment": "Portunia Gate" });
            crate::acme::cloudflare_call(&token, "POST", &format!("/zones/{zone}/dns_records"), Some(body))?;
            done.push(format!("{host} : {}", t!("DNS record created", "enregistrement DNS créé")));
        }
        Ok(done)
    })
    .await??;
    let saved = set_hosts(state, &hosts).await?;
    Ok((saved, done))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_d_hote() {
        assert_eq!(check_host(" https://API.acme.fr/ ").unwrap(), "api.acme.fr");
        assert_eq!(check_host("").unwrap(), "");
        assert!(check_host("acme").is_err());
        assert!(check_host("a b.fr").is_err());
        assert!(check_host("-x.acme.fr").is_err());
    }

    #[test]
    fn routes_fusionnees() {
        let current = json!([
            { "hostname": "acces.acme.fr", "service": "http://localhost:8445" },
            { "hostname": "ssh.acme.fr", "service": "tcp://localhost:22" },
            { "service": "http_status:404" }
        ]);
        let ours = vec![("ssh.acme.fr".to_string(), "tcp://localhost:2222".to_string()), ("rdp.acme.fr".to_string(), "tcp://localhost:3390".to_string())];
        let merged = merge_ingress(&current, &ours);
        let names: Vec<&str> = merged.iter().map(|r| r["hostname"].as_str().unwrap_or("*")).collect();
        assert_eq!(names, ["acces.acme.fr", "ssh.acme.fr", "rdp.acme.fr", "*"], "le portail reste, l'ancienne route ssh est remplacée, la règle finale reste dernière");
        assert_eq!(merged[1]["service"], "tcp://localhost:2222");
        let empty = merge_ingress(&Value::Null, &ours);
        assert_eq!(empty.last().unwrap()["service"], "http_status:404");
    }
}
