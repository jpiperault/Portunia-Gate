//! Notifications de la Gate : courriel (SMTP), Microsoft Teams (webhook « Workflows ») et
//! webhook JSON signé. Utilisées par l'approbation des accès et par les alertes.
//!
//! Réglage `notifications` (JSON) ; mot de passe SMTP et secret du webhook scellés par la Gate.
//! Webhook : POST du JSON, en-têtes `X-Portunia-Gate-Date` (secondes Unix) et
//! `X-Portunia-Gate-Signature: sha256=<hex>`, HMAC-SHA256 de « date.corps » avec le secret :
//! le destinataire vérifie l'origine et refuse un message rejoué (date trop ancienne).

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::{audit, model, State};

const KEY: &str = "notifications";

/// Réglages des notifications (secrets en clair seulement le temps d'un envoi).
#[derive(Clone, Default, Debug)]
pub struct Settings {
    pub smtp_host: String,
    pub smtp_port: u16,
    /// starttls, tls ou aucune.
    pub smtp_security: String,
    pub smtp_user: String,
    pub smtp_password: Option<String>,
    pub smtp_from: String,
    pub teams_url: String,
    pub webhook_url: String,
    pub webhook_secret: Option<String>,
}

impl Settings {
    pub fn mail_ready(&self) -> bool {
        !self.smtp_host.is_empty() && !self.smtp_from.is_empty()
    }
}

/// Réglages enregistrés, secrets descellés.
pub async fn settings(state: &State) -> Result<Settings> {
    let v = model::setting(&state.db, KEY).await?.unwrap_or(Value::Null);
    let open = |field: &str, purpose: &str| -> Option<String> {
        let sealed = STANDARD.decode(v[field].as_str()?).ok()?;
        state.keys.open(purpose, &sealed).ok().and_then(|p| String::from_utf8(p).ok())
    };
    Ok(Settings {
        smtp_host: v["smtp_hote"].as_str().unwrap_or_default().to_string(),
        smtp_port: v["smtp_port"].as_u64().unwrap_or(587) as u16,
        smtp_security: v["smtp_securite"].as_str().unwrap_or("starttls").to_string(),
        smtp_user: v["smtp_compte"].as_str().unwrap_or_default().to_string(),
        smtp_password: open("smtp_mot_de_passe", "notifications:smtp"),
        smtp_from: v["smtp_expediteur"].as_str().unwrap_or_default().to_string(),
        teams_url: v["teams_url"].as_str().unwrap_or_default().to_string(),
        webhook_url: v["webhook_url"].as_str().unwrap_or_default().to_string(),
        webhook_secret: open("webhook_secret", "notifications:webhook"),
    })
}

/// Vue sans secrets (API, ligne de commande).
pub fn public(s: &Settings) -> Value {
    json!({
        "smtp_hote": s.smtp_host, "smtp_port": s.smtp_port, "smtp_securite": s.smtp_security,
        "smtp_compte": s.smtp_user, "smtp_mot_de_passe": s.smtp_password.is_some(), "smtp_expediteur": s.smtp_from,
        "teams_url": s.teams_url, "webhook_url": s.webhook_url, "webhook_secret": s.webhook_secret.is_some(),
    })
}

/// Vérifie puis enregistre (secrets scellés).
pub async fn save(state: &State, s: &Settings) -> Result<()> {
    if !["starttls", "tls", "aucune"].contains(&s.smtp_security.as_str()) {
        bail!(t!("SMTP security: starttls, tls or aucune", "Sécurité SMTP : starttls, tls ou aucune"));
    }
    if !s.smtp_from.is_empty() {
        s.smtp_from.parse::<lettre::message::Mailbox>().map_err(|_| anyhow!(t!("Sender: an e-mail address", "Expéditeur : une adresse e-mail")))?;
    }
    for (name, url) in [("Teams", &s.teams_url), ("webhook", &s.webhook_url)] {
        if !url.is_empty() && !url.starts_with("https://") {
            bail!(t!(format!("{name}: an https:// address"), format!("{name} : une adresse https://")));
        }
    }
    let seal = |plain: &Option<String>, purpose: &str| -> Result<Value> {
        Ok(match plain {
            Some(p) if !p.is_empty() => json!(STANDARD.encode(state.keys.seal(purpose, p.as_bytes())?)),
            _ => Value::Null,
        })
    };
    let value = json!({
        "smtp_hote": s.smtp_host.trim(), "smtp_port": s.smtp_port, "smtp_securite": s.smtp_security,
        "smtp_compte": s.smtp_user.trim(), "smtp_mot_de_passe": seal(&s.smtp_password, "notifications:smtp")?,
        "smtp_expediteur": s.smtp_from.trim(), "teams_url": s.teams_url.trim(), "webhook_url": s.webhook_url.trim(),
        "webhook_secret": seal(&s.webhook_secret, "notifications:webhook")?,
    });
    model::set_setting(&state.db, KEY, value).await
}

/// Courriel en texte simple.
pub async fn mail(s: &Settings, to: &[String], subject: &str, body: &str) -> Result<()> {
    use lettre::{message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
    if !s.mail_ready() {
        bail!(t!("E-mail is not set up (notify set --smtp-host … --from …)", "Le courriel n'est pas réglé (notify set --smtp-host … --from …)"));
    }
    let mut builder = Message::builder().from(s.smtp_from.parse().context("expéditeur")?).subject(subject).header(ContentType::TEXT_PLAIN);
    let mut any = false;
    for address in to.iter().filter(|a| !a.trim().is_empty()) {
        builder = builder.bcc(address.trim().parse().with_context(|| format!("adresse {address}"))?);
        any = true;
    }
    if !any {
        return Ok(());
    }
    let message = builder.body(body.to_string())?;
    let transport = match s.smtp_security.as_str() {
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(&s.smtp_host)?,
        "aucune" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&s.smtp_host),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&s.smtp_host)?,
    };
    let mut transport = transport.port(s.smtp_port).timeout(Some(std::time::Duration::from_secs(20)));
    if !s.smtp_user.is_empty() {
        transport = transport.credentials(Credentials::new(s.smtp_user.clone(), s.smtp_password.clone().unwrap_or_default()));
    }
    transport.build().send(message).await?;
    Ok(())
}

/// Message dans un canal Microsoft Teams (webhook d'un flux « Workflows » : carte adaptative).
pub async fn teams(s: &Settings, title: &str, text: &str) -> Result<()> {
    if s.teams_url.is_empty() {
        return Ok(());
    }
    let card = json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard", "version": "1.4",
                "body": [
                    { "type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": true },
                    { "type": "TextBlock", "text": text, "wrap": true },
                ],
            },
        }],
    });
    post(s.teams_url.clone(), card.to_string(), Vec::new()).await
}

/// Signature d'un webhook : HMAC-SHA256 de « date.corps », en hexadécimal.
pub fn signature(secret: &str, date: i64, body: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let tag = ring::hmac::sign(&key, format!("{date}.{body}").as_bytes());
    tag.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Webhook JSON signé : { "evenement", "date", "gate", "detail" }.
pub async fn webhook(s: &Settings, gate: &str, event: &str, detail: &Value) -> Result<()> {
    if s.webhook_url.is_empty() {
        return Ok(());
    }
    let date = chrono::Utc::now().timestamp();
    let body = json!({ "evenement": event, "date": chrono::Utc::now(), "gate": gate, "detail": detail }).to_string();
    let mut headers = vec![("X-Portunia-Gate-Date".to_string(), date.to_string())];
    if let Some(secret) = s.webhook_secret.as_deref().filter(|x| !x.is_empty()) {
        headers.push(("X-Portunia-Gate-Signature".to_string(), format!("sha256={}", signature(secret, date, &body))));
    }
    post(s.webhook_url.clone(), body, headers).await
}

async fn post(url: String, body: String, headers: Vec<(String, String)>) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut req = ureq::post(&url).timeout(std::time::Duration::from_secs(15)).set("Content-Type", "application/json");
        for (k, v) in &headers {
            req = req.set(k, v);
        }
        match req.send_string(&body) {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, r)) => Err(anyhow!("HTTP {code} : {}", r.into_string().unwrap_or_default().chars().take(200).collect::<String>())),
            Err(e) => Err(anyhow!("{e}")),
        }
    })
    .await?
}

/// Un message à diffuser : courriel à ces adresses, Teams et webhook (selon les réglages).
pub struct Notice {
    pub event: &'static str,
    pub title: String,
    pub text: String,
    pub detail: Value,
    pub to: Vec<String>,
}

/// Envoie en tâche de fond ; un échec est noté au journal (`notification.echec`), jamais bloquant.
pub fn send(state: std::sync::Arc<State>, n: Notice) {
    tokio::spawn(async move {
        let s = match settings(&state).await {
            Ok(s) => s,
            Err(e) => return tracing::warn!("notifications : {e:#}"),
        };
        let gate = crate::api::setting_str(&state, "nom", "Portunia Gate").await.unwrap_or_else(|_| "Portunia Gate".into());
        let subject = format!("[{gate}] {}", n.title);
        let mut failures = Vec::new();
        if s.mail_ready() && !n.to.is_empty() {
            if let Err(e) = mail(&s, &n.to, &subject, &n.text).await {
                failures.push(("courriel", format!("{e:#}")));
            }
        }
        if let Err(e) = teams(&s, &subject, &n.text).await {
            failures.push(("teams", format!("{e:#}")));
        }
        if let Err(e) = webhook(&s, &gate, n.event, &n.detail).await {
            failures.push(("webhook", format!("{e:#}")));
        }
        for (canal, why) in failures {
            tracing::warn!("notification {canal} : {why}");
            audit::note(&state.db, "systeme", "notification.echec", json!({ "canal": canal, "evenement": n.event, "raison": why })).await;
        }
    });
}

/// Adresses e-mail des membres d'un groupe (ou des administrateurs si aucun groupe).
pub async fn group_emails(state: &State, group: Option<uuid::Uuid>) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = match group {
        Some(g) => sqlx::query_as("SELECT u.email FROM users u JOIN group_members m ON m.user_id = u.id WHERE m.group_id = $1 AND NOT u.disabled AND u.email <> ''").bind(g).fetch_all(&state.db).await?,
        None => sqlx::query_as("SELECT email FROM users WHERE role = 'admin' AND NOT disabled AND email <> ''").fetch_all(&state.db).await?,
    };
    Ok(rows.into_iter().map(|r| r.0).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_du_webhook() {
        // Vérifiable avec : printf '1700000000.{"a":1}' | openssl dgst -sha256 -hmac secret
        let s = signature("secret", 1_700_000_000, r#"{"a":1}"#);
        assert_eq!(s.len(), 64);
        assert_eq!(s, signature("secret", 1_700_000_000, r#"{"a":1}"#));
        assert_ne!(s, signature("secret", 1_700_000_001, r#"{"a":1}"#), "la date fait partie de la signature");
        assert_ne!(s, signature("autre", 1_700_000_000, r#"{"a":1}"#));
    }
}
