//! Lectures et écritures en base : comptes, cibles, droits, sessions, réglages.

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Datelike, Local, Timelike, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::Policy;

/// Politique d'authentification par défaut : mot de passe et code, ou clé SSH et code.
pub const DEFAULT_POLICY: &str = "password+totp,key+totp";

pub async fn setting(db: &PgPool, key: &str) -> Result<Option<Value>> {
    Ok(sqlx::query_scalar("SELECT value FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(db)
        .await?)
}

pub async fn set_setting(db: &PgPool, key: &str, value: Value) -> Result<()> {
    sqlx::query("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
        .bind(key)
        .bind(value)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn default_policy(db: &PgPool) -> Result<Policy> {
    let text = setting(db, "auth_policy")
        .await?
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| DEFAULT_POLICY.into());
    Policy::parse(&text)
}

// ---------- Comptes ----------

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct User {
    pub id: Uuid,
    pub login: String,
    #[allow(dead_code)] // affiché par la console web
    pub display_name: String,
    pub role: String,
    pub password_hash: Option<String>,
    pub totp_secret: Option<Vec<u8>>,
    pub totp_last_step: i64,
    pub auth_policy: Option<String>,
    pub disabled: bool,
}

impl User {
    pub async fn policy(&self, db: &PgPool) -> Result<Policy> {
        match &self.auth_policy {
            Some(text) => Policy::parse(text),
            None => default_policy(db).await,
        }
    }
}

const USER_COLUMNS: &str = "id, login, display_name, role, password_hash, totp_secret, totp_last_step, auth_policy, disabled";

pub async fn user_by_login(db: &PgPool, login: &str) -> Result<Option<User>> {
    Ok(sqlx::query_as(&format!("SELECT {USER_COLUMNS} FROM users WHERE login = $1"))
        .bind(login)
        .fetch_optional(db)
        .await?)
}

pub async fn users(db: &PgPool) -> Result<Vec<User>> {
    Ok(sqlx::query_as(&format!("SELECT {USER_COLUMNS} FROM users ORDER BY login"))
        .fetch_all(db)
        .await?)
}

pub fn check_login(login: &str) -> Result<()> {
    if login.is_empty() || login.len() > 64 || !login.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        bail!("Identifiant invalide : lettres, chiffres, point, tiret et souligné uniquement");
    }
    Ok(())
}

pub async fn create_user(db: &PgPool, login: &str, role: &str, password_hash: Option<String>, policy: Option<String>) -> Result<Uuid> {
    check_login(login)?;
    if !["user", "auditor", "admin"].contains(&role) {
        bail!("Rôle inconnu : user, auditor ou admin");
    }
    if let Some(p) = &policy {
        Policy::parse(p)?;
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, login, role, password_hash, auth_policy) VALUES ($1, $2, $3, $4, $5)")
        .bind(id)
        .bind(login)
        .bind(role)
        .bind(password_hash)
        .bind(policy)
        .execute(db)
        .await
        .map_err(|e| {
            if is_unique(&e) {
                anyhow!("Le compte « {login} » existe déjà")
            } else {
                e.into()
            }
        })?;
    Ok(id)
}

pub async fn set_totp(db: &PgPool, user: Uuid, sealed: Option<Vec<u8>>) -> Result<()> {
    sqlx::query("UPDATE users SET totp_secret = $2, totp_last_step = 0 WHERE id = $1")
        .bind(user)
        .bind(sealed)
        .execute(db)
        .await?;
    Ok(())
}

/// Mémorise le pas TOTP utilisé, seulement s'il est plus récent : deux connexions
/// simultanées ne peuvent pas réutiliser le même code.
pub async fn consume_totp_step(db: &PgPool, user: Uuid, step: i64) -> Result<bool> {
    let done = sqlx::query("UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2")
        .bind(user)
        .bind(step)
        .execute(db)
        .await?;
    Ok(done.rows_affected() == 1)
}

pub async fn user_key_owner(db: &PgPool, fingerprint: &str) -> Result<Option<Uuid>> {
    Ok(sqlx::query_scalar("SELECT user_id FROM user_keys WHERE fingerprint = $1")
        .bind(fingerprint)
        .fetch_optional(db)
        .await?)
}

pub async fn add_user_key(db: &PgPool, user: Uuid, public_key: &str, fingerprint: &str, label: &str) -> Result<()> {
    sqlx::query("INSERT INTO user_keys (id, user_id, public_key, fingerprint, label) VALUES ($1, $2, $3, $4, $5)")
        .bind(Uuid::new_v4())
        .bind(user)
        .bind(public_key)
        .bind(fingerprint)
        .bind(label)
        .execute(db)
        .await
        .map_err(|e| {
            if is_unique(&e) {
                anyhow!("Cette clé est déjà enregistrée")
            } else {
                e.into()
            }
        })?;
    Ok(())
}

// ---------- Groupes ----------

pub async fn create_group(db: &PgPool, name: &str) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(name)
        .execute(db)
        .await
        .map_err(|e| {
            if is_unique(&e) {
                anyhow!("Le groupe « {name} » existe déjà")
            } else {
                e.into()
            }
        })?;
    Ok(id)
}

pub async fn group_id(db: &PgPool, name: &str) -> Result<Uuid> {
    sqlx::query_scalar("SELECT id FROM groups WHERE name = $1")
        .bind(name)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| anyhow!("Groupe inconnu : {name}"))
}

pub async fn add_member(db: &PgPool, group: Uuid, user: Uuid) -> Result<()> {
    sqlx::query("INSERT INTO group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(group)
        .bind(user)
        .execute(db)
        .await?;
    Ok(())
}

// ---------- Cibles ----------

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct Target {
    pub id: Uuid,
    pub name: String,
    pub folder: String,
    pub host: String,
    pub port: i32,
    pub mode: String,
    pub account: Option<String>,
    pub secret_kind: String,
    pub secret: Option<Vec<u8>>,
    pub host_key: Option<String>,
}

impl Target {
    pub fn records(&self) -> bool {
        self.mode != "rebond"
    }
    pub fn vaulted(&self) -> bool {
        self.mode == "coffre"
    }
    pub fn secret_purpose(&self) -> String {
        format!("cible:{}", self.id)
    }
}

const TARGET_COLUMNS: &str = "id, name, folder, host, port, mode, account, secret_kind, secret, host_key";

pub async fn target_by_name(db: &PgPool, name: &str) -> Result<Option<Target>> {
    Ok(
        sqlx::query_as(&format!("SELECT {TARGET_COLUMNS} FROM targets WHERE lower(name) = lower($1)"))
            .bind(name)
            .fetch_optional(db)
            .await?,
    )
}

/// Cible en mode rebond désignée par son adresse (connexion « ssh -J »).
pub async fn target_by_address(db: &PgPool, host: &str, port: i32) -> Result<Option<Target>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {TARGET_COLUMNS} FROM targets WHERE (lower(host) = lower($1) OR lower(name) = lower($1)) AND port = $2 ORDER BY name LIMIT 1"
    ))
    .bind(host)
    .bind(port)
    .fetch_optional(db)
    .await?)
}

pub async fn targets(db: &PgPool) -> Result<Vec<Target>> {
    Ok(
        sqlx::query_as(&format!("SELECT {TARGET_COLUMNS} FROM targets ORDER BY folder, name"))
            .fetch_all(db)
            .await?,
    )
}

pub struct NewTarget {
    pub name: String,
    pub folder: String,
    pub host: String,
    pub port: i32,
    pub mode: String,
    pub account: Option<String>,
    pub secret_kind: String,
}

pub async fn create_target(db: &PgPool, t: NewTarget, seal: impl FnOnce(Uuid) -> Result<Option<Vec<u8>>>) -> Result<Uuid> {
    if !["rebond", "enregistre", "coffre"].contains(&t.mode.as_str()) {
        bail!("Mode inconnu : rebond, enregistre ou coffre");
    }
    if t.mode == "coffre" && (t.account.is_none() || t.secret_kind == "none") {
        bail!("En mode coffre, indiquez le compte de la cible et son secret");
    }
    let id = Uuid::new_v4();
    let secret = seal(id)?;
    sqlx::query(
        "INSERT INTO targets (id, name, folder, host, port, mode, account, secret_kind, secret) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(&t.name)
    .bind(&t.folder)
    .bind(&t.host)
    .bind(t.port)
    .bind(&t.mode)
    .bind(&t.account)
    .bind(&t.secret_kind)
    .bind(secret)
    .execute(db)
    .await
    .map_err(|e| if is_unique(&e) { anyhow!("La cible « {} » existe déjà", t.name) } else { e.into() })?;
    Ok(id)
}

/// Mémorise l'empreinte si aucune ne l'est encore ; vrai si c'est cet appel qui l'a fait.
pub async fn pin_host_key(db: &PgPool, target: Uuid, fingerprint: &str) -> Result<bool> {
    let done = sqlx::query("UPDATE targets SET host_key = $2 WHERE id = $1 AND host_key IS NULL")
        .bind(target)
        .bind(fingerprint)
        .execute(db)
        .await?;
    Ok(done.rows_affected() == 1)
}

// ---------- Droits ----------

#[derive(sqlx::FromRow, Clone, Debug)]
struct RuleRow {
    allow_sftp: bool,
    allow_tunnels: bool,
    record_input: bool,
    days: i16,
    hour_from: Option<i16>,
    hour_to: Option<i16>,
    expires_at: Option<DateTime<Utc>>,
}

impl RuleRow {
    fn active_now(&self) -> bool {
        let now = Local::now();
        if self.expires_at.is_some_and(|e| e <= Utc::now()) {
            return false;
        }
        let day_bit = 1i16 << now.weekday().num_days_from_monday();
        if self.days & day_bit == 0 {
            return false;
        }
        let hour = now.hour() as i16;
        match (self.hour_from, self.hour_to) {
            (Some(from), Some(to)) if from < to => hour >= from && hour < to,
            // Plage qui passe minuit (22 h - 6 h).
            (Some(from), Some(to)) => hour >= from || hour < to,
            _ => true,
        }
    }
}

/// Ce qu'un utilisateur peut faire sur une cible, toutes règles actives réunies.
#[derive(Clone, Copy, Debug, Default)]
pub struct Access {
    pub sftp: bool,
    pub tunnels: bool,
    pub record_input: bool,
}

pub async fn access(db: &PgPool, user: Uuid, target: Uuid) -> Result<Option<Access>> {
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT r.allow_sftp, r.allow_tunnels, r.record_input, r.days, r.hour_from, r.hour_to, r.expires_at
         FROM rules r
         JOIN rule_targets rt ON rt.rule_id = r.id
         JOIN group_members gm ON gm.group_id = r.group_id
         WHERE gm.user_id = $1 AND rt.target_id = $2",
    )
    .bind(user)
    .bind(target)
    .fetch_all(db)
    .await?;
    let active: Vec<&RuleRow> = rows.iter().filter(|r| r.active_now()).collect();
    if active.is_empty() {
        return Ok(None);
    }
    Ok(Some(Access {
        sftp: active.iter().any(|r| r.allow_sftp),
        tunnels: active.iter().any(|r| r.allow_tunnels),
        record_input: active.iter().any(|r| r.record_input),
    }))
}

/// Cibles accessibles maintenant, pour le menu.
pub async fn allowed_targets(db: &PgPool, user: Uuid) -> Result<Vec<Target>> {
    let mut out = Vec::new();
    for target in targets(db).await? {
        if access(db, user, target.id).await?.is_some() {
            out.push(target);
        }
    }
    Ok(out)
}

pub struct NewRule {
    pub name: String,
    pub group: Uuid,
    pub targets: Vec<Uuid>,
    pub allow_sftp: bool,
    pub allow_tunnels: bool,
    pub record_input: bool,
    pub days: i16,
    pub hours: Option<(i16, i16)>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub async fn create_rule(db: &PgPool, r: NewRule) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO rules (id, name, group_id, allow_sftp, allow_tunnels, record_input, days, hour_from, hour_to, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(&r.name)
    .bind(r.group)
    .bind(r.allow_sftp)
    .bind(r.allow_tunnels)
    .bind(r.record_input)
    .bind(r.days)
    .bind(r.hours.map(|h| h.0))
    .bind(r.hours.map(|h| h.1))
    .bind(r.expires_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if is_unique(&e) {
            anyhow!("La règle « {} » existe déjà", r.name)
        } else {
            e.into()
        }
    })?;
    for target in &r.targets {
        sqlx::query("INSERT INTO rule_targets (rule_id, target_id) VALUES ($1, $2)")
            .bind(id)
            .bind(target)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(id)
}

// ---------- Sessions ----------

pub async fn session_start(db: &PgPool, id: Uuid, user: Uuid, target: Uuid, kind: &str, detail: &str, client: &str) -> Result<()> {
    sqlx::query("INSERT INTO sessions (id, user_id, target_id, kind, detail, client_addr) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(id)
        .bind(user)
        .bind(target)
        .bind(kind)
        .bind(detail)
        .bind(client)
        .execute(db)
        .await?;
    Ok(())
}

pub struct Finished {
    pub recording: Option<String>,
    pub sha256: Option<String>,
    pub signature: Option<String>,
    pub bytes: i64,
}

pub async fn session_end(db: &PgPool, id: Uuid, f: Finished) -> Result<()> {
    sqlx::query("UPDATE sessions SET ended_at = now(), recording = $2, recording_sha256 = $3, signature = $4, bytes = $5 WHERE id = $1")
        .bind(id)
        .bind(f.recording)
        .bind(f.sha256)
        .bind(f.signature)
        .bind(f.bytes)
        .execute(db)
        .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub login: String,
    pub target: String,
    pub kind: String,
    pub detail: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub recording: Option<String>,
    pub bytes: i64,
}

pub async fn last_sessions(db: &PgPool, count: i64) -> Result<Vec<SessionRow>> {
    Ok(sqlx::query_as(
        "SELECT s.id, u.login, t.name AS target, s.kind, s.detail, s.started_at, s.ended_at, s.recording, s.bytes
         FROM sessions s JOIN users u ON u.id = s.user_id JOIN targets t ON t.id = s.target_id
         ORDER BY s.started_at DESC LIMIT $1",
    )
    .bind(count)
    .fetch_all(db)
    .await?)
}

fn is_unique(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some("23505"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plages_horaires() {
        let all = RuleRow {
            allow_sftp: false,
            allow_tunnels: false,
            record_input: false,
            days: 127,
            hour_from: None,
            hour_to: None,
            expires_at: None,
        };
        assert!(all.active_now());
        let expired = RuleRow {
            expires_at: Some(Utc::now() - chrono::Duration::minutes(1)),
            ..all.clone()
        };
        assert!(!expired.active_now());
        let no_day = RuleRow { days: 0, ..all.clone() };
        assert!(!no_day.active_now());
        let hour = Local::now().hour() as i16;
        let here = RuleRow {
            hour_from: Some(hour),
            hour_to: Some(hour + 1),
            ..all.clone()
        };
        assert!(here.active_now());
        let elsewhere = RuleRow {
            hour_from: Some((hour + 2) % 24),
            hour_to: Some((hour + 3) % 24 + if (hour + 3) % 24 == 0 { 24 } else { 0 }),
            ..all
        };
        assert!(!elsewhere.active_now());
    }
}
