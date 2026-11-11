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

/// Comptes dont les sessions ouvertes doivent se fermer (mot de passe ou code réinitialisé en
/// ligne de commande) : le service les ferme à sa prochaine vérification.
pub const ORDER_CUT: &str = "console_coupures";

pub async fn order_cut(db: &PgPool, user: Uuid) -> Result<()> {
    let current = setting(db, ORDER_CUT).await?.unwrap_or(Value::Null);
    let n = current["n"].as_i64().unwrap_or(0) + 1;
    let mut list = current["comptes"].as_array().cloned().unwrap_or_default();
    list.push(serde_json::json!({ "n": n, "compte": user }));
    // Les 50 derniers suffisent : le service passe toutes les 30 secondes.
    let excess = list.len().saturating_sub(50);
    list.drain(..excess);
    set_setting(db, ORDER_CUT, serde_json::json!({ "n": n, "comptes": list })).await
}

/// Ordre de la ligne de commande : couper une session (appliqué par le service sous 30 s).
pub const ORDER_CUT_SESSION: &str = "console_coupures_sessions";

pub async fn order_cut_session(db: &PgPool, session: Uuid, by: &str) -> Result<()> {
    let current = setting(db, ORDER_CUT_SESSION).await?.unwrap_or(Value::Null);
    let n = current["n"].as_i64().unwrap_or(0) + 1;
    let mut list = current["sessions"].as_array().cloned().unwrap_or_default();
    list.push(serde_json::json!({ "n": n, "session": session, "par": by }));
    let excess = list.len().saturating_sub(50);
    list.drain(..excess);
    set_setting(db, ORDER_CUT_SESSION, serde_json::json!({ "n": n, "sessions": list })).await
}

/// Fait avancer un compteur rangé dans les réglages (ordre passé d'un processus à l'autre).
pub async fn bump_setting(db: &PgPool, key: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, '1'::jsonb)
         ON CONFLICT (key) DO UPDATE SET value = to_jsonb(COALESCE((settings.value #>> '{}')::bigint, 0) + 1)",
    )
    .bind(key)
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
    pub must_change_password: bool,
    pub totp_pending: Option<Vec<u8>>,
}

impl User {
    pub async fn policy(&self, db: &PgPool) -> Result<Policy> {
        match &self.auth_policy {
            Some(text) => Policy::parse(text),
            None => default_policy(db).await,
        }
    }
}

const USER_COLUMNS: &str =
    "id, login, display_name, role, password_hash, totp_secret, totp_last_step, auth_policy, disabled, must_change_password, totp_pending";

/// Ferme les connexions ouvertes du compte : jetons de Portunia, sessions du portail et
/// téléphones enrôlés.
/// Après un mot de passe ou un code réinitialisé, ou un compte désactivé.
pub async fn revoke_logins(db: &PgPool, user: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM api_sessions WHERE user_id = $1").bind(user).execute(db).await?;
    sqlx::query("DELETE FROM web_sessions WHERE user_id = $1").bind(user).execute(db).await?;
    // Téléphones enrôlés : à refaire après une connexion par mot de passe et code.
    sqlx::query("DELETE FROM appareils WHERE user_id = $1").bind(user).execute(db).await?;
    Ok(())
}

pub async fn user_by_id(db: &PgPool, id: Uuid) -> Result<Option<User>> {
    Ok(sqlx::query_as(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

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
        bail!(t!("Invalid login: letters, digits, dot, hyphen and underscore only", "Identifiant invalide : lettres, chiffres, point, tiret et souligné uniquement"));
    }
    Ok(())
}

pub async fn create_user(db: &PgPool, login: &str, role: &str, password_hash: Option<String>, policy: Option<String>) -> Result<Uuid> {
    check_login(login)?;
    if !["user", "auditor", "admin"].contains(&role) {
        bail!(t!("Unknown role: user, auditor or admin", "Rôle inconnu : user, auditor ou admin"));
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
                anyhow!(t!(format!("Account « {login} » already exists"), format!("Le compte « {login} » existe déjà")))
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

/// Mot de passe RDP scellé du compte, et sa date ; aucun : entrée RDP sans Portunia fermée
/// pour ce compte.
pub async fn rdp_password(db: &PgPool, user: Uuid) -> Result<Option<(Vec<u8>, DateTime<Utc>)>> {
    let row: Option<(Option<Vec<u8>>, Option<DateTime<Utc>>)> = sqlx::query_as("SELECT rdp_password, rdp_password_at FROM users WHERE id = $1")
        .bind(user)
        .fetch_optional(db)
        .await?;
    Ok(row.and_then(|(p, at)| Some((p?, at.unwrap_or_else(Utc::now)))))
}

pub async fn set_rdp_password(db: &PgPool, user: Uuid, sealed: Option<Vec<u8>>) -> Result<()> {
    sqlx::query("UPDATE users SET rdp_password = $2, rdp_password_at = CASE WHEN $2 IS NULL THEN NULL ELSE now() END WHERE id = $1")
        .bind(user)
        .bind(sealed)
        .execute(db)
        .await?;
    Ok(())
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
                anyhow!(t!("This key is already registered", "Cette clé est déjà enregistrée"))
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
                anyhow!(t!(format!("Group « {name} » already exists"), format!("Le groupe « {name} » existe déjà")))
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
        .ok_or_else(|| anyhow!(t!(format!("Unknown group: {name}"), format!("Groupe inconnu : {name}"))))
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
    /// ssh, rdp (Bureau à distance), http ou https (interface web).
    pub protocole: String,
    /// Interface web en mode coffre : auto, remplir ou basic (voir webvault.rs).
    pub web_connexion: String,
    /// Texte de la vignette (portail, Portunia) ; vide : texte automatique.
    pub description: String,
}

/// Protocole et mode compatibles. Bureau à distance : rebond (la Gate relaie la connexion
/// chiffrée sans la lire), enregistré (la Gate relaie et enregistre ; identifiants Windows
/// tapés par l'utilisateur) ou coffre (enregistré, et la Gate ouvre la session Windows avec
/// le compte du coffre).
pub fn check_protocol(protocole: &str, mode: &str) -> Result<()> {
    match protocole {
        "ssh" => Ok(()),
        "rdp" if mode == "rebond" || mode == "enregistre" || mode == "coffre" => Ok(()),
        "rdp" => bail!(t!("Remote Desktop: jump, recorded or vault mode", "Bureau à distance : mode rebond, enregistré ou coffre")),
        // Interface web : la Gate relaie chaque requête et note les pages ouvertes ; en mode
        // coffre, elle connecte en plus l'utilisateur avec le compte du coffre.
        "http" | "https" if mode == "enregistre" || mode == "coffre" => Ok(()),
        "http" | "https" => bail!(t!("Web interface: recorded or vault mode", "Interface web : mode enregistré ou coffre")),
        _ => bail!(t!("Unknown protocol: ssh, rdp, http or https", "Protocole inconnu : ssh, rdp, http ou https")),
    }
}

/// Connexion d'une interface web en mode coffre ; nom anglais « fill » accepté.
pub fn web_login(value: &str) -> Result<String> {
    match value {
        "auto" => Ok("auto".into()),
        "remplir" | "fill" => Ok("remplir".into()),
        "basic" => Ok("basic".into()),
        _ => bail!(t!("Web login: auto, fill or basic", "Connexion web : auto, remplir ou basic")),
    }
}

/// Noms anglais des modes (vault, recorded, jump) : rangés sous leur nom français.
pub fn mode_alias(mode: &str) -> &str {
    match mode {
        "vault" => "coffre",
        "recorded" => "enregistre",
        "jump" => "rebond",
        other => other,
    }
}

impl Target {
    pub fn is_rdp(&self) -> bool {
        self.protocole == "rdp"
    }
    /// Interface web (http ou https), relayée par la Gate.
    pub fn is_web(&self) -> bool {
        self.protocole == "http" || self.protocole == "https"
    }
    pub fn is_ssh(&self) -> bool {
        !self.is_rdp() && !self.is_web()
    }
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

const TARGET_COLUMNS: &str = "id, name, folder, host, port, mode, account, secret_kind, secret, host_key, protocole, web_connexion, description";

pub async fn target_by_id(db: &PgPool, id: Uuid) -> Result<Option<Target>> {
    Ok(sqlx::query_as(&format!("SELECT {TARGET_COLUMNS} FROM targets WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn target_by_name(db: &PgPool, name: &str) -> Result<Option<Target>> {
    Ok(
        sqlx::query_as(&format!("SELECT {TARGET_COLUMNS} FROM targets WHERE lower(name) = lower($1)"))
            .bind(name)
            .fetch_optional(db)
            .await?,
    )
}

/// Cibles en mode rebond désignées par leur adresse ou leur nom (connexion « ssh -J »).
/// Plusieurs cibles peuvent partager une adresse : l'appelant garde celle qui est autorisée.
pub async fn rebond_targets_at(db: &PgPool, host: &str, port: i32) -> Result<Vec<Target>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {TARGET_COLUMNS} FROM targets
         WHERE mode = 'rebond' AND (lower(host) = lower($1) OR lower(name) = lower($1)) AND port = $2 ORDER BY name"
    ))
    .bind(host)
    .bind(port)
    .fetch_all(db)
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
    pub protocole: String,
    pub web_connexion: String,
    pub description: String,
}

/// Description d'un serveur : une ligne, 200 caractères au plus.
pub fn check_description(text: &str) -> Result<String> {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() > 200 {
        bail!(t!("Description: 200 characters at most", "Description : 200 caractères au plus"));
    }
    Ok(text)
}

pub async fn create_target(db: &PgPool, t: NewTarget, seal: impl FnOnce(Uuid) -> Result<Option<Vec<u8>>>) -> Result<Uuid> {
    if !["rebond", "enregistre", "coffre"].contains(&t.mode.as_str()) {
        bail!(t!("Unknown mode: jump (rebond), recorded (enregistre) or vault (coffre)", "Mode inconnu : rebond, enregistre ou coffre"));
    }
    check_protocol(&t.protocole, &t.mode)?;
    if t.mode == "coffre" && (t.account.is_none() || t.secret_kind == "none") {
        bail!(t!("In vault mode, give the target's account and its secret", "En mode coffre, indiquez le compte de la cible et son secret"));
    }
    let id = Uuid::new_v4();
    let secret = seal(id)?;
    sqlx::query(
        "INSERT INTO targets (id, name, folder, host, port, mode, account, secret_kind, secret, protocole, web_connexion, description)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
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
    .bind(&t.protocole)
    .bind(&t.web_connexion)
    .bind(check_description(&t.description)?)
    .execute(db)
    .await
    .map_err(|e| if is_unique(&e) { anyhow!(t!(format!("Target « {} » already exists", t.name), format!("La cible « {} » existe déjà", t.name))) } else { e.into() })?;
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
    /// Accès seulement après approbation (0.38).
    approval: bool,
    allow_sftp: bool,
    allow_tunnels: bool,
    record_input: bool,
    allow_files: bool,
    days: i16,
    hour_from: Option<i16>,
    hour_to: Option<i16>,
    expires_at: Option<DateTime<Utc>>,
}

impl RuleRow {
    fn active_now(&self) -> bool {
        rule_state(self.days, self.hour_from, self.hour_to, self.expires_at) == "active"
    }
}

/// État d'une règle en ce moment : « active », « hors_plage » ou « expiree ».
pub fn rule_state(days: i16, hour_from: Option<i16>, hour_to: Option<i16>, expires_at: Option<DateTime<Utc>>) -> &'static str {
    let now = Local::now();
    if expires_at.is_some_and(|e| e <= Utc::now()) {
        return "expiree";
    }
    let day_bit = 1i16 << now.weekday().num_days_from_monday();
    if days & day_bit == 0 {
        return "hors_plage";
    }
    let hour = now.hour() as i16;
    let inside = match (hour_from, hour_to) {
        (Some(from), Some(to)) if from < to => hour >= from && hour < to,
        // Plage qui passe minuit (22 h - 6 h).
        (Some(from), Some(to)) => hour >= from || hour < to,
        _ => true,
    };
    if inside {
        "active"
    } else {
        "hors_plage"
    }
}

/// Ce qu'un utilisateur peut faire sur une cible, toutes règles actives réunies.
#[derive(Clone, Copy, Debug, Default)]
pub struct Access {
    pub sftp: bool,
    pub tunnels: bool,
    pub record_input: bool,
    /// Bureau à distance : copie de fichiers par le presse-papiers.
    pub files: bool,
}

pub async fn access(db: &PgPool, user: Uuid, target: Uuid) -> Result<Option<Access>> {
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT r.approval, r.allow_sftp, r.allow_tunnels, r.record_input, r.allow_files, r.days, r.hour_from, r.hour_to, r.expires_at
         FROM rules r
         JOIN rule_targets rt ON rt.rule_id = r.id
         JOIN group_members gm ON gm.group_id = r.group_id
         WHERE gm.user_id = $1 AND rt.target_id = $2",
    )
    .bind(user)
    .bind(target)
    .fetch_all(db)
    .await?;
    let mut active: Vec<&RuleRow> = rows.iter().filter(|r| r.active_now()).collect();
    // Règle avec approbation : ne compte qu'avec un accès accordé et pas encore terminé.
    if active.iter().any(|r| r.approval) && !approved(db, user, target).await? {
        active.retain(|r| !r.approval);
    }
    if active.is_empty() {
        return Ok(None);
    }
    Ok(Some(Access {
        sftp: active.iter().any(|r| r.allow_sftp),
        tunnels: active.iter().any(|r| r.allow_tunnels),
        record_input: active.iter().any(|r| r.record_input),
        files: active.iter().any(|r| r.allow_files),
    }))
}

/// Accès accordé par un approbateur et pas encore terminé.
pub async fn approved(db: &PgPool, user: Uuid, target: Uuid) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM approvals WHERE user_id = $1 AND target_id = $2 AND status = 'accordee' AND until > now())",
    )
    .bind(user)
    .bind(target)
    .fetch_one(db)
    .await?)
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
    pub allow_files: bool,
    pub days: i16,
    pub hours: Option<(i16, i16)>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub async fn create_rule(db: &PgPool, r: NewRule) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO rules (id, name, group_id, allow_sftp, allow_tunnels, record_input, days, hour_from, hour_to, expires_at, allow_files)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
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
    .bind(r.allow_files)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if is_unique(&e) {
            anyhow!(t!(format!("Rule « {} » already exists", r.name), format!("La règle « {} » existe déjà", r.name)))
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
    // Les noms sont copiés : l'historique reste lisible si le compte ou le serveur est supprimé.
    sqlx::query(
        "INSERT INTO sessions (id, user_id, target_id, kind, detail, client_addr, user_login, target_name, mode)
         VALUES ($1, $2, $3, $4, $5, $6, (SELECT login FROM users WHERE id = $2), (SELECT name FROM targets WHERE id = $3),
                 (SELECT mode FROM targets WHERE id = $3))",
    )
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

/// Fichier d'enregistrement d'une session encore ouverte (suivie en direct).
pub async fn session_recording(db: &PgPool, id: Uuid, path: &str) -> Result<()> {
    sqlx::query("UPDATE sessions SET recording = $2 WHERE id = $1").bind(id).bind(path).execute(db).await?;
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

/// Index de relecture, calculé à la fermeture de l'enregistrement.
/// Nombre de fichiers copiés pendant une session Bureau à distance.
pub async fn session_files(db: &PgPool, id: Uuid, count: i32) -> Result<()> {
    sqlx::query("UPDATE sessions SET fichiers = $2 WHERE id = $1").bind(id).bind(count).execute(db).await?;
    Ok(())
}

pub async fn session_index(db: &PgPool, id: Uuid, frappe: bool, texte: &str) -> Result<()> {
    sqlx::query("UPDATE sessions SET frappe = $2, texte = $3 WHERE id = $1")
        .bind(id)
        .bind(frappe)
        .bind(texte)
        .execute(db)
        .await?;
    Ok(())
}

/// Session vue par l'audit (liste et lecteur).
#[derive(sqlx::FromRow)]
pub struct AuditSession {
    pub id: Uuid,
    pub login: String,
    pub target: String,
    pub kind: String,
    pub detail: String,
    pub mode: String,
    pub client_addr: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub recording: Option<String>,
    pub recording_sha256: Option<String>,
    pub signature: Option<String>,
    pub frappe: bool,
    pub bytes: i64,
    /// Fichiers copiés par le presse-papiers (Bureau à distance).
    pub fichiers: i32,
}

const AUDIT_COLUMNS: &str = "s.id, s.user_login AS login, s.target_name AS target, s.kind, s.detail, s.mode, s.client_addr,
    s.started_at, s.ended_at, s.recording, s.recording_sha256, s.signature, s.frappe, s.bytes, s.fichiers";

#[derive(Default)]
pub struct AuditFilter {
    pub login: Option<String>,
    pub target: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    /// Recherche dans le texte indexé (écran et frappe).
    pub text: Option<String>,
    pub with_input: bool,
    /// Seulement les sessions où des fichiers ont été copiés.
    pub with_files: bool,
    pub limit: i64,
}

pub async fn audit_sessions(db: &PgPool, f: &AuditFilter) -> Result<Vec<AuditSession>> {
    let like = f.text.as_ref().map(|t| format!("%{}%", t.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    Ok(sqlx::query_as(&format!(
        "SELECT {AUDIT_COLUMNS} FROM sessions s
         WHERE ($1::text IS NULL OR s.user_login = $1)
           AND ($2::text IS NULL OR s.target_name = $2)
           AND ($3::timestamptz IS NULL OR s.started_at >= $3)
           AND ($4::timestamptz IS NULL OR s.started_at < $4)
           AND ($5::text IS NULL OR s.texte ILIKE $5)
           AND (NOT $6 OR s.frappe)
           AND (NOT $8 OR s.fichiers > 0)
         ORDER BY s.started_at DESC LIMIT $7"
    ))
    .bind(&f.login)
    .bind(&f.target)
    .bind(f.since)
    .bind(f.until)
    .bind(like)
    .bind(f.with_input)
    .bind(f.limit)
    .bind(f.with_files)
    .fetch_all(db)
    .await?)
}

pub async fn audit_session(db: &PgPool, id: Uuid) -> Result<Option<AuditSession>> {
    Ok(sqlx::query_as(&format!("SELECT {AUDIT_COLUMNS} FROM sessions s WHERE s.id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

/// Sessions dont l'identifiant commence par ce début (8 caractères affichés par « sessions »).
pub async fn audit_sessions_by_prefix(db: &PgPool, prefix: &str) -> Result<Vec<AuditSession>> {
    let prefix: String = prefix.chars().filter(|c| c.is_ascii_hexdigit() || *c == '-').collect::<String>().to_lowercase();
    Ok(sqlx::query_as(&format!("SELECT {AUDIT_COLUMNS} FROM sessions s WHERE s.id::text LIKE $1 ORDER BY s.started_at DESC LIMIT 2"))
        .bind(format!("{prefix}%"))
        .fetch_all(db)
        .await?)
}

#[derive(sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub login: String,
    pub target: String,
    pub kind: String,
    pub detail: String,
    pub client_addr: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub recording: Option<String>,
    pub bytes: i64,
}

pub async fn last_sessions(db: &PgPool, count: i64) -> Result<Vec<SessionRow>> {
    Ok(sqlx::query_as(
        "SELECT s.id, s.user_login AS login, s.target_name AS target, s.kind, s.detail, s.client_addr, s.started_at, s.ended_at,
                s.recording, s.bytes
         FROM sessions s ORDER BY s.started_at DESC LIMIT $1",
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
            approval: false,
            allow_sftp: false,
            allow_tunnels: false,
            record_input: false,
            allow_files: false,
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

    #[test]
    fn description_sur_une_ligne() {
        assert_eq!(check_description("  Messagerie  de\n l'agence ").unwrap(), "Messagerie de l'agence");
        assert!(check_description(&"x".repeat(200)).is_ok());
        assert!(check_description(&"x".repeat(201)).is_err());
    }
}
