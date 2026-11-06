//! API HTTPS utilisée par Portunia : connexion (avec première connexion et enrôlement
//! du code), liste des serveurs, jetons SSH à usage unique et administration.
//!
//! Toutes les routes sont sous /api/v1. Authentification : « Authorization: Bearer <jeton> ».

use std::{collections::BTreeSet, net::SocketAddr, sync::Arc};

use anyhow::anyhow;
use axum::{
    extract::{ConnectInfo, Path, Query, State as AxState},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    audit,
    auth::{self, Factor},
    keys::{random, sha256_hex},
    model::{self, User},
    State,
};

// ---------- Erreurs ----------

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "erreur": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        // Erreurs métier (« existe déjà », « inconnu ») : on les montre telles quelles.
        ApiError(StatusCode::BAD_REQUEST, format!("{e:#}"))
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!("{} {e}", t!("database:", "base :"));
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, t!("Gate database error", "Erreur de la base de la Gate").into())
    }
}

fn err(status: StatusCode, text: impl Into<String>) -> ApiError {
    ApiError(status, text.into())
}

type ApiResult<T = Json<Value>> = Result<T, ApiError>;

// ---------- Contexte ----------

struct Api {
    state: Arc<State>,
}

type Ctx = AxState<Arc<Api>>;

pub async fn run(state: Arc<State>) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let files = crate::tls::files(&state.config.data_dir);
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&files.cert, &files.key)
        .await
        .map_err(|e| anyhow!(t!(format!("API certificate: {e}"), format!("certificat de l'API : {e}"))))?;
    let listen: SocketAddr = state
        .config
        .api_listen
        .parse()
        .map_err(|_| anyhow!(t!("invalid PORTUNIA_GATE_API_LISTEN", "PORTUNIA_GATE_API_LISTEN invalide")))?;
    let api = Arc::new(Api { state });
    let app = Router::new()
        .route("/api/v1/gate", get(gate))
        .route("/api/v1/connexion", post(login).delete(logout))
        .route("/api/v1/moi", get(me))
        .route("/api/v1/serveurs", get(servers))
        .route("/api/v1/serveurs/{nom}/ticket", post(ticket))
        .route("/api/v1/serveurs/{nom}/rdp-natif", post(native_rdp))
        .route("/api/v1/admin/cibles", get(admin_targets).post(admin_target_create))
        .route("/api/v1/admin/cibles/{id}", put(admin_target_update).delete(admin_target_delete))
        .route("/api/v1/admin/cibles/{id}/oublier-empreinte", post(admin_target_forget_key))
        .route("/api/v1/admin/comptes", get(admin_users).post(admin_user_create))
        .route("/api/v1/admin/comptes/{id}", put(admin_user_update).delete(admin_user_delete))
        .route("/api/v1/admin/comptes/{id}/reinitialiser-code", post(admin_user_reset_totp))
        .route("/api/v1/admin/comptes/{id}/mot-de-passe-provisoire", post(admin_user_temp_password))
        .route("/api/v1/admin/comptes/{id}/cles", post(admin_user_add_key))
        .route("/api/v1/admin/groupes", get(admin_groups).post(admin_group_create))
        .route("/api/v1/admin/groupes/{id}", delete(admin_group_delete))
        .route("/api/v1/admin/regles", get(admin_rules).post(admin_rule_create))
        .route("/api/v1/admin/regles/{id}", put(admin_rule_update).delete(admin_rule_delete))
        .route("/api/v1/admin/journal", get(admin_journal))
        .route("/api/v1/admin/journal/verification", get(admin_journal_verify))
        .route("/api/v1/admin/journal.csv", get(admin_journal_csv))
        .route("/api/v1/admin/sessions", get(admin_sessions))
        .route("/api/v1/admin/reglages", get(admin_settings).put(admin_settings_update))
        .route("/api/v1/rdp", get(rdp_passage))
        .route("/api/v1/admin/portail", get(admin_portal).put(admin_portal_update))
        .route("/api/v1/admin/portail/fermer-sessions", post(admin_portal_close))
        .route("/api/v1/admin/portail/relais", post(admin_relay_add))
        .route("/api/v1/admin/portail/tester", post(admin_portal_check))
        .route("/api/v1/admin/portail/certificat", put(admin_cert_import).delete(admin_cert_remove))
        .route("/api/v1/admin/portail/acme", put(admin_acme_update))
        .route("/api/v1/admin/acces-cloudflare", get(admin_cf_access).put(admin_cf_access_update))
        .route("/api/v1/admin/portail/acme/renouveler", post(admin_acme_renew))
        .route("/api/v1/admin/portail/relais/{id}", delete(admin_relay_remove))
        .route("/api/v1/audit/sessions", get(audit_sessions))
        .route("/api/v1/audit/sessions/{id}/enregistrement", get(audit_recording))
        .route("/api/v1/audit/sessions/{id}/flux", get(audit_rdp_stream))
        // Vue en direct : sessions ouvertes, et les couper.
        .route("/api/v1/audit/direct", get(audit_live))
        // Approbation des accès : demander, décider, annuler.
        .route("/api/v1/approbations", get(approvals_list).post(approvals_request))
        .route("/api/v1/approbations/{id}/decision", post(approvals_decide))
        .route("/api/v1/approbations/{id}/annuler", post(approvals_cancel))
        // Notifications (courriel, Teams, webhook) : réglages et essai.
        .route("/api/v1/admin/notifications", get(admin_notify).put(admin_notify_update))
        .route("/api/v1/admin/notifications/essai", post(admin_notify_test))
        .route("/api/v1/admin/etat", get(admin_status))
        .route("/api/v1/admin/mise-a-jour", get(admin_update).post(admin_update_apply).delete(admin_update_cancel))
        .route("/api/v1/audit/sessions/{id}/couper", post(audit_cut))
        // Export d'une relecture (vidéo, sous-titres, transcription, .cast) : noté au journal.
        .route("/api/v1/audit/sessions/{id}/export", post(audit_export))
        .route("/api/v1/assistance", get(assist_status))
        .route("/api/v1/assistance/{place}", get(assist_join))
        .route("/api/v1/admin/assistance", get(admin_assist).put(admin_assist_update))
        .route("/api/v1/admin/durcissement", get(admin_hardening))
        .route("/api/v1/admin/rdp-natif", get(admin_native_rdp).put(admin_native_rdp_update))
        // Interfaces web ouvertes depuis Portunia : entrée avec un jeton, puis toute autre
        // adresse va au serveur web de la session (cookie).
        .route("/web/entree", get(web_entry))
        .fallback(web_any)
        .with_state(api)
        // Messages dans la langue demandée par Portunia (Accept-Language).
        .layer(axum::middleware::from_fn(crate::lang::middleware))
        .layer(axum::middleware::from_fn(crate::http::deadline));
    tracing::info!("{} https://{listen}", t!("API listening on", "API en écoute sur"));
    // TCP_NODELAY : les petits messages (frappe, souris du Bureau à distance) partent sans attendre.
    let mut server = axum_server::bind_rustls(listen, tls).map(|a| a.acceptor(axum_server::accept::NoDelayAcceptor));
    crate::http::limit(&mut server);
    server.serve(app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

fn token() -> anyhow::Result<String> {
    Ok(B64URL.encode(random::<32>()?))
}

pub(crate) async fn setting_str(state: &State, key: &str, default: &str) -> anyhow::Result<String> {
    Ok(model::setting(&state.db, key)
        .await?
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| default.into()))
}

pub(crate) async fn session_hours(state: &State) -> anyhow::Result<i64> {
    Ok(model::setting(&state.db, "duree_session_h")
        .await?
        .and_then(|v| v.as_i64())
        .unwrap_or(8)
        .clamp(1, 24 * 7))
}

pub(crate) async fn remember_allowed(state: &State) -> anyhow::Result<bool> {
    Ok(model::setting(&state.db, "memo_mot_de_passe")
        .await?
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

async fn gate_info(state: &State) -> anyhow::Result<Value> {
    Ok(json!({
        "nom": setting_str(state, "nom", "Portunia Gate").await?,
        "version": env!("CARGO_PKG_VERSION"),
        "site": model::setting(&state.db, "site_id").await?,
        "port_ssh": state.config.ssh_public_port,
        "empreinte_ssh": state.keys.host_fingerprint(),
        "memo_mot_de_passe": remember_allowed(state).await?,
        "duree_session_h": session_hours(state).await?,
        "relecture_propres": own_sessions_allowed(state).await?,
        // Accès de l'extérieur par Cloudflare en TCP (cloudflared sur le poste) : noms d'hôte publiés.
        "cloudflare": crate::cfaccess::hosts(state).await.ok().filter(|h| !h.is_empty()),
    }))
}

/// Compte authentifié par le jeton d'API.
async fn caller(api: &Api, headers: &HeaderMap) -> Result<User, ApiError> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, t!("Sign-in to the Gate required", "Connexion à la Gate requise")))?;
    let user_id: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM api_sessions WHERE token_hash = $1 AND expires_at > now()")
        .bind(sha256_hex(bearer.as_bytes()))
        .fetch_optional(&api.state.db)
        .await?;
    let id = user_id.ok_or_else(|| err(StatusCode::UNAUTHORIZED, t!("Gate session expired: sign in again", "Session de la Gate expirée : reconnectez-vous")))?;
    let user = model::user_by_id(&api.state.db, id).await?.filter(|u| !u.disabled);
    user.ok_or_else(|| err(StatusCode::UNAUTHORIZED, t!("Account disabled", "Compte désactivé")))
}

async fn admin(api: &Api, headers: &HeaderMap) -> Result<User, ApiError> {
    let user = caller(api, headers).await?;
    if user.role != "admin" {
        return Err(err(StatusCode::FORBIDDEN, t!("Restricted to the Gate's administrators", "Réservé aux administrateurs de la Gate")));
    }
    Ok(user)
}

/// Lecture du journal et des sessions : administrateurs et auditeurs.
async fn auditor(api: &Api, headers: &HeaderMap) -> Result<User, ApiError> {
    let user = caller(api, headers).await?;
    if user.role != "admin" && user.role != "auditor" {
        return Err(err(StatusCode::FORBIDDEN, t!("Restricted to the Gate's administrators and auditors", "Réservé aux administrateurs et auditeurs de la Gate")));
    }
    Ok(user)
}

// ---------- Connexion ----------

async fn gate(AxState(api): Ctx) -> ApiResult {
    Ok(Json(gate_info(&api.state).await?))
}

#[derive(Deserialize)]
struct LoginBody {
    login: String,
    mot_de_passe: String,
    code: Option<String>,
    nouveau_mot_de_passe: Option<String>,
    client: Option<String>,
}

/// Connexion en plusieurs passages : la réponse dit ce qui manque (« code_requis »,
/// « changer_mot_de_passe », « enrolement ») jusqu'à « ok » avec le jeton.
async fn login(AxState(api): Ctx, ConnectInfo(addr): ConnectInfo<SocketAddr>, Json(body): Json<LoginBody>) -> ApiResult {
    let state = &api.state;
    let ip = addr.ip().to_string();
    if let crate::limits::Verdict::Blocked { first } = state.limits.attempt(&body.login, &ip) {
        if first {
            audit::note(&state.db, &body.login, "auth.bloquee", json!({ "methode": "api", "adresse": ip })).await;
        }
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            t!("Too many attempts: try again in a few minutes", "Trop d'essais : réessayez dans quelques minutes"),
        ));
    }
    let fail = |why: &'static str| {
        let api = api.clone();
        let (login, ip) = (body.login.clone(), ip.clone());
        async move {
            audit::note(
                &api.state.db,
                &login,
                "auth.echec",
                json!({ "methode": "api", "raison": why, "adresse": ip }),
            )
            .await;
            err(StatusCode::UNAUTHORIZED, t!("Wrong login, password or code", "Identifiant, mot de passe ou code incorrect"))
        }
    };

    let Some(user) = model::user_by_login(&state.db, &body.login).await?.filter(|u| !u.disabled) else {
        auth::burn_password(body.mot_de_passe.clone()).await;
        return Err(fail("compte inconnu ou désactivé").await);
    };
    if !auth::check_password(user.password_hash.clone(), body.mot_de_passe.clone()).await {
        return Err(fail("mot de passe incorrect").await);
    }

    // 1. Mot de passe provisoire : à changer d'abord.
    if user.must_change_password {
        let Some(new) = body.nouveau_mot_de_passe.as_deref().filter(|p| !p.is_empty()) else {
            state.limits.forgive(&body.login, &ip);
            return Ok(Json(json!({ "etat": "changer_mot_de_passe" })));
        };
        if new == body.mot_de_passe {
            return Err(err(
                StatusCode::BAD_REQUEST,
                t!("Choose a password different from the temporary one", "Choisissez un mot de passe différent du mot de passe provisoire"),
            ));
        }
        let hash = auth::hash_password(new)?;
        sqlx::query("UPDATE users SET password_hash = $2, must_change_password = false WHERE id = $1")
            .bind(user.id)
            .bind(hash)
            .execute(&state.db)
            .await?;
        audit::note(
            &state.db,
            &user.login,
            "compte.mot_de_passe",
            json!({ "par": "utilisateur", "adresse": ip }),
        )
        .await;
    }

    // 2. Code : selon la politique du compte.
    let policy = user.policy(&state.db).await?;
    let password_only = BTreeSet::from([Factor::Password]);
    let mut factors = vec!["mot de passe"];
    if !policy.satisfied(&password_only) {
        if !policy.could_use(&password_only, Factor::Totp) {
            return Err(err(
                StatusCode::FORBIDDEN,
                t!("This account signs in with an SSH key: sign-in from Portunia unavailable", "Ce compte se connecte par clé SSH : connexion depuis Portunia indisponible"),
            ));
        }
        let code = body.code.as_deref().unwrap_or("").trim().to_string();
        match &user.totp_secret {
            // Pas encore enrôlé : on propose un secret, confirmé par un premier code juste.
            None => {
                // Un code tapé avant d'avoir vu le code QR (ancien secret, autre outil) ne compte pas :
                // on affiche d'abord le code QR au lieu de refuser.
                let shown = user.totp_pending.is_some();
                let code = if shown { code } else { String::new() };
                let sealed = match &user.totp_pending {
                    Some(sealed) => sealed.clone(),
                    None => {
                        let sealed = state.keys.seal(&format!("totp:{}", user.id), &random::<20>()?)?;
                        sqlx::query("UPDATE users SET totp_pending = $2 WHERE id = $1")
                            .bind(user.id)
                            .bind(&sealed)
                            .execute(&state.db)
                            .await?;
                        sealed
                    }
                };
                let secret = state.keys.open(&format!("totp:{}", user.id), &sealed)?;
                let step = (!code.is_empty()).then(|| auth::totp_check(&secret, &code, 0)).flatten();
                let Some(step) = step else {
                    if !code.is_empty() {
                        return Err(fail("code d'enrôlement incorrect").await);
                    }
                    state.limits.forgive(&body.login, &ip);
                    let issuer = setting_str(state, "nom", "Portunia Gate").await?;
                    return Ok(Json(json!({
                        "etat": "enrolement",
                        "secret": auth::base32(&secret),
                        "uri": auth::otpauth_uri(&issuer, &user.login, &secret),
                    })));
                };
                sqlx::query("UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = $2 WHERE id = $1")
                    .bind(user.id)
                    .bind(step)
                    .execute(&state.db)
                    .await?;
                audit::note(
                    &state.db,
                    &user.login,
                    "compte.totp_enrole",
                    json!({ "par": "utilisateur", "adresse": ip }),
                )
                .await;
            }
            Some(sealed) => {
                if code.is_empty() {
                    state.limits.forgive(&body.login, &ip);
                    return Ok(Json(json!({ "etat": "code_requis" })));
                }
                let secret = state.keys.open(&format!("totp:{}", user.id), sealed)?;
                let ok = match auth::totp_check(&secret, &code, user.totp_last_step) {
                    Some(step) => model::consume_totp_step(&state.db, user.id, step).await?,
                    None => false,
                };
                if !ok {
                    return Err(fail("code incorrect ou déjà utilisé").await);
                }
            }
        }
        factors.push("code");
    }

    // 3. Jeton de session.
    state.limits.success(&body.login, &ip);
    let jeton = token()?;
    let expires = Utc::now() + chrono::Duration::hours(session_hours(state).await?);
    let client = body.client.unwrap_or_default().chars().take(80).collect::<String>();
    sqlx::query("INSERT INTO api_sessions (token_hash, user_id, expires_at, client, address) VALUES ($1, $2, $3, $4, $5)")
        .bind(sha256_hex(jeton.as_bytes()))
        .bind(user.id)
        .bind(expires)
        .bind(&client)
        .bind(&ip)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM api_sessions WHERE expires_at < now()")
        .execute(&state.db)
        .await?;
    audit::note(
        &state.db,
        &user.login,
        "auth.reussie",
        json!({ "facteurs": factors, "via": "portunia", "client": client, "adresse": ip }),
    )
    .await;
    Ok(Json(json!({
        "etat": "ok",
        "jeton": jeton,
        "expire": expires,
        "compte": { "login": user.login, "role": user.role },
        "gate": gate_info(state).await?,
    })))
}

async fn logout(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    if let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        sqlx::query("DELETE FROM api_sessions WHERE token_hash = $1")
            .bind(sha256_hex(bearer.as_bytes()))
            .execute(&api.state.db)
            .await?;
    }
    Ok(Json(json!({ "etat": "ok" })))
}

async fn me(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    let user = caller(&api, &headers).await?;
    Ok(Json(
        json!({ "compte": { "login": user.login, "role": user.role }, "gate": gate_info(&api.state).await? }),
    ))
}

fn mode_label(mode: &str) -> &'static str {
    match mode {
        "coffre" => "coffre",
        "enregistre" => "enregistre",
        _ => "rebond",
    }
}

async fn servers(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    let user = caller(&api, &headers).await?;
    let native = crate::rdpnative::settings(&api.state).await?;
    let mut out = Vec::new();
    for t in model::targets(&api.state.db).await? {
        if let Some(access) = model::access(&api.state.db, user.id, t.id).await? {
            out.push(json!({
                "nom": t.name,
                "dossier": t.folder,
                "mode": mode_label(&t.mode),
                "hote": t.host,
                "port": t.port,
                "compte": t.account,
                "protocole": t.protocole,
                "description": t.description,
                "sftp": access.sftp && t.vaulted(),
                "tunnels": access.tunnels && t.vaulted(),
                // Entrée RDP native ouverte pour ce serveur (fichier .rdp pour mstsc, Remmina…).
                "rdp_natif": native.enabled && t.is_rdp() && native.allows(&t.mode),
            }));
        }
    }
    Ok(Json(json!({ "serveurs": out })))
}

/// Jeton SSH à usage unique (valable 60 s) : Portunia s'en sert comme mot de passe
/// de « login%serveur » sur le port SSH de la Gate.
async fn ticket(AxState(api): Ctx, headers: HeaderMap, Path(nom): Path<String>) -> ApiResult {
    let user = caller(&api, &headers).await?;
    let db = &api.state.db;
    let target = model::target_by_name(db, &nom)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown server", "Serveur inconnu")))?;
    if model::access(db, user.id, target.id).await?.is_none() {
        audit::note(
            db,
            &user.login,
            "acces.refuse",
            json!({ "cible": target.name, "raison": "aucune règle active", "via": "portunia" }),
        )
        .await;
        return Err(err(
            StatusCode::FORBIDDEN,
            t!(format!("{} is not allowed for you at the moment", target.name), format!("{} ne vous est pas autorisé en ce moment", target.name)),
        ));
    }
    let ticket = issue_ticket(db, user.id, target.id, None).await?;
    Ok(Json(json!({
        "ticket": ticket,
        "utilisateur_ssh": format!("{}%{}", user.login, target.name),
        "port_ssh": api.state.config.ssh_public_port,
        "mode": mode_label(&target.mode),
        "hote": target.host,
        "port": target.port,
        "compte": target.account,
        "protocole": target.protocole,
    })))
}

/// Jeton SSH à usage unique (60 s) pour ce compte et ce serveur. `client_addr` : adresse
/// réelle de l'utilisateur quand c'est le portail web qui se connecte pour lui.
pub async fn issue_ticket(db: &sqlx::PgPool, user: Uuid, target: Uuid, client_addr: Option<&str>) -> anyhow::Result<String> {
    issue_ticket_for(db, user, target, client_addr, 60).await
}

/// Même jeton, valable `seconds` secondes (fichier .rdp de l'entrée native).
pub async fn issue_ticket_for(db: &sqlx::PgPool, user: Uuid, target: Uuid, client_addr: Option<&str>, seconds: i64) -> anyhow::Result<String> {
    let ticket = format!("hj1_{}", token()?);
    sqlx::query("DELETE FROM ssh_tickets WHERE expires_at < now()").execute(db).await?;
    sqlx::query(
        "INSERT INTO ssh_tickets (ticket_hash, user_id, target_id, expires_at, client_addr) VALUES ($1, $2, $3, now() + make_interval(secs => $5), $4)",
    )
    .bind(sha256_hex(ticket.as_bytes()))
    .bind(user)
    .bind(target)
    .bind(client_addr)
    .bind(seconds as f64)
    .execute(db)
    .await?;
    Ok(ticket)
}

/// Jeton présenté sans compte ni serveur (passage Bureau à distance) : consommé, il dit
/// pour qui et vers quoi il a été émis, et l'adresse réelle qu'il porte.
pub async fn take_ticket(db: &sqlx::PgPool, ticket: &str) -> anyhow::Result<Option<(Uuid, Uuid, Option<String>)>> {
    Ok(sqlx::query_as(
        "DELETE FROM ssh_tickets WHERE ticket_hash = $1 AND expires_at > now() RETURNING user_id, target_id, client_addr",
    )
    .bind(sha256_hex(ticket.as_bytes()))
    .fetch_optional(db)
    .await?)
}

/// Utilisé par le serveur SSH : un jeton valide pour ce compte et ce serveur est consommé.
/// Renvoie `Some(adresse réelle)` (vide si le jeton n'en porte pas), `None` s'il est refusé.
pub async fn consume_ticket(db: &sqlx::PgPool, ticket: &str, user: Uuid, target: Option<Uuid>) -> anyhow::Result<Option<String>> {
    let Some(target) = target else { return Ok(None) };
    let done: Option<Option<String>> = sqlx::query_scalar(
        "DELETE FROM ssh_tickets WHERE ticket_hash = $1 AND user_id = $2 AND target_id = $3 AND expires_at > now() RETURNING client_addr",
    )
    .bind(sha256_hex(ticket.as_bytes()))
    .bind(user)
    .bind(target)
    .fetch_optional(db)
    .await?;
    Ok(done.map(Option::unwrap_or_default))
}

// ---------- Administration : cibles ----------

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SecretBody {
    MotDePasse {
        valeur: String,
    },
    Cle {
        valeur: String,
    },
    /// Portunia Gate crée une clé et l'installe avec ce mot de passe, utilisé une seule fois.
    Generer {
        mot_de_passe: String,
    },
}

#[derive(Deserialize)]
struct TargetBody {
    nom: String,
    #[serde(default)]
    dossier: String,
    hote: String,
    #[serde(default = "default_port")]
    port: i32,
    mode: String,
    compte: Option<String>,
    secret: Option<SecretBody>,
    /// ssh (par défaut), rdp, http ou https.
    #[serde(default = "default_protocol")]
    protocole: String,
    /// Interface web en mode coffre : auto (par défaut), remplir ou basic.
    #[serde(default)]
    connexion_web: Option<String>,
    /// Texte de la vignette ; absent : inchangé (modification) ou vide (création).
    #[serde(default)]
    description: Option<String>,
}

fn default_port() -> i32 {
    22
}

fn default_protocol() -> String {
    "ssh".into()
}

fn target_json(t: &model::Target) -> Value {
    json!({
        "id": t.id,
        "nom": t.name,
        "dossier": t.folder,
        "hote": t.host,
        "port": t.port,
        "mode": mode_label(&t.mode),
        "compte": t.account,
        "secret": t.secret_kind,
        "empreinte": t.host_key,
        "protocole": t.protocole,
        "connexion_web": t.web_connexion,
        "description": t.description,
    })
}

/// Connexion web demandée (vérifiée par check_target), sinon celle donnée.
fn web_login_of(asked: Option<&str>, otherwise: &str) -> String {
    asked.and_then(|w| model::web_login(w).ok()).unwrap_or_else(|| otherwise.to_string())
}

async fn admin_targets(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    let list: Vec<Value> = model::targets(&api.state.db).await?.iter().map(target_json).collect();
    Ok(Json(json!({ "cibles": list })))
}

fn check_target(body: &TargetBody) -> Result<(), ApiError> {
    if body.nom.trim().is_empty() || body.hote.trim().is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, t!("Name and address required", "Nom et adresse obligatoires")));
    }
    if !(1..=65535).contains(&body.port) {
        return Err(err(StatusCode::BAD_REQUEST, t!("Port: 1 to 65535", "Port : 1 à 65535")));
    }
    if body.nom.contains('%') || body.nom.contains(char::is_whitespace) {
        return Err(err(StatusCode::BAD_REQUEST, t!("The name must contain neither spaces nor « % »", "Le nom ne doit contenir ni espace ni « % »")));
    }
    model::check_protocol(&body.protocole, &body.mode).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    if body.protocole != "ssh" && matches!(&body.secret, Some(SecretBody::Generer { .. }) | Some(SecretBody::Cle { .. })) {
        return Err(err(StatusCode::BAD_REQUEST, t!("Remote Desktop and web: the vault keeps a password, not an SSH key", "Bureau à distance et web : le coffre garde un mot de passe, pas une clé SSH")));
    }
    if let Some(w) = &body.connexion_web {
        model::web_login(w).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    }
    if let Some(d) = &body.description {
        model::check_description(d).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    }
    Ok(())
}

/// Secret en clair prêt à chiffrer : (type, contenu).
async fn resolve_secret(api: &Api, actor: &str, probe: &model::Target, secret: SecretBody) -> Result<(String, Vec<u8>), ApiError> {
    Ok(match secret {
        SecretBody::MotDePasse { valeur } => ("password".into(), valeur.into_bytes()),
        SecretBody::Cle { valeur } => {
            russh::keys::decode_secret_key(&valeur, None).map_err(|e| {
                err(
                    StatusCode::BAD_REQUEST,
                    t!(format!("Unreadable private key (without passphrase): {e}"), format!("Clé privée illisible (sans phrase de passe) : {e}")),
                )
            })?;
            ("key".into(), valeur.into_bytes())
        }
        SecretBody::Generer { mot_de_passe } => {
            let account = probe
                .account
                .clone()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, t!("Give the account on the server", "Indiquez le compte sur le serveur")))?;
            let key = crate::target::install_new_key(&api.state, probe, &account, &mot_de_passe, actor).await?;
            audit::note(
                &api.state.db,
                actor,
                "cible.cle_installee",
                json!({ "cible": probe.name, "compte": account }),
            )
            .await;
            ("key".into(), key.into_bytes())
        }
    })
}

async fn admin_target_create(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<TargetBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    check_target(&body)?;
    let probe = model::Target {
        id: Uuid::new_v4(),
        name: body.nom.trim().into(),
        folder: body.dossier.trim().into(),
        host: body.hote.trim().into(),
        port: body.port,
        mode: body.mode.clone(),
        account: body.compte.clone().filter(|a| !a.trim().is_empty()),
        secret_kind: "none".into(),
        secret: None,
        host_key: None,
        protocole: body.protocole.clone(),
        web_connexion: web_login_of(body.connexion_web.as_deref(), "auto"),
        description: body.description.clone().unwrap_or_default(),
    };
    let secret = match body.secret {
        Some(s) => Some(resolve_secret(&api, &actor.login, &probe, s).await?),
        None => None,
    };
    let new = model::NewTarget {
        name: probe.name.clone(),
        folder: probe.folder.clone(),
        host: probe.host.clone(),
        port: probe.port,
        mode: probe.mode.clone(),
        account: probe.account.clone(),
        secret_kind: secret.as_ref().map(|s| s.0.clone()).unwrap_or_else(|| "none".into()),
        protocole: probe.protocole.clone(),
        web_connexion: probe.web_connexion.clone(),
        description: probe.description.clone(),
    };
    let keys = &api.state.keys;
    let id = model::create_target(&api.state.db, new, |id| match &secret {
        Some((_, plain)) => Ok(Some(keys.seal(&format!("cible:{id}"), plain)?)),
        None => Ok(None),
    })
    .await?;
    audit::note(
        &api.state.db,
        &actor.login,
        "cible.creee",
        json!({ "cible": probe.name, "adresse": format!("{}:{}", probe.host, probe.port), "mode": probe.mode, "protocole": probe.protocole }),
    )
    .await;
    Ok(Json(json!({ "id": id })))
}

async fn admin_target_update(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>, Json(body): Json<TargetBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    check_target(&body)?;
    let db = &api.state.db;
    let current = model::target_by_id(db, id)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown server", "Serveur inconnu")))?;
    let mut probe = current.clone();
    probe.host = body.hote.trim().into();
    probe.port = body.port;
    probe.account = body.compte.clone().filter(|a| !a.trim().is_empty());
    // Changement d'adresse : l'ancienne empreinte ne vaut plus, et le secret du coffre doit être
    // ressaisi, sinon un jeton volé suffirait à l'envoyer vers un autre serveur.
    let moved = probe.host != current.host || probe.port != current.port;
    if moved {
        probe.host_key = None;
        if body.secret.is_none() && current.secret.is_some() {
            return Err(err(
                StatusCode::BAD_REQUEST,
                t!("The address changes: type the vault secret again", "L'adresse change : ressaisissez le secret du coffre"),
            ));
        }
    }
    let (kind, sealed) = match body.secret {
        Some(s) => {
            let (kind, plain) = resolve_secret(&api, &actor.login, &probe, s).await?;
            (kind, Some(api.state.keys.seal(&current.secret_purpose(), &plain)?))
        }
        None => (current.secret_kind.clone(), current.secret.clone()),
    };
    if body.mode == "coffre" && (probe.account.is_none() || sealed.is_none()) {
        return Err(err(StatusCode::BAD_REQUEST, t!("In vault mode, give the account and its secret", "En mode coffre, indiquez le compte et son secret")));
    }
    if !["rebond", "enregistre", "coffre"].contains(&body.mode.as_str()) {
        return Err(err(StatusCode::BAD_REQUEST, t!("Mode: jump (rebond), recorded (enregistre) or vault (coffre)", "Mode : rebond, enregistre ou coffre")));
    }
    sqlx::query(
        "UPDATE targets SET name = $2, folder = $3, host = $4, port = $5, mode = $6, account = $7, secret_kind = $8, secret = $9, host_key = $10,
                protocole = $11, web_connexion = $12, description = $13
         WHERE id = $1",
    )
    .bind(id)
    .bind(body.nom.trim())
    .bind(body.dossier.trim())
    .bind(&probe.host)
    .bind(probe.port)
    .bind(&body.mode)
    .bind(&probe.account)
    .bind(&kind)
    .bind(sealed)
    .bind(&probe.host_key)
    .bind(&body.protocole)
    .bind(web_login_of(body.connexion_web.as_deref(), &current.web_connexion))
    .bind(match &body.description {
        Some(d) => model::check_description(d).unwrap_or_default(),
        None => current.description.clone(),
    })
    .execute(db)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.code().as_deref() == Some("23505") => err(StatusCode::CONFLICT, t!("This name is already taken", "Ce nom est déjà pris")),
        _ => e.into(),
    })?;
    api.state.live.recheck();
    audit::note(
        db,
        &actor.login,
        "cible.modifiee",
        json!({ "cible": body.nom, "avant": current.name, "mode": body.mode, "adresse": format!("{}:{}", probe.host, probe.port), "adresse_avant": format!("{}:{}", current.host, current.port) }),
    )
    .await;
    Ok(Json(json!({ "etat": "ok" })))
}

async fn admin_target_delete(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let t = model::target_by_id(db, id)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown server", "Serveur inconnu")))?;
    sqlx::query("DELETE FROM targets WHERE id = $1").bind(id).execute(db).await?;
    api.state.live.recheck();
    audit::note(db, &actor.login, "cible.supprimee", json!({ "cible": t.name })).await;
    Ok(Json(json!({ "etat": "ok" })))
}

async fn admin_target_forget_key(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let t = model::target_by_id(db, id)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown server", "Serveur inconnu")))?;
    sqlx::query("UPDATE targets SET host_key = NULL WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    audit::note(
        db,
        &actor.login,
        "cible.empreinte_oubliee",
        json!({ "cible": t.name, "ancienne": t.host_key }),
    )
    .await;
    Ok(Json(json!({ "etat": "ok" })))
}

// ---------- Administration : comptes et groupes ----------

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    login: String,
    role: String,
    auth_policy: Option<String>,
    disabled: bool,
    enrolled: bool,
    must_change_password: bool,
    groups: Vec<String>,
    keys: i64,
    email: String,
}

async fn admin_users(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    let rows: Vec<UserRow> = sqlx::query_as(
        "SELECT u.id, u.login, u.role, u.auth_policy, u.disabled, u.totp_secret IS NOT NULL AS enrolled, u.must_change_password, u.email,
                COALESCE(array_agg(g.name ORDER BY g.name) FILTER (WHERE g.name IS NOT NULL), '{}') AS groups,
                (SELECT count(*) FROM user_keys k WHERE k.user_id = u.id) AS keys
         FROM users u LEFT JOIN group_members m ON m.user_id = u.id LEFT JOIN groups g ON g.id = m.group_id
         GROUP BY u.id ORDER BY u.login",
    )
    .fetch_all(&api.state.db)
    .await?;
    let list: Vec<Value> = rows
        .into_iter()
        .map(|u| {
            json!({
                "id": u.id, "login": u.login, "role": u.role, "politique": u.auth_policy, "desactive": u.disabled,
                "code_enrole": u.enrolled, "mot_de_passe_provisoire": u.must_change_password, "groupes": u.groups, "cles": u.keys, "email": u.email,
            })
        })
        .collect();
    Ok(Json(
        json!({ "comptes": list, "politique_generale": model::default_policy(&api.state.db).await?.to_string() }),
    ))
}

#[derive(Deserialize)]
struct UserBody {
    login: Option<String>,
    role: String,
    politique: Option<String>,
    #[serde(default)]
    groupes: Vec<String>,
    #[serde(default)]
    desactive: bool,
    /// Adresse e-mail (notifications) ; absente : inchangée.
    email: Option<String>,
}

/// Adresse e-mail vérifiée (vide : aucune).
fn clean_email(v: &str) -> Result<String, ApiError> {
    let v = v.trim();
    if !v.is_empty() && v.parse::<lettre::Address>().is_err() {
        return Err(err(StatusCode::BAD_REQUEST, t!("Not an e-mail address", "Ce n'est pas une adresse e-mail")));
    }
    Ok(v.to_string())
}

async fn set_groups(db: &sqlx::PgPool, user: Uuid, groups: &[String]) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM group_members WHERE user_id = $1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    for name in groups {
        let gid: Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE name = $1")
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| anyhow!(t!(format!("Unknown group: {name}"), format!("Groupe inconnu : {name}"))))?;
        sqlx::query("INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)")
            .bind(gid)
            .bind(user)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

fn clean_policy(p: Option<String>) -> Result<Option<String>, ApiError> {
    match p.filter(|p| !p.trim().is_empty()) {
        Some(p) => Ok(Some(auth::Policy::parse(&p)?.to_string())),
        None => Ok(None),
    }
}

async fn admin_user_create(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<UserBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let login = body.login.unwrap_or_default().trim().to_string();
    let password = auth::temp_password()?;
    let id = model::create_user(
        db,
        &login,
        &body.role,
        Some(auth::hash_password(&password)?),
        clean_policy(body.politique)?,
    )
    .await?;
    sqlx::query("UPDATE users SET must_change_password = true WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    set_groups(db, id, &body.groupes).await?;
    if let Some(email) = &body.email {
        sqlx::query("UPDATE users SET email = $2 WHERE id = $1").bind(id).bind(clean_email(email)?).execute(db).await?;
    }
    audit::note(
        db,
        &actor.login,
        "compte.cree",
        json!({ "compte": login, "role": body.role, "groupes": body.groupes }),
    )
    .await;
    Ok(Json(json!({ "id": id, "mot_de_passe_provisoire": password })))
}

async fn admin_user_update(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>, Json(body): Json<UserBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let user = model::user_by_id(db, id)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown account", "Compte inconnu")))?;
    if !["user", "auditor", "admin"].contains(&body.role.as_str()) {
        return Err(err(StatusCode::BAD_REQUEST, t!("Role: user, auditor or admin", "Rôle : user, auditor ou admin")));
    }
    if user.id == actor.id && (body.role != "admin" || body.desactive) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            t!("You cannot remove your own administrator rights", "Vous ne pouvez pas retirer vos propres droits d'administrateur"),
        ));
    }
    sqlx::query("UPDATE users SET role = $2, auth_policy = $3, disabled = $4 WHERE id = $1")
        .bind(id)
        .bind(&body.role)
        .bind(clean_policy(body.politique)?)
        .bind(body.desactive)
        .execute(db)
        .await?;
    set_groups(db, id, &body.groupes).await?;
    if let Some(email) = &body.email {
        sqlx::query("UPDATE users SET email = $2 WHERE id = $1").bind(id).bind(clean_email(email)?).execute(db).await?;
    }
    if body.desactive {
        model::revoke_logins(db, id).await?;
    }
    api.state.live.recheck();
    audit::note(
        db,
        &actor.login,
        "compte.modifie",
        json!({ "compte": user.login, "role": body.role, "groupes": body.groupes, "desactive": body.desactive }),
    )
    .await;
    Ok(Json(json!({ "etat": "ok" })))
}

async fn admin_user_delete(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    if id == actor.id {
        return Err(err(StatusCode::BAD_REQUEST, t!("You cannot delete your own account", "Vous ne pouvez pas supprimer votre propre compte")));
    }
    let user = model::user_by_id(db, id)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown account", "Compte inconnu")))?;
    sqlx::query("DELETE FROM users WHERE id = $1").bind(id).execute(db).await?;
    api.state.live.recheck();
    audit::note(db, &actor.login, "compte.supprime", json!({ "compte": user.login })).await;
    Ok(Json(json!({ "etat": "ok" })))
}

async fn admin_user_reset_totp(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let user = model::user_by_id(db, id)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown account", "Compte inconnu")))?;
    sqlx::query("UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = 0 WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    model::revoke_logins(db, id).await?;
    api.state.live.cut_user(id, t!("Your sign-in was reset by an administrator", "Votre connexion a été réinitialisée par un administrateur"));
    audit::note(db, &actor.login, "compte.totp_reinitialise", json!({ "compte": user.login })).await;
    Ok(Json(json!({ "etat": "ok" })))
}

async fn admin_user_temp_password(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let user = model::user_by_id(db, id)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown account", "Compte inconnu")))?;
    let password = auth::temp_password()?;
    sqlx::query("UPDATE users SET password_hash = $2, must_change_password = true WHERE id = $1")
        .bind(id)
        .bind(auth::hash_password(&password)?)
        .execute(db)
        .await?;
    model::revoke_logins(db, id).await?;
    api.state.live.cut_user(id, t!("Your sign-in was reset by an administrator", "Votre connexion a été réinitialisée par un administrateur"));
    audit::note(db, &actor.login, "compte.mot_de_passe_provisoire", json!({ "compte": user.login })).await;
    Ok(Json(json!({ "mot_de_passe_provisoire": password })))
}

#[derive(Deserialize)]
struct KeyBody {
    cle: String,
}

async fn admin_user_add_key(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>, Json(body): Json<KeyBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let user = model::user_by_id(db, id)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown account", "Compte inconnu")))?;
    let public = russh::keys::PublicKey::from_openssh(body.cle.trim())
        .map_err(|e| err(StatusCode::BAD_REQUEST, t!(format!("Unreadable public key: {e}"), format!("Clé publique illisible : {e}"))))?;
    let fp = public.fingerprint(russh::keys::HashAlg::Sha256).to_string();
    model::add_user_key(db, id, body.cle.trim(), &fp, &String::from_utf8_lossy(public.comment().as_bytes())).await?;
    audit::note(
        db,
        &actor.login,
        "compte.cle_ajoutee",
        json!({ "compte": user.login, "empreinte": fp }),
    )
    .await;
    Ok(Json(json!({ "empreinte": fp })))
}

#[derive(sqlx::FromRow)]
struct GroupRow {
    id: Uuid,
    name: String,
    members: Vec<String>,
}

async fn admin_groups(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    let rows: Vec<GroupRow> = sqlx::query_as(
        "SELECT g.id, g.name, COALESCE(array_agg(u.login ORDER BY u.login) FILTER (WHERE u.login IS NOT NULL), '{}') AS members
         FROM groups g LEFT JOIN group_members m ON m.group_id = g.id LEFT JOIN users u ON u.id = m.user_id
         GROUP BY g.id ORDER BY g.name",
    )
    .fetch_all(&api.state.db)
    .await?;
    let list: Vec<Value> = rows
        .into_iter()
        .map(|g| json!({ "id": g.id, "nom": g.name, "membres": g.members }))
        .collect();
    Ok(Json(json!({ "groupes": list })))
}

#[derive(Deserialize)]
struct GroupBody {
    nom: String,
}

async fn admin_group_create(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<GroupBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let name = body.nom.trim();
    if name.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, t!("Group name required", "Nom du groupe obligatoire")));
    }
    let id = model::create_group(&api.state.db, name).await?;
    audit::note(&api.state.db, &actor.login, "groupe.cree", json!({ "groupe": name })).await;
    Ok(Json(json!({ "id": id })))
}

async fn admin_group_delete(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let name: Option<String> = sqlx::query_scalar("DELETE FROM groups WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(db)
        .await?;
    let name = name.ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown group", "Groupe inconnu")))?;
    api.state.live.recheck();
    audit::note(db, &actor.login, "groupe.supprime", json!({ "groupe": name })).await;
    Ok(Json(json!({ "etat": "ok" })))
}

// ---------- Administration : règles ----------

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: Uuid,
    name: String,
    group_name: String,
    allow_sftp: bool,
    allow_tunnels: bool,
    record_input: bool,
    allow_files: bool,
    days: i16,
    hour_from: Option<i16>,
    hour_to: Option<i16>,
    expires_at: Option<DateTime<Utc>>,
    targets: Vec<String>,
    approval: bool,
    approvers: Option<String>,
}

async fn admin_rules(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT r.id, r.name, g.name AS group_name, r.allow_sftp, r.allow_tunnels, r.record_input, r.allow_files, r.days, r.hour_from, r.hour_to, r.expires_at,
                COALESCE(array_agg(t.name ORDER BY t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS targets,
                r.approval, ag.name AS approvers
         FROM rules r JOIN groups g ON g.id = r.group_id LEFT JOIN groups ag ON ag.id = r.approver_group
         LEFT JOIN rule_targets rt ON rt.rule_id = r.id LEFT JOIN targets t ON t.id = rt.target_id
         GROUP BY r.id, g.name, ag.name ORDER BY r.name",
    )
    .fetch_all(&api.state.db)
    .await?;
    let list: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let state = model::rule_state(r.days, r.hour_from, r.hour_to, r.expires_at);
            json!({
                "id": r.id, "nom": r.name, "groupe": r.group_name, "cibles": r.targets, "sftp": r.allow_sftp,
                "tunnels": r.allow_tunnels, "frappe": r.record_input, "fichiers": r.allow_files, "jours": r.days, "heure_debut": r.hour_from,
                "heure_fin": r.hour_to, "expire": r.expires_at, "etat": state,
                "approbation": r.approval, "approbateurs": r.approvers,
            })
        })
        .collect();
    Ok(Json(json!({ "regles": list })))
}

#[derive(Deserialize)]
struct RuleBody {
    nom: String,
    groupe: String,
    cibles: Vec<String>,
    #[serde(default)]
    sftp: bool,
    #[serde(default)]
    tunnels: bool,
    #[serde(default)]
    frappe: bool,
    /// Bureau à distance : copie de fichiers. Absent : inchangé (Portunia antérieur à 0.64).
    fichiers: Option<bool>,
    #[serde(default = "all_days")]
    jours: i16,
    heure_debut: Option<i16>,
    heure_fin: Option<i16>,
    /// Date de fin (AAAA-MM-JJ), incluse.
    expire: Option<String>,
    /// Accès seulement après approbation (0.38). Absent : inchangé.
    approbation: Option<bool>,
    /// Groupe des approbateurs ; vide : les administrateurs. Absent : inchangé.
    approbateurs: Option<String>,
}

/// Approbation d'une règle (après création ou modification).
async fn rule_approval(db: &sqlx::PgPool, id: Uuid, body: &RuleBody) -> Result<(), ApiError> {
    if let Some(on) = body.approbation {
        sqlx::query("UPDATE rules SET approval = $2 WHERE id = $1").bind(id).bind(on).execute(db).await.map_err(anyhow::Error::from)?;
    }
    if let Some(name) = &body.approbateurs {
        let group = match name.trim() {
            "" => None,
            n => Some(model::group_id(db, n).await?),
        };
        sqlx::query("UPDATE rules SET approver_group = $2 WHERE id = $1").bind(id).bind(group).execute(db).await.map_err(anyhow::Error::from)?;
    }
    Ok(())
}

fn all_days() -> i16 {
    127
}

async fn rule_parts(db: &sqlx::PgPool, body: &RuleBody) -> Result<(Uuid, Vec<Uuid>, Option<(i16, i16)>, Option<DateTime<Utc>>), ApiError> {
    if body.nom.trim().is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, t!("Rule name required", "Nom de la règle obligatoire")));
    }
    let group = model::group_id(db, &body.groupe).await?;
    let mut targets = Vec::new();
    for name in &body.cibles {
        targets.push(
            model::target_by_name(db, name)
                .await?
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, t!(format!("Unknown server: {name}"), format!("Serveur inconnu : {name}"))))?
                .id,
        );
    }
    if targets.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, t!("Choose at least one server", "Choisissez au moins un serveur")));
    }
    if !(0..=127).contains(&body.jours) || body.jours == 0 {
        return Err(err(StatusCode::BAD_REQUEST, t!("Choose at least one day", "Choisissez au moins un jour")));
    }
    let hours = match (body.heure_debut, body.heure_fin) {
        (Some(a), Some(b)) if (0..=23).contains(&a) && (1..=24).contains(&b) && a != b => Some((a, b)),
        (None, None) => None,
        _ => return Err(err(StatusCode::BAD_REQUEST, t!("Hours: start from 0 to 23, end from 1 to 24, different", "Heures : début de 0 à 23, fin de 1 à 24, différentes"))),
    };
    let expires = match body.expire.as_deref().filter(|e| !e.is_empty()) {
        Some(d) => {
            let date = chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| err(StatusCode::BAD_REQUEST, t!("Date: YYYY-MM-DD", "Date : AAAA-MM-JJ")))?;
            let end = date.and_hms_opt(23, 59, 59).unwrap().and_local_timezone(chrono::Local).single();
            Some(end.ok_or_else(|| err(StatusCode::BAD_REQUEST, t!("Ambiguous date", "Date ambiguë")))?.with_timezone(&Utc))
        }
        None => None,
    };
    Ok((group, targets, hours, expires))
}

async fn admin_rule_create(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<RuleBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let (group, targets, hours, expires_at) = rule_parts(db, &body).await?;
    let id = model::create_rule(
        db,
        model::NewRule {
            name: body.nom.trim().into(),
            group,
            targets,
            allow_sftp: body.sftp,
            allow_tunnels: body.tunnels,
            record_input: body.frappe,
            allow_files: body.fichiers.unwrap_or(false),
            days: body.jours,
            hours,
            expires_at,
        },
    )
    .await?;
    rule_approval(db, id, &body).await?;
    audit::note(db, &actor.login, "regle.creee", json!({ "regle": body.nom, "groupe": body.groupe, "cibles": body.cibles, "sftp": body.sftp, "tunnels": body.tunnels, "frappe": body.frappe, "fichiers": body.fichiers.unwrap_or(false) })).await;
    Ok(Json(json!({ "id": id })))
}

async fn admin_rule_update(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>, Json(body): Json<RuleBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let (group, targets, hours, expires_at) = rule_parts(db, &body).await?;
    let mut tx = db.begin().await?;
    let done = sqlx::query(
        "UPDATE rules SET name = $2, group_id = $3, allow_sftp = $4, allow_tunnels = $5, record_input = $6, days = $7,
         hour_from = $8, hour_to = $9, expires_at = $10, allow_files = COALESCE($11, allow_files) WHERE id = $1",
    )
    .bind(id)
    .bind(body.nom.trim())
    .bind(group)
    .bind(body.sftp)
    .bind(body.tunnels)
    .bind(body.frappe)
    .bind(body.jours)
    .bind(hours.map(|h| h.0))
    .bind(hours.map(|h| h.1))
    .bind(expires_at)
    .bind(body.fichiers)
    .execute(&mut *tx)
    .await?;
    if done.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, t!("Unknown rule", "Règle inconnue")));
    }
    sqlx::query("DELETE FROM rule_targets WHERE rule_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for t in targets {
        sqlx::query("INSERT INTO rule_targets (rule_id, target_id) VALUES ($1, $2)")
            .bind(id)
            .bind(t)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    rule_approval(db, id, &body).await?;
    api.state.live.recheck();
    audit::note(db, &actor.login, "regle.modifiee", json!({ "regle": body.nom, "groupe": body.groupe, "cibles": body.cibles, "sftp": body.sftp, "tunnels": body.tunnels, "frappe": body.frappe, "jours": body.jours, "fichiers": body.fichiers, "heures": hours, "expire": body.expire })).await;
    Ok(Json(json!({ "etat": "ok" })))
}

async fn admin_rule_delete(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let name: Option<String> = sqlx::query_scalar("DELETE FROM rules WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(db)
        .await?;
    let name = name.ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown rule", "Règle inconnue")))?;
    api.state.live.recheck();
    audit::note(db, &actor.login, "regle.supprimee", json!({ "regle": name })).await;
    Ok(Json(json!({ "etat": "ok" })))
}

// ---------- Journal, sessions, réglages ----------

#[derive(Deserialize)]
struct JournalQuery {
    limite: Option<i64>,
    q: Option<String>,
}

async fn journal_rows(api: &Api, query: &JournalQuery) -> Result<Vec<audit::Entry>, ApiError> {
    let limit = query.limite.unwrap_or(200).clamp(1, 5000);
    let filter = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|q| !q.is_empty())
        // PostgreSQL refuse le caractère nul dans un texte : il ne doit pas devenir une erreur 500.
        .map(|q| format!("%{}%", q.replace(['%', '\0'], "")));
    let mut rows: Vec<audit::Entry> = sqlx::query_as(
        "SELECT * FROM audit WHERE $2::text IS NULL OR actor ILIKE $2 OR event ILIKE $2 OR detail::text ILIKE $2 ORDER BY seq DESC LIMIT $1",
    )
    .bind(limit)
    .bind(filter)
    .fetch_all(&api.state.db)
    .await?;
    rows.reverse();
    Ok(rows)
}

async fn admin_journal(AxState(api): Ctx, headers: HeaderMap, Query(query): Query<JournalQuery>) -> ApiResult {
    auditor(&api, &headers).await?;
    let list: Vec<Value> = journal_rows(&api, &query)
        .await?
        .into_iter()
        .map(|e| json!({ "seq": e.seq, "date": e.at, "qui": e.actor, "evenement": e.event, "detail": e.detail }))
        .collect();
    Ok(Json(json!({ "evenements": list })))
}

async fn admin_journal_verify(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    auditor(&api, &headers).await?;
    Ok(Json(match audit::verify(&api.state.db).await? {
        Ok(n) => json!({ "intact": true, "evenements": n }),
        Err(broken) => json!({ "intact": false, "probleme": broken }),
    }))
}

pub(crate) fn csv_field(text: &str) -> String {
    // Une cellule qui commence par = + - @, une tabulation ou un retour serait lue comme une
    // formule par un tableur.
    let safe = if text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{text}")
    } else {
        text.to_string()
    };
    format!("\"{}\"", safe.replace('"', "\"\""))
}

async fn admin_journal_csv(AxState(api): Ctx, headers: HeaderMap, Query(query): Query<JournalQuery>) -> Result<Response, ApiError> {
    auditor(&api, &headers).await?;
    let mut out = String::from("\u{feff}numero;date;qui;evenement;detail\n");
    for e in journal_rows(
        &api,
        &JournalQuery {
            limite: Some(query.limite.unwrap_or(5000)),
            q: query.q,
        },
    )
    .await?
    {
        out.push_str(&format!(
            "{};{};{};{};{}\n",
            e.seq,
            csv_field(&e.at.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string()),
            csv_field(&e.actor),
            csv_field(&e.event),
            csv_field(&e.detail.to_string())
        ));
    }
    Ok(([(header::CONTENT_TYPE, "text/csv; charset=utf-8")], out).into_response())
}

async fn admin_sessions(AxState(api): Ctx, headers: HeaderMap, Query(query): Query<JournalQuery>) -> ApiResult {
    auditor(&api, &headers).await?;
    let list: Vec<Value> = model::last_sessions(&api.state.db, query.limite.unwrap_or(200).clamp(1, 2000))
        .await?
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id, "compte": s.login, "serveur": s.target, "type": s.kind, "detail": s.detail, "adresse": s.client_addr,
                "debut": s.started_at, "fin": s.ended_at, "enregistree": s.recording.is_some(), "octets": s.bytes,
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": list })))
}

async fn admin_settings(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    let state = &api.state;
    Ok(Json(json!({
        "nom": setting_str(state, "nom", "Portunia Gate").await?,
        "banniere": setting_str(state, "banniere", crate::sshd::default_banner()).await?,
        "politique": model::default_policy(&state.db).await?.to_string(),
        "duree_session_h": session_hours(state).await?,
        "memo_mot_de_passe": remember_allowed(state).await?,
        "relecture_propres": own_sessions_allowed(state).await?,
        // Prévenir l'utilisateur d'une session suivie en direct (terminaux SSH).
        "direct_prevenir": live_notice(state).await?,
        "commandes_sensibles": sensitive_commands(state).await?,
        // Copies des fichiers copiés en Bureau à distance, gardées par session (Mo ; 0 : aucune).
        "copies_fichiers_mo": model::setting(&state.db, "copies_fichiers_mo").await?.and_then(|v| v.as_u64()).unwrap_or(0),
        // « en », « fr », ou vide : langue du système de la Gate.
        "langue": setting_str(state, "langue", "").await?,
        // Jours de conservation des enregistrements (0 : toujours) ; Gate 0.39.
        "conservation_jours": crate::status::retention_days(state).await?,
    })))
}

#[derive(Deserialize)]
struct SettingsBody {
    nom: Option<String>,
    banniere: Option<String>,
    politique: Option<String>,
    duree_session_h: Option<i64>,
    memo_mot_de_passe: Option<bool>,
    relecture_propres: Option<bool>,
    direct_prevenir: Option<bool>,
    commandes_sensibles: Option<Vec<String>>,
    langue: Option<String>,
    copies_fichiers_mo: Option<u64>,
    conservation_jours: Option<i64>,
}

async fn admin_settings_update(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<SettingsBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let mut changed = serde_json::Map::new();
    if let Some(v) = body.nom.filter(|v| !v.trim().is_empty()) {
        model::set_setting(db, "nom", json!(v.trim())).await?;
        changed.insert("nom".into(), json!(v.trim()));
    }
    if let Some(v) = body.banniere {
        model::set_setting(db, "banniere", json!(v)).await?;
        changed.insert("banniere".into(), json!(v));
    }
    if let Some(v) = body.politique {
        let p = auth::Policy::parse(&v)?.to_string();
        model::set_setting(db, "auth_policy", json!(p)).await?;
        changed.insert("politique".into(), json!(p));
    }
    if let Some(v) = body.duree_session_h {
        if !(1..=168).contains(&v) {
            return Err(err(StatusCode::BAD_REQUEST, t!("Session duration: 1 to 168 hours", "Durée de session : 1 à 168 heures")));
        }
        model::set_setting(db, "duree_session_h", json!(v)).await?;
        changed.insert("duree_session_h".into(), json!(v));
    }
    if let Some(v) = body.memo_mot_de_passe {
        model::set_setting(db, "memo_mot_de_passe", json!(v)).await?;
        changed.insert("memo_mot_de_passe".into(), json!(v));
    }
    if let Some(v) = body.relecture_propres {
        model::set_setting(db, "relecture_propres", json!(v)).await?;
        changed.insert("relecture_propres".into(), json!(v));
    }
    if let Some(v) = body.direct_prevenir {
        model::set_setting(db, "direct_prevenir", json!(v)).await?;
        changed.insert("direct_prevenir".into(), json!(v));
    }
    if let Some(list) = body.commandes_sensibles {
        let list: Vec<String> = list.into_iter().map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect();
        model::set_setting(db, "commandes_sensibles", json!(list)).await?;
        changed.insert("commandes_sensibles".into(), json!(list));
    }
    if let Some(v) = body.copies_fichiers_mo {
        if v > 10_240 {
            return Err(err(StatusCode::BAD_REQUEST, t!("File copies: 0 to 10240 MB", "Copies de fichiers : 0 à 10240 Mo")));
        }
        model::set_setting(db, "copies_fichiers_mo", json!(v)).await?;
        changed.insert("copies_fichiers_mo".into(), json!(v));
    }
    let mut purge = false;
    if let Some(v) = body.conservation_jours {
        if !(0..=36500).contains(&v) {
            return Err(err(StatusCode::BAD_REQUEST, t!("Retention of recordings: 0 to 36500 days", "Conservation des enregistrements : 0 à 36500 jours")));
        }
        model::set_setting(db, crate::status::RETENTION, json!(v)).await?;
        changed.insert(crate::status::RETENTION.into(), json!(v));
        purge = v > 0;
    }
    if let Some(v) = body.langue {
        let v = v.trim().to_lowercase();
        if !["", "en", "fr"].contains(&v.as_str()) {
            return Err(err(StatusCode::BAD_REQUEST, t!("Language: en, fr, or empty for the system's language", "Langue : en, fr, ou vide pour la langue du système")));
        }
        model::set_setting(db, "langue", json!(v)).await?;
        // Le serveur SSH et les journaux changent de langue tout de suite.
        crate::lang::set_process(crate::lang::Lang::from_tag(&v).unwrap_or_else(crate::lang::from_env));
        changed.insert("langue".into(), json!(v));
    }
    audit::note(db, &actor.login, "reglage.modifie", Value::Object(changed)).await;
    // Nouvelle durée de conservation : appliquée tout de suite, en tâche de fond.
    if purge {
        let state = api.state.clone();
        let login = actor.login.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::status::purge(&state, &login).await {
                tracing::warn!("{} {e:#}", t!("recordings retention:", "conservation des enregistrements :"));
            }
        });
    }
    Ok(Json(json!({ "etat": "ok" })))
}

// ---------- Audit : relecture des sessions ----------

/// Commandes repérées sur la barre de temps du lecteur (réglable).
const SENSITIVE_DEFAULT: &[&str] = &[
    "rm -rf", "rm -fr", "mkfs", "dd if=", "chmod -R 777", "shutdown", "reboot", "iptables -F", "userdel", "DROP TABLE", "DROP DATABASE",
];

pub(crate) async fn own_sessions_allowed(state: &State) -> anyhow::Result<bool> {
    Ok(model::setting(&state.db, "relecture_propres").await?.and_then(|v| v.as_bool()).unwrap_or(false))
}

pub(crate) async fn live_notice(state: &State) -> anyhow::Result<bool> {
    Ok(model::setting(&state.db, "direct_prevenir").await?.and_then(|v| v.as_bool()).unwrap_or(true))
}

pub(crate) async fn sensitive_commands(state: &State) -> anyhow::Result<Vec<String>> {
    Ok(match model::setting(&state.db, "commandes_sensibles").await? {
        Some(Value::Array(list)) => list.into_iter().filter_map(|v| v.as_str().map(str::to_owned)).collect(),
        _ => SENSITIVE_DEFAULT.iter().map(|s| s.to_string()).collect(),
    })
}

/// Qui peut relire : administrateurs et auditeurs (toutes les sessions), et, si le réglage
/// l'autorise, chaque compte pour ses propres sessions. Renvoie le compte et sa restriction.
async fn reader(api: &Api, headers: &HeaderMap) -> Result<(User, Option<String>), ApiError> {
    let user = caller(api, headers).await?;
    if user.role == "admin" || user.role == "auditor" {
        return Ok((user, None));
    }
    if own_sessions_allowed(&api.state).await? {
        let own = user.login.clone();
        return Ok((user, Some(own)));
    }
    Err(err(StatusCode::FORBIDDEN, t!("Replay restricted to the Gate's administrators and auditors", "Relecture réservée aux administrateurs et auditeurs de la Gate")))
}

/// Date « AAAA-MM-JJ » (minuit, heure de la Gate) ou RFC 3339.
fn parse_day(text: &str, end: bool) -> Result<DateTime<Utc>, ApiError> {
    if let Ok(d) = DateTime::parse_from_rfc3339(text) {
        return Ok(d.with_timezone(&Utc));
    }
    let day = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d").map_err(|_| err(StatusCode::BAD_REQUEST, t!("Expected date: YYYY-MM-DD", "Date attendue : AAAA-MM-JJ")))?;
    let day = if end { day.succ_opt().unwrap_or(day) } else { day };
    let local = day
        .and_hms_opt(0, 0, 0)
        .and_then(|d| d.and_local_timezone(chrono::Local).earliest())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, t!("Invalid date", "Date invalide")))?;
    Ok(local.with_timezone(&Utc))
}

#[derive(Deserialize)]
struct AuditQuery {
    compte: Option<String>,
    serveur: Option<String>,
    depuis: Option<String>,
    jusqua: Option<String>,
    texte: Option<String>,
    frappe: Option<bool>,
    fichiers: Option<bool>,
    limite: Option<i64>,
}

fn nonempty(v: Option<String>) -> Option<String> {
    v.map(|s| s.replace('\0', "").trim().to_string()).filter(|s| !s.is_empty())
}

async fn audit_sessions(AxState(api): Ctx, headers: HeaderMap, Query(q): Query<AuditQuery>) -> ApiResult {
    let (_, own) = reader(&api, &headers).await?;
    let restricted = own.is_some();
    let text = nonempty(q.texte);
    let filter = model::AuditFilter {
        login: own.or(nonempty(q.compte)),
        target: nonempty(q.serveur),
        since: nonempty(q.depuis).map(|d| parse_day(&d, false)).transpose()?,
        until: nonempty(q.jusqua).map(|d| parse_day(&d, true)).transpose()?,
        text: text.clone(),
        with_input: q.frappe.unwrap_or(false),
        with_files: q.fichiers.unwrap_or(false),
        // Une recherche lit chaque fichier trouvé pour donner le moment : liste plus courte.
        limit: q.limite.unwrap_or(200).clamp(1, if text.is_some() { 100 } else { 2000 }),
    };
    let rows = model::audit_sessions(&api.state.db, &filter).await?;
    // Moment et extrait de la recherche, lus dans les fichiers (hors du fil de l'API).
    let found: Vec<Option<(f64, String)>> = match &text {
        Some(t) => {
            let jobs: Vec<Option<String>> = rows.iter().map(|s| s.recording.clone()).collect();
            let t = t.clone();
            tokio::task::spawn_blocking(move || {
                jobs.into_iter()
                    .map(|path| {
                        let web = path.as_deref().is_some_and(|p| p.ends_with(".weblog"));
                        let content = path.and_then(|p| std::fs::read_to_string(p).ok())?;
                        if web {
                            crate::websession::find(&content, &t)
                        } else {
                            crate::replay::Cast::parse(&content).find(&t)
                        }
                    })
                    .collect()
            })
            .await
            .map_err(|e| anyhow!(t!(format!("search: {e}"), format!("recherche : {e}"))))?
        }
        None => vec![None; rows.len()],
    };
    let list: Vec<Value> = rows
        .into_iter()
        .zip(found)
        .map(|(s, hit)| {
            json!({
                "id": s.id, "compte": s.login, "serveur": s.target, "type": s.kind, "detail": s.detail, "mode": s.mode,
                "adresse": s.client_addr, "debut": s.started_at, "fin": s.ended_at, "enregistree": s.recording.is_some(),
                "relisible": s.recording.is_some() && s.kind != "rdp" && s.kind != "web",
                // Journal d'actions web : Portunia 0.74 et suivants.
                "relisible_web": s.recording.is_some() && s.kind == "web",
                // Lecteur Bureau à distance : Portunia 0.47 et suivants (les précédents gardent « relecture bientôt »).
                "relisible_rdp": s.recording.is_some() && s.kind == "rdp",
                "frappe": s.frappe, "fichiers": s.fichiers, "octets": s.bytes,
                "trouve": hit.map(|(t, extrait)| json!({ "t": t, "extrait": extrait })),
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": list, "propres_seulement": restricted })))
}

#[derive(Deserialize)]
struct RecordingQuery {
    reveler: Option<bool>,
    /// Relecture déjà ouverte qui se met à jour (session en direct) : rien de plus au journal.
    suite: Option<bool>,
}

/// Une relecture commence : notée au journal (« session.suivie » si la session est encore
/// ouverte) ; l'utilisateur en est prévenu si le réglage live_notice le demande.
async fn note_view(state: &State, user: &User, s: &model::AuditSession, id: Uuid, reveal: bool, q: &RecordingQuery) {
    if q.suite.unwrap_or(false) {
        return;
    }
    let live = s.ended_at.is_none() && state.live.sessions().contains(&id);
    let event = if reveal {
        "enregistrement.revele"
    } else if live {
        "session.suivie"
    } else {
        "enregistrement.consulte"
    };
    audit::note(&state.db, &user.login, event, json!({ "session": id, "cible": s.target, "compte": s.login })).await;
    if live && live_notice(state).await.unwrap_or(true) {
        state.live.notify_session(id, &t!(format!("Portunia Gate: this session is being followed live by {}.", user.login), format!("Portunia Gate : cette session est suivie en direct par {}.", user.login)));
    }
}

/// Enregistrement d'une session lisible par l'appelant, avec le contrôle de sa signature.
struct Loaded {
    user: User,
    session: model::AuditSession,
    raw: Vec<u8>,
    sha: String,
    signature: &'static str,
}

async fn load_recording(api: &Api, headers: &HeaderMap, id: Uuid, reveal: bool) -> Result<Loaded, ApiError> {
    let (user, own) = reader(api, headers).await?;
    let state = &api.state;
    let s = model::audit_session(&state.db, id)
        .await?
        .filter(|s| own.as_ref().is_none_or(|o| *o == s.login))
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Session not found", "Session introuvable")))?;
    let path = s.recording.clone().ok_or_else(|| err(StatusCode::NOT_FOUND, t!("This session was not recorded", "Cette session n'a pas été enregistrée")))?;
    if reveal && user.role != "admin" {
        return Err(err(StatusCode::FORBIDDEN, t!("Only an administrator can reveal masked input", "Seul un administrateur peut révéler les saisies masquées")));
    }
    let raw = tokio::task::spawn_blocking(move || std::fs::read(path))
        .await
        .map_err(|e| anyhow!(t!(format!("reading: {e}"), format!("lecture : {e}"))))?
        .map_err(|e| err(StatusCode::NOT_FOUND, t!(format!("Unreadable recording file: {e}"), format!("Fichier d'enregistrement illisible : {e}"))))?;
    let sha = sha256_hex(&raw);
    let signature = match (&s.recording_sha256, &s.signature) {
        (Some(expected), Some(sig)) => {
            let sig = base64::engine::general_purpose::STANDARD.decode(sig).unwrap_or_default();
            let message = crate::recording::signature_message(id, &sha);
            if *expected == sha && state.keys.verify(message.as_bytes(), &sig) {
                "verifiee"
            } else {
                "alteree"
            }
        }
        // Session en cours ou interrompue : pas encore de signature.
        _ => "absente",
    };
    Ok(Loaded { user, session: s, raw, sha, signature })
}

/// Relectures déjà faites de cette session (les 20 dernières).
async fn consultations(state: &State, id: Uuid) -> Result<Vec<Value>, ApiError> {
    let views: Vec<(String, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT actor, at, event FROM audit WHERE event IN ('enregistrement.consulte', 'enregistrement.revele', 'session.suivie', 'enregistrement.exporte') AND detail->>'session' = $1
         ORDER BY seq DESC LIMIT 20",
    )
    .bind(id.to_string())
    .fetch_all(&state.db)
    .await?;
    Ok(views.into_iter().map(|(qui, date, evenement)| json!({ "qui": qui, "date": date, "evenement": evenement })).collect())
}

async fn audit_recording(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>, Query(q): Query<RecordingQuery>) -> ApiResult {
    let reveal = q.reveler.unwrap_or(false);
    let Loaded { user, session: s, raw, sha, signature } = load_recording(&api, &headers, id, reveal).await?;
    let state = &api.state;
    let session = json!({
        "id": s.id, "compte": s.login, "serveur": s.target, "type": s.kind, "detail": s.detail, "mode": s.mode,
        "adresse": s.client_addr, "debut": s.started_at, "fin": s.ended_at, "frappe": s.frappe, "octets": raw.len(),
    });
    // Interface web : le journal d'actions (pages, envois, WebSocket, coffre).
    if s.kind == "web" {
        let (_, actions, duration) = crate::websession::read(&raw).map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
        note_view(state, &user, &s, id, false, &q).await;
        return Ok(Json(json!({
            "session": session,
            "web": { "actions": actions, "duree": duration },
            "revele": false,
            "saisies_masquees": 0,
            "signature": signature,
            "empreinte": sha,
            "commandes_sensibles": [],
            "consultations": consultations(state, id).await?,
        })));
    }
    // Bureau à distance : les événements ici, l'image par /flux.
    if s.kind == "rdp" {
        let replay = tokio::task::spawn_blocking(move || crate::rdpcap::read(&raw))
            .await
            .map_err(|e| anyhow!("{e}"))?
            .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
        let mut events = replay.events;
        let hidden = if reveal { 0 } else { crate::rdpcap::mask_clipboard(&mut events) };
        let clips = events.iter().filter(|e| e["k"] == "presse-papiers").count();
        note_view(state, &user, &s, id, reveal, &q).await;
        return Ok(Json(json!({
            "session": session,
            "rdp": { "evenements": events, "duree": replay.duration, "images": replay.display.len(), "compte": crate::rdpcap::counts(&events) },
            "revele": reveal,
            "saisies_masquees": if reveal { clips } else { hidden },
            "signature": signature,
            "empreinte": sha,
            "commandes_sensibles": sensitive_commands(state).await?,
            "consultations": consultations(state, id).await?,
        })));
    }
    let text = String::from_utf8_lossy(&raw);
    let cast = crate::replay::Cast::parse(&text);
    let hidden = cast.lines.iter().filter(|l| l.secret).count();
    let content = if reveal { text.into_owned() } else { cast.masked() };
    note_view(state, &user, &s, id, reveal, &q).await;
    Ok(Json(json!({
        "session": session,
        "cast": content,
        "revele": reveal,
        "saisies_masquees": hidden,
        "signature": signature,
        "empreinte": sha,
        "commandes_sensibles": sensitive_commands(state).await?,
        "consultations": consultations(state, id).await?,
    })))
}

/// Image d'une session Bureau à distance, pour le lecteur de Portunia : blocs temps (f64),
/// longueur (u32), message RDP du serveur. Sans presse-papiers ni authentification.
/// La consultation est inscrite au journal par /enregistrement, que le lecteur appelle d'abord.
async fn audit_rdp_stream(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>, Query(q): Query<StreamQuery>) -> Result<Response, ApiError> {
    let Loaded { session: s, raw, signature, .. } = load_recording(&api, &headers, id, false).await?;
    if s.kind != "rdp" {
        return Err(err(StatusCode::NOT_FOUND, t!("Not a Remote Desktop session", "Ce n'est pas une session Bureau à distance")));
    }
    // Session en direct : seulement les images après celles déjà reçues.
    let skip = q.depuis.unwrap_or(0);
    let body = tokio::task::spawn_blocking(move || {
        crate::rdpcap::read(&raw).map(|mut r| {
            r.display.drain(..skip.min(r.display.len()));
            crate::rdpcap::display_stream(&r)
        })
    })
        .await
        .map_err(|e| anyhow!("{e}"))?
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
            (axum::http::header::HeaderName::from_static("x-portunia-gate-signature"), signature),
        ],
        body,
    )
        .into_response())
}

#[derive(Deserialize)]
struct StreamQuery {
    /// Nombre d'images déjà reçues.
    depuis: Option<usize>,
}

/// Sessions ouvertes en ce moment (Audit › En direct).
async fn audit_live(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    auditor(&api, &headers).await?;
    let ids = api.state.live.sessions();
    let mut list = Vec::new();
    for id in ids {
        if let Some(s) = model::audit_session(&api.state.db, id).await?.filter(|s| s.ended_at.is_none()) {
            list.push(json!({
                "id": s.id, "compte": s.login, "serveur": s.target, "type": s.kind, "detail": s.detail, "mode": s.mode,
                "adresse": s.client_addr, "debut": s.started_at, "fin": null, "enregistree": s.recording.is_some(),
                "relisible": s.recording.is_some() && s.kind != "rdp" && s.kind != "web",
                "relisible_rdp": s.recording.is_some() && s.kind == "rdp",
                "relisible_web": s.recording.is_some() && s.kind == "web",
                "frappe": s.frappe, "fichiers": s.fichiers, "octets": s.bytes,
            }));
        }
    }
    list.sort_by(|a, b| b["debut"].as_str().cmp(&a["debut"].as_str()));
    Ok(Json(json!({ "sessions": list, "prevenir": live_notice(&api.state).await? })))
}

#[derive(Deserialize)]
struct CutBody {
    /// Désactiver aussi le compte (administrateurs seulement).
    #[serde(default)]
    desactiver: bool,
}

// ---------- État et mise à jour de la Gate (0.39) ----------

#[derive(Deserialize)]
struct StatusQuery {
    /// Vérifie tout de suite la dernière version publiée.
    verifier: Option<bool>,
    /// Seulement le niveau et les alertes (pastille de la barre latérale).
    court: Option<bool>,
}

async fn admin_status(AxState(api): Ctx, headers: HeaderMap, Query(q): Query<StatusQuery>) -> ApiResult {
    admin(&api, &headers).await?;
    let r = crate::status::report(&api.state, true, q.verifier == Some(true)).await?;
    if q.court == Some(true) {
        return Ok(Json(json!({ "niveau": r["niveau"], "alertes": r["alertes"], "mise_a_jour": r["mise_a_jour"]["disponible"] })));
    }
    Ok(Json(r))
}

async fn admin_update(AxState(api): Ctx, headers: HeaderMap, Query(q): Query<StatusQuery>) -> ApiResult {
    admin(&api, &headers).await?;
    let mut s = crate::update::summary(&api.state, q.verifier == Some(true)).await?;
    s["sessions_ouvertes"] = json!(api.state.live.sessions().len());
    Ok(Json(s))
}

#[derive(Deserialize)]
struct UpdateBody {
    /// Version voulue (défaut : la dernière publiée).
    version: Option<String>,
    /// Date (RFC 3339) ; absente : tout de suite.
    a: Option<DateTime<Utc>>,
    /// Prévenir les utilisateurs connectés 5 minutes avant.
    prevenir: Option<bool>,
}

async fn admin_update_apply(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<UpdateBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let version = match body.version.map(|v| v.trim().trim_start_matches('v').to_string()).filter(|v| !v.is_empty()) {
        Some(v) => v,
        None => crate::update::latest(true)
            .await
            .version
            .ok_or_else(|| err(StatusCode::BAD_GATEWAY, t!("Latest version unknown: the Gate cannot reach GitHub", "Dernière version inconnue : la Gate n'atteint pas GitHub")))?,
    };
    let p = crate::update::plan(&api.state, &version, body.a, body.prevenir.unwrap_or(false), &actor.login, false).await?;
    Ok(Json(json!({ "etat": "ok", "programmee": p })))
}

async fn admin_update_cancel(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let done = crate::update::cancel(&api.state, &actor.login).await?;
    Ok(Json(json!({ "etat": if done { "ok" } else { "aucune" } })))
}

async fn admin_notify(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    Ok(Json(crate::notify::public(&crate::notify::settings(&api.state).await?)))
}

#[derive(Deserialize)]
struct NotifyBody {
    smtp_hote: Option<String>,
    smtp_port: Option<u16>,
    smtp_securite: Option<String>,
    smtp_compte: Option<String>,
    /// Nouveau mot de passe SMTP ; absent : inchangé ; vide : retiré.
    smtp_mot_de_passe: Option<String>,
    smtp_expediteur: Option<String>,
    teams_url: Option<String>,
    webhook_url: Option<String>,
    /// true : nouveau secret de signature, renvoyé une seule fois.
    nouveau_secret_webhook: Option<bool>,
}

async fn admin_notify_update(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<NotifyBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let state = &api.state;
    let mut s = crate::notify::settings(state).await?;
    if let Some(v) = body.smtp_hote { s.smtp_host = v.trim().to_string(); }
    if let Some(v) = body.smtp_port { s.smtp_port = v; }
    if let Some(v) = body.smtp_securite { s.smtp_security = v.trim().to_lowercase(); }
    if let Some(v) = body.smtp_compte { s.smtp_user = v.trim().to_string(); }
    if let Some(v) = body.smtp_mot_de_passe { s.smtp_password = Some(v).filter(|p| !p.is_empty()); }
    if let Some(v) = body.smtp_expediteur { s.smtp_from = v.trim().to_string(); }
    if let Some(v) = body.teams_url { s.teams_url = v.trim().to_string(); }
    if let Some(v) = body.webhook_url { s.webhook_url = v.trim().to_string(); }
    let mut secret = None;
    if body.nouveau_secret_webhook == Some(true) {
        use base64::Engine;
        let fresh = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::keys::random::<32>()?);
        s.webhook_secret = Some(fresh.clone());
        secret = Some(fresh);
    }
    crate::notify::save(state, &s).await.map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    audit::note(&state.db, &actor.login, "notifications.modifiees", crate::notify::public(&s)).await;
    Ok(Json(json!({ "etat": "ok", "secret_webhook": secret })))
}

#[derive(Deserialize)]
struct NotifyTest {
    /// Adresse du courriel d'essai (absente : pas de courriel).
    email: Option<String>,
}

/// Essai : courriel à l'adresse donnée, Teams et webhook s'ils sont réglés. Résultat par canal.
async fn admin_notify_test(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<NotifyTest>) -> ApiResult {
    admin(&api, &headers).await?;
    let state = &api.state;
    let s = crate::notify::settings(state).await?;
    let gate = setting_str(state, "nom", "Portunia Gate").await?;
    let text = t!("Test message from the Gate: notifications work.", "Message d'essai de la Gate : les notifications fonctionnent.");
    let subject = format!("[{gate}] {}", t!("Test", "Essai"));
    let result = |r: anyhow::Result<()>| match r {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "erreur": format!("{e:#}") }),
    };
    let mail = match body.email.filter(|e| !e.trim().is_empty()) {
        Some(to) => Some(result(crate::notify::mail(&s, &[to], &subject, text).await)),
        None => None,
    };
    let teams = (!s.teams_url.is_empty()).then_some(());
    let teams = match teams { Some(()) => Some(result(crate::notify::teams(&s, &subject, text).await)), None => None };
    let hook = match s.webhook_url.is_empty() { false => Some(result(crate::notify::webhook(&s, &gate, "essai", &json!({ "message": text })).await)), true => None };
    Ok(Json(json!({ "courriel": mail, "teams": teams, "webhook": hook })))
}

/// Approbations vues par le compte : ses demandes, les serveurs qu'il peut demander, ce qu'il
/// peut décider et les accès accordés qu'il peut retirer.
async fn approvals_list(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    let user = caller(&api, &headers).await?;
    let db = &api.state.db;
    let mine: Vec<Value> = crate::approval::mine(db, user.id).await?.iter().map(|r| r.json()).collect();
    let open: Vec<Value> = crate::approval::requestable(db, &user)
        .await?
        .into_iter()
        .map(|(t, pending)| json!({ "serveur": t.name, "description": t.description, "protocole": t.protocole, "demande": pending.map(|p| p.json()) }))
        .collect();
    let decide: Vec<Value> = crate::approval::to_decide(db, &user).await?.iter().map(|r| r.json()).collect();
    let granted: Vec<Value> = crate::approval::granted_by_me_or_mine(db, &user).await?.iter().map(|r| r.json()).collect();
    Ok(Json(json!({ "mes_demandes": mine, "a_demander": open, "a_traiter": decide, "en_cours": granted })))
}

#[derive(Deserialize)]
struct ApprovalBody {
    serveur: String,
    motif: String,
    #[serde(default)]
    ticket: String,
}

async fn approvals_request(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<ApprovalBody>) -> ApiResult {
    let user = caller(&api, &headers).await?;
    let r = crate::approval::request(&api.state, &user, &body.serveur, &body.motif, &body.ticket, "portunia")
        .await
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(r.json()))
}

#[derive(Deserialize)]
struct DecisionBody {
    accorder: bool,
    #[serde(default)]
    minutes: i64,
    #[serde(default)]
    commentaire: String,
}

async fn approvals_decide(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>, Json(body): Json<DecisionBody>) -> ApiResult {
    let user = caller(&api, &headers).await?;
    let r = crate::approval::decide(&api.state, &user, id, body.accorder, body.minutes, &body.commentaire)
        .await
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(r.json()))
}

async fn approvals_cancel(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>) -> ApiResult {
    let user = caller(&api, &headers).await?;
    crate::approval::cancel(&api.state, &user, id).await.map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(json!({ "etat": "ok" })))
}

#[derive(Deserialize)]
struct ExportBody {
    /// mp4, webm, srt, txt ou cast.
    format: String,
}

/// Un export de relecture fait dans Portunia : inscrit au journal (enregistrement.exporte).
async fn audit_export(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>, Json(body): Json<ExportBody>) -> ApiResult {
    let (user, own) = reader(&api, &headers).await?;
    let format = body.format.trim().to_ascii_lowercase();
    if !["mp4", "webm", "srt", "txt", "cast"].contains(&format.as_str()) {
        return Err(err(StatusCode::BAD_REQUEST, t!("Export format: mp4, webm, srt, txt or cast", "Format d'export : mp4, webm, srt, txt ou cast")));
    }
    let s = model::audit_session(&api.state.db, id)
        .await?
        .filter(|s| own.as_ref().is_none_or(|o| *o == s.login))
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Session not found", "Session introuvable")))?;
    audit::note(&api.state.db, &user.login, "enregistrement.exporte", json!({ "session": id, "cible": s.target, "compte": s.login, "format": format })).await;
    Ok(Json(json!({ "etat": "ok" })))
}

/// Coupe une session ouverte ; désactive aussi le compte si demandé.
async fn audit_cut(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<Uuid>, Json(body): Json<CutBody>) -> ApiResult {
    let actor = auditor(&api, &headers).await?;
    if body.desactiver && actor.role != "admin" {
        return Err(err(StatusCode::FORBIDDEN, t!("Only an administrator can disable an account", "Seul un administrateur peut désactiver un compte")));
    }
    let state = &api.state;
    let s = model::audit_session(&state.db, id).await?.ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Session not found", "Session introuvable")))?;
    if s.login == actor.login && body.desactiver {
        return Err(err(StatusCode::BAD_REQUEST, t!("You cannot disable your own account", "Vous ne pouvez pas désactiver votre propre compte")));
    }
    let why = t!(format!("Session cut by {}.", actor.login), format!("Session coupée par {}.", actor.login));
    if !state.live.cut_session(id, &why) {
        return Err(err(StatusCode::NOT_FOUND, t!("This session is no longer open", "Cette session n'est plus ouverte")));
    }
    if body.desactiver {
        sqlx::query("UPDATE users SET disabled = true WHERE login = $1").bind(&s.login).execute(&state.db).await.map_err(anyhow::Error::from)?;
        if let Some(u) = model::user_by_login(&state.db, &s.login).await? {
            state.live.cut_user(u.id, &why);
        }
        state.live.recheck();
    }
    audit::note(&state.db, &actor.login, "session.coupee_par", json!({ "session": id, "cible": s.target, "compte": s.login, "desactive": body.desactiver })).await;
    Ok(Json(json!({ "etat": "ok" })))
}

// ---------- Bureau à distance (Portunia) ----------

/// Passage RDCleanPath pour Portunia : le jeton à usage unique de /serveurs/{nom}/ticket
/// est présenté dans la demande RDCleanPath elle-même.
async fn rdp_passage(
    AxState(api): Ctx,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> Response {
    let state = api.state.clone();
    let addr = addr.ip().to_string();
    let lang = crate::lang::get();
    ws.on_upgrade(move |socket| crate::lang::scope(lang, crate::rdp::relay(state, socket, crate::rdp::Origin::Portunia { addr })))
}

// ---------- Interfaces web (Portunia) ----------

#[derive(Deserialize)]
struct WebEntry {
    jeton: String,
}

fn web_refused(status: StatusCode, text: &str) -> Response {
    (status, [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], text.to_string()).into_response()
}

/// Entrée : le jeton à usage unique de Portunia devient une clé de session web (cookie, 8 h),
/// puis le navigateur de Portunia va à la racine du serveur.
async fn web_entry(AxState(api): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Query(q): Query<WebEntry>) -> Response {
    let state = &api.state;
    let cookie_name = crate::webproxy::key_cookie_name(&headers);
    let result = async {
        let Some((user_id, target_id, _)) = take_ticket(&state.db, &q.jeton).await? else {
            return Ok(web_refused(StatusCode::UNAUTHORIZED, t!("Invalid, expired or already used token: open the server again from Portunia", "Jeton invalide, expiré ou déjà utilisé : rouvrez le serveur depuis Portunia")));
        };
        let user = model::user_by_id(&state.db, user_id).await?.filter(|u| !u.disabled);
        let target = model::target_by_id(&state.db, target_id).await?.filter(|t| t.is_web());
        let (Some(user), Some(target)) = (user, target) else {
            return Ok(web_refused(StatusCode::FORBIDDEN, t!("Account or server unavailable", "Compte ou serveur indisponible")));
        };
        if !crate::webproxy::allowed(state, &user, &target).await? {
            return Ok(web_refused(StatusCode::FORBIDDEN, t!("Server not allowed at the moment", "Serveur non autorisé en ce moment")));
        }
        crate::webproxy::opened(state, &user, &target, &peer.ip().to_string(), "portunia").await;
        let key = crate::webproxy::new_key(user.id, target.id)?;
        let cookie = format!("{cookie_name}={key}; Path=/; HttpOnly; SameSite=Lax");
        Ok::<_, anyhow::Error>((StatusCode::FOUND, [(axum::http::header::SET_COOKIE, cookie), (axum::http::header::LOCATION, "/".to_string())]).into_response())
    }
    .await;
    result.unwrap_or_else(|e| web_refused(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

/// Toute autre adresse : relayée vers le serveur web de la clé de session.
async fn web_any(AxState(api): Ctx, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: axum::extract::Request) -> Response {
    let state = &api.state;
    let Some((user_id, target_id)) = crate::webproxy::cookie(req.headers(), &crate::webproxy::key_cookie_name(req.headers())).and_then(|k| crate::webproxy::key_owner(&k)) else {
        return web_refused(StatusCode::NOT_FOUND, t!("Not found", "Introuvable"));
    };
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let found = async {
        let user = model::user_by_id(&state.db, user_id).await?;
        let target = model::target_by_id(&state.db, target_id).await?;
        Ok::<_, anyhow::Error>(match (user, target) {
            (Some(u), Some(t)) if crate::webproxy::allowed(state, &u, &t).await? => Some((u, t)),
            _ => None,
        })
    }
    .await;
    match found {
        Ok(Some((user, target))) => crate::webproxy::forward(state, &user, &target, req, &path, true, &peer.ip().to_string()).await,
        Ok(None) => web_refused(StatusCode::FORBIDDEN, t!("Server not allowed at the moment: open it again from Portunia", "Serveur non autorisé en ce moment : rouvrez-le depuis Portunia")),
        Err(e) => web_refused(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

// ---------- Administration : portail web ----------

// ---------- Assistance à distance (Portunia Assist) ----------

/// Pour la barre latérale de Portunia : le relais est-il actif, puis-je l'utiliser, et l'adresse
/// à donner à la personne aidée.
async fn assist_status(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    let user = caller(&api, &headers).await?;
    let state = &api.state;
    let s = crate::assist::settings(state).await?;
    let portal = crate::portal::settings(state).await?;
    let page = if portal.url.is_empty() { String::new() } else { format!("{}/assistance", portal.url.trim_end_matches('/')) };
    Ok(Json(json!({
        "actif": s.enabled,
        "autorise": crate::assist::can_help(state, user.id).await?,
        "adresse": page,
        "programme": crate::assist::agent_file(state).exists(),
    })))
}

/// Le dépanneur rejoint la place donnée par la personne aidée (WebSocket).
async fn assist_join(AxState(api): Ctx, headers: HeaderMap, Path(place): Path<String>, ws: axum::extract::ws::WebSocketUpgrade) -> Result<Response, ApiError> {
    let user = caller(&api, &headers).await?;
    let state = api.state.clone();
    if !crate::assist::can_help(&state, user.id).await? {
        return Err(err(StatusCode::FORBIDDEN, t!("Remote assistance is disabled, or not allowed for this account", "L'assistance à distance est désactivée, ou non autorisée pour ce compte")));
    }
    if place.len() != 3 || !place.chars().all(|c| c.is_ascii_digit()) {
        return Err(err(StatusCode::BAD_REQUEST, t!("Invalid code", "Code invalide")));
    }
    let name = setting_str(&state, "nom", "Portunia Gate").await?;
    let who = format!("{} ({name})", user.login);
    Ok(ws.on_upgrade(move |socket| crate::assist::helper(state, socket, user.login, user.id, who, place)))
}

async fn admin_assist(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    let state = &api.state;
    let s = crate::assist::settings(state).await?;
    let groups: Vec<String> = sqlx::query_scalar("SELECT name FROM groups ORDER BY name").fetch_all(&state.db).await?;
    let portal = crate::portal::settings(state).await?;
    let (count, today): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE event = 'assistance.ouverte'), count(*) FILTER (WHERE event = 'assistance.ouverte' AND at >= date_trunc('day', now()))
         FROM audit WHERE event = 'assistance.ouverte'",
    )
    .fetch_one(&state.db)
    .await?;
    Ok(Json(json!({
        "actif": s.enabled,
        "groupe": s.group,
        "groupes": groups,
        "duree_h": s.hours,
        "adresse": if portal.url.is_empty() { String::new() } else { format!("{}/assistance", portal.url.trim_end_matches('/')) },
        "programme": crate::assist::agent_file(state).exists(),
        "en_attente": state.assist.waiting_count(),
        "total": count,
        "aujourd_hui": today,
    })))
}

#[derive(Deserialize)]
struct AssistBody {
    actif: Option<bool>,
    groupe: Option<String>,
    duree_h: Option<i64>,
}

async fn admin_assist_update(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<AssistBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let state = &api.state;
    let db = &state.db;
    let mut changed = serde_json::Map::new();
    if let Some(g) = body.groupe {
        model::set_setting(db, "assistance_groupe", json!(g.trim())).await?;
        changed.insert("groupe".into(), json!(g.trim()));
    }
    if let Some(h) = body.duree_h {
        if !(1..=12).contains(&h) {
            return Err(err(StatusCode::BAD_REQUEST, t!("Session duration: 1 to 12 hours", "Durée d'une assistance : 1 à 12 heures")));
        }
        model::set_setting(db, "assistance_duree_h", json!(h)).await?;
        changed.insert("duree_h".into(), json!(h));
    }
    if let Some(on) = body.actif {
        model::set_setting(db, "assistance_actif", json!(on)).await?;
        changed.insert("actif".into(), json!(on));
        if on {
            // Le programme de la personne aidée, servi par la page de téléchargement.
            let state = api.state.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::assist::fetch_agent(state).await {
                    tracing::warn!("{} {e:#}", t!("Portunia Assistance download:", "téléchargement de Portunia Assistance :"));
                }
            });
        } else {
            state.assist.close_all();
        }
    }
    audit::note(db, &actor.login, "assistance.reglage", Value::Object(changed)).await;
    Ok(Json(json!({ "etat": "ok" })))
}

// ---------- Entrée RDP native ----------

#[derive(Deserialize)]
struct NativeBody {
    /// Mode enregistré : identifiants Windows, gardés en mémoire le temps du jeton.
    compte: Option<String>,
    mot_de_passe: Option<String>,
}

/// Jeton à usage unique pour un client RDP ordinaire (mstsc, Remmina…) : Portunia en fait un
/// fichier .rdp (« loadbalanceinfo »).
async fn native_rdp(AxState(api): Ctx, headers: HeaderMap, Path(nom): Path<String>, Json(body): Json<NativeBody>) -> ApiResult {
    let user = caller(&api, &headers).await?;
    let state = &api.state;
    let db = &state.db;
    let s = crate::rdpnative::settings(state).await?;
    if !s.enabled {
        return Err(err(StatusCode::FORBIDDEN, t!("The native RDP entry is closed on this Gate", "L'entrée RDP native est fermée sur cette Gate")));
    }
    let target = model::target_by_name(db, &nom)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, t!("Unknown server", "Serveur inconnu")))?;
    if !target.is_rdp() || !s.allows(&target.mode) {
        return Err(err(
            StatusCode::FORBIDDEN,
            t!(format!("{}: not available through the native RDP entry", target.name), format!("{} : pas accessible par l'entrée RDP native", target.name)),
        ));
    }
    if model::access(db, user.id, target.id).await?.is_none() {
        audit::note(db, &user.login, "acces.refuse", json!({ "cible": target.name, "raison": "aucune règle active", "via": "rdp natif" })).await;
        return Err(err(
            StatusCode::FORBIDDEN,
            t!(format!("{} is not allowed for you at the moment", target.name), format!("{} ne vous est pas autorisé en ce moment", target.name)),
        ));
    }
    let ticket = issue_ticket_for(db, user.id, target.id, None, s.ticket_s).await?;
    let account = body.compte.map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
    let password = body.mot_de_passe.filter(|p| !p.is_empty());
    let given = target.mode == "enregistre" && account.is_some() && password.is_some();
    if let (true, Some(account), Some(password)) = (given, account, password) {
        crate::rdpnative::keep_credentials(&ticket, account, password, std::time::Duration::from_secs(s.ticket_s as u64));
    }
    audit::note(db, &user.login, "rdp_natif.fichier", json!({ "cible": target.name, "mode": target.mode, "identifiants": given })).await;
    Ok(Json(json!({
        "jeton": format!("{}{ticket}", crate::rdpnative::TOKEN_PREFIX),
        "port": s.port,
        "adresse": s.address,
        "mode": mode_label(&target.mode),
        "validite_s": s.ticket_s,
        "empreinte": crate::tls::fingerprint(&state.config.data_dir)?,
    })))
}

async fn admin_native_rdp(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    let s = crate::rdpnative::settings(&api.state).await?;
    let status = crate::rdpnative::status();
    Ok(Json(json!({
        "actif": s.enabled,
        "port": s.port,
        "adresse": s.address,
        "modes": s.modes,
        "jeton_s": s.ticket_s,
        "ecoute": status.listening,
        "erreur": status.error,
        "empreinte": crate::tls::fingerprint(&api.state.config.data_dir)?,
    })))
}

#[derive(Deserialize)]
struct NativeSettingsBody {
    actif: Option<bool>,
    port: Option<u16>,
    adresse: Option<String>,
    modes: Option<Vec<String>>,
    jeton_s: Option<i64>,
}

async fn admin_native_rdp_update(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<NativeSettingsBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let mut changed = serde_json::Map::new();
    if let Some(port) = body.port {
        if port == 0 {
            return Err(err(StatusCode::BAD_REQUEST, t!("Port: 1 to 65535", "Port : 1 à 65535")));
        }
        model::set_setting(db, "rdp_natif_port", json!(port)).await?;
        changed.insert("port".into(), json!(port));
    }
    if let Some(address) = body.adresse {
        let address = address.trim().to_string();
        crate::rdpnative::check_address(&address).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
        model::set_setting(db, "rdp_natif_adresse", json!(address)).await?;
        changed.insert("adresse".into(), json!(address));
    }
    if let Some(modes) = body.modes {
        if let Some(bad) = modes.iter().find(|m| !crate::rdpnative::MODES.contains(&m.as_str())) {
            return Err(err(StatusCode::BAD_REQUEST, t!(format!("Unknown mode: {bad} (rebond, coffre, enregistre)"), format!("Mode inconnu : {bad} (rebond, coffre, enregistre)"))));
        }
        model::set_setting(db, "rdp_natif_modes", json!(modes)).await?;
        changed.insert("modes".into(), json!(modes));
    }
    if let Some(seconds) = body.jeton_s {
        if !(30..=600).contains(&seconds) {
            return Err(err(StatusCode::BAD_REQUEST, t!("Validity of the .rdp file: 30 to 600 seconds", "Validité du fichier .rdp : 30 à 600 secondes")));
        }
        model::set_setting(db, "rdp_natif_jeton_s", json!(seconds)).await?;
        changed.insert("jeton_s".into(), json!(seconds));
    }
    if let Some(on) = body.actif {
        model::set_setting(db, "rdp_natif_actif", json!(on)).await?;
        changed.insert("actif".into(), json!(on));
    }
    audit::note(db, &actor.login, "rdp_natif.reglage", Value::Object(changed)).await;
    Ok(Json(json!({ "etat": "ok" })))
}

// ---------- Administration : durcissement ----------

/// Âge au-delà duquel l'état du serveur n'est plus relevé (normalement toutes les 15 minutes).
const HARDENING_STALE_MIN: i64 = 60;

/// État écrit par le serveur (voir installer.sh), avec ce qui mérite une alerte. La Gate ne fait
/// que lire : le durcissement se pilote sur le serveur, avec les droits de root.
pub(crate) fn hardening_report(text: Option<&str>, now: DateTime<Utc>) -> Value {
    let Some(text) = text else { return json!({ "actif": false }) };
    let Ok(state) = serde_json::from_str::<Value>(text) else {
        return json!({ "actif": true, "alertes": ["illisible"] });
    };
    let date = state["date"].as_str().and_then(|d| DateTime::parse_from_rfc3339(d).ok());
    let age = date.map(|d| (now - d.with_timezone(&Utc)).num_minutes());
    let mut alerts = Vec::new();
    if age.is_none_or(|a| a > HARDENING_STALE_MIN) {
        alerts.push("ancien");
    }
    if state["pare_feu_prevu"] == json!(true) && state["pare_feu"] != json!(true) {
        alerts.push("pare_feu");
    }
    if state["services_relances"].as_array().is_some_and(|l| !l.is_empty()) {
        alerts.push("services");
    }
    json!({ "actif": true, "etat": state, "age_min": age, "alertes": alerts })
}

async fn admin_hardening(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    let text = tokio::fs::read_to_string(api.state.config.data_dir.join("durcissement.json")).await.ok();
    Ok(Json(hardening_report(text.as_deref().filter(|t| t.len() < 64 * 1024), Utc::now())))
}

async fn admin_portal(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    let state = &api.state;
    let s = crate::portal::settings(state).await?;
    let (logins, failures): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE event = 'portail.connexion'), count(*) FILTER (WHERE event = 'portail.echec')
         FROM audit WHERE at >= date_trunc('day', now())",
    )
    .fetch_one(&state.db)
    .await?;
    let groups: Vec<String> = sqlx::query_scalar("SELECT name FROM groups ORDER BY name").fetch_all(&state.db).await?;
    crate::portal::reload_exposure(state).await?;
    let exposed = crate::portal::exposure(state);
    let (https, fixed) = crate::portal::https_address(state).await?;
    let listener = crate::portal::https_status();
    Ok(Json(json!({
        "mode": exposed.mode.id(),
        "proxys": exposed.proxies,
        "entete": exposed.header,
        "reseaux": exposed.networks,
        // Entrée interne, ouverte en même temps que l'entrée externe (mode) ou seule (mode interne).
        "interne": {
            "actif": exposed.internal_open(),
            "reseaux": exposed.internal_networks,
            "url": s.internal_url,
            "code_toujours": s.internal_code_always,
        },
        "relais": crate::relay::report(state).await?,
        "actif": s.enabled,
        "url": s.url,
        "groupe": s.group,
        "groupes": groups,
        "duree_h": s.hours,
        "inactivite_min": s.idle_min,
        "presse_papiers": s.clipboard,
        "code_toujours": s.code_always,
        "turnstile_site": s.turnstile_site,
        "turnstile_secret_defini": s.turnstile_secret.is_some(),
        "ecoute": {
            "tunnel": state.config.portal_listen,
            "proxy": https,
            "https": { "fixe": fixed, "ouverte": listener.listening, "erreur": listener.error },
        },
        "tunnel": crate::tunnel::summary(state).await,
        "tunnel_gere": crate::tunnel::report(state).await?,
        "certificat": crate::cert::report(),
        "acme": crate::acme::report(state).await?,
        "sessions_en_cours": state.web.active(),
        "connexions_jour": logins,
        "echecs_jour": failures,
    })))
}

async fn admin_cf_access(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    let state = &api.state;
    let tunnel = crate::tunnel::token(state).await?.and_then(|t| crate::tunnel::parse(&t).ok()).map(|(_, i)| i.tunnel);
    Ok(Json(json!({
        "hotes": crate::cfaccess::hosts(state).await?,
        // Publication par l'API Cloudflare possible seulement avec le tunnel lancé par la Gate.
        "tunnel_gere": tunnel,
        "rdp_natif_actif": crate::rdpnative::settings(state).await?.enabled,
    })))
}

#[derive(Deserialize)]
struct CfAccessBody {
    #[serde(default)]
    api: String,
    #[serde(default)]
    ssh: String,
    #[serde(default)]
    rdp: String,
    /// Jeton d'API Cloudflare pour publier routes et DNS ; absent : noms enregistrés seulement.
    jeton_api: Option<String>,
}

async fn admin_cf_access_update(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<CfAccessBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let state = &api.state;
    let wanted = crate::cfaccess::Hosts { api: body.api, ssh: body.ssh, rdp: body.rdp };
    let bad = |e: anyhow::Error| err(StatusCode::BAD_REQUEST, &e.to_string());
    let (hosts, done) = match body.jeton_api.filter(|t| !t.trim().is_empty()) {
        Some(token) => crate::cfaccess::publish(state, &token, &wanted).await.map_err(bad)?,
        None => (crate::cfaccess::set_hosts(state, &wanted).await.map_err(bad)?, Vec::new()),
    };
    audit::note(&state.db, &actor.login, "acces_cloudflare.modifie", json!({ "hotes": hosts, "publie": !done.is_empty() })).await;
    Ok(Json(json!({ "hotes": hosts, "fait": done })))
}

#[derive(Deserialize)]
struct PortalBody {
    actif: Option<bool>,
    url: Option<String>,
    groupe: Option<String>,
    duree_h: Option<i64>,
    inactivite_min: Option<i64>,
    presse_papiers: Option<bool>,
    /// Faux : plus de code sur le portail, sauf pour les comptes dont la politique propre l'impose.
    code_toujours: Option<bool>,
    turnstile_site: Option<String>,
    /// Vide : efface le secret ; absent : le garde.
    turnstile_secret: Option<String>,
    mode: Option<String>,
    proxys: Option<Vec<String>>,
    entete: Option<String>,
    reseaux: Option<Vec<String>>,
    /// Jeton du tunnel Cloudflare géré ; vide : l'efface ; absent : le garde.
    tunnel_jeton: Option<String>,
    /// Écoute HTTPS du portail (« 8446 », « 0.0.0.0:8446 ») ; vide : la ferme ; absent : la garde.
    https: Option<String>,
    /// Entrée interne, en plus de l'entrée externe.
    interne_actif: Option<bool>,
    interne_reseaux: Option<Vec<String>>,
    /// Adresse de l'entrée interne (https://…) ; vide : l'hôte demandé par le navigateur.
    interne_url: Option<String>,
    interne_code_toujours: Option<bool>,
}

async fn admin_portal_update(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<PortalBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let state = &api.state;
    let db = &state.db;
    let mut changed = serde_json::Map::new();
    if let Some(url) = body.url {
        let url = url.trim().trim_end_matches('/').to_string();
        if !url.is_empty() && !url.starts_with("https://") {
            return Err(err(StatusCode::BAD_REQUEST, t!("Public address: https://…", "Adresse publique : https://…")));
        }
        model::set_setting(db, "portail_url", json!(url)).await?;
        changed.insert("url".into(), json!(url));
    }
    if let Some(url) = body.interne_url {
        let url = url.trim().trim_end_matches('/').to_string();
        if !url.is_empty() && !url.starts_with("https://") {
            return Err(err(StatusCode::BAD_REQUEST, t!("Internal address: https://…", "Adresse interne : https://…")));
        }
        model::set_setting(db, "portail_interne_url", json!(url)).await?;
        changed.insert("interne_url".into(), json!(url));
    }
    if let Some(v) = body.interne_code_toujours {
        model::set_setting(db, "portail_interne_code_toujours", json!(v)).await?;
        changed.insert("interne_code_toujours".into(), json!(v));
    }
    if let Some(g) = body.groupe {
        model::set_setting(db, "portail_groupe", json!(g.trim())).await?;
        changed.insert("groupe".into(), json!(g.trim()));
    }
    if let Some(h) = body.duree_h {
        if !(1..=12).contains(&h) {
            return Err(err(StatusCode::BAD_REQUEST, t!("Web session duration: 1 to 12 hours", "Durée d'une session web : 1 à 12 heures")));
        }
        model::set_setting(db, "portail_duree_h", json!(h)).await?;
        changed.insert("duree_h".into(), json!(h));
    }
    if let Some(m) = body.inactivite_min {
        if !(5..=240).contains(&m) {
            return Err(err(StatusCode::BAD_REQUEST, t!("Inactivity: 5 to 240 minutes", "Inactivité : 5 à 240 minutes")));
        }
        model::set_setting(db, "portail_inactivite_min", json!(m)).await?;
        changed.insert("inactivite_min".into(), json!(m));
    }
    if let Some(v) = body.presse_papiers {
        model::set_setting(db, "portail_presse_papiers", json!(v)).await?;
        changed.insert("presse_papiers".into(), json!(v));
    }
    if let Some(v) = body.code_toujours {
        model::set_setting(db, "portail_code_toujours", json!(v)).await?;
        changed.insert("code_toujours".into(), json!(v));
    }
    if let Some(site) = body.turnstile_site {
        model::set_setting(db, "portail_turnstile_site", json!(site.trim())).await?;
        changed.insert("turnstile_site".into(), json!(site.trim()));
    }
    if let Some(secret) = body.turnstile_secret {
        let sealed = if secret.trim().is_empty() { String::new() } else { crate::portal::seal_turnstile(state, secret.trim())? };
        model::set_setting(db, "portail_turnstile_secret", json!(sealed)).await?;
        changed.insert("turnstile_secret".into(), json!(if sealed.is_empty() { "effacé" } else { "changé" }));
    }
    if let Some(address) = body.https {
        let set = crate::portal::set_https(state, &address).await.map_err(|e| err(StatusCode::BAD_REQUEST, &e.to_string()))?;
        audit::note(db, &actor.login, "portail.https", json!({ "ecoute": set })).await;
    }
    if let Some(token) = body.tunnel_jeton {
        let info = crate::tunnel::set_token(state, &token).await.map_err(|e| err(StatusCode::BAD_REQUEST, &e.to_string()))?;
        audit::note(db, &actor.login, "portail.tunnel", json!({ "tunnel": info.map(|i| i.tunnel) })).await;
    }
    if body.mode.is_some() || body.proxys.is_some() || body.entete.is_some() || body.reseaux.is_some() || body.interne_actif.is_some() || body.interne_reseaux.is_some() {
        let before = crate::portal::exposure(state);
        let internal = crate::portal::InternalChange { open: body.interne_actif, networks: body.interne_reseaux.as_deref() };
        let after = crate::portal::set_exposure(state, body.mode.as_deref(), body.proxys.as_deref(), body.entete.as_deref(), body.reseaux.as_deref(), internal)
            .await
            .map_err(|e| err(StatusCode::BAD_REQUEST, &e.to_string()))?;
        if before.mode != after.mode
            || before.proxies != after.proxies
            || before.header != after.header
            || before.networks != after.networks
            || before.internal_open() != after.internal_open()
            || before.internal_networks != after.internal_networks
        {
            audit::note(db, &actor.login, "portail.exposition", crate::portal::exposure_note(&after)).await;
        }
    }
    if let Some(on) = body.actif {
        let was = crate::portal::settings(state).await?.enabled;
        model::set_setting(db, "portail_actif", json!(on)).await?;
        if was != on {
            if !on {
                // Désactivé : plus de connexion, et les terminaux web ouverts se ferment.
                sqlx::query("DELETE FROM web_sessions").execute(db).await?;
                state.web.close_all();
            }
            audit::note(db, &actor.login, if on { "portail.active" } else { "portail.desactive" }, json!({})).await;
        }
    }
    state.live.recheck();
    if !changed.is_empty() {
        audit::note(db, &actor.login, "portail.modifie", Value::Object(changed)).await;
    }
    Ok(Json(json!({ "etat": "ok" })))
}

#[derive(Deserialize)]
struct RelayBody {
    nom: String,
    adresse: String,
}

async fn admin_relay_add(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<RelayBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let state = &api.state;
    let (entry, code) = crate::relay::add(state, &body.nom, &body.adresse).await.map_err(|e| err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    audit::note(&state.db, &actor.login, "relais.ajoute", json!({ "nom": entry.nom, "adresse": entry.adresse })).await;
    Ok(Json(json!({ "id": entry.id, "code": code })))
}

async fn admin_relay_remove(AxState(api): Ctx, headers: HeaderMap, Path(id): Path<String>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let state = &api.state;
    let gone = crate::relay::remove(state, &id).await.map_err(|e| err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let Some(name) = gone else {
        return Err(err(StatusCode::NOT_FOUND, t!("Unknown relay", "Relais inconnu")));
    };
    // Les terminaux web passés par ce relais ne doivent pas lui survivre.
    state.web.close_all();
    audit::note(&state.db, &actor.login, "relais.revoque", json!({ "nom": name })).await;
    Ok(Json(json!({ "etat": "ok" })))
}

async fn admin_portal_check(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    admin(&api, &headers).await?;
    Ok(Json(crate::tunnel::check(&api.state).await?))
}

#[derive(Deserialize)]
struct CertBody {
    /// Certificat PEM avec sa chaîne (et, éventuellement, la clé).
    certificat: Option<String>,
    cle: Option<String>,
    /// Fichier PFX en base64.
    pfx: Option<String>,
    mot_de_passe: Option<String>,
}

async fn admin_cert_import(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<CertBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let state = &api.state;
    let bad = |e: anyhow::Error| err(StatusCode::BAD_REQUEST, &format!("{e:#}"));
    let (chain, key) = match (body.pfx, body.certificat) {
        (Some(pfx), _) => {
            let der = base64::engine::general_purpose::STANDARD.decode(pfx.trim()).map_err(|_| err(StatusCode::BAD_REQUEST, t!("PFX: unreadable file", "PFX : fichier illisible")))?;
            crate::cert::from_pfx(&der, body.mot_de_passe.as_deref().unwrap_or("")).map_err(bad)?
        }
        (None, Some(chain)) => {
            let key = body.cle.filter(|k| !k.trim().is_empty()).unwrap_or_else(|| chain.clone());
            (chain, key)
        }
        (None, None) => return Err(err(StatusCode::BAD_REQUEST, t!("Give a certificate (PEM) or a PFX file", "Indiquez un certificat (PEM) ou un fichier PFX"))),
    };
    let info = crate::cert::store(state, "importe", &chain, &key).await.map_err(bad)?;
    crate::acme::disable(state).await?;
    crate::cert::refresh(state).await?;
    audit::note(&state.db, &actor.login, "portail.certificat", json!({ "source": "importe", "noms": info.noms, "emetteur": info.emetteur, "expire": info.expire })).await;
    Ok(Json(json!({ "etat": "ok", "certificat": info })))
}

async fn admin_cert_remove(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let state = &api.state;
    crate::cert::remove(state).await.map_err(|e| err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    crate::acme::disable(state).await?;
    crate::cert::refresh(state).await?;
    audit::note(&state.db, &actor.login, "portail.certificat", json!({ "source": "auto" })).await;
    Ok(Json(json!({ "etat": "ok" })))
}

#[derive(Deserialize)]
struct AcmeBody {
    actif: bool,
    #[serde(default)]
    domaines: Vec<String>,
    #[serde(default)]
    email: String,
    #[serde(default)]
    methode: String,
    #[serde(default)]
    essai: bool,
    /// Vide : l'efface ; absent : le garde.
    cloudflare_jeton: Option<String>,
    /// Accord aux conditions de Let's Encrypt, donné par l'administrateur.
    #[serde(default)]
    conditions: bool,
}

async fn admin_acme_update(AxState(api): Ctx, headers: HeaderMap, Json(body): Json<AcmeBody>) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let state = &api.state;
    if body.actif && !body.conditions {
        return Err(err(StatusCode::BAD_REQUEST, t!("Accept the Let's Encrypt Subscriber Agreement first", "Acceptez d'abord les conditions d'utilisation de Let's Encrypt")));
    }
    let token_changed = body.cloudflare_jeton.is_some();
    let c = crate::acme::update(
        state,
        crate::acme::Update { actif: body.actif, domaines: body.domaines, email: body.email, methode: body.methode, essai: body.essai, cloudflare_jeton: body.cloudflare_jeton },
    )
    .await
    .map_err(|e| err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    audit::note(
        &state.db,
        &actor.login,
        "portail.acme",
        json!({ "actif": c.actif, "domaines": c.domaines, "methode": c.methode, "essai": c.essai, "jeton_cloudflare_change": token_changed }),
    )
    .await;
    Ok(Json(crate::acme::report(state).await?))
}

async fn admin_acme_renew(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let state = &api.state;
    if !crate::acme::config(state).await?.actif {
        return Err(err(StatusCode::BAD_REQUEST, t!("Let's Encrypt is not enabled", "Let's Encrypt n'est pas activé")));
    }
    crate::acme::wake(true);
    audit::note(&state.db, &actor.login, "portail.acme_renouveler", json!({})).await;
    Ok(Json(json!({ "etat": "ok" })))
}

async fn admin_portal_close(AxState(api): Ctx, headers: HeaderMap) -> ApiResult {
    let actor = admin(&api, &headers).await?;
    let db = &api.state.db;
    let open = api.state.web.active();
    sqlx::query("DELETE FROM web_sessions").execute(db).await?;
    api.state.web.close_all();
    audit::note(db, &actor.login, "portail.sessions_fermees", json!({ "terminaux": open })).await;
    Ok(Json(json!({ "etat": "ok", "fermees": open })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(minutes: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-01T10:00:00Z").unwrap().with_timezone(&Utc) + chrono::Duration::minutes(minutes)
    }

    const GOOD: &str = r#"{"date":"2026-11-01T10:00:00Z","pare_feu":true,"pare_feu_prevu":true,"ssh":true,"noyau":true,"mises_a_jour":true,"services_arretes":2,"services_relances":[]}"#;

    #[test]
    fn durcissement_absent() {
        assert_eq!(hardening_report(None, at(0))["actif"], false);
    }

    #[test]
    fn durcissement_sans_alerte() {
        let r = hardening_report(Some(GOOD), at(15));
        assert_eq!(r["age_min"], 15);
        assert_eq!(r["alertes"], json!([]));
    }

    #[test]
    fn durcissement_alertes() {
        assert_eq!(hardening_report(Some(GOOD), at(61))["alertes"], json!(["ancien"]));
        let off = GOOD.replace("\"pare_feu\":true", "\"pare_feu\":false");
        assert_eq!(hardening_report(Some(&off), at(1))["alertes"], json!(["pare_feu"]));
        let lxc = off.replace("\"pare_feu_prevu\":true", "\"pare_feu_prevu\":false");
        assert_eq!(hardening_report(Some(&lxc), at(1))["alertes"], json!([]), "pare-feu de l'hôte : pas d'alerte");
        let back = GOOD.replace("\"services_relances\":[]", "\"services_relances\":[\"cups.service\"]");
        assert_eq!(hardening_report(Some(&back), at(1))["alertes"], json!(["services"]));
        assert_eq!(hardening_report(Some("pas du json"), at(1))["alertes"], json!(["illisible"]));
    }
}
