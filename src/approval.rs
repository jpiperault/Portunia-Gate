//! Approbation des accès (choix du questionnaire « contrôle des accès ») : une règle peut
//! exiger qu'un approbateur accorde l'accès. L'utilisateur demande avec un motif (et un ticket
//! facultatif) ; un membre du groupe d'approbateurs de la règle (les administrateurs si la règle
//! n'en a pas) accorde pour une durée qu'il choisit, ou refuse. Pas d'auto-approbation.
//! L'utilisateur est prévenu 10 minutes avant la fin (terminal SSH), puis ses sessions sont
//! coupées. Demandes et décisions sont notées au journal et notifiées (courriel, Teams,
//! webhook, et Portunia qui interroge la Gate).

use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    audit,
    model::{self, User},
    notify, State,
};

/// Une demande en attente sans réponse expire au bout de ce délai.
const PENDING_HOURS: i64 = 24;
/// Préavis avant la fin d'un accès accordé.
const WARN_MINUTES: i64 = 10;
/// Durée accordée : de 5 minutes à 7 jours.
pub const MIN_MINUTES: i64 = 5;
pub const MAX_MINUTES: i64 = 7 * 24 * 60;

#[derive(sqlx::FromRow, Clone)]
pub struct Request {
    pub id: Uuid,
    pub user_id: Uuid,
    pub login: String,
    pub target_id: Uuid,
    pub target: String,
    pub reason: String,
    pub ticket: String,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    pub decided_by: String,
    pub decided_at: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub comment: String,
}

const SELECT: &str = "SELECT a.id, a.user_id, u.login, a.target_id, t.name AS target, a.reason, a.ticket, a.status, a.requested_at,
                             a.decided_by, a.decided_at, a.until, a.comment
                      FROM approvals a JOIN users u ON u.id = a.user_id JOIN targets t ON t.id = a.target_id";

impl Request {
    pub fn json(&self) -> Value {
        json!({
            "id": self.id, "compte": self.login, "serveur": self.target, "motif": self.reason, "ticket": self.ticket,
            "etat": self.status, "demande": self.requested_at, "decide_par": self.decided_by, "decide": self.decided_at,
            "jusqua": self.until, "commentaire": self.comment,
        })
    }
}

pub async fn get(db: &sqlx::PgPool, id: Uuid) -> Result<Option<Request>> {
    Ok(sqlx::query_as(&format!("{SELECT} WHERE a.id = $1")).bind(id).fetch_optional(db).await?)
}

/// Groupes d'approbateurs des règles avec approbation qui donnent ce serveur à ce compte
/// (`None` : les administrateurs).
async fn approver_groups(db: &sqlx::PgPool, user: Uuid, target: Uuid) -> Result<Vec<Option<Uuid>>> {
    let rows: Vec<(Option<Uuid>,)> = sqlx::query_as(
        "SELECT DISTINCT r.approver_group FROM rules r
         JOIN rule_targets rt ON rt.rule_id = r.id JOIN group_members gm ON gm.group_id = r.group_id
         WHERE r.approval AND gm.user_id = $1 AND rt.target_id = $2",
    )
    .bind(user)
    .bind(target)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// Ce compte peut-il décider de cette demande ? Jamais pour lui-même.
pub async fn can_decide(db: &sqlx::PgPool, approver: &User, r: &Request) -> Result<bool> {
    if approver.id == r.user_id || approver.disabled {
        return Ok(false);
    }
    for group in approver_groups(db, r.user_id, r.target_id).await? {
        match group {
            None if approver.role == "admin" => return Ok(true),
            Some(g) => {
                let member: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2)")
                    .bind(g)
                    .bind(approver.id)
                    .fetch_one(db)
                    .await?;
                if member {
                    return Ok(true);
                }
            }
            None => {}
        }
    }
    Ok(false)
}

/// Serveurs que ce compte peut demander maintenant (règle avec approbation active, pas d'accès
/// en ce moment), avec sa demande en attente éventuelle.
pub async fn requestable(db: &sqlx::PgPool, user: &User) -> Result<Vec<(model::Target, Option<Request>)>> {
    let ids: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT DISTINCT rt.target_id FROM rules r
         JOIN rule_targets rt ON rt.rule_id = r.id JOIN group_members gm ON gm.group_id = r.group_id
         WHERE r.approval AND gm.user_id = $1",
    )
    .bind(user.id)
    .fetch_all(db)
    .await?;
    let mut out = Vec::new();
    for (target_id,) in ids {
        if model::access(db, user.id, target_id).await?.is_some() {
            continue;
        }
        // Règle avec approbation active maintenant (jours, heures, expiration).
        if !active_approval_rule(db, user.id, target_id).await? {
            continue;
        }
        let Some(target) = model::target_by_id(db, target_id).await? else { continue };
        let pending: Option<Request> = sqlx::query_as(&format!("{SELECT} WHERE a.user_id = $1 AND a.target_id = $2 AND a.status = 'attente' ORDER BY a.requested_at DESC LIMIT 1"))
            .bind(user.id)
            .bind(target_id)
            .fetch_optional(db)
            .await?;
        out.push((target, pending));
    }
    out.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    Ok(out)
}

async fn active_approval_rule(db: &sqlx::PgPool, user: Uuid, target: Uuid) -> Result<bool> {
    let rows: Vec<(i16, Option<i16>, Option<i16>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT r.days, r.hour_from, r.hour_to, r.expires_at FROM rules r
         JOIN rule_targets rt ON rt.rule_id = r.id JOIN group_members gm ON gm.group_id = r.group_id
         WHERE r.approval AND gm.user_id = $1 AND rt.target_id = $2",
    )
    .bind(user)
    .bind(target)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().any(|(d, a, b, e)| model::rule_state(d, a, b, e) == "active"))
}

/// Nouvelle demande. `via` : portunia, portail ou console.
pub async fn request(state: &Arc<State>, user: &User, target_name: &str, reason: &str, ticket: &str, via: &str) -> Result<Request> {
    let db = &state.db;
    let reason = reason.trim();
    let ticket = ticket.trim();
    if reason.is_empty() {
        bail!(t!("Give a reason", "Indiquez un motif"));
    }
    if reason.chars().count() > 500 || ticket.chars().count() > 100 {
        bail!(t!("Reason: 500 characters at most; ticket: 100", "Motif : 500 caractères au plus ; ticket : 100"));
    }
    let list = requestable(db, user).await?;
    let Some((target, pending)) = list.into_iter().find(|(t, _)| t.name.eq_ignore_ascii_case(target_name)) else {
        bail!(t!("This server does not need an approval for you right now", "Ce serveur ne demande pas d'approbation pour vous en ce moment"));
    };
    if let Some(p) = pending {
        return Ok(p);
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO approvals (id, user_id, target_id, reason, ticket) VALUES ($1, $2, $3, $4, $5)")
        .bind(id)
        .bind(user.id)
        .bind(target.id)
        .bind(reason)
        .bind(ticket)
        .execute(db)
        .await?;
    audit::note(db, &user.login, "approbation.demandee", json!({ "demande": id, "cible": target.name, "motif": reason, "ticket": ticket, "via": via })).await;
    // Les approbateurs : courriel, Teams, webhook.
    let mut to = Vec::new();
    for g in approver_groups(db, user.id, target.id).await? {
        to.extend(notify::group_emails(state, g).await.unwrap_or_default());
    }
    to.sort();
    to.dedup();
    let ticket_line = if ticket.is_empty() { String::new() } else { format!("\nTicket : {ticket}") };
    notify::send(
        state.clone(),
        notify::Notice {
            event: "approbation.demandee",
            title: t!(format!("Access request: {} → {}", user.login, target.name), format!("Demande d'accès : {} → {}", user.login, target.name)).to_string(),
            text: t!(
                format!("{} asks for access to {}.\nReason: {reason}{ticket_line}\n\nTo answer: Portunia › Gate › Approvals, or on the Gate: sudo portunia-gate approval grant {} --minutes 60", user.login, target.name, &id.to_string()[..8]),
                format!("{} demande l'accès à {}.\nMotif : {reason}{ticket_line}\n\nPour répondre : Portunia › Gate › Approbations, ou sur la Gate : sudo portunia-gate approval grant {} --minutes 60", user.login, target.name, &id.to_string()[..8])
            )
            .to_string(),
            detail: json!({ "demande": id, "compte": user.login, "serveur": target.name, "motif": reason, "ticket": ticket }),
            to,
        },
    );
    get(db, id).await?.ok_or_else(|| anyhow!("demande introuvable"))
}

/// Ce compte décide-t-il de demandes (administrateur pour une règle sans groupe d'approbateurs,
/// ou membre d'un groupe d'approbateurs) ? Sert à l'application Android pour ses notifications.
pub async fn is_approver(db: &sqlx::PgPool, user: &User) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM rules r WHERE r.approval AND (
            (r.approver_group IS NULL AND $2) OR
            EXISTS (SELECT 1 FROM group_members m WHERE m.group_id = r.approver_group AND m.user_id = $1)))",
    )
    .bind(user.id)
    .bind(user.role == "admin")
    .fetch_one(db)
    .await?)
}

/// Demandes en attente que ce compte peut décider.
pub async fn to_decide(db: &sqlx::PgPool, approver: &User) -> Result<Vec<Request>> {
    let pending: Vec<Request> = sqlx::query_as(&format!("{SELECT} WHERE a.status = 'attente' ORDER BY a.requested_at")).fetch_all(db).await?;
    let mut out = Vec::new();
    for r in pending {
        if can_decide(db, approver, &r).await? {
            out.push(r);
        }
    }
    Ok(out)
}

/// Accès accordés en cours, que ce compte peut retirer.
pub async fn granted_by_me_or_mine(db: &sqlx::PgPool, approver: &User) -> Result<Vec<Request>> {
    let list: Vec<Request> = sqlx::query_as(&format!("{SELECT} WHERE a.status = 'accordee' AND a.until > now() ORDER BY a.until")).fetch_all(db).await?;
    let mut out = Vec::new();
    for r in list {
        if can_decide(db, approver, &r).await? {
            out.push(r);
        }
    }
    Ok(out)
}

/// Demandes récentes d'un compte.
pub async fn mine(db: &sqlx::PgPool, user: Uuid) -> Result<Vec<Request>> {
    Ok(sqlx::query_as(&format!("{SELECT} WHERE a.user_id = $1 ORDER BY a.requested_at DESC LIMIT 30")).bind(user).fetch_all(db).await?)
}

/// Accorde (pour `minutes`) ou refuse une demande en attente.
pub async fn decide(state: &Arc<State>, approver: &User, id: Uuid, grant: bool, minutes: i64, comment: &str) -> Result<Request> {
    decide_by(state, &approver.login, Some(approver), id, grant, minutes, comment).await
}

/// Décision par `by` ; `checked` : le compte dont on vérifie les droits (`None` : la console
/// de la Gate, qui agit comme un administrateur).
pub async fn decide_by(state: &Arc<State>, by: &str, checked: Option<&User>, id: Uuid, grant: bool, minutes: i64, comment: &str) -> Result<Request> {
    let db = &state.db;
    let r = get(db, id).await?.ok_or_else(|| anyhow!(t!("Unknown request", "Demande inconnue")))?;
    if let Some(approver) = checked {
        if !can_decide(db, approver, &r).await? {
            bail!(t!("You cannot decide on this request (you are not one of its approvers, or it is yours)", "Vous ne pouvez pas décider de cette demande (vous n'en êtes pas approbateur, ou c'est la vôtre)"));
        }
    }
    if r.status != "attente" {
        bail!(t!("This request was already answered", "Cette demande a déjà reçu une réponse"));
    }
    let comment = comment.trim().chars().take(500).collect::<String>();
    if grant && !(MIN_MINUTES..=MAX_MINUTES).contains(&minutes) {
        bail!(t!("Duration: 5 minutes to 7 days", "Durée : 5 minutes à 7 jours"));
    }
    let until = grant.then(|| Utc::now() + chrono::Duration::minutes(minutes));
    let status = if grant { "accordee" } else { "refusee" };
    let done = sqlx::query("UPDATE approvals SET status = $2, decided_by = $3, decided_at = now(), until = $4, comment = $5 WHERE id = $1 AND status = 'attente'")
        .bind(id)
        .bind(status)
        .bind(by)
        .bind(until)
        .bind(&comment)
        .execute(db)
        .await?;
    if done.rows_affected() == 0 {
        bail!(t!("This request was already answered", "Cette demande a déjà reçu une réponse"));
    }
    let event = if grant { "approbation.accordee" } else { "approbation.refusee" };
    audit::note(db, by, event, json!({ "demande": id, "compte": r.login, "cible": r.target, "jusqua": until, "minutes": grant.then_some(minutes), "commentaire": comment })).await;
    state.live.recheck();
    // Le demandeur : courriel (et Teams/webhook pour la trace).
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND email <> ''").bind(r.user_id).fetch_optional(db).await?;
    let when = until.map(|u| u.with_timezone(&chrono::Local).format("%d/%m %H:%M").to_string()).unwrap_or_default();
    let text = if grant {
        t!(format!("{by} granted your access to {} until {when}.{}", r.target, if comment.is_empty() { String::new() } else { format!("\n{comment}") }),
           format!("{by} a accordé votre accès à {} jusqu'au {when}.{}", r.target, if comment.is_empty() { String::new() } else { format!("\n{comment}") })).to_string()
    } else {
        t!(format!("{by} refused your access to {}.{}", r.target, if comment.is_empty() { String::new() } else { format!("\n{comment}") }),
           format!("{by} a refusé votre accès à {}.{}", r.target, if comment.is_empty() { String::new() } else { format!("\n{comment}") })).to_string()
    };
    notify::send(
        state.clone(),
        notify::Notice {
            event,
            title: if grant { t!(format!("Access granted: {}", r.target), format!("Accès accordé : {}", r.target)).to_string() } else { t!(format!("Access refused: {}", r.target), format!("Accès refusé : {}", r.target)).to_string() },
            text,
            detail: json!({ "demande": id, "compte": r.login, "serveur": r.target, "par": by, "jusqua": until }),
            to: email.into_iter().collect(),
        },
    );
    get(db, id).await?.ok_or_else(|| anyhow!("demande introuvable"))
}

/// Annule une demande en attente (son auteur) ou retire un accès accordé (un approbateur) :
/// les sessions ouvertes grâce à lui se ferment.
pub async fn cancel(state: &Arc<State>, actor: &User, id: Uuid) -> Result<()> {
    cancel_by(state, &actor.login, Some(actor), id).await
}

/// Annulation par `by` ; `checked` : le compte dont on vérifie les droits (`None` : la console).
pub async fn cancel_by(state: &Arc<State>, by: &str, checked: Option<&User>, id: Uuid) -> Result<()> {
    let db = &state.db;
    let r = get(db, id).await?.ok_or_else(|| anyhow!(t!("Unknown request", "Demande inconnue")))?;
    let open = matches!(r.status.as_str(), "attente" | "accordee");
    let allowed = open
        && match checked {
            None => true,
            Some(actor) => actor.id == r.user_id || can_decide(db, actor, &r).await?,
        };
    if !allowed {
        bail!(t!("This request cannot be cancelled", "Cette demande ne peut pas être annulée"));
    }
    sqlx::query("UPDATE approvals SET status = 'annulee', until = LEAST(until, now()), decided_by = CASE WHEN decided_by = '' THEN $2 ELSE decided_by END WHERE id = $1")
        .bind(id)
        .bind(by)
        .execute(db)
        .await?;
    audit::note(db, by, "approbation.annulee", json!({ "demande": id, "compte": r.login, "cible": r.target, "etait": r.status })).await;
    state.live.recheck();
    Ok(())
}

/// Préavis de fin, fin des accès accordés, expiration des demandes sans réponse.
pub async fn run(state: Arc<State>) -> Result<()> {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tick.tick().await;
        if let Err(e) = sweep(&state).await {
            tracing::warn!("{} {e:#}", t!("approvals:", "approbations :"));
        }
    }
}

async fn sweep(state: &Arc<State>) -> Result<()> {
    let db = &state.db;
    let stale: Vec<(Uuid, String)> = sqlx::query_as(
        "UPDATE approvals a SET status = 'expiree' FROM users u
         WHERE u.id = a.user_id AND a.status = 'attente' AND a.requested_at < now() - make_interval(hours => $1::int)
         RETURNING a.id, u.login",
    )
    .bind(PENDING_HOURS as i32)
    .fetch_all(db)
    .await?;
    for (id, login) in stale {
        audit::note(db, &login, "approbation.sans_reponse", json!({ "demande": id })).await;
    }
    let ending: Vec<(Uuid, Uuid, Uuid, DateTime<Utc>)> = sqlx::query_as(
        "UPDATE approvals SET warned = true
         WHERE status = 'accordee' AND NOT warned AND until > now() AND until <= now() + make_interval(mins => $1::int)
         RETURNING id, user_id, target_id, until",
    )
    .bind(WARN_MINUTES as i32)
    .fetch_all(db)
    .await?;
    for (_, user, target, until) in ending {
        let at = until.with_timezone(&chrono::Local).format("%H:%M");
        let left = (until - Utc::now()).num_minutes().max(1);
        state.live.notify_user_target(user, target, &t!(
            format!("Portunia Gate: your approved access ends at {at} (in {left} min); the session will then be closed."),
            format!("Portunia Gate : votre accès approuvé se termine à {at} (dans {left} min) ; la session sera alors fermée.")
        ));
    }
    let over: Vec<(Uuid, String, String)> = sqlx::query_as(
        "UPDATE approvals a SET status = 'expiree' FROM users u, targets t
         WHERE u.id = a.user_id AND t.id = a.target_id AND a.status = 'accordee' AND a.until <= now()
         RETURNING a.id, u.login, t.name",
    )
    .fetch_all(db)
    .await?;
    if !over.is_empty() {
        for (id, login, target) in over {
            audit::note(db, &login, "approbation.terminee", json!({ "demande": id, "cible": target })).await;
        }
        state.live.recheck();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durees() {
        assert!((MIN_MINUTES..=MAX_MINUTES).contains(&60));
        assert!(!(MIN_MINUTES..=MAX_MINUTES).contains(&1));
        assert!(!(MIN_MINUTES..=MAX_MINUTES).contains(&(8 * 24 * 60)));
    }
}
