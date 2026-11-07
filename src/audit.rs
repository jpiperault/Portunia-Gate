//! Journal d'audit chaîné : chaque événement porte l'empreinte du précédent,
//! si bien qu'une ligne supprimée ou modifiée casse la chaîne.

use anyhow::Result;
use chrono::{DateTime, SubsecRound, Utc};
use serde_json::Value;
use sqlx::PgPool;

use crate::keys::Keys;

const GENESIS: &str = "portunia-gate-journal-v1";

fn link(prev: &str, seq: i64, at: &DateTime<Utc>, actor: &str, event: &str, detail: &Value) -> String {
    // serde_json trie les clés des objets : le texte est stable d'une lecture à l'autre.
    let text = format!(
        "{prev}\n{seq}\n{}\n{actor}\n{event}\n{}",
        at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        detail
    );
    crate::keys::sha256_hex(text.as_bytes())
}

/// Un nom vient parfois d'une tentative sans compte : il reste court et sur une ligne.
fn clean_actor(actor: &str) -> String {
    actor.chars().take(64).map(|c| if c.is_control() { '_' } else { c }).collect()
}

/// Ajoute un événement. Un verrou de transaction sérialise les écritures.
///
/// L'écriture se fait dans sa propre tâche : si l'appelant est interrompu (client qui se
/// déconnecte), la transaction va quand même jusqu'au bout et libère le verrou. Sans cela,
/// un verrou resté pris bloquait toutes les écritures suivantes, puis tout la Gate.
pub async fn log(db: &PgPool, actor: &str, event: &str, detail: Value) -> Result<()> {
    let (db, actor, event) = (db.clone(), clean_actor(actor), event.to_string());
    tokio::spawn(async move { write(&db, &actor, &event, detail).await })
        .await
        .map_err(|e| anyhow::anyhow!(t!(format!("audit log: {e}"), format!("journal d'audit : {e}"))))?
}

async fn write(db: &PgPool, actor: &str, event: &str, detail: Value) -> Result<()> {
    let mut tx = db.begin().await?;
    // Jamais d'attente sans fin sur le verrou du journal.
    sqlx::query("SET LOCAL lock_timeout = '10s'").execute(&mut *tx).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(7340301)").execute(&mut *tx).await?;
    let last: Option<(i64, String)> = sqlx::query_as("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
        .fetch_optional(&mut *tx)
        .await?;
    let (seq, prev) = match last {
        Some((seq, hash)) => (seq + 1, hash),
        None => (1, GENESIS.to_string()),
    };
    // PostgreSQL garde la microseconde : on hache exactement ce qui sera relu.
    let at = Utc::now().trunc_subsecs(6);
    let hash = link(&prev, seq, &at, actor, event, &detail);
    sqlx::query("INSERT INTO audit (seq, at, actor, event, detail, prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(seq)
        .bind(at)
        .bind(actor)
        .bind(event)
        .bind(&detail)
        .bind(&prev)
        .bind(&hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!(actor, event, %detail, "audit");
    Ok(())
}

/// Écrit dans le journal sans interrompre l'action en cours si la base répond mal :
/// l'échec est signalé dans les traces du service.
pub async fn note(db: &PgPool, actor: &str, event: &str, detail: Value) {
    if let Err(e) = log(db, actor, event, detail).await {
        tracing::error!("journal d'audit : {e:#}");
    }
}

#[derive(sqlx::FromRow)]
pub struct Entry {
    pub seq: i64,
    pub at: DateTime<Utc>,
    pub actor: String,
    pub event: String,
    pub detail: Value,
    pub prev_hash: String,
    pub hash: String,
}

/// Réglage : jours de conservation du journal (0 : gardé toujours).
pub const RETENTION: &str = "journal_jours";
/// En deçà, la purge est refusée : le journal sert de preuve.
pub const MIN_DAYS: i64 = 90;

/// Texte signé d'une ancre : la chaîne reprend à `seq`, dont le précédent avait l'empreinte `prev`.
fn anchor_message(seq: i64, prev: &str) -> String {
    format!("portunia-gate-journal-ancre-v1\n{seq}\n{prev}")
}

/// Point de départ de la chaîne : la dernière ancre (signature vérifiée), sinon le début.
async fn start<'e, E: sqlx::PgExecutor<'e>>(db: E, keys: &Keys) -> Result<std::result::Result<(i64, String), String>> {
    let anchor: Option<(i64, String, String)> = sqlx::query_as("SELECT seq, prev_hash, signature FROM audit_ancres ORDER BY seq DESC LIMIT 1").fetch_optional(db).await?;
    let Some((seq, prev, sig)) = anchor else { return Ok(Ok((1, GENESIS.to_string()))) };
    use base64::Engine;
    let sig = base64::engine::general_purpose::STANDARD.decode(sig).unwrap_or_default();
    if !keys.verify(anchor_message(seq, &prev).as_bytes(), &sig) {
        return Ok(Err(t!(format!("purge anchor at event #{seq} modified"), format!("ancre de purge de l'événement n° {seq} modifiée"))));
    }
    Ok(Ok((seq, prev)))
}

/// Vérifie la chaîne depuis `(seq, prev)` jusqu'à `until` exclu (ou la fin), par lots.
/// Renvoie le nombre d'événements et l'empreinte du dernier, ou le premier maillon cassé.
async fn walk(tx: &mut sqlx::PgConnection, from: (i64, String), until: Option<i64>) -> Result<std::result::Result<(i64, String), String>> {
    let (mut expected, mut prev) = from;
    let mut count = 0i64;
    loop {
        let rows: Vec<Entry> = sqlx::query_as("SELECT * FROM audit WHERE seq >= $1 AND ($2::bigint IS NULL OR seq < $2) ORDER BY seq LIMIT 5000")
            .bind(expected)
            .bind(until)
            .fetch_all(&mut *tx)
            .await?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            if row.seq != expected {
                return Ok(Err(t!(format!("event #{expected} missing"), format!("événement n° {expected} manquant"))));
            }
            if row.prev_hash != prev || link(&prev, row.seq, &row.at, &row.actor, &row.event, &row.detail) != row.hash {
                return Ok(Err(t!(format!("event #{} modified", row.seq), format!("événement n° {} modifié", row.seq))));
            }
            prev = row.hash.clone();
            expected += 1;
            count += 1;
        }
    }
    // Des événements avant l'ancre auraient dû disparaître avec la purge : rien à vérifier.
    Ok(Ok((count, prev)))
}

/// Vérifie toute la chaîne (depuis la dernière purge). Renvoie le nombre d'événements, ou le
/// premier maillon cassé.
pub async fn verify(db: &PgPool, keys: &Keys) -> Result<std::result::Result<i64, String>> {
    let mut conn = db.acquire().await?;
    let from = match start(&mut *conn, keys).await? {
        Ok(f) => f,
        Err(e) => return Ok(Err(e)),
    };
    Ok(walk(&mut *conn, from, None).await?.map(|(n, _)| n))
}

/// Supprime les événements de plus de `days` jours (au moins MIN_DAYS), après avoir vérifié
/// qu'ils sont intacts : une chaîne cassée n'est jamais purgée, elle reste la preuve.
/// Le dernier événement est toujours gardé. Renvoie le nombre d'événements supprimés.
pub async fn purge(db: &PgPool, keys: &Keys, actor: &str, days: i64) -> Result<i64> {
    anyhow::ensure!(days >= MIN_DAYS, t!(format!("audit log retention: at least {MIN_DAYS} days"), format!("conservation du journal : au moins {MIN_DAYS} jours")));
    let mut tx = db.begin().await?;
    sqlx::query("SET LOCAL lock_timeout = '10s'").execute(&mut *tx).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(7340301)").execute(&mut *tx).await?;
    let keep: Option<(i64, String)> = sqlx::query_as(
        "SELECT seq, prev_hash FROM audit WHERE at >= now() - make_interval(days => $1::int) OR seq = (SELECT max(seq) FROM audit) ORDER BY seq LIMIT 1",
    )
    .bind(days as i32)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((keep, prev)) = keep else { return Ok(0) };
    let from = match start(&mut *tx, keys).await? {
        Ok(f) => f,
        Err(e) => anyhow::bail!(t!(format!("audit log not purged, it is altered: {e}"), format!("journal non purgé, il est altéré : {e}"))),
    };
    if from.0 >= keep {
        return Ok(0);
    }
    let removed = match walk(&mut *tx, from, Some(keep)).await? {
        Ok((n, last)) if last == prev => n,
        Ok(_) => anyhow::bail!(t!(format!("audit log not purged, it is altered: event #{keep} modified"), format!("journal non purgé, il est altéré : événement n° {keep} modifié"))),
        Err(e) => anyhow::bail!(t!(format!("audit log not purged, it is altered: {e}"), format!("journal non purgé, il est altéré : {e}"))),
    };
    use base64::Engine;
    let sig = base64::engine::general_purpose::STANDARD.encode(keys.sign(anchor_message(keep, &prev).as_bytes()));
    sqlx::query("INSERT INTO audit_ancres (seq, prev_hash, supprimes, signature) VALUES ($1, $2, $3, $4)")
        .bind(keep)
        .bind(&prev)
        .bind(removed)
        .bind(sig)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM audit WHERE seq < $1").bind(keep).execute(&mut *tx).await?;
    tx.commit().await?;
    log(db, actor, "journal.purge", serde_json::json!({ "supprimes": removed, "jours": days, "depuis": keep })).await?;
    Ok(removed)
}

/// Dernière purge : (premier événement gardé, événements supprimés, date).
pub async fn last_purge(db: &PgPool) -> Result<Option<(i64, i64, DateTime<Utc>)>> {
    Ok(sqlx::query_as("SELECT seq, supprimes, at FROM audit_ancres ORDER BY seq DESC LIMIT 1").fetch_optional(db).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nom_court_sur_une_ligne() {
        assert_eq!(clean_actor("alice"), "alice");
        assert_eq!(clean_actor("a\nb\t\u{0}c"), "a_b__c");
        assert_eq!(clean_actor(&"é".repeat(1_000_000)).chars().count(), 64);
    }
}
