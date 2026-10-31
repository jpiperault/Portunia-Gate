//! Journal d'audit chaîné : chaque événement porte l'empreinte du précédent,
//! si bien qu'une ligne supprimée ou modifiée casse la chaîne.

use anyhow::Result;
use chrono::{DateTime, SubsecRound, Utc};
use serde_json::Value;
use sqlx::PgPool;

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

/// Ajoute un événement. Un verrou de transaction sérialise les écritures.
///
/// L'écriture se fait dans sa propre tâche : si l'appelant est interrompu (client qui se
/// déconnecte), la transaction va quand même jusqu'au bout et libère le verrou. Sans cela,
/// un verrou resté pris bloquait toutes les écritures suivantes, puis tout la Gate.
pub async fn log(db: &PgPool, actor: &str, event: &str, detail: Value) -> Result<()> {
    let (db, actor, event) = (db.clone(), actor.to_string(), event.to_string());
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

pub async fn last(db: &PgPool, count: i64) -> Result<Vec<Entry>> {
    let mut rows: Vec<Entry> = sqlx::query_as("SELECT * FROM audit ORDER BY seq DESC LIMIT $1")
        .bind(count)
        .fetch_all(db)
        .await?;
    rows.reverse();
    Ok(rows)
}

/// Vérifie toute la chaîne. Renvoie le nombre d'événements, ou le premier maillon cassé.
pub async fn verify(db: &PgPool) -> Result<std::result::Result<i64, String>> {
    let rows: Vec<Entry> = sqlx::query_as("SELECT * FROM audit ORDER BY seq").fetch_all(db).await?;
    let mut prev = GENESIS.to_string();
    for (i, row) in rows.iter().enumerate() {
        let expected_seq = i as i64 + 1;
        if row.seq != expected_seq {
            return Ok(Err(t!(format!("event #{expected_seq} missing"), format!("événement n° {expected_seq} manquant"))));
        }
        if row.prev_hash != prev || link(&prev, row.seq, &row.at, &row.actor, &row.event, &row.detail) != row.hash {
            return Ok(Err(t!(format!("event #{} modified", row.seq), format!("événement n° {} modifié", row.seq))));
        }
        prev = row.hash.clone();
    }
    Ok(Ok(rows.len() as i64))
}
