//! Téléphones enrôlés (Gate 0.47) : l'application Android Portunia Gate crée une clé ECDSA P-256
//! dans le Keystore du téléphone, qui ne sort jamais de sa puce et ne signe qu'après l'empreinte.
//! L'enrôlement se fait juste après une connexion au portail par mot de passe et code ; la Gate
//! garde la clé publique. Ensuite, la connexion au portail se fait par un défi à usage unique
//! signé par le téléphone : possession du téléphone et empreinte, deux facteurs.
//!
//! Retrait : par l'utilisateur (dans l'application), par un administrateur (Portunia, ligne de
//! commande), avec la réinitialisation du mot de passe ou du code, la désactivation du compte,
//! ou au bout de 90 jours sans usage.

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::keys::random;

/// Téléphones par compte, au plus.
pub const MAX_PER_USER: i64 = 5;
/// Sans usage pendant ce nombre de jours, un téléphone est retiré.
pub const EXPIRY_DAYS: i64 = 90;
/// L'enrôlement suit de près une connexion par mot de passe et code.
pub const ENROL_WITHIN_MIN: i64 = 10;
/// Durée de validité d'un défi.
const CHALLENGE_TTL: Duration = Duration::from_secs(90);

/// En-tête DER d'une clé publique P-256 (SubjectPublicKeyInfo, point non compressé), telle que
/// la donne Android (`PublicKey.getEncoded()`).
const SPKI_P256: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Point de la clé publique (65 octets, 0x04‖X‖Y), depuis la clé envoyée par le téléphone.
pub fn public_point(spki: &[u8]) -> Result<Vec<u8>> {
    if spki.len() != SPKI_P256.len() + 65 || spki[..SPKI_P256.len()] != SPKI_P256 || spki[SPKI_P256.len()] != 0x04 {
        bail!("{}", t!("public key: P-256 expected", "clé publique : P-256 attendue"));
    }
    // Un point hors de la courbe est refusé par ring à chaque vérification.
    Ok(spki[SPKI_P256.len()..].to_vec())
}

/// Message signé par le téléphone pour un défi.
pub fn message(device: Uuid, challenge: &str) -> Vec<u8> {
    format!("portunia-gate-appareil:{device}:{challenge}").into_bytes()
}

/// Signature ECDSA P-256 / SHA-256 (DER, comme `Signature("SHA256withECDSA")` d'Android).
pub fn verify(point: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, point).verify(msg, signature).is_ok()
}

static CHALLENGES: LazyLock<Mutex<HashMap<String, (Uuid, Instant)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Défi à usage unique pour ce téléphone.
pub fn challenge(device: Uuid) -> Result<String> {
    let c = B64URL.encode(random::<32>()?);
    let mut map = CHALLENGES.lock().unwrap();
    map.retain(|_, (_, at)| at.elapsed() < CHALLENGE_TTL);
    if map.len() > 2000 {
        bail!("{}", t!("Too many requests: try again in a minute", "Trop de demandes : réessayez dans une minute"));
    }
    map.insert(c.clone(), (device, Instant::now()));
    Ok(c)
}

/// Défi encore valable, donné à ce téléphone ; consommé dans tous les cas.
pub fn take(challenge: &str, device: Uuid) -> bool {
    match CHALLENGES.lock().unwrap().remove(challenge) {
        Some((d, at)) => d == device && at.elapsed() < CHALLENGE_TTL,
        None => false,
    }
}

pub struct Device {
    pub id: Uuid,
    pub user: Uuid,
    pub name: String,
    pub key: Vec<u8>,
    pub created: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

impl Device {
    /// Plus servi depuis 90 jours (ou jamais depuis son enrôlement).
    pub fn expired(&self) -> bool {
        Utc::now() - self.last_used.unwrap_or(self.created) > chrono::Duration::days(EXPIRY_DAYS)
    }
}

pub async fn get(db: &PgPool, id: Uuid) -> Result<Option<Device>> {
    let row: Option<(Uuid, Uuid, String, Vec<u8>, DateTime<Utc>, Option<DateTime<Utc>>)> =
        sqlx::query_as("SELECT id, user_id, nom, cle, created_at, last_used FROM appareils WHERE id = $1").bind(id).fetch_optional(db).await?;
    Ok(row.map(|(id, user, name, key, created, last_used)| Device { id, user, name, key, created, last_used }))
}

/// Enregistre un téléphone ; refusé au-delà de 5 par compte.
pub async fn add(db: &PgPool, user: Uuid, name: &str, point: &[u8], address: &str) -> Result<Uuid> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM appareils WHERE user_id = $1").bind(user).fetch_one(db).await?;
    if count >= MAX_PER_USER {
        bail!("{}", t!(format!("At most {MAX_PER_USER} phones per account: remove one first"), format!("Au plus {MAX_PER_USER} téléphones par compte : retirez-en un d'abord")));
    }
    let id = Uuid::new_v4();
    let name: String = name.trim().chars().filter(|c| !c.is_control()).take(60).collect();
    let name = if name.is_empty() { t!("Phone", "Téléphone").to_string() } else { name };
    sqlx::query("INSERT INTO appareils (id, user_id, nom, cle, address) VALUES ($1, $2, $3, $4, $5)")
        .bind(id)
        .bind(user)
        .bind(&name)
        .bind(point)
        .bind(address)
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn used(db: &PgPool, id: Uuid, address: &str) -> Result<()> {
    sqlx::query("UPDATE appareils SET last_used = now(), address = $2 WHERE id = $1").bind(id).bind(address).execute(db).await?;
    Ok(())
}

/// Retire un téléphone (ses sessions du portail se ferment avec lui) ; son nom s'il existait.
pub async fn remove(db: &PgPool, id: Uuid) -> Result<Option<(Uuid, String)>> {
    Ok(sqlx::query_as("DELETE FROM appareils WHERE id = $1 RETURNING user_id, nom").bind(id).fetch_optional(db).await?)
}

/// Retire tous les téléphones d'un compte ; leur nombre.
pub async fn remove_all(db: &PgPool, user: Uuid) -> Result<u64> {
    Ok(sqlx::query("DELETE FROM appareils WHERE user_id = $1").bind(user).execute(db).await?.rows_affected())
}

/// Téléphones d'un compte, pour Portunia et la ligne de commande.
pub async fn list(db: &PgPool, user: Uuid) -> Result<Vec<Value>> {
    let rows: Vec<(Uuid, String, DateTime<Utc>, Option<DateTime<Utc>>, String)> =
        sqlx::query_as("SELECT id, nom, created_at, last_used, address FROM appareils WHERE user_id = $1 ORDER BY created_at").bind(user).fetch_all(db).await?;
    Ok(rows
        .into_iter()
        .map(|(id, nom, created, last_used, address)| json!({ "id": id, "nom": nom, "enrole": created, "utilise": last_used, "adresse": address }))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    #[test]
    fn defi_signe() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        // Clé publique comme Android l'envoie : en-tête SPKI puis le point.
        let mut spki = SPKI_P256.to_vec();
        spki.extend_from_slice(pair.public_key().as_ref());
        let point = public_point(&spki).unwrap();
        let device = Uuid::new_v4();
        let c = challenge(device).unwrap();
        let sig = pair.sign(&rng, &message(device, &c)).unwrap();
        assert!(verify(&point, &message(device, &c), sig.as_ref()));
        assert!(!verify(&point, &message(Uuid::new_v4(), &c), sig.as_ref()));
        // Défi à usage unique, lié au téléphone.
        assert!(!take(&c, Uuid::new_v4()));
        let c2 = challenge(device).unwrap();
        assert!(take(&c2, device));
        assert!(!take(&c2, device));
        assert!(public_point(&spki[1..]).is_err());
    }
}
