//! Mots de passe (Argon2id), codes TOTP (RFC 6238) et politique d'authentification.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use ring::hmac;

pub fn hash_password(password: &str) -> Result<String> {
    if password.chars().count() < 10 {
        bail!("Le mot de passe doit contenir au moins 10 caractères");
    }
    let salt = SaltString::encode_b64(&crate::keys::random::<16>()?).map_err(|e| anyhow!("sel : {e}"))?;
    Ok(Argon2::default().hash_password(password.as_bytes(), &salt).map_err(|e| anyhow!("hachage : {e}"))?.to_string())
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

// ---------- TOTP ----------

pub const TOTP_STEP: i64 = 30;

/// Code à 6 chiffres pour un pas de temps donné (HMAC-SHA1, comme les applications du marché).
pub fn totp_code(secret: &[u8], step: i64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let h = tag.as_ref();
    let offset = (h[h.len() - 1] & 0x0f) as usize;
    let value = u32::from_be_bytes([h[offset] & 0x7f, h[offset + 1], h[offset + 2], h[offset + 3]]);
    value % 1_000_000
}

pub fn current_step() -> i64 {
    chrono::Utc::now().timestamp() / TOTP_STEP
}

/// Pas accepté pour ce code (± 1 pas de tolérance d'horloge), à condition d'être
/// postérieur au dernier pas utilisé : un code ne sert qu'une fois.
pub fn totp_check(secret: &[u8], code: &str, last_step: i64) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = code.parse().ok()?;
    let now = current_step();
    (now - 1..=now + 1).find(|&step| step > last_step && totp_code(secret, step) == wanted)
}

pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for &b in bytes {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn otpauth_uri(issuer: &str, login: &str, secret: &[u8]) -> String {
    let enc = |s: &str| s.replace(' ', "%20").replace(':', "%3A");
    format!("otpauth://totp/{}:{}?secret={}&issuer={}&digits=6&period=30", enc(issuer), enc(login), base32(secret), enc(issuer))
}

/// Code QR à afficher dans un terminal (deux lignes de pixels par ligne de texte).
pub fn qr_terminal(text: &str) -> Result<String> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| anyhow!("code QR : {e}"))?;
    Ok(code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build())
}

// ---------- Politique ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Factor {
    Password,
    Key,
    Totp,
}

/// Combinaisons acceptées, par exemple « password+totp,key » : mot de passe avec code,
/// ou clé SSH seule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy(Vec<BTreeSet<Factor>>);

impl Policy {
    pub fn parse(text: &str) -> Result<Self> {
        let mut alternatives = Vec::new();
        for alt in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let mut set = BTreeSet::new();
            for factor in alt.split('+').map(str::trim) {
                set.insert(match factor {
                    "password" | "motdepasse" => Factor::Password,
                    "key" | "cle" | "clé" => Factor::Key,
                    "totp" | "code" => Factor::Totp,
                    other => bail!("facteur inconnu « {other} » (password, key, totp)"),
                });
            }
            if set == BTreeSet::from([Factor::Totp]) {
                bail!("le code TOTP seul ne suffit pas : associez-le à un mot de passe ou une clé");
            }
            alternatives.push(set);
        }
        if alternatives.is_empty() {
            bail!("politique vide");
        }
        Ok(Self(alternatives))
    }

    pub fn satisfied(&self, have: &BTreeSet<Factor>) -> bool {
        self.0.iter().any(|alt| alt.is_subset(have))
    }

    /// Une combinaison reste-t-elle atteignable en ajoutant `next` à ce qui est déjà prouvé ?
    pub fn could_use(&self, have: &BTreeSet<Factor>, next: Factor) -> bool {
        self.0.iter().any(|alt| alt.contains(&next) && have.iter().all(|f| alt.contains(f)))
    }

    pub fn needs_totp(&self) -> bool {
        self.0.iter().any(|alt| alt.contains(&Factor::Totp))
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let alts: Vec<String> = self
            .0
            .iter()
            .map(|alt| {
                alt.iter()
                    .map(|f| match f {
                        Factor::Password => "password",
                        Factor::Key => "key",
                        Factor::Totp => "totp",
                    })
                    .collect::<Vec<_>>()
                    .join("+")
            })
            .collect();
        write!(f, "{}", alts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_rfc6238() {
        // Vecteurs de la RFC 6238 (SHA1, secret « 12345678901234567890 »), 8 chiffres tronqués à 6.
        let secret = b"12345678901234567890";
        assert_eq!(totp_code(secret, 59 / 30), 287082);
        assert_eq!(totp_code(secret, 1111111109 / 30), 81804);
        assert_eq!(totp_code(secret, 2000000000 / 30), 279037);
    }

    #[test]
    fn code_unique() {
        let secret = b"abcdefghijabcdefghij";
        let step = current_step();
        let code = format!("{:06}", totp_code(secret, step));
        assert_eq!(totp_check(secret, &code, 0), Some(step));
        assert_eq!(totp_check(secret, &code, step), None, "déjà utilisé");
        assert_eq!(totp_check(secret, "12345", 0), None);
    }

    #[test]
    fn base32_rfc4648() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"f"), "MY");
    }

    #[test]
    fn politiques() {
        let p = Policy::parse("password+totp,key").unwrap();
        assert!(p.satisfied(&BTreeSet::from([Factor::Key])));
        assert!(!p.satisfied(&BTreeSet::from([Factor::Password])));
        assert!(p.satisfied(&BTreeSet::from([Factor::Password, Factor::Totp])));
        assert!(p.could_use(&BTreeSet::from([Factor::Password]), Factor::Totp));
        assert!(!p.could_use(&BTreeSet::from([Factor::Key]), Factor::Totp));
        assert!(Policy::parse("totp").is_err());
        assert_eq!(p.to_string(), "password+totp,key");
    }

    #[test]
    fn mots_de_passe() {
        let h = hash_password("un mot de passe solide").unwrap();
        assert!(verify_password(&h, "un mot de passe solide"));
        assert!(!verify_password(&h, "autre chose"));
        assert!(hash_password("court").is_err());
    }
}
