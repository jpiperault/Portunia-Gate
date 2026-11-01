//! Certificat HTTPS de l'API : auto-signé et créé à l'installation, ou fourni par
//! l'entreprise (PORTUNIA_GATE_TLS_CERT et PORTUNIA_GATE_TLS_KEY, fichiers PEM).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

pub fn files(data_dir: &Path) -> TlsFiles {
    // Variables vides (Docker Compose les transmet ainsi quand .env ne les définit pas) : non définies.
    let var = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    match (var("PORTUNIA_GATE_TLS_CERT"), var("PORTUNIA_GATE_TLS_KEY")) {
        (Some(cert), Some(key)) => TlsFiles {
            cert: cert.into(),
            key: key.into(),
        },
        _ => TlsFiles {
            cert: data_dir.join("api.crt"),
            key: data_dir.join("api.key"),
        },
    }
}

/// Crée le certificat auto-signé s'il manque. Renvoie vrai s'il vient d'être créé.
pub fn create_missing(data_dir: &Path, names: &[String]) -> Result<bool> {
    let f = files(data_dir);
    if f.cert.exists() {
        return Ok(false);
    }
    write_self_signed(names, "Portunia Gate", &f.cert, &f.key)?;
    Ok(true)
}

/// Crée un certificat auto-signé et sa clé.
pub fn write_self_signed(names: &[String], common_name: &str, cert_path: &Path, key_path: &Path) -> Result<()> {
    let mut params = rcgen::CertificateParams::new(names.to_vec()).map_err(|e| anyhow!("certificat : {e}"))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2045, 1, 1);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| anyhow!("clé du certificat : {e}"))?;
    let cert = params.self_signed(&key).map_err(|e| anyhow!("certificat : {e}"))?;
    crate::keys::write_private(key_path, key.serialize_pem().as_bytes())?;
    std::fs::write(cert_path, cert.pem())?;
    Ok(())
}

/// Empreinte SHA-256 du certificat (DER), telle que Portunia l'affiche : « AB:CD:… ».
pub fn fingerprint(data_dir: &Path) -> Result<String> {
    let pem = std::fs::read(files(data_dir).cert).context(t!("API certificate unreadable", "certificat de l'API illisible"))?;
    let der = rustls_pemfile_first(&pem)?;
    Ok(format_fingerprint(&der))
}

pub fn format_fingerprint(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    digest.as_ref().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Premier certificat d'un fichier PEM (le certificat du serveur, avant la chaîne).
fn rustls_pemfile_first(pem: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem).context("certificat : PEM attendu")?;
    let start = text
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or_else(|| anyhow!("certificat : PEM attendu"))?;
    let body = &text[start + 27..];
    let end = body
        .find("-----END CERTIFICATE-----")
        .ok_or_else(|| anyhow!("certificat : PEM incomplet"))?;
    let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(b64)?)
}
