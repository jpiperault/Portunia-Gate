//! Certificat présenté par l'écoute HTTPS du portail, distinct de celui de l'API (que les consoles
//! épinglent) : auto-signé, importé d'une PKI (PEM ou PFX), obtenu par Let's Encrypt, ou fichiers
//! nommés dans le fichier de configuration. Remplacé à chaud, sans rouvrir l'écoute.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex, RwLock},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{model, State};

pub const SETTING: &str = "portail_certificat";
const PURPOSE: &str = "reglage:certificat";
/// Protocole annoncé par l'autorité qui vérifie un défi TLS-ALPN-01 (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";
/// Alerte avant l'échéance d'un certificat qui ne se renouvelle pas seul.
pub const WARN_DAYS: i64 = 21;

#[derive(Serialize, Deserialize)]
struct Stored {
    /// « importe » ou « acme ».
    source: String,
    chaine: String,
    /// Clé PEM chiffrée par le coffre.
    cle: String,
}

/// Ce que l'administration affiche du certificat en place.
#[derive(Serialize, Clone, Debug)]
pub struct Info {
    /// auto, importe, acme ou fichier.
    pub source: String,
    /// Fixé par PORTUNIA_GATE_PORTAL_TLS_CERT : non modifiable depuis l'administration.
    pub fixe: bool,
    pub sujet: String,
    pub emetteur: String,
    pub noms: Vec<String>,
    pub debut: DateTime<Utc>,
    pub expire: DateTime<Utc>,
    pub auto_signe: bool,
    pub empreinte: String,
}

impl Info {
    pub fn days_left(&self) -> i64 {
        (self.expire - Utc::now()).num_days()
    }
}

// ---------- Choix du certificat pendant la négociation ----------

#[derive(Debug, Default)]
pub struct Resolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
    /// Certificats de défi TLS-ALPN-01, par nom demandé.
    challenges: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let acme = hello.alpn().is_some_and(|mut protocols| protocols.any(|p| p == ACME_TLS_ALPN));
        if acme {
            let name = hello.server_name()?.to_ascii_lowercase();
            return self.challenges.lock().unwrap_or_else(|e| e.into_inner()).get(&name).cloned();
        }
        self.current.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

pub static RESOLVER: LazyLock<Arc<Resolver>> = LazyLock::new(|| Arc::new(Resolver::default()));

/// Configuration TLS de l'écoute HTTPS : le certificat est lu à chaque connexion.
pub fn server_config() -> Result<Arc<rustls::ServerConfig>> {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(RESOLVER.clone());
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// Présente le certificat de défi TLS-ALPN-01 pour ce nom, le temps de la vérification.
pub fn add_challenge(name: &str, digest: &[u8]) -> Result<()> {
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).map_err(|e| anyhow!("{e}"))?;
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| anyhow!("{e}"))?;
    let cert = params.self_signed(&key).map_err(|e| anyhow!("{e}"))?;
    let (ck, _) = certified(&cert.pem(), &key.serialize_pem())?;
    RESOLVER
        .challenges
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(name.to_ascii_lowercase(), ck);
    Ok(())
}

pub fn clear_challenges() {
    RESOLVER.challenges.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

// ---------- Lecture et contrôle ----------

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// Contrôle une chaîne et sa clé ; le certificat qui correspond à la clé est mis en tête.
fn certified(chain_pem: &str, key_pem: &str) -> Result<(Arc<CertifiedKey>, Info)> {
    let mut certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .filter_map(|c| c.ok())
        .collect();
    if certs.is_empty() {
        bail!(t!(
            "no certificate found (PEM « BEGIN CERTIFICATE » expected)",
            "aucun certificat trouvé (PEM « BEGIN CERTIFICATE » attendu)"
        ));
    }
    if key_pem.contains("ENCRYPTED PRIVATE KEY") || key_pem.contains("Proc-Type: 4,ENCRYPTED") {
        bail!(t!(
            "the private key is password-protected: give it unencrypted, or import a PFX file",
            "la clé privée est protégée par un mot de passe : donnez-la en clair, ou importez un fichier PFX"
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|_| {
        anyhow!(t!(
            "no private key found (PEM « BEGIN PRIVATE KEY » expected)",
            "aucune clé privée trouvée (PEM « BEGIN PRIVATE KEY » attendu)"
        ))
    })?;
    let provider = rustls::crypto::ring::default_provider();
    let signer = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| anyhow!("{} {e}", t!("unsupported private key:", "clé privée non prise en charge :")))?;
    let public = signer
        .public_key()
        .ok_or_else(|| anyhow!(t!("unsupported private key", "clé privée non prise en charge")))?;
    let leaf = certs
        .iter()
        .position(|c| x509_parser::parse_x509_certificate(c).is_ok_and(|(_, x)| x.public_key().raw == public.as_ref()))
        .ok_or_else(|| {
            anyhow!(t!(
                "the private key does not match the certificate",
                "la clé privée ne correspond pas au certificat"
            ))
        })?;
    let first = certs.remove(leaf);
    certs.insert(0, first);
    let info = describe(&certs[0])?;
    Ok((Arc::new(CertifiedKey::new(certs, signer)), info))
}

fn describe(der: &[u8]) -> Result<Info> {
    use x509_parser::extensions::GeneralName;
    let (_, x) =
        x509_parser::parse_x509_certificate(der).map_err(|e| anyhow!("{} {e}", t!("unreadable certificate:", "certificat illisible :")))?;
    let short = |n: &x509_parser::x509::X509Name| {
        n.iter_common_name()
            .next()
            .and_then(|c| c.as_str().ok().map(str::to_owned))
            .or_else(|| n.iter_organization().next().and_then(|o| o.as_str().ok().map(str::to_owned)))
            .unwrap_or_else(|| n.to_string())
    };
    let mut names = Vec::new();
    if let Ok(Some(san)) = x.subject_alternative_name() {
        for n in &san.value.general_names {
            match n {
                GeneralName::DNSName(d) => names.push(d.to_string()),
                GeneralName::IPAddress(ip) => match ip.len() {
                    4 => names.push(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*ip).unwrap_or_default()).to_string()),
                    16 => names.push(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*ip).unwrap_or_default()).to_string()),
                    _ => {}
                },
                _ => {}
            }
        }
    }
    let time = |t: x509_parser::time::ASN1Time| DateTime::from_timestamp(t.timestamp(), 0).unwrap_or_default();
    Ok(Info {
        source: String::new(),
        fixe: false,
        sujet: short(x.subject()),
        emetteur: short(x.issuer()),
        noms: names,
        debut: time(x.validity().not_before),
        expire: time(x.validity().not_after),
        auto_signe: x.subject().as_raw() == x.issuer().as_raw(),
        empreinte: crate::tls::format_fingerprint(der),
    })
}

/// Fichier PFX (PKCS#12) : chaîne et clé au format PEM.
pub fn from_pfx(der: &[u8], password: &str) -> Result<(String, String)> {
    let store = p12_keystore::KeyStore::from_pkcs12(der, password, p12_keystore::Pkcs12ImportPolicy::Relaxed).map_err(|e| {
        let text = e.to_string();
        if text.to_lowercase().contains("mac") {
            anyhow!(t!("PFX: wrong password", "PFX : mot de passe incorrect"))
        } else {
            anyhow!("PFX : {text}")
        }
    })?;
    let mut extra = Vec::new();
    let mut found = None;
    for (_, entry) in store.entries() {
        match entry {
            p12_keystore::KeyStoreEntry::PrivateKeyChain(chain) if found.is_none() && !chain.certs().is_empty() => {
                found = Some(chain.clone())
            }
            p12_keystore::KeyStoreEntry::Certificate(c) => extra.push(c.as_der().to_vec()),
            _ => {}
        }
    }
    let chain = found.ok_or_else(|| {
        anyhow!(t!(
            "PFX: no certificate with its private key",
            "PFX : aucun certificat accompagné de sa clé privée"
        ))
    })?;
    let mut text: String = chain.certs().iter().map(|c| pem("CERTIFICATE", c.as_der())).collect();
    for der in extra {
        if !chain.certs().iter().any(|c| c.as_der() == der.as_slice()) {
            text.push_str(&pem("CERTIFICATE", &der));
        }
    }
    Ok((text, pem("PRIVATE KEY", chain.key().as_der())))
}

// ---------- Sources ----------

fn env_pair(cert: &str, key: &str) -> Option<(PathBuf, PathBuf)> {
    let var = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    Some((var(cert)?.into(), var(key)?.into()))
}

/// Certificat imposé par le fichier de configuration.
fn fixed_files() -> Option<(PathBuf, PathBuf)> {
    env_pair("PORTUNIA_GATE_PORTAL_TLS_CERT", "PORTUNIA_GATE_PORTAL_TLS_KEY")
}

pub fn is_fixed() -> bool {
    fixed_files().is_some()
}

fn auto_files(data_dir: &Path) -> (PathBuf, PathBuf) {
    (data_dir.join("portail.crt"), data_dir.join("portail.key"))
}

/// Ce qui identifie la source en place : la recharger seulement quand elle change.
enum Source {
    Files {
        cert: PathBuf,
        key: PathBuf,
        kind: &'static str,
        fixed: bool,
    },
    Stored(String),
}

impl Source {
    fn signature(&self) -> String {
        match self {
            Source::Files { cert, key, kind, .. } => {
                let stamp = |p: &Path| {
                    std::fs::metadata(p)
                        .map(|m| format!("{:?}:{}", m.modified().ok(), m.len()))
                        .unwrap_or_default()
                };
                format!("{kind}|{}|{}|{}|{}", cert.display(), stamp(cert), key.display(), stamp(key))
            }
            Source::Stored(raw) => format!(
                "base|{}",
                crate::keys::hex(ring::digest::digest(&ring::digest::SHA256, raw.as_bytes()).as_ref())
            ),
        }
    }
}

async fn stored_raw(state: &State) -> Result<Option<String>> {
    Ok(model::setting(&state.db, SETTING)
        .await?
        .filter(|v| v.is_object())
        .map(|v| v.to_string()))
}

async fn source(state: &State) -> Result<Source> {
    if let Some((cert, key)) = fixed_files() {
        return Ok(Source::Files {
            cert,
            key,
            kind: "fichier",
            fixed: true,
        });
    }
    if let Some(raw) = stored_raw(state).await? {
        return Ok(Source::Stored(raw));
    }
    // Ancienne configuration : le certificat de l'entreprise servait l'API et le portail.
    if let Some((cert, key)) = env_pair("PORTUNIA_GATE_TLS_CERT", "PORTUNIA_GATE_TLS_KEY") {
        return Ok(Source::Files {
            cert,
            key,
            kind: "fichier",
            fixed: false,
        });
    }
    let (cert, key) = auto_files(&state.config.data_dir);
    if !cert.exists() {
        let mut names = crate::tls_names();
        if let Some(host) = crate::portal::settings(state).await.ok().and_then(|s| host_of(&s.url)) {
            if !names.contains(&host) {
                names.insert(0, host);
            }
        }
        crate::tls::write_self_signed(&names, "Portunia Gate", &cert, &key)?;
    }
    Ok(Source::Files {
        cert,
        key,
        kind: "auto",
        fixed: false,
    })
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', ':']).next()?.to_string();
    (!host.is_empty()).then_some(host)
}

async fn load(state: &State, source: &Source) -> Result<(Arc<CertifiedKey>, Info)> {
    match source {
        Source::Files { cert, key, kind, fixed } => {
            let chain =
                std::fs::read_to_string(cert).with_context(|| format!("{} {}", t!("unreadable:", "illisible :"), cert.display()))?;
            let key = std::fs::read_to_string(key).with_context(|| format!("{} {}", t!("unreadable:", "illisible :"), key.display()))?;
            let (ck, mut info) = certified(&chain, &key)?;
            info.source = kind.to_string();
            info.fixe = *fixed;
            Ok((ck, info))
        }
        Source::Stored(raw) => {
            let stored: Stored = serde_json::from_str(raw)?;
            let sealed = base64::engine::general_purpose::STANDARD.decode(&stored.cle)?;
            let key = String::from_utf8(state.keys.open(PURPOSE, &sealed)?)?;
            let (ck, mut info) = certified(&stored.chaine, &key)?;
            info.source = stored.source;
            Ok((ck, info))
        }
    }
}

struct Current {
    signature: String,
    info: Option<Info>,
    error: Option<String>,
}

static CURRENT: Mutex<Option<Current>> = Mutex::new(None);

/// Met en place le certificat voulu s'il a changé (base, fichiers ou réglage).
pub async fn refresh(state: &State) -> Result<()> {
    let source = source(state).await?;
    let signature = source.signature();
    if CURRENT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|c| c.signature == signature)
    {
        return Ok(());
    }
    let loaded = load(state, &source).await;
    let mut current = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    match loaded {
        Ok((ck, info)) => {
            *RESOLVER.current.write().unwrap_or_else(|e| e.into_inner()) = Some(ck);
            tracing::info!(
                "{} {} ({}, {} {})",
                t!("portal certificate:", "certificat du portail :"),
                info.noms.join(", "),
                info.source,
                t!("expires", "expire le"),
                info.expire.format("%Y-%m-%d")
            );
            *current = Some(Current {
                signature,
                info: Some(info),
                error: None,
            });
        }
        Err(e) => {
            // Le certificat précédent reste servi.
            tracing::error!("{} {e:#}", t!("portal certificate:", "certificat du portail :"));
            let info = current.as_ref().and_then(|c| c.info.clone());
            *current = Some(Current {
                signature,
                info,
                error: Some(format!("{e:#}")),
            });
        }
    }
    Ok(())
}

/// Certificat servi en ce moment (après le premier `refresh`).
pub fn current() -> Option<Info> {
    CURRENT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|c| c.info.clone())
}

pub fn report() -> Value {
    let guard = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    let info = guard.as_ref().and_then(|c| c.info.clone());
    let error = guard.as_ref().and_then(|c| c.error.clone());
    let days = info.as_ref().map(Info::days_left);
    json!({
        "info": info,
        "jours": days,
        "alerte": days.is_some_and(|d| d <= WARN_DAYS),
        "fixe": is_fixed(),
        "erreur": error,
    })
}

/// Lecture sans rien changer, pour la ligne de commande.
pub async fn inspect(state: &State) -> Result<Info> {
    Ok(load(state, &source(state).await?).await?.1)
}

/// Enregistre un certificat (importé ou obtenu par ACME) ; le service le prend sous quelques secondes.
pub async fn store(state: &State, source: &str, chain_pem: &str, key_pem: &str) -> Result<Info> {
    if is_fixed() {
        bail!(t!(
            "The portal certificate is set by PORTUNIA_GATE_PORTAL_TLS_CERT in the configuration file: change it there",
            "Le certificat du portail est fixé par PORTUNIA_GATE_PORTAL_TLS_CERT dans le fichier de configuration : changez-le là"
        ));
    }
    let (_, mut info) = certified(chain_pem, key_pem)?;
    if info.expire <= Utc::now() {
        bail!(
            "{} {}",
            t!("certificate expired on", "certificat expiré le"),
            info.expire.format("%Y-%m-%d")
        );
    }
    // Chaîne réécrite proprement, certificat du serveur en tête.
    let (ck, _) = certified(chain_pem, key_pem)?;
    let chain: String = ck.cert.iter().map(|c| pem("CERTIFICATE", c)).collect();
    let sealed = base64::engine::general_purpose::STANDARD.encode(state.keys.seal(PURPOSE, key_pem.as_bytes())?);
    let stored = Stored {
        source: source.into(),
        chaine: chain,
        cle: sealed,
    };
    model::set_setting(&state.db, SETTING, serde_json::to_value(&stored)?).await?;
    info.source = source.into();
    Ok(info)
}

/// Revient au certificat auto-signé (ou aux fichiers du fichier de configuration).
pub async fn remove(state: &State) -> Result<()> {
    if is_fixed() {
        bail!(t!(
            "The portal certificate is set by PORTUNIA_GATE_PORTAL_TLS_CERT in the configuration file: change it there",
            "Le certificat du portail est fixé par PORTUNIA_GATE_PORTAL_TLS_CERT dans le fichier de configuration : changez-le là"
        ));
    }
    model::set_setting(&state.db, SETTING, json!("")).await
}

/// Source enregistrée en base (« importe », « acme »), s'il y en a une.
pub async fn stored_source(state: &State) -> Result<Option<String>> {
    Ok(match stored_raw(state).await? {
        Some(raw) => serde_json::from_str::<Stored>(&raw).ok().map(|s| s.source),
        None => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed(names: &[&str]) -> (String, String) {
        let params = rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn certificat_et_cle() {
        let (cert, key) = self_signed(&["portail.example.com", "10.0.5.4"]);
        let (_, info) = certified(&cert, &key).unwrap();
        assert_eq!(info.noms, vec!["portail.example.com", "10.0.5.4"]);
        assert!(info.auto_signe);
        assert!(info.expire > Utc::now());
        let (_, other) = self_signed(&["autre"]);
        assert!(certified(&cert, &other).is_err());
        assert!(certified("", &key).is_err());
        assert!(certified(&cert, "").is_err());
    }

    #[test]
    fn serveur_remis_en_tete() {
        let (leaf, key) = self_signed(&["a.example.com"]);
        let (ca, _) = self_signed(&["ca"]);
        let (ck, info) = certified(&format!("{ca}{leaf}"), &key).unwrap();
        assert_eq!(info.noms, vec!["a.example.com"]);
        assert_eq!(ck.cert.len(), 2);
    }

    #[test]
    fn pfx() {
        let (cert, key) = self_signed(&["pfx.example.com"]);
        let cert_der = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
        let key_der = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
        let chain = p12_keystore::PrivateKeyChain::new(
            vec![1u8],
            p12_keystore::PrivateKey::from_der(key_der.secret_der()).unwrap(),
            [p12_keystore::Certificate::from_der(&cert_der).unwrap()],
        );
        let mut store = p12_keystore::KeyStore::new();
        store.add_entry("portail", p12_keystore::KeyStoreEntry::PrivateKeyChain(chain));
        let der = store.writer("secret").write().unwrap();
        let (chain_pem, key_pem) = from_pfx(&der, "secret").unwrap();
        assert_eq!(certified(&chain_pem, &key_pem).unwrap().1.noms, vec!["pfx.example.com"]);
        assert!(from_pfx(&der, "faux").is_err());
    }

    #[test]
    fn hote_de_l_adresse() {
        assert_eq!(host_of("https://portail.example.com/x").as_deref(), Some("portail.example.com"));
        assert_eq!(host_of("https://portail.example.com:8446").as_deref(), Some("portail.example.com"));
        assert_eq!(host_of(""), None);
    }

    /// Comme l'autorité, ne vérifie rien : l'extension du défi est critique et inconnue de webpki.
    #[derive(Debug)]
    struct Blind(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for Blind {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Le certificat de défi n'est présenté qu'à l'autorité (ALPN acme-tls/1).
    #[tokio::test]
    async fn defi_tls_alpn() {
        let (cert, key) = self_signed(&["defi.example.com"]);
        let (ck, normal) = certified(&cert, &key).unwrap();
        *RESOLVER.current.write().unwrap() = Some(ck);
        add_challenge("defi.example.com", &[7u8; 32]).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config().unwrap());
        async fn served(acceptor: tokio_rustls::TlsAcceptor, alpn: Option<&[u8]>) -> Vec<u8> {
            let (a, b) = tokio::io::duplex(65536);
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(Blind(provider)))
                .with_no_client_auth();
            if let Some(p) = alpn {
                config.alpn_protocols = vec![p.to_vec()];
            }
            let server = tokio::spawn(async move { acceptor.accept(a).await.ok() });
            let name = rustls::pki_types::ServerName::try_from("defi.example.com").unwrap();
            let tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, b).await.unwrap();
            let der = tls.get_ref().1.peer_certificates().unwrap()[0].to_vec();
            drop(tls);
            let _ = server.await;
            der
        }
        let plain = served(acceptor.clone(), Some(b"http/1.1")).await;
        assert_eq!(crate::tls::format_fingerprint(&plain), normal.empreinte);
        let challenge = served(acceptor, Some(ACME_TLS_ALPN)).await;
        assert_ne!(crate::tls::format_fingerprint(&challenge), normal.empreinte);
        let (_, x) = x509_parser::parse_x509_certificate(&challenge).unwrap();
        assert!(x.extensions().iter().any(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31"));
        clear_challenges();
    }
}
