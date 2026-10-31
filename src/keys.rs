//! Clés de la Gate, créées à l'installation dans le dossier de données :
//! - coffre.key : 32 octets, chiffre les secrets des cibles et les secrets TOTP ;
//! - ssh_host_ed25519_key : identité SSH de la Gate ;
//! - signature.key : signe les enregistrements (Ed25519, PKCS#8).

use std::{fs, io::Write, path::Path};

use anyhow::{anyhow, Context, Result};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN},
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use russh::keys::{
    ssh_key::{private::Ed25519Keypair, LineEnding},
    HashAlg, PrivateKey,
};

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| anyhow!(t!("random generator unavailable", "générateur aléatoire indisponible")))?;
    Ok(out)
}

/// Écrit un fichier lisible par le seul propriétaire, sans jamais en écraser un existant.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| t!(format!("creating {}", path.display()), format!("création de {}", path.display())))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub struct Keys {
    vault: LessSafeKey,
    pub host: PrivateKey,
    signer: Ed25519KeyPair,
}

impl Keys {
    /// Crée les clés manquantes (installation). Ne remplace jamais une clé existante.
    pub fn create_missing(dir: &Path) -> Result<Vec<String>> {
        fs::create_dir_all(dir)?;
        let mut created = Vec::new();
        let vault = dir.join("coffre.key");
        if !vault.exists() {
            write_private(&vault, &random::<32>()?)?;
            created.push(vault.display().to_string());
        }
        let host = dir.join("ssh_host_ed25519_key");
        if !host.exists() {
            let key = PrivateKey::from(Ed25519Keypair::from_seed(&random::<32>()?));
            let text = key.to_openssh(LineEnding::LF).map_err(|e| anyhow!("clé SSH : {e}"))?;
            write_private(&host, text.as_bytes())?;
            created.push(host.display().to_string());
        }
        let signature = dir.join("signature.key");
        if !signature.exists() {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| anyhow!("clé de signature"))?;
            write_private(&signature, pkcs8.as_ref())?;
            created.push(signature.display().to_string());
        }
        Ok(created)
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let raw = fs::read(dir.join("coffre.key")).context(t!("vault key unreadable (run « portunia-gate init »)", "clé du coffre illisible (lancez « portunia-gate init »)"))?;
        let vault = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &raw).map_err(|_| anyhow!(t!("invalid vault key", "clé du coffre invalide")))?);
        let host = russh::keys::load_secret_key(dir.join("ssh_host_ed25519_key"), None).context(t!("SSH host key unreadable", "clé d'hôte SSH illisible"))?;
        let signer = Ed25519KeyPair::from_pkcs8(&fs::read(dir.join("signature.key")).context(t!("signing key unreadable", "clé de signature illisible"))?)
            .map_err(|_| anyhow!(t!("invalid signing key", "clé de signature invalide")))?;
        Ok(Self { vault, host, signer })
    }

    pub fn host_fingerprint(&self) -> String {
        self.host.public_key().fingerprint(HashAlg::Sha256).to_string()
    }

    /// Chiffre un secret. `purpose` le lie à son usage : un secret copié ailleurs ne se déchiffre pas.
    pub fn seal(&self, purpose: &str, plain: &[u8]) -> Result<Vec<u8>> {
        let nonce = random::<NONCE_LEN>()?;
        let mut data = plain.to_vec();
        self.vault
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad(purpose)), &mut data)
            .map_err(|_| anyhow!(t!("encryption failed", "chiffrement impossible")))?;
        let mut out = nonce.to_vec();
        out.extend(data);
        Ok(out)
    }

    pub fn open(&self, purpose: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN {
            return Err(anyhow!(t!("damaged secret", "secret abîmé")));
        }
        let (nonce, data) = sealed.split_at(NONCE_LEN);
        let mut data = data.to_vec();
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| anyhow!(t!("damaged secret", "secret abîmé")))?;
        let plain = self
            .vault
            .open_in_place(nonce, Aad::from(aad(purpose)), &mut data)
            .map_err(|_| anyhow!(t!("unreadable secret (different vault key?)", "secret illisible (clé du coffre différente ?)")))?;
        Ok(plain.to_vec())
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signer.sign(message).as_ref().to_vec()
    }

    pub fn signature_public_key(&self) -> Vec<u8> {
        self.signer.public_key().as_ref().to_vec()
    }

    /// Vérifie une signature produite par `sign` (clé publique de la Gate).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, self.signer.public_key().as_ref())
            .verify(message, signature)
            .is_ok()
    }
}

fn aad(purpose: &str) -> Vec<u8> {
    format!("portunia-gate-coffre-v1:{purpose}").into_bytes()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coffre_lie_au_usage() {
        let dir = std::env::temp_dir().join(format!("portunia-gate-cles-{}", uuid::Uuid::new_v4()));
        Keys::create_missing(&dir).unwrap();
        let keys = Keys::load(&dir).unwrap();
        let sealed = keys.seal("cible:a", b"secret").unwrap();
        assert_eq!(keys.open("cible:a", &sealed).unwrap(), b"secret");
        assert!(keys.open("cible:b", &sealed).is_err(), "un secret ne sert qu'à son usage");
        assert!(Keys::create_missing(&dir).unwrap().is_empty(), "rien n'est recréé");
        fs::remove_dir_all(dir).unwrap();
    }
}
