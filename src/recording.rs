//! Enregistrement d'une session au format asciicast v2 (lisible par Portunia et asciinema),
//! signé à la fermeture par la clé de la Gate.

use std::{
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::Result;
use serde_json::json;
use uuid::Uuid;

use crate::keys::{sha256_hex, Keys};

pub struct Recorder {
    path: PathBuf,
    out: BufWriter<File>,
    start: Instant,
    record_input: bool,
    /// Fin de séquence UTF-8 coupée entre deux paquets, gardée pour le suivant.
    carry_out: Vec<u8>,
    carry_in: Vec<u8>,
    pub bytes: u64,
    /// Une écriture a échoué : l'enregistrement n'est plus complet.
    failed: bool,
}

impl Recorder {
    pub fn create(dir: &Path, session: Uuid, cols: u32, rows: u32, title: &str, record_input: bool) -> Result<Self> {
        let now = chrono::Utc::now();
        let dir = dir.join(now.format("%Y/%m").to_string());
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{session}.cast"));
        let mut out = BufWriter::new(File::create(&path)?);
        let header = json!({
            "version": 2,
            "width": if cols < 10 { 80 } else { cols },
            "height": if rows < 3 { 24 } else { rows },
            "timestamp": now.timestamp(),
            "title": title,
            "env": { "TERM": "xterm-256color" },
        });
        writeln!(out, "{header}")?;
        Ok(Self {
            path,
            out,
            start: Instant::now(),
            record_input,
            carry_out: Vec::new(),
            carry_in: Vec::new(),
            bytes: 0,
            failed: false,
        })
    }

    fn event(&mut self, kind: &str, text: &str) {
        if text.is_empty() {
            return;
        }
        let line = json!([self.start.elapsed().as_secs_f64(), kind, text]);
        self.failed |= writeln!(self.out, "{line}").is_err();
    }

    pub fn output(&mut self, data: &[u8]) {
        self.bytes += data.len() as u64;
        let text = take_utf8(&mut self.carry_out, data);
        self.event("o", &text);
    }

    pub fn input(&mut self, data: &[u8]) {
        if !self.record_input {
            return;
        }
        let text = take_utf8(&mut self.carry_in, data);
        self.event("i", &text);
    }

    pub fn resize(&mut self, cols: u32, rows: u32) {
        self.event("r", &format!("{cols}x{rows}"));
    }

    /// La session doit s'arrêter : elle ne serait plus enregistrée.
    /// Fichier de l'enregistrement.
    pub fn path(&self) -> String {
        self.path.display().to_string()
    }

    pub fn failed(&self) -> bool {
        self.failed
    }

    pub fn records_input(&self) -> bool {
        self.record_input
    }

    pub fn flush(&mut self) {
        self.failed |= self.out.flush().is_err();
    }

    /// Ferme le fichier ; renvoie son chemin, son empreinte et la signature de la Gate.
    /// Ce qui a pu être écrit reste signé, même après une erreur d'écriture.
    pub fn finish(mut self, keys: &Keys, session: Uuid) -> Result<(String, String, String, u64)> {
        let _ = self.out.flush();
        drop(self.out);
        let content = std::fs::read(&self.path)?;
        let sha = sha256_hex(&content);
        let signature = signature_message(session, &sha);
        use base64::Engine;
        let sig = base64::engine::general_purpose::STANDARD.encode(keys.sign(signature.as_bytes()));
        Ok((self.path.display().to_string(), sha, sig, self.bytes))
    }
}

/// Texte signé : l'enregistrement est lié à sa session, il ne peut pas être échangé avec un autre.
pub fn signature_message(session: Uuid, sha256: &str) -> String {
    format!("portunia-gate-enregistrement-v1\n{session}\n{sha256}")
}

/// Extension des enregistrements compressés (gzip), ajoutée au nom d'origine.
pub const COMPRESSED: &str = ".gz";

/// Contenu d'un enregistrement, tel que la Gate l'a écrit : décompressé s'il a été compressé.
/// Un fichier compressé entre-temps (`<chemin>.gz`) est lu aussi.
/// L'empreinte et la signature portent sur ce contenu, compressé ou non.
pub fn read(path: &str) -> std::io::Result<Vec<u8>> {
    let raw = match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !path.ends_with(COMPRESSED) => std::fs::read(format!("{path}{COMPRESSED}"))?,
        other => other?,
    };
    if raw.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::with_capacity(raw.len() * 6);
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&raw[..]), &mut out)?;
        Ok(out)
    } else {
        Ok(raw)
    }
}

/// Nom d'origine d'un enregistrement (sans « .gz ») : base des copies « <session>-fichiers ».
pub fn original(path: &Path) -> PathBuf {
    match path.to_str().and_then(|p| p.strip_suffix(COMPRESSED)) {
        Some(p) => PathBuf::from(p),
        None => path.to_path_buf(),
    }
}

/// Compresse un enregistrement terminé dans `<chemin>.gz`, s'il est intact (son empreinte est
/// `sha256`) : un fichier altéré est laissé tel quel, comme preuve. L'original n'est pas supprimé.
/// Renvoie le nouveau chemin et les tailles avant et après.
pub fn compress(path: &Path, sha256: &str) -> std::io::Result<(PathBuf, u64, u64)> {
    use std::io::{Error, ErrorKind, Read};
    let mut input = std::io::BufReader::with_capacity(1 << 20, File::open(path)?);
    let dest = PathBuf::from(format!("{}{COMPRESSED}", path.display()));
    let tmp = PathBuf::from(format!("{}{COMPRESSED}.tmp", path.display()));
    let result = (|| {
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        let mut gz = flate2::write::GzEncoder::new(BufWriter::new(File::create(&tmp)?), flate2::Compression::default());
        let mut buf = vec![0u8; 1 << 16];
        let mut before = 0u64;
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            before += n as u64;
            hash.update(&buf[..n]);
            gz.write_all(&buf[..n])?;
        }
        if crate::keys::hex(hash.finish().as_ref()) != sha256 {
            return Err(Error::new(ErrorKind::InvalidData, "empreinte différente : fichier altéré, laissé tel quel"));
        }
        let file = gz.finish()?.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        let after = file.metadata()?.len();
        std::fs::rename(&tmp, &dest)?;
        Ok((dest.clone(), before, after))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Décode ce qui est complet en UTF-8 et garde une séquence coupée pour la suite.
fn take_utf8(carry: &mut Vec<u8>, data: &[u8]) -> String {
    carry.extend_from_slice(data);
    let mut end = carry.len();
    // Une séquence UTF-8 fait au plus 4 octets : on ne recule que sur la fin.
    for back in 1..=3.min(carry.len()) {
        let b = carry[carry.len() - back];
        if b & 0xC0 == 0x80 {
            continue;
        }
        if b >= 0xC0 {
            let need = if b >= 0xF0 {
                4
            } else if b >= 0xE0 {
                3
            } else {
                2
            };
            if back < need {
                end = carry.len() - back;
            }
        }
        break;
    }
    let rest = carry.split_off(end);
    let text = String::from_utf8_lossy(carry).into_owned();
    *carry = rest;
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn disque_plein() {
        // /dev/full refuse toute écriture, comme un disque plein.
        let out = BufWriter::with_capacity(1, std::fs::OpenOptions::new().write(true).open("/dev/full").unwrap());
        let mut r = Recorder { path: "/dev/full".into(), out, start: Instant::now(), record_input: true, carry_out: Vec::new(), carry_in: Vec::new(), bytes: 0, failed: false };
        assert!(!r.failed());
        r.output(b"texte");
        r.flush();
        assert!(r.failed());
    }

    #[test]
    fn compression() {
        let dir = std::env::temp_dir().join(format!("portunia-gate-compression-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.cast");
        let content: String = (0..2000).map(|i| format!("[{i}.0, \"o\", \"ligne {i} du terminal\\r\\n\"]\n")).collect();
        std::fs::write(&path, &content).unwrap();
        let sha = sha256_hex(content.as_bytes());
        assert!(compress(&path, "0000").is_err(), "empreinte différente : pas de compression");
        assert!(!dir.join("s.cast.gz").exists() && !dir.join("s.cast.gz.tmp").exists());
        let (dest, before, after) = compress(&path, &sha).unwrap();
        assert_eq!(dest, dir.join("s.cast.gz"));
        assert!(before == content.len() as u64 && after * 4 < before, "{before} → {after}");
        // Lu à l'ancien chemin (déjà supprimé) comme au nouveau, et identique à l'original.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(read(path.to_str().unwrap()).unwrap(), content.as_bytes());
        assert_eq!(read(dest.to_str().unwrap()).unwrap(), content.as_bytes());
        assert_eq!(original(&dest), path);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn utf8_coupe() {
        let mut carry = Vec::new();
        let e = "é".as_bytes();
        assert_eq!(take_utf8(&mut carry, &[b'a', e[0]]), "a");
        assert_eq!(take_utf8(&mut carry, &[e[1], b'b']), "éb");
        assert!(carry.is_empty());
    }
}
