//! Enregistrement des sessions Bureau à distance (`.rdpcap`), et sa relecture.
//!
//! La Gate voit la session en clair (passage RDCleanPath). Il n'en garde que ce qu'il faut
//! pour la rejouer et l'auditer :
//! - les messages du serveur qui portent l'image (sans l'authentification NLA ni le
//!   presse-papiers, qui deviennent des événements) ;
//! - des événements : clics et position de la souris, texte copié-collé, disposition du
//!   clavier, et la frappe seulement si la règle d'accès l'enregistre.
//! Ce que le poste envoie (authentification, frappe non autorisée) n'est jamais écrit.
//!
//! Format v2 : une ligne d'en-tête JSON (`"format": "portunia-gate-rdp-v2"`), puis des blocs :
//! temps (f64, secondes, grand-boutien), sorte (u8 : 1 image, 2 événement JSON), longueur (u32),
//! octets. Le format v1 (Portunia Gate 0.8 et 0.9) gardait les deux sens bruts : il se relit en
//! repassant par le même tri, sans la frappe.

use std::{collections::HashMap, io::Write, path::PathBuf, time::Instant};

use anyhow::{bail, Result};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{keys::sha256_hex, State};

pub const DISPLAY: u8 = 1;
pub const EVENT: u8 = 2;

/// Un message RDP complet d'un sens de la connexion.
enum Pdu {
    /// Authentification NLA (CredSSP, encodage DER) : jamais gardée.
    Der,
    /// Résultat de l'autorisation anticipée (4 octets après NLA) : jamais gardé.
    EarlyAuth,
    /// Message « lent » : TPKT, X.224, MCS.
    Tpkt(Vec<u8>),
    /// Message « rapide » (fast-path) : image côté serveur, saisie côté poste.
    FastPath(Vec<u8>),
}

/// Découpe un sens de la connexion en messages complets, quelle que soit la taille des lectures.
#[derive(Default)]
struct Framer {
    buf: Vec<u8>,
    /// Un premier message TPKT a été vu : la phase NLA est finie.
    rdp: bool,
    /// Flux incompréhensible : on arrête de l'interpréter.
    lost: bool,
}

impl Framer {
    fn push(&mut self, data: &[u8]) -> Vec<Pdu> {
        let mut out = Vec::new();
        if self.lost {
            return out;
        }
        self.buf.extend_from_slice(data);
        loop {
            let Some(&first) = self.buf.first() else { break };
            let size = if first == 0x30 {
                der_size(&self.buf)
            } else if first == 0x03 {
                (self.buf.len() >= 4).then(|| u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize)
            } else if !self.rdp {
                Some(4)
            } else if first & 0x03 == 0 {
                fastpath_size(&self.buf)
            } else {
                self.lost = true;
                self.buf.clear();
                break;
            };
            let Some(size) = size else { break };
            if size < 2 {
                self.lost = true;
                self.buf.clear();
                break;
            }
            if self.buf.len() < size {
                break;
            }
            let pdu: Vec<u8> = self.buf.drain(..size).collect();
            out.push(if first == 0x30 {
                Pdu::Der
            } else if first == 0x03 {
                self.rdp = true;
                Pdu::Tpkt(pdu)
            } else if !self.rdp {
                Pdu::EarlyAuth
            } else {
                Pdu::FastPath(pdu)
            });
        }
        out
    }
}

/// Taille totale d'un élément DER (None : en-tête pas encore complet).
fn der_size(b: &[u8]) -> Option<usize> {
    let first = *b.get(1)?;
    if first < 0x80 {
        return Some(2 + first as usize);
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return Some(0);
    }
    let len = b.get(2..2 + n)?.iter().fold(0usize, |acc, &x| (acc << 8) | x as usize);
    Some(2 + n + len)
}

/// Taille totale d'un message fast-path (longueur sur un ou deux octets).
fn fastpath_size(b: &[u8]) -> Option<usize> {
    let l1 = *b.get(1)?;
    if l1 & 0x80 == 0 {
        Some(l1 as usize)
    } else {
        Some((((l1 & 0x7f) as usize) << 8) | *b.get(2)? as usize)
    }
}

/// Bloc de données GCC (type sur 2 octets, longueur sur 2 octets) cherché dans un message MCS.
fn gcc_block(data: &[u8], kind: u16) -> Option<&[u8]> {
    let tag = kind.to_le_bytes();
    (0..data.len().saturating_sub(4)).find_map(|i| {
        if data[i..i + 2] != tag {
            return None;
        }
        let len = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
        (len >= 8 && i + len <= data.len()).then(|| &data[i..i + len])
    })
}

fn u16le(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn u32le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Données d'un canal virtuel dans un message MCS « Send Data » (requête du poste ou
/// indication du serveur) : (canal, données).
fn send_data(pdu: &[u8]) -> Option<(u16, &[u8])> {
    // TPKT (4) + X.224 données (3) + MCS.
    let mcs = pdu.get(7..)?;
    let choice = mcs.first()? >> 2;
    if choice != 25 && choice != 26 {
        return None;
    }
    let channel = u16::from_be_bytes(mcs.get(3..5)?.try_into().ok()?);
    // Priorité et segmentation (1 octet), puis longueur PER.
    let l = *mcs.get(6)?;
    let (len, start) = if l & 0x80 == 0 { (l as usize, 7) } else { ((((l & 0x3f) as usize) << 8) | *mcs.get(7)? as usize, 8) };
    Some((channel, mcs.get(start..start + len)?))
}

/// Un sens du presse-papiers : morceaux en cours et format demandé par l'autre côté.
#[derive(Default)]
struct ClipSide {
    chunk: Vec<u8>,
    /// Format demandé par ce côté (la réponse viendra de l'autre).
    requested: Option<u32>,
}

/// Trie une session RDP (les deux sens, en clair) en blocs d'image et événements.
pub struct Tap {
    record_input: bool,
    server: Framer,
    client: Framer,
    /// Noms des canaux virtuels demandés par le poste, dans l'ordre.
    channel_names: Vec<String>,
    /// Canal du presse-papiers (« cliprdr »), une fois connu.
    cliprdr: Option<u16>,
    /// Presse-papiers : [poste, serveur].
    clip: [ClipSide; 2],
    last_move: f64,
}

pub enum Record {
    Display(f64, Vec<u8>),
    Event(f64, Value),
}

impl Tap {
    pub fn new(record_input: bool) -> Self {
        Self {
            record_input,
            server: Framer::default(),
            client: Framer::default(),
            channel_names: Vec::new(),
            cliprdr: None,
            clip: Default::default(),
            last_move: -1.0,
        }
    }

    /// Octets envoyés par le serveur.
    pub fn server(&mut self, t: f64, data: &[u8]) -> Vec<Record> {
        let mut out = Vec::new();
        for pdu in self.server.push(data) {
            match pdu {
                Pdu::Der | Pdu::EarlyAuth => {}
                Pdu::FastPath(p) => out.push(Record::Display(t, p)),
                Pdu::Tpkt(p) => {
                    // Réponse MCS : numéros des canaux virtuels, dans l'ordre demandé par le poste.
                    if self.cliprdr.is_none() && p.get(7..9) == Some(&[0x7f, 0x66]) {
                        if let Some(net) = gcc_block(&p, 0x0c03) {
                            let count = u16le(net, 6).unwrap_or(0) as usize;
                            let ids: Vec<u16> = (0..count).filter_map(|i| u16le(net, 8 + 2 * i)).collect();
                            self.cliprdr = self.channel_names.iter().position(|n| n == "cliprdr").and_then(|i| ids.get(i).copied());
                        }
                    }
                    match send_data(&p) {
                        Some((channel, data)) if Some(channel) == self.cliprdr => {
                            let data = data.to_vec();
                            self.clipboard(1, t, &data, &mut out);
                        }
                        _ => out.push(Record::Display(t, p)),
                    }
                }
            }
        }
        out
    }

    /// Octets envoyés par le poste.
    pub fn client(&mut self, t: f64, data: &[u8]) -> Vec<Record> {
        let mut out = Vec::new();
        for pdu in self.client.push(data) {
            match pdu {
                Pdu::Der | Pdu::EarlyAuth => {}
                Pdu::FastPath(p) => self.input(t, &p, &mut out),
                Pdu::Tpkt(p) => {
                    // Demande de connexion MCS : disposition du clavier et canaux demandés.
                    if p.get(7..9) == Some(&[0x7f, 0x65]) {
                        if let Some(layout) = gcc_block(&p, 0xc001).and_then(|core| u32le(core, 16)) {
                            out.push(Record::Event(t, json!({ "k": "clavier", "disposition": layout })));
                        }
                        if let Some(net) = gcc_block(&p, 0xc003) {
                            let count = u32le(net, 4).unwrap_or(0).min(31) as usize;
                            self.channel_names = (0..count)
                                .filter_map(|i| net.get(8 + 12 * i..16 + 12 * i))
                                .map(|n| String::from_utf8_lossy(n).trim_end_matches('\0').to_ascii_lowercase())
                                .collect();
                        }
                        continue;
                    }
                    if let Some((channel, data)) = send_data(&p) {
                        if Some(channel) == self.cliprdr {
                            let data = data.to_vec();
                            self.clipboard(0, t, &data, &mut out);
                        }
                    }
                }
            }
        }
        out
    }

    /// Saisie rapide du poste : souris toujours, clavier seulement si la règle l'enregistre.
    fn input(&mut self, t: f64, p: &[u8], out: &mut Vec<Record>) {
        let header = p[0];
        let mut at = if p.get(1).is_some_and(|l| l & 0x80 != 0) { 3 } else { 2 };
        let mut count = ((header >> 2) & 0x0f) as usize;
        if count == 0 {
            let Some(&n) = p.get(at) else { return };
            count = n as usize;
            at += 1;
        }
        // Somme de contrôle (connexion chiffrée par RDP, pas par TLS) : on ne sait pas lire la suite.
        if header & 0xc0 != 0 {
            return;
        }
        for _ in 0..count {
            let Some(&eh) = p.get(at) else { return };
            at += 1;
            let (code, flags) = (eh >> 5, eh & 0x1f);
            match code {
                // Touche (code de touche matériel).
                0 => {
                    let Some(&key) = p.get(at) else { return };
                    at += 1;
                    if self.record_input {
                        out.push(Record::Event(t, json!({ "k": "touche", "c": key, "e": flags & 0x02 != 0, "r": flags & 0x01 != 0 })));
                    }
                }
                // Souris, et boutons supplémentaires.
                1 | 2 => {
                    let (Some(f), Some(x), Some(y)) = (u16le(p, at), u16le(p, at + 2), u16le(p, at + 4)) else { return };
                    at += 6;
                    if code == 1 && f & 0x8000 != 0 && f & 0x7000 != 0 {
                        let button = if f & 0x1000 != 0 { "g" } else if f & 0x2000 != 0 { "d" } else { "m" };
                        out.push(Record::Event(t, json!({ "k": "clic", "x": x, "y": y, "b": button })));
                    } else if f & 0x0800 != 0 && t - self.last_move >= 0.1 {
                        self.last_move = t;
                        out.push(Record::Event(t, json!({ "k": "souris", "x": x, "y": y })));
                    }
                }
                // Synchronisation des voyants du clavier (2 : verr. num., 4 : majuscules).
                3 => {
                    if self.record_input {
                        out.push(Record::Event(t, json!({ "k": "voyants", "f": flags })));
                    }
                }
                // Caractère Unicode.
                4 => {
                    let Some(u) = u16le(p, at) else { return };
                    at += 2;
                    if self.record_input {
                        out.push(Record::Event(t, json!({ "k": "unicode", "u": u, "r": flags & 0x01 != 0 })));
                    }
                }
                // Horodatage QoE.
                5 => at += 4,
                // Souris relative.
                6 => at += 6,
                _ => return,
            }
        }
    }

    /// Message du presse-papiers (« cliprdr ») envoyé par `side` (0 poste, 1 serveur).
    fn clipboard(&mut self, side: usize, t: f64, data: &[u8], out: &mut Vec<Record>) {
        // En-tête de canal : longueur totale (u32), drapeaux (u32 : 1 premier, 2 dernier).
        let (Some(flags), Some(chunk)) = (u32le(data, 4), data.get(8..)) else { return };
        if flags & 0x0020_0000 != 0 {
            // Données compressées : pas lisibles ici.
            return;
        }
        if flags & 1 != 0 {
            self.clip[side].chunk.clear();
        }
        self.clip[side].chunk.extend_from_slice(chunk);
        if flags & 2 == 0 || self.clip[side].chunk.len() > 4 * 1024 * 1024 {
            return;
        }
        let pdu = std::mem::take(&mut self.clip[side].chunk);
        let (Some(kind), Some(len)) = (u16le(&pdu, 0), u32le(&pdu, 4)) else { return };
        let body = pdu.get(8..8 + len as usize).unwrap_or(&[]);
        match kind {
            // Demande de données : format voulu.
            4 => self.clip[side].requested = u32le(body, 0),
            // Réponse : le texte demandé par l'autre côté.
            5 => {
                let format = self.clip[1 - side].requested.take();
                let text = match format {
                    Some(13) => {
                        let units: Vec<u16> = body.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
                        String::from_utf16_lossy(&units)
                    }
                    Some(1) | Some(7) => body.iter().take_while(|&&b| b != 0).map(|&b| b as char).collect(),
                    _ => return,
                };
                if !text.is_empty() {
                    let sens = if side == 0 { "vers-serveur" } else { "vers-poste" };
                    out.push(Record::Event(t, json!({ "k": "presse-papiers", "sens": sens, "texte": text })));
                }
            }
            _ => {}
        }
    }
}

fn write_record(out: &mut impl Write, record: &Record) -> std::io::Result<u64> {
    let (t, kind, bytes) = match record {
        Record::Display(t, b) => (*t, DISPLAY, std::borrow::Cow::Borrowed(b.as_slice())),
        Record::Event(t, v) => (*t, EVENT, std::borrow::Cow::Owned(v.to_string().into_bytes())),
    };
    out.write_all(&t.to_be_bytes())?;
    out.write_all(&[kind])?;
    out.write_all(&(bytes.len() as u32).to_be_bytes())?;
    out.write_all(&bytes)?;
    Ok(13 + bytes.len() as u64)
}

/// Enregistrement d'une session en cours, écrit au fil de l'eau puis signé.
pub struct Recorder {
    path: PathBuf,
    out: std::io::BufWriter<std::fs::File>,
    start: Instant,
    tap: Tap,
    bytes: u64,
}

impl Recorder {
    pub fn create(dir: &std::path::Path, session: Uuid, title: &str, record_input: bool) -> Result<Self> {
        let now = chrono::Utc::now();
        let dir = dir.join(now.format("%Y/%m").to_string());
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{session}.rdpcap"));
        let mut out = std::io::BufWriter::new(std::fs::File::create(&path)?);
        writeln!(out, "{}", json!({ "format": "portunia-gate-rdp-v2", "timestamp": now.timestamp(), "title": title, "frappe": record_input }))?;
        Ok(Self { path, out, start: Instant::now(), tap: Tap::new(record_input), bytes: 0 })
    }

    pub fn server(&mut self, data: &[u8]) {
        let t = self.start.elapsed().as_secs_f64();
        for r in self.tap.server(t, data) {
            self.bytes += write_record(&mut self.out, &r).unwrap_or(0);
        }
    }

    pub fn client(&mut self, data: &[u8]) {
        let t = self.start.elapsed().as_secs_f64();
        for r in self.tap.client(t, data) {
            self.bytes += write_record(&mut self.out, &r).unwrap_or(0);
        }
    }

    /// Ferme et signe, comme un enregistrement SSH.
    pub fn finish(mut self, state: &State, session: Uuid) -> Result<(String, String, String, u64)> {
        self.out.flush()?;
        drop(self.out);
        let content = std::fs::read(&self.path)?;
        let sha = sha256_hex(&content);
        use base64::Engine;
        let sig = base64::engine::general_purpose::STANDARD.encode(state.keys.sign(crate::recording::signature_message(session, &sha).as_bytes()));
        Ok((self.path.display().to_string(), sha, sig, self.bytes))
    }
}

/// Session relue : blocs d'image et événements (avec leur temps dans « t »).
pub struct Replay {
    pub display: Vec<(f64, Vec<u8>)>,
    pub events: Vec<Value>,
    pub duration: f64,
}

/// Relit un fichier `.rdpcap` (v1 ou v2).
pub fn read(raw: &[u8]) -> Result<Replay> {
    let newline = raw.iter().position(|&b| b == b'\n').unwrap_or(raw.len());
    let header: Value = serde_json::from_slice(&raw[..newline]).unwrap_or(Value::Null);
    let v1 = match header["format"].as_str() {
        Some("portunia-gate-rdp-v1") => true,
        Some("portunia-gate-rdp-v2") => false,
        _ => bail!("format d'enregistrement RDP inconnu"),
    };
    let mut replay = Replay { display: Vec::new(), events: Vec::new(), duration: 0.0 };
    // v1 : les deux sens bruts, triés ici (sans la frappe, que ces versions ne filtraient pas).
    let mut tap = v1.then(|| Tap::new(false));
    let mut at = newline + 1;
    while at + 13 <= raw.len() {
        let t = f64::from_be_bytes(raw[at..at + 8].try_into()?);
        let kind = raw[at + 8];
        let len = u32::from_be_bytes(raw[at + 9..at + 13].try_into()?) as usize;
        let Some(bytes) = raw.get(at + 13..at + 13 + len) else { break };
        at += 13 + len;
        replay.duration = replay.duration.max(t);
        let records = match &mut tap {
            Some(tap) if kind == 1 => tap.server(t, bytes),
            Some(tap) => tap.client(t, bytes),
            None if kind == DISPLAY => vec![Record::Display(t, bytes.to_vec())],
            None if kind == EVENT => match serde_json::from_slice(bytes) {
                Ok(v) => vec![Record::Event(t, v)],
                Err(_) => vec![],
            },
            None => vec![],
        };
        for r in records {
            match r {
                Record::Display(t, b) => replay.display.push((t, b)),
                Record::Event(t, mut v) => {
                    v["t"] = json!((t * 1000.0).round() / 1000.0);
                    replay.events.push(v);
                }
            }
        }
    }
    Ok(replay)
}

/// Flux d'images envoyé au lecteur : temps (f64), longueur (u32), message, à la suite.
pub fn display_stream(replay: &Replay) -> Vec<u8> {
    let mut out = Vec::with_capacity(replay.display.iter().map(|(_, b)| b.len() + 12).sum());
    for (t, b) in &replay.display {
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// Masque le texte copié-collé (sauf relecture révélée par un administrateur).
pub fn mask_clipboard(events: &mut [Value]) -> usize {
    let mut n = 0;
    for e in events.iter_mut().filter(|e| e["k"] == "presse-papiers") {
        let len = e["texte"].as_str().map(|s| s.chars().count()).unwrap_or(0);
        e["texte"] = Value::Null;
        e["longueur"] = json!(len);
        e["masque"] = json!(true);
        n += 1;
    }
    n
}

/// Statistiques par sorte d'événement (pour le résumé de la relecture).
pub fn counts(events: &[Value]) -> HashMap<String, usize> {
    let mut m = HashMap::new();
    for e in events {
        if let Some(k) = e["k"].as_str() {
            *m.entry(k.to_string()).or_insert(0) += 1;
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tpkt(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![3, 0, 0, 0];
        p.extend_from_slice(payload);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    /// Message MCS « Send Data » vers un canal, avec en-tête de canal virtuel.
    fn send_data(choice: u8, channel: u16, data: &[u8]) -> Vec<u8> {
        let mut vc = Vec::new();
        vc.extend_from_slice(&(data.len() as u32).to_le_bytes());
        vc.extend_from_slice(&3u32.to_le_bytes());
        vc.extend_from_slice(data);
        let mut mcs = vec![0x02, 0xf0, 0x80, choice << 2, 0, 1];
        mcs.extend_from_slice(&channel.to_be_bytes());
        mcs.push(0x70);
        mcs.push(0x80 | ((vc.len() >> 8) as u8));
        mcs.push(vc.len() as u8);
        mcs.extend_from_slice(&vc);
        tpkt(&mcs)
    }

    fn clip(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut p = kind.to_le_bytes().to_vec();
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&(body.len() as u32).to_le_bytes());
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn tri_de_session() {
        let mut tap = Tap::new(false);
        // NLA (DER) puis résultat anticipé : rien n'est gardé.
        assert!(tap.server(0.0, &[0x30, 0x03, 1, 2, 3, 0, 0, 0, 0]).is_empty());
        assert!(tap.client(0.0, &[0x30, 0x02, 9, 9]).is_empty());
        // Demande MCS : clavier français, canaux « rdpsnd » et « cliprdr ».
        let mut core = vec![0x01, 0xc0, 20, 0];
        core.extend_from_slice(&[0; 12]);
        core.extend_from_slice(&0x040cu32.to_le_bytes());
        let mut net = vec![0x03, 0xc0, 32, 0];
        net.extend_from_slice(&2u32.to_le_bytes());
        net.extend_from_slice(b"rdpsnd\0\0");
        net.extend_from_slice(&0u32.to_le_bytes());
        net.extend_from_slice(b"cliprdr\0");
        net.extend_from_slice(&0u32.to_le_bytes());
        let mut ci = vec![0x02, 0xf0, 0x80, 0x7f, 0x65];
        ci.extend_from_slice(&core);
        ci.extend_from_slice(&net);
        let r = tap.client(0.1, &tpkt(&ci));
        assert!(matches!(&r[..], [Record::Event(_, v)] if v["disposition"] == 0x040c));
        // Réponse MCS : canaux 1004 et 1005 ; elle sert aussi à l'image.
        let mut sn = vec![0x03, 0x0c, 12, 0, 0xeb, 0x03, 2, 0];
        sn.extend_from_slice(&1004u16.to_le_bytes());
        sn.extend_from_slice(&1005u16.to_le_bytes());
        let mut cr = vec![0x02, 0xf0, 0x80, 0x7f, 0x66];
        cr.extend_from_slice(&sn);
        assert!(matches!(&tap.server(0.2, &tpkt(&cr))[..], [Record::Display(..)]));
        assert_eq!(tap.cliprdr, Some(1005));
        // Le poste demande du texte Unicode, le serveur répond « héllo » : un événement, pas d'image.
        tap.client(1.0, &send_data(25, 1005, &clip(4, &13u32.to_le_bytes())));
        let text: Vec<u8> = "héllo\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let r = tap.server(1.1, &send_data(26, 1005, &clip(5, &text)));
        assert!(matches!(&r[..], [Record::Event(_, v)] if v["texte"] == "héllo" && v["sens"] == "vers-poste"));
        // Saisie rapide : une touche (non gardée : règle sans frappe) et un clic gauche.
        let mut input = vec![2 << 2, 0, 0, 0x1e];
        input.push(1 << 5);
        input.extend_from_slice(&0x9000u16.to_le_bytes());
        input.extend_from_slice(&100u16.to_le_bytes());
        input.extend_from_slice(&200u16.to_le_bytes());
        input[1] = input.len() as u8;
        let r = tap.client(2.0, &input);
        assert!(matches!(&r[..], [Record::Event(_, v)] if v["k"] == "clic" && v["x"] == 100 && v["b"] == "g"));
        // Même saisie avec la frappe enregistrée : la touche apparaît.
        tap.record_input = true;
        assert_eq!(tap.client(2.1, &input).len(), 2);
        // Voyants : majuscules et verrouillage numérique, tenus dans l'en-tête de l'événement.
        let r = tap.client(2.2, &[1 << 2, 3, (3 << 5) | 6]);
        assert!(matches!(&r[..], [Record::Event(_, v)] if v["k"] == "voyants" && v["f"] == 6));
        // Image fast-path coupée en deux lectures.
        let fp = [0x00, 0x05, 1, 2, 3];
        assert!(tap.server(3.0, &fp[..2]).is_empty());
        assert!(matches!(&tap.server(3.0, &fp[2..])[..], [Record::Display(..)]));
    }

    #[test]
    fn masque() {
        let mut e = vec![json!({ "k": "presse-papiers", "texte": "secret" }), json!({ "k": "clic" })];
        assert_eq!(mask_clipboard(&mut e), 1);
        assert!(e[0]["texte"].is_null() && e[0]["longueur"] == 6);
    }
}
