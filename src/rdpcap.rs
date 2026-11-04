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

/// Un message RDP complet d'un sens de la connexion, avec ses octets.
pub(crate) enum Pdu {
    /// Authentification NLA (CredSSP, encodage DER) : jamais gardée.
    Der(Vec<u8>),
    /// Résultat de l'autorisation anticipée (4 octets après NLA) : jamais gardé.
    EarlyAuth(Vec<u8>),
    /// Message « lent » : TPKT, X.224, MCS.
    Tpkt(Vec<u8>),
    /// Message « rapide » (fast-path) : image côté serveur, saisie côté poste.
    FastPath(Vec<u8>),
    /// Flux devenu incompréhensible : plus rien n'est interprété.
    Lost,
}

/// Découpe un sens de la connexion en messages complets, quelle que soit la taille des lectures.
#[derive(Default)]
pub(crate) struct Framer {
    buf: Vec<u8>,
    /// Un premier message TPKT a été vu : la phase NLA est finie.
    rdp: bool,
    /// Flux incompréhensible : on arrête de l'interpréter.
    pub(crate) lost: bool,
}

impl Framer {
    pub(crate) fn push(&mut self, data: &[u8]) -> Vec<Pdu> {
        let mut out = Vec::new();
        if self.lost {
            out.push(Pdu::Lost);
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
                Some(0)
            };
            let Some(size) = size else { break };
            if size < 2 {
                self.lost = true;
                self.buf.clear();
                out.push(Pdu::Lost);
                break;
            }
            if self.buf.len() < size {
                break;
            }
            let pdu: Vec<u8> = self.buf.drain(..size).collect();
            out.push(if first == 0x30 {
                Pdu::Der(pdu)
            } else if first == 0x03 {
                self.rdp = true;
                Pdu::Tpkt(pdu)
            } else if !self.rdp {
                Pdu::EarlyAuth(pdu)
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
pub(crate) fn gcc_block(data: &[u8], kind: u16) -> Option<&[u8]> {
    let tag = kind.to_le_bytes();
    (0..data.len().saturating_sub(4)).find_map(|i| {
        if data[i..i + 2] != tag {
            return None;
        }
        let len = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
        (len >= 8 && i + len <= data.len()).then(|| &data[i..i + len])
    })
}

pub(crate) fn u16le(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
pub(crate) fn u32le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Données d'un canal virtuel dans un message MCS « Send Data » (requête du poste ou
/// indication du serveur) : (canal, données).
pub(crate) fn send_data(pdu: &[u8]) -> Option<(u16, &[u8])> {
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
    /// Numéro du format « FileGroupDescriptorW » dans la dernière liste de ce côté.
    file_format: Option<u32>,
    /// Fichiers proposés par ce côté (dernière liste demandée par l'autre).
    offered: Vec<Offered>,
}

/// Fichier proposé dans le presse-papiers (MS-RDPECLIP, FILEDESCRIPTORW).
#[derive(Clone)]
struct Offered {
    name: String,
    size: u64,
}

/// Fichier en cours de copie : empreinte calculée au fil des morceaux, reçus dans l'ordre.
struct Transfer {
    name: String,
    size: u64,
    received: u64,
    hash: ring::digest::Context,
    /// Un morceau est arrivé hors de l'ordre : pas d'empreinte complète.
    in_order: bool,
    /// Copie gardée pour l'audit (tant qu'elle tient dans la limite).
    copy: Option<Vec<u8>>,
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
    /// Demandes de contenu de fichier en cours, par flux : (côté qui demande, index, drapeaux, position).
    streams: HashMap<u32, (usize, u32, u32, u64)>,
    /// Copies en cours : (côté qui fournit, index du fichier).
    transfers: HashMap<(usize, u32), Transfer>,
    /// Octets de copies de fichiers que l'on peut encore garder (0 : aucune copie).
    keep_budget: u64,
    /// Fichiers copiés, pour le journal d'audit.
    pub files: Vec<Value>,
    last_move: f64,
}

pub enum Record {
    Display(f64, Vec<u8>),
    Event(f64, Value),
    /// Copie d'un fichier transféré, gardée à côté de l'enregistrement : (nom, contenu).
    File(String, Vec<u8>),
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
            streams: HashMap::new(),
            transfers: HashMap::new(),
            keep_budget: 0,
            files: Vec::new(),
            last_move: -1.0,
        }
    }

    /// Octets envoyés par le serveur.
    pub fn server(&mut self, t: f64, data: &[u8]) -> Vec<Record> {
        let mut out = Vec::new();
        for pdu in self.server.push(data) {
            match pdu {
                Pdu::Der(_) | Pdu::EarlyAuth(_) | Pdu::Lost => {}
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
                Pdu::Der(_) | Pdu::EarlyAuth(_) | Pdu::Lost => {}
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
            // Liste des formats : celui des fichiers, s'il y est.
            2 => self.clip[side].file_format = file_format(body),
            // Demande de données : format voulu.
            4 => self.clip[side].requested = u32le(body, 0),
            // Demande de contenu de fichier (flux, index, drapeaux 1 taille / 2 morceau, position).
            8 => {
                if let (Some(stream), Some(index), Some(flags), Some(low), Some(high)) = (u32le(body, 0), u32le(body, 4), u32le(body, 8), u32le(body, 12), u32le(body, 16)) {
                    if self.streams.len() < 4096 {
                        self.streams.insert(stream, (side, index, flags, ((high as u64) << 32) | low as u64));
                    }
                }
            }
            // Contenu de fichier, réponse à la demande de l'autre côté.
            9 => self.file_contents(side, t, u16le(&pdu, 2).unwrap_or(0), body, out),
            // Réponse : le texte demandé par l'autre côté, ou la liste de ses fichiers.
            5 => {
                let format = self.clip[1 - side].requested.take();
                if format.is_some() && format == self.clip[side].file_format {
                    self.clip[side].offered = file_descriptors(body);
                    return;
                }
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

    /// Morceau d'un fichier envoyé par `side` : l'empreinte avance, et le fichier complet
    /// devient un événement (nom, taille, SHA-256) et une ligne du journal d'audit.
    fn file_contents(&mut self, side: usize, t: f64, msg_flags: u16, body: &[u8], out: &mut Vec<Record>) {
        let Some(stream) = u32le(body, 0) else { return };
        let Some((asker, index, flags, position)) = self.streams.remove(&stream) else { return };
        // Réponse en échec (2), ou venue du côté qui a demandé : rien à suivre.
        if msg_flags & 2 != 0 || asker == side {
            return;
        }
        let data = &body[4..];
        let key = (side, index);
        if !self.transfers.contains_key(&key) {
            // Liste des fichiers non vue (noms courts…) : nom par son rang, taille donnée plus tard.
            let offer = self.clip[side].offered.get(index as usize).cloned().unwrap_or(Offered { name: format!("#{index}"), size: u64::MAX });
            let copy = (self.keep_budget >= offer.size).then(Vec::new);
            self.keep_budget = self.keep_budget.saturating_sub(if copy.is_some() { offer.size } else { 0 });
            self.transfers.insert(key, Transfer { name: offer.name, size: offer.size, received: 0, hash: ring::digest::Context::new(&ring::digest::SHA256), in_order: true, copy });
        }
        let Some(tr) = self.transfers.get_mut(&key) else { return };
        // Demande de taille (1) : la taille fait foi (la liste peut ne pas la donner) ; un
        // fichier vide est alors complet.
        if flags & 1 != 0 {
            if let Some(size) = data.get(..8).and_then(|b| b.try_into().ok()).map(u64::from_le_bytes) {
                tr.size = size;
            }
        } else if flags & 2 != 0 {
            if position == tr.received {
                tr.hash.update(data);
                if let Some(c) = &mut tr.copy {
                    c.extend_from_slice(data);
                }
                tr.received += data.len() as u64;
            } else if position > tr.received {
                tr.in_order = false;
                tr.copy = None;
                tr.received = tr.received.max(position + data.len() as u64);
            }
        }
        if tr.received >= tr.size {
            if let Some(tr) = self.transfers.remove(&key) {
                self.file_done(side, t, tr, false, out);
            }
        }
    }

    /// Fichier copié (ou interrompu) : événement de l'enregistrement, ligne pour l'audit, copie.
    fn file_done(&mut self, side: usize, t: f64, tr: Transfer, incomplete: bool, out: &mut Vec<Record>) {
        let sens = if side == 0 { "vers-serveur" } else { "vers-poste" };
        let sha = (tr.in_order && !incomplete).then(|| crate::keys::hex(tr.hash.finish().as_ref()));
        let mut e = json!({ "k": "fichier", "sens": sens, "nom": tr.name, "taille": tr.size, "sha256": sha });
        if incomplete {
            e["incomplet"] = json!(true);
            e["recu"] = json!(tr.received);
        }
        if let (Some(copy), false) = (tr.copy, incomplete) {
            e["copie"] = json!(true);
            out.push(Record::File(tr.name.clone(), copy));
        }
        self.files.push(e.clone());
        out.push(Record::Event(t, e));
    }

    /// Fin de session : les copies inachevées sont notées comme telles.
    pub fn finish_files(&mut self, t: f64) -> Vec<Record> {
        let mut out = Vec::new();
        let pending: Vec<((usize, u32), Transfer)> = self.transfers.drain().collect();
        for ((side, _), tr) in pending {
            if tr.received > 0 {
                self.file_done(side, t, tr, true, &mut out);
            }
        }
        out
    }
}

/// Numéro du format « FileGroupDescriptorW » dans une liste de formats à noms longs
/// (numéro u32, nom UTF-16 terminé par un zéro).
fn file_format(body: &[u8]) -> Option<u32> {
    let mut at = 0;
    while at + 4 <= body.len() {
        let id = u32le(body, at)?;
        at += 4;
        let mut units = Vec::new();
        while let Some(u) = u16le(body, at) {
            at += 2;
            if u == 0 {
                break;
            }
            units.push(u);
        }
        if String::from_utf16_lossy(&units) == "FileGroupDescriptorW" {
            return Some(id);
        }
    }
    None
}

/// Liste des fichiers proposés (FILEDESCRIPTORW : 592 octets chacun ; taille aux octets 64 et
/// 68, nom UTF-16 de 260 caractères à l'octet 72). Les dossiers (attribut 0x10) ne comptent pas
/// pour la taille.
fn file_descriptors(body: &[u8]) -> Vec<Offered> {
    let count = u32le(body, 0).unwrap_or(0).min(10_000) as usize;
    (0..count)
        .filter_map(|i| body.get(4 + i * 592..4 + (i + 1) * 592))
        .map(|d| {
            let units: Vec<u16> = d[72..592].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
            let directory = u32le(d, 36).unwrap_or(0) & 0x10 != 0;
            let size = if directory { 0 } else { ((u32le(d, 64).unwrap_or(0) as u64) << 32) | u32le(d, 68).unwrap_or(0) as u64 };
            Offered { name: String::from_utf16_lossy(&units), size }
        })
        .collect()
}

fn write_record(out: &mut impl Write, record: &Record) -> std::io::Result<u64> {
    let (t, kind, bytes) = match record {
        Record::Display(t, b) => (*t, DISPLAY, std::borrow::Cow::Borrowed(b.as_slice())),
        Record::Event(t, v) => (*t, EVENT, std::borrow::Cow::Owned(v.to_string().into_bytes())),
        // Les copies de fichiers sont écrites à part, pas dans le flux.
        Record::File(..) => return Ok(0),
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
    tap: Tap,
    bytes: u64,
    /// Une écriture a échoué : l'enregistrement n'est plus complet.
    failed: bool,
    /// Temps du dernier morceau reçu (pour dater la fin des copies inachevées).
    last_t: f64,
    /// Copies de fichiers déjà écrites.
    copies: usize,
}

/// Enregistrement fermé et signé, avec les fichiers copiés pendant la session.
pub struct Closed {
    pub path: String,
    pub sha256: String,
    pub signature: String,
    pub bytes: u64,
    pub files: Vec<Value>,
}

/// Nom de fichier sans danger pour la copie gardée (ni chemin, ni caractère spécial).
fn safe_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let clean: String = base.chars().map(|c| if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).take(100).collect();
    let clean = clean.trim_start_matches('.').to_string();
    if clean.is_empty() {
        "fichier".into()
    } else {
        clean
    }
}

/// Morceau de la session à enregistrer, daté à son passage dans le relais.
struct Chunk {
    t: f64,
    from_server: bool,
    data: Vec<u8>,
}

/// Enregistrement tenu par son propre fil : le relais lui confie les octets et repart,
/// sans attendre le disque. Si le disque ne suit plus, le relais attend (jamais de perte).
pub struct Tape {
    tx: Option<tokio::sync::mpsc::Sender<Chunk>>,
    writer: Option<std::thread::JoinHandle<Recorder>>,
    start: Instant,
}

impl Tape {
    /// Octets du serveur (`from_server`) ou du poste. false : l'enregistrement est
    /// impossible, la session doit s'arrêter.
    pub async fn push(&self, from_server: bool, data: &[u8]) -> bool {
        let chunk = Chunk { t: self.start.elapsed().as_secs_f64(), from_server, data: data.to_vec() };
        match &self.tx {
            Some(tx) => tx.send(chunk).await.is_ok(),
            None => false,
        }
    }

    /// Termine l'écriture puis ferme et signe.
    pub async fn finish(mut self, state: &State, session: Uuid) -> Result<Closed> {
        drop(self.tx.take());
        let writer = self.writer.take().ok_or_else(|| anyhow::anyhow!("enregistrement déjà fermé"))?;
        let recorder = tokio::task::spawn_blocking(move || writer.join()).await?.map_err(|_| anyhow::anyhow!("fil d'enregistrement arrêté"))?;
        recorder.finish(state, session)
    }
}

impl Recorder {
    /// `keep_files` : octets de fichiers copiés que l'on garde à côté de l'enregistrement (0 : aucun).
    pub fn create(dir: &std::path::Path, session: Uuid, title: &str, record_input: bool, keep_files: u64) -> Result<Self> {
        let now = chrono::Utc::now();
        let dir = dir.join(now.format("%Y/%m").to_string());
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{session}.rdpcap"));
        // Grand tampon : peu d'écritures sur le disque, même quand l'image change beaucoup.
        let mut out = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&path)?);
        writeln!(out, "{}", json!({ "format": "portunia-gate-rdp-v2", "timestamp": now.timestamp(), "title": title, "frappe": record_input }))?;
        let mut tap = Tap::new(record_input);
        tap.keep_budget = keep_files;
        Ok(Self { path, out, tap, bytes: 0, failed: false, last_t: 0.0, copies: 0 })
    }

    /// Confie l'enregistrement à un fil dédié.
    pub fn spawn(mut self) -> Result<Tape> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Chunk>(256);
        let writer = std::thread::Builder::new().name("rdpcap".into()).spawn(move || {
            while let Some(chunk) = rx.blocking_recv() {
                self.last_t = chunk.t;
                let records = if chunk.from_server { self.tap.server(chunk.t, &chunk.data) } else { self.tap.client(chunk.t, &chunk.data) };
                for r in records {
                    self.write(&r);
                }
                // Écriture impossible : le canal se ferme, le relais arrête la session.
                if self.failed {
                    break;
                }
            }
            self
        })?;
        Ok(Tape { tx: Some(tx), writer: Some(writer), start: Instant::now() })
    }

    fn write(&mut self, record: &Record) {
        if let Record::File(name, data) = record {
            // Copie gardée pour l'audit, dans « <session>-fichiers » à côté de l'enregistrement ;
            // son empreinte est dans l'enregistrement signé et dans le journal.
            self.copies += 1;
            let stem = self.path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let dir = self.path.with_file_name(format!("{stem}-fichiers"));
            let saved = std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(dir.join(format!("{:03}-{}", self.copies, safe_name(name))), data));
            if let Err(e) = saved {
                tracing::warn!("{} {name}: {e}", t!("RDP file copy not kept:", "copie de fichier RDP non gardée :"));
            }
            return;
        }
        match write_record(&mut self.out, record) {
            Ok(n) => self.bytes += n,
            Err(_) => self.failed = true,
        }
    }

    /// Ferme et signe, comme un enregistrement SSH.
    fn finish(mut self, state: &State, session: Uuid) -> Result<Closed> {
        for r in self.tap.finish_files(self.last_t) {
            self.write(&r);
        }
        let _ = self.out.flush();
        drop(self.out);
        let content = std::fs::read(&self.path)?;
        let sha = sha256_hex(&content);
        use base64::Engine;
        let sig = base64::engine::general_purpose::STANDARD.encode(state.keys.sign(crate::recording::signature_message(session, &sha).as_bytes()));
        Ok(Closed { path: self.path.display().to_string(), sha256: sha, signature: sig, bytes: self.bytes, files: std::mem::take(&mut self.tap.files) })
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
                Record::File(..) => {}
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
    fn copie_de_fichier() {
        let mut tap = Tap::new(false);
        tap.cliprdr = Some(1005);
        tap.keep_budget = 1024;
        // Le serveur annonce des fichiers (format 0xc0ff « FileGroupDescriptorW »).
        let mut list = 0xc0ffu32.to_le_bytes().to_vec();
        list.extend("FileGroupDescriptorW\0".encode_utf16().flat_map(|u| u.to_le_bytes()));
        tap.server(0.0, &send_data(26, 1005, &clip(2, &list)));
        // Le poste demande la liste, le serveur décrit « rapport.txt », 11 octets.
        tap.client(0.1, &send_data(25, 1005, &clip(4, &0xc0ffu32.to_le_bytes())));
        let mut d = vec![0u8; 592];
        d[68..72].copy_from_slice(&11u32.to_le_bytes());
        for (i, u) in "rapport.txt".encode_utf16().enumerate() {
            d[72 + 2 * i..74 + 2 * i].copy_from_slice(&u.to_le_bytes());
        }
        let mut descriptors = 1u32.to_le_bytes().to_vec();
        descriptors.extend_from_slice(&d);
        tap.server(0.2, &send_data(26, 1005, &clip(5, &descriptors)));
        // Le poste colle : contenu en deux morceaux (flux 7, index 0).
        let request = |position: u32, size: u32| {
            let mut r = 7u32.to_le_bytes().to_vec();
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&2u32.to_le_bytes());
            r.extend_from_slice(&position.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&size.to_le_bytes());
            r
        };
        let answer = |data: &[u8]| {
            let mut a = 7u32.to_le_bytes().to_vec();
            a.extend_from_slice(data);
            a
        };
        tap.client(1.0, &send_data(25, 1005, &clip(8, &request(0, 6))));
        assert!(tap.server(1.1, &send_data(26, 1005, &clip(9, &answer(b"bonjou")))).is_empty());
        tap.client(1.2, &send_data(25, 1005, &clip(8, &request(6, 5))));
        let r = tap.server(1.3, &send_data(26, 1005, &clip(9, &answer(b"r !\n\n"))));
        let event = r.iter().find_map(|r| if let Record::Event(_, v) = r { Some(v.clone()) } else { None }).unwrap();
        assert_eq!(event["k"], "fichier");
        assert_eq!(event["sens"], "vers-poste");
        assert_eq!(event["nom"], "rapport.txt");
        assert_eq!(event["taille"], 11);
        assert_eq!(event["sha256"], sha256_hex(b"bonjour !\n\n"));
        assert!(r.iter().any(|r| matches!(r, Record::File(n, data) if n == "rapport.txt" && data == b"bonjour !\n\n")), "copie gardée");
        assert_eq!(tap.files.len(), 1);
    }

    #[test]
    fn nom_de_copie_sans_danger() {
        assert_eq!(safe_name("..\\..\\Windows\\win.ini"), "win.ini");
        assert_eq!(safe_name("../../.ssh"), "ssh");
        assert_eq!(safe_name("rapport final (v2).pdf"), "rapport_final__v2_.pdf");
        assert_eq!(safe_name(""), "fichier");
    }

    #[test]
    fn masque() {
        let mut e = vec![json!({ "k": "presse-papiers", "texte": "secret" }), json!({ "k": "clic" })];
        assert_eq!(mask_clipboard(&mut e), 1);
        assert!(e[0]["texte"].is_null() && e[0]["longueur"] == 6);
    }
}
