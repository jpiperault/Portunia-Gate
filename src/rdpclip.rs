//! Copie de fichiers par le presse-papiers du Bureau à distance (MS-RDPECLIP), filtrée en
//! ligne quand la règle d'accès ne l'autorise pas.
//!
//! Le texte copié-collé passe toujours. Pour les fichiers, la Gate :
//! - retire des capacités du presse-papiers, dans les deux sens, l'annonce des flux de
//!   fichiers (et du verrouillage qui va avec) : ni Windows ni le client ne proposent alors de
//!   copier un fichier ;
//! - ne transmet aucune demande ni aucun morceau de contenu de fichier qui passerait quand même
//!   (client modifié), et les compte pour le journal ;
//! - coupe la session si le presse-papiers est compressé ou si le flux devient illisible :
//!   elle ne pourrait plus garantir le blocage.
//!
//! Chaque message TPKT porte un seul morceau de canal virtuel : retirer un message entier ne
//! dérange pas le reste du flux. Les capacités se modifient sur place, sans changer de longueur.

use std::sync::{Arc, Mutex};

use crate::rdpcap::{channel_name, gcc_block, send_data, u16le, u32le, Framer, Pdu};

/// Capacités générales du presse-papiers liées aux fichiers : flux de fichiers (0x04),
/// verrouillage des données (0x10), fichiers de plus de 4 Go (0x20).
const FILE_CAPS: u32 = 0x04 | 0x10 | 0x20;

/// Ce que les deux sens partagent : le numéro du canal du presse-papiers, et les blocages.
#[derive(Default)]
struct Shared {
    channel_names: Vec<String>,
    cliprdr: Option<u16>,
    blocked: u32,
}

/// Filtre d'une session ; un `Side` par sens.
#[derive(Clone, Default)]
pub struct Guard(Arc<Mutex<Shared>>);

pub struct Side {
    guard: Guard,
    framer: Framer,
    from_server: bool,
    /// Message en cours (plusieurs morceaux) à ne pas transmettre.
    dropping: bool,
}

impl Guard {
    pub fn side(&self, from_server: bool) -> Side {
        Side { guard: self.clone(), framer: Framer::default(), from_server, dropping: false }
    }

    /// Demandes ou contenus de fichiers retenus pendant la session.
    pub fn blocked(&self) -> u32 {
        self.0.lock().unwrap().blocked
    }
}

impl Side {
    /// Octets reçus d'un côté → octets à transmettre à l'autre. Err : la session doit s'arrêter.
    pub fn filter(&mut self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::with_capacity(data.len());
        for pdu in self.framer.push(data) {
            match pdu {
                Pdu::Der(b) | Pdu::EarlyAuth(b) | Pdu::FastPath(b) => out.extend_from_slice(&b),
                Pdu::Lost => return Err(t!("unreadable Remote Desktop stream: file copy could not be blocked", "flux Bureau à distance illisible : la copie de fichiers ne pourrait pas être bloquée")),
                Pdu::Tpkt(mut b) => {
                    if self.keep(&mut b)? {
                        out.extend_from_slice(&b);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Un message « lent » : canaux à la connexion, puis presse-papiers. false : à retenir.
    fn keep(&mut self, pdu: &mut [u8]) -> Result<bool, &'static str> {
        let mut shared = self.guard.0.lock().unwrap();
        // Demande MCS du poste : noms des canaux ; réponse du serveur : leurs numéros.
        if !self.from_server && pdu.get(7..9) == Some(&[0x7f, 0x65]) {
            if let Some(net) = gcc_block(pdu, 0xc003) {
                let count = u32le(net, 4).unwrap_or(0).min(31) as usize;
                shared.channel_names = (0..count)
                    .filter_map(|i| net.get(8 + 12 * i..16 + 12 * i))
                    .map(channel_name)
                    .collect();
            }
            return Ok(true);
        }
        if self.from_server && shared.cliprdr.is_none() && pdu.get(7..9) == Some(&[0x7f, 0x66]) {
            if let Some(net) = gcc_block(pdu, 0x0c03) {
                let count = u16le(net, 6).unwrap_or(0) as usize;
                let ids: Vec<u16> = (0..count).filter_map(|i| u16le(net, 8 + 2 * i)).collect();
                shared.cliprdr = shared.channel_names.iter().position(|n| n == "cliprdr").and_then(|i| ids.get(i).copied());
            }
            // Le poste a demandé le presse-papiers mais son numéro reste inconnu : sans lui, le
            // filtre ne verrait rien passer (A4). La session est coupée plutôt que laissée libre.
            if shared.cliprdr.is_none() && shared.channel_names.iter().any(|n| n == "cliprdr") {
                return Err(t!("unreadable Remote Desktop channels: file copy could not be blocked", "canaux du Bureau à distance illisibles : la copie de fichiers ne pourrait pas être bloquée"));
            }
            return Ok(true);
        }
        let Some(cliprdr) = shared.cliprdr else { return Ok(true) };
        let (channel, offset) = match send_data(pdu) {
            Some((channel, data)) => (channel, data.as_ptr() as usize - pdu.as_ptr() as usize),
            None => return Ok(true),
        };
        if channel != cliprdr {
            return Ok(true);
        }
        let data = &mut pdu[offset..];
        // En-tête de canal : longueur (u32), drapeaux (u32 : 1 premier morceau, 2 dernier).
        let Some(flags) = u32le(data, 4) else { return Ok(true) };
        if flags & 0x0020_0000 != 0 {
            return Err(t!("compressed clipboard: file copy could not be blocked", "presse-papiers compressé : la copie de fichiers ne pourrait pas être bloquée"));
        }
        if flags & 1 != 0 {
            // Premier morceau : type du message du presse-papiers.
            self.dropping = false;
            match u16le(data, 8) {
                // Capacités : on retire celles des fichiers.
                Some(7) => strip_file_caps(&mut data[8..]),
                // Demande ou contenu de fichier : retenu, jusqu'à son dernier morceau.
                Some(8) | Some(9) => {
                    self.dropping = true;
                    shared.blocked += 1;
                }
                _ => {}
            }
        }
        let keep = !self.dropping;
        if flags & 2 != 0 {
            self.dropping = false;
        }
        Ok(keep)
    }
}

/// Message des capacités du presse-papiers (en-tête de 8 octets, nombre de jeux, puis jeux :
/// type, longueur, version, drapeaux) : drapeaux des fichiers effacés dans le jeu général.
fn strip_file_caps(msg: &mut [u8]) {
    let count = u16le(msg, 8).unwrap_or(0) as usize;
    let mut at = 12;
    for _ in 0..count.min(16) {
        let (Some(kind), Some(len)) = (u16le(msg, at), u16le(msg, at + 2)) else { return };
        if kind == 1 {
            if let Some(f) = u32le(msg, at + 8) {
                msg[at + 8..at + 12].copy_from_slice(&(f & !FILE_CAPS).to_le_bytes());
            }
        }
        if len < 4 {
            return;
        }
        at += len as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Message TPKT « Send Data » du canal `channel` portant `payload` (un seul morceau).
    fn send(channel: u16, request: bool, payload: &[u8]) -> Vec<u8> {
        let mut chan = Vec::new();
        chan.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        chan.extend_from_slice(&3u32.to_le_bytes());
        chan.extend_from_slice(payload);
        let mut mcs = vec![if request { 25 << 2 } else { 26 << 2 }, 0, 7, (channel >> 8) as u8, channel as u8, 0x70];
        mcs.push(0x80 | (chan.len() >> 8) as u8);
        mcs.push(chan.len() as u8);
        mcs.extend_from_slice(&chan);
        let mut p = vec![3, 0, 0, 0, 2, 0xf0, 0x80];
        p.extend_from_slice(&mcs);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    /// Filtre déjà relié : canal du presse-papiers 1005.
    fn ready() -> (Guard, Side, Side) {
        let g = Guard::default();
        g.0.lock().unwrap().cliprdr = Some(1005);
        let (mut client, mut server) = (g.side(false), g.side(true));
        // Phase RDP commencée des deux côtés.
        client.framer.push(&send(1003, true, b"x"));
        server.framer.push(&send(1003, false, b"x"));
        (g, client, server)
    }

    fn clip(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut m = kind.to_le_bytes().to_vec();
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&(body.len() as u32).to_le_bytes());
        m.extend_from_slice(body);
        m
    }

    #[test]
    fn capacites_fichiers_retirees() {
        let (_, mut client, _) = ready();
        let mut caps = 1u16.to_le_bytes().to_vec();
        caps.extend_from_slice(&[0, 0]);
        caps.extend_from_slice(&1u16.to_le_bytes());
        caps.extend_from_slice(&12u16.to_le_bytes());
        caps.extend_from_slice(&2u32.to_le_bytes());
        caps.extend_from_slice(&(0x02u32 | 0x04 | 0x10).to_le_bytes());
        let pdu = send(1005, true, &clip(7, &caps));
        let out = client.filter(&pdu).unwrap();
        assert_eq!(out.len(), pdu.len(), "même longueur");
        let flags = u32::from_le_bytes(out[out.len() - 4..].try_into().unwrap());
        assert_eq!(flags, 0x02, "noms longs gardés, fichiers retirés");
    }

    #[test]
    fn contenu_de_fichier_retenu() {
        let (g, mut client, mut server) = ready();
        let request = send(1005, true, &clip(8, &[0; 28]));
        assert!(client.filter(&request).unwrap().is_empty());
        let response = send(1005, false, &clip(9, b"\x01\0\0\0secret"));
        assert!(server.filter(&response).unwrap().is_empty());
        let text = send(1005, false, &clip(5, b"h\0i\0\0\0"));
        assert_eq!(server.filter(&text).unwrap(), text, "le texte passe");
        assert_eq!(g.blocked(), 2);
    }

    #[test]
    fn autres_canaux_intacts() {
        let (_, mut client, _) = ready();
        let other = send(1004, true, &clip(8, &[0; 28]));
        assert_eq!(client.filter(&other).unwrap(), other);
    }

    #[test]
    fn compresse_refuse() {
        let (_, mut client, _) = ready();
        let mut pdu = send(1005, true, &clip(2, &[]));
        // Drapeau « compressé » dans l'en-tête de canal.
        let at = pdu.len() - 8 - 4;
        pdu[at + 2] |= 0x20;
        assert!(client.filter(&pdu).is_err());
    }
}
