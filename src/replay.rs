//! Lecture d'un enregistrement (asciicast v2) pour la relecture : lignes tapées, saisies
//! masquées, texte affiché pour la recherche.
//!
//! Une saisie est « sans écho » quand rien ne s'affiche entre sa première touche et Entrée :
//! c'est presque toujours un mot de passe (sudo, su, ssh…). Elle reste dans le fichier signé,
//! mais l'API la remplace par des points, sauf pour un administrateur qui la révèle.

use serde_json::Value;

struct Event {
    time: f64,
    kind: String,
    data: String,
}

/// Une ligne tapée : de la première touche à Entrée (ou Ctrl+C).
pub struct Line {
    pub time: f64,
    pub text: String,
    pub secret: bool,
    /// Indices des événements « i » de la ligne (terminaison comprise).
    events: Vec<usize>,
}

pub struct Cast {
    header: String,
    events: Vec<Event>,
    pub lines: Vec<Line>,
}

const TEXT_LIMIT: usize = 4 << 20;
/// Ce qui remplace une saisie masquée, quelle que soit sa longueur.
const MASK: &str = "••••••";

fn printable(c: char) -> bool {
    !c.is_control()
}

impl Cast {
    pub fn parse(text: &str) -> Cast {
        let mut rows = text.lines();
        let header = rows.next().unwrap_or("{}").to_string();
        let events: Vec<Event> = rows
            .filter_map(|row| {
                let v: Value = serde_json::from_str(row).ok()?;
                Some(Event {
                    time: v.get(0)?.as_f64()?,
                    kind: v.get(1)?.as_str()?.to_string(),
                    data: v.get(2)?.as_str()?.to_string(),
                })
            })
            .collect();
        let lines = split_lines(&events);
        Cast { header, events, lines }
    }

    /// Le fichier, chaque saisie sans écho remplacée par un seul événement « x » de longueur
    /// fixe, posé à sa première touche : ni le texte ni sa longueur ne se devinent.
    pub fn masked(&self) -> String {
        let hidden: std::collections::HashSet<usize> = self.lines.iter().filter(|l| l.secret).flat_map(|l| l.events.iter().copied()).collect();
        let first: std::collections::HashSet<usize> = self.lines.iter().filter(|l| l.secret).filter_map(|l| l.events.first().copied()).collect();
        let mut out = String::with_capacity(self.header.len() + self.events.len() * 24);
        out.push_str(&self.header);
        out.push('\n');
        let mut push = |row: Value| {
            out.push_str(&row.to_string());
            out.push('\n');
        };
        for (i, e) in self.events.iter().enumerate() {
            if !hidden.contains(&i) {
                push(serde_json::json!([e.time, e.kind, e.data]));
                continue;
            }
            // Les caractères disparaissent ; Entrée et les touches de contrôle restent.
            if first.contains(&i) {
                push(serde_json::json!([e.time, "x", MASK]));
            }
            let keys: String = e.data.chars().filter(|c| matches!(c, '\r' | '\n' | '\u{3}' | '\u{4}')).collect();
            if !keys.is_empty() {
                push(serde_json::json!([e.time, "i", keys]));
            }
        }
        out
    }

    /// Lignes affichées, chacune avec le moment où elle a commencé.
    fn screen_lines(&self) -> Vec<(f64, String)> {
        let mut out = Vec::new();
        let mut strip = Strip::default();
        let mut current = String::new();
        let mut start = 0.0;
        for e in self.events.iter().filter(|e| e.kind == "o") {
            for c in e.data.chars() {
                match strip.feed(c) {
                    Some('\n') => {
                        if !current.trim().is_empty() {
                            out.push((start, std::mem::take(&mut current)));
                        }
                        current.clear();
                    }
                    Some('\u{8}') => {
                        current.pop();
                    }
                    Some(c) => {
                        if current.is_empty() {
                            start = e.time;
                        }
                        current.push(c);
                    }
                    None => {}
                }
            }
        }
        if !current.trim().is_empty() {
            out.push((start, current));
        }
        out
    }

    /// Texte indexé pour la recherche : écran et lignes tapées, sans les saisies masquées.
    pub fn search_text(&self) -> String {
        let mut out = String::new();
        for l in self.lines.iter().filter(|l| !l.secret && !l.text.is_empty()) {
            out.push_str(&l.text);
            out.push('\n');
        }
        for (_, l) in self.screen_lines() {
            if out.len() > TEXT_LIMIT {
                break;
            }
            out.push_str(l.trim_end());
            out.push('\n');
        }
        out
    }

    /// Premier passage contenant `query` (sans tenir compte de la casse) : moment et extrait.
    /// Une ligne tapée passe avant le texte affiché (qui contient aussi l'invite).
    pub fn find(&self, query: &str) -> Option<(f64, String)> {
        let q = query.to_lowercase();
        self.lines
            .iter()
            .find(|l| !l.secret && l.text.to_lowercase().contains(&q))
            .map(|l| (l.time, l.text.clone()))
            .or_else(|| self.screen_lines().into_iter().find(|(_, l)| l.to_lowercase().contains(&q)))
            .map(|(t, text)| (t, excerpt(text.trim(), &q)))
    }
}

fn excerpt(text: &str, q: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 100 {
        return text.to_string();
    }
    let at = (0..chars.len())
        .find(|&i| chars[i..].iter().collect::<String>().to_lowercase().starts_with(q))
        .unwrap_or(0);
    let from = at.saturating_sub(40);
    let to = (from + 100).min(chars.len());
    format!("{}{}{}", if from > 0 { "…" } else { "" }, chars[from..to].iter().collect::<String>(), if to < chars.len() { "…" } else { "" })
}

/// Une ligne en cours : texte tapé, et si un écho s'est affiché pendant la frappe.
struct Pending {
    line: Line,
    typed: bool,
    echoed: bool,
}

/// Texte affiché (sans séquences de contrôle) entre `from` et `until` secondes.
fn shown_between(events: &[Event], start: usize, until: f64) -> String {
    let mut strip = Strip::default();
    let mut out = String::new();
    for e in events[start..].iter().take_while(|e| e.time <= until).filter(|e| e.kind == "o") {
        out.extend(e.data.chars().filter_map(|c| strip.feed(c)).filter(|c| printable(*c)));
    }
    out
}

/// Ferme une ligne. Une ligne collée d'un bloc (texte et Entrée dans le même envoi) n'a pas
/// pu montrer d'écho pendant la frappe : on le cherche dans la seconde qui suit.
fn close(events: &[Event], next: usize, p: Pending, end: f64) -> Line {
    let mut line = p.line;
    let echoed = p.echoed || (!line.text.is_empty() && shown_between(events, next, end + 1.0).contains(line.text.trim()));
    line.secret = p.typed && !echoed;
    line
}

fn split_lines(events: &[Event]) -> Vec<Line> {
    let mut lines = Vec::new();
    let mut current: Option<Pending> = None;
    for (i, e) in events.iter().enumerate() {
        match e.kind.as_str() {
            "o" => {
                if let Some(p) = current.as_mut() {
                    if p.typed && e.data.chars().any(printable) {
                        p.echoed = true;
                    }
                }
            }
            "i" => {
                let mut chars = e.data.chars().peekable();
                while chars.peek().is_some() {
                    let p = current.get_or_insert_with(|| Pending {
                        line: Line {
                            time: e.time,
                            text: String::new(),
                            secret: false,
                            events: Vec::new(),
                        },
                        typed: false,
                        echoed: false,
                    });
                    if p.line.events.last() != Some(&i) {
                        p.line.events.push(i);
                    }
                    let mut end = false;
                    while let Some(c) = chars.next() {
                        match c {
                            '\r' | '\n' | '\u{3}' => {
                                end = true;
                                break;
                            }
                            '\u{7f}' | '\u{8}' => {
                                p.line.text.pop();
                            }
                            // Touche spéciale (flèche, fonction) : séquence d'échappement ignorée.
                            '\u{1b}' => {
                                if chars.peek() == Some(&'[') || chars.peek() == Some(&'O') {
                                    chars.next();
                                    for n in chars.by_ref() {
                                        if n.is_ascii_alphabetic() || n == '~' {
                                            break;
                                        }
                                    }
                                }
                            }
                            c if printable(c) => {
                                p.line.text.push(c);
                                p.typed = true;
                            }
                            _ => {}
                        }
                    }
                    if end {
                        // Entrée suivie d'un saut de ligne (« \r\n ») : une seule fin de ligne.
                        if chars.peek() == Some(&'\n') {
                            chars.next();
                        }
                        let p = current.take().unwrap();
                        lines.push(close(events, i + 1, p, e.time));
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(p) = current {
        let end = p.line.time;
        lines.push(close(events, events.len(), p, end));
    }
    lines
}

/// Retire les séquences de contrôle du terminal ; garde le texte, les retours à la ligne
/// et l'effacement d'un caractère.
#[derive(Default)]
struct Strip {
    state: u8,
}

impl Strip {
    fn feed(&mut self, c: char) -> Option<char> {
        match self.state {
            // ESC reçu
            1 => {
                self.state = match c {
                    '[' => 2,
                    ']' | 'P' | '_' | '^' => 3,
                    '(' | ')' | '#' => 5,
                    _ => 0,
                };
                None
            }
            // CSI : jusqu'à l'octet final
            2 => {
                if ('@'..='~').contains(&c) {
                    self.state = 0;
                }
                None
            }
            // OSC / DCS : jusqu'à BEL ou ESC \
            3 => {
                if c == '\u{7}' {
                    self.state = 0;
                } else if c == '\u{1b}' {
                    self.state = 4;
                }
                None
            }
            4 => {
                self.state = if c == '\\' { 0 } else { 3 };
                None
            }
            5 => {
                self.state = 0;
                None
            }
            _ => match c {
                '\u{1b}' => {
                    self.state = 1;
                    None
                }
                '\n' => Some('\n'),
                '\u{8}' => Some('\u{8}'),
                '\t' => Some(' '),
                c if c.is_control() => None,
                c => Some(c),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cast(events: &[(f64, &str, &str)]) -> String {
        let mut s = String::from("{\"version\":2,\"width\":80,\"height\":24}\n");
        for (t, k, d) in events {
            s.push_str(&serde_json::json!([t, k, d]).to_string());
            s.push('\n');
        }
        s
    }

    #[test]
    fn saisie_sans_echo_masquee() {
        let text = cast(&[
            (0.0, "o", "$ "),
            (1.0, "i", "l"),
            (1.01, "o", "l"),
            (1.1, "i", "s"),
            (1.11, "o", "s"),
            (1.2, "i", "\r"),
            (1.21, "o", "\r\nfichier\r\n[sudo] mot de passe : "),
            (2.0, "i", "s"),
            (2.1, "i", "3"),
            (2.2, "i", "\r"),
            (2.3, "o", "\r\n$ "),
        ]);
        let c = Cast::parse(&text);
        assert_eq!(c.lines.len(), 2);
        assert_eq!(c.lines[0].text, "ls");
        assert!(!c.lines[0].secret);
        assert!(c.lines[1].secret);
        let masked = c.masked();
        assert!(!masked.contains("\"s3\"") && !masked.contains("[2.0,\"i\",\"s\"]"));
        assert_eq!(masked.matches("\"x\"").count(), 1, "un seul bloc, longueur cachée");
        assert!(masked.contains("[2.2,\"i\",\"\\r\"]"));
        let index = c.search_text();
        assert!(index.contains("ls") && index.contains("fichier") && !index.contains("s3"));
    }

    #[test]
    fn ligne_collee_pas_masquee() {
        // Ligne envoyée d'un bloc : l'écho arrive après Entrée ; mot de passe collé : pas d'écho.
        let text = cast(&[
            (0.0, "o", "$ "),
            (1.0, "i", "ls -la\r"),
            (1.05, "o", "\u{1b}[32mls -la\u{1b}[0m\r\ntotal 0\r\n[sudo] mot de passe : "),
            (2.0, "i", "Secret1\r"),
            (2.1, "o", "\r\n$ "),
            (3.0, "i", "pwd\recho ok\r"),
            (3.05, "o", "pwd\r\n/root\r\n$ echo ok\r\nok\r\n$ "),
        ]);
        let c = Cast::parse(&text);
        let summary: Vec<(&str, bool)> = c.lines.iter().map(|l| (l.text.as_str(), l.secret)).collect();
        assert_eq!(summary, vec![("ls -la", false), ("Secret1", true), ("pwd", false), ("echo ok", false)]);
        assert!(!c.masked().contains("Secret1"));
    }

    #[test]
    fn effacement_et_recherche() {
        let text = cast(&[
            (0.0, "o", "\u{1b}[1;32m$\u{1b}[0m "),
            (1.0, "i", "rmx"),
            (1.01, "o", "rmx"),
            (1.1, "i", "\u{7f}"),
            (1.11, "o", "\u{8} \u{8}"),
            (1.2, "i", " -rf /tmp/a\r"),
            (1.21, "o", " -rf /tmp/a\r\n"),
        ]);
        let c = Cast::parse(&text);
        assert_eq!(c.lines[0].text, "rm -rf /tmp/a");
        let (t, extrait) = c.find("RM -RF").unwrap();
        assert_eq!(t, 1.0);
        assert_eq!(extrait, "rm -rf /tmp/a");
    }
}
