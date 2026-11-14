//! Coffre des interfaces web : l'utilisateur arrive connecté sans jamais voir le mot de passe.
//!
//! Deux façons, réglées par serveur (`web_connexion`) :
//! - `auto` / `remplir` : la Gate glisse dans chaque page un petit script qui remplit le
//!   formulaire de connexion (identifiant du coffre, et dans le champ mot de passe un jeton à
//!   usage unique), puis le valide (`auto`) ou laisse cliquer (`remplir`). Quand le navigateur
//!   envoie la connexion, quel qu'en soit le format (formulaire, JSON, en-tête Basic…), la Gate
//!   remplace le jeton par le vrai mot de passe. Marche aussi pour les applications qui se
//!   connectent en JavaScript. En `auto`, un serveur qui demande l'authentification HTTP
//!   (401 Basic) la reçoit aussi.
//! - `basic` : la Gate ajoute l'en-tête `Authorization: Basic` à chaque requête.
//!
//! Le mot de passe ne part jamais vers le navigateur. Un jeton ne sert qu'une fois, 10 minutes
//! au plus, et seulement pour le compte et le serveur qui l'ont reçu ; chaque usage est noté
//! au journal (`web.coffre`, avec le chemin), pour voir où le mot de passe a été envoyé.
//!
//! Depuis la 0.49 (A2 de l'audit du 11 novembre), le jeton n'est remplacé que dans un envoi qui
//! ressemble à une connexion : méthode POST, formulaire ou JSON, jeton présent une seule fois et
//! valeur entière d'un seul champ « mot de passe » (pass, pwd, mdp, secret). Jamais dans le
//! chemin, ni dans un autre champ (recherche, profil) : une page qui recopierait ce qu'elle reçoit
//! montrerait sinon le mot de passe. Un jeton vu ailleurs est brûlé et noté (`web.coffre_refuse`),
//! et si la réponse contient malgré tout le mot de passe, il y est masqué (`web.coffre_masque`).

use std::{
    collections::{HashMap, HashSet},
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use axum::http::{header, HeaderMap, HeaderValue};
use base64::{engine::general_purpose::STANDARD, Engine};
use uuid::Uuid;

/// Préfixe des jetons (lettres et chiffres seulement : aucun encodage ne les change).
const PREFIX: &str = "pgwv";
const LIFETIME: Duration = Duration::from_secs(600);
/// Corps de requête examiné au plus (connexion : quelques centaines d'octets).
pub const MAX_REQUEST: usize = 1 << 20;
/// Page HTML modifiée au plus.
pub const MAX_PAGE: usize = 8 << 20;

struct Marker {
    user: Uuid,
    target: Uuid,
    expires: Instant,
}

static MARKERS: LazyLock<Mutex<HashMap<String, Marker>>> = LazyLock::new(Mutex::default);
/// Serveurs qui ont demandé l'authentification HTTP (401 Basic) : l'en-tête leur est ensuite envoyé.
static BASIC: LazyLock<Mutex<HashSet<Uuid>>> = LazyLock::new(Mutex::default);

/// Nouveau jeton pour ce compte et ce serveur.
pub fn new_marker(user: Uuid, target: Uuid) -> Result<String> {
    let bytes = crate::keys::random::<16>()?;
    let marker = format!("{PREFIX}{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let mut markers = MARKERS.lock().unwrap();
    markers.retain(|_, m| m.expires > Instant::now());
    markers.insert(marker.clone(), Marker { user, target, expires: Instant::now() + LIFETIME });
    Ok(marker)
}

/// Jetons valables de ce compte pour ce serveur présents dans `text`, retirés de la liste
/// (usage unique).
fn take_markers(text: &str, user: Uuid, target: Uuid) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(PREFIX) {
        let candidate: String = rest[i..].chars().take(PREFIX.len() + 32).collect();
        rest = &rest[i + PREFIX.len()..];
        if candidate.len() == PREFIX.len() + 32 && !found.contains(&candidate) {
            found.push(candidate);
        }
    }
    let mut markers = MARKERS.lock().unwrap();
    found.retain(|m| markers.get(m).is_some_and(|k| k.user == user && k.target == target && k.expires > Instant::now()));
    for m in &found {
        markers.remove(m);
    }
    found
}

/// Ce que devient le corps d'une requête en mode coffre.
#[derive(Debug, PartialEq)]
pub enum Substitution {
    /// Aucun jeton de ce compte : le corps part tel quel.
    None,
    /// Jeton présent hors d'un envoi de connexion : brûlé, le corps part tel quel (sans le mot de passe).
    Refused(&'static str),
    /// Connexion : le jeton est remplacé par le mot de passe.
    Done(Vec<u8>),
}

/// Nom d'un champ de mot de passe (« password », « j_password », « pwd », « mdp »…).
fn password_field(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["pass", "pwd", "mdp", "secret"].iter().any(|k| n.contains(k))
}

fn form_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Champs (nom, valeur) d'un objet JSON, à toutes les profondeurs ; `f` peut changer la valeur.
fn json_fields(v: &mut serde_json::Value, f: &mut dyn FnMut(&str, &mut serde_json::Value)) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                f(k, val);
                json_fields(val, f);
            }
        }
        serde_json::Value::Array(list) => list.iter_mut().for_each(|x| json_fields(x, f)),
        _ => {}
    }
}

/// Remplace le jeton par le mot de passe, seulement dans un envoi de connexion (voir l'en-tête
/// du module). `post` : la requête est un POST.
pub fn substitute_body(body: &[u8], content_type: &str, post: bool, user: Uuid, target: Uuid, password: &str) -> Substitution {
    let Ok(text) = std::str::from_utf8(body) else { return Substitution::None };
    let markers = take_markers(text, user, target);
    let Some(marker) = markers.first() else { return Substitution::None };
    if !post {
        return Substitution::Refused("jeton envoyé hors d'un POST");
    }
    if markers.len() != 1 || text.matches(marker.as_str()).count() != 1 {
        return Substitution::Refused("jeton répété");
    }
    let ct = content_type.to_ascii_lowercase();
    if ct.contains("x-www-form-urlencoded") {
        let pairs: Vec<(String, String)> = text.split('&').map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (form_decode(k), form_decode(v))
        }).collect();
        let Some(i) = pairs.iter().position(|(_, v)| v == marker) else { return Substitution::Refused("jeton mêlé à un autre texte") };
        if !password_field(&pairs[i].0) {
            return Substitution::Refused("jeton hors d'un champ mot de passe");
        }
        if pairs.iter().filter(|(k, v)| password_field(k) && !v.is_empty()).count() != 1 {
            return Substitution::Refused("plusieurs champs mot de passe (changement de mot de passe ?)");
        }
        let parts: Vec<&str> = text.split('&').collect();
        let out: Vec<String> = parts.iter().enumerate().map(|(j, p)| {
            if j == i {
                format!("{}={}", p.split_once('=').map(|x| x.0).unwrap_or(p), form_encode(password))
            } else {
                p.to_string()
            }
        }).collect();
        return Substitution::Done(out.join("&").into_bytes());
    }
    if ct.contains("json") {
        let Ok(mut v) = serde_json::from_str::<serde_json::Value>(text) else { return Substitution::Refused("JSON illisible") };
        let (mut hits, mut wrong, mut filled) = (0, 0, 0);
        json_fields(&mut v, &mut |k, val| {
            let is_pw = password_field(k);
            if is_pw && val.as_str().is_some_and(|s| !s.is_empty()) {
                filled += 1;
            }
            if val.as_str() == Some(marker.as_str()) {
                if is_pw {
                    hits += 1;
                    *val = serde_json::Value::String(password.to_string());
                } else {
                    wrong += 1;
                }
            }
        });
        if wrong > 0 || hits != 1 {
            return Substitution::Refused("jeton hors d'un champ mot de passe");
        }
        if filled != 1 {
            return Substitution::Refused("plusieurs champs mot de passe (changement de mot de passe ?)");
        }
        return Substitution::Done(serde_json::to_vec(&v).unwrap_or_default());
    }
    Substitution::Refused("format d'envoi non pris en charge")
}

/// Jeton de ce compte dans le chemin ou les paramètres : jamais remplacé (une page 404 qui
/// recopie l'adresse montrerait le mot de passe), seulement brûlé. Vrai s'il y en avait un.
pub fn marker_in_path(path: &str, user: Uuid, target: Uuid) -> bool {
    !take_markers(path, user, target).is_empty()
}

/// Le mot de passe, sous ses formes courantes (brut, HTML, URL, JSON), masqué dans une réponse.
/// `None` : il n'y était pas.
pub fn mask_password(page: &[u8], password: &str) -> Option<Vec<u8>> {
    if password.len() < 4 {
        return None;
    }
    let text = String::from_utf8_lossy(page);
    let html = password.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;");
    let quoted = serde_json::to_string(password).unwrap_or_default();
    let forms = [password.to_string(), html, form_encode(password), form_encode(password).replace('+', "%20"), quoted[1..quoted.len() - 1].to_string()];
    let mut out = text.to_string();
    let mut found = false;
    for f in forms.iter().filter(|f| !f.is_empty()) {
        if out.contains(f.as_str()) {
            found = true;
            out = out.replace(f.as_str(), "********");
        }
    }
    found.then(|| out.into_bytes())
}

/// En-tête `Authorization: Basic` calculé par l'application avec le jeton.
pub fn substitute_basic(value: &str, user: Uuid, target: Uuid, password: &str) -> Option<String> {
    let encoded = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic "))?;
    let decoded = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    let markers = take_markers(&decoded, user, target);
    if markers.is_empty() {
        return None;
    }
    let plain = markers.iter().fold(decoded, |d, m| d.replace(m, password));
    Some(format!("Basic {}", STANDARD.encode(plain)))
}

fn form_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn basic_header(account: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{account}:{password}")))
}

/// Le serveur a demandé l'authentification HTTP : l'en-tête lui sera envoyé désormais.
pub fn wants_basic(target: Uuid) -> bool {
    BASIC.lock().unwrap().contains(&target)
}

pub fn remember_basic(target: Uuid) {
    BASIC.lock().unwrap().insert(target);
}

/// Défi « WWW-Authenticate: Basic » dans la réponse.
pub fn basic_challenge(headers: &HeaderMap) -> bool {
    headers.get_all(header::WWW_AUTHENTICATE).iter().filter_map(|v| v.to_str().ok()).any(|v| v.trim_start().to_ascii_lowercase().starts_with("basic"))
}

/// Script glissé dans les pages : remplit le formulaire de connexion visible, une fois par
/// apparition, et le valide (une fois par 20 secondes, pour ne pas boucler si le serveur refuse).
fn script(account: &str, marker: &str, submit: bool) -> String {
    // « </ » échappé : un identifiant ne peut pas fermer la balise script.
    let config = serde_json::json!({ "u": account, "m": marker, "s": submit }).to_string().replace("</", r"<\/");
    format!(
        r#"(()=>{{const c={config},k='portunia_gate_coffre:'+c.u+':'+location.pathname.split('/').slice(0,3).join('/');
const vis=e=>!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length);
const set=(e,v)=>{{const d=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(e),'value');d&&d.set?d.set.call(e,v):e.value=v;
e.dispatchEvent(new Event('input',{{bubbles:true}}));e.dispatchEvent(new Event('change',{{bubbles:true}}));}};
const user=p=>{{const all=[...document.querySelectorAll('input')].filter(e=>vis(e)&&/^(text|email|tel|)$/i.test(e.type||'text'));
const before=all.filter(e=>e.compareDocumentPosition(p)&Node.DOCUMENT_POSITION_FOLLOWING);
const same=before.filter(e=>!p.form||e.form===p.form);
const named=same.find(e=>e.autocomplete==='username'||/user|login|mail|ident|account|compte|name/i.test(e.name+' '+e.id+' '+(e.placeholder||'')));
return named||same[same.length-1]||null;}};
const send=p=>{{const f=p.form,s=f||document;
const b=s.querySelector('button[type=submit],input[type=submit]')||[...s.querySelectorAll('button,[role=button],input[type=button]')].find(e=>vis(e)&&/log|sign|conn|valid|submit|entrer|ok/i.test((e.textContent||'')+' '+(e.value||'')));
if(b){{b.click();return;}}if(f){{f.requestSubmit?f.requestSubmit():f.submit();return;}}
p.dispatchEvent(new KeyboardEvent('keydown',{{key:'Enter',code:'Enter',keyCode:13,bubbles:true}}));}};
const run=()=>{{const p=[...document.querySelectorAll('input[type=password]')].find(e=>vis(e)&&!e.value&&!e.dataset.pgw);if(!p)return;
p.dataset.pgw='1';const u=user(p);if(u&&!u.value)set(u,c.u);set(p,c.m);
let last=0;try{{last=+sessionStorage.getItem(k)||0;}}catch(e){{}}
if(c.s&&Date.now()-last>20000){{try{{sessionStorage.setItem(k,Date.now());}}catch(e){{}}setTimeout(()=>send(p),400);}}}};
let t=0;const later=()=>{{clearTimeout(t);t=setTimeout(run,150);}};
new MutationObserver(later).observe(document.documentElement,{{childList:true,subtree:true,attributes:true,attributeFilter:['style','class','hidden']}});
document.readyState==='loading'?document.addEventListener('DOMContentLoaded',run):run();}})();"#
    )
}

/// Page HTML avec le script de remplissage, et politique de sécurité (CSP) qui l'autorise.
pub fn inject(html: &[u8], headers: &mut HeaderMap, account: &str, marker: &str, submit: bool) -> Vec<u8> {
    let code = script(account, marker, submit);
    let tag = format!("<script>{code}</script>");
    let page = String::from_utf8_lossy(html);
    let lower = page.to_ascii_lowercase();
    let at = lower
        .find("</head>")
        .or_else(|| lower.find("<body").and_then(|i| lower[i..].find('>').map(|j| i + j + 1)))
        .unwrap_or(0);
    let mut out = String::with_capacity(page.len() + tag.len());
    out.push_str(&page[..at]);
    out.push_str(&tag);
    out.push_str(&page[at..]);
    allow_in_csp(headers, &code);
    out.into_bytes()
}

/// Ajoute l'empreinte du script à `script-src` (ou `default-src`) de chaque politique, sauf si
/// elle autorise déjà les scripts en ligne (`'unsafe-inline'` sans nonce ni empreinte : une
/// empreinte ajoutée l'annulerait).
fn allow_in_csp(headers: &mut HeaderMap, code: &str) {
    let hash = format!("'sha256-{}'", STANDARD.encode(ring::digest::digest(&ring::digest::SHA256, code.as_bytes())));
    let policies: Vec<String> = headers.get_all(header::CONTENT_SECURITY_POLICY).iter().filter_map(|v| v.to_str().ok().map(str::to_string)).collect();
    if policies.is_empty() {
        return;
    }
    headers.remove(header::CONTENT_SECURITY_POLICY);
    for policy in policies {
        let updated = csp_with_hash(&policy, &hash);
        if let Ok(v) = HeaderValue::from_str(&updated) {
            headers.append(header::CONTENT_SECURITY_POLICY, v);
        }
    }
}

fn csp_with_hash(policy: &str, hash: &str) -> String {
    let directives: Vec<&str> = policy.split(';').map(str::trim).filter(|d| !d.is_empty()).collect();
    let name = |d: &str| d.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    let wanted = if directives.iter().any(|d| name(d) == "script-src-elem") {
        "script-src-elem"
    } else if directives.iter().any(|d| name(d) == "script-src") {
        "script-src"
    } else if directives.iter().any(|d| name(d) == "default-src") {
        "default-src"
    } else {
        return policy.to_string();
    };
    directives
        .iter()
        .map(|d| {
            if name(d) != wanted {
                return d.to_string();
            }
            let lower = d.to_ascii_lowercase();
            let inline_allowed = lower.contains("'unsafe-inline'") && !lower.contains("'nonce-") && !lower.contains("'sha");
            if inline_allowed {
                d.to_string()
            } else {
                // « 'none' » seul n'admet rien d'autre : remplacé par l'empreinte.
                let kept: Vec<&str> = d.split_whitespace().filter(|w| !w.eq_ignore_ascii_case("'none'")).collect();
                format!("{} {hash}", kept.join(" "))
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jeton_remplace_selon_le_format() {
        let (u, t) = (Uuid::new_v4(), Uuid::new_v4());
        let pw = "p@ss w\"rd&é";
        let m = new_marker(u, t).unwrap();
        let json = format!(r#"{{"user":"admin","password":"{m}"}}"#);
        let Substitution::Done(out) = substitute_body(json.as_bytes(), "application/json", true, u, t, pw) else { panic!("JSON") };
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["password"], pw);
        // Usage unique.
        assert_eq!(substitute_body(json.as_bytes(), "application/json", true, u, t, pw), Substitution::None);

        let m = new_marker(u, t).unwrap();
        let form = format!("login=admin&pass={m}&x=1");
        let Substitution::Done(out) = substitute_body(form.as_bytes(), "application/x-www-form-urlencoded; charset=UTF-8", true, u, t, pw) else { panic!("formulaire") };
        assert_eq!(String::from_utf8(out).unwrap(), "login=admin&pass=p%40ss+w%22rd%26%C3%A9&x=1");

        let m = new_marker(u, t).unwrap();
        let basic = format!("Basic {}", STANDARD.encode(format!("admin:{m}")));
        assert_eq!(substitute_basic(&basic, u, t, pw).unwrap(), basic_header("admin", pw));
    }

    /// A2 : le jeton ne devient le mot de passe que dans un POST de connexion.
    #[test]
    fn jeton_refuse_hors_connexion() {
        let (u, t) = (Uuid::new_v4(), Uuid::new_v4());
        let pw = "Secret-Du-Coffre-42";
        let form = "application/x-www-form-urlencoded";
        let cases: Vec<(String, &str, bool)> = vec![
            // Champ de recherche, autre champ, texte brut, GET, jeton répété, changement de mot de passe.
            ("q={m}".into(), form, true),
            ("user={m}&password=x".into(), form, true),
            ("{m}".into(), "text/plain", true),
            ("password={m}".into(), form, false),
            ("password={m}&password2={m}".into(), form, true),
            ("old_password={m}&new_password=abc&confirm_password=abc".into(), form, true),
            ("password=avant{m}".into(), form, true),
            (r#"{"q":"{m}"}"#.into(), "application/json", true),
            (r#"{"user":{"password":"{m}","new_password":"x"}}"#.into(), "application/json", true),
        ];
        for (body, ct, post) in cases {
            let m = new_marker(u, t).unwrap();
            let body = body.replace("{m}", &m);
            let r = substitute_body(body.as_bytes(), ct, post, u, t, pw);
            assert!(matches!(r, Substitution::Refused(_)), "{body} : {r:?}");
            // Brûlé : la page suivante en reçoit un autre.
            assert_eq!(substitute_body(body.as_bytes(), ct, post, u, t, pw), Substitution::None);
        }
        // JSON imbriqué, un seul champ : accepté.
        let m = new_marker(u, t).unwrap();
        let body = format!(r#"{{"auth":{{"login":"admin","pwd":"{m}"}}}}"#);
        assert!(matches!(substitute_body(body.as_bytes(), "application/json", true, u, t, pw), Substitution::Done(_)));
        // Chemin : jamais remplacé, seulement brûlé.
        let m = new_marker(u, t).unwrap();
        assert!(marker_in_path(&format!("/introuvable-{m}"), u, t));
        assert!(!marker_in_path(&format!("/introuvable-{m}"), u, t));
        // Réponse qui recopie le mot de passe : masqué, sous toutes ses formes.
        let page = format!("<p>Recherche : {pw}</p><a href=\"?q=a%20b\">", );
        assert_eq!(String::from_utf8(mask_password(page.as_bytes(), pw).unwrap()).unwrap(), "<p>Recherche : ********</p><a href=\"?q=a%20b\">");
        assert_eq!(String::from_utf8(mask_password(b"x=p%40ss", "p@ss").unwrap()).unwrap(), "x=********");
        assert_eq!(mask_password(b"rien", pw), None);
    }

    #[test]
    fn jeton_d_un_autre_compte_ignore() {
        let (u, t) = (Uuid::new_v4(), Uuid::new_v4());
        let m = new_marker(u, t).unwrap();
        let body = format!("password={m}");
        let form = "application/x-www-form-urlencoded";
        assert_eq!(substitute_body(body.as_bytes(), form, true, Uuid::new_v4(), t, "x"), Substitution::None);
        assert_eq!(substitute_body(body.as_bytes(), form, true, u, Uuid::new_v4(), "x"), Substitution::None);
        // Toujours valable pour son compte (le refus ne l'a pas consommé).
        assert_eq!(substitute_body(body.as_bytes(), form, true, u, t, "x"), Substitution::Done(b"password=x".to_vec()));
    }

    #[test]
    fn script_place_et_autorise() {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; script-src 'self' 'nonce-abc'"));
        let out = String::from_utf8(inject(b"<html><HEAD><title>x</title></HEAD><body></body></html>", &mut h, "admin", "pgwv0", true)).unwrap();
        assert!(out.find("<script>").unwrap() < out.find("</HEAD>").unwrap());
        let csp = h.get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap();
        assert!(csp.starts_with("default-src 'self'; script-src 'self' 'nonce-abc' 'sha256-"), "{csp}");

        assert_eq!(csp_with_hash("script-src 'self' 'unsafe-inline'", "'sha256-x'"), "script-src 'self' 'unsafe-inline'");
        assert_eq!(csp_with_hash("default-src 'none'", "'sha256-x'"), "default-src 'sha256-x'");
        assert_eq!(csp_with_hash("img-src *", "'sha256-x'"), "img-src *");
    }
}

