//! Language of messages: English by default, French when the system, the browser or
//! Portunia ask for it. Every text is written in both languages next to each other:
//! `t!("English", "Français")`.
//!
//! - Command line, installer, SSH server: the bastion's language, from `HEIMDIA_LANG`, then
//!   `LC_ALL`, `LC_MESSAGES`, `LANG` (French if it starts with `fr`), English otherwise.
//! - API and web portal: each request may ask for its own language (`Accept-Language`,
//!   portal cookie); it applies to the whole handling of that request.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    En,
    Fr,
}

static PROCESS: AtomicU8 = AtomicU8::new(0);

tokio::task_local! {
    static REQUEST: Lang;
}

impl Lang {
    /// « fr », « fr-FR », « fr_FR.UTF-8 »… → French ; « en… » → English.
    pub fn from_tag(tag: &str) -> Option<Lang> {
        let tag = tag.trim().to_ascii_lowercase();
        if tag.starts_with("fr") {
            Some(Lang::Fr)
        } else if tag.starts_with("en") {
            Some(Lang::En)
        } else {
            None
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Fr => "fr",
        }
    }
}

/// Language of the system the command runs on.
pub fn from_env() -> Lang {
    for name in ["HEIMDIA_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(value) = std::env::var(name) {
            if value.trim().is_empty() {
                continue;
            }
            // LC_ALL=C or POSIX: no preference, keep looking only for HEIMDIA_LANG's sake.
            return Lang::from_tag(&value).unwrap_or(Lang::En);
        }
    }
    Lang::En
}

/// First language of an `Accept-Language` header that we speak.
pub fn from_accept(header: &str) -> Option<Lang> {
    header.split(',').filter_map(|part| Lang::from_tag(part.split(';').next().unwrap_or(""))).next()
}

pub fn set_process(lang: Lang) {
    PROCESS.store(lang as u8, Ordering::Relaxed);
}

/// Language in effect: the request's if any, otherwise the bastion's.
pub fn get() -> Lang {
    REQUEST.try_with(|l| *l).unwrap_or_else(|_| if PROCESS.load(Ordering::Relaxed) == Lang::Fr as u8 { Lang::Fr } else { Lang::En })
}

pub fn is_fr() -> bool {
    get() == Lang::Fr
}

/// Runs a request's handling in its own language.
pub async fn scope<F: std::future::Future>(lang: Lang, f: F) -> F::Output {
    REQUEST.scope(lang, f).await
}

/// Name of the web portal's cookie that keeps the language chosen with its switch.
pub const COOKIE: &str = "heimdia_langue";

/// Language asked by a request: the portal's cookie, then `Accept-Language`.
pub fn from_request(headers: &axum::http::HeaderMap) -> Option<Lang> {
    let cookie = headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .and_then(|(_, v)| Lang::from_tag(v));
    cookie.or_else(|| {
        headers
            .get(axum::http::header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .and_then(from_accept)
    })
}

/// Axum layer: the request is handled in its own language.
pub async fn middleware(request: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    match from_request(request.headers()) {
        Some(lang) => scope(lang, next.run(request)).await,
        None => next.run(request).await,
    }
}

/// `t!("English", "Français")`: the text in the language in effect (only the chosen
/// argument is evaluated, so `format!` works in both).
#[macro_export]
macro_rules! t {
    ($en:expr, $fr:expr $(,)?) => {
        if $crate::lang::is_fr() { $fr } else { $en }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn langues() {
        assert_eq!(from_accept("fr-FR,fr;q=0.9,en;q=0.8"), Some(Lang::Fr));
        assert_eq!(from_accept("de-DE,en-US;q=0.8"), Some(Lang::En));
        assert_eq!(from_accept("de"), None);
        assert_eq!(Lang::from_tag("fr_FR.UTF-8"), Some(Lang::Fr));
    }
}
