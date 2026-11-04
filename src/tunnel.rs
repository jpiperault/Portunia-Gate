//! Tunnel Cloudflare géré par la Gate : rien à installer en root. La Gate télécharge cloudflared
//! (version et empreinte fixées), le lance sous son propre compte et le relance s'il s'arrête.
//! Le jeton du tunnel est chiffré par le coffre et passé par l'environnement, jamais en argument.

use crate::{model, portal, State};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// Version de cloudflared téléchargée, et empreintes publiées par Cloudflare pour celle-ci.
pub const VERSION: &str = "2026.9.1";
const BINARIES: &[(&str, &str, &str)] = &[
    ("x86_64", "cloudflared-linux-amd64", "03f1f25d1cc93b9ad6c60569d44060bc4f17ed97075760ed8cfca4b12dcd68cc"),
    ("aarch64", "cloudflared-linux-arm64", "3d97437c71848bd8df68041e12436b484a661d95073ea1937f01a845ce88faa3"),
];
/// Métriques du cloudflared de la Gate ; celui d'installer.sh ou de Docker garde le 20241.
const METRICS: &str = "127.0.0.1:20242";
const SETTING: &str = "portail_tunnel_jeton";
const PURPOSE: &str = "reglage:tunnel";
/// Délai d'attente entre deux relances, doublé à chaque échec.
const RETRY_MIN: u64 = 5;
const RETRY_MAX: u64 = 120;

// ---------- Jeton ----------

/// Ce qu'on peut montrer d'un jeton : jamais son secret.
#[derive(Debug, PartialEq)]
pub struct Token {
    pub account: String,
    pub tunnel: String,
}

/// Lit un jeton collé seul ou dans la commande d'installation de Cloudflare (« … --token eyJ… »).
pub fn parse(input: &str) -> Result<(String, Token)> {
    let bad = || anyhow!(t!("This does not look like a Cloudflare tunnel token.", "Ce jeton ne ressemble pas à un jeton de tunnel Cloudflare."));
    let token = input
        .split(|c: char| !(c.is_ascii_alphanumeric() || "+/=_-".contains(c)))
        .filter(|w| w.starts_with("eyJ"))
        .max_by_key(|w| w.len())
        .ok_or_else(bad)?;
    let trimmed = token.trim_end_matches('=');
    let raw = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|_| bad())?;
    let v: Value = serde_json::from_slice(&raw).map_err(|_| bad())?;
    let field = |k: &str| v[k].as_str().map(str::to_owned).filter(|s| !s.is_empty());
    let (Some(account), Some(tunnel), Some(_)) = (field("a"), field("t"), field("s")) else { return Err(bad()) };
    if !account.chars().all(|c| c.is_ascii_hexdigit()) || uuid::Uuid::parse_str(&tunnel).is_err() {
        return Err(bad());
    }
    Ok((token.to_string(), Token { account, tunnel }))
}

/// Jeton enregistré (déchiffré), s'il y en a un.
pub async fn token(state: &State) -> Result<Option<String>> {
    let Some(sealed) = model::setting(&state.db, SETTING).await?.and_then(|v| v.as_str().map(str::to_owned)).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::STANDARD.decode(sealed)?;
    Ok(Some(String::from_utf8(state.keys.open(PURPOSE, &bytes)?)?))
}

/// Enregistre (ou efface, si vide) le jeton. Rend ce qu'on peut en montrer.
pub async fn set_token(state: &State, input: &str) -> Result<Option<Token>> {
    if input.trim().is_empty() {
        model::set_setting(&state.db, SETTING, json!("")).await?;
        return Ok(None);
    }
    let (token, info) = parse(input)?;
    let sealed = base64::engine::general_purpose::STANDARD.encode(state.keys.seal(PURPOSE, token.as_bytes())?);
    model::set_setting(&state.db, SETTING, json!(sealed)).await?;
    Ok(Some(info))
}

// ---------- État ----------

#[derive(Clone)]
struct Status {
    /// arrete, telechargement, demarrage, relie, deconnecte, erreur
    state: &'static str,
    error: Option<String>,
    since: Option<DateTime<Utc>>,
    connections: u32,
}

static STATUS: Mutex<Status> = Mutex::new(Status { state: "arrete", error: None, since: None, connections: 0 });

fn status() -> Status {
    STATUS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn set_status(state: &'static str, error: Option<String>, connections: u32) {
    let mut s = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    if s.state != state {
        s.since = Some(Utc::now());
    }
    s.state = state;
    s.error = error;
    s.connections = connections;
}

/// Page « /ready » des métriques de cloudflared : connexions prêtes vers Cloudflare.
pub async fn probe(addr: &str) -> Option<u32> {
    let ask = async {
        let mut tcp = tokio::net::TcpStream::connect(addr).await?;
        tcp.write_all(b"GET /ready HTTP/1.0\r\nHost: localhost\r\n\r\n").await?;
        let mut buf = Vec::new();
        tcp.take(4096).read_to_end(&mut buf).await?;
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).into_owned())
    };
    let text = tokio::time::timeout(Duration::from_secs(2), ask).await.ok()?.ok()?;
    let ready = text.split_once("\"readyConnections\":").and_then(|(_, rest)| {
        rest.trim_start().split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
    });
    Some(if text.starts_with("HTTP/1.") && text.contains(" 200 ") { ready.unwrap_or(1).max(1) } else { 0 })
}

/// État résumé pour l'onglet : relie, deconnecte ou absent.
pub async fn summary(state: &State) -> &'static str {
    let managed = token(state).await.ok().flatten().is_some();
    let n = if managed { (status().state == "relie").then_some(1).or(Some(0)) } else { probe(&state.config.tunnel_metrics).await };
    match n {
        Some(n) if n > 0 => "relie",
        Some(_) => "deconnecte",
        None => "absent",
    }
}

/// Tout ce que l'onglet montre du tunnel géré.
pub async fn report(state: &State) -> Result<Value> {
    let saved = token(state).await?;
    let info = saved.as_deref().and_then(|t| parse(t).ok()).map(|(_, i)| i);
    let s = status();
    let port = state.config.portal_listen.rsplit(':').next().unwrap_or("8445").to_string();
    // Un cloudflared installé à côté (installer.sh, Docker) répond sur l'autre port de métriques.
    let other = if saved.is_none() { probe(&state.config.tunnel_metrics).await } else { None };
    Ok(json!({
        "jeton_defini": saved.is_some(),
        "tunnel_id": info.as_ref().map(|i| i.tunnel.clone()),
        "etat": s.state,
        "erreur": s.error,
        "depuis": s.since,
        "connexions": s.connections,
        "version": VERSION,
        "service": format!("http://localhost:{port}"),
        "externe": other.is_some(),
        "externe_relie": other.is_some_and(|n| n > 0),
    }))
}

// ---------- Programme ----------

fn dir(state: &State) -> PathBuf {
    state.config.data_dir.join("cloudflared")
}

/// cloudflared prêt à lancer : celui donné par PORTUNIA_GATE_CLOUDFLARED, sinon la version fixée,
/// téléchargée une fois et vérifiée.
async fn binary(state: &State) -> Result<PathBuf> {
    if let Some(path) = &state.config.cloudflared {
        return Ok(path.clone());
    }
    let arch = std::env::consts::ARCH;
    let Some(&(_, name, sum)) = BINARIES.iter().find(|(a, _, _)| *a == arch).filter(|_| cfg!(target_os = "linux")) else {
        bail!(t!(
            "no cloudflared for this system: set PORTUNIA_GATE_CLOUDFLARED",
            "pas de cloudflared pour ce système : réglez PORTUNIA_GATE_CLOUDFLARED"
        ));
    };
    let dest = dir(state).join(format!("cloudflared-{VERSION}"));
    if let Ok(bytes) = tokio::fs::read(&dest).await {
        if crate::keys::sha256_hex(&bytes) == sum {
            return Ok(dest);
        }
    }
    set_status("telechargement", None, 0);
    let url = format!("https://github.com/cloudflare/cloudflared/releases/download/{VERSION}/{name}");
    let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let resp = ureq::get(&url).timeout(Duration::from_secs(300)).call()?;
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(resp.into_reader(), 256 * 1024 * 1024), &mut out)?;
        Ok(out)
    })
    .await?
    .context(t!("cannot download cloudflared from GitHub", "téléchargement de cloudflared depuis GitHub impossible"))?;
    anyhow::ensure!(
        crate::keys::sha256_hex(&bytes) == sum,
        t!("the downloaded cloudflared does not have the expected fingerprint", "le cloudflared téléchargé n'a pas l'empreinte attendue")
    );
    tokio::fs::create_dir_all(dir(state)).await?;
    // Les versions précédentes ne servent plus.
    if let Ok(mut entries) = tokio::fs::read_dir(dir(state)).await {
        while let Ok(Some(e)) = entries.next_entry().await {
            if e.file_name().to_string_lossy().starts_with("cloudflared-") {
                let _ = tokio::fs::remove_file(e.path()).await;
            }
        }
    }
    let tmp = dest.with_extension("tmp");
    tokio::fs::write(&tmp, &bytes).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700)).await?;
    }
    tokio::fs::rename(&tmp, &dest).await?;
    crate::audit::note(&state.db, "systeme", "portail.cloudflared", json!({ "version": VERSION, "sha256": sum })).await;
    Ok(dest)
}

/// Jeton à servir maintenant : en mode Cloudflare seulement.
async fn wanted(state: &State) -> Result<Option<String>> {
    if portal::exposure(state).mode != portal::Mode::Cloudflare {
        return Ok(None);
    }
    token(state).await
}

/// Ligne utile d'un journal de cloudflared, sans la date.
fn log_message(line: &str) -> Option<String> {
    let (_, rest) = line.split_once(" ERR ").or_else(|| line.split_once(" FTL "))?;
    Some(rest.trim().chars().take(300).collect())
}

/// Lance cloudflared et le surveille. Rend Ok quand il faut l'arrêter (jeton ou mode changés).
async fn supervise(state: &State, token: &str) -> Result<()> {
    let bin = binary(state).await?;
    set_status("demarrage", None, 0);
    let home = dir(state);
    tokio::fs::create_dir_all(&home).await?;
    let mut child = tokio::process::Command::new(&bin)
        .args(["tunnel", "--no-autoupdate", "--metrics", METRICS, "--loglevel", "info", "run"])
        .env_clear()
        .env("HOME", &home)
        .env("TUNNEL_TOKEN", token)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            // Dossier de données monté « noexec » (certains LXC, durcissements) : le programme
            // téléchargé ne peut pas s'y lancer. Le cloudflared du système, lui, le peut.
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                t!(
                    " (folder mounted noexec? install cloudflared in /usr/bin and set PORTUNIA_GATE_CLOUDFLARED=/usr/bin/cloudflared in the configuration file)",
                    " (dossier monté noexec ? installez cloudflared dans /usr/bin et ajoutez PORTUNIA_GATE_CLOUDFLARED=/usr/bin/cloudflared au fichier de configuration)"
                )
            } else {
                ""
            };
            anyhow!("{} {}: {e}{hint}", t!("cannot start", "démarrage impossible de"), bin.display())
        })?;
    let last = Arc::new(Mutex::new(None::<String>));
    if let Some(err) = child.stderr.take() {
        let last = last.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::debug!(target: "cloudflared", "{line}");
                if let Some(msg) = log_message(&line) {
                    *last.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg);
                }
            }
        });
    }
    let started = tokio::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    loop {
        tokio::select! {
            exit = child.wait() => {
                let why = last.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| format!("{:?}", exit));
                bail!("{} {why}", t!("cloudflared stopped:", "cloudflared s'est arrêté :"));
            }
            _ = tick.tick() => {
                if wanted(state).await.ok().flatten().as_deref() != Some(token) {
                    let _ = child.kill().await;
                    set_status("arrete", None, 0);
                    return Ok(());
                }
                let n = probe(METRICS).await.unwrap_or(0);
                let error = last.lock().unwrap_or_else(|e| e.into_inner()).clone();
                if n > 0 {
                    set_status("relie", None, n);
                } else if started.elapsed() > Duration::from_secs(30) {
                    set_status("deconnecte", error, 0);
                }
            }
        }
    }
}

pub async fn run(state: Arc<State>) -> Result<()> {
    // Le mode enregistré avant tout : ne pas lancer le tunnel d'une Gate exposée autrement.
    let _ = portal::reload_exposure(&state).await;
    let mut wait = RETRY_MIN;
    loop {
        match wanted(&state).await {
            Ok(Some(token)) => match supervise(&state, &token).await {
                Ok(()) => wait = RETRY_MIN,
                Err(e) => {
                    let msg = format!("{e:#}");
                    tracing::warn!("tunnel Cloudflare : {msg}");
                    set_status("erreur", Some(msg), 0);
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                    wait = (wait * 2).min(RETRY_MAX);
                    continue;
                }
            },
            Ok(None) => {
                set_status("arrete", None, 0);
                wait = RETRY_MIN;
            }
            Err(e) => set_status("erreur", Some(format!("{e:#}")), 0),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// ---------- Essai de bout en bout ----------

/// Appelle l'adresse publique comme le ferait un navigateur et vérifie que c'est bien cette Gate
/// qui répond, à travers Cloudflare.
pub async fn check(state: &State) -> Result<Value> {
    let url = portal::settings(state).await?.url;
    if url.is_empty() {
        return Ok(json!({ "ok": false, "message": t!("Fill in the public address first.", "Renseignez d'abord l'adresse publique.") }));
    }
    let target = format!("{url}{}", portal::PING_PATH);
    // Lancée en ligne de commande, la vérification attend l'identifiant du service, pas le sien.
    let expected = crate::model::setting(&state.db, crate::live::SNAPSHOT)
        .await?
        .and_then(|s| s["instance"].as_str().map(str::to_owned))
        .filter(|_| !crate::portal::is_service())
        .unwrap_or_else(|| portal::instance_id().to_string());
    let answer = tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new().redirects(0).timeout(Duration::from_secs(15)).build();
        match agent.get(&target).call() {
            Ok(r) => {
                let status = r.status();
                let location = r.header("location").unwrap_or_default().to_string();
                (status, location, r.into_string().unwrap_or_default())
            }
            Err(ureq::Error::Status(code, r)) => (code, String::new(), r.into_string().unwrap_or_default()),
            Err(e) => (0, String::new(), e.to_string()),
        }
    })
    .await?;
    let (code, location, body) = answer;
    let (ok, message) = match code {
        200 if body.trim() == expected => (true, t!("This Gate answers at the public address.", "Cette Gate répond à l'adresse publique.").to_string()),
        200 => (false, t!("Another machine answers at this address: check the tunnel's route (Routes tab).", "Une autre machine répond à cette adresse : vérifiez la route du tunnel (onglet Routes).").to_string()),
        301..=308 if location.contains("cloudflareaccess.com") => (
            true,
            t!("The address is protected by Cloudflare Access: the Gate cannot look further, which is expected.", "L'adresse est protégée par Cloudflare Access : la Gate ne peut pas voir au-delà, c'est normal.").to_string(),
        ),
        530 => (false, t!("Cloudflare does not reach the tunnel: is it connected?", "Cloudflare ne joint pas le tunnel : est-il relié ?").to_string()),
        502 | 503 | 504 => (
            false,
            t!("Cloudflare reaches the tunnel but not the portal: in the tunnel's route, the Service URL must be ", "Cloudflare joint le tunnel mais pas le portail : dans la route du tunnel, la Service URL doit être ").to_string()
                + &format!("http://localhost:{}", state.config.portal_listen.rsplit(':').next().unwrap_or("8445")),
        ),
        0 => (false, format!("{} {body}", t!("Address unreachable:", "Adresse injoignable :"))),
        c => (false, format!("{} {c}", t!("Unexpected answer:", "Réponse inattendue :"))),
    };
    Ok(json!({ "ok": ok, "message": message, "code": code }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Jeton fabriqué pour l'essai (format de Cloudflare : JSON a/t/s en base64).
    fn sample() -> String {
        let json = r#"{"a":"0123456789abcdef0123456789abcdef","t":"6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b","s":"c2VjcmV0LWRlLWVzc2Fp"}"#;
        base64::engine::general_purpose::STANDARD.encode(json)
    }

    #[test]
    fn jeton_seul_ou_dans_la_commande() {
        let token = sample();
        let (t1, info) = parse(&token).unwrap();
        assert_eq!(t1, token);
        assert_eq!(info.tunnel, "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b");
        let (t2, _) = parse(&format!("sudo cloudflared service install {token}\n")).unwrap();
        assert_eq!(t2, token);
        let (t3, _) = parse(&format!("cloudflared.exe tunnel run --token {token}")).unwrap();
        assert_eq!(t3, token);
    }

    #[test]
    fn jeton_refuse() {
        assert!(parse("").is_err());
        assert!(parse("bonjour").is_err());
        assert!(parse(&base64::engine::general_purpose::STANDARD.encode(r#"{"a":"x","t":"y"}"#)).is_err());
        let bad_tunnel = base64::engine::general_purpose::STANDARD.encode(r#"{"a":"abcd","t":"pas-un-uuid","s":"x"}"#);
        assert!(parse(&bad_tunnel).is_err());
    }

    #[test]
    fn journal() {
        assert_eq!(
            log_message("2026-11-02T10:00:00Z ERR Couldn't start tunnel error=\"Unauthorized: Invalid tunnel secret\"").as_deref(),
            Some("Couldn't start tunnel error=\"Unauthorized: Invalid tunnel secret\"")
        );
        assert_eq!(log_message("2026-11-02T10:00:00Z INF Registered tunnel connection"), None);
    }

    #[tokio::test]
    async fn metriques() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            for body in ["{\"status\":200,\"readyConnections\":4}", "{\"status\":503,\"readyConnections\":0}"] {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf).await;
                let code = if body.contains("200") { "200 OK" } else { "503 Service Unavailable" };
                let _ = s.write_all(format!("HTTP/1.0 {code}\r\n\r\n{body}").as_bytes()).await;
            }
        });
        assert_eq!(probe(&addr).await, Some(4));
        assert_eq!(probe(&addr).await, Some(0));
        assert_eq!(probe("127.0.0.1:1").await, None);
    }
}
