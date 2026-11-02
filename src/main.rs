//! Portunia Gate, the SSH and Remote Desktop gateway of Portunia.
//!
//! `portunia-gate serve` runs the service; the other commands administer the Gate from the
//! server (`sudo portunia-gate …`). Messages follow the system's language (English or French).

#[macro_use]
mod lang;
mod acme;
mod api;
mod assist;
mod audit;
mod auth;
mod cert;
mod config;
mod health;
mod http;
mod keys;
mod limits;
mod live;
mod model;
mod portal;
mod relay;
mod rdp;
mod rdpcap;
mod recording;
mod replay;
mod sshd;
mod target;
mod tls;
mod tunnel;

use std::{io::IsTerminal, path::PathBuf, sync::Arc};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::{config::Config, keys::Keys};

pub struct State {
    pub db: PgPool,
    pub keys: Keys,
    pub config: Config,
    /// Terminaux ouverts depuis le portail web.
    pub web: portal::Live,
    /// Relais de Portunia Assist : places en attente.
    pub assist: assist::Rooms,
    /// Essais de connexion et connexions SSH non authentifiées.
    pub limits: limits::Limiter,
    /// Sessions en cours, fermées quand leur accès prend fin.
    pub live: live::Registry,
    /// Mode d'exposition du portail web.
    pub exposure: std::sync::RwLock<portal::Exposure>,
    /// Liaisons avec les relais dédiés.
    pub relays: relay::Links,
}

#[derive(Parser)]
#[command(name = "portunia-gate", version, about = "SSH and Remote Desktop gateway of Portunia (messages in English or French, following the system's language or PORTUNIA_GATE_LANG)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// First install: database, keys and administrator account.
    Init {
        /// Administrator login.
        #[arg(long, default_value = "admin")]
        admin: String,
        /// Prepares the database and keys without creating an administrator.
        #[arg(long)]
        no_admin: bool,
        /// Shows a temporary password: the administrator changes it and enrols their code in Portunia.
        #[arg(long = "temporary", alias = "provisoire")]
        provisoire: bool,
        /// Gate name shown in Portunia and in authenticator apps.
        #[arg(long = "name", alias = "nom")]
        nom: Option<String>,
    },
    /// Version, fingerprints to compare in Portunia, and number of accounts.
    Info,
    /// Runs the Gate.
    Serve,
    /// User accounts.
    #[command(subcommand)]
    User(UserCmd),
    /// User groups.
    #[command(subcommand)]
    Group(GroupCmd),
    /// Servers protected by the Gate.
    #[command(subcommand)]
    Target(TargetCmd),
    /// Access rules.
    #[command(subcommand)]
    Rule(RuleCmd),
    /// Audit log.
    Audit {
        /// Checks the whole chain.
        #[arg(long)]
        verify: bool,
        /// Number of events shown.
        #[arg(long, default_value_t = 30)]
        last: i64,
    },
    /// Latest sessions.
    Sessions {
        #[arg(long, default_value_t = 30)]
        last: i64,
    },
    /// Web portal.
    #[command(subcommand)]
    Portal(PortalCmd),
    /// Dedicated relay: this machine publishes the web portal of a Gate.
    #[command(subcommand)]
    Edge(EdgeCmd),
    /// General settings: auth_policy, banner (banniere), name (nom), language (langue: en or fr).
    Setting {
        /// auth_policy, banner, name or language.
        key: String,
        /// New value; without a value, shows the current one.
        value: Option<String>,
    },
}

#[derive(Subcommand)]
enum PortalCmd {
    /// Shows how the portal is exposed.
    Show,
    /// Changes how browsers reach the portal; what is not given stays as it is.
    Expose {
        /// cloudflare, internal, direct, proxy or relay.
        mode: Option<String>,
        /// Proxy mode: trusted proxies, comma-separated addresses or networks.
        #[arg(long)]
        trusted: Option<String>,
        /// Proxy mode: header holding the visitor's address.
        #[arg(long)]
        header: Option<String>,
        /// Internal and direct modes: allowed networks, comma-separated (empty: the default).
        #[arg(long)]
        networks: Option<String>,
    },
    /// Declares a dedicated relay and gives its pairing code.
    RelayAdd {
        name: String,
        /// Address the Gate reaches the relay at, e.g. 10.0.5.20:8447.
        address: String,
    },
    /// HTTPS listening of the portal (internal, direct, proxy modes): a port or address:port.
    Https {
        /// e.g. 8446 or 0.0.0.0:8446; without it, shows the current one.
        address: Option<String>,
        /// Closes the HTTPS listener.
        #[arg(long, conflicts_with = "address")]
        off: bool,
    },
    /// Certificate of the portal's HTTPS listener: shows it, imports one (PEM or PFX) or goes back to self-signed.
    Cert {
        /// Certificate (PEM, with its chain) or PFX file to import.
        #[arg(long = "import", value_name = "FILE")]
        import: Option<PathBuf>,
        /// Private key (PEM), if not in the certificate file.
        #[arg(long, requires = "import")]
        key: Option<PathBuf>,
        /// Back to the self-signed certificate.
        #[arg(long, conflicts_with = "import")]
        remove: bool,
    },
    /// Cloudflare tunnel run by the Gate: token pasted from Cloudflare (alone or with its command).
    Tunnel {
        /// Tunnel token (« - »: read on the standard input); without it, shows the tunnel.
        token: Option<String>,
        /// Removes the token: the Gate stops its tunnel.
        #[arg(long, conflicts_with = "token")]
        remove: bool,
    },
    /// Lists the dedicated relays.
    RelayList,
    /// Revokes a dedicated relay.
    RelayRemove { name: String },
}

#[derive(Subcommand)]
enum EdgeCmd {
    /// Makes this machine a relay. Nothing is sent to the Gate: it is the Gate that calls.
    Enroll {
        /// Pairing code given by the Gate.
        code: String,
        /// Address open to browsers.
        #[arg(long, default_value = "0.0.0.0:443")]
        public: String,
        /// Address open to the Gate only.
        #[arg(long, default_value = "0.0.0.0:8447")]
        tunnel: String,
        /// Public name, for the self-signed certificate.
        #[arg(long, default_value = "portunia-gate-relais")]
        name: String,
        /// Certificate shown to browsers (PEM); self-signed without it.
        #[arg(long, requires = "key")]
        cert: Option<std::path::PathBuf>,
        /// Key of that certificate (PEM).
        #[arg(long, requires = "cert")]
        key: Option<std::path::PathBuf>,
    },
    /// Replaces the certificate shown to browsers; then restart the service.
    Certificate { cert: std::path::PathBuf, key: std::path::PathBuf },
    /// Runs the relay.
    Serve,
}

#[derive(Subcommand)]
enum UserCmd {
    /// Creates an account (password asked, then code enrolment if needed).
    Add {
        login: String,
        /// user, auditor or admin.
        #[arg(long, default_value = "user")]
        role: String,
        /// Accepted combinations, e.g. "password+totp,key+totp" (empty = global setting).
        #[arg(long)]
        policy: Option<String>,
        /// No password (key sign-in only).
        #[arg(long)]
        no_password: bool,
        /// Shows a temporary password: the user changes it and enrols their code in Portunia.
        #[arg(long = "temporary", alias = "provisoire", conflicts_with = "no_password")]
        provisoire: bool,
    },
    /// Lists accounts.
    List,
    /// Deletes an account (its past sessions stay in the log).
    Delete { login: String },
    /// Changes an account's role: user, auditor or admin.
    Role { login: String, role: String },
    /// Adds a public SSH key ("ssh-ed25519 AAAA…" text or path of a .pub file).
    Key { login: String, key: String },
    /// Enrols (or re-enrols) the TOTP code.
    Totp { login: String },
    /// Changes the password.
    Passwd { login: String },
    /// Disables or re-enables an account.
    Disable {
        login: String,
        #[arg(long)]
        undo: bool,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Creates a group.
    Add {
        name: String,
    },
    /// Adds accounts to a group.
    Member {
        group: String,
        logins: Vec<String>,
    },
}

#[derive(Subcommand)]
enum TargetCmd {
    /// Adds a server.
    Add {
        name: String,
        #[arg(long)]
        host: String,
        /// Port (22 for SSH, 3389 for Remote Desktop by default).
        #[arg(long)]
        port: Option<i32>,
        /// ssh or rdp (Remote Desktop).
        #[arg(long, default_value = "ssh")]
        protocol: String,
        /// coffre (vault), enregistre (recorded) or rebond (jump); also vault, recorded, jump.
        #[arg(long, default_value = "coffre")]
        mode: String,
        /// Account on the server.
        #[arg(long)]
        account: Option<String>,
        /// Display folder (Production, Staging…).
        #[arg(long, default_value = "")]
        folder: String,
        /// Account password, asked when typing.
        #[arg(long)]
        password: bool,
        /// Account private key (OpenSSH file).
        #[arg(long)]
        key_file: Option<String>,
    },
    /// Lists servers.
    List,
}

#[derive(Subcommand)]
enum RuleCmd {
    /// Adds a rule: a group, servers and conditions.
    Add {
        name: String,
        #[arg(long)]
        group: String,
        /// Comma-separated servers.
        #[arg(long, value_delimiter = ',')]
        targets: Vec<String>,
        #[arg(long)]
        sftp: bool,
        #[arg(long)]
        tunnels: bool,
        /// Also records keystrokes (careful: captures typed passwords).
        #[arg(long)]
        record_input: bool,
        /// Days: "mon-fri", "mon,wed,fri" (French "lun-ven" also accepted); empty = every day.
        #[arg(long)]
        days: Option<String>,
        /// Hours: "7-20".
        #[arg(long)]
        hours: Option<String>,
        /// Expiry date: YYYY-MM-DD.
        #[arg(long)]
        expires: Option<String>,
    },
}

fn prompt_secret(label: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        Ok(rpassword::prompt_password(label)?)
    } else {
        // Hors terminal (scripts) : une ligne lue sur l'entrée standard.
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }
}

fn prompt_line(label: &str) -> Result<String> {
    use std::io::Write;
    print!("{label}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn new_password() -> Result<String> {
    loop {
        let first = prompt_secret(t!("Password (at least 10 characters): ", "Mot de passe (10 caractères minimum) : "))?;
        if first.chars().count() < 10 {
            println!("{}", t!("Too short.", "Trop court."));
            if !std::io::stdin().is_terminal() {
                bail!(t!("password too short", "mot de passe trop court"));
            }
            continue;
        }
        if std::io::stdin().is_terminal() && prompt_secret(t!("Confirm: ", "Confirmez : "))? != first {
            println!("{}", t!("The two entries differ.", "Les deux saisies diffèrent."));
            continue;
        }
        return Ok(first);
    }
}

async fn connect_db(config: &Config) -> Result<PgPool> {
    let mut last = None;
    // Au démarrage de Docker Compose, PostgreSQL peut mettre quelques secondes à répondre.
    for _ in 0..30 {
        // Délai pour obtenir une connexion, et connexions renouvelées : une requête bloquée
        // donne une erreur au lieu d'attendre indéfiniment.
        let options = PgPoolOptions::new()
            .max_connections(20)
            .acquire_timeout(std::time::Duration::from_secs(15))
            .idle_timeout(std::time::Duration::from_secs(600))
            .max_lifetime(std::time::Duration::from_secs(3600));
        match options.connect(&config.database_url).await {
            Ok(pool) => {
                sqlx::migrate!().run(&pool).await.context(t!("database schema update", "mise à jour du schéma de la base"))?;
                return Ok(pool);
            }
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
    let last = last.map(|e| e.to_string()).unwrap_or_default();
    Err(anyhow!(t!(format!("PostgreSQL database unreachable: {last}"), format!("base PostgreSQL injoignable : {last}"))))
}

/// Enrôle le code TOTP : affiche le code QR et exige un premier code juste.
async fn enroll_totp(state: &State, user: &model::User) -> Result<()> {
    let secret = keys::random::<20>()?;
    let issuer = model::setting(&state.db, "nom")
        .await?
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "Portunia Gate".into());
    let uri = auth::otpauth_uri(&issuer, &user.login, &secret);
    println!("{}", t!("\nScan this code with your authenticator app:\n", "\nScannez ce code dans votre application d'authentification :\n"));
    println!("{}", auth::qr_terminal(&uri)?);
    println!("{} {}\n", t!("Or type the key:", "Ou saisissez la clé :"), auth::base32(&secret));
    for _ in 0..3 {
        let code = prompt_line(t!("Code shown by the app: ", "Code affiché par l'application : "))?;
        if let Some(step) = auth::totp_check(&secret, &code, 0) {
            model::set_totp(&state.db, user.id, Some(state.keys.seal(&format!("totp:{}", user.id), &secret)?)).await?;
            model::consume_totp_step(&state.db, user.id, step).await?;
            audit::log(&state.db, "console", "compte.totp_enrole", json!({ "compte": user.login })).await?;
            println!("{}", t!("Code saved.", "Code enregistré."));
            return Ok(());
        }
        println!("{}", t!("Wrong code (check the phone's clock).", "Code incorrect (vérifiez l'heure du téléphone)."));
    }
    bail!(t!("enrolment abandoned: no correct code", "enrôlement abandonné : aucun code juste"))
}

fn parse_days(text: &str) -> Result<i16> {
    // Noms français ou anglais, indifféremment.
    const NAMES: [&str; 7] = ["lun", "mar", "mer", "jeu", "ven", "sam", "dim"];
    const EN: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    let index = |d: &str| {
        let d = d.trim().to_lowercase();
        NAMES
            .iter()
            .position(|n| d.starts_with(n))
            .or_else(|| EN.iter().position(|n| d.starts_with(n)))
            .ok_or_else(|| anyhow!(t!(format!("unknown day: {d}"), format!("jour inconnu : {d}"))))
    };
    let mut mask = 0i16;
    for part in text.split(',') {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (index(a)?, index(b)?);
                let mut d = a;
                loop {
                    mask |= 1 << d;
                    if d == b {
                        break;
                    }
                    d = (d + 1) % 7;
                }
            }
            None => mask |= 1 << index(part)?,
        }
    }
    Ok(mask)
}

#[tokio::main]
async fn main() {
    lang::set_process(lang::from_env());
    let cli = Cli::parse();
    let service = matches!(cli.command, Command::Serve | Command::Edge(EdgeCmd::Serve));
    // Commandes d'administration : sortie lue par « head » ou un pipe fermé, s'arrêter sans erreur,
    // comme les outils Unix. Jamais pour le service : une connexion à la base fermée par PostgreSQL
    // (socket Unix) le tuerait d'un SIGPIPE, que systemd prend pour un arrêt normal.
    #[cfg(unix)]
    if !service {
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }
    // Le service trace son activité ; les commandes d'administration n'affichent que les avertissements.
    let default_filter = if service {
        "portunia_gate=info,russh=warn"
    } else {
        "portunia_gate=warn,russh=warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| default_filter.into()))
        .with_target(false)
        // Couleurs au terminal seulement : journalctl et les fichiers reçoivent du texte simple.
        .with_ansi(std::io::stderr().is_terminal())
        // Traces sur la sortie d'erreur : la sortie standard reste aux commandes d'administration.
        .with_writer(std::io::stderr)
        .init();
    if let Err(e) = run(cli).await {
        eprintln!("{} {e:#}", t!("Error:", "Erreur :"));
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    // Le relais n'a pas de base : il ne lit pas la configuration de la Gate.
    if let Command::Edge(cmd) = &cli.command {
        return match cmd {
            EdgeCmd::Enroll { code, public, tunnel, name, cert, key } => {
                relay::enroll(code, public, tunnel, name, cert.as_deref(), key.as_deref())?;
                println!("✓ {}", t!("Relay ready: it now waits for the Gate", "Relais prêt : il attend maintenant la Gate"));
                Ok(())
            }
            EdgeCmd::Certificate { cert, key } => relay::set_certificate(cert, key),
            EdgeCmd::Serve => relay::serve_edge().await,
        };
    }
    let config = Config::from_env()?;

    if let Command::Init {
        admin,
        no_admin,
        provisoire,
        nom,
    } = &cli.command
    {
        return init(config, admin, *no_admin, *provisoire, nom.as_deref()).await;
    }
    let db = connect_db(&config).await?;
    // Le service parle la langue choisie dans les réglages de la Gate, sinon celle du système ;
    // les commandes d'administration, celle de qui les tape.
    if matches!(cli.command, Command::Serve) {
        if let Some(l) = model::setting(&db, "langue").await?.and_then(|v| v.as_str().and_then(lang::Lang::from_tag)) {
            lang::set_process(l);
        }
    }
    let keys = Keys::load(&config.data_dir)?;
    let state = Arc::new(State { db, keys, config, web: portal::Live::default(), assist: assist::Rooms::default(), limits: Default::default(), live: Default::default(), exposure: Default::default(), relays: Default::default() });

    match cli.command {
        Command::Init { .. } | Command::Edge(_) => unreachable!(),
        Command::Info => {
            let nom = model::setting(&state.db, "nom")
                .await?
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| "Portunia Gate".into());
            let users = model::users(&state.db).await?;
            println!("{nom} · Portunia Gate {}", env!("CARGO_PKG_VERSION"));
            let admins = users.iter().filter(|u| u.role == "admin").count();
            // installer.sh lit l'empreinte sur la ligne « API certificate » / « Certificat de l'API ».
            println!("{}{}", t!("SSH host key          ", "Clé d'hôte SSH        "), state.keys.host_fingerprint());
            println!("{}{}", t!("API certificate       ", "Certificat de l'API   "), tls::fingerprint(&state.config.data_dir)?);
            println!(
                "{}",
                t!(
                    format!("Accounts              {} including {admins} administrator(s)", users.len()),
                    format!("Comptes               {} dont {admins} administrateur(s)", users.len())
                )
            );
            Ok(())
        }
        Command::Serve => {
            audit::log(
                &state.db,
                "systeme",
                "service.demarre",
                json!({ "version": env!("CARGO_PKG_VERSION") }),
            )
            .await?;
            // Installations antérieures à l'API : le certificat est créé au premier démarrage.
            if tls::create_missing(&state.config.data_dir, &tls_names())? {
                tracing::info!("certificat de l'API créé, empreinte {}", tls::fingerprint(&state.config.data_dir)?);
            }
            // Assistance active : Portunia Assist tenu à jour (au démarrage, puis chaque jour).
            let s = state.clone();
            tokio::spawn(async move {
                loop {
                    if assist::settings(&s).await.map(|x| x.enabled).unwrap_or(false) {
                        if let Err(e) = assist::fetch_agent(s.clone()).await {
                            tracing::warn!("{} {e:#}", t!("Portunia Assistance download:", "téléchargement de Portunia Assistance :"));
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(24 * 3600)).await;
                }
            });
            tokio::try_join!(sshd::run(state.clone()), api::run(state.clone()), portal::run(state.clone()), relay::run(state.clone()), tunnel::run(state.clone()), acme::run(state.clone()), health::run(state.clone()), live::run(state.clone()))?;
            Ok(())
        }
        Command::User(cmd) => user_cmd(&state, cmd).await,
        Command::Group(cmd) => group_cmd(&state, cmd).await,
        Command::Target(cmd) => target_cmd(&state, cmd).await,
        Command::Rule(cmd) => rule_cmd(&state, cmd).await,
        Command::Portal(cmd) => portal_cmd(&state, cmd).await,
        Command::Audit { verify, last } => {
            if verify {
                match audit::verify(&state.db).await? {
                    Ok(n) => println!("{}", t!(format!("Log intact: {n} chained events."), format!("Journal intact : {n} événements chaînés."))),
                    Err(broken) => bail!(t!(format!("LOG TAMPERED WITH: {broken}"), format!("JOURNAL ALTÉRÉ : {broken}"))),
                }
            }
            for e in audit::last(&state.db, last).await? {
                println!(
                    "{:>6}  {}  {:<14} {:<26} {}",
                    e.seq,
                    e.at.with_timezone(&chrono::Local).format("%d/%m %H:%M:%S"),
                    e.actor,
                    e.event,
                    e.detail
                );
            }
            Ok(())
        }
        Command::Sessions { last } => {
            for s in model::last_sessions(&state.db, last).await? {
                let end = s
                    .ended_at
                    .map(|e| e.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
                    .unwrap_or_else(|| t!("ongoing", "en cours").into());
                println!(
                    "{}  {}  {:<12} {:<12} {:<7} {:<30} {:>9} o  {}",
                    &s.id.to_string()[..8],
                    s.started_at.with_timezone(&chrono::Local).format("%d/%m %H:%M:%S"),
                    end,
                    s.login,
                    s.kind,
                    format!("{} {}", s.target, s.detail),
                    s.bytes,
                    s.recording.unwrap_or_default()
                );
            }
            Ok(())
        }
        Command::Setting { key, value } => {
            // Noms anglais acceptés ; les réglages restent rangés sous leur nom français.
            let key = match key.as_str() {
                "banner" => "banniere".to_string(),
                "name" => "nom".to_string(),
                "language" => "langue".to_string(),
                _ => key,
            };
            if !["auth_policy", "banniere", "nom", "langue"].contains(&key.as_str()) {
                bail!(t!("unknown setting: auth_policy, banner, name or language", "réglage inconnu : auth_policy, banniere, nom ou langue"));
            }
            if key == "langue" {
                if let Some(v) = &value {
                    if !["en", "fr", ""].contains(&v.as_str()) {
                        bail!(t!("language: en, fr, or empty for the system's language", "langue : en, fr, ou vide pour la langue du système"));
                    }
                }
            }
            match value {
                None => println!(
                    "{}",
                    model::setting(&state.db, &key)
                        .await?
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| t!("(default)", "(défaut)").into())
                ),
                Some(v) => {
                    if key == "auth_policy" {
                        auth::Policy::parse(&v)?;
                    }
                    model::set_setting(&state.db, &key, json!(v)).await?;
                    audit::log(&state.db, "console", "reglage.modifie", json!({ "reglage": key, "valeur": v })).await?;
                    println!("{}", t!("Setting saved.", "Réglage enregistré."));
                }
            }
            Ok(())
        }
    }
}

/// Noms du certificat de l'API : PORTUNIA_GATE_TLS_NAMES (séparés par des virgules), sinon « portunia-gate ».
/// Portunia vérifie l'empreinte du certificat, pas son nom.
fn tls_names() -> Vec<String> {
    std::env::var("PORTUNIA_GATE_TLS_NAMES")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec!["portunia-gate".into(), "localhost".into()])
}

async fn init(config: Config, admin: &str, no_admin: bool, provisional: bool, nom: Option<&str>) -> Result<()> {
    println!("Portunia Gate {}, {}\n", env!("CARGO_PKG_VERSION"), t!("first install", "première installation"));
    for created in Keys::create_missing(&config.data_dir)? {
        println!("✓ {} {created}", t!("Created:", "Créé :"));
    }
    if tls::create_missing(&config.data_dir, &tls_names())? {
        println!("✓ {}", t!("Created: API certificate", "Créé : certificat de l'API"));
    }
    std::fs::create_dir_all(config.recordings_dir())?;
    let db = connect_db(&config).await?;
    println!("✓ {}", t!("PostgreSQL database ready", "Base PostgreSQL prête"));
    let keys = Keys::load(&config.data_dir)?;
    let state = State { db, keys, config, web: portal::Live::default(), assist: assist::Rooms::default(), limits: Default::default(), live: Default::default(), exposure: Default::default(), relays: Default::default() };
    if model::setting(&state.db, "site_id").await?.is_none() {
        model::set_setting(&state.db, "site_id", json!(uuid::Uuid::new_v4())).await?;
    }
    if let Some(nom) = nom.map(str::trim).filter(|n| !n.is_empty()) {
        model::set_setting(&state.db, "nom", json!(nom)).await?;
    }
    use base64::Engine;
    let sig = base64::engine::general_purpose::STANDARD.encode(state.keys.signature_public_key());
    model::set_setting(&state.db, "signature_publique", json!(sig)).await?;
    println!("✓ {}{}", t!("SSH host key          ", "Clé d'hôte SSH        "), state.keys.host_fingerprint());
    println!("✓ {}{}", t!("API certificate       ", "Certificat de l'API   "), tls::fingerprint(&state.config.data_dir)?);
    println!("✓ {} {sig}", t!("Recording signature: public key", "Signature des enregistrements : clé publique"));
    println!(
        "  {} {}",
        t!("BACK UP outside the server:", "À SAUVEGARDER hors du serveur :"),
        state.config.data_dir.join("vault.key").display()
    );

    let has_admin = model::users(&state.db).await?.iter().any(|u| u.role == "admin");
    if no_admin {
        println!(
            "\n{}",
            t!(
                "No administrator created (--no-admin): run « portunia-gate init » to create one.",
                "Aucun administrateur créé (--no-admin) : lancez « portunia-gate init » pour le créer."
            )
        );
    } else if has_admin {
        println!("\n{}", t!("An administrator already exists: nothing else to do.", "Un administrateur existe déjà : rien d'autre à faire."));
    } else {
        println!("\n{} {admin}", t!("Administrator account:", "Compte administrateur :"));
        create_account(&state, admin, "admin", None, false, provisional).await?;
    }
    audit::log(
        &state.db,
        "console",
        "installation",
        json!({ "version": env!("CARGO_PKG_VERSION") }),
    )
    .await?;
    println!("\n✓ {}", t!("Ready.", "Prêt."));
    Ok(())
}

/// Crée un compte depuis la console. Provisoire : mot de passe affiché une fois, que l'utilisateur
/// change à sa première connexion dans Portunia, où il enrôle aussi son code. Sinon : mot de passe
/// saisi et code enrôlé ici ; un enrôlement abandonné supprime le compte au lieu de le laisser
/// à moitié créé.
async fn create_account(
    state: &State,
    login: &str,
    role: &str,
    policy: Option<String>,
    no_password: bool,
    provisional: bool,
) -> Result<()> {
    let db = &state.db;
    if !["user", "auditor", "admin"].contains(&role) {
        bail!(t!("role: user, auditor or admin", "rôle : user, auditor ou admin"));
    }
    if model::user_by_login(db, login).await?.is_some() {
        bail!(t!(format!("account {login} already exists"), format!("le compte {login} existe déjà")));
    }
    let temp = provisional.then(auth::temp_password).transpose()?;
    let hash = match (&temp, no_password) {
        (Some(temp), _) => Some(auth::hash_password(temp)?),
        (None, true) => None,
        (None, false) => Some(auth::hash_password(&new_password()?)?),
    };
    let id = model::create_user(db, login, role, hash, policy).await?;
    if temp.is_some() {
        sqlx::query("UPDATE users SET must_change_password = true WHERE id = $1")
            .bind(id)
            .execute(db)
            .await?;
    } else {
        let user = model::user_by_id(db, id).await?.ok_or_else(|| anyhow!(t!("account not found", "compte introuvable")))?;
        if user.policy(db).await?.needs_totp() {
            if let Err(e) = enroll_totp(state, &user).await {
                sqlx::query("DELETE FROM users WHERE id = $1").bind(id).execute(db).await?;
                bail!(t!(format!("{e}; account not created, run the command again"), format!("{e} ; compte non créé, relancez la commande")));
            }
        }
    }
    audit::log(db, "console", "compte.cree", json!({ "compte": login, "role": role })).await?;
    match temp {
        // installer.sh lit le mot de passe après « Temporary password: » / « Mot de passe provisoire : ».
        Some(temp) => println!(
            "{}",
            t!(
                format!("Account {login} created. Temporary password: {temp}\nAt their first sign-in in Portunia, the user chooses their password then scans their QR code."),
                format!("Compte {login} créé. Mot de passe provisoire : {temp}\nÀ la première connexion dans Portunia, l'utilisateur choisit son mot de passe puis scanne son code QR.")
            )
        ),
        None => println!("{}", t!(format!("Account {login} created."), format!("Compte {login} créé."))),
    }
    Ok(())
}

async fn user_cmd(state: &State, cmd: UserCmd) -> Result<()> {
    let db = &state.db;
    let find = |login: String| async move {
        model::user_by_login(db, &login)
            .await?
            .ok_or_else(|| anyhow!(t!(format!("Unknown account: {login}"), format!("Compte inconnu : {login}"))))
    };
    match cmd {
        UserCmd::Add {
            login,
            role,
            policy,
            no_password,
            provisoire,
        } => {
            let policy = policy.map(|p| auth::Policy::parse(&p).map(|p| p.to_string())).transpose()?;
            create_account(state, &login, &role, policy, no_password, provisoire).await?;
        }
        UserCmd::Delete { login } => {
            let user = find(login).await?;
            let admins = model::users(db).await?.iter().filter(|u| u.role == "admin" && !u.disabled).count();
            if user.role == "admin" && admins <= 1 {
                bail!(t!("this is the last administrator: create another one before deleting it", "c'est le dernier administrateur : créez-en un autre avant de le supprimer"));
            }
            sqlx::query("DELETE FROM users WHERE id = $1").bind(user.id).execute(db).await?;
            audit::log(db, "console", "compte.supprime", json!({ "compte": user.login })).await?;
            println!("{}", t!(format!("Account {} deleted.", user.login), format!("Compte {} supprimé.", user.login)));
        }
        UserCmd::Role { login, role } => {
            if !["user", "auditor", "admin"].contains(&role.as_str()) {
                bail!(t!("role: user, auditor or admin", "rôle : user, auditor ou admin"));
            }
            let user = find(login).await?;
            sqlx::query("UPDATE users SET role = $2 WHERE id = $1")
                .bind(user.id)
                .bind(&role)
                .execute(db)
                .await?;
            audit::log(db, "console", "compte.modifie", json!({ "compte": user.login, "role": role })).await?;
            println!("{}", t!(format!("{} is now {role}.", user.login), format!("{} est maintenant {role}.", user.login)));
        }
        UserCmd::List => {
            for u in model::users(db).await? {
                println!(
                    "{:<20} {:<8} code {:<9} {}{}",
                    u.login,
                    u.role,
                    if u.totp_secret.is_some() { t!("enrolled", "enrôlé") } else { t!("missing", "absent") },
                    u.auth_policy.unwrap_or_else(|| t!("(global)", "(général)").into()),
                    if u.disabled { t!("  DISABLED", "  DÉSACTIVÉ") } else { "" }
                );
            }
        }
        UserCmd::Key { login, key } => {
            let user = find(login).await?;
            let text = if std::path::Path::new(&key).exists() {
                std::fs::read_to_string(&key)?
            } else {
                key
            };
            let public = russh::keys::PublicKey::from_openssh(text.trim()).map_err(|e| anyhow!(t!(format!("unreadable public key: {e}"), format!("clé publique illisible : {e}"))))?;
            let fp = public.fingerprint(russh::keys::HashAlg::Sha256).to_string();
            model::add_user_key(db, user.id, text.trim(), &fp, &String::from_utf8_lossy(public.comment().as_bytes())).await?;
            audit::log(
                db,
                "console",
                "compte.cle_ajoutee",
                json!({ "compte": user.login, "empreinte": fp }),
            )
            .await?;
            println!("{} {fp}", t!("Key added:", "Clé ajoutée :"));
        }
        UserCmd::Totp { login } => {
            let user = find(login).await?;
            enroll_totp(state, &user).await?;
        }
        UserCmd::Passwd { login } => {
            let user = find(login).await?;
            let hash = auth::hash_password(&new_password()?)?;
            sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
                .bind(user.id)
                .bind(hash)
                .execute(db)
                .await?;
            audit::log(db, "console", "compte.mot_de_passe", json!({ "compte": user.login })).await?;
            println!("{}", t!("Password changed.", "Mot de passe changé."));
        }
        UserCmd::Disable { login, undo } => {
            let user = find(login).await?;
            sqlx::query("UPDATE users SET disabled = $2 WHERE id = $1")
                .bind(user.id)
                .bind(!undo)
                .execute(db)
                .await?;
            audit::log(
                db,
                "console",
                if undo { "compte.reactive" } else { "compte.desactive" },
                json!({ "compte": user.login }),
            )
            .await?;
            println!("{}", if undo { t!("Account re-enabled.", "Compte réactivé.") } else { t!("Account disabled.", "Compte désactivé.") });
        }
    }
    Ok(())
}

async fn group_cmd(state: &State, cmd: GroupCmd) -> Result<()> {
    let db = &state.db;
    match cmd {
        GroupCmd::Add { name } => {
            model::create_group(db, &name).await?;
            audit::log(db, "console", "groupe.cree", json!({ "groupe": name })).await?;
            println!("{}", t!("Group created.", "Groupe créé."));
        }
        GroupCmd::Member { group, logins } => {
            let gid = model::group_id(db, &group).await?;
            for login in logins {
                let user = model::user_by_login(db, &login)
                    .await?
                    .ok_or_else(|| anyhow!(t!(format!("Unknown account: {login}"), format!("Compte inconnu : {login}"))))?;
                model::add_member(db, gid, user.id).await?;
                audit::log(db, "console", "groupe.membre_ajoute", json!({ "groupe": group, "compte": login })).await?;
            }
            println!("{}", t!("Members added.", "Membres ajoutés."));
        }
    }
    Ok(())
}

async fn target_cmd(state: &State, cmd: TargetCmd) -> Result<()> {
    let db = &state.db;
    match cmd {
        TargetCmd::Add {
            name,
            host,
            port,
            protocol,
            mode,
            account,
            folder,
            password,
            key_file,
        } => {
            let port = port.unwrap_or(if protocol == "rdp" { 3389 } else { 22 });
            let mode = model::mode_alias(&mode).to_string();
            let secret: Option<(String, Vec<u8>)> = match (password, key_file) {
                (true, Some(_)) => bail!(t!("Choose --password or --key-file, not both", "Choisissez --password ou --key-file, pas les deux")),
                (true, None) => Some((
                    "password".into(),
                    prompt_secret(t!("Password of the account on the target: ", "Mot de passe du compte sur la cible : "))?.into_bytes(),
                )),
                (false, Some(path)) => {
                    let text = std::fs::read_to_string(&path).with_context(|| t!(format!("reading {path}"), format!("lecture de {path}")))?;
                    russh::keys::decode_secret_key(&text, None)
                        .map_err(|e| anyhow!(t!(format!("unreadable private key (without passphrase): {e}"), format!("clé privée illisible (sans phrase de passe) : {e}"))))?;
                    Some(("key".into(), text.into_bytes()))
                }
                (false, None) => None,
            };
            let kind = secret.as_ref().map(|s| s.0.clone()).unwrap_or_else(|| "none".into());
            let new = model::NewTarget {
                name: name.clone(),
                folder,
                host: host.clone(),
                port,
                mode: mode.clone(),
                account,
                secret_kind: kind,
                protocole: protocol.clone(),
            };
            model::create_target(db, new, |id| match &secret {
                Some((_, plain)) => Ok(Some(state.keys.seal(&format!("cible:{id}"), plain)?)),
                None => Ok(None),
            })
            .await?;
            audit::log(
                db,
                "console",
                "cible.creee",
                json!({ "cible": name, "adresse": format!("{host}:{port}"), "mode": mode }),
            )
            .await?;
            println!("{}", t!("Target created. Its server's fingerprint will be remembered at the first connection.", "Cible créée. L'empreinte de son serveur sera mémorisée à la première connexion."));
        }
        TargetCmd::List => {
            for t in model::targets(db).await? {
                println!(
                    "{:<16} {:<12} {:<4} {:<24} {:<10} {:<12} {}",
                    t.name,
                    t.folder,
                    t.protocole,
                    format!("{}:{}", t.host, t.port),
                    t.mode,
                    t.account.unwrap_or_default(),
                    t.host_key.unwrap_or_else(|| t!("fingerprint to remember", "empreinte à mémoriser").into())
                );
            }
        }
    }
    Ok(())
}

async fn portal_cmd(state: &State, cmd: PortalCmd) -> Result<()> {
    let e = match cmd {
        PortalCmd::RelayAdd { name, address } => {
            let (entry, code) = relay::add(state, &name, &address).await?;
            audit::log(&state.db, "console", "relais.ajoute", json!({ "nom": entry.nom, "adresse": entry.adresse })).await?;
            println!("{}", t!("On the relay machine:", "Sur la machine du relais :"));
            println!("  sudo bash installer.sh relay {code}");
            return Ok(());
        }
        PortalCmd::Https { address, off } => {
            if off || address.is_some() {
                let set = portal::set_https(state, address.as_deref().unwrap_or("")).await?;
                audit::log(&state.db, "console", "portail.https", json!({ "ecoute": set })).await?;
                match set {
                    Some(a) => println!("✓ {} {a}", t!("HTTPS listening (within seconds):", "Écoute HTTPS (sous quelques secondes) :")),
                    None => println!("✓ {}", t!("HTTPS listening closed", "Écoute HTTPS fermée")),
                }
                return Ok(());
            }
            let (address, fixed) = portal::https_address(state).await?;
            println!("HTTPS: {}{}", address.as_deref().unwrap_or("—"), if fixed { t!(" (PORTUNIA_GATE_PORTAL_TLS_LISTEN)", " (PORTUNIA_GATE_PORTAL_TLS_LISTEN)") } else { "" });
            return Ok(());
        }
        PortalCmd::Cert { import, key, remove } => {
            if remove {
                cert::remove(state).await?;
                acme::disable(state).await?;
                audit::log(&state.db, "console", "portail.certificat", json!({ "source": "auto" })).await?;
                println!("✓ {}", t!("Back to the self-signed certificate (within seconds)", "Retour au certificat auto-signé (sous quelques secondes)"));
                return Ok(());
            }
            if let Some(file) = import {
                let bytes = std::fs::read(&file)?;
                let (chain, key_pem) = if bytes.starts_with(b"-----") || std::str::from_utf8(&bytes).is_ok_and(|t| t.contains("-----BEGIN")) {
                    let text = String::from_utf8(bytes)?;
                    let key_pem = match &key {
                        Some(k) => std::fs::read_to_string(k)?,
                        None => text.clone(),
                    };
                    (text, key_pem)
                } else {
                    let password = rpassword::prompt_password(t!("PFX password: ", "Mot de passe du PFX : "))?;
                    cert::from_pfx(&bytes, &password)?
                };
                let info = cert::store(state, "importe", &chain, &key_pem).await?;
                acme::disable(state).await?;
                audit::log(&state.db, "console", "portail.certificat", json!({ "source": "importe", "noms": info.noms, "emetteur": info.emetteur, "expire": info.expire })).await?;
                println!("✓ {} {} ({}, {} {})", t!("Certificate imported:", "Certificat importé :"), info.noms.join(", "), info.emetteur, t!("expires", "expire le"), info.expire.format("%Y-%m-%d"));
                println!("  {}", t!("The portal serves it within seconds.", "Le portail le présente sous quelques secondes."));
                return Ok(());
            }
            let info = cert::inspect(state).await?;
            println!("{} {}{}", t!("Source:", "Source :"), info.source, if info.fixe { " (PORTUNIA_GATE_PORTAL_TLS_CERT)" } else { "" });
            println!("{} {}", t!("Names:", "Noms :"), info.noms.join(", "));
            println!("{} {}", t!("Issuer:", "Émetteur :"), info.emetteur);
            println!("{} {} ({} {})", t!("Expires:", "Expire le :"), info.expire.format("%Y-%m-%d"), info.days_left(), t!("days", "jours"));
            println!("{} {}", t!("Fingerprint:", "Empreinte :"), info.empreinte);
            let a = acme::config(state).await?;
            if a.actif {
                println!("Let's Encrypt : {} ({})", a.domaines.join(", "), a.methode);
            }
            return Ok(());
        }
        PortalCmd::Tunnel { token, remove } => {
            if remove || token.is_some() {
                // « - » : le jeton n'apparaît pas dans la liste des processus.
                let token = match token.as_deref() {
                    Some("-") => {
                        let mut line = String::new();
                        std::io::stdin().read_line(&mut line)?;
                        anyhow::ensure!(!line.trim().is_empty(), t!("Tunnel token missing.", "Jeton du tunnel manquant."));
                        line
                    }
                    other => other.unwrap_or_default().to_string(),
                };
                let info = tunnel::set_token(state, &token).await?;
                let tunnel_id = info.as_ref().map(|i| i.tunnel.clone());
                audit::log(&state.db, "console", "portail.tunnel", json!({ "tunnel": tunnel_id })).await?;
                if let Some(id) = tunnel_id {
                    println!("✓ {} {id}", t!("Token saved, tunnel", "Jeton enregistré, tunnel"));
                    println!("  {}", t!("The Gate starts it within seconds in Cloudflare mode (portunia-gate portal expose cloudflare).", "La Gate le démarre sous quelques secondes en mode Cloudflare (portunia-gate portal expose cloudflare)."));
                } else {
                    println!("✓ {}", t!("Token removed: the Gate stops its tunnel", "Jeton effacé : la Gate arrête son tunnel"));
                }
                return Ok(());
            }
            let r = tunnel::report(state).await?;
            println!("{} {}", t!("Token:", "Jeton :"), if r["jeton_defini"] == json!(true) { r["tunnel_id"].as_str().unwrap_or("?") } else { "—" });
            println!("{} {}", t!("Route Service URL:", "Service URL de la route :"), r["service"].as_str().unwrap_or_default());
            println!("{}", t!("Live state: Portunia › Administer › Web portal.", "État en direct : Portunia › Administrer › Portail web."));
            return Ok(());
        }
        PortalCmd::RelayList => {
            for r in relay::list(state).await? {
                println!("{}  {}", r.nom, r.adresse);
            }
            return Ok(());
        }
        PortalCmd::RelayRemove { name } => {
            portal::reload_exposure(state).await?;
            let Some(gone) = relay::remove(state, &name).await? else { bail!(t!("unknown relay", "relais inconnu")) };
            audit::log(&state.db, "console", "relais.revoque", json!({ "nom": gone })).await?;
            println!("✓ {gone}");
            return Ok(());
        }
        PortalCmd::Show => {
            portal::reload_exposure(state).await?;
            portal::exposure(state)
        }
        PortalCmd::Expose { mode, trusted, header, networks } => {
            let e = portal::set_exposure(state, mode.as_deref(), trusted.map(|v| vec![v]).as_deref(), header.as_deref(), networks.map(|v| vec![v]).as_deref()).await?;
            audit::log(&state.db, "console", "portail.exposition", json!({ "mode": e.mode.id(), "proxys": e.proxies, "entete": e.header, "reseaux": e.networks })).await?;
            println!("✓ {}", t!("Saved: applied within 30 seconds", "Enregistré : appliqué sous 30 secondes"));
            e
        }
    };
    println!("{} {}", t!("Mode:", "Mode :"), e.mode.id());
    println!("{} {}", t!("Trusted proxies:", "Proxys de confiance :"), e.proxies.join(", "));
    println!("{} {}", t!("Address header:", "En-tête de l'adresse :"), e.header);
    println!("{} {}", t!("Allowed networks:", "Réseaux autorisés :"), e.networks.join(", "));
    Ok(())
}

async fn rule_cmd(state: &State, cmd: RuleCmd) -> Result<()> {
    let db = &state.db;
    match cmd {
        RuleCmd::Add {
            name,
            group,
            targets,
            sftp,
            tunnels,
            record_input,
            days,
            hours,
            expires,
        } => {
            let group_id = model::group_id(db, &group).await?;
            let mut ids = Vec::new();
            for t in &targets {
                ids.push(
                    model::target_by_name(db, t)
                        .await?
                        .ok_or_else(|| anyhow!(t!(format!("Unknown target: {t}"), format!("Cible inconnue : {t}"))))?
                        .id,
                );
            }
            if ids.is_empty() {
                bail!(t!("Give at least one target (--targets a,b)", "Indiquez au moins une cible (--targets a,b)"));
            }
            let hours = match hours {
                Some(h) => {
                    let (a, b) = h.split_once('-').ok_or_else(|| anyhow!(t!("Hours: « 7-20 »", "Heures : « 7-20 »")))?;
                    Some((a.trim().parse::<i16>()?, b.trim().parse::<i16>()?))
                }
                None => None,
            };
            let expires_at = match expires {
                Some(d) => {
                    let date = chrono::NaiveDate::parse_from_str(&d, "%Y-%m-%d").map_err(|_| anyhow!(t!("Date: YYYY-MM-DD", "Date : AAAA-MM-JJ")))?;
                    let end = date
                        .and_hms_opt(23, 59, 59)
                        .unwrap()
                        .and_local_timezone(chrono::Local)
                        .single()
                        .ok_or_else(|| anyhow!(t!("ambiguous date", "date ambiguë")))?;
                    Some(end.with_timezone(&chrono::Utc))
                }
                None => None,
            };
            let days = days.as_deref().map(parse_days).transpose()?.unwrap_or(127);
            model::create_rule(
                db,
                model::NewRule {
                    name: name.clone(),
                    group: group_id,
                    targets: ids,
                    allow_sftp: sftp,
                    allow_tunnels: tunnels,
                    record_input,
                    days,
                    hours,
                    expires_at,
                },
            )
            .await?;
            audit::log(
                db,
                "console",
                "regle.creee",
                json!({ "regle": name, "groupe": group, "cibles": targets, "sftp": sftp, "tunnels": tunnels, "frappe": record_input }),
            )
            .await?;
            println!("{}", t!("Rule created.", "Règle créée."));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn jours() {
        assert_eq!(super::parse_days("lun-ven").unwrap(), 0b0011111);
        assert_eq!(super::parse_days("sam,dim").unwrap(), 0b1100000);
        assert_eq!(super::parse_days("ven-lun").unwrap(), 0b1110001);
        assert_eq!(super::parse_days("mon-fri").unwrap(), 0b0011111);
        assert!(super::parse_days("xyz").is_err());
    }
}
