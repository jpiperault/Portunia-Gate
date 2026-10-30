//! Heimdia, le bastion SSH de Portunia.
//!
//! `heimdia serve` lance le service ; les autres commandes administrent le bastion
//! depuis le serveur (`docker compose exec heimdia heimdia …`).

mod api;
mod audit;
mod auth;
mod config;
mod health;
mod keys;
mod model;
mod portal;
mod rdp;
mod recording;
mod replay;
mod sshd;
mod target;
mod tls;

use std::{io::IsTerminal, sync::Arc};

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
}

#[derive(Parser)]
#[command(name = "heimdia", version, about = "Bastion SSH de Portunia")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Première installation : base, clés et compte administrateur.
    Init {
        /// Identifiant de l'administrateur.
        #[arg(long, default_value = "admin")]
        admin: String,
        /// Prépare la base et les clés sans créer d'administrateur.
        #[arg(long)]
        no_admin: bool,
        /// Mot de passe provisoire affiché : l'administrateur le change et enrôle son code dans Portunia.
        #[arg(long)]
        provisoire: bool,
        /// Nom du bastion affiché dans Portunia et les applications d'authentification.
        #[arg(long)]
        nom: Option<String>,
    },
    /// Version, empreintes à comparer dans Portunia et nombre de comptes.
    Info,
    /// Lance le bastion.
    Serve,
    /// Comptes des utilisateurs.
    #[command(subcommand)]
    User(UserCmd),
    /// Groupes d'utilisateurs.
    #[command(subcommand)]
    Group(GroupCmd),
    /// Serveurs protégés par le bastion.
    #[command(subcommand)]
    Target(TargetCmd),
    /// Règles d'accès.
    #[command(subcommand)]
    Rule(RuleCmd),
    /// Journal d'audit.
    Audit {
        /// Vérifie toute la chaîne.
        #[arg(long)]
        verify: bool,
        /// Nombre d'événements affichés.
        #[arg(long, default_value_t = 30)]
        last: i64,
    },
    /// Dernières sessions.
    Sessions {
        #[arg(long, default_value_t = 30)]
        last: i64,
    },
    /// Réglages généraux (politique d'authentification, bannière, nom).
    Setting {
        /// auth_policy, banniere ou nom.
        key: String,
        /// Nouvelle valeur ; sans valeur, affiche l'actuelle.
        value: Option<String>,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Crée un compte (mot de passe demandé, puis enrôlement du code si nécessaire).
    Add {
        login: String,
        /// user, auditor ou admin.
        #[arg(long, default_value = "user")]
        role: String,
        /// Combinaisons acceptées, ex. « password+totp,key+totp » (vide = réglage général).
        #[arg(long)]
        policy: Option<String>,
        /// Pas de mot de passe (connexion par clé uniquement).
        #[arg(long)]
        no_password: bool,
        /// Mot de passe provisoire affiché : l'utilisateur le change et enrôle son code dans Portunia.
        #[arg(long, conflicts_with = "no_password")]
        provisoire: bool,
    },
    /// Liste les comptes.
    List,
    /// Supprime un compte (ses sessions passées restent dans le journal).
    Delete { login: String },
    /// Change le rôle d'un compte : user, auditor ou admin.
    Role { login: String, role: String },
    /// Ajoute une clé SSH publique (texte « ssh-ed25519 AAAA… » ou chemin d'un fichier .pub).
    Key { login: String, key: String },
    /// Enrôle (ou réenrôle) le code TOTP.
    Totp { login: String },
    /// Change le mot de passe.
    Passwd { login: String },
    /// Désactive ou réactive un compte.
    Disable {
        login: String,
        #[arg(long)]
        undo: bool,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    Add {
        name: String,
    },
    /// Ajoute des comptes à un groupe.
    Member {
        group: String,
        logins: Vec<String>,
    },
}

#[derive(Subcommand)]
enum TargetCmd {
    /// Ajoute une cible.
    Add {
        name: String,
        #[arg(long)]
        host: String,
        /// Port (22 en SSH, 3389 en Bureau à distance par défaut).
        #[arg(long)]
        port: Option<i32>,
        /// ssh ou rdp (Bureau à distance, mode rebond pour l'instant).
        #[arg(long, default_value = "ssh")]
        protocol: String,
        /// rebond, enregistre ou coffre.
        #[arg(long, default_value = "coffre")]
        mode: String,
        /// Compte sur la cible.
        #[arg(long)]
        account: Option<String>,
        /// Dossier d'affichage (Production, Recette…).
        #[arg(long, default_value = "")]
        folder: String,
        /// Mot de passe du compte, demandé à la saisie.
        #[arg(long)]
        password: bool,
        /// Clé privée du compte (fichier OpenSSH).
        #[arg(long)]
        key_file: Option<String>,
    },
    List,
}

#[derive(Subcommand)]
enum RuleCmd {
    /// Ajoute une règle : un groupe, des cibles et des conditions.
    Add {
        name: String,
        #[arg(long)]
        group: String,
        /// Cibles séparées par des virgules.
        #[arg(long, value_delimiter = ',')]
        targets: Vec<String>,
        #[arg(long)]
        sftp: bool,
        #[arg(long)]
        tunnels: bool,
        /// Enregistre aussi la frappe (attention : capte les mots de passe tapés).
        #[arg(long)]
        record_input: bool,
        /// Jours : « lun-ven », « lun,mer,ven » ; vide = tous les jours.
        #[arg(long)]
        days: Option<String>,
        /// Heures : « 7-20 ».
        #[arg(long)]
        hours: Option<String>,
        /// Date d'expiration : AAAA-MM-JJ.
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
        let first = prompt_secret("Mot de passe (10 caractères minimum) : ")?;
        if first.chars().count() < 10 {
            println!("Trop court.");
            if !std::io::stdin().is_terminal() {
                bail!("mot de passe trop court");
            }
            continue;
        }
        if std::io::stdin().is_terminal() && prompt_secret("Confirmez : ")? != first {
            println!("Les deux saisies diffèrent.");
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
                sqlx::migrate!().run(&pool).await.context("mise à jour du schéma de la base")?;
                return Ok(pool);
            }
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
    Err(anyhow!(
        "base PostgreSQL injoignable : {}",
        last.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// Enrôle le code TOTP : affiche le code QR et exige un premier code juste.
async fn enroll_totp(state: &State, user: &model::User) -> Result<()> {
    let secret = keys::random::<20>()?;
    let issuer = model::setting(&state.db, "nom")
        .await?
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "Heimdia".into());
    let uri = auth::otpauth_uri(&issuer, &user.login, &secret);
    println!("\nScannez ce code dans votre application d'authentification :\n");
    println!("{}", auth::qr_terminal(&uri)?);
    println!("Ou saisissez la clé : {}\n", auth::base32(&secret));
    for _ in 0..3 {
        let code = prompt_line("Code affiché par l'application : ")?;
        if let Some(step) = auth::totp_check(&secret, &code, 0) {
            model::set_totp(&state.db, user.id, Some(state.keys.seal(&format!("totp:{}", user.id), &secret)?)).await?;
            model::consume_totp_step(&state.db, user.id, step).await?;
            audit::log(&state.db, "console", "compte.totp_enrole", json!({ "compte": user.login })).await?;
            println!("Code enregistré.");
            return Ok(());
        }
        println!("Code incorrect (vérifiez l'heure du téléphone).");
    }
    bail!("enrôlement abandonné : aucun code juste")
}

fn parse_days(text: &str) -> Result<i16> {
    const NAMES: [&str; 7] = ["lun", "mar", "mer", "jeu", "ven", "sam", "dim"];
    let index = |d: &str| {
        NAMES
            .iter()
            .position(|n| d.trim().to_lowercase().starts_with(n))
            .ok_or_else(|| anyhow!("jour inconnu : {d}"))
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
    // Sortie lue par « head » ou un pipe fermé : s'arrêter sans erreur, comme les outils Unix.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    // Le service trace son activité ; les commandes d'administration n'affichent que les avertissements.
    let default_filter = if matches!(cli.command, Command::Serve) {
        "heimdia=info,russh=warn"
    } else {
        "heimdia=warn,russh=warn"
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
        eprintln!("Erreur : {e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
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
    let keys = Keys::load(&config.data_dir)?;
    let state = Arc::new(State { db, keys, config, web: portal::Live::default() });

    match cli.command {
        Command::Init { .. } => unreachable!(),
        Command::Info => {
            let nom = model::setting(&state.db, "nom")
                .await?
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| "Heimdia".into());
            let users = model::users(&state.db).await?;
            println!("{nom} · Heimdia {}", env!("CARGO_PKG_VERSION"));
            println!("Clé d'hôte SSH        {}", state.keys.host_fingerprint());
            println!("Certificat de l'API   {}", tls::fingerprint(&state.config.data_dir)?);
            println!(
                "Comptes               {} dont {} administrateur(s)",
                users.len(),
                users.iter().filter(|u| u.role == "admin").count()
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
            tokio::try_join!(sshd::run(state.clone()), api::run(state.clone()), portal::run(state.clone()), health::run(state.clone()))?;
            Ok(())
        }
        Command::User(cmd) => user_cmd(&state, cmd).await,
        Command::Group(cmd) => group_cmd(&state, cmd).await,
        Command::Target(cmd) => target_cmd(&state, cmd).await,
        Command::Rule(cmd) => rule_cmd(&state, cmd).await,
        Command::Audit { verify, last } => {
            if verify {
                match audit::verify(&state.db).await? {
                    Ok(n) => println!("Journal intact : {n} événements chaînés."),
                    Err(broken) => bail!("JOURNAL ALTÉRÉ : {broken}"),
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
                    .unwrap_or_else(|| "en cours".into());
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
            if !["auth_policy", "banniere", "nom"].contains(&key.as_str()) {
                bail!("réglage inconnu : auth_policy, banniere ou nom");
            }
            match value {
                None => println!(
                    "{}",
                    model::setting(&state.db, &key)
                        .await?
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "(défaut)".into())
                ),
                Some(v) => {
                    if key == "auth_policy" {
                        auth::Policy::parse(&v)?;
                    }
                    model::set_setting(&state.db, &key, json!(v)).await?;
                    audit::log(&state.db, "console", "reglage.modifie", json!({ "reglage": key, "valeur": v })).await?;
                    println!("Réglage enregistré.");
                }
            }
            Ok(())
        }
    }
}

/// Noms du certificat de l'API : HEIMDIA_TLS_NAMES (séparés par des virgules), sinon « heimdia ».
/// Portunia vérifie l'empreinte du certificat, pas son nom.
fn tls_names() -> Vec<String> {
    std::env::var("HEIMDIA_TLS_NAMES")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec!["heimdia".into(), "localhost".into()])
}

async fn init(config: Config, admin: &str, no_admin: bool, provisional: bool, nom: Option<&str>) -> Result<()> {
    println!("Heimdia {}, première installation\n", env!("CARGO_PKG_VERSION"));
    for created in Keys::create_missing(&config.data_dir)? {
        println!("✓ Créé : {created}");
    }
    if tls::create_missing(&config.data_dir, &tls_names())? {
        println!("✓ Créé : certificat de l'API");
    }
    std::fs::create_dir_all(config.recordings_dir())?;
    let db = connect_db(&config).await?;
    println!("✓ Base PostgreSQL prête");
    let keys = Keys::load(&config.data_dir)?;
    let state = State { db, keys, config, web: portal::Live::default() };
    if model::setting(&state.db, "site_id").await?.is_none() {
        model::set_setting(&state.db, "site_id", json!(uuid::Uuid::new_v4())).await?;
    }
    if let Some(nom) = nom.map(str::trim).filter(|n| !n.is_empty()) {
        model::set_setting(&state.db, "nom", json!(nom)).await?;
    }
    use base64::Engine;
    let sig = base64::engine::general_purpose::STANDARD.encode(state.keys.signature_public_key());
    model::set_setting(&state.db, "signature_publique", json!(sig)).await?;
    println!("✓ Clé d'hôte SSH        {}", state.keys.host_fingerprint());
    println!("✓ Certificat de l'API   {}", tls::fingerprint(&state.config.data_dir)?);
    println!("✓ Signature des enregistrements : clé publique {sig}");
    println!(
        "  À SAUVEGARDER hors du serveur : {}",
        state.config.data_dir.join("coffre.key").display()
    );

    let has_admin = model::users(&state.db).await?.iter().any(|u| u.role == "admin");
    if no_admin {
        println!(
            "
Aucun administrateur créé (--no-admin) : lancez « heimdia init » pour le créer."
        );
    } else if has_admin {
        println!("\nUn administrateur existe déjà : rien d'autre à faire.");
    } else {
        println!("\nCompte administrateur : {admin}");
        create_account(&state, admin, "admin", None, false, provisional).await?;
    }
    audit::log(
        &state.db,
        "console",
        "installation",
        json!({ "version": env!("CARGO_PKG_VERSION") }),
    )
    .await?;
    println!("\n✓ Prêt.");
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
        bail!("rôle : user, auditor ou admin");
    }
    if model::user_by_login(db, login).await?.is_some() {
        bail!("le compte {login} existe déjà");
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
        let user = model::user_by_id(db, id).await?.ok_or_else(|| anyhow!("compte introuvable"))?;
        if user.policy(db).await?.needs_totp() {
            if let Err(e) = enroll_totp(state, &user).await {
                sqlx::query("DELETE FROM users WHERE id = $1").bind(id).execute(db).await?;
                bail!("{e} ; compte non créé, relancez la commande");
            }
        }
    }
    audit::log(db, "console", "compte.cree", json!({ "compte": login, "role": role })).await?;
    match temp {
        Some(temp) => println!(
            "Compte {login} créé. Mot de passe provisoire : {temp}\n\
             À la première connexion dans Portunia, l'utilisateur choisit son mot de passe puis scanne son code QR."
        ),
        None => println!("Compte {login} créé."),
    }
    Ok(())
}

async fn user_cmd(state: &State, cmd: UserCmd) -> Result<()> {
    let db = &state.db;
    let find = |login: String| async move {
        model::user_by_login(db, &login)
            .await?
            .ok_or_else(|| anyhow!("Compte inconnu : {login}"))
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
                bail!("c'est le dernier administrateur : créez-en un autre avant de le supprimer");
            }
            sqlx::query("DELETE FROM users WHERE id = $1").bind(user.id).execute(db).await?;
            audit::log(db, "console", "compte.supprime", json!({ "compte": user.login })).await?;
            println!("Compte {} supprimé.", user.login);
        }
        UserCmd::Role { login, role } => {
            if !["user", "auditor", "admin"].contains(&role.as_str()) {
                bail!("rôle : user, auditor ou admin");
            }
            let user = find(login).await?;
            sqlx::query("UPDATE users SET role = $2 WHERE id = $1")
                .bind(user.id)
                .bind(&role)
                .execute(db)
                .await?;
            audit::log(db, "console", "compte.modifie", json!({ "compte": user.login, "role": role })).await?;
            println!("{} est maintenant {role}.", user.login);
        }
        UserCmd::List => {
            for u in model::users(db).await? {
                println!(
                    "{:<20} {:<8} code {:<9} {}{}",
                    u.login,
                    u.role,
                    if u.totp_secret.is_some() { "enrôlé" } else { "absent" },
                    u.auth_policy.unwrap_or_else(|| "(général)".into()),
                    if u.disabled { "  DÉSACTIVÉ" } else { "" }
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
            let public = russh::keys::PublicKey::from_openssh(text.trim()).map_err(|e| anyhow!("clé publique illisible : {e}"))?;
            let fp = public.fingerprint(russh::keys::HashAlg::Sha256).to_string();
            model::add_user_key(db, user.id, text.trim(), &fp, &String::from_utf8_lossy(public.comment().as_bytes())).await?;
            audit::log(
                db,
                "console",
                "compte.cle_ajoutee",
                json!({ "compte": user.login, "empreinte": fp }),
            )
            .await?;
            println!("Clé ajoutée : {fp}");
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
            println!("Mot de passe changé.");
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
            println!("{}", if undo { "Compte réactivé." } else { "Compte désactivé." });
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
            println!("Groupe créé.");
        }
        GroupCmd::Member { group, logins } => {
            let gid = model::group_id(db, &group).await?;
            for login in logins {
                let user = model::user_by_login(db, &login)
                    .await?
                    .ok_or_else(|| anyhow!("Compte inconnu : {login}"))?;
                model::add_member(db, gid, user.id).await?;
                audit::log(db, "console", "groupe.membre_ajoute", json!({ "groupe": group, "compte": login })).await?;
            }
            println!("Membres ajoutés.");
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
            let secret: Option<(String, Vec<u8>)> = match (password, key_file) {
                (true, Some(_)) => bail!("Choisissez --password ou --key-file, pas les deux"),
                (true, None) => Some((
                    "password".into(),
                    prompt_secret("Mot de passe du compte sur la cible : ")?.into_bytes(),
                )),
                (false, Some(path)) => {
                    let text = std::fs::read_to_string(&path).with_context(|| format!("lecture de {path}"))?;
                    russh::keys::decode_secret_key(&text, None)
                        .map_err(|e| anyhow!("clé privée illisible (sans phrase de passe) : {e}"))?;
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
            println!("Cible créée. L'empreinte de son serveur sera mémorisée à la première connexion.");
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
                    t.host_key.unwrap_or_else(|| "empreinte à mémoriser".into())
                );
            }
        }
    }
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
                        .ok_or_else(|| anyhow!("Cible inconnue : {t}"))?
                        .id,
                );
            }
            if ids.is_empty() {
                bail!("Indiquez au moins une cible (--targets a,b)");
            }
            let hours = match hours {
                Some(h) => {
                    let (a, b) = h.split_once('-').ok_or_else(|| anyhow!("Heures : « 7-20 »"))?;
                    Some((a.trim().parse::<i16>()?, b.trim().parse::<i16>()?))
                }
                None => None,
            };
            let expires_at = match expires {
                Some(d) => {
                    let date = chrono::NaiveDate::parse_from_str(&d, "%Y-%m-%d").map_err(|_| anyhow!("Date : AAAA-MM-JJ"))?;
                    let end = date
                        .and_hms_opt(23, 59, 59)
                        .unwrap()
                        .and_local_timezone(chrono::Local)
                        .single()
                        .ok_or_else(|| anyhow!("date ambiguë"))?;
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
            println!("Règle créée.");
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
        assert!(super::parse_days("xyz").is_err());
    }
}
