//! Serveur SSH du bastion : authentification des utilisateurs, choix de la cible,
//! puis relais de la session vers la cible (enregistrée selon son mode).
//!
//! Formes acceptées :
//! - `ssh login@bastion` : menu des serveurs autorisés ;
//! - `ssh login%cible@bastion` : accès direct (shell, commande, SFTP) ;
//! - `ssh -J login@bastion cible` : rebond de bout en bout, cibles en mode rebond.

use std::{borrow::Cow, collections::BTreeSet, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use russh::{
    keys::HashAlg,
    server::{self, Auth, ChannelOpenHandle, Msg, Response, Session},
    Channel, ChannelId, ChannelMsg, ChannelOpenFailure, MethodKind, MethodSet, Pty,
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    audit,
    auth::{totp_check, verify_password, Factor},
    model::{self, Access, Target, User},
    recording::Recorder,
    target::{self, ConnectError, Credentials},
    State,
};

pub const DEFAULT_BANNER: &str =
    "Accès réservé aux personnes autorisées. Les connexions sont journalisées et les sessions peuvent être enregistrées.";

pub async fn run(state: Arc<State>) -> Result<()> {
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::PublicKey);
    methods.push(MethodKind::Password);
    methods.push(MethodKind::KeyboardInteractive);
    let config = Arc::new(server::Config {
        keys: vec![state.keys.host.clone()],
        methods,
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        max_auth_attempts: 6,
        inactivity_timeout: Some(Duration::from_secs(8 * 3600)),
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    tracing::info!("SSH en écoute sur {}", state.config.ssh_listen);
    let listen = state.config.ssh_listen.clone();
    let mut server = Server { state };
    use russh::server::Server as _;
    server.run_on_address(config, listen.as_str()).await?;
    Ok(())
}

#[derive(Clone)]
struct Server {
    state: Arc<State>,
}

impl server::Server for Server {
    type Handler = Conn;

    fn new_client(&mut self, addr: Option<SocketAddr>) -> Conn {
        Conn {
            state: self.state.clone(),
            addr: addr.map(|a| a.ip().to_string()).unwrap_or_default(),
            requested: String::new(),
            user: None,
            factors: BTreeSet::new(),
            ki: KiStage::Start,
            ctx: None,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        tracing::debug!("session SSH terminée : {error:#}");
    }
}

#[derive(PartialEq)]
enum KiStage {
    Start,
    Password,
    Totp,
}

/// Une connexion d'utilisateur au bastion.
struct Conn {
    state: Arc<State>,
    addr: String,
    /// Nom tapé par l'utilisateur (« login » ou « login%cible »).
    requested: String,
    user: Option<User>,
    factors: BTreeSet<Factor>,
    ki: KiStage,
    ctx: Option<Arc<Ctx>>,
}

/// Ce qui est connu une fois l'utilisateur authentifié.
struct Ctx {
    state: Arc<State>,
    user: User,
    addr: String,
    /// Cible demandée dans le nom (« login%cible »), avec les droits du moment.
    target: Option<(Target, Option<Access>)>,
    requested_target: Option<String>,
}

fn split_login(requested: &str) -> (&str, Option<&str>) {
    match requested.split_once('%') {
        Some((login, target)) if !target.is_empty() => (login, Some(target)),
        _ => (requested.trim_end_matches('%'), None),
    }
}

fn ki_prompt(text: &str, echo: bool) -> Auth {
    Auth::Partial {
        name: Cow::Borrowed("Heimdia"),
        instructions: Cow::Borrowed(""),
        prompts: Cow::Owned(vec![(Cow::Owned(text.to_string()), echo)]),
    }
}

impl Conn {
    /// Charge le compte demandé (une fois par connexion). Un compte désactivé ou inconnu
    /// est traité comme un échec, sans dire lequel des deux.
    async fn load(&mut self, requested: &str) -> Result<Option<User>> {
        if self.requested != requested || self.user.is_none() {
            self.requested = requested.to_string();
            self.factors.clear();
            self.ki = KiStage::Start;
            let (login, _) = split_login(requested);
            self.user = model::user_by_login(&self.state.db, login).await?.filter(|u| !u.disabled);
        }
        Ok(self.user.clone())
    }

    async fn fail(&self, method: &str, why: &str) {
        let (login, _) = split_login(&self.requested);
        audit::note(
            &self.state.db,
            login,
            "auth.echec",
            json!({ "methode": method, "raison": why, "adresse": self.addr }),
        )
        .await;
    }

    /// Après un facteur réussi : accès complet, ou demande du code TOTP.
    async fn decide(&mut self, user: &User) -> Result<Auth> {
        let policy = user.policy(&self.state.db).await?;
        if policy.satisfied(&self.factors) {
            let methods: Vec<&str> = self
                .factors
                .iter()
                .map(|f| match f {
                    Factor::Password => "mot de passe",
                    Factor::Key => "clé",
                    Factor::Totp => "code",
                })
                .collect();
            audit::note(
                &self.state.db,
                &user.login,
                "auth.reussie",
                json!({ "facteurs": methods, "adresse": self.addr }),
            )
            .await;
            return Ok(Auth::Accept);
        }
        if policy.could_use(&self.factors, Factor::Totp) {
            if user.totp_secret.is_none() {
                self.fail("totp", "code TOTP non enrôlé").await;
                return Ok(Auth::reject());
            }
            return Ok(Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
                partial_success: true,
            });
        }
        Ok(Auth::reject())
    }

    async fn check_totp(&mut self, user: &User, code: &str) -> Result<bool> {
        let Some(sealed) = &user.totp_secret else { return Ok(false) };
        let secret = self.state.keys.open(&format!("totp:{}", user.id), sealed)?;
        let Some(step) = totp_check(&secret, code, user.totp_last_step) else {
            return Ok(false);
        };
        model::consume_totp_step(&self.state.db, user.id, step).await
    }
}

impl server::Handler for Conn {
    type Error = anyhow::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        let text = model::setting(&self.state.db, "banniere")
            .await?
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| DEFAULT_BANNER.to_string());
        Ok(Some(format!("{text}\r\n")))
    }

    async fn auth_password(&mut self, requested: &str, password: &str) -> Result<Auth, Self::Error> {
        let Some(user) = self.load(requested).await? else {
            self.fail("mot de passe", "compte inconnu ou désactivé").await;
            return Ok(Auth::reject());
        };
        let policy = user.policy(&self.state.db).await?;
        if !policy.could_use(&self.factors, Factor::Password) {
            return Ok(Auth::reject());
        }
        if !user.password_hash.as_deref().is_some_and(|h| verify_password(h, password)) {
            self.fail("mot de passe", "mot de passe incorrect").await;
            return Ok(Auth::reject());
        }
        self.factors.insert(Factor::Password);
        self.decide(&user).await
    }

    async fn auth_publickey_offered(&mut self, requested: &str, key: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
        let Some(user) = self.load(requested).await? else {
            return Ok(Auth::reject());
        };
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        let owned = model::user_key_owner(&self.state.db, &fingerprint).await? == Some(user.id);
        let usable = user.policy(&self.state.db).await?.could_use(&self.factors, Factor::Key);
        Ok(if owned && usable { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, requested: &str, key: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
        let Some(user) = self.load(requested).await? else {
            return Ok(Auth::reject());
        };
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        if model::user_key_owner(&self.state.db, &fingerprint).await? != Some(user.id) {
            self.fail("clé", "clé inconnue").await;
            return Ok(Auth::reject());
        }
        self.factors.insert(Factor::Key);
        self.decide(&user).await
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        requested: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let Some(user) = self.load(requested).await? else {
            self.fail("clavier", "compte inconnu ou désactivé").await;
            return Ok(Auth::reject());
        };
        let policy = user.policy(&self.state.db).await?;
        let answer = response
            .and_then(|mut r| r.next())
            .map(|b| String::from_utf8_lossy(&b).into_owned());
        match (&self.ki, answer) {
            // Premier passage : mot de passe si rien n'est encore prouvé, sinon le code.
            (KiStage::Start, _) | (_, None) => {
                if self.factors.is_empty() && policy.could_use(&self.factors, Factor::Password) {
                    self.ki = KiStage::Password;
                    Ok(ki_prompt("Mot de passe : ", false))
                } else if policy.could_use(&self.factors, Factor::Totp) && user.totp_secret.is_some() {
                    self.ki = KiStage::Totp;
                    Ok(ki_prompt("Code d'authentification : ", true))
                } else {
                    Ok(Auth::reject())
                }
            }
            (KiStage::Password, Some(password)) => {
                if !user.password_hash.as_deref().is_some_and(|h| verify_password(h, &password)) {
                    self.fail("mot de passe", "mot de passe incorrect").await;
                    self.ki = KiStage::Start;
                    return Ok(Auth::reject());
                }
                self.factors.insert(Factor::Password);
                if policy.satisfied(&self.factors) {
                    return self.decide(&user).await;
                }
                if policy.could_use(&self.factors, Factor::Totp) && user.totp_secret.is_some() {
                    self.ki = KiStage::Totp;
                    return Ok(ki_prompt("Code d'authentification : ", true));
                }
                Ok(Auth::reject())
            }
            (KiStage::Totp, Some(code)) => {
                if !self.check_totp(&user, &code).await? {
                    self.fail("code", "code incorrect ou déjà utilisé").await;
                    // On reste sur le code : une nouvelle tentative le redemande.
                    return Ok(Auth::reject());
                }
                self.factors.insert(Factor::Totp);
                self.decide(&user).await
            }
        }
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        let Some(user) = self.user.clone() else { return Ok(()) };
        let (_, wanted) = split_login(&self.requested);
        let target = match wanted {
            Some(name) => match model::target_by_name(&self.state.db, name).await? {
                Some(t) => {
                    let access = model::access(&self.state.db, user.id, t.id).await?;
                    Some((t, access))
                }
                None => None,
            },
            None => None,
        };
        self.ctx = Some(Arc::new(Ctx {
            state: self.state.clone(),
            user,
            addr: self.addr.clone(),
            target,
            requested_target: wanted.map(str::to_owned),
        }));
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(ctx) = self.ctx.clone() else {
            reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            if let Err(e) = run_channel(ctx, channel).await {
                tracing::warn!("session : {e:#}");
            }
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(&mut self, channel: ChannelId, _name: &str, _value: &str, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data);
        let allowed = self
            .ctx
            .as_ref()
            .and_then(|c| c.target.as_ref())
            .is_some_and(|(t, access)| access.is_some_and(|a| a.sftp || !is_file_copy(&command)) && t.vaulted());
        if allowed {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        let allowed = name == "sftp"
            && self
                .ctx
                .as_ref()
                .and_then(|c| c.target.as_ref())
                .is_some_and(|(t, access)| access.is_some_and(|a| a.sftp) && t.vaulted());
        if allowed {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        origin: &str,
        origin_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(ctx) = self.ctx.clone() else {
            reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        };
        let db = &self.state.db;
        // 1. Rebond de bout en bout (ssh -J) vers une cible en mode rebond.
        for t in model::rebond_targets_at(db, host, port as i32).await? {
            if model::access(db, ctx.user.id, t.id).await?.is_some() {
                reply.accept().await;
                tokio::spawn(async move {
                    if let Err(e) = relay_tcp(ctx, t, channel).await {
                        tracing::warn!("rebond : {e:#}");
                    }
                });
                return Ok(());
            }
        }
        // 2. Tunnel (ssh -L) à travers une cible du coffre, si la règle l'autorise.
        if let Some((t, Some(access))) = ctx.target.clone() {
            if access.tunnels && t.vaulted() {
                reply.accept().await;
                let (host, origin) = (host.to_string(), origin.to_string());
                tokio::spawn(async move {
                    if let Err(e) = relay_tunnel(ctx, t, channel, host, port, origin, origin_port).await {
                        tracing::warn!("tunnel : {e:#}");
                    }
                });
                return Ok(());
            }
        }
        audit::note(
            db,
            &ctx.user.login,
            "acces.refuse",
            json!({ "demande": format!("{host}:{port}"), "type": "tunnel", "adresse": ctx.addr }),
        )
        .await;
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }
}

/// scp et rsync copient des fichiers : soumis au même droit que SFTP.
fn is_file_copy(command: &str) -> bool {
    let first = command.split_whitespace().next().unwrap_or("");
    matches!(first.rsplit('/').next().unwrap_or(""), "scp" | "rsync" | "sftp-server")
}

#[derive(Clone)]
struct PtyInfo {
    term: String,
    cols: u32,
    rows: u32,
    pix_w: u32,
    pix_h: u32,
    modes: Vec<(Pty, u32)>,
}

/// Attend la demande du client (shell, commande ou SFTP) puis la sert.
async fn run_channel(ctx: Arc<Ctx>, mut channel: Channel<Msg>) -> Result<()> {
    let mut pty: Option<PtyInfo> = None;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::RequestPty {
                term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                terminal_modes,
                ..
            }) => {
                pty = Some(PtyInfo {
                    term,
                    cols: col_width,
                    rows: row_height,
                    pix_w: pix_width,
                    pix_h: pix_height,
                    modes: terminal_modes,
                });
            }
            Some(ChannelMsg::WindowChange { col_width, row_height, .. }) => {
                if let Some(p) = &mut pty {
                    p.cols = col_width;
                    p.rows = row_height;
                }
            }
            Some(ChannelMsg::RequestShell { .. }) => return shell(ctx, channel, pty).await,
            Some(ChannelMsg::Exec { command, .. }) => return exec(ctx, channel, pty, String::from_utf8_lossy(&command).into_owned()).await,
            Some(ChannelMsg::RequestSubsystem { name, .. }) => return sftp(ctx, channel, name).await,
            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => return Ok(()),
            Some(_) => {}
        }
    }
}

async fn say(channel: &Channel<Msg>, text: &str) {
    let _ = channel.data_bytes(text.replace('\n', "\r\n").into_bytes()).await;
}

async fn close(channel: &Channel<Msg>, status: u32) {
    let _ = channel.exit_status(status).await;
    let _ = channel.eof().await;
    let _ = channel.close().await;
}

/// Lit une ligne tapée dans le terminal (avec écho ou masquée). None : abandon (Ctrl+C, Ctrl+D, fermeture).
async fn read_line(channel: &mut Channel<Msg>, echo: bool, pty: &mut Option<PtyInfo>) -> Option<String> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(120), channel.wait()).await.ok()??;
        match msg {
            ChannelMsg::Data { data } => {
                for &b in data.iter() {
                    match b {
                        b'\r' | b'\n' => {
                            say(channel, "\n").await;
                            return Some(String::from_utf8_lossy(&line).trim().to_string());
                        }
                        3 | 4 => {
                            say(channel, "^C\n").await;
                            return None;
                        }
                        0x7f | 0x08 => {
                            // Retire un caractère entier, même accentué.
                            while let Some(last) = line.pop() {
                                if last & 0xC0 != 0x80 {
                                    break;
                                }
                            }
                            if echo {
                                say(channel, "\x08 \x08").await;
                            }
                        }
                        0x1b => {}
                        _ if b >= 0x20 || b & 0x80 != 0 => {
                            line.push(b);
                            if echo && line.len() < 256 {
                                let _ = channel.data_bytes(vec![b]).await;
                            }
                        }
                        _ => {}
                    }
                }
            }
            ChannelMsg::WindowChange { col_width, row_height, .. } => {
                if let Some(p) = pty {
                    p.cols = col_width;
                    p.rows = row_height;
                }
            }
            ChannelMsg::Eof | ChannelMsg::Close => return None,
            _ => {}
        }
    }
}

/// Menu des serveurs autorisés quand le nom ne désigne pas de cible.
async fn choose_target(ctx: &Ctx, channel: &mut Channel<Msg>, pty: &mut Option<PtyInfo>) -> Result<Option<Target>> {
    let targets = model::allowed_targets(&ctx.state.db, ctx.user.id).await?;
    let name = model::setting(&ctx.state.db, "nom")
        .await?
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "Heimdia".into());
    if targets.is_empty() {
        say(
            channel,
            &format!(
                "\n  {name} · bonjour {}\n  Aucun serveur ne vous est autorisé en ce moment.\n\n",
                ctx.user.login
            ),
        )
        .await;
        return Ok(None);
    }
    let width = targets.iter().map(|t| t.name.chars().count()).max().unwrap_or(0);
    let mut text = format!("\n  {name} · bonjour {}\n  Serveurs autorisés :\n", ctx.user.login);
    for (i, t) in targets.iter().enumerate() {
        let mode = match t.mode.as_str() {
            "coffre" => "coffre",
            "enregistre" => "enregistré",
            _ => "rebond",
        };
        text.push_str(&format!("    {:>2}  {:<width$}  {:<14}  {mode}\n", i + 1, t.name, t.folder));
    }
    say(channel, &text).await;
    for _ in 0..3 {
        say(channel, "  Votre choix (numéro ou nom) : ").await;
        let Some(answer) = read_line(channel, true, pty).await else {
            return Ok(None);
        };
        let found = answer
            .parse::<usize>()
            .ok()
            .and_then(|n| targets.get(n.wrapping_sub(1)))
            .or_else(|| targets.iter().find(|t| t.name.eq_ignore_ascii_case(&answer)));
        match found {
            Some(t) => return Ok(Some(t.clone())),
            None if answer.is_empty() => {}
            None => say(channel, "  Choix inconnu.\n").await,
        }
    }
    Ok(None)
}

/// Session interactive.
async fn shell(ctx: Arc<Ctx>, mut channel: Channel<Msg>, mut pty: Option<PtyInfo>) -> Result<()> {
    let db = &ctx.state.db;
    let login = ctx.user.login.clone();
    let target = match (&ctx.target, &ctx.requested_target) {
        (Some((t, _)), _) => t.clone(),
        (None, Some(name)) => {
            audit::note(
                db,
                &login,
                "acces.refuse",
                json!({ "demande": name, "raison": "cible inconnue", "adresse": ctx.addr }),
            )
            .await;
            say(&channel, &format!("Serveur inconnu ou non autorisé : {name}\n")).await;
            close(&channel, 1).await;
            return Ok(());
        }
        (None, None) => match choose_target(&ctx, &mut channel, &mut pty).await? {
            Some(t) => t,
            None => {
                close(&channel, 1).await;
                return Ok(());
            }
        },
    };
    // Les droits sont relus au moment d'ouvrir : une règle retirée s'applique tout de suite.
    let Some(access) = model::access(db, ctx.user.id, target.id).await? else {
        audit::note(
            db,
            &login,
            "acces.refuse",
            json!({ "cible": target.name, "raison": "aucune règle active", "adresse": ctx.addr }),
        )
        .await;
        say(&channel, &format!("Serveur inconnu ou non autorisé : {}\n", target.name)).await;
        close(&channel, 1).await;
        return Ok(());
    };

    say(&channel, &format!("Connexion à {}…\n", target.name)).await;
    let Some((handle, creds_user)) = connect_interactive(&ctx, &target, &mut channel, &mut pty).await? else {
        close(&channel, 1).await;
        return Ok(());
    };
    let remote = handle.channel_open_session().await?;
    let p = pty.clone().unwrap_or(PtyInfo {
        term: "xterm-256color".into(),
        cols: 80,
        rows: 24,
        pix_w: 0,
        pix_h: 0,
        modes: vec![],
    });
    remote
        .request_pty(true, &p.term, p.cols, p.rows, p.pix_w, p.pix_h, &p.modes)
        .await?;
    remote.request_shell(true).await?;

    let id = Uuid::new_v4();
    let detail = format!("{creds_user}@{}", target.name);
    model::session_start(db, id, ctx.user.id, target.id, "shell", &detail, &ctx.addr).await?;
    audit::note(
        db,
        &login,
        "session.ouverte",
        json!({ "session": id, "cible": target.name, "compte": creds_user, "mode": target.mode, "adresse": ctx.addr }),
    )
    .await;
    let mut recorder = if target.records() {
        say(&channel, "Heimdia : session enregistrée.\n").await;
        Some(Recorder::create(
            &ctx.state.config.recordings_dir(),
            id,
            p.cols,
            p.rows,
            &format!("{login} → {detail}"),
            access.record_input,
        )?)
    } else {
        None
    };
    let started = std::time::Instant::now();
    let status = pump(&mut channel, remote, recorder.as_mut()).await;
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
    finish(&ctx, id, recorder, started, &target.name).await;
    close(&channel, status.unwrap_or(0)).await;
    Ok(())
}

/// Connexion à la cible pour une session interactive : identifiants du coffre, ou demandés
/// dans le terminal (trois essais).
async fn connect_interactive(
    ctx: &Ctx,
    target: &Target,
    channel: &mut Channel<Msg>,
    pty: &mut Option<PtyInfo>,
) -> Result<Option<(target::Handle, String)>> {
    let login = &ctx.user.login;
    if target.vaulted() {
        let creds = target::vault_credentials(&ctx.state, target)?;
        return match target::connect(&ctx.state, target, &creds, login).await {
            Ok(h) => Ok(Some((h, creds.user().to_string()))),
            Err(ConnectError::Refused) => {
                audit::note(&ctx.state.db, login, "cible.coffre_refuse", json!({ "cible": target.name })).await;
                say(
                    channel,
                    "Le compte du coffre a été refusé par le serveur. Prévenez un administrateur.\n",
                )
                .await;
                Ok(None)
            }
            Err(ConnectError::Other(e)) => {
                say(channel, &format!("{e:#}\n")).await;
                Ok(None)
            }
        };
    }
    let account = match &target.account {
        Some(a) => a.clone(),
        None => {
            say(channel, &format!("Identifiant sur {} : ", target.name)).await;
            match read_line(channel, true, pty).await {
                Some(a) if !a.is_empty() => a,
                _ => return Ok(None),
            }
        }
    };
    for attempt in 0..3 {
        say(channel, &format!("Mot de passe de {account}@{} : ", target.name)).await;
        let Some(password) = read_line(channel, false, pty).await else {
            return Ok(None);
        };
        let creds = Credentials::Password {
            user: account.clone(),
            password,
        };
        match target::connect(&ctx.state, target, &creds, login).await {
            Ok(h) => return Ok(Some((h, account))),
            Err(ConnectError::Refused) => {
                audit::note(
                    &ctx.state.db,
                    login,
                    "cible.identifiants_refuses",
                    json!({ "cible": target.name, "compte": account, "essai": attempt + 1 }),
                )
                .await;
                say(channel, "Accès refusé.\n").await;
            }
            Err(ConnectError::Other(e)) => {
                say(channel, &format!("{e:#}\n")).await;
                return Ok(None);
            }
        }
    }
    Ok(None)
}

/// Relaie les deux sens jusqu'à la fermeture ; renvoie le code de sortie de la cible.
async fn pump(user: &mut Channel<Msg>, mut remote: Channel<russh::client::Msg>, mut rec: Option<&mut Recorder>) -> Option<u32> {
    let mut status = None;
    loop {
        tokio::select! {
            msg = user.wait() => match msg {
                Some(ChannelMsg::Data { data }) => {
                    if let Some(r) = rec.as_deref_mut() { r.input(&data); }
                    if remote.data_bytes(data.to_vec()).await.is_err() { break; }
                }
                Some(ChannelMsg::WindowChange { col_width, row_height, pix_width, pix_height }) => {
                    if let Some(r) = rec.as_deref_mut() { r.resize(col_width, row_height); }
                    let _ = remote.window_change(col_width, row_height, pix_width, pix_height).await;
                }
                Some(ChannelMsg::Eof) => { let _ = remote.eof().await; }
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            msg = remote.wait() => match msg {
                Some(ChannelMsg::Data { data }) => {
                    if let Some(r) = rec.as_deref_mut() { r.output(&data); r.flush(); }
                    if user.data_bytes(data.to_vec()).await.is_err() { break; }
                }
                Some(ChannelMsg::ExtendedData { data, ext }) => {
                    if let Some(r) = rec.as_deref_mut() { r.output(&data); r.flush(); }
                    if user.extended_data_bytes(ext, data.to_vec()).await.is_err() { break; }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => status = Some(exit_status),
                Some(ChannelMsg::Eof) => { let _ = user.eof().await; }
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
        }
    }
    status
}

async fn finish(ctx: &Ctx, id: Uuid, recorder: Option<Recorder>, started: std::time::Instant, target: &str) {
    let mut done = model::Finished {
        recording: None,
        sha256: None,
        signature: None,
        bytes: 0,
    };
    if let Some(rec) = recorder {
        match rec.finish(&ctx.state.keys, id) {
            Ok((path, sha, sig, bytes)) => {
                done = model::Finished {
                    recording: Some(path),
                    sha256: Some(sha),
                    signature: Some(sig),
                    bytes: bytes as i64,
                };
            }
            Err(e) => tracing::error!("enregistrement {id} : {e:#}"),
        }
    }
    let bytes = done.bytes;
    if let Err(e) = model::session_end(&ctx.state.db, id, done).await {
        tracing::error!("fin de session {id} : {e:#}");
    }
    audit::note(
        &ctx.state.db,
        &ctx.user.login,
        "session.fermee",
        json!({ "session": id, "cible": target, "duree_s": started.elapsed().as_secs(), "octets": bytes }),
    )
    .await;
}

/// Commande unique (ssh login%cible@bastion "commande"), cibles du coffre.
async fn exec(ctx: Arc<Ctx>, mut channel: Channel<Msg>, pty: Option<PtyInfo>, command: String) -> Result<()> {
    let Some((target, Some(access))) = ctx.target.clone() else {
        say(&channel, "Indiquez le serveur dans le nom : utilisateur%serveur@bastion\n").await;
        close(&channel, 1).await;
        return Ok(());
    };
    if !target.vaulted() || (is_file_copy(&command) && !access.sftp) {
        close(&channel, 1).await;
        return Ok(());
    }
    let creds = target::vault_credentials(&ctx.state, &target)?;
    let handle = match target::connect(&ctx.state, &target, &creds, &ctx.user.login).await {
        Ok(h) => h,
        Err(_) => {
            say(&channel, &format!("Connexion à {} impossible.\n", target.name)).await;
            close(&channel, 1).await;
            return Ok(());
        }
    };
    let remote = handle.channel_open_session().await?;
    if let Some(p) = &pty {
        remote
            .request_pty(true, &p.term, p.cols, p.rows, p.pix_w, p.pix_h, &p.modes)
            .await?;
    }
    remote.exec(true, command.as_bytes()).await?;
    let id = Uuid::new_v4();
    let db = &ctx.state.db;
    model::session_start(db, id, ctx.user.id, target.id, "exec", &command, &ctx.addr).await?;
    audit::note(
        db,
        &ctx.user.login,
        "commande.executee",
        json!({ "session": id, "cible": target.name, "commande": command, "adresse": ctx.addr }),
    )
    .await;
    let (cols, rows) = pty.as_ref().map(|p| (p.cols, p.rows)).unwrap_or((80, 24));
    // Copies de fichiers : on journalise sans enregistrer le contenu binaire.
    let mut recorder = if target.records() && !is_file_copy(&command) {
        Some(Recorder::create(
            &ctx.state.config.recordings_dir(),
            id,
            cols,
            rows,
            &format!("{} → {}: {command}", ctx.user.login, target.name),
            access.record_input,
        )?)
    } else {
        None
    };
    let started = std::time::Instant::now();
    let status = pump(&mut channel, remote, recorder.as_mut()).await;
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
    finish(&ctx, id, recorder, started, &target.name).await;
    close(&channel, status.unwrap_or(0)).await;
    Ok(())
}

/// SFTP vers une cible du coffre : les échanges sont relayés et la session journalisée.
async fn sftp(ctx: Arc<Ctx>, mut channel: Channel<Msg>, name: String) -> Result<()> {
    let Some((target, Some(access))) = ctx.target.clone() else {
        close(&channel, 1).await;
        return Ok(());
    };
    if name != "sftp" || !access.sftp || !target.vaulted() {
        close(&channel, 1).await;
        return Ok(());
    }
    let creds = target::vault_credentials(&ctx.state, &target)?;
    let Ok(handle) = target::connect(&ctx.state, &target, &creds, &ctx.user.login).await else {
        close(&channel, 1).await;
        return Ok(());
    };
    let remote = handle.channel_open_session().await?;
    remote.request_subsystem(true, "sftp").await?;
    let id = Uuid::new_v4();
    let db = &ctx.state.db;
    model::session_start(db, id, ctx.user.id, target.id, "sftp", creds.user(), &ctx.addr).await?;
    audit::note(
        db,
        &ctx.user.login,
        "sftp.ouvert",
        json!({ "session": id, "cible": target.name, "adresse": ctx.addr }),
    )
    .await;
    let started = std::time::Instant::now();
    let status = pump(&mut channel, remote, None).await;
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
    finish(&ctx, id, None, started, &target.name).await;
    close(&channel, status.unwrap_or(0)).await;
    Ok(())
}

/// Rebond de bout en bout : le bastion relaie les octets chiffrés sans les lire.
async fn relay_tcp(ctx: Arc<Ctx>, target: Target, channel: Channel<Msg>) -> Result<()> {
    let id = Uuid::new_v4();
    let db = &ctx.state.db;
    let mut tcp = tokio::net::TcpStream::connect((target.host.as_str(), target.port as u16)).await?;
    model::session_start(db, id, ctx.user.id, target.id, "rebond", "ssh -J", &ctx.addr).await?;
    audit::note(
        db,
        &ctx.user.login,
        "rebond.ouvert",
        json!({ "session": id, "cible": target.name, "adresse": ctx.addr }),
    )
    .await;
    let started = std::time::Instant::now();
    let mut stream = channel.into_stream();
    let (up, down) = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await.unwrap_or((0, 0));
    let _ = model::session_end(
        db,
        id,
        model::Finished {
            recording: None,
            sha256: None,
            signature: None,
            bytes: (up + down) as i64,
        },
    )
    .await;
    audit::note(
        db,
        &ctx.user.login,
        "rebond.ferme",
        json!({ "session": id, "cible": target.name, "duree_s": started.elapsed().as_secs(), "octets": up + down }),
    )
    .await;
    Ok(())
}

/// Tunnel (ssh -L) ouvert depuis la cible du coffre.
async fn relay_tunnel(
    ctx: Arc<Ctx>,
    target: Target,
    channel: Channel<Msg>,
    host: String,
    port: u32,
    origin: String,
    origin_port: u32,
) -> Result<()> {
    let creds = target::vault_credentials(&ctx.state, &target)?;
    let handle = match target::connect(&ctx.state, &target, &creds, &ctx.user.login).await {
        Ok(h) => h,
        Err(ConnectError::Refused) => anyhow::bail!("compte du coffre refusé par {}", target.name),
        Err(ConnectError::Other(e)) => return Err(e),
    };
    let remote = handle.channel_open_direct_tcpip(host.clone(), port, origin, origin_port).await?;
    let id = Uuid::new_v4();
    let db = &ctx.state.db;
    let detail = format!("{host}:{port}");
    model::session_start(db, id, ctx.user.id, target.id, "tunnel", &detail, &ctx.addr).await?;
    audit::note(
        db,
        &ctx.user.login,
        "tunnel.ouvert",
        json!({ "session": id, "cible": target.name, "vers": detail, "adresse": ctx.addr }),
    )
    .await;
    let (mut a, mut b) = (channel.into_stream(), remote.into_stream());
    let (up, down) = tokio::io::copy_bidirectional(&mut a, &mut b).await.unwrap_or((0, 0));
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
    let _ = model::session_end(
        db,
        id,
        model::Finished {
            recording: None,
            sha256: None,
            signature: None,
            bytes: (up + down) as i64,
        },
    )
    .await;
    audit::note(
        db,
        &ctx.user.login,
        "tunnel.ferme",
        json!({ "session": id, "cible": target.name, "octets": up + down }),
    )
    .await;
    Ok(())
}
