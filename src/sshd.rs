//! Serveur SSH de la Gate : authentification des utilisateurs, choix de la cible,
//! puis relais de la session vers la cible (enregistrée selon son mode).
//!
//! Formes acceptées :
//! - `ssh login@Gate` : menu des serveurs autorisés ;
//! - `ssh login%cible@Gate` : accès direct (shell, commande, SFTP) ;
//! - `ssh -J login@Gate cible` : rebond de bout en bout, cibles en mode rebond ;
//! - `login%sortie` avec des canaux « direct-tcpip » : sortie web de Portunia (egress.rs).

use std::{
    borrow::Cow,
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

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
    auth::{check_password, totp_check, Factor},
    egress,
    limits::{Slot, Verdict},
    live::{self, Cut, Watched},
    model::{self, Access, Target, User},
    recording::Recorder,
    target::{self, ConnectError, Credentials},
    State,
};

/// Temps laissé pour s'authentifier.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(60);

pub fn default_banner() -> &'static str {
    t!(
        "Access restricted to authorised persons. Connections are logged and sessions may be recorded.",
        "Accès réservé aux personnes autorisées. Les connexions sont journalisées et les sessions peuvent être enregistrées."
    )
}

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
        // Pas de keepalive SSH : envoyé aussi pendant l'authentification, il fait couper OpenSSH
        // (« bad message during authentication: type 80 ») quand l'utilisateur met plus de
        // 30 s à taper son code. Un poste disparu est repéré par le keepalive TCP (voir `serve`).
        keepalive_interval: None,
        ..Default::default()
    });
    tracing::info!("{} {}", t!("SSH listening on", "SSH en écoute sur"), state.config.ssh_listen);
    let listener = tokio::net::TcpListener::bind(state.config.ssh_listen.as_str()).await?;
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!("SSH : {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Plafond des connexions pas encore authentifiées.
        let Some(slot) = state.limits.connection(peer.ip()) else { continue };
        let authenticated = Arc::new(AtomicBool::new(false));
        let conn = Conn {
            state: state.clone(),
            addr: peer.ip().to_string(),
            requested: String::new(),
            user: None,
            factors: BTreeSet::new(),
            ki: KiStage::Start,
            ctx: None,
            slot: Some(slot),
            authenticated: authenticated.clone(),
            watch: None,
            by_ticket: false,
        };
        tokio::spawn(serve(config.clone(), tcp, conn, authenticated, LOGIN_TIMEOUT));
    }
}

/// Keepalive TCP : un poste disparu (réseau coupé, veille) ferme sa session en 2 minutes environ,
/// sans message SSH qui gênerait l'authentification.
fn tcp_keepalive(socket: &std::net::TcpStream) {
    let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(60)).with_interval(Duration::from_secs(15));
    #[cfg(target_os = "linux")]
    let keepalive = keepalive.with_retries(4);
    if let Err(e) = socket2::SockRef::from(socket).set_tcp_keepalive(&keepalive) {
        tracing::debug!("keepalive TCP : {e}");
    }
}

fn duplicate(tcp: tokio::net::TcpStream) -> std::io::Result<(tokio::net::TcpStream, std::net::TcpStream)> {
    let std = tcp.into_std()?;
    let copy = std.try_clone()?;
    Ok((tokio::net::TcpStream::from_std(std)?, copy))
}

/// Sert une connexion ; sans authentification après `LOGIN_TIMEOUT`, elle est fermée.
async fn serve<H>(config: Arc<server::Config>, tcp: tokio::net::TcpStream, conn: H, authenticated: Arc<AtomicBool>, limit: Duration)
where
    H: server::Handler<Error = anyhow::Error> + Send + 'static,
{
    // Double du socket : fermer la session ne suffit pas tant que la négociation n'a pas abouti,
    // la tâche resterait en attente et garderait sa place.
    let Ok((tcp, socket)) = duplicate(tcp) else { return };
    tcp_keepalive(&socket);
    let cut = || {
        let _ = socket.shutdown(std::net::Shutdown::Both);
    };
    let Ok(Ok(mut session)) = tokio::time::timeout(limit, server::run_stream(config, tcp, conn)).await else {
        cut();
        return;
    };
    let ended = tokio::select! {
        ended = &mut session => ended,
        _ = tokio::time::sleep(limit) => {
            if !authenticated.load(Ordering::SeqCst) {
                cut();
            }
            session.await
        }
    };
    if let Err(error) = ended {
        tracing::debug!("{} {error:#}", t!("SSH session ended:", "session SSH terminée :"));
    }
}

#[derive(PartialEq)]
enum KiStage {
    Start,
    Password,
    Totp,
}

/// Une connexion d'utilisateur à la Gate.
struct Conn {
    state: Arc<State>,
    addr: String,
    /// Nom tapé par l'utilisateur (« login » ou « login%cible »).
    requested: String,
    user: Option<User>,
    factors: BTreeSet<Factor>,
    ki: KiStage,
    ctx: Option<Arc<Ctx>>,
    /// Place parmi les connexions non authentifiées, rendue à l'authentification.
    slot: Option<Slot>,
    authenticated: Arc<AtomicBool>,
    /// Inscription de la connexion : fermée si le compte perd son accès.
    watch: Option<live::Guard>,
    /// Authentifié par un jeton à usage unique : la connexion ne vaut que pour sa cible (B5).
    by_ticket: bool,
}

/// Ce qui est connu une fois l'utilisateur authentifié.
struct Ctx {
    state: Arc<State>,
    user: User,
    addr: String,
    /// Cible demandée dans le nom (« login%cible »), avec les droits du moment.
    target: Option<(Target, Option<Access>)>,
    requested_target: Option<String>,
    /// Connexion par jeton : rebond seulement vers la cible du jeton.
    by_ticket: bool,
    /// Sortie web : navigation de cette connexion, ouverte au premier site demandé.
    navigation: tokio::sync::Mutex<Option<Arc<egress::Navigation>>>,
}

impl Ctx {
    /// Le compte existe encore et n'est pas désactivé.
    async fn active(&self) -> Result<bool> {
        Ok(model::user_by_id(&self.state.db, self.user.id).await?.is_some_and(|u| !u.disabled))
    }

    /// La cible demandée dans le nom et les droits de cet instant, relus à chaque ouverture :
    /// une connexion restée ouverte ne garde pas des droits retirés depuis.
    async fn current(&self) -> Result<Option<(Target, Access)>> {
        let Some((target, _)) = &self.target else { return Ok(None) };
        if !self.active().await? {
            return Ok(None);
        }
        let Some(target) = model::target_by_id(&self.state.db, target.id).await? else { return Ok(None) };
        Ok(model::access(&self.state.db, self.user.id, target.id).await?.map(|access| (target, access)))
    }

    /// Navigation de cette connexion (sortie web) ; sa coupure ferme toute la connexion.
    async fn navigation(&self, target: &Target, handle: server::Handle) -> Result<Arc<egress::Navigation>> {
        let mut slot = self.navigation.lock().await;
        if let Some(nav) = slot.as_ref() {
            return Ok(nav.clone());
        }
        let nav = egress::Navigation::start(self.state.clone(), self.user.id, &self.user.login, target, &self.addr).await?;
        let mut cut = nav.cut();
        tokio::spawn(async move {
            if let Some(why) = cut.wait().await {
                let _ = handle.disconnect(russh::Disconnect::ByApplication, why, "fr".into()).await;
            }
        });
        *slot = Some(nav.clone());
        Ok(nav)
    }

    fn watch(&self, target: &Target, recorded: bool, session: Uuid) -> (live::Guard, Cut) {
        self.state.live.watch(Watched { user: self.user.id, login: &self.user.login, target: Some(target), web: false, recorded, session: Some(session), portal: None })
    }
}

fn split_login(requested: &str) -> (&str, Option<&str>) {
    match requested.split_once('%') {
        Some((login, target)) if !target.is_empty() => (login, Some(target)),
        _ => (requested.trim_end_matches('%'), None),
    }
}

fn ki_prompt(text: &str, echo: bool) -> Auth {
    Auth::Partial {
        name: Cow::Borrowed("Portunia Gate"),
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

    /// Compte un essai avant de le vérifier ; faux si les essais sont épuisés.
    async fn attempt(&self, requested: &str, method: &str) -> bool {
        let (login, _) = split_login(requested);
        match self.state.limits.attempt(login, &self.addr) {
            Verdict::Allowed => true,
            Verdict::Blocked { first } => {
                if first {
                    audit::note(&self.state.db, login, "auth.bloquee", json!({ "methode": method, "adresse": self.addr })).await;
                }
                false
            }
        }
    }

    fn forgive(&self, requested: &str) {
        self.state.limits.forgive(split_login(requested).0, &self.addr);
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
            self.state.limits.success(split_login(&self.requested).0, &self.addr);
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
            .unwrap_or_else(|| default_banner().to_string());
        Ok(Some(format!("{text}\r\n")))
    }

    async fn auth_password(&mut self, requested: &str, password: &str) -> Result<Auth, Self::Error> {
        let Some(user) = self.load(requested).await? else {
            if self.attempt(requested, "mot de passe").await {
                crate::auth::burn_password(password.to_string()).await;
                self.fail("mot de passe", "compte inconnu ou désactivé").await;
            }
            return Ok(Auth::reject());
        };
        // Jeton à usage unique remis par l'API à Portunia, pour ce compte et ce serveur :
        // aucun calcul à faire, il ne compte comme essai que s'il est refusé.
        if password.starts_with("hj1_") {
            let (_, wanted) = split_login(requested);
            let target = match wanted {
                Some(name) => model::target_by_name(&self.state.db, name).await?.map(|t| t.id),
                None => None,
            };
            if let Some(real) = crate::api::consume_ticket(&self.state.db, password, user.id, target).await? {
                // Portail web : la connexion vient de la Gate lui-même, l'adresse utile est celle du navigateur.
                let via = if real.is_empty() { "jeton Portunia" } else { "portail web" };
                if !real.is_empty() {
                    self.addr = real;
                }
                audit::note(
                    &self.state.db,
                    &user.login,
                    "auth.reussie",
                    json!({ "facteurs": [via], "adresse": self.addr }),
                )
                .await;
                self.by_ticket = true;
                return Ok(Auth::Accept);
            }
            if self.attempt(requested, "jeton").await {
                self.fail("jeton", "jeton invalide, expiré ou déjà utilisé").await;
            }
            return Ok(Auth::reject());
        }
        let policy = user.policy(&self.state.db).await?;
        if !policy.could_use(&self.factors, Factor::Password) {
            return Ok(Auth::reject());
        }
        if !self.attempt(requested, "mot de passe").await {
            return Ok(Auth::reject());
        }
        if !check_password(user.password_hash.clone(), password.to_string()).await {
            self.fail("mot de passe", "mot de passe incorrect").await;
            return Ok(Auth::reject());
        }
        if user.must_change_password {
            self.fail("mot de passe", "mot de passe provisoire à changer (Portunia ou portunia-gate user passwd)").await;
            return Ok(Auth::reject());
        }
        self.forgive(requested);
        self.factors.insert(Factor::Password);
        self.decide(&user).await
    }

    async fn auth_publickey_offered(&mut self, requested: &str, offer: server::PublicKeyOffer<'_>) -> Result<Auth, Self::Error> {
        let Some(user) = self.load(requested).await? else {
            return Ok(Auth::reject());
        };
        let fingerprint = offer.public_key.fingerprint(HashAlg::Sha256).to_string();
        let owned = model::user_key_owner(&self.state.db, &fingerprint).await? == Some(user.id);
        let usable = user.policy(&self.state.db).await?.could_use(&self.factors, Factor::Key);
        Ok(if owned && usable { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, requested: &str, verified: server::VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        let Some(user) = self.load(requested).await? else {
            return Ok(Auth::reject());
        };
        let fingerprint = verified.public_key.fingerprint(HashAlg::Sha256).to_string();
        if model::user_key_owner(&self.state.db, &fingerprint).await? != Some(user.id) {
            if self.attempt(requested, "clé").await {
                self.fail("clé", "clé inconnue").await;
            }
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
            if self.attempt(requested, "clavier").await {
                self.fail("clavier", "compte inconnu ou désactivé").await;
            }
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
                    Ok(ki_prompt(t!("Password: ", "Mot de passe : "), false))
                } else if policy.could_use(&self.factors, Factor::Totp) && user.totp_secret.is_some() {
                    self.ki = KiStage::Totp;
                    Ok(ki_prompt(t!("Authentication code: ", "Code d'authentification : "), true))
                } else {
                    Ok(Auth::reject())
                }
            }
            (KiStage::Password, Some(password)) => {
                if !self.attempt(requested, "mot de passe").await {
                    self.ki = KiStage::Start;
                    return Ok(Auth::reject());
                }
                if !check_password(user.password_hash.clone(), password).await {
                    self.fail("mot de passe", "mot de passe incorrect").await;
                    self.ki = KiStage::Start;
                    return Ok(Auth::reject());
                }
                // Mot de passe provisoire : il se change dans Portunia, pas en SSH.
                if user.must_change_password {
                    self.fail("mot de passe", "mot de passe provisoire à changer (Portunia ou portunia-gate user passwd)").await;
                    self.ki = KiStage::Start;
                    return Ok(Auth::reject());
                }
                self.forgive(requested);
                self.factors.insert(Factor::Password);
                if policy.satisfied(&self.factors) {
                    return self.decide(&user).await;
                }
                if policy.could_use(&self.factors, Factor::Totp) && user.totp_secret.is_some() {
                    self.ki = KiStage::Totp;
                    return Ok(ki_prompt(t!("Authentication code: ", "Code d'authentification : "), true));
                }
                Ok(Auth::reject())
            }
            (KiStage::Totp, Some(code)) => {
                if !self.attempt(requested, "code").await {
                    return Ok(Auth::reject());
                }
                if !self.check_totp(&user, &code).await? {
                    self.fail("code", "code incorrect ou déjà utilisé").await;
                    // On reste sur le code : une nouvelle tentative le redemande.
                    return Ok(Auth::reject());
                }
                self.forgive(requested);
                self.factors.insert(Factor::Totp);
                self.decide(&user).await
            }
        }
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        let Some(user) = self.user.clone() else { return Ok(()) };
        self.authenticated.store(true, Ordering::SeqCst);
        self.slot = None;
        // Compte désactivé ou supprimé : la connexion entière se ferme.
        let (guard, mut cut) = self.state.live.watch(Watched { user: user.id, login: &user.login, target: None, web: false, recorded: false, session: None, portal: None });
        self.watch = Some(guard);
        let handle = session.handle();
        tokio::spawn(async move {
            if let Some(why) = cut.wait().await {
                let _ = handle.disconnect(russh::Disconnect::ByApplication, why, "fr".into()).await;
            }
        });
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
            by_ticket: self.by_ticket,
            navigation: tokio::sync::Mutex::new(None),
        }));
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let ctx = match self.ctx.clone() {
            Some(ctx) if ctx.active().await? => ctx,
            _ => {
                reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
                return Ok(());
            }
        };
        reply.accept().await;
        tokio::spawn(async move {
            if let Err(e) = run_channel(ctx, channel).await {
                tracing::warn!("session: {e:#}");
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
        let current = match &self.ctx {
            Some(ctx) => ctx.current().await?,
            None => None,
        };
        let allowed = current.is_some_and(|(t, access)| (access.sftp || !is_file_copy(&command)) && t.vaulted());
        if allowed {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        let current = match &self.ctx {
            Some(ctx) if name == "sftp" => ctx.current().await?,
            _ => None,
        };
        let allowed = current.is_some_and(|(t, access)| access.sftp && t.vaulted());
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let ctx = match self.ctx.clone() {
            Some(ctx) if ctx.active().await? => ctx,
            _ => {
                reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
                return Ok(());
            }
        };
        let db = &self.state.db;
        let current = ctx.current().await?;
        // 0. Sortie web (« login%sortie ») : la cible filtre les sites, la Gate résout et relaie.
        if let Some((t, _)) = current.as_ref().filter(|(t, _)| t.is_egress()) {
            let nav = match ctx.navigation(t, session.handle()).await {
                Ok(nav) if nav.closed().is_none() => nav,
                _ => {
                    reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
                    return Ok(());
                }
            };
            let site = host.trim_end_matches('.').to_ascii_lowercase();
            if let Some(why) = egress::refusal(t, &site, port) {
                nav.refused(&site, port, why).await;
                reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
                return Ok(());
            }
            let Some(opened) = nav.enter(&site) else {
                reply.reject(ChannelOpenFailure::ResourceShortage).await;
                return Ok(());
            };
            tokio::spawn(relay_egress(nav, opened, channel, reply, site, port as u16));
            return Ok(());
        }
        // 1. Rebond de bout en bout (ssh -J) vers une cible en mode rebond.
        for t in model::rebond_targets_at(db, host, port as i32).await? {
            if ctx.by_ticket && ctx.target.as_ref().map(|(own, _)| own.id) != Some(t.id) {
                continue;
            }
            if model::access(db, ctx.user.id, t.id).await?.is_some() {
                reply.accept().await;
                tokio::spawn(async move {
                    if let Err(e) = relay_tcp(ctx, t, channel).await {
                        tracing::warn!("{} {e:#}", t!("jump:", "rebond :"));
                    }
                });
                return Ok(());
            }
        }
        // 2. Tunnel (ssh -L) à travers une cible du coffre, si la règle l'autorise.
        if let Some((t, access)) = current {
            if access.tunnels && t.vaulted() {
                reply.accept().await;
                let (host, origin) = (host.to_string(), origin.to_string());
                tokio::spawn(async move {
                    if let Err(e) = relay_tunnel(ctx, t, channel, host, port, origin, origin_port).await {
                        tracing::warn!("tunnel: {e:#}");
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

/// Copie de fichiers côté serveur et rien d'autre : « scp -t/-f », « rsync --server » ou
/// « sftp-server », sans aucun caractère que le shell de la cible interpréterait. Seule une telle
/// commande n'est pas enregistrée (A5) : « rsync x; bash -i » l'est, comme toute commande.
fn pure_file_copy(command: &str) -> bool {
    const SHELL: &str = ";&|`$<>()\\{}*?![]#~'\"";
    if command.chars().any(|c| SHELL.contains(c) || c.is_control()) {
        return false;
    }
    let words: Vec<&str> = command.split_whitespace().collect();
    let Some(first) = words.first() else { return false };
    match first.rsplit('/').next().unwrap_or("") {
        "scp" => words[1..].iter().any(|w| w.starts_with('-') && (w.contains('t') || w.contains('f'))),
        "rsync" => words.get(1) == Some(&"--server"),
        "sftp-server" => words.len() == 1,
        _ => false,
    }
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
    // Les serveurs Bureau à distance s'ouvrent depuis Portunia, pas dans ce terminal.
    let targets: Vec<Target> = model::allowed_targets(&ctx.state.db, ctx.user.id).await?.into_iter().filter(|t| t.is_ssh()).collect();
    let name = model::setting(&ctx.state.db, "nom")
        .await?
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "Portunia Gate".into());
    if targets.is_empty() {
        say(
            channel,
            &t!(
                format!("\n  {name} · hello {}\n  No server is allowed for you at the moment.\n\n", ctx.user.login),
                format!("\n  {name} · bonjour {}\n  Aucun serveur ne vous est autorisé en ce moment.\n\n", ctx.user.login)
            ),
        )
        .await;
        return Ok(None);
    }
    let width = targets.iter().map(|t| t.name.chars().count()).max().unwrap_or(0);
    let mut text = t!(
        format!("\n  {name} · hello {}\n  Allowed servers:\n", ctx.user.login),
        format!("\n  {name} · bonjour {}\n  Serveurs autorisés :\n", ctx.user.login)
    );
    for (i, t) in targets.iter().enumerate() {
        let mode = match t.mode.as_str() {
            "coffre" => t!("vault", "coffre"),
            "enregistre" => t!("recorded", "enregistré"),
            _ => t!("jump", "rebond"),
        };
        text.push_str(&format!("    {:>2}  {:<width$}  {:<14}  {mode}\n", i + 1, t.name, t.folder));
    }
    say(channel, &text).await;
    for _ in 0..3 {
        say(channel, t!("  Your choice (number or name): ", "  Votre choix (numéro ou nom) : ")).await;
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
            None => say(channel, t!("  Unknown choice.\n", "  Choix inconnu.\n")).await,
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
            say(&channel, &t!(format!("Unknown or not allowed server: {name}\n"), format!("Serveur inconnu ou non autorisé : {name}\n"))).await;
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
    // Compte, serveur et droits sont relus au moment d'ouvrir : un retrait s'applique tout de suite.
    let opening = if ctx.active().await? {
        match model::target_by_id(db, target.id).await? {
            Some(fresh) => model::access(db, ctx.user.id, fresh.id).await?.map(|access| (fresh, access)),
            None => None,
        }
    } else {
        None
    };
    let Some((target, access)) = opening else {
        audit::note(
            db,
            &login,
            "acces.refuse",
            json!({ "cible": target.name, "raison": "aucune règle active", "adresse": ctx.addr }),
        )
        .await;
        say(&channel, &t!(format!("Unknown or not allowed server: {}\n", target.name), format!("Serveur inconnu ou non autorisé : {}\n", target.name))).await;
        close(&channel, 1).await;
        return Ok(());
    };
    if !target.is_ssh() {
        say(&channel, &t!(format!("{} is not an SSH server: open it from Portunia or the web portal.\n", target.name), format!("{} n'est pas un serveur SSH : ouvrez-le depuis Portunia ou le portail web.\n", target.name))).await;
        close(&channel, 1).await;
        return Ok(());
    }
    if target.records() && !live::can_record(&ctx.state) {
        audit::note(db, &login, "enregistrement.echec", json!({ "cible": target.name, "raison": "espace disque insuffisant", "adresse": ctx.addr })).await;
        say(&channel, &format!("{}\n", live::no_space_message())).await;
        close(&channel, 1).await;
        return Ok(());
    }

    say(&channel, &t!(format!("Connecting to {}…\n", target.name), format!("Connexion à {}…\n", target.name))).await;
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
    let mut recorder = None;
    if target.records() {
        say(&channel, t!("Portunia Gate: session recorded.\n", "Portunia Gate : session enregistrée.\n")).await;
        match Recorder::create(&ctx.state.config.recordings_dir(), id, p.cols, p.rows, &format!("{login} → {detail}"), access.record_input) {
            Ok(r) => {
                // Fichier connu dès l'ouverture : la session se suit en direct depuis l'Audit.
                model::session_recording(db, id, &r.path()).await?;
                recorder = Some(r)
            }
            Err(e) => {
                refuse_unrecorded(&ctx, id, &target.name, &e, &channel).await;
                let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
                return Ok(());
            }
        }
    }
    let (_watch, mut cut) = ctx.watch(&target, recorder.is_some(), id);
    let started = std::time::Instant::now();
    let (status, ended) = pump(&mut channel, remote, recorder.as_mut(), &mut cut).await;
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
    finish(&ctx, id, recorder, started, &target.name).await;
    end_session(&channel, status, ended).await;
    Ok(())
}

/// Enregistrement impossible : la session ne commence pas.
async fn refuse_unrecorded(ctx: &Ctx, id: Uuid, target: &str, error: &anyhow::Error, channel: &Channel<Msg>) {
    audit::note(&ctx.state.db, &ctx.user.login, "enregistrement.echec", json!({ "session": id, "cible": target, "raison": error.to_string(), "adresse": ctx.addr })).await;
    let done = model::Finished { recording: None, sha256: None, signature: None, bytes: 0 };
    if let Err(e) = model::session_end(&ctx.state.db, id, done).await {
        tracing::error!("{} {id}: {e:#}", t!("end of session", "fin de session"));
    }
    say(channel, t!("Recording is impossible: session refused. Tell an administrator.\n", "Enregistrement impossible : session refusée. Prévenez un administrateur.\n")).await;
    close(channel, 1).await;
}

/// Fin de session côté utilisateur, avec la raison si la Gate l'a fermée.
async fn end_session(channel: &Channel<Msg>, status: Option<u32>, ended: Option<String>) {
    if let Some(why) = &ended {
        say(channel, &format!("\r\n{why}\n")).await;
    }
    close(channel, status.unwrap_or(if ended.is_some() { 1 } else { 0 })).await;
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
                    t!("The vault account was refused by the server. Tell an administrator.\n", "Le compte du coffre a été refusé par le serveur. Prévenez un administrateur.\n"),
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
            say(channel, &t!(format!("Login on {}: ", target.name), format!("Identifiant sur {} : ", target.name))).await;
            match read_line(channel, true, pty).await {
                Some(a) if !a.is_empty() => a,
                _ => return Ok(None),
            }
        }
    };
    for attempt in 0..3 {
        say(channel, &t!(format!("Password for {account}@{}: ", target.name), format!("Mot de passe de {account}@{} : ", target.name))).await;
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
                say(channel, t!("Access denied.\n", "Accès refusé.\n")).await;
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
/// Renvoie aussi la raison si la Gate a fermé la session (accès retiré, enregistrement impossible).
async fn pump(user: &mut Channel<Msg>, mut remote: Channel<russh::client::Msg>, mut rec: Option<&mut Recorder>, cut: &mut Cut) -> (Option<u32>, Option<String>) {
    let mut status = None;
    let mut ended = None;
    let mut notices = cut.notices();
    loop {
        if rec.as_deref().is_some_and(Recorder::failed) {
            ended = Some(t!("Recording failed: session closed. Tell an administrator.", "Enregistrement impossible : session fermée. Prévenez un administrateur.").to_string());
            break;
        }
        tokio::select! {
            why = cut.reason() => {
                ended = Some(why);
                break;
            }
            // Session suivie en direct (réglage live_notice) : dit à l'utilisateur, pas enregistré.
            text = notices.next() => {
                let _ = user.data_bytes(format!("\r\n\x1b[1;33m{text}\x1b[0m\r\n").into_bytes()).await;
            }
            msg = user.wait() => match msg {
                Some(ChannelMsg::Data { data }) => {
                    if let Some(r) = rec.as_deref_mut() { r.input(&data); r.flush(); }
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
    (status, ended)
}

async fn finish(ctx: &Ctx, id: Uuid, recorder: Option<Recorder>, started: std::time::Instant, target: &str) {
    let mut done = model::Finished {
        recording: None,
        sha256: None,
        signature: None,
        bytes: 0,
    };
    let mut index = None;
    if let Some(rec) = recorder {
        let with_input = rec.records_input();
        if rec.failed() {
            tracing::error!("{} {id}", t!("incomplete recording, session closed:", "enregistrement incomplet, session fermée :"));
            audit::note(&ctx.state.db, &ctx.user.login, "enregistrement.echec", json!({ "session": id, "cible": target, "raison": "écriture impossible" })).await;
        }
        match rec.finish(&ctx.state.keys, id) {
            Ok((path, sha, sig, bytes)) => {
                index = Some((path.clone(), with_input));
                done = model::Finished {
                    recording: Some(path),
                    sha256: Some(sha),
                    signature: Some(sig),
                    bytes: bytes as i64,
                };
            }
            Err(e) => tracing::error!("{} {id}: {e:#}", t!("recording", "enregistrement")),
        }
    }
    let bytes = done.bytes;
    if let Err(e) = model::session_end(&ctx.state.db, id, done).await {
        tracing::error!("{} {id}: {e:#}", t!("end of session", "fin de session"));
    }
    // Texte de la session pour la recherche de l'audit (saisies masquées exclues).
    if let Some((path, with_input)) = index {
        let text = tokio::task::spawn_blocking(move || std::fs::read_to_string(path).map(|c| crate::replay::Cast::parse(&c).search_text())).await;
        match text {
            Ok(Ok(text)) => {
                if let Err(e) = model::session_index(&ctx.state.db, id, with_input, &text).await {
                    tracing::error!("{} {id}: {e:#}", t!("session index", "index de la session"));
                }
            }
            Ok(Err(e)) => tracing::error!("{} {id}: {e}", t!("session index", "index de la session")),
            Err(e) => tracing::error!("{} {id}: {e}", t!("session index", "index de la session")),
        }
    }
    audit::note(
        &ctx.state.db,
        &ctx.user.login,
        "session.fermee",
        json!({ "session": id, "cible": target, "duree_s": started.elapsed().as_secs(), "octets": bytes }),
    )
    .await;
}

/// Commande unique (ssh login%cible@Gate "commande"), cibles du coffre.
async fn exec(ctx: Arc<Ctx>, mut channel: Channel<Msg>, pty: Option<PtyInfo>, command: String) -> Result<()> {
    let Some((target, access)) = ctx.current().await? else {
        say(&channel, t!("Give the server in the name: user%server@gate\n", "Indiquez le serveur dans le nom : utilisateur%serveur@gate\n")).await;
        close(&channel, 1).await;
        return Ok(());
    };
    if !target.vaulted() || (is_file_copy(&command) && !access.sftp) {
        close(&channel, 1).await;
        return Ok(());
    }
    let recorded = target.records() && !pure_file_copy(&command);
    if recorded && !live::can_record(&ctx.state) {
        audit::note(&ctx.state.db, &ctx.user.login, "enregistrement.echec", json!({ "cible": target.name, "raison": "espace disque insuffisant", "adresse": ctx.addr })).await;
        say(&channel, &format!("{}\n", live::no_space_message())).await;
        close(&channel, 1).await;
        return Ok(());
    }
    let creds = target::vault_credentials(&ctx.state, &target)?;
    let handle = match target::connect(&ctx.state, &target, &creds, &ctx.user.login).await {
        Ok(h) => h,
        Err(_) => {
            say(&channel, &t!(format!("Cannot connect to {}.\n", target.name), format!("Connexion à {} impossible.\n", target.name))).await;
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
    let mut recorder = None;
    if recorded {
        match Recorder::create(&ctx.state.config.recordings_dir(), id, cols, rows, &format!("{} → {}: {command}", ctx.user.login, target.name), access.record_input) {
            Ok(r) => {
                model::session_recording(&ctx.state.db, id, &r.path()).await?;
                recorder = Some(r)
            }
            Err(e) => {
                refuse_unrecorded(&ctx, id, &target.name, &e, &channel).await;
                let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
                return Ok(());
            }
        }
    }
    let (_watch, mut cut) = ctx.watch(&target, recorder.is_some(), id);
    let started = std::time::Instant::now();
    let (status, ended) = pump(&mut channel, remote, recorder.as_mut(), &mut cut).await;
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
    finish(&ctx, id, recorder, started, &target.name).await;
    end_session(&channel, status, ended).await;
    Ok(())
}

/// SFTP vers une cible du coffre : les échanges sont relayés et la session journalisée.
async fn sftp(ctx: Arc<Ctx>, mut channel: Channel<Msg>, name: String) -> Result<()> {
    let Some((target, access)) = ctx.current().await? else {
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
    let (_watch, mut cut) = ctx.watch(&target, false, id);
    let started = std::time::Instant::now();
    let (status, ended) = pump(&mut channel, remote, None, &mut cut).await;
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "fr").await;
    finish(&ctx, id, None, started, &target.name).await;
    close(&channel, status.unwrap_or(if ended.is_some() { 1 } else { 0 })).await;
    Ok(())
}

/// Relaie dans les deux sens jusqu'à la fin de l'un des côtés ; renvoie les octets passés
/// dans chaque sens, même si la connexion se termine sur une erreur (un serveur Windows
/// coupe brutalement après un refus d'identifiants). Une fermeture par la Gate ne compte pas les octets.
async fn relay_counted<A, B>(a: A, b: B, cut: &mut Cut) -> (u64, u64)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn pump<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(mut from: R, mut to: W) -> u64 {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total = 0;
        while let Ok(n) = from.read(&mut buf).await {
            if n == 0 || to.write_all(&buf[..n]).await.is_err() {
                break;
            }
            total += n as u64;
        }
        let _ = to.shutdown().await;
        total
    }
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    // Le premier sens qui se termine arrête l'autre : la session est finie.
    let up = pump(ar, bw);
    let down = pump(br, aw);
    tokio::pin!(up, down);
    tokio::select! {
        u = &mut up => (u, tokio::time::timeout(std::time::Duration::from_secs(2), &mut down).await.unwrap_or(0)),
        d = &mut down => (tokio::time::timeout(std::time::Duration::from_secs(2), &mut up).await.unwrap_or(0), d),
        _ = cut.reason() => (0, 0),
    }
}

/// Sortie web : résolution sur la Gate (adresses internes refusées), connexion, puis relais
/// jusqu'à la fin ou la coupure. Le canal n'est accepté qu'une fois le site joint : le
/// navigateur reçoit un vrai refus sinon.
async fn relay_egress(nav: Arc<egress::Navigation>, opened: egress::Opened, channel: Channel<Msg>, reply: ChannelOpenHandle, site: String, port: u16) {
    let addresses = match egress::resolve(&site, port).await {
        Ok(a) => a,
        Err(why) => {
            nav.refused(&site, port as u32, why).await;
            reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return;
        }
    };
    let tcp = match egress::connect(&addresses).await {
        Ok(tcp) => tcp,
        Err(_) => {
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return;
        }
    };
    reply.accept().await;
    let mut cut = nav.cut();
    let (up, down) = relay_counted(channel.into_stream(), tcp, &mut cut).await;
    opened.done(up + down);
}

/// Rebond de bout en bout : la Gate relaie les octets chiffrés sans les lire.
async fn relay_tcp(ctx: Arc<Ctx>, target: Target, channel: Channel<Msg>) -> Result<()> {
    let id = Uuid::new_v4();
    let db = &ctx.state.db;
    let connect = async {
        let address = crate::target::addresses(&target.host, target.port as u16).await?;
        tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(&address[..]))
            .await
            .map_err(|_| anyhow::anyhow!(t!(format!("{} unreachable (timed out)", target.name), format!("{} injoignable (délai dépassé)", target.name))))?
            .map_err(anyhow::Error::from)
    };
    // Cible refusée ou injoignable : le canal se ferme tout de suite, le client n'attend pas.
    let tcp = match connect.await {
        Ok(tcp) => tcp,
        Err(e) => {
            let _ = channel.close().await;
            return Err(e);
        }
    };
    let detail = if target.is_rdp() { "rdp" } else { "ssh -J" };
    model::session_start(db, id, ctx.user.id, target.id, "rebond", detail, &ctx.addr).await?;
    audit::note(
        db,
        &ctx.user.login,
        "rebond.ouvert",
        json!({ "session": id, "cible": target.name, "protocole": target.protocole, "adresse": ctx.addr }),
    )
    .await;
    let started = std::time::Instant::now();
    let (_watch, mut cut) = ctx.watch(&target, false, id);
    let (up, down) = relay_counted(channel.into_stream(), tcp, &mut cut).await;
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
        Err(ConnectError::Refused) => anyhow::bail!(t!(format!("vault account refused by {}", target.name), format!("compte du coffre refusé par {}", target.name))),
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
    let (_watch, mut cut) = ctx.watch(&target, false, id);
    let (mut a, mut b) = (channel.into_stream(), remote.into_stream());
    let (up, down) = tokio::select! {
        copied = tokio::io::copy_bidirectional(&mut a, &mut b) => copied.unwrap_or((0, 0)),
        _ = cut.reason() => (0, 0),
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Nobody;
    impl server::Handler for Nobody {
        type Error = anyhow::Error;
    }

    #[test]
    fn copie_pure_ou_commande_enregistree() {
        for ok in ["scp -t /tmp", "scp -f fichier.txt", "/usr/bin/scp -r -t dossier", "rsync --server -vlogDtpre.iLsfxCIvu . /srv/x", "sftp-server", "/usr/lib/openssh/sftp-server"] {
            assert!(pure_file_copy(ok), "{ok}");
        }
        for bad in [
            "rsync x; bash -i", "rsync --version & whoami", "rsync --server . /x | sh", "scp -t /tmp && id", "scp -t $(id)", "scp -t `id`",
            "rsync --server .\nbash", "scp /etc/passwd", "rsync -av a b", "sftp-server -l DEBUG3", "bash -c 'rsync'", "scp -t > /etc/x", "",
        ] {
            assert!(!pure_file_copy(bad), "{bad:?}");
        }
        // Le droit SFTP reste demandé pour tout ce qui commence par une copie.
        assert!(is_file_copy("rsync x; bash -i"));
    }

    /// Lance `serve` avec une limite d'une seconde et renvoie le côté client.
    async fn connection() -> tokio::net::TcpStream {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(address).await.unwrap();
        let (tcp, _) = listener.accept().await.unwrap();
        let key = russh::keys::PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[1; 32]));
        let config = Arc::new(server::Config { keys: vec![key], ..Default::default() });
        tokio::spawn(serve(config, tcp, Nobody, Arc::new(AtomicBool::new(false)), Duration::from_secs(1)));
        client
    }

    /// Lit jusqu'à la fermeture ; faux si la connexion reste ouverte.
    async fn closes(client: &mut tokio::net::TcpStream) -> bool {
        let mut buf = [0u8; 4096];
        let end = async {
            loop {
                match client.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), end).await.is_ok()
    }

    #[tokio::test]
    async fn connexion_muette_fermee() {
        let mut client = connection().await;
        assert!(closes(&mut client).await);
    }

    #[tokio::test]
    async fn connexion_sans_authentification_fermee() {
        let mut client = connection().await;
        client.write_all(b"SSH-2.0-essai\r\n").await.unwrap();
        assert!(closes(&mut client).await);
    }
}
