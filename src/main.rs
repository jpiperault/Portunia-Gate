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
mod cfaccess;
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
mod rdpclip;
mod rdpnative;
mod rdplogin;
mod recording;
mod replay;
mod sshd;
mod target;
mod tls;
mod tunnel;
mod webproxy;
mod approval;
mod notify;
mod status;
mod update;
mod webvault;
mod websession;

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
        /// Only events whose account, name or detail contains this text.
        #[arg(long)]
        search: Option<String>,
        /// Writes the events to a CSV file (spreadsheet), up to 5000 with --last.
        #[arg(long, value_name = "FILE")]
        csv: Option<PathBuf>,
    },
    /// Sessions, newest first; « sessions show ID » for one session and its recording.
    #[command(args_conflicts_with_subcommands = true)]
    Sessions {
        #[command(subcommand)]
        cmd: Option<SessionsCmd>,
        #[arg(long, default_value_t = 30)]
        last: i64,
        /// Account.
        #[arg(long)]
        user: Option<String>,
        /// Server.
        #[arg(long)]
        server: Option<String>,
        /// From this day (YYYY-MM-DD).
        #[arg(long)]
        since: Option<String>,
        /// Up to this day included (YYYY-MM-DD).
        #[arg(long)]
        until: Option<String>,
        /// Text shown on screen or typed during the session.
        #[arg(long)]
        text: Option<String>,
        /// Only sessions whose keystrokes are recorded.
        #[arg(long)]
        input: bool,
        /// Only Remote Desktop sessions where files were copied.
        #[arg(long)]
        files: bool,
    },
    /// Server hardening state, as noted by the installer every 15 minutes.
    Hardening,
    /// Web portal.
    #[command(subcommand)]
    Portal(PortalCmd),
    /// Remote assistance (Portunia Assistance relay).
    #[command(subcommand)]
    Assist(AssistCmd),
    /// Native RDP entry: mstsc, Remmina, FreeRDP or Windows App with a single-use .rdp file from Portunia.
    #[command(subcommand)]
    Rdp(RdpCmd),
    /// Notifications: e-mail (SMTP), Microsoft Teams and signed JSON webhook (approval, alerts).
    #[command(subcommand)]
    Notify(NotifyCmd),
    /// Access approval: requests waiting, grant, refuse, withdraw.
    #[command(subcommand)]
    Approval(ApprovalCmd),
    /// Dedicated relay: this machine publishes the web portal of a Gate.
    #[command(subcommand)]
    Edge(EdgeCmd),
    /// Gate status: health, hardware, services, storage, activity, update.
    Status {
        /// Full report in JSON.
        #[arg(long)]
        json: bool,
    },
    /// Update of the Gate (Debian package): check, apply now or at a set time, cancel.
    #[command(subcommand)]
    Update(UpdateCmd),
    /// General settings; without a name, lists them all.
    Setting {
        /// auth_policy, banner, name, language, session_hours, remember_password, own_replay, live_notice, sensitive_commands, file_copies_mb or recording_days.
        key: Option<String>,
        /// New value; without a value, shows the current one.
        value: Option<String>,
    },
}

#[derive(Subcommand)]
enum SessionsCmd {
    /// One session: account, server, times, recording file and its signature check.
    Show {
        /// Identifier, or its first characters as listed by « sessions ».
        id: String,
    },
    /// Cuts an open session (within 30 seconds); --disable also disables the account.
    Cut {
        /// Identifier, or its first characters as listed by « sessions ».
        id: String,
        /// Also disable the account.
        #[arg(long)]
        disable: bool,
    },
}

#[derive(Subcommand)]
enum PortalCmd {
    /// Shows the portal: state, settings and how it is exposed.
    Show,
    /// Opens the portal to browsers.
    On,
    /// Closes the portal; open web sessions close within 30 seconds.
    Off,
    /// Portal settings; what is not given stays as it is.
    Set {
        /// Public address (https://…); empty: none (the host asked by the browser).
        #[arg(long)]
        url: Option<String>,
        /// Group whose members may sign in.
        #[arg(long)]
        group: Option<String>,
        /// Web session duration in hours (1 to 12).
        #[arg(long)]
        duration: Option<i64>,
        /// Closing after inactivity, in minutes (5 to 240).
        #[arg(long)]
        idle: Option<i64>,
        /// Copy-paste in the web terminal: on or off.
        #[arg(long, value_parser = parse_switch)]
        clipboard: Option<bool>,
        /// Authenticator code on the portal: on, or off (still required by accounts whose own combinations demand it).
        #[arg(long, value_parser = parse_switch)]
        code: Option<bool>,
        /// Turnstile site key; empty: Turnstile off.
        #[arg(long)]
        turnstile_site: Option<String>,
        /// Asks the Turnstile secret key (empty entry: erases it).
        #[arg(long)]
        turnstile_secret: bool,
        /// Address of the internal entry (https://…); empty: the host asked by the browser.
        #[arg(long)]
        internal_url: Option<String>,
        /// Authenticator code on the internal entry: on, or off (accounts' own combinations still apply).
        #[arg(long, value_parser = parse_switch)]
        internal_code: Option<bool>,
    },
    /// Closes all web sessions without closing the portal (within 30 seconds).
    CloseSessions,
    /// Checks that this Gate answers at the portal's public address.
    Test,
    /// Let's Encrypt certificate of the HTTPS listener; without options, shows its state.
    Acme {
        /// Domain names, comma-separated.
        #[arg(long, value_delimiter = ',')]
        domains: Option<Vec<String>>,
        /// Contact address for Let's Encrypt (expiry notices).
        #[arg(long)]
        email: Option<String>,
        /// tls-alpn (HTTPS listener reachable on 443) or dns-cloudflare (Cloudflare API token).
        #[arg(long)]
        method: Option<String>,
        /// Test authority (certificates not trusted by browsers): on or off.
        #[arg(long, value_parser = parse_switch)]
        staging: Option<bool>,
        /// Asks the Cloudflare API token (Zone › DNS › Edit) for dns-cloudflare; empty entry: erases it.
        #[arg(long)]
        cloudflare_token: bool,
        /// Accepts the Let's Encrypt Subscriber Agreement (needed to turn it on).
        #[arg(long)]
        accept_terms: bool,
        /// Turns Let's Encrypt off (the current certificate stays until replaced).
        #[arg(long, conflicts_with_all = ["domains", "renew"])]
        off: bool,
        /// Renews the certificate now.
        #[arg(long)]
        renew: bool,
    },
    /// Changes how browsers reach the portal; what is not given stays as it is.
    Expose {
        /// External entry: cloudflare, direct, proxy or relay; internal: no external entry.
        mode: Option<String>,
        /// Internal entry (company network), open as well as the external one: on or off.
        #[arg(long, value_parser = parse_switch)]
        internal: Option<bool>,
        /// Internal entry: allowed networks, comma-separated (empty: private networks).
        #[arg(long)]
        internal_networks: Option<String>,
        /// Proxy mode: trusted proxies, comma-separated addresses or networks.
        #[arg(long)]
        trusted: Option<String>,
        /// Proxy mode: header holding the visitor's address.
        #[arg(long)]
        header: Option<String>,
        /// Direct mode: allowed networks, comma-separated (empty: everyone).
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
    /// Access from outside through Cloudflare in TCP (cloudflared on the workstation): host names of
    /// the API, SSH and native RDP; without options, shows them. Empty value: nothing for that service.
    Tcp {
        #[arg(long)]
        api: Option<String>,
        #[arg(long)]
        ssh: Option<String>,
        #[arg(long)]
        rdp: Option<String>,
        /// Also publishes them in the Gate's tunnel and the DNS: asks a Cloudflare API token (not kept).
        #[arg(long)]
        publish: bool,
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
    /// Accepted sign-in combinations, e.g. "key+totp"; "" goes back to the global setting.
    Policy { login: String, policy: String },
    /// New temporary password, shown once: the user chooses theirs at the next sign-in in Portunia. Closes their sessions.
    ResetPassword { login: String },
    /// Erases the TOTP code: a new one is enrolled at the next sign-in in Portunia, or with « user totp ». Closes their sessions.
    ResetCode { login: String },
    /// RDP password for an ordinary RDP client without Portunia (mstsc, user « login%server »): a new one, shown once, or --remove.
    RdpPassword {
        login: String,
        /// Removes it: the account can no longer connect this way.
        #[arg(long)]
        remove: bool,
    },
    /// E-mail address of the account (approval and alert notifications); empty to remove it.
    Email { login: String, address: String },
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
    /// Removes accounts from a group (their open sessions close if they lose their access).
    Remove {
        group: String,
        logins: Vec<String>,
    },
    /// Lists groups and their members.
    List,
    /// Deletes a group, and the rules that give it access.
    Delete { name: String },
}

#[derive(Subcommand)]
enum TargetCmd {
    /// Adds a server.
    Add {
        name: String,
        #[arg(long)]
        host: String,
        /// Port (by default 22 for SSH, 3389 for Remote Desktop, 443 for https, 80 for http).
        #[arg(long)]
        port: Option<i32>,
        /// ssh, rdp (Remote Desktop), https or http (web interface: recorded or vault mode).
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
        /// Web interface in vault mode: auto (fills the sign-in form and submits it; HTTP authentication if the server asks), fill (fills only) or basic (HTTP authentication always).
        #[arg(long, default_value = "auto")]
        web_login: String,
        /// Text shown on the server's tile in the web portal and in Portunia (200 characters at most).
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Lists servers.
    List,
    /// Changes a server; what is not given stays as it is.
    Edit {
        name: String,
        /// New name.
        #[arg(long)]
        rename: Option<String>,
        /// New address: the remembered fingerprint is forgotten and the vault secret must be given again.
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<i32>,
        /// coffre (vault), enregistre (recorded) or rebond (jump); also vault, recorded, jump.
        #[arg(long)]
        mode: Option<String>,
        /// Account on the server; empty: none.
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        folder: Option<String>,
        /// New vault password, asked when typing.
        #[arg(long)]
        password: bool,
        /// New vault private key (OpenSSH file).
        #[arg(long)]
        key_file: Option<String>,
        /// Web interface in vault mode: auto, fill or basic.
        #[arg(long)]
        web_login: Option<String>,
        /// Text shown on the server's tile; empty: automatic text.
        #[arg(long)]
        description: Option<String>,
    },
    /// Replaces the vault secret: --password, --key-file, or --generate (SSH: the Gate creates a key and installs it).
    Secret {
        name: String,
        /// Password, asked when typing.
        #[arg(long)]
        password: bool,
        /// Private key (OpenSSH file).
        #[arg(long)]
        key_file: Option<String>,
        /// Generates a key and installs it on the server with the account's current password (asked once, then forgotten).
        #[arg(long)]
        generate: bool,
    },
    /// Forgets the remembered fingerprint (server reinstalled); the next one is remembered at the next connection.
    Forget { name: String },
    /// Deletes a server: its secret is erased, its sessions and recordings stay.
    Delete { name: String },
}

#[derive(Subcommand)]
enum RdpCmd {
    /// Shows the native RDP entry: state, port, modes and validity of the .rdp files.
    Show,
    /// Opens the native RDP entry (listening within 3 seconds).
    On,
    /// Closes the native RDP entry; sessions under way continue.
    Off,
    /// Settings of the native RDP entry; what is not given stays as it is.
    Set {
        /// Listening port (3390 by default).
        #[arg(long)]
        port: Option<u16>,
        /// Public address written in the .rdp files: host or host:port (empty: the Gate's address known to Portunia).
        #[arg(long)]
        address: Option<String>,
        /// Server modes reachable this way, comma separated: rebond, coffre, enregistre.
        #[arg(long)]
        modes: Option<String>,
        /// Validity of a .rdp file, in seconds (30 to 600).
        #[arg(long)]
        ticket_seconds: Option<i64>,
    },
    /// Prints the port if the entry is open (used by the installer for the firewall).
    #[command(hide = true)]
    Port,
}

#[derive(Subcommand)]
enum ApprovalCmd {
    /// Requests waiting and accesses granted under way.
    List,
    /// Grants a request for a duration (as the console: any request).
    Grant {
        /// Identifier, or its first characters as listed by « approval list ».
        id: String,
        /// Duration in minutes (5 to 10080).
        #[arg(long)]
        minutes: i64,
        #[arg(long, default_value = "")]
        comment: String,
    },
    /// Refuses a request.
    Deny {
        id: String,
        #[arg(long, default_value = "")]
        comment: String,
    },
    /// Withdraws a granted access (its sessions close within 30 seconds) or cancels a request.
    Revoke { id: String },
}

#[derive(Subcommand)]
enum UpdateCmd {
    /// Installed version and latest published version (checked now).
    Check,
    /// Updates the Gate: database backup, installation, automatic rollback if the new version does not start.
    Apply {
        /// Version to install (default: the latest published).
        #[arg(long)]
        version: Option<String>,
        /// When: HH:MM (today or tomorrow) or YYYY-MM-DDTHH:MM, in the Gate's time zone; default: now.
        #[arg(long)]
        at: Option<String>,
        /// Warn the connected users 5 minutes before (sessions are cut during the restart).
        #[arg(long)]
        notice: bool,
        /// Without rollback, when the package of the installed version is no longer published.
        #[arg(long)]
        no_rollback: bool,
        /// Waits for the end and shows each step.
        #[arg(long)]
        wait: bool,
    },
    /// Cancels a scheduled update.
    Cancel,
    /// Scheduled update and last run (steps, result).
    Status,
    /// Run by portunia-gate-update.service (root): carries out the requested update.
    #[command(hide = true)]
    Run,
}

#[derive(Subcommand)]
enum NotifyCmd {
    /// Shows the notification settings (secrets hidden).
    Show,
    /// Notification settings; what is not given stays as it is (empty: removed).
    Set {
        /// SMTP server (empty: no e-mail).
        #[arg(long)]
        smtp_host: Option<String>,
        /// SMTP port (587 with starttls, 465 with tls, 25).
        #[arg(long)]
        smtp_port: Option<u16>,
        /// starttls, tls or aucune.
        #[arg(long)]
        smtp_security: Option<String>,
        /// SMTP account (empty: no authentication).
        #[arg(long)]
        smtp_user: Option<String>,
        /// Asks for the SMTP password (typed, not shown).
        #[arg(long)]
        smtp_password: bool,
        /// Sender address (« Portunia Gate <gate@example.com> »).
        #[arg(long)]
        from: Option<String>,
        /// Microsoft Teams « Workflows » webhook address (empty: none).
        #[arg(long)]
        teams_url: Option<String>,
        /// JSON webhook address (empty: none).
        #[arg(long)]
        webhook_url: Option<String>,
        /// Generates a new webhook signing secret and shows it once.
        #[arg(long)]
        webhook_secret: bool,
    },
    /// Sends a test: e-mail to this address, and Teams and webhook if set.
    Test {
        /// Address receiving the test e-mail.
        email: Option<String>,
    },
}

#[derive(Subcommand)]
enum AssistCmd {
    /// Shows the assistance state and settings.
    Show,
    /// Opens assistance.
    On,
    /// Closes assistance; sessions under way stop within 30 seconds.
    Off,
    /// Assistance settings; what is not given stays as it is.
    Set {
        /// Group of the technicians.
        #[arg(long)]
        group: Option<String>,
        /// Maximum duration of an assistance, in hours (1 to 12).
        #[arg(long)]
        duration: Option<i64>,
    },
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
        /// Remote Desktop: file copy through the clipboard (logged with name, size and SHA-256).
        #[arg(long)]
        files: bool,
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
    /// Lists rules, with their state now (active, outside hours, expired).
    List,
    /// Changes a rule; what is not given stays as it is.
    Edit {
        name: String,
        /// New name.
        #[arg(long)]
        rename: Option<String>,
        #[arg(long)]
        group: Option<String>,
        /// Comma-separated servers (replace the current ones).
        #[arg(long, value_delimiter = ',')]
        targets: Option<Vec<String>>,
        /// on or off.
        #[arg(long, value_parser = parse_switch)]
        sftp: Option<bool>,
        /// on or off.
        #[arg(long, value_parser = parse_switch)]
        tunnels: Option<bool>,
        /// on or off (on: captures typed passwords).
        #[arg(long, value_parser = parse_switch)]
        record_input: Option<bool>,
        /// Remote Desktop file copy: on or off.
        #[arg(long, value_parser = parse_switch)]
        files: Option<bool>,
        /// Days: "mon-fri", "mon,wed,fri"; empty: every day.
        #[arg(long)]
        days: Option<String>,
        /// Hours: "7-20"; empty: all day.
        #[arg(long)]
        hours: Option<String>,
        /// Expiry date: YYYY-MM-DD; empty: none.
        #[arg(long)]
        expires: Option<String>,
    },
    /// Deletes a rule: sessions it allowed close within 30 seconds.
    Delete { name: String },
    /// Access only after approval (on/off), approved by a group (--approvers; empty: administrators).
    Approval {
        name: String,
        /// on or off.
        #[arg(value_parser = parse_switch, action = clap::ArgAction::Set)]
        on: bool,
        /// Group of the approvers; empty: administrators.
        #[arg(long)]
        approvers: Option<String>,
    },
}

/// Interrupteur en ligne de commande : on/off, en anglais ou en français.
fn parse_switch(text: &str) -> Result<bool, String> {
    match text.to_lowercase().as_str() {
        "on" | "yes" | "true" | "1" | "oui" => Ok(true),
        "off" | "no" | "false" | "0" | "non" => Ok(false),
        _ => Err(t!("on or off", "on ou off").to_string()),
    }
}

/// Heures « 7-20 » : début de 0 à 23, fin de 1 à 24, différentes.
fn parse_hours(text: &str) -> Result<(i16, i16)> {
    let (a, b) = text.split_once('-').ok_or_else(|| anyhow!(t!("Hours: « 7-20 »", "Heures : « 7-20 »")))?;
    let (a, b) = (a.trim().parse::<i16>()?, b.trim().parse::<i16>()?);
    if !(0..=23).contains(&a) || !(1..=24).contains(&b) || a == b {
        bail!(t!("Hours: start from 0 to 23, end from 1 to 24, different", "Heures : début de 0 à 23, fin de 1 à 24, différentes"));
    }
    Ok((a, b))
}

/// Date de fin « AAAA-MM-JJ », incluse : 23:59:59 à l'heure locale.
fn parse_expiry(text: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    let date = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d").map_err(|_| anyhow!(t!("Date: YYYY-MM-DD", "Date : AAAA-MM-JJ")))?;
    let end = date
        .and_hms_opt(23, 59, 59)
        .unwrap()
        .and_local_timezone(chrono::Local)
        .single()
        .ok_or_else(|| anyhow!(t!("ambiguous date", "date ambiguë")))?;
    Ok(end.with_timezone(&chrono::Utc))
}

/// Secret du coffre donné en ligne de commande : (type, contenu en clair).
fn console_secret(password: bool, key_file: Option<&str>) -> Result<Option<(String, Vec<u8>)>> {
    Ok(match (password, key_file) {
        (true, Some(_)) => bail!(t!("Choose --password or --key-file, not both", "Choisissez --password ou --key-file, pas les deux")),
        (true, None) => Some((
            "password".into(),
            prompt_secret(t!("Password of the account on the target: ", "Mot de passe du compte sur la cible : "))?.into_bytes(),
        )),
        (false, Some(path)) => {
            let text = std::fs::read_to_string(path).with_context(|| t!(format!("reading {path}"), format!("lecture de {path}")))?;
            russh::keys::decode_secret_key(&text, None)
                .map_err(|e| anyhow!(t!(format!("unreadable private key (without passphrase): {e}"), format!("clé privée illisible (sans phrase de passe) : {e}"))))?;
            Some(("key".into(), text.into_bytes()))
        }
        (false, None) => None,
    })
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
    // Service de mise à jour (root) : sans connexion à la base de la Gate.
    if let Command::Update(UpdateCmd::Run) = &cli.command {
        return update::run_root(&config);
    }

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
            portal::set_service();
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
            tokio::try_join!(sshd::run(state.clone()), api::run(state.clone()), portal::run(state.clone()), relay::run(state.clone()), tunnel::run(state.clone()), acme::run(state.clone()), health::run(state.clone()), live::run(state.clone()), rdpnative::run(state.clone()), websession::run(state.clone()), approval::run(state.clone()), status::run(state.clone()), update::run(state.clone()))?;
            Ok(())
        }
        Command::User(cmd) => user_cmd(&state, cmd).await,
        Command::Group(cmd) => group_cmd(&state, cmd).await,
        Command::Target(cmd) => target_cmd(&state, cmd).await,
        Command::Rule(cmd) => rule_cmd(&state, cmd).await,
        Command::Portal(cmd) => portal_cmd(&state, cmd).await,
        Command::Assist(cmd) => assist_cmd(&state, cmd).await,
        Command::Rdp(cmd) => rdp_cmd(&state, cmd).await,
        Command::Notify(cmd) => notify_cmd(&state, cmd).await,
        Command::Approval(cmd) => approval_cmd(&state, cmd).await,
        Command::Status { json } => status_cmd(&state, json).await,
        Command::Update(cmd) => update_cmd(&state, cmd).await,
        Command::Audit { verify, last, search, csv } => {
            if verify {
                match audit::verify(&state.db).await? {
                    Ok(n) => println!("{}", t!(format!("Log intact: {n} chained events."), format!("Journal intact : {n} événements chaînés."))),
                    Err(broken) => bail!(t!(format!("LOG TAMPERED WITH: {broken}"), format!("JOURNAL ALTÉRÉ : {broken}"))),
                }
            }
            let filter = search
                .as_deref()
                .map(str::trim)
                .filter(|q| !q.is_empty())
                .map(|q| format!("%{}%", q.replace(['%', '\0'], "")));
            let mut rows: Vec<audit::Entry> = sqlx::query_as(
                "SELECT * FROM audit WHERE $2::text IS NULL OR actor ILIKE $2 OR event ILIKE $2 OR detail::text ILIKE $2 ORDER BY seq DESC LIMIT $1",
            )
            .bind(last.clamp(1, 5000))
            .bind(filter)
            .fetch_all(&state.db)
            .await?;
            rows.reverse();
            if let Some(path) = csv {
                // Même format que l'export de Portunia : séparateur « ; », lisible par un tableur.
                let mut out = String::from("\u{feff}numero;date;qui;evenement;detail\n");
                for e in &rows {
                    out.push_str(&format!(
                        "{};{};{};{};{}\n",
                        e.seq,
                        api::csv_field(&e.at.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string()),
                        api::csv_field(&e.actor),
                        api::csv_field(&e.event),
                        api::csv_field(&e.detail.to_string())
                    ));
                }
                std::fs::write(&path, out).with_context(|| t!(format!("writing {}", path.display()), format!("écriture de {}", path.display())))?;
                println!("✓ {} {} ({})", rows.len(), t!("events written to", "événements écrits dans"), path.display());
                return Ok(());
            }
            for e in rows {
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
        Command::Sessions { cmd: Some(SessionsCmd::Show { id }), .. } => session_show(&state, &id).await,
        Command::Sessions { cmd: Some(SessionsCmd::Cut { id, disable }), .. } => session_cut(&state, &id, disable).await,
        Command::Sessions { cmd: None, last, user, server, since, until, text, input, files } => {
            let filter = model::AuditFilter {
                login: user,
                target: server,
                since: since.as_deref().map(|d| parse_day(d, false)).transpose()?,
                until: until.as_deref().map(|d| parse_day(d, true)).transpose()?,
                text,
                with_input: input,
                with_files: files,
                limit: last.clamp(1, 2000),
            };
            for s in model::audit_sessions(&state.db, &filter).await? {
                let end = s
                    .ended_at
                    .map(|e| e.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
                    .unwrap_or_else(|| t!("ongoing", "en cours").into());
                let mut marks = Vec::new();
                if s.recording.is_some() {
                    marks.push(t!("recorded", "enregistrée"));
                }
                if s.frappe {
                    marks.push(t!("keystrokes", "frappe"));
                }
                let copied = t!(format!("{} file(s)", s.fichiers), format!("{} fichier(s)", s.fichiers));
                if s.fichiers > 0 {
                    marks.push(&copied);
                }
                println!(
                    "{}  {}  {:<8} {:<12} {:<5} {:<10} {:<30} {:<16} {:>10} o  {}",
                    &s.id.to_string()[..8],
                    s.started_at.with_timezone(&chrono::Local).format("%d/%m %H:%M:%S"),
                    end,
                    s.login,
                    s.kind,
                    s.mode,
                    format!("{} {}", s.target, s.detail).trim(),
                    s.client_addr,
                    s.bytes,
                    marks.join(", ")
                );
            }
            Ok(())
        }
        Command::Hardening => {
            let text = std::fs::read_to_string(state.config.data_dir.join("durcissement.json")).ok();
            let r = api::hardening_report(text.as_deref().filter(|t| t.len() < 64 * 1024), chrono::Utc::now());
            if r["actif"] != json!(true) {
                println!("{}", t!("Not hardened: sudo bash installer.sh harden (« harden simulation » shows the plan).", "Pas durci : sudo bash installer.sh durcir (« durcir simulation » montre le plan)."));
                return Ok(());
            }
            let e = &r["etat"];
            let yes_no = |v: &serde_json::Value| if *v == json!(true) { t!("yes", "oui") } else { t!("no", "non") };
            println!("{} {} ({} {} min)", t!("Noted:", "Relevé :"), e["date"].as_str().unwrap_or("?"), t!("age", "il y a"), r["age_min"]);
            println!("{} {}", t!("Firewall:", "Pare-feu :"), yes_no(&e["pare_feu"]));
            println!("{} {}", t!("System SSH tightened:", "SSH du système resserré :"), yes_no(&e["ssh"]));
            println!("{} {}", t!("Kernel settings:", "Réglages du noyau :"), yes_no(&e["noyau"]));
            println!("{} {}", t!("Automatic security updates:", "Mises à jour de sécurité automatiques :"), yes_no(&e["mises_a_jour"]));
            println!("{} {}", t!("Services stopped:", "Services arrêtés :"), e["services_arretes"]);
            let alerts: Vec<&str> = r["alertes"].as_array().into_iter().flatten().filter_map(|a| a.as_str()).collect();
            for a in &alerts {
                println!(
                    "⚠ {}",
                    match *a {
                        "ancien" => t!("State not noted for over an hour: is the hardening timer running?", "État non relevé depuis plus d'une heure : la minuterie du durcissement tourne-t-elle ?"),
                        "pare_feu" => t!("The firewall is stopped although planned.", "Le pare-feu est arrêté alors qu'il est prévu."),
                        "services" => t!("Stopped services were started again.", "Des services arrêtés ont été relancés."),
                        _ => t!("Unreadable state.", "État illisible."),
                    }
                );
            }
            if alerts.is_empty() {
                println!("✓ {}", t!("No alert.", "Aucune alerte."));
            }
            Ok(())
        }
        Command::Setting { key: None, .. } => {
            for (name, value) in all_settings(&state).await? {
                println!("{name:<20} {value}");
            }
            Ok(())
        }
        Command::Setting { key: Some(key), value } => setting_cmd(&state, &key, value).await,
    }
}

/// Réglages généraux, sous leur nom anglais, avec leur valeur effective.
async fn all_settings(state: &State) -> Result<Vec<(&'static str, String)>> {
    let on_off = |b: bool| if b { "on" } else { "off" }.to_string();
    Ok(vec![
        ("name", api::setting_str(state, "nom", "Portunia Gate").await?),
        ("language", api::setting_str(state, "langue", "").await?),
        ("auth_policy", model::default_policy(&state.db).await?.to_string()),
        ("session_hours", api::session_hours(state).await?.to_string()),
        ("remember_password", on_off(api::remember_allowed(state).await?)),
        ("own_replay", on_off(api::own_sessions_allowed(state).await?)),
        ("live_notice", on_off(api::live_notice(state).await?)),
        ("sensitive_commands", api::sensitive_commands(state).await?.join(", ")),
        ("file_copies_mb", model::setting(&state.db, "copies_fichiers_mo").await?.and_then(|v| v.as_u64()).unwrap_or(0).to_string()),
        ("recording_days", status::retention_days(state).await?.to_string()),
        ("banner", api::setting_str(state, "banniere", sshd::default_banner()).await?.replace('\n', "\\n")),
    ])
}

async fn setting_cmd(state: &State, key: &str, value: Option<String>) -> Result<()> {
    // Noms anglais ou français ; les réglages restent rangés sous leur nom français.
    let key = match key {
        "banner" | "banniere" => "banniere",
        "name" | "nom" => "nom",
        "language" | "langue" => "langue",
        "auth_policy" | "politique" => "auth_policy",
        "session_hours" | "duree_session_h" => "duree_session_h",
        "remember_password" | "memo_mot_de_passe" => "memo_mot_de_passe",
        "own_replay" | "relecture_propres" => "relecture_propres",
        "live_notice" | "direct_prevenir" => "direct_prevenir",
        "sensitive_commands" | "commandes_sensibles" => "commandes_sensibles",
        "file_copies_mb" | "copies_fichiers_mo" => "copies_fichiers_mo",
        "recording_days" | "conservation_jours" => status::RETENTION,
        _ => bail!(t!(
            "unknown setting: auth_policy, banner, name, language, session_hours, remember_password, own_replay, live_notice, sensitive_commands, file_copies_mb or recording_days",
            "réglage inconnu : auth_policy, banner, name, language, session_hours, remember_password, own_replay, live_notice, sensitive_commands, file_copies_mb ou recording_days"
        )),
    };
    let Some(v) = value else {
        let shown = all_settings(state).await?;
        let english = match key {
            "banniere" => "banner",
            "nom" => "name",
            "langue" => "language",
            "duree_session_h" => "session_hours",
            "memo_mot_de_passe" => "remember_password",
            "relecture_propres" => "own_replay",
            "direct_prevenir" => "live_notice",
            "commandes_sensibles" => "sensitive_commands",
            "copies_fichiers_mo" => "file_copies_mb",
            "conservation_jours" => "recording_days",
            other => other,
        };
        println!("{}", shown.into_iter().find(|(n, _)| *n == english).map(|(_, v)| v).unwrap_or_default());
        return Ok(());
    };
    let stored = match key {
        "langue" => {
            let v = v.trim().to_lowercase();
            if !["en", "fr", ""].contains(&v.as_str()) {
                bail!(t!("language: en, fr, or empty for the system's language", "langue : en, fr, ou vide pour la langue du système"));
            }
            json!(v)
        }
        "nom" => {
            anyhow::ensure!(!v.trim().is_empty(), t!("name: give a name", "nom : indiquez un nom"));
            json!(v.trim())
        }
        "auth_policy" => json!(auth::Policy::parse(&v)?.to_string()),
        "duree_session_h" => {
            let h: i64 = v.trim().parse().map_err(|_| anyhow!(t!("session_hours: a number of hours", "session_hours : un nombre d'heures")))?;
            if !(1..=168).contains(&h) {
                bail!(t!("Session duration: 1 to 168 hours", "Durée de session : 1 à 168 heures"));
            }
            json!(h)
        }
        "memo_mot_de_passe" | "relecture_propres" | "direct_prevenir" => json!(parse_switch(&v).map_err(|e| anyhow!(e))?),
        "copies_fichiers_mo" => {
            let mb: u64 = v.trim().parse().map_err(|_| anyhow!(t!("file_copies_mb: a number of megabytes (0: no copy)", "file_copies_mb : un nombre de mégaoctets (0 : aucune copie)")))?;
            if mb > 10_240 {
                bail!(t!("file_copies_mb: 0 to 10240", "file_copies_mb : 0 à 10240"));
            }
            json!(mb)
        }
        "commandes_sensibles" => {
            let list: Vec<String> = v.split(',').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect();
            json!(list)
        }
        "conservation_jours" => {
            let days: i64 = v.trim().parse().map_err(|_| anyhow!(t!("recording_days: a number of days (0: kept forever)", "recording_days : un nombre de jours (0 : gardés toujours)")))?;
            if !(0..=36500).contains(&days) {
                bail!(t!("recording_days: 0 to 36500", "recording_days : 0 à 36500"));
            }
            json!(days)
        }
        _ => json!(v),
    };
    model::set_setting(&state.db, key, stored.clone()).await?;
    audit::log(&state.db, "console", "reglage.modifie", json!({ "reglage": key, "valeur": stored })).await?;
    println!("{}", t!("Setting saved.", "Réglage enregistré."));
    if key == "langue" {
        println!("  {}", t!("The service follows it within 30 seconds.", "Le service la suit sous 30 secondes."));
    }
    if key == status::RETENTION && stored.as_i64().unwrap_or(0) > 0 {
        let (sessions, bytes) = status::purge(state, "console").await?;
        println!("  {}", t!(format!("Recordings removed now: {sessions} session(s), {}. Then every hour by the service.", status::human(bytes)), format!("Enregistrements supprimés maintenant : {sessions} session(s), {}. Ensuite chaque heure par le service.", status::human(bytes))));
    }
    Ok(())
}

/// `status` : l'état de la Gate, lisible au terminal (ou en JSON).
async fn status_cmd(state: &State, as_json: bool) -> Result<()> {
    let r = status::report(state, false, true).await?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&r)?);
        return Ok(());
    }
    let level = r["niveau"].as_str().unwrap_or("?");
    let mark = |etat: &str| match etat {
        "ok" => "✓",
        "alerte" => "⚠",
        "erreur" => "✗",
        _ => "·",
    };
    println!(
        "{} {} · Portunia Gate {} · {}",
        mark(level),
        r["nom"].as_str().unwrap_or(""),
        r["version"].as_str().unwrap_or(""),
        match level {
            "ok" => t!("healthy", "en bonne santé"),
            "alerte" => t!("needs attention", "à surveiller"),
            _ => t!("problem", "problème"),
        }
    );
    for a in r["alertes"].as_array().into_iter().flatten() {
        println!("  ⚠ {}", a.as_str().unwrap_or(""));
    }
    let pct = |v: &serde_json::Value| v.as_f64().map(|p| format!("{p:.0} %")).unwrap_or_else(|| "?".into());
    println!();
    println!("{:<22}{} · {}", t!("Server", "Serveur"), r["hote"].as_str().unwrap_or("?"), r["systeme"].as_str().unwrap_or("?"));
    if let Some(s) = r["machine_depuis_s"].as_u64() {
        println!("{:<22}{} {} {}", t!("Up for", "Allumé depuis"), s / 86400, t!("d", "j"), format!("{} h", s % 86400 / 3600));
    }
    println!("{:<22}{} ({} {})", t!("Processor", "Processeur"), pct(&r["cpu"]["pourcent"]), r["cpu"]["coeurs"], t!("cores", "cœurs"));
    if let (Some(t), Some(u)) = (r["memoire"]["total"].as_u64(), r["memoire"]["utilisee"].as_u64()) {
        println!("{:<22}{} / {}", t!("Memory", "Mémoire"), status::human(u), status::human(t));
    }
    if let (Some(t), Some(f)) = (r["disque"]["total"].as_u64(), r["disque"]["libre"].as_u64()) {
        println!("{:<22}{} ({} {} / {})", t!("Disk", "Disque"), pct(&r["disque"]["pourcent"]), status::human(f), t!("free of", "libres sur"), status::human(t));
    }
    println!();
    for s in r["services"].as_array().into_iter().flatten() {
        println!("{} {:<20}{}", mark(s["etat"].as_str().unwrap_or("")), s["nom"].as_str().unwrap_or(""), s["detail"].as_str().unwrap_or(""));
    }
    let st = &r["stockage"];
    println!();
    println!(
        "{:<22}{} · {} {}",
        t!("Recordings", "Enregistrements"),
        status::human(st["enregistrements"]["octets"].as_u64().unwrap_or(0)),
        st["enregistrements"]["fichiers"],
        t!("files", "fichiers")
    );
    if let Some(d) = st["par_jour"].as_f64() {
        println!("{:<22}+{} {}", t!("Rate", "Rythme"), status::human(d as u64), t!("per day", "par jour"));
    }
    if let Some(d) = st["plein_dans_jours"].as_i64() {
        println!("{:<22}{} {}", t!("Disk full in", "Disque plein dans"), d, t!("days", "jours"));
    }
    let days = st["conservation_jours"].as_i64().unwrap_or(0);
    println!(
        "{:<22}{}",
        t!("Retention", "Conservation"),
        if days == 0 { t!("forever (setting recording_days DAYS)", "toujours (setting recording_days JOURS)").to_string() } else { t!(format!("{days} days"), format!("{days} jours")) }
    );
    let a = &r["activite"];
    println!();
    println!(
        "{:<22}{} {} · {} {} · {} {}",
        t!("Activity", "Activité"),
        a["sessions_ouvertes"],
        t!("open", "ouvertes"),
        a["sessions_jour"],
        t!("today", "aujourd'hui"),
        a["refus_24h"],
        t!("refusals (24 h)", "refus (24 h)")
    );
    println!("{:<22}{}", t!("Audit log", "Journal"), t!("check: sudo portunia-gate audit --verify", "vérification : sudo portunia-gate audit --verify"));
    let u = &r["mise_a_jour"];
    if u["disponible"] == json!(true) {
        println!("\n{} {} → {} : sudo portunia-gate update apply", t!("Update available:", "Mise à jour disponible :"), u["actuelle"].as_str().unwrap_or(""), u["derniere"].as_str().unwrap_or(""));
    }
    Ok(())
}

/// HH:MM (aujourd'hui, ou demain si l'heure est passée) ou AAAA-MM-JJTHH:MM, heure de la Gate.
fn parse_when(text: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    use chrono::TimeZone;
    let text = text.trim().replace(' ', "T");
    let local = if let Ok(t) = chrono::NaiveTime::parse_from_str(&text, "%H:%M") {
        let now = chrono::Local::now();
        let mut day = now.date_naive();
        if t <= now.time() {
            day = day.succ_opt().unwrap_or(day);
        }
        day.and_time(t)
    } else {
        chrono::NaiveDateTime::parse_from_str(&text, "%Y-%m-%dT%H:%M").map_err(|_| anyhow!(t!("--at: HH:MM or YYYY-MM-DDTHH:MM", "--at : HH:MM ou AAAA-MM-JJTHH:MM")))?
    };
    let at = chrono::Local.from_local_datetime(&local).earliest().ok_or_else(|| anyhow!(t!("--at: time that does not exist (time change)", "--at : heure qui n'existe pas (changement d'heure)")))?;
    Ok(at.with_timezone(&chrono::Utc))
}

fn print_progress(p: &update::Progress) {
    println!(
        "{} {} → {} · {} · {}",
        t!("Last run:", "Dernière exécution :"),
        p.de,
        p.vers,
        match p.resultat.as_str() {
            "reussie" => t!("done", "réussie"),
            "retour_arriere" => t!("rolled back", "retour en arrière"),
            "en_cours" => t!("under way", "en cours"),
            _ => t!("failed", "échec"),
        },
        p.debut.map(|d| d.with_timezone(&chrono::Local).format("%d/%m %H:%M").to_string()).unwrap_or_default()
    );
    for line in &p.journal {
        println!("  {line}");
    }
    if !p.message.is_empty() {
        println!("  {}", p.message);
    }
}

async fn update_cmd(state: &State, cmd: UpdateCmd) -> Result<()> {
    match cmd {
        UpdateCmd::Run => unreachable!(),
        UpdateCmd::Check => {
            let s = update::summary(state, true).await?;
            println!("{} {}", t!("Installed:", "Installée :"), update::CURRENT);
            match s["derniere"].as_str() {
                Some(v) => println!("{} {v}{}", t!("Latest published:", "Dernière publiée :"), if s["disponible"] == json!(true) { t!(" — update available", " — mise à jour disponible") } else { t!(" — up to date", " — à jour") }),
                None => println!("{} {}", t!("Latest version unknown:", "Dernière version inconnue :"), s["erreur_verification"].as_str().unwrap_or("?")),
            }
            if let Some(why) = s["impossible"].as_str() {
                println!("{why}");
            }
            Ok(())
        }
        UpdateCmd::Apply { version, at, notice, no_rollback, wait } => {
            let version = match version {
                Some(v) => v.trim().trim_start_matches('v').to_string(),
                None => update::latest(true).await.version.ok_or_else(|| anyhow!(t!("latest version unknown: give --version", "dernière version inconnue : indiquez --version")))?,
            };
            let at = at.as_deref().map(parse_when).transpose()?;
            let p = update::plan(state, &version, at, notice, "console", no_rollback).await?;
            if p.a > chrono::Utc::now() + chrono::Duration::seconds(5) {
                println!(
                    "✓ {}",
                    t!(
                        format!("Update to {version} scheduled for {}{}. Cancel: sudo portunia-gate update cancel", p.a.with_timezone(&chrono::Local).format("%d/%m/%Y %H:%M"), if notice { " (users warned 5 minutes before)" } else { "" }),
                        format!("Mise à jour en {version} programmée le {}{}. Annuler : sudo portunia-gate update cancel", p.a.with_timezone(&chrono::Local).format("%d/%m/%Y %H:%M"), if notice { " (utilisateurs prévenus 5 minutes avant)" } else { "" })
                    )
                );
                return Ok(());
            }
            println!("✓ {}", t!(format!("Update to {version} started: the Gate restarts within a few minutes."), format!("Mise à jour en {version} lancée : la Gate redémarre dans quelques minutes.")));
            if !wait {
                println!("  {}", t!("Follow it: sudo portunia-gate update status", "Suivre : sudo portunia-gate update status"));
                return Ok(());
            }
            // Attend que le service root prenne la demande, puis le résultat.
            let start = std::time::Instant::now();
            let mut shown = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if let Some(p) = update::progress().filter(|p| p.vers == version && p.debut.is_some_and(|d| d > chrono::Utc::now() - chrono::Duration::hours(1))) {
                    for line in p.journal.iter().skip(shown) {
                        println!("  {line}");
                    }
                    shown = p.journal.len();
                    if p.resultat != "en_cours" {
                        anyhow::ensure!(p.resultat == "reussie", "{}", p.message);
                        return Ok(());
                    }
                } else if start.elapsed() > std::time::Duration::from_secs(30) && update::request_path(&state.config.data_dir).exists() {
                    bail!(t!("the update service does not take the request: systemctl status portunia-gate-update.path", "le service de mise à jour ne prend pas la demande : systemctl status portunia-gate-update.path"));
                }
                if start.elapsed() > std::time::Duration::from_secs(20 * 60) {
                    bail!(t!("no result after 20 minutes: sudo portunia-gate update status", "pas de résultat après 20 minutes : sudo portunia-gate update status"));
                }
            }
        }
        UpdateCmd::Cancel => {
            if update::cancel(state, "console").await? {
                println!("✓ {}", t!("Scheduled update cancelled.", "Mise à jour programmée annulée."));
            } else {
                println!("{}", t!("No scheduled update.", "Aucune mise à jour programmée."));
            }
            Ok(())
        }
        UpdateCmd::Status => {
            println!("{} {} · {} {}", t!("Installed:", "Installée :"), update::CURRENT, t!("mode:", "mode :"), update::mode());
            match update::planned(state).await? {
                Some(p) => println!(
                    "{} {} — {}{}",
                    t!("Scheduled:", "Programmée :"),
                    p.version,
                    p.a.with_timezone(&chrono::Local).format("%d/%m/%Y %H:%M"),
                    if p.prevenir { t!(" (users warned)", " (utilisateurs prévenus)") } else { "" }
                ),
                None => println!("{}", t!("No scheduled update.", "Aucune mise à jour programmée.")),
            }
            if let Some(p) = update::progress() {
                print_progress(&p);
            }
            Ok(())
        }
    }
}

/// Date « AAAA-MM-JJ » à minuit, heure de la Gate ; `end` : fin de ce jour (minuit suivant).
fn parse_day(text: &str, end: bool) -> Result<chrono::DateTime<chrono::Utc>> {
    let day = chrono::NaiveDate::parse_from_str(text.trim(), "%Y-%m-%d").map_err(|_| anyhow!(t!("Date: YYYY-MM-DD", "Date : AAAA-MM-JJ")))?;
    let day = if end { day.succ_opt().unwrap_or(day) } else { day };
    let local = day
        .and_hms_opt(0, 0, 0)
        .and_then(|d| d.and_local_timezone(chrono::Local).earliest())
        .ok_or_else(|| anyhow!(t!("Invalid date", "Date invalide")))?;
    Ok(local.with_timezone(&chrono::Utc))
}

/// Une session : compte, serveur, horaires, fichier d'enregistrement et contrôle de sa signature.
/// Approbation en ligne de commande : la console agit comme un administrateur sans compte.
async fn approval_cmd(state: &Arc<State>, cmd: ApprovalCmd) -> Result<()> {
    let db = &state.db;
    let find = |prefix: String| async move {
        let rows: Vec<(uuid::Uuid,)> = sqlx::query_as("SELECT id FROM approvals WHERE id::text LIKE $1 || '%'").bind(prefix.to_lowercase()).fetch_all(db).await?;
        match rows.as_slice() {
            [one] => Ok(one.0),
            [] => Err(anyhow!(t!("Unknown request", "Demande inconnue"))),
            _ => Err(anyhow!(t!("Several requests start this way: give more characters", "Plusieurs demandes commencent ainsi : donnez plus de caractères"))),
        }
    };
    let local = |d: chrono::DateTime<chrono::Utc>| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string();
    match cmd {
        ApprovalCmd::List => {
            let rows: Vec<approval::Request> = sqlx::query_as(
                "SELECT a.id, a.user_id, u.login, a.target_id, t.name AS target, a.reason, a.ticket, a.status, a.requested_at, a.decided_by, a.decided_at, a.until, a.comment
                 FROM approvals a JOIN users u ON u.id = a.user_id JOIN targets t ON t.id = a.target_id
                 WHERE a.status = 'attente' OR (a.status = 'accordee' AND a.until > now()) ORDER BY a.requested_at",
            )
            .fetch_all(db)
            .await?;
            if rows.is_empty() {
                println!("{}", t!("No request waiting, no access under way.", "Aucune demande en attente, aucun accès en cours."));
            }
            for r in rows {
                let state = if r.status == "attente" { t!("waiting", "en attente").to_string() } else { format!("{} {}", t!("granted until", "accordé jusqu'au"), r.until.map(local).unwrap_or_default()) };
                println!("{}  {:<14} {:<18} {:<26} {}{}", &r.id.to_string()[..8], r.login, r.target, state, r.reason, if r.ticket.is_empty() { String::new() } else { format!(" [{}]", r.ticket) });
            }
        }
        ApprovalCmd::Grant { id, minutes, comment } => {
            let id = find(id).await?;
            let r = approval::decide_by(state, "console", None, id, true, minutes, &comment).await?;
            println!("{}", t!(format!("Granted: {} → {} until {}.", r.login, r.target, r.until.map(local).unwrap_or_default()), format!("Accordé : {} → {} jusqu'au {}.", r.login, r.target, r.until.map(local).unwrap_or_default())));
        }
        ApprovalCmd::Deny { id, comment } => {
            let id = find(id).await?;
            let r = approval::decide_by(state, "console", None, id, false, 0, &comment).await?;
            println!("{}", t!(format!("Refused: {} → {}.", r.login, r.target), format!("Refusé : {} → {}.", r.login, r.target)));
        }
        ApprovalCmd::Revoke { id } => {
            let id = find(id).await?;
            approval::cancel_by(state, "console", None, id).await?;
            println!("{}", t!("Withdrawn: its sessions close within 30 seconds.", "Retiré : ses sessions se ferment sous 30 secondes."));
        }
    }
    Ok(())
}

/// Notifications : réglages et essai.
async fn notify_cmd(state: &Arc<State>, cmd: NotifyCmd) -> Result<()> {
    match cmd {
        NotifyCmd::Show => {
            let s = notify::settings(state).await?;
            let shown = |v: &str| if v.is_empty() { "—".to_string() } else { v.to_string() };
            println!("{} {}:{} ({})", t!("SMTP:", "SMTP :"), shown(&s.smtp_host), s.smtp_port, s.smtp_security);
            println!("{} {}{}", t!("SMTP account:", "Compte SMTP :"), shown(&s.smtp_user), if s.smtp_password.is_some() { t!(" (password saved)", " (mot de passe enregistré)") } else { "" });
            println!("{} {}", t!("Sender:", "Expéditeur :"), shown(&s.smtp_from));
            println!("Teams : {}", shown(&s.teams_url));
            println!("Webhook : {}{}", shown(&s.webhook_url), if s.webhook_secret.is_some() { t!(" (signed)", " (signé)") } else { "" });
        }
        NotifyCmd::Set { smtp_host, smtp_port, smtp_security, smtp_user, smtp_password, from, teams_url, webhook_url, webhook_secret } => {
            let mut s = notify::settings(state).await?;
            if let Some(v) = smtp_host { s.smtp_host = v.trim().to_string(); }
            if let Some(v) = smtp_port { s.smtp_port = v; }
            if let Some(v) = smtp_security { s.smtp_security = v.trim().to_lowercase(); }
            if let Some(v) = smtp_user { s.smtp_user = v.trim().to_string(); }
            if smtp_password {
                s.smtp_password = Some(rpassword::prompt_password(t!("SMTP password: ", "Mot de passe SMTP : "))?);
            }
            if let Some(v) = from { s.smtp_from = v.trim().to_string(); }
            if let Some(v) = teams_url { s.teams_url = v.trim().to_string(); }
            if let Some(v) = webhook_url { s.webhook_url = v.trim().to_string(); }
            let mut new_secret = None;
            if webhook_secret {
                use base64::Engine;
                let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(keys::random::<32>()?);
                s.webhook_secret = Some(secret.clone());
                new_secret = Some(secret);
            }
            notify::save(state, &s).await?;
            audit::log(&state.db, "console", "notifications.modifiees", notify::public(&s)).await?;
            println!("{}", t!("Notification settings saved.", "Réglages des notifications enregistrés."));
            if let Some(secret) = new_secret {
                println!("{} {secret}", t!("Webhook signing secret (shown only once):", "Secret de signature du webhook (affiché une seule fois) :"));
            }
        }
        NotifyCmd::Test { email } => {
            let s = notify::settings(state).await?;
            let gate = api::setting_str(state, "nom", "Portunia Gate").await?;
            let text = t!("Test message from the Gate: notifications work.", "Message d'essai de la Gate : les notifications fonctionnent.");
            if let Some(to) = email {
                notify::mail(&s, &[to.clone()], &format!("[{gate}] {}", t!("Test", "Essai")), text).await?;
                println!("✓ {} {to}", t!("E-mail sent to", "Courriel envoyé à"));
            }
            if !s.teams_url.is_empty() {
                notify::teams(&s, &format!("[{gate}] {}", t!("Test", "Essai")), text).await?;
                println!("✓ Teams");
            }
            if !s.webhook_url.is_empty() {
                notify::webhook(&s, &gate, "essai", &json!({ "message": text })).await?;
                println!("✓ Webhook");
            }
        }
    }
    Ok(())
}

/// Coupe une session ouverte : ordre appliqué par le service sous 30 secondes.
async fn session_cut(state: &State, id: &str, disable: bool) -> Result<()> {
    let found = model::audit_sessions_by_prefix(&state.db, id).await?;
    let s = match found.as_slice() {
        [one] => one,
        [] => bail!(t!("Session not found", "Session introuvable")),
        _ => bail!(t!("Several sessions start this way: give more characters", "Plusieurs sessions commencent ainsi : donnez plus de caractères")),
    };
    if s.ended_at.is_some() {
        bail!(t!("This session is already closed", "Cette session est déjà fermée"));
    }
    model::order_cut_session(&state.db, s.id, "console").await?;
    if disable {
        if let Some(u) = model::user_by_login(&state.db, &s.login).await? {
            sqlx::query("UPDATE users SET disabled = true WHERE id = $1").bind(u.id).execute(&state.db).await?;
            model::order_cut(&state.db, u.id).await?;
        }
    }
    audit::log(&state.db, "console", "session.coupee_par", json!({ "session": s.id, "cible": s.target, "compte": s.login, "desactive": disable })).await?;
    println!("{}", t!("Session cut within 30 seconds.", "Session coupée sous 30 secondes."));
    if disable {
        println!("{}", t!(format!("Account {} disabled.", s.login), format!("Compte {} désactivé.", s.login)));
    }
    Ok(())
}

async fn session_show(state: &State, id: &str) -> Result<()> {
    let found = model::audit_sessions_by_prefix(&state.db, id).await?;
    let s = match found.as_slice() {
        [one] => one,
        [] => bail!(t!("Session not found", "Session introuvable")),
        _ => bail!(t!("Several sessions start this way: give more characters", "Plusieurs sessions commencent ainsi : donnez plus de caractères")),
    };
    let local = |d: chrono::DateTime<chrono::Utc>| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string();
    println!("{} {}", t!("Session:", "Session :"), s.id);
    println!("{} {}", t!("Account:", "Compte :"), s.login);
    println!("{} {} {} ({}, {})", t!("Server:", "Serveur :"), s.target, s.detail, s.kind, s.mode);
    println!("{} {}", t!("From:", "Depuis :"), s.client_addr);
    println!("{} {} → {}", t!("Times:", "Horaires :"), local(s.started_at), s.ended_at.map(local).unwrap_or_else(|| t!("ongoing", "en cours").into()));
    println!("{} {} o", t!("Volume:", "Volume :"), s.bytes);
    println!("{} {}", t!("Keystrokes recorded:", "Frappe enregistrée :"), if s.frappe { t!("yes", "oui") } else { t!("no", "non") });
    let Some(path) = &s.recording else {
        println!("{}", t!("Not recorded (jump mode or no recording).", "Non enregistrée (mode rebond ou sans enregistrement)."));
        return Ok(());
    };
    println!("{} {path}", t!("Recording:", "Enregistrement :"));
    let raw = std::fs::read(path).map_err(|e| anyhow!(t!(format!("unreadable recording file: {e}"), format!("fichier d'enregistrement illisible : {e}"))))?;
    let sha = keys::sha256_hex(&raw);
    match (&s.recording_sha256, &s.signature) {
        (Some(expected), Some(sig)) => {
            use base64::Engine;
            let sig = base64::engine::general_purpose::STANDARD.decode(sig).unwrap_or_default();
            if *expected == sha && state.keys.verify(recording::signature_message(s.id, &sha).as_bytes(), &sig) {
                println!("✓ {}", t!("Signature verified: the file is as the Gate wrote it.", "Signature vérifiée : le fichier est tel que la Gate l'a écrit."));
            } else {
                println!("⚠ {}", t!("ALTERED FILE: its fingerprint or signature does not match.", "FICHIER ALTÉRÉ : son empreinte ou sa signature ne correspond pas."));
            }
        }
        _ => println!("{}", t!("No signature yet (session ongoing or interrupted).", "Pas encore de signature (session en cours ou interrompue).")),
    }
    if s.kind == "web" {
        // Journal d'actions : lisible directement.
        if let Ok((_, actions, _)) = websession::read(&raw) {
            for a in actions {
                println!("{:>9.1} s  {:<9} {:<6} {:<4} {}", a["t"].as_f64().unwrap_or(0.0), a["k"].as_str().unwrap_or_default(), a["methode"].as_str().unwrap_or_default(), a["statut"], a["chemin"].as_str().unwrap_or_default());
            }
        }
    } else if s.kind == "rdp" {
        println!("{}", t!("Replay: Portunia › Audit (Remote Desktop recordings are read by Portunia only).", "Relecture : Portunia › Audit (les enregistrements Bureau à distance ne se lisent que dans Portunia)."));
    } else {
        println!("{} sudo asciinema play {path}", t!("Replay in a terminal (not logged, masked input shown):", "Relecture dans un terminal (non journalisée, saisies masquées visibles) :"));
    }
    Ok(())
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
            let extra: Vec<(uuid::Uuid, Vec<String>, i64)> = sqlx::query_as(
                "SELECT u.id,
                        COALESCE((SELECT array_agg(g.name ORDER BY g.name) FROM group_members m JOIN groups g ON g.id = m.group_id WHERE m.user_id = u.id), '{}'),
                        (SELECT count(*) FROM user_keys k WHERE k.user_id = u.id)
                 FROM users u",
            )
            .fetch_all(db)
            .await?;
            for u in model::users(db).await? {
                let (groups, keys) = extra.iter().find(|e| e.0 == u.id).map(|e| (e.1.join(","), e.2)).unwrap_or_default();
                let mut marks = Vec::new();
                if u.must_change_password {
                    marks.push(t!("TEMPORARY PASSWORD", "MOT DE PASSE PROVISOIRE"));
                }
                if u.disabled {
                    marks.push(t!("DISABLED", "DÉSACTIVÉ"));
                }
                println!(
                    "{:<20} {:<8} code {:<9} {} {:<3} {:<26} {:<30} {}",
                    u.login,
                    u.role,
                    if u.totp_secret.is_some() { t!("enrolled", "enrôlé") } else { t!("missing", "absent") },
                    t!("keys", "clés"),
                    keys,
                    u.auth_policy.unwrap_or_else(|| t!("(global)", "(général)").into()),
                    groups,
                    marks.join("  ")
                );
            }
        }
        UserCmd::Policy { login, policy } => {
            let user = find(login).await?;
            let policy = Some(policy.trim().to_string()).filter(|p| !p.is_empty()).map(|p| auth::Policy::parse(&p).map(|p| p.to_string())).transpose()?;
            sqlx::query("UPDATE users SET auth_policy = $2 WHERE id = $1").bind(user.id).bind(&policy).execute(db).await?;
            audit::log(db, "console", "compte.modifie", json!({ "compte": user.login, "politique": policy })).await?;
            println!("{} {}", t!("Sign-in combinations:", "Combinaisons de connexion :"), policy.unwrap_or_else(|| t!("global setting", "réglage général").into()));
        }
        UserCmd::ResetPassword { login } => {
            let user = find(login).await?;
            let password = auth::temp_password()?;
            sqlx::query("UPDATE users SET password_hash = $2, must_change_password = true WHERE id = $1")
                .bind(user.id)
                .bind(auth::hash_password(&password)?)
                .execute(db)
                .await?;
            model::revoke_logins(db, user.id).await?;
            model::order_cut(db, user.id).await?;
            audit::log(db, "console", "compte.mot_de_passe_provisoire", json!({ "compte": user.login })).await?;
            println!("{} {password}", t!("Temporary password:", "Mot de passe provisoire :"));
            println!(
                "  {}",
                t!(
                    "At the next sign-in in Portunia, the user chooses theirs. Without Portunia: sudo portunia-gate user passwd. Their open sessions close within 30 seconds.",
                    "À la prochaine connexion dans Portunia, l'utilisateur choisit le sien. Sans Portunia : sudo portunia-gate user passwd. Ses sessions ouvertes se ferment sous 30 secondes."
                )
            );
        }
        UserCmd::Email { login, address } => {
            let user = find(login).await?;
            let address = address.trim().to_string();
            if !address.is_empty() {
                address.parse::<lettre::Address>().map_err(|_| anyhow!(t!("not an e-mail address", "ce n'est pas une adresse e-mail")))?;
            }
            sqlx::query("UPDATE users SET email = $2 WHERE id = $1").bind(user.id).bind(&address).execute(&state.db).await?;
            audit::log(&state.db, "console", "compte.modifie", json!({ "compte": user.login, "email": address })).await?;
            println!("{}", t!("E-mail address saved.", "Adresse e-mail enregistrée."));
        }
        UserCmd::RdpPassword { login, remove } => {
            let user = find(login).await?;
            if remove {
                rdplogin::remove_password(state, &user, "console").await?;
                println!("{}", t!("RDP password removed.", "Mot de passe RDP retiré."));
            } else {
                let password = rdplogin::new_password(state, &user, "console").await?;
                println!("{}", t!(format!("RDP password of {} (shown only once): {password}", user.login), format!("Mot de passe RDP de {} (affiché une seule fois) : {password}", user.login)));
                println!(
                    "{}",
                    t!(
                        "In mstsc: Computer = the Gate's address and native RDP port; User = login%server (or login%server%code). Native RDP must be on (« portunia-gate rdp on »).",
                        "Dans mstsc : Ordinateur = adresse de la Gate et port du RDP natif ; Utilisateur = compte%serveur (ou compte%serveur%code). Le RDP natif doit être ouvert (« portunia-gate rdp on »)."
                    )
                );
            }
        }
        UserCmd::ResetCode { login } => {
            let user = find(login).await?;
            sqlx::query("UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = 0 WHERE id = $1")
                .bind(user.id)
                .execute(db)
                .await?;
            model::revoke_logins(db, user.id).await?;
            model::order_cut(db, user.id).await?;
            audit::log(db, "console", "compte.totp_reinitialise", json!({ "compte": user.login })).await?;
            println!(
                "{}",
                t!(
                    "Code erased: a new one is enrolled at the next sign-in in Portunia, or with « sudo portunia-gate user totp ». Open sessions close within 30 seconds.",
                    "Code effacé : un nouveau s'enrôle à la prochaine connexion dans Portunia, ou avec « sudo portunia-gate user totp ». Les sessions ouvertes se ferment sous 30 secondes."
                )
            );
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
            // Mot de passe choisi par l'administrateur : il n'est plus provisoire.
            sqlx::query("UPDATE users SET password_hash = $2, must_change_password = false WHERE id = $1")
                .bind(user.id)
                .bind(hash)
                .execute(db)
                .await?;
            // Les connexions ouvertes avec l'ancien mot de passe se ferment.
            model::revoke_logins(db, user.id).await?;
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
            if !undo {
                // Plus de connexion ; ses sessions ouvertes se ferment au tour suivant du service.
                model::revoke_logins(db, user.id).await?;
            }
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
        GroupCmd::Remove { group, logins } => {
            let gid = model::group_id(db, &group).await?;
            for login in logins {
                let user = model::user_by_login(db, &login)
                    .await?
                    .ok_or_else(|| anyhow!(t!(format!("Unknown account: {login}"), format!("Compte inconnu : {login}"))))?;
                let done = sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2")
                    .bind(gid)
                    .bind(user.id)
                    .execute(db)
                    .await?;
                if done.rows_affected() == 0 {
                    println!("{}", t!(format!("{login} was not a member."), format!("{login} n'était pas membre.")));
                    continue;
                }
                audit::log(db, "console", "groupe.membre_retire", json!({ "groupe": group, "compte": login })).await?;
            }
            println!("{}", t!("Members removed: sessions they lose close within 30 seconds.", "Membres retirés : les sessions qu'ils perdent se ferment sous 30 secondes."));
        }
        GroupCmd::List => {
            let rows: Vec<(String, Vec<String>)> = sqlx::query_as(
                "SELECT g.name, COALESCE(array_agg(u.login ORDER BY u.login) FILTER (WHERE u.login IS NOT NULL), '{}')
                 FROM groups g LEFT JOIN group_members m ON m.group_id = g.id LEFT JOIN users u ON u.id = m.user_id
                 GROUP BY g.id ORDER BY g.name",
            )
            .fetch_all(db)
            .await?;
            for (name, members) in rows {
                println!("{:<24} {}", name, members.join(", "));
            }
        }
        GroupCmd::Delete { name } => {
            let gone: Option<String> = sqlx::query_scalar("DELETE FROM groups WHERE name = $1 RETURNING name")
                .bind(&name)
                .fetch_optional(db)
                .await?;
            let gone = gone.ok_or_else(|| anyhow!(t!(format!("Unknown group: {name}"), format!("Groupe inconnu : {name}"))))?;
            audit::log(db, "console", "groupe.supprime", json!({ "groupe": gone })).await?;
            println!("{}", t!("Group deleted, with its rules.", "Groupe supprimé, avec ses règles."));
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
            web_login,
            description,
        } => {
            let port = port.unwrap_or(match protocol.as_str() { "rdp" => 3389, "https" => 443, "http" => 80, _ => 22 });
            let web = matches!(protocol.as_str(), "http" | "https");
            // Interface web sans secret : mode enregistré (le coffre, mode par défaut, en demande un).
            let mode = model::mode_alias(&mode).to_string();
            let mode = if web && mode == "coffre" && !password { "enregistre".to_string() } else { mode };
            let secret = console_secret(password, key_file.as_deref())?;
            if web && secret.as_ref().is_some_and(|s| s.0 == "key") {
                bail!(t!("Web interface: the vault keeps a password, not an SSH key", "Interface web : le coffre garde un mot de passe, pas une clé SSH"));
            }
            let web_login = model::web_login(&web_login)?;
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
                web_connexion: web_login,
                description,
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
        TargetCmd::Edit {
            name,
            rename,
            host,
            port,
            mode,
            account,
            folder,
            password,
            key_file,
            web_login,
            description,
        } => {
            let current = find_target(db, &name).await?;
            let mut t = current.clone();
            if let Some(n) = rename {
                if n.trim().is_empty() || n.contains('%') || n.contains(char::is_whitespace) {
                    bail!(t!("The name must contain neither spaces nor « % »", "Le nom ne doit contenir ni espace ni « % »"));
                }
                t.name = n.trim().into();
            }
            if let Some(h) = host {
                t.host = h.trim().into();
            }
            if let Some(p) = port {
                if !(1..=65535).contains(&p) {
                    bail!(t!("Port: 1 to 65535", "Port : 1 à 65535"));
                }
                t.port = p;
            }
            if let Some(m) = mode {
                t.mode = model::mode_alias(&m).to_string();
            }
            if let Some(a) = account {
                t.account = Some(a.trim().to_string()).filter(|a| !a.is_empty());
            }
            if let Some(f) = folder {
                t.folder = f.trim().into();
            }
            if let Some(w) = web_login {
                t.web_connexion = model::web_login(&w)?;
            }
            if let Some(d) = description {
                t.description = model::check_description(&d)?;
            }
            model::check_protocol(&t.protocole, &t.mode)?;
            if !["rebond", "enregistre", "coffre"].contains(&t.mode.as_str()) {
                bail!(t!("Mode: jump (rebond), recorded (enregistre) or vault (coffre)", "Mode : rebond, enregistre ou coffre"));
            }
            let secret = console_secret(password, key_file.as_deref())?;
            if secret.as_ref().is_some_and(|s| s.0 == "key") && !t.is_ssh() {
                bail!(t!("Remote Desktop and web: the vault keeps a password, not an SSH key", "Bureau à distance et web : le coffre garde un mot de passe, pas une clé SSH"));
            }
            // Changement d'adresse : l'ancienne empreinte ne vaut plus, et le secret du coffre doit être
            // ressaisi (comme dans Portunia).
            let moved = t.host != current.host || t.port != current.port;
            if moved {
                t.host_key = None;
                if secret.is_none() && current.secret.is_some() {
                    bail!(t!("The address changes: give the vault secret again (--password or --key-file)", "L'adresse change : redonnez le secret du coffre (--password ou --key-file)"));
                }
            }
            if let Some((kind, plain)) = &secret {
                t.secret_kind = kind.clone();
                t.secret = Some(state.keys.seal(&current.secret_purpose(), plain)?);
            }
            if t.mode == "coffre" && (t.account.is_none() || t.secret.is_none()) {
                bail!(t!("In vault mode, give the account and its secret", "En mode coffre, indiquez le compte et son secret"));
            }
            save_target(db, &t).await?;
            audit::log(
                db,
                "console",
                "cible.modifiee",
                json!({ "cible": t.name, "avant": current.name, "mode": t.mode, "adresse": format!("{}:{}", t.host, t.port), "adresse_avant": format!("{}:{}", current.host, current.port) }),
            )
            .await?;
            println!("{}", t!("Server changed: open sessions are rechecked within 30 seconds.", "Serveur modifié : les sessions ouvertes sont revérifiées sous 30 secondes."));
            if moved {
                println!("{}", t!("New address: the fingerprint will be remembered at the next connection.", "Nouvelle adresse : l'empreinte sera mémorisée à la prochaine connexion."));
            }
        }
        TargetCmd::Secret { name, password, key_file, generate } => {
            let mut t = find_target(db, &name).await?;
            let (kind, plain) = if generate {
                if password || key_file.is_some() {
                    bail!(t!("Choose --password, --key-file or --generate", "Choisissez --password, --key-file ou --generate"));
                }
                if !t.is_ssh() {
                    bail!(t!("Remote Desktop and web: the vault keeps a password, not an SSH key", "Bureau à distance et web : le coffre garde un mot de passe, pas une clé SSH"));
                }
                let account = t.account.clone().ok_or_else(|| anyhow!(t!("Give the account on the server first (target edit --account)", "Indiquez d'abord le compte sur le serveur (target edit --account)")))?;
                let current = prompt_secret(&t!(format!("Current password of {account} on {}: ", t.name), format!("Mot de passe actuel de {account} sur {} : ", t.name)))?;
                let key = target::install_new_key(state, &t, &account, &current, "console").await?;
                audit::log(db, "console", "cible.cle_installee", json!({ "cible": t.name, "compte": account })).await?;
                ("key".to_string(), key.into_bytes())
            } else {
                console_secret(password, key_file.as_deref())?
                    .ok_or_else(|| anyhow!(t!("Give --password, --key-file or --generate", "Indiquez --password, --key-file ou --generate")))?
            };
            if kind == "key" && !t.is_ssh() {
                bail!(t!("Remote Desktop and web: the vault keeps a password, not an SSH key", "Bureau à distance et web : le coffre garde un mot de passe, pas une clé SSH"));
            }
            t.secret = Some(state.keys.seal(&t.secret_purpose(), &plain)?);
            t.secret_kind = kind.clone();
            save_target(db, &t).await?;
            audit::log(db, "console", "cible.secret_change", json!({ "cible": t.name, "secret": kind })).await?;
            println!("{}", t!("Vault secret replaced.", "Secret du coffre remplacé."));
        }
        TargetCmd::Forget { name } => {
            let t = find_target(db, &name).await?;
            sqlx::query("UPDATE targets SET host_key = NULL WHERE id = $1").bind(t.id).execute(db).await?;
            audit::log(db, "console", "cible.empreinte_oubliee", json!({ "cible": t.name, "ancienne": t.host_key })).await?;
            println!("{}", t!("Fingerprint forgotten: the next one will be remembered at the next connection.", "Empreinte oubliée : la suivante sera mémorisée à la prochaine connexion."));
        }
        TargetCmd::Delete { name } => {
            let t = find_target(db, &name).await?;
            sqlx::query("DELETE FROM targets WHERE id = $1").bind(t.id).execute(db).await?;
            audit::log(db, "console", "cible.supprimee", json!({ "cible": t.name })).await?;
            println!("{}", t!("Server deleted: its sessions close within 30 seconds; recordings stay.", "Serveur supprimé : ses sessions se ferment sous 30 secondes ; les enregistrements restent."));
        }
    }
    Ok(())
}

async fn find_target(db: &PgPool, name: &str) -> Result<model::Target> {
    model::target_by_name(db, name)
        .await?
        .ok_or_else(|| anyhow!(t!(format!("Unknown target: {name}"), format!("Cible inconnue : {name}"))))
}

async fn save_target(db: &PgPool, t: &model::Target) -> Result<()> {
    sqlx::query(
        "UPDATE targets SET name = $2, folder = $3, host = $4, port = $5, mode = $6, account = $7, secret_kind = $8, secret = $9, host_key = $10,
                web_connexion = $11, description = $12
         WHERE id = $1",
    )
    .bind(t.id)
    .bind(&t.name)
    .bind(&t.folder)
    .bind(&t.host)
    .bind(t.port)
    .bind(&t.mode)
    .bind(&t.account)
    .bind(&t.secret_kind)
    .bind(&t.secret)
    .bind(&t.host_key)
    .bind(&t.web_connexion)
    .bind(&t.description)
    .execute(db)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.code().as_deref() == Some("23505") => anyhow!(t!("This name is already taken", "Ce nom est déjà pris")),
        _ => e.into(),
    })?;
    Ok(())
}

async fn portal_cmd(state: &State, cmd: PortalCmd) -> Result<()> {
    let db = &state.db;
    let e = match cmd {
        PortalCmd::On | PortalCmd::Off => {
            let on = matches!(cmd, PortalCmd::On);
            let was = portal::settings(state).await?.enabled;
            model::set_setting(db, "portail_actif", json!(on)).await?;
            if was != on {
                if !on {
                    close_web_sessions(db).await?;
                }
                audit::log(db, "console", if on { "portail.active" } else { "portail.desactive" }, json!({})).await?;
            }
            if on {
                let s = portal::settings(state).await?;
                println!("✓ {}", t!("Portal open.", "Portail ouvert."));
                if s.url.is_empty() {
                    println!("  {}", t!("No public address: set one behind Cloudflare or a proxy (portal set --url https://…).", "Pas d'adresse publique : réglez-la derrière Cloudflare ou un proxy (portal set --url https://…)."));
                }
                if model::group_id(db, &s.group).await.is_err() {
                    println!("  {}", t!(format!("Group « {} » missing: nobody can sign in (group add, group member).", s.group), format!("Groupe « {} » absent : personne ne peut se connecter (group add, group member).", s.group)));
                }
            } else {
                println!("✓ {}", t!("Portal closed: open web sessions close within 30 seconds.", "Portail fermé : les sessions web ouvertes se ferment sous 30 secondes."));
            }
            return Ok(());
        }
        PortalCmd::Set { url, group, duration, idle, clipboard, code, turnstile_site, turnstile_secret, internal_url, internal_code } => {
            let mut changed = serde_json::Map::new();
            if let Some(url) = url {
                let url = url.trim().trim_end_matches('/').to_string();
                if !url.is_empty() && !url.starts_with("https://") {
                    bail!(t!("Public address: https://…", "Adresse publique : https://…"));
                }
                changed.insert("url".into(), json!(url));
            }
            if let Some(g) = group {
                changed.insert("groupe".into(), json!(g.trim()));
            }
            if let Some(h) = duration {
                if !(1..=12).contains(&h) {
                    bail!(t!("Web session duration: 1 to 12 hours", "Durée d'une session web : 1 à 12 heures"));
                }
                changed.insert("duree_h".into(), json!(h));
            }
            if let Some(m) = idle {
                if !(5..=240).contains(&m) {
                    bail!(t!("Inactivity: 5 to 240 minutes", "Inactivité : 5 à 240 minutes"));
                }
                changed.insert("inactivite_min".into(), json!(m));
            }
            if let Some(v) = clipboard {
                changed.insert("presse_papiers".into(), json!(v));
            }
            if let Some(v) = code {
                changed.insert("code_toujours".into(), json!(v));
            }
            if let Some(site) = turnstile_site {
                changed.insert("turnstile_site".into(), json!(site.trim()));
            }
            if let Some(url) = internal_url {
                let url = url.trim().trim_end_matches('/').to_string();
                if !url.is_empty() && !url.starts_with("https://") {
                    bail!(t!("Internal address: https://…", "Adresse interne : https://…"));
                }
                changed.insert("interne_url".into(), json!(url));
            }
            if let Some(v) = internal_code {
                changed.insert("interne_code_toujours".into(), json!(v));
            }
            // Tout est vérifié avant d'écrire : une valeur refusée ne laisse rien à moitié changé.
            for (key, value) in &changed {
                model::set_setting(db, &format!("portail_{key}"), value.clone()).await?;
            }
            if turnstile_secret {
                let secret = prompt_secret(t!("Turnstile secret key (empty: erase): ", "Clé secrète Turnstile (vide : l'effacer) : "))?;
                let sealed = if secret.trim().is_empty() { String::new() } else { portal::seal_turnstile(state, secret.trim())? };
                model::set_setting(db, "portail_turnstile_secret", json!(sealed)).await?;
                changed.insert("turnstile_secret".into(), json!(if sealed.is_empty() { "effacé" } else { "changé" }));
            }
            anyhow::ensure!(!changed.is_empty(), t!("Nothing to change: see portunia-gate portal set --help", "Rien à changer : voir portunia-gate portal set --help"));
            audit::log(db, "console", "portail.modifie", serde_json::Value::Object(changed)).await?;
            println!("✓ {}", t!("Portal settings saved: open sessions are rechecked within 30 seconds.", "Réglages du portail enregistrés : les sessions ouvertes sont revérifiées sous 30 secondes."));
            return Ok(());
        }
        PortalCmd::CloseSessions => {
            let open = close_web_sessions(db).await?;
            audit::log(db, "console", "portail.sessions_fermees", json!({ "connexions": open })).await?;
            println!("✓ {}", t!(format!("{open} web sign-in(s) ended; open web terminals close within 30 seconds."), format!("{open} connexion(s) web terminée(s) ; les terminaux web ouverts se ferment sous 30 secondes.")));
            return Ok(());
        }
        PortalCmd::Test => {
            let r = tunnel::check(state).await?;
            let ok = r["ok"] == json!(true);
            println!("{} {}", if ok { "✓" } else { "✗" }, r["message"].as_str().unwrap_or_default());
            if !ok {
                std::process::exit(1);
            }
            return Ok(());
        }
        PortalCmd::Acme { domains, email, method, staging, cloudflare_token, accept_terms, off, renew } => {
            let current = acme::config(state).await?;
            let changing = off || domains.is_some() || email.is_some() || method.is_some() || staging.is_some() || cloudflare_token;
            if changing {
                let turn_on = !off && (current.actif || domains.is_some());
                if turn_on && !current.actif && !accept_terms {
                    bail!(t!(
                        format!("Read the Let's Encrypt Subscriber Agreement ({}), then add --accept-terms", acme::TERMS),
                        format!("Lisez les conditions d'utilisation de Let's Encrypt ({}), puis ajoutez --accept-terms", acme::TERMS)
                    ));
                }
                let token = if cloudflare_token {
                    Some(prompt_secret(t!("Cloudflare API token (empty: erase): ", "Jeton d'API Cloudflare (vide : l'effacer) : "))?)
                } else {
                    None
                };
                let c = acme::update(
                    state,
                    acme::Update {
                        actif: turn_on,
                        domaines: domains.unwrap_or_else(|| current.domaines.clone()),
                        email: email.unwrap_or_else(|| current.email.clone()),
                        methode: method.unwrap_or_else(|| if current.methode.is_empty() { "tls-alpn".into() } else { current.methode.clone() }),
                        essai: staging.unwrap_or(current.essai),
                        cloudflare_jeton: token.clone(),
                    },
                )
                .await?;
                model::bump_setting(db, live::ACME_WAKE).await?;
                audit::log(
                    db,
                    "console",
                    "portail.acme",
                    json!({ "actif": c.actif, "domaines": c.domaines, "methode": c.methode, "essai": c.essai, "jeton_cloudflare_change": token.is_some() }),
                )
                .await?;
                println!(
                    "✓ {}",
                    if c.actif {
                        t!("Let's Encrypt on: the service requests the certificate within 30 seconds (portal acme to follow).", "Let's Encrypt activé : le service demande le certificat sous 30 secondes (portal acme pour suivre).")
                    } else {
                        t!("Let's Encrypt off.", "Let's Encrypt désactivé.")
                    }
                );
            }
            if renew {
                anyhow::ensure!(acme::config(state).await?.actif, t!("Let's Encrypt is not enabled", "Let's Encrypt n'est pas activé"));
                model::bump_setting(db, live::ACME_WAKE).await?;
                audit::log(db, "console", "portail.acme_renouveler", json!({})).await?;
                println!("✓ {}", t!("Renewal requested: done by the service within 30 seconds.", "Renouvellement demandé : fait par le service sous 30 secondes."));
            }
            if !changing && !renew {
                let c = acme::config(state).await?;
                println!("Let's Encrypt : {}", if c.actif { t!("on", "activé") } else { t!("off", "désactivé") });
                if c.actif || !c.domaines.is_empty() {
                    println!("{} {}", t!("Domains:", "Domaines :"), c.domaines.join(", "));
                    println!("{} {}", t!("Email:", "E-mail :"), if c.email.is_empty() { "—" } else { &c.email });
                    println!("{} {}{}", t!("Check:", "Vérification :"), if c.methode.is_empty() { "tls-alpn" } else { &c.methode }, if c.essai { t!(" (test authority)", " (autorité d'essai)") } else { "" });
                }
                if let Some(live) = service_snapshot(state).await? {
                    let a = &live["acme"];
                    for (label, key) in [(t!("State:", "État :"), "etat"), (t!("Step:", "Étape :"), "etape"), (t!("Error:", "Erreur :"), "erreur"), (t!("Last:", "Dernier :"), "derniere"), (t!("Next:", "Prochain :"), "prochaine")] {
                        if let Some(v) = a[key].as_str() {
                            println!("{label} {v}");
                        }
                    }
                }
            }
            return Ok(());
        }
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
        PortalCmd::Tcp { api, ssh, rdp, publish } => {
            let mut hosts = cfaccess::hosts(state).await?;
            let changed = api.is_some() || ssh.is_some() || rdp.is_some() || publish;
            if let Some(v) = api {
                hosts.api = v;
            }
            if let Some(v) = ssh {
                hosts.ssh = v;
            }
            if let Some(v) = rdp {
                hosts.rdp = v;
            }
            if changed {
                let saved = if publish {
                    let token = prompt_secret(t!("Cloudflare API token (Cloudflare Tunnel › Edit, DNS › Edit): ", "Jeton d'API Cloudflare (Cloudflare Tunnel › Edit, DNS › Edit) : "))?;
                    let (saved, done) = cfaccess::publish(state, &token, &hosts).await?;
                    for line in done {
                        println!("✓ {line}");
                    }
                    saved
                } else {
                    cfaccess::set_hosts(state, &hosts).await?
                };
                audit::log(&state.db, "console", "acces_cloudflare.modifie", json!({ "hotes": saved, "publie": publish })).await?;
                hosts = saved;
            }
            let show = |h: &str| if h.is_empty() { "—".to_string() } else { h.to_string() };
            println!("API : {}", show(&hosts.api));
            println!("SSH : {}", show(&hosts.ssh));
            println!("RDP : {}", show(&hosts.rdp));
            if !hosts.rdp.is_empty() && !rdpnative::settings(state).await?.enabled {
                println!("{}", t!("(native RDP is off: sudo portunia-gate rdp on)", "(RDP natif coupé : sudo portunia-gate rdp on)"));
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
            let s = portal::settings(state).await?;
            let yes_no = |b: bool| if b { t!("yes", "oui") } else { t!("no", "non") };
            println!("{} {}", t!("Portal:", "Portail :"), if s.enabled { t!("open", "ouvert") } else { t!("closed", "fermé") });
            println!("{} {}", t!("Public address:", "Adresse publique :"), if s.url.is_empty() { "—" } else { &s.url });
            println!("{} {}", t!("Allowed group:", "Groupe autorisé :"), s.group);
            println!("{} {} h · {} {} min", t!("Web session:", "Session web :"), s.hours, t!("inactivity", "inactivité"), s.idle_min);
            println!("{} {}", t!("Copy-paste:", "Copier-coller :"), yes_no(s.clipboard));
            println!(
                "{} {}",
                t!("Authenticator code:", "Code d'authentification :"),
                if s.code_always { t!("required (except accounts exempted by their own combinations)", "exigé (sauf comptes exemptés par leurs combinaisons propres)") } else { t!("not required (except accounts whose own combinations demand it)", "non exigé (sauf comptes dont les combinaisons propres l'imposent)") }
            );
            println!(
                "Turnstile : {}{}",
                if s.turnstile_site.is_empty() { "—" } else { &s.turnstile_site },
                if s.turnstile_secret.is_some() { t!(" (secret key set)", " (clé secrète définie)") } else { "" }
            );
            let open: i64 = sqlx::query_scalar("SELECT count(*) FROM web_sessions WHERE expires_at > now()").fetch_one(db).await?;
            println!("{} {open}", t!("Web sign-ins under way:", "Connexions web en cours :"));
            if let Some(live) = service_snapshot(state).await? {
                let t = &live["tunnel"];
                if t["jeton_defini"] == json!(true) {
                    println!(
                        "{} {}{}",
                        t!("Managed Cloudflare tunnel:", "Tunnel Cloudflare géré :"),
                        t["etat"].as_str().unwrap_or("?"),
                        t["erreur"].as_str().map(|e| format!(" — {e}")).unwrap_or_default()
                    );
                } else if t["externe"] == json!(true) {
                    println!("{} {}", t!("Separate cloudflared:", "cloudflared à part :"), if t["externe_relie"] == json!(true) { t!("connected", "relié") } else { t!("not connected", "non relié") });
                }
                let h = &live["https"];
                println!(
                    "{} {}{}",
                    t!("HTTPS listener:", "Écoute HTTPS :"),
                    h["ouverte"].as_str().unwrap_or("—"),
                    h["erreur"].as_str().map(|e| format!(" — {e}")).unwrap_or_default()
                );
                println!("{} {}", t!("Open web terminals:", "Terminaux web ouverts :"), live["terminaux_web"]);
            }
            portal::reload_exposure(state).await?;
            portal::exposure(state)
        }
        PortalCmd::Expose { mode, internal, internal_networks, trusted, header, networks } => {
            let inner = internal_networks.map(|v| vec![v]);
            let change = portal::InternalChange { open: internal, networks: inner.as_deref() };
            let e = portal::set_exposure(state, mode.as_deref(), trusted.map(|v| vec![v]).as_deref(), header.as_deref(), networks.map(|v| vec![v]).as_deref(), change).await?;
            audit::log(&state.db, "console", "portail.exposition", portal::exposure_note(&e)).await?;
            println!("✓ {}", t!("Saved: applied within 30 seconds", "Enregistré : appliqué sous 30 secondes"));
            e
        }
    };
    let s = portal::settings(state).await?;
    println!("{} {}", t!("External entry:", "Entrée externe :"), if e.mode == portal::Mode::Internal { "—".to_string() } else { e.mode.id().to_string() });
    println!("{} {}", t!("Trusted proxies:", "Proxys de confiance :"), e.proxies.join(", "));
    println!("{} {}", t!("Address header:", "En-tête de l'adresse :"), e.header);
    println!("{} {}", t!("Allowed networks (direct):", "Réseaux autorisés (direct) :"), e.networks.join(", "));
    if e.internal_open() {
        println!(
            "{} {} · {} · {}",
            t!("Internal entry:", "Entrée interne :"),
            if e.internal_networks.is_empty() { t!("private networks", "réseaux privés").to_string() } else { e.internal_networks.join(", ") },
            if s.internal_url.is_empty() { "—" } else { &s.internal_url },
            if s.internal_code_always { t!("code required", "code exigé") } else { t!("code per account", "code selon le compte") }
        );
    } else {
        println!("{} {}", t!("Internal entry:", "Entrée interne :"), t!("closed", "fermée"));
    }
    Ok(())
}

/// Termine les connexions web et demande au service (autre processus) de fermer les terminaux
/// web ouverts, au plus tard à sa prochaine vérification (live.rs). Renvoie le nombre de connexions.
async fn close_web_sessions(db: &PgPool) -> Result<u64> {
    let done = sqlx::query("DELETE FROM web_sessions").execute(db).await?;
    model::bump_setting(db, live::PORTAL_CLOSE).await?;
    Ok(done.rows_affected())
}

/// État en direct écrit par le service à chaque tour (live.rs) ; prévient s'il est ancien.
async fn service_snapshot(state: &State) -> Result<Option<serde_json::Value>> {
    let Some(live) = model::setting(&state.db, live::SNAPSHOT).await? else {
        println!("{}", t!("(No live state: the service has not run since version 0.26.)", "(Pas d'état en direct : le service n'a pas tourné depuis la version 0.26.)"));
        return Ok(None);
    };
    let age = live["date"]
        .as_str()
        .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
        .map(|d| (chrono::Utc::now() - d.with_timezone(&chrono::Utc)).num_seconds());
    if age.is_none_or(|a| a > 120) {
        println!(
            "⚠ {}",
            t!("Live state older than 2 minutes: is the service running? (systemctl status portunia-gate)", "État en direct vieux de plus de 2 minutes : le service tourne-t-il ? (systemctl status portunia-gate)")
        );
    }
    Ok(Some(live))
}

async fn rdp_cmd(state: &State, cmd: RdpCmd) -> Result<()> {
    let db = &state.db;
    match cmd {
        RdpCmd::Show => {
            let s = rdpnative::settings(state).await?;
            println!("{} {}", t!("Native RDP entry:", "Entrée RDP native :"), if s.enabled { t!("open", "ouverte") } else { t!("closed", "fermée") });
            println!("{} {}", t!("Port:", "Port :"), s.port);
            println!(
                "{} {}",
                t!("Address in the .rdp files:", "Adresse dans les fichiers .rdp :"),
                if s.address.is_empty() { t!("the Gate's address known to Portunia", "l'adresse de la Gate que connaît Portunia").to_string() } else { s.address.clone() }
            );
            println!("{} {}", t!("Modes:", "Modes :"), if s.modes.is_empty() { "—".to_string() } else { s.modes.join(", ") });
            println!("{} {} s", t!("Validity of a .rdp file:", "Validité d'un fichier .rdp :"), s.ticket_s);
            println!("{} {}", t!("Certificate shown to RDP clients", "Certificat présenté aux clients RDP"), tls::fingerprint(&state.config.data_dir)?);
            if let Some(live) = service_snapshot(state).await? {
                let native = &live["rdp_natif"];
                match (native["ouverte"].as_str(), native["erreur"].as_str()) {
                    (Some(addr), _) => println!("{} {addr}", t!("Listening on", "En écoute sur")),
                    (None, Some(e)) => println!("⚠ {} {e}", t!("Not listening:", "Pas en écoute :")),
                    _ if s.enabled => println!("{}", t!("Not listening yet (within 3 seconds).", "Pas encore en écoute (sous 3 secondes).")),
                    _ => {}
                }
            }
        }
        RdpCmd::On | RdpCmd::Off => {
            let on = matches!(cmd, RdpCmd::On);
            model::set_setting(db, "rdp_natif_actif", json!(on)).await?;
            audit::log(db, "console", "rdp_natif.reglage", json!({ "actif": on })).await?;
            if on {
                let s = rdpnative::settings(state).await?;
                println!("✓ {}", t!(format!("Native RDP entry open: listening on port {} within 3 seconds.", s.port), format!("Entrée RDP native ouverte : en écoute sur le port {} sous 3 secondes.", s.port)));
                println!("  {}", t!("Open this port on the firewall (and publish it with Docker).", "Ouvrez ce port sur le pare-feu (et publiez-le avec Docker)."));
            } else {
                println!("✓ {}", t!("Native RDP entry closed; sessions under way continue.", "Entrée RDP native fermée ; les sessions en cours continuent."));
            }
        }
        RdpCmd::Set { port, address, modes, ticket_seconds } => {
            let mut changed = serde_json::Map::new();
            if let Some(p) = port {
                anyhow::ensure!(p > 0, t!("Port: 1 to 65535", "Port : 1 à 65535"));
                changed.insert("port".into(), json!(p));
            }
            if let Some(a) = address {
                let a = a.trim().to_string();
                rdpnative::check_address(&a)?;
                changed.insert("adresse".into(), json!(a));
            }
            if let Some(m) = modes {
                let list: Vec<String> = m.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                if let Some(bad) = list.iter().find(|x| !rdpnative::MODES.contains(&x.as_str())) {
                    bail!(t!(format!("Unknown mode: {bad} (rebond, coffre, enregistre)"), format!("Mode inconnu : {bad} (rebond, coffre, enregistre)")));
                }
                changed.insert("modes".into(), json!(list));
            }
            if let Some(sec) = ticket_seconds {
                anyhow::ensure!((30..=600).contains(&sec), t!("Validity of the .rdp file: 30 to 600 seconds", "Validité du fichier .rdp : 30 à 600 secondes"));
                changed.insert("jeton_s".into(), json!(sec));
            }
            anyhow::ensure!(!changed.is_empty(), t!("Nothing to change: --port, --address, --modes or --ticket-seconds", "Rien à changer : --port, --address, --modes ou --ticket-seconds"));
            for (key, value) in &changed {
                model::set_setting(db, &format!("rdp_natif_{key}"), value.clone()).await?;
            }
            audit::log(db, "console", "rdp_natif.reglage", serde_json::Value::Object(changed)).await?;
            println!("✓ {}", t!("Native RDP settings saved (applied within 3 seconds).", "Réglages du RDP natif enregistrés (appliqués sous 3 secondes)."));
        }
        RdpCmd::Port => {
            let s = rdpnative::settings(state).await?;
            if s.enabled {
                println!("{}", s.port);
            }
        }
    }
    Ok(())
}

async fn assist_cmd(state: &State, cmd: AssistCmd) -> Result<()> {
    let db = &state.db;
    match cmd {
        AssistCmd::Show => {
            let s = assist::settings(state).await?;
            let portal = portal::settings(state).await?;
            println!("{} {}", t!("Assistance:", "Assistance :"), if s.enabled { t!("open", "ouverte") } else { t!("closed", "fermée") });
            println!("{} {}", t!("Technicians' group:", "Groupe des dépanneurs :"), s.group);
            println!("{} {} h", t!("Maximum duration:", "Durée maximale :"), s.hours);
            println!("{} {}", t!("Portunia Assistance program:", "Programme Portunia Assistance :"), if assist::agent_file(state).exists() { t!("ready", "prêt") } else { t!("not downloaded yet", "pas encore téléchargé") });
            if let Some(live) = service_snapshot(state).await? {
                println!("{} {}", t!("People waiting for a technician:", "Personnes en attente d'un dépanneur :"), live["assistance_en_attente"]);
            }
            println!(
                "{} {}",
                t!("Page for the person helped:", "Page de la personne aidée :"),
                if portal.url.is_empty() { t!("— (set the portal's public address: portal set --url)", "— (réglez l'adresse publique du portail : portal set --url)").to_string() } else { format!("{}/assistance", portal.url) }
            );
        }
        AssistCmd::On | AssistCmd::Off => {
            let on = matches!(cmd, AssistCmd::On);
            model::set_setting(db, "assistance_actif", json!(on)).await?;
            audit::log(db, "console", "assistance.reglage", json!({ "actif": on })).await?;
            if on {
                let s = assist::settings(state).await?;
                println!("✓ {}", t!("Assistance open: the Gate fetches Portunia Assistance within 30 seconds.", "Assistance ouverte : la Gate récupère Portunia Assistance sous 30 secondes."));
                if model::group_id(db, &s.group).await.is_err() {
                    println!("  {}", t!(format!("Group « {} » missing: no technician can help (group add, group member).", s.group), format!("Groupe « {} » absent : aucun dépanneur ne peut aider (group add, group member).", s.group)));
                }
            } else {
                println!("✓ {}", t!("Assistance closed: sessions under way stop within 30 seconds.", "Assistance fermée : les sessions en cours s'arrêtent sous 30 secondes."));
            }
        }
        AssistCmd::Set { group, duration } => {
            let mut changed = serde_json::Map::new();
            if let Some(h) = duration {
                if !(1..=12).contains(&h) {
                    bail!(t!("Session duration: 1 to 12 hours", "Durée d'une assistance : 1 à 12 heures"));
                }
                changed.insert("duree_h".into(), json!(h));
            }
            if let Some(g) = group {
                changed.insert("groupe".into(), json!(g.trim()));
            }
            anyhow::ensure!(!changed.is_empty(), t!("Nothing to change: --group or --duration", "Rien à changer : --group ou --duration"));
            for (key, value) in &changed {
                model::set_setting(db, &format!("assistance_{key}"), value.clone()).await?;
            }
            audit::log(db, "console", "assistance.reglage", serde_json::Value::Object(changed)).await?;
            println!("✓ {}", t!("Assistance settings saved.", "Réglages de l'assistance enregistrés."));
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
            files,
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
            let hours = hours.as_deref().map(parse_hours).transpose()?;
            let expires_at = expires.as_deref().map(parse_expiry).transpose()?;
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
                    allow_files: files,
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
                json!({ "regle": name, "groupe": group, "cibles": targets, "sftp": sftp, "tunnels": tunnels, "frappe": record_input, "fichiers": files }),
            )
            .await?;
            println!("{}", t!("Rule created.", "Règle créée."));
        }
        RuleCmd::List => {
            for r in rules(db).await? {
                let state = match model::rule_state(r.days, r.hour_from, r.hour_to, r.expires_at) {
                    "active" => t!("active", "active"),
                    "expiree" => t!("expired", "expirée"),
                    _ => t!("outside hours", "hors plage"),
                };
                let mut options = Vec::new();
                for (on, label) in [(r.allow_sftp, "sftp"), (r.allow_tunnels, "tunnels"), (r.record_input, t!("keystrokes", "frappe")), (r.allow_files, t!("files", "fichiers"))] {
                    if on {
                        options.push(label);
                    }
                }
                let hours = match (r.hour_from, r.hour_to) {
                    (Some(a), Some(b)) => format!("{a}-{b}h"),
                    _ => t!("all day", "toute la journée").into(),
                };
                let expires = r.expires_at.map(|e| format!(" {} {}", t!("until", "jusqu'au"), e.with_timezone(&chrono::Local).format("%Y-%m-%d"))).unwrap_or_default();
                println!(
                    "{:<20} {:<12} {:<18} {}  {} {}{}  [{}]",
                    r.name,
                    state,
                    r.group_name,
                    r.targets.join(","),
                    days_label(r.days),
                    hours,
                    expires,
                    options.join(", ")
                );
            }
        }
        RuleCmd::Edit {
            name,
            rename,
            group,
            targets,
            sftp,
            tunnels,
            record_input,
            files,
            days,
            hours,
            expires,
        } => {
            let r = rules(db).await?
                .into_iter()
                .find(|r| r.name == name)
                .ok_or_else(|| anyhow!(t!(format!("Unknown rule: {name}"), format!("Règle inconnue : {name}"))))?;
            let new_name = rename.map(|n| n.trim().to_string()).unwrap_or_else(|| r.name.clone());
            if new_name.is_empty() {
                bail!(t!("Rule name required", "Nom de la règle obligatoire"));
            }
            let group_name = group.unwrap_or_else(|| r.group_name.clone());
            let group_id = model::group_id(db, &group_name).await?;
            let target_names = targets.unwrap_or_else(|| r.targets.clone());
            let mut ids = Vec::new();
            for t in &target_names {
                ids.push(find_target(db, t).await?.id);
            }
            if ids.is_empty() {
                bail!(t!("Give at least one target (--targets a,b)", "Indiquez au moins une cible (--targets a,b)"));
            }
            let days = match days.as_deref().map(str::trim) {
                Some("") => 127,
                Some(d) => parse_days(d)?,
                None => r.days,
            };
            let hours = match hours.as_deref().map(str::trim) {
                Some("") => None,
                Some(h) => Some(parse_hours(h)?),
                None => r.hour_from.zip(r.hour_to),
            };
            let expires_at = match expires.as_deref().map(str::trim) {
                Some("") => None,
                Some(d) => Some(parse_expiry(d)?),
                None => r.expires_at,
            };
            let (sftp, tunnels, record_input) = (sftp.unwrap_or(r.allow_sftp), tunnels.unwrap_or(r.allow_tunnels), record_input.unwrap_or(r.record_input));
            let files = files.unwrap_or(r.allow_files);
            let mut tx = db.begin().await?;
            sqlx::query(
                "UPDATE rules SET name = $2, group_id = $3, allow_sftp = $4, allow_tunnels = $5, record_input = $6, days = $7,
                 hour_from = $8, hour_to = $9, expires_at = $10, allow_files = $11 WHERE id = $1",
            )
            .bind(r.id)
            .bind(&new_name)
            .bind(group_id)
            .bind(sftp)
            .bind(tunnels)
            .bind(record_input)
            .bind(days)
            .bind(hours.map(|h| h.0))
            .bind(hours.map(|h| h.1))
            .bind(expires_at)
            .bind(files)
            .execute(&mut *tx)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(d) if d.code().as_deref() == Some("23505") => anyhow!(t!("This name is already taken", "Ce nom est déjà pris")),
                _ => e.into(),
            })?;
            sqlx::query("DELETE FROM rule_targets WHERE rule_id = $1").bind(r.id).execute(&mut *tx).await?;
            for t in ids {
                sqlx::query("INSERT INTO rule_targets (rule_id, target_id) VALUES ($1, $2)")
                    .bind(r.id)
                    .bind(t)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
            audit::log(
                db,
                "console",
                "regle.modifiee",
                json!({ "regle": new_name, "groupe": group_name, "cibles": target_names, "sftp": sftp, "tunnels": tunnels, "frappe": record_input, "jours": days, "fichiers": files, "heures": hours, "expire": expires_at }),
            )
            .await?;
            println!("{}", t!("Rule changed: open sessions are rechecked within 30 seconds.", "Règle modifiée : les sessions ouvertes sont revérifiées sous 30 secondes."));
        }
        RuleCmd::Approval { name, on, approvers } => {
            let id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM rules WHERE name = $1")
                .bind(&name)
                .fetch_optional(db)
                .await?
                .ok_or_else(|| anyhow!(t!(format!("Unknown rule: {name}"), format!("Règle inconnue : {name}"))))?;
            sqlx::query("UPDATE rules SET approval = $2 WHERE id = $1").bind(id).bind(on).execute(db).await?;
            if let Some(g) = &approvers {
                let group = match g.trim() {
                    "" => None,
                    n => Some(model::group_id(db, n).await?),
                };
                sqlx::query("UPDATE rules SET approver_group = $2 WHERE id = $1").bind(id).bind(group).execute(db).await?;
            }
            audit::log(db, "console", "regle.modifiee", json!({ "regle": name, "approbation": on, "approbateurs": approvers })).await?;
            println!("{}", if on {
                t!("Approval required: open sessions without an approved access close within 30 seconds.", "Approbation exigée : les sessions ouvertes sans accès approuvé se ferment sous 30 secondes.")
            } else {
                t!("Approval no longer required.", "Approbation plus exigée.")
            });
        }
        RuleCmd::Delete { name } => {
            let gone: Option<String> = sqlx::query_scalar("DELETE FROM rules WHERE name = $1 RETURNING name")
                .bind(&name)
                .fetch_optional(db)
                .await?;
            let gone = gone.ok_or_else(|| anyhow!(t!(format!("Unknown rule: {name}"), format!("Règle inconnue : {name}"))))?;
            audit::log(db, "console", "regle.supprimee", json!({ "regle": gone })).await?;
            println!("{}", t!("Rule deleted: sessions it allowed close within 30 seconds.", "Règle supprimée : les sessions qu'elle permettait se ferment sous 30 secondes."));
        }
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: uuid::Uuid,
    name: String,
    group_name: String,
    allow_sftp: bool,
    allow_tunnels: bool,
    record_input: bool,
    allow_files: bool,
    days: i16,
    hour_from: Option<i16>,
    hour_to: Option<i16>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    targets: Vec<String>,
}

async fn rules(db: &PgPool) -> Result<Vec<RuleRow>> {
    Ok(sqlx::query_as(
        "SELECT r.id, r.name, g.name AS group_name, r.allow_sftp, r.allow_tunnels, r.record_input, r.allow_files, r.days, r.hour_from, r.hour_to, r.expires_at,
                COALESCE(array_agg(t.name ORDER BY t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS targets
         FROM rules r JOIN groups g ON g.id = r.group_id
         LEFT JOIN rule_targets rt ON rt.rule_id = r.id LEFT JOIN targets t ON t.id = rt.target_id
         GROUP BY r.id, g.name ORDER BY r.name",
    )
    .fetch_all(db)
    .await?)
}

/// Jours d'une règle, lisibles : « tous les jours », « lun-ven », « lun,mer,ven ».
fn days_label(mask: i16) -> String {
    const FR: [&str; 7] = ["lun", "mar", "mer", "jeu", "ven", "sam", "dim"];
    const EN: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    let names = if lang::is_fr() { FR } else { EN };
    match mask {
        127 => t!("every day", "tous les jours").into(),
        0b0011111 => format!("{}-{}", names[0], names[4]),
        _ => (0..7).filter(|d| mask & (1 << d) != 0).map(|d| names[d]).collect::<Vec<_>>().join(","),
    }
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

    #[test]
    fn interrupteur() {
        assert_eq!(super::parse_switch("on"), Ok(true));
        assert_eq!(super::parse_switch("Oui"), Ok(true));
        assert_eq!(super::parse_switch("off"), Ok(false));
        assert!(super::parse_switch("peut-être").is_err());
    }

    #[test]
    fn heures() {
        assert_eq!(super::parse_hours("7-20").unwrap(), (7, 20));
        assert_eq!(super::parse_hours("22-6").unwrap(), (22, 6), "plage qui passe minuit");
        assert!(super::parse_hours("7").is_err());
        assert!(super::parse_hours("8-8").is_err());
        assert!(super::parse_hours("0-25").is_err());
    }

    #[test]
    fn jours_lisibles() {
        assert_eq!(super::days_label(0b0011111), super::days_label(super::parse_days("mon-fri").unwrap()));
        assert!(super::days_label(0b0010101).split(',').count() == 3);
    }

    #[test]
    fn commandes_valides() {
        use clap::CommandFactory;
        super::Cli::command().debug_assert();
    }
}
