# Portunia Gate

**English** · [Français](README.fr.md)

SSH and Remote Desktop gateway for [Portunia](https://github.com/jpiperault/Portunia): users go through Portunia Gate to reach servers. Portunia Gate checks who they are, decides where they may go, supplies the server account when needed without ever showing it, records sessions and keeps a tamper-evident audit log.

> Status: **version 0.8, recorded Remote Desktop**, also in the browser (web portal); SSH web portal (0.7), jump Remote Desktop (0.6), SSH session replay (0.5). See the [Roadmap](#roadmap).

## What Portunia Gate does

| | |
|---|---|
| **Three modes per server** | **Jump**: end-to-end relay (`ssh -J`); the Gate does not see the content, it logs the connection. **Recorded**: the Gate relays and records the session; users type their own credentials. **Vault**: like Recorded, and the Gate supplies the server account, which the user never knows. |
| **Signing in to the Gate** | Password, SSH key and TOTP code (Google Authenticator, Microsoft Authenticator…), in any combination: a global policy and a per-account policy. A code works only once. |
| **Permissions** | Rules link a group to servers, with days, hours, an expiry date, and SFTP and tunnels allowed or not. Anything not allowed is denied. |
| **Recording** | Asciicast format (readable by Portunia and asciinema), screen only or keystrokes too, depending on the rule. Every file is signed by the Gate. |
| **Replay** | In Portunia, like a video: keystrokes as subtitles, idle time skipped, sensitive commands highlighted, search across all sessions. Typed passwords are masked; every replay is written to the audit log. |
| **Audit log** | Sign-ins, failures, sessions, administration changes. Each event contains the fingerprint of the previous one: a deleted or edited line shows (`portunia-gate audit --verify`). |
| **Portunia** | Portunia Gate extension: the Gate appears in the sidebar, its servers open with a one-time token, administrators manage everything from Portunia (servers and vault, accounts, groups, rules, settings) and auditors replay sessions and read the log. |
| **Remote Desktop** | Windows servers (RDP) behind the Gate, opened from Portunia or the web portal. Jump, Recorded and Vault modes (see [Remote Desktop](#remote-desktop-rdp)). |
| **Web portal** | For people without Portunia at hand: a sign-in page, a terminal and Remote Desktop in the browser, behind Cloudflare, with no open port. Turned on or off with one click in Portunia (see [Web portal](#web-portal)). |
| **Other clients** | Any SSH client: OpenSSH, PuTTY, MobaXterm, WinSCP (SFTP). |

## Install

Two ways to install, with the same setup wizard:

| | **Debian package** (recommended) | **Docker** |
|---|---|---|
| Install time | 1 to 2 minutes: package already built | 10 to 30 minutes: built on the server |
| Suggested server | 1 CPU, 2 GB RAM, 10 GB disk | 2 CPUs, 4 GB RAM, 20 GB disk |
| LXC container | Nothing to enable | *nesting* and *keyctl* options required |
| How it runs | Hardened systemd service, the distribution's PostgreSQL | Two containers (Portunia Gate and PostgreSQL) |
| Updating | `sudo bash installer.sh update` (downloads the latest version) | `sudo ./installer.sh update` (`git pull`, then rebuild) |
| Processors | x86-64 (amd64) | x86-64 and ARM |

Either way: a **Debian 12 or 13** or **Ubuntu 22.04 or later** server (virtual machine or LXC container) with root or sudo access, and ports **2222** (SSH) and **8443** (API for Portunia) reachable from users' computers.

### Debian package

```bash
curl -fsSLO https://github.com/jpiperault/Portunia-Gate-releases/releases/latest/download/installer.sh
sudo bash installer.sh
```

The wizard downloads the latest Portunia Gate version, checks its SHA-256 fingerprint, installs the package and PostgreSQL, creates the database (local socket access, no password) and the `portunia-gate` service.

Installed files:

| | |
|---|---|
| `/usr/lib/portunia-gate/portunia-gate` | The program |
| `/usr/bin/portunia-gate` | The administration command (`sudo portunia-gate …`) |
| `/etc/portunia-gate/portunia-gate.env` | Settings: ports, time zone, database access |
| `/var/lib/portunia-gate/` | Keys, API certificate, session recordings |
| PostgreSQL database `portunia_gate` | Accounts, servers, rules, sessions, audit log |

The service runs under a dedicated system account (`_portunia_gate`), writes only to `/var/lib/portunia-gate` and sees neither home folders nor the rest of the system. Useful commands: `sudo systemctl status portunia-gate`, `sudo journalctl -u portunia-gate -f`.

Install a specific package (no Internet access, or an older version): `sudo bash installer.sh --package portunia-gate_0.4.0_amd64.deb`.

### Docker

```bash
git clone https://github.com/jpiperault/Portunia-Gate.git
cd Portunia-Gate
sudo ./installer.sh --docker
```

The repository is private: `git clone` asks for your GitHub username and, as the password, an access token (GitHub › Settings › Developer settings › Personal access tokens, read access to the repository). The wizard installs Docker if needed and, with less than 4 GB of RAM, offers a temporary swap file for the build. In a Proxmox LXC container, first enable *nesting* and *keyctl* (Options › Features), then restart the container.

### The questions

The wizard asks five questions; Enter keeps the suggested value:

| Question | Suggested value | |
|---|---|---|
| Gate name | Portunia Gate | Shown in Portunia and in the authenticator app. |
| Administrator login | admin | Your account to administer the Gate from Portunia. |
| SSH port | 2222 | |
| API port | 8443 | |
| Time zone | the server's | Used by the time ranges of access rules. |

It then creates the keys, the certificate, the database and the administrator account, starts the Gate and shows what to enter in Portunia: address, certificate fingerprint, login and a **temporary password**. Portunia then asks the administrator to choose a password and scan a QR code with an authenticator app (leave the Code field empty on the first sign-in).

The Gate restarts on its own with the server.

### Back up the vault key, right away

The **vault key** encrypts server passwords and TOTP secrets. Without it, a restore loses all those secrets. The wizard puts a copy in your home folder (`~/portunia-gate-vault.key`): copy it off the server (password manager, company vault), then delete that copy. The wizard shows the exact commands, for example:

```bash
scp julien@192.168.1.20:/home/julien/portunia-gate-vault.key .   # from your computer
rm ~/portunia-gate-vault.key                                      # on the server
```

### Running the wizard again

`sudo bash installer.sh` on an installed Gate opens a menu:

| Choice | Direct command | |
|---|---|---|
| Information for Portunia | `sudo bash installer.sh info` | Address and fingerprint to give to users. |
| Update | `sudo bash installer.sh update` | Installs the latest version and restarts. **Open sessions are cut.** |
| Create an administrator | `sudo bash installer.sh admin julien` | Backup administrator with a temporary password, for example if the only administrator lost their phone. |
| Web portal | `sudo bash installer.sh portal` | Hands the Cloudflare tunnel token to the Gate (same as Administer › Web portal, see [Web portal](#web-portal)). |

With Docker, run the wizard from the repository folder (`sudo ./installer.sh`).

An interrupted install (power cut, error) resumes when you run the wizard again: settings already entered are offered again.

### Unattended install

Without a terminal, the wizard uses the suggested values, or those of the `PORTUNIA_GATE_NAME`, `PORTUNIA_GATE_ADMIN`, `PORTUNIA_GATE_SSH_PORT`, `PORTUNIA_GATE_API_PORT` and `TZ` variables:

```bash
sudo PORTUNIA_GATE_ADMIN=julien PORTUNIA_GATE_NAME="ACME Gate" bash installer.sh </dev/null
```

### Harden the server (optional)

On a server dedicated to the Gate, the assistant can keep only what is needed: firewall closed except the useful ports, unneeded services stopped, system SSH and kernel tightened, automatic security updates. Answer yes at install time, or use `--harden`, or later:

```bash
sudo bash installer.sh harden plan
sudo bash installer.sh harden
```

The plan changes nothing. If a new SSH connection is not confirmed within 5 minutes, the firewall and system SSH are put back as they were. Details and undoing: [operations](docs/operations.md).

### Company certificate

The API certificate is self-signed: Portunia recognises it by its fingerprint, which is enough. The certificate browsers see on the portal is a separate one, set in Administer › Web portal (see *Portal certificate*). To use a company certificate for the API (PEM files, certificate followed by its chain):

Debian package:

```bash
sudo install -o _portunia_gate -g _portunia_gate -m 600 cert.pem /var/lib/portunia-gate/entreprise.crt
sudo install -o _portunia_gate -g _portunia_gate -m 600 key.pem /var/lib/portunia-gate/entreprise.key
echo 'PORTUNIA_GATE_TLS_CERT=/var/lib/portunia-gate/entreprise.crt' | sudo tee -a /etc/portunia-gate/portunia-gate.env
echo 'PORTUNIA_GATE_TLS_KEY=/var/lib/portunia-gate/entreprise.key' | sudo tee -a /etc/portunia-gate/portunia-gate.env
sudo systemctl restart portunia-gate
```

Docker, from the repository folder:

```bash
sudo docker compose cp cert.pem portunia-gate:/var/lib/portunia-gate/entreprise.crt
sudo docker compose cp key.pem portunia-gate:/var/lib/portunia-gate/entreprise.key
echo 'PORTUNIA_GATE_TLS_CERT=/var/lib/portunia-gate/entreprise.crt' | sudo tee -a .env
echo 'PORTUNIA_GATE_TLS_KEY=/var/lib/portunia-gate/entreprise.key' | sudo tee -a .env
sudo docker compose up -d
```

The fingerprint changes: users will have to accept the new one (`sudo portunia-gate info`).

## Adding the Gate to Portunia

1. **Enable the extension**: Portunia › Extensions › Portunia Gate › Enable. The **Gates** section appears in the sidebar.
2. **Add the Gate**: Gates › **+** › type the address given by the wizard (`192.168.1.20`, or `192.168.1.20:9443` if you changed the API port).
3. **Check the fingerprint**: Portunia shows the Gate certificate's fingerprint. Compare it with the one given by the wizard (or `sudo portunia-gate info` on the server, "API certificate" line). If it differs, stop: someone may be impersonating the Gate.
4. **Sign in**: login and password; **leave the Code field empty** on the first sign-in.
5. **First sign-in**: Portunia asks you to choose a new password (at least 10 characters), then shows a QR code. Scan it with your authenticator app and type the 6-digit code it shows.
6. **Open a server**: allowed servers appear under the Gate, by folder. One click opens the session, without typing the code again (one-time token):
   - **vault**: direct connection, the Gate supplies the account;
   - **recorded**: the server asks for your credentials in the terminal;
   - **jump**: Portunia asks for your server credentials; the connection is end-to-end encrypted.
7. **Administer** (Portunia Teams, administrator account): Gate **⋯** menu › **Administer**. A tab opens with servers and vault, accounts, groups, rules, web portal and settings.
8. **Audit** (Portunia Teams, administrator or auditor account): Gate **⋯** menu › **Audit**. A tab opens with sessions and the log (see [Replaying sessions](#replaying-sessions)).

Further accounts are created from the administration tab: Portunia shows a temporary password to give to the user, who then follows steps 2 to 5.

Nothing shows under the Gate? No rule grants access to a server yet: create a server, a group containing the account, then a rule linking them.

## Replaying sessions

Gate **⋯** menu › **Audit** › **Sessions** (administrator and auditor roles).

**Live (0.36)**: **Audit** › **Live** lists the sessions open right now (SSH, Remote Desktop, web interfaces), refreshed every 10 seconds. **Follow** opens the player at the end of the session, which keeps growing as the session goes on (● LIVE): the screen, keystrokes if the rule records them, clicks, web actions. **Cut** closes the session at once; an administrator can also disable the account at the same time. Following is logged (`session.suivie`), cutting too (`session.coupee_par`). With the `live_notice` setting (on by default), an SSH user is told in their terminal that their session is followed. There is no taking over the keyboard. Command line: `sudo portunia-gate sessions cut ID [--disable]`.

**Finding a session**: filters by account, server and period, "With keystrokes" box. Search covers the keystrokes and the displayed text of all recorded sessions: the "Found" column gives the moment and the excerpt, and a click opens the replay at that point.

**The player**, in a tab:

| | |
|---|---|
| Playback | Play and pause (space bar), ±10 s (arrows: ±5 s), speed 1× to 16×, full screen. Clicking the timeline or a line of the panel jumps there. |
| Idle time | Periods with no activity longer than 5 s are hatched on the timeline and skipped during playback ("Skip pauses" button). |
| Subtitles | **CC Keystrokes** button: what the person types, special keys included (Enter, Tab, ⌫, Ctrl+C, arrows). |
| Markers | Every command; in orange sudo, Ctrl+C and masked input; in red sensitive commands; at the bottom, errors shown on screen. |
| Panel | **Keystrokes**: typed lines, time-stamped, with search. **Details**: account, server, mode, address, duration, fingerprint, signature, previous replays. |
| Signature | Checked on every opening. A file changed since the session is flagged in red. |
| Exports | **.cast recording** (readable by asciinema), **Transcript** (time-stamped text) and, with Portunia 0.76, **Video** (MP4 made on the workstation, keystrokes as subtitles plus an .srt file, watermark). Each export is logged since 0.37 (`enregistrement.exporte`). |
| Detach | **⧉ Detach** opens the player in its own window. |

**Masked input**: keystrokes not echoed on screen (sudo, su, ssh passwords…) are replaced by fixed-length dots, in the player as in search. They remain in the signed file: an administrator can **reveal** them (button in the player), and that replay is written to the log (`enregistrement.revele`). The `.cast` export of a masked replay is an unsigned copy; that of a revealed replay is the original, signed file.

**Sessions without keystrokes** (rule recording the screen only): no subtitles; the panel lists the commands detected on screen, after the prompt.

**Every replay is written to the log** (`enregistrement.consulte`), and the player shows the watching account as a watermark.

**Replaying one's own sessions**: Administer › Settings › "Each account can replay its own sessions". "User" accounts then see **My sessions** in the Gate menu, without being able to reveal masked input.

**Sensitive commands**: Administer › Settings, one per line (by default `rm -rf`, `mkfs`, `dd if=`, `shutdown`, `reboot`, `DROP TABLE`…).

Sessions recorded before version 0.5 can be replayed but are not included in search.

## Remote Desktop (RDP)

Windows servers are declared like the others: Administer › Servers and vault › **Add a server**, protocol **Remote Desktop (RDP)**, port 3389. They appear under the Gate in Portunia with an **RDP** badge and open in a Remote Desktop tab.

In Jump and Recorded modes, users type their Windows credentials each time; neither Portunia nor the Gate keeps them. In Vault mode (0.29), the Gate signs in to Windows itself with the account it keeps: users type nothing and never see the password.

| | **Jump** (0.6) | **Recorded** (0.8) | **Vault** (0.29) |
|---|---|---|---|
| Path | Tunnel through the Gate's SSH port (2222), with a one-time token; the RDP connection is end-to-end encrypted. | The Gate's gateway (RDCleanPath, on the API or portal port) with a one-time token: the Gate opens the encrypted connection to the Windows server and relays the session. | Same as Recorded. |
| What the Gate sees | None of the content; it checks the rule and logs (`rebond.ouvert`, duration, bytes). | The session (to record it), but not the password: Windows authentication (NLA) happens between the client and the server. | The session; the Gate performs the Windows authentication (NLA, NTLM) with the vault account, and the client authenticates to the Gate with its one-time token. The server must offer NLA. |
| Recording | No. | Yes, signed file (`.rdpcap`): the image sent by the server, clicks, copy-pastes (text masked until an administrator reveals it) and keystrokes if the rule records them. Replay in Portunia (0.47 or later), like an SSH session. | Yes, as in Recorded. |
| Clients | Portunia; the **web portal** too since 0.29, where the Gate relays without recording (a browser cannot tunnel end-to-end). | Portunia and the **web portal** (Remote Desktop in the browser). | Portunia and the web portal. |
| Server certificate | Checked by the client. | Checked by the Gate: fingerprint kept on first connection, connection refused if it changes (`cible.empreinte_differente`). | Checked by the Gate, as in Recorded. |

The Gate must reach port 3389 of the Windows servers. In Portunia, the Remote Desktop extension must be enabled; otherwise RDP servers stay visible, greyed out. An RDP server does not appear in the Gate's `ssh` menu and does not open as a terminal.

A vault RDP server keeps a password (local account or `DOMAIN\account`), not a key. If the password changes on the server, the connection fails with `cible.coffre_refuse`: replace the secret.

### Ordinary RDP clients (native RDP, 0.31)

Users can also open the Gate's Windows servers in an ordinary RDP client: **mstsc**, **Windows App** (Mac), **Remmina** or **FreeRDP**. Portunia prepares a **single-use .rdp file** (right-click the server › *Open in the Windows client (mstsc)*); the token travels in the file's `loadbalanceinfo` field, which these clients send in their very first packet, before any encryption. Portunia and the web portal keep working as before.

The entry listens on its own port (**3390**), **closed by default**: Portunia › Administer › **Native RDP**, or `sudo portunia-gate rdp on`. Everything is set there: port, address written in the files, modes reachable this way, validity of a file (2 minutes by default).

| | **Jump** | **Vault** | **Recorded** |
|---|---|---|---|
| What the Gate does | Removes the token, then lets the connection through untouched: TLS and Windows authentication (NLA) end to end, nothing recorded. | Signs in to Windows (NLA) with the vault account, then relays and records. | Same, with the Windows account typed in Portunia when preparing the file: kept **in memory** until the client connects, never on disk. Without an account, only for a server that accepts TLS without NLA (the user types it in the Windows sign-in screen). |
| Certificate seen by the client | The Windows server's. | The Gate's API certificate (a warning once without a company certificate: compare it with `sudo portunia-gate info`). | Same as Vault. |

The log records `rdp_natif.fichier` (file prepared), then the usual session events (`session.ouverte`, `rebond.ouvert`…) with `(natif)` after the address. Open the port on the firewall (hardening opens it when the entry is open); with Docker, it is published as `PORTUNIA_GATE_RDP_PORT` (3390). A file is single-use: an RDP client that reconnects on its own after a network cut is refused; prepare a new file.

**Without Portunia (0.34).** In mstsc, Windows App or Remmina, type the Gate's address and native RDP port as the computer, `login%server` as the user (`login%server%123456` with the 6-digit code when the account's policy asks for one) and the account's **RDP password** as the password. The Gate checks all three through NLA (it acts as the Windows server for the client), then opens the server as in Vault or Recorded mode; Jump servers stay reachable only with Portunia's .rdp file. The RDP password is separate from the account password: the user creates it in the web portal (*Connect with mstsc or Windows App*, which also offers a ready-made .rdp shortcut per server) or an administrator with `sudo portunia-gate user rdp-password LOGIN`; it is sealed by the Gate (NTLM needs to read it back), shown only once, and `--remove` takes it away. Recorded servers must then accept a connection without NLA: the user signs in to Windows in its sign-in screen. Refusals are logged (`acces.refuse`, type « rdp natif », with the reason); creating or removing a password too (`rdp_natif.mot_de_passe`).

**Native sessions and replay (0.34.1).** Native Vault and Recorded sessions are always recorded, so the Gate withdraws the client's RDP 8 graphics pipeline (GFX) announcement: Windows then sends the picture as classic updates, which the replay decodes. Through the GFX channel, the replay stayed black.

## Gate status and updates

Since 0.39, **Gate status** (Portunia: Gate menu › *Gate status*, or the *Status* section of the administration; `sudo portunia-gate status`) shows at a glance: overall health, version, uptime, processor, memory, disk and network (with 24-hour curves in Portunia), services (database, HTTPS certificate, dedicated relays, clock, notifications, hardening), storage (recordings, database, filling rate and « disk full in N days »), activity (open sessions, sessions today, refused sign-ins, approvals waiting) and the integrity of the signed log (checked every 6 hours). In Portunia, the Gate's dot in the sidebar turns orange or red when something needs attention.

- **Update in one click** (Debian package, Portunia Pro): *Update…*, now or at a set time (tonight at 3:00 by default), optionally warning the connected users 5 minutes before. A separate system service, run as root (`portunia-gate-update`), backs up the database, downloads the new package and the one installed (for the rollback) and checks their published SHA-256, installs, then waits for the new version to start. If it does not start within 3 minutes: **automatic rollback** (previous package reinstalled, database restored). It only accepts a version newer than the installed one. The administrators are told the result (and when a new version is published) by e-mail, Teams or webhook.
- **Command line**: `update check`, `update apply [--at 03:00] [--notice] [--wait]`, `update status`, `update cancel`. With Docker: `sudo ./installer.sh update`, as before.
- **Recording retention**: `sudo portunia-gate setting recording_days 180` (or Portunia: Settings, or the Status page). Beyond it, the recordings of ended sessions are deleted every hour; the sessions stay in the list and the deletion is logged (`enregistrement.purge`). 0: kept forever (default).
- **Disk alert**: above 85 % full, the administrators are told (once a day at most).
- **Log**: `mise_a_jour.programmee`, `.lancee`, `.reussie`, `.retour_arriere`, `.echec`, `.annulee`, `.disponible`; `disque.presque_plein`; `journal.altere`.

## Access approval

Since 0.38 a rule can require an approval: its servers open only once an approver has granted access, for a duration. Settings: in the rule, *Access only after approval* and the **approvers** group (empty: the administrators); `sudo portunia-gate rule approval NAME on --approvers GROUP`.

- **Asking**: the user gives a reason (and an optional ticket number) in Portunia (Gate menu › **Approvals**) or in the web portal (*Servers on approval*). The approvers are notified (e-mail, Teams, webhook, and Portunia, which checks every minute).
- **Deciding**: an approver grants for a duration (30 minutes to 3 days in Portunia, 5 minutes to 7 days on the command line) or refuses, with a comment. Nobody approves their own request. A request without an answer expires after 24 hours.
- **End**: the user is told 10 minutes before (in the SSH terminal), then their sessions close. An approver can **withdraw** an access at any time; the user can cancel their request.
- **Log**: `approbation.demandee`, `approbation.accordee`, `approbation.refusee`, `approbation.annulee`, `approbation.terminee`, `approbation.sans_reponse`.
- **Command line**: `approval list`, `approval grant ID --minutes 60`, `approval deny ID`, `approval revoke ID` (the console acts as an administrator).

## Notifications

E-mail (SMTP), Microsoft Teams (a channel's « Workflows » webhook) and a signed JSON webhook, used by access approval: Administer › Settings › **Notifications** (with a test), or `sudo portunia-gate notify set --smtp-host smtp.example.com --smtp-user gate --smtp-password --from "Portunia Gate <gate@example.com>"`, then `notify test you@example.com`. Each account's e-mail address is set in its form or with `user email LOGIN ADDRESS`. The webhook receives `{"evenement", "date", "gate", "detail"}` with `X-Portunia-Gate-Date` (Unix seconds) and `X-Portunia-Gate-Signature: sha256=<HMAC-SHA256 of "date.body">`. A failed sending is logged (`notification.echec`) and never blocks anything.

## Web interfaces

Since 0.30, administration consoles (vCenter, iDRAC, iLO, firewalls, NAS…) are declared as servers with protocol `https` or `http`, in recorded mode. The Gate relays every request (rule checked again every 30 s), logs each page opened (`web.page`) and pins the server's certificate like for Remote Desktop. From Portunia they open in a dedicated window through a local relay to the Gate API (8-hour web session); from the web portal in a tab at `/web/<name>/` (one web interface at a time per browser; the application shares the portal's address, so only publish trusted applications there). The Gate's cookies and the visitor's address never reach the server; WebSockets go through. Since 0.32, vault mode as well: the Gate signs the user in with the vault account. It fills the sign-in form in the page (JavaScript applications included) with a one-time token instead of the password, and swaps the token for the password on the way to the server, so the password never reaches the browser; or it sends HTTP authentication (Basic). Each use is logged (`web.coffre`).

Since 0.35, each account has a **web session** per server, listed with the other sessions (type `web`): it opens at the first request and closes after 15 minutes without a request, when access ends or when it is cut. Its signed action log notes pages opened, data sent (forms, changes: methods other than GET), WebSockets and vault use, with path (without parameters) and status; never what is typed. It is read in Portunia › Audit (*Actions*) or with `sudo portunia-gate sessions show ID`, and searched by path.

## Web portal

A web page to open your servers from any browser, without Portunia: sign-in, list of allowed servers, SSH terminal or Remote Desktop in a tab. It is not used for administration. SSH goes through the Gate's own SSH server with a one-time token: same rules, same vault, same recording, same log. Remote Desktop goes through the Gate's RDCleanPath gateway (every mode, see [Remote Desktop](#remote-desktop-rdp)). A web session is replayed in the audit like any other; its address is followed by "(web)".

**Security**

| | |
|---|---|
| Exposure | **Cloudflare Tunnel** (recommended): the Gate runs `cloudflared` itself (outbound connection to Cloudflare, no inbound port, nothing to install as root). Or **Cloudflare proxy**: HTTPS on port 8446, accepting Cloudflare addresses only. |
| Sign-in | Password **and** code always required, even for an account that does without in Portunia. Five attempts per account and twenty per address in ten minutes. **Cloudflare Turnstile** anti-bot check when its keys are set. |
| Accounts | Members of the **chosen group** only ("Accès web" by default). First sign-in and lost code: not on the portal, but with Portunia or the administrator. |
| Session | "HttpOnly, Secure, SameSite=Strict" cookie, 1 hour by default; closed after 15 minutes without typing (warning 90 s before). |
| Page | Nothing loaded from outside (except Turnstile), strict content security policy, cannot be framed by another site, public address checked on every sign-in. |
| Servers | SSH in Vault or Recorded mode; Remote Desktop in every mode (IronRDP web client in the page): Recorded and Jump with Windows credentials typed in the page and sent to the server, never to the Gate (Jump: relayed without recording); Vault with nothing to type. SSH jump servers (end-to-end) stay with Portunia. |
| Audit log | `portail.connexion`, `portail.echec`, `portail.active`, `portail.desactive`, `portail.modifie`, `portail.sessions_fermees`. |

**Setup**

1. **Create the tunnel** in Cloudflare: **Networking › Tunnels › Create Tunnel**, a name (e.g. `portunia-gate`), then copy the installation command shown, for any system. It holds the token; do not run it.
2. **Give it to the Gate**: in Portunia, Administer › Web portal › Cloudflare mode, paste the command or the token and save. Or from the server: `sudo bash installer.sh portal`, or `sudo portunia-gate portal tunnel -` (token on the standard input; `--remove` stops it). The Gate downloads `cloudflared` 2026.9.1 from Cloudflare's GitHub, checks its SHA-256 fingerprint, runs it under its own account and restarts it if it stops. The token is encrypted by the vault. Server without access to GitHub: `PORTUNIA_GATE_CLOUDFLARED=/usr/bin/cloudflared`.
   The tunnel then turns **Healthy** in Cloudflare.
3. **Publish the address**: in the tunnel, **Routes** tab › **Add route** › **Published application**. **Subdomain** and **Domain** (the *Full hostname*, e.g. `access.your-domain.com`, is the public address), **Path** empty, **Service URL** `http://localhost:8445`, then **Add route** (Cloudflare creates the DNS record). Never add `ssh://` or `rdp://` routes to your servers: they would bypass the Gate (no access control, vault, recording or audit).
4. **Check**: in the Web portal tab, public address `https://` + Full hostname, **Save**, then **Test the public address**: the Gate calls its own public address through Cloudflare and checks it answers itself.
5. **Recommended: Cloudflare Access** on that address (company account required before the sign-in page is even shown), and **Turnstile** (keys entered in Portunia).
6. **Turn it on** in Portunia: Gate **⋯** menu › **Administer** › **Web portal**: public address, allowed group, durations, copy and paste, then the switch. Create the group and add the relevant accounts.

Turning the portal off (switch) shows "Portal closed" and immediately closes open web sessions; **Close all web sessions** closes them without turning the portal off.

**Exposure mode** (Portunia 0.52 and Portunia Gate 0.17 and later): Administer › Web portal, or `sudo portunia-gate portal expose` (`portal show` displays it, applied within 30 seconds).

| Mode | Who can reach the portal | Visitor address |
|---|---|---|
| `cloudflare` (default) | Tunnel; HTTPS from Cloudflare addresses only | `CF-Connecting-IP`, from the machine itself or Cloudflare only |
| `proxy` | The declared trusted proxies, nobody else | Chosen header (`X-Forwarded-For` by default), read from the right |
| `internal` | Private networks, or the networks given | Connection address |
| `direct` | Everyone, or the networks given | Connection address |
| `relay` | The dedicated relays only | Given by the relay |

```bash
sudo portunia-gate portal expose proxy --trusted 10.0.5.10,10.0.5.11 --header X-Forwarded-For
```

**Dedicated relay** (Portunia 0.53 and Portunia Gate 0.18 and later): a separate machine, typically in a DMZ, publishes the portal while the Gate stays on the internal network. The Gate opens the connections towards the relay, so no flow goes from the DMZ to the internal network. The relay holds no vault, account or database, only a secret shared with the Gate and its certificates. Its HTTPS ends on the relay: if it is compromised, what passes through while the attacker is there can be read (passwords, codes, terminals), so revoke it at once.

1. In Portunia, Administer › Web portal › Dedicated relay, give a name and the address the Gate reaches it at (e.g. `10.0.5.20:8447`), then **Add a relay**. The command is shown once. Or `sudo portunia-gate portal relay-add dmz-01 10.0.5.20:8447`.
2. On the relay machine (Debian amd64): `sudo bash installer.sh relay CODE access.your-domain.com`.
3. Firewall: port 443 from browsers to the relay, port 8447 from the Gate to the relay **and from nowhere else** (the relay limits handshakes per address, but only the firewall keeps strangers away from this port), nothing from the relay to the internal network.
4. In Portunia, select **Dedicated relay** and save: the Gate then refuses any direct access to the portal.

The relay presents a self-signed certificate. For your own: `portunia-gate edge certificate CERT KEY` run as `_portunia_gate`, then `systemctl restart portunia-gate-relais`. Update: `sudo bash installer.sh update` on the relay. Several relays can sit behind a load balancer. Audit log: `relais.ajoute`, `relais.revoque`.

Modes `proxy`, `internal` and `direct` use the HTTPS listener: open it in Administer › Web portal (**HTTPS listening**, a port or `address:port`, e.g. `8446`), or `sudo portunia-gate portal https 8446` (`--off` closes it). The Gate opens, moves or closes it within seconds, without restarting. Ports under 1024 are refused by the system: redirect 443 to 8446 on the firewall or the box. The hardened firewall always allows 8446. `PORTUNIA_GATE_PORTAL_TLS_LISTEN` in the configuration file, if set, takes precedence (the tab then shows it read-only). The web socket must pass through the proxy or WAF.

**Portal certificate** (HTTPS listener), separate from the API certificate, which Portunia consoles pin: changing it never affects them. In Administer › Web portal › **Portal certificate**:

- **Import a certificate** from an internal or public PKI: PEM certificate with its chain and its unencrypted key, or a PFX file (.pfx, .p12) and its password. Applied within seconds, without restarting. Command line: `sudo portunia-gate portal cert --import cert.pem --key key.pem` (or `--import portail.pfx`), `sudo portunia-gate portal cert` shows it, `--remove` goes back to self-signed.
- **Let's Encrypt** (Pro): domain names, contact email, then the check. *TLS-ALPN-01*: HTTPS listening open and port 443 of the public address redirected to it; nothing else to open. *DNS-01 through Cloudflare*: an API token with Zone › DNS › Edit on the zone (My Profile › API Tokens › Create Token › Edit zone DNS); nothing to open, wildcard names (`*.example.com`) allowed. The Gate obtains the certificate, then renews it 30 days before it expires; after a failure it tries again every 6 hours, or at once with **Renew now**. The account and the token are kept encrypted by the vault. A staging option issues test certificates without touching Let's Encrypt's limits.
- Files kept outside the Gate (renewed by another tool): `PORTUNIA_GATE_PORTAL_TLS_CERT` and `PORTUNIA_GATE_PORTAL_TLS_KEY` in the configuration file; they take precedence, and new files are taken within seconds. Without anything, the portal uses `PORTUNIA_GATE_TLS_CERT` if set (former behaviour), otherwise a self-signed certificate.

Audit log: `portail.certificat`, `portail.acme`, `portail.acme_obtenu`, `portail.acme_echec`, `portail.acme_renouveler`. `cloudflared` on another machine than the Gate: list its network in `PORTUNIA_GATE_PORTAL_TUNNEL_PEERS`, otherwise its header is ignored.

Cloudflare proxy instead of the tunnel: `sudo portunia-gate portal https 8446` (package), or `PORTUNIA_GATE_PORTAL_PORT=0.0.0.0:8446` in `.env` (Docker), then restart; in Cloudflare, the proxied address points to that port over HTTPS ("Full" SSL mode).

## Remote assistance

Take control of a relative's or a customer's PC with **Portunia Assistance** (Portunia Gate 0.11 and later, Portunia 0.48 and later). The person goes to `https://your-portal-address/assistance`, downloads Portunia Assistance (a single program, no install, no account) and reads you a 9-digit code; you type it in Portunia (**Remote assistance** in the sidebar). They see your name and choose: view only, or view and control. Their screen opens in a Remote Desktop tab.

| | |
|---|---|
| Relay | The Gate only puts the two sides in touch and passes the data on: the link is encrypted end to end from the code (SPAKE2 key exchange, ChaCha20-Poly1305). The Gate never sees the screen nor the keystrokes, and does not record them. |
| Code | Single use, given out by the Gate when Portunia Assistance opens; a wrong code ends the attempt and the person gets a new one. |
| Who | Members of the **helpers group** only ("Dépanneurs" by default), signed in to the Gate from Portunia. |
| Person helped | A frame and a **Stop** bar stay on their screen (not visible in the shared image); pressing Esc three times also stops. The assistance ends after the maximum duration (4 hours by default). |
| Program | The Gate downloads `portunia-assistance.exe` from the Portunia releases when assistance is enabled, then once a day, and checks its SHA-256 fingerprint. It is not code-signed yet: Windows SmartScreen warns on first opening ("More info" › "Run anyway"). |
| Audit log | `assistance.ouverte`, `assistance.fermee`, `assistance.reglage`, `assistance.place_inconnue`, `assistance.programme`. |

**Setup**: the page and the relay use the web portal address (see [Web portal](#web-portal), steps 1 to 3; the portal itself can stay off). In Portunia, enable the **Remote assistance** extension, then Gate **⋯** menu › **Administer** › **Assistance**: helpers group, maximum duration, then the switch. Create the group and add the helpers' accounts.

## Connecting without Portunia

```bash
ssh -p 2222 julien@Gate              # menu of allowed servers
ssh -p 2222 julien%web-01@Gate       # straight to web-01
ssh -J julien@Gate:2222 admin@fw-01  # end-to-end jump (servers in Jump mode)
sftp -P 2222 julien%web-01@Gate      # files (Vault mode, if the rule allows SFTP)
```

The TOTP code must have been enrolled first, in Portunia or with `sudo portunia-gate user totp julien`.

Windows servers can also be opened in mstsc, Windows App or Remmina, with a single-use .rdp file prepared by Portunia: see [Ordinary RDP clients](#ordinary-rdp-clients-native-rdp-031).

## Command-line administration

Everything is done either from Portunia or here; only replaying sessions stays in Portunia. On the server, the wizard installs the `portunia-gate` command, used with sudo from any folder:

```bash
# Information
sudo portunia-gate info                                            # version, fingerprints, accounts

# Accounts
sudo portunia-gate user add marc --temporary                       # temporary password, code enrolled in Portunia
sudo portunia-gate user add marc                                   # password and code entered here
sudo portunia-gate user add contractor --policy "key+totp"         # SSH key and code required
sudo portunia-gate user key marc "ssh-ed25519 AAAA… marc@pc"
sudo portunia-gate user role marc auditor                          # user, auditor (replay and log) or admin
sudo portunia-gate user list | passwd marc | totp marc | disable marc | delete marc
sudo portunia-gate user policy marc "key+totp" | reset-password marc | reset-code marc

# Groups
sudo portunia-gate group add "Linux admins"
sudo portunia-gate group member "Linux admins" marc julien
sudo portunia-gate group remove "Linux admins" marc
sudo portunia-gate group list | delete "Linux admins"

# Servers (modes: coffre = vault, enregistre = recorded, rebond = jump)
sudo portunia-gate target add web-01 --host 10.0.1.11 --mode coffre --account admin --password --folder Production
sudo portunia-gate target add stg-app --host 10.0.2.5 --mode enregistre --folder Staging
sudo portunia-gate target add fw-edge --host 10.0.0.1 --mode rebond --folder Network
sudo portunia-gate target add srv-ad-01 --host 10.0.3.10 --protocol rdp --mode enregistre --folder Windows
sudo portunia-gate target list
sudo portunia-gate target edit web-01 --folder Production --account root   # --rename, --host, --port, --mode, --password, --key-file
sudo portunia-gate target secret web-01 --generate                 # or --password, --key-file: replaces the vault secret
sudo portunia-gate target forget web-01                            # server reinstalled: forget its fingerprint
sudo portunia-gate target delete fw-edge

# Rules
sudo portunia-gate rule add prod --group "Linux admins" --targets web-01,stg-app --sftp --days mon-fri --hours 7-20
sudo portunia-gate rule add contractor-db --group Contractors --targets db-01 --expires 2026-12-31
sudo portunia-gate rule list                                       # with their state now
sudo portunia-gate rule edit prod --sftp off --hours ""            # "" clears days, hours or expiry
sudo portunia-gate rule delete contractor-db
sudo portunia-gate rule add windows --group Accounting --targets srv-ad-01 --files   # Remote Desktop file copy (logged, SHA-256)

# Web portal and assistance
sudo portunia-gate portal set --url https://access.acme.com --group "Web access" --duration 4 --idle 30 --clipboard on
sudo portunia-gate portal on                                       # off closes it; close-sessions ends web sessions
sudo portunia-gate portal show
sudo portunia-gate assist set --group Technicians --duration 4
sudo portunia-gate assist on                                       # off, show

# Settings
sudo portunia-gate setting auth_policy "password+totp,key+totp"    # global policy
sudo portunia-gate setting banner "Authorised access only. Sessions are recorded."
sudo portunia-gate setting name "ACME Gate"
sudo portunia-gate setting language fr                           # en, fr, or "" for the system language

# Checks
sudo portunia-gate audit --verify --last 50
sudo portunia-gate sessions --last 20
sudo portunia-gate audit --search marc --csv journal.csv
sudo portunia-gate sessions --user marc --since 2026-11-01   # sessions show ID: recording and signature
```

Full reference, with every command and option: [docs/command-line.md](docs/command-line.md). `sudo portunia-gate --help` and `sudo portunia-gate user --help` list them on the server.

See also [docs/operations.md](docs/operations.md): backups, updates, logs, troubleshooting.

## Roadmap

1. **Core**: SSH proxy, three modes, vault, accounts and TOTP, permissions, signed recording, chained audit log, Docker Compose.
2. **Portunia integration**: API, adding the Gate in Portunia, servers in the sidebar, one-time tokens, first sign-in, full administration, keys generated and installed on vault servers. Setup wizard (0.3), Debian package (0.4).
3. **Audit**: replay and search (0.5), live view and session termination, on-demand MP4 video, detachable player, configurable retention with disk estimate, syslog and CSV.
4. **Remote Desktop**: jump (0.6), recorded with signed recording (0.8), replay (0.10), vault (0.29: the Gate opens the Windows session with the vault account), ordinary RDP clients (0.31: mstsc, Windows App, Remmina with a single-use .rdp file), then rules (clipboard, sound).
5. **Web portal**: SSH (0.7) and Remote Desktop (0.8) in the browser behind Cloudflare, then passkeys, branding.
6. **Remote assistance**: Portunia Assistance relay with a code (0.11), then invitation link, unattended access to your own PCs, file transfer, chat.
7. **Operations**: built-in backup, apt repository for updates, ARM package, imports (Portunia, CSV), optional web console.
8. **Master console**: a central Portunia Gate for service providers, relays at customers' sites.
