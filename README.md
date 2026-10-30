# Heimdia

**English** · [Français](README.fr.md)

SSH and Remote Desktop bastion for [Portunia](https://github.com/jpiperault/Portunia): users go through Heimdia to reach servers. Heimdia checks who they are, decides where they may go, supplies the server account when needed without ever showing it, records sessions and keeps a tamper-evident audit log.

> Status: **version 0.8, recorded Remote Desktop**, also in the browser (web portal); SSH web portal (0.7), jump Remote Desktop (0.6), SSH session replay (0.5). See the [Roadmap](#roadmap).

## What Heimdia does

| | |
|---|---|
| **Three modes per server** | **Jump**: end-to-end relay (`ssh -J`); the bastion does not see the content, it logs the connection. **Recorded**: the bastion relays and records the session; users type their own credentials. **Vault**: like Recorded, and the bastion supplies the server account, which the user never knows. |
| **Signing in to the bastion** | Password, SSH key and TOTP code (Google Authenticator, Microsoft Authenticator…), in any combination: a global policy and a per-account policy. A code works only once. |
| **Permissions** | Rules link a group to servers, with days, hours, an expiry date, and SFTP and tunnels allowed or not. Anything not allowed is denied. |
| **Recording** | Asciicast format (readable by Portunia and asciinema), screen only or keystrokes too, depending on the rule. Every file is signed by the bastion. |
| **Replay** | In Portunia, like a video: keystrokes as subtitles, idle time skipped, sensitive commands highlighted, search across all sessions. Typed passwords are masked; every replay is written to the audit log. |
| **Audit log** | Sign-ins, failures, sessions, administration changes. Each event contains the fingerprint of the previous one: a deleted or edited line shows (`heimdia audit --verify`). |
| **Portunia** | Heimdia extension: the bastion appears in the sidebar, its servers open with a one-time token, administrators manage everything from Portunia (servers and vault, accounts, groups, rules, settings) and auditors replay sessions and read the log. |
| **Remote Desktop** | Windows servers (RDP) behind the bastion, opened from Portunia or the web portal. Jump and Recorded modes (see [Remote Desktop](#remote-desktop-rdp)). |
| **Web portal** | For people without Portunia at hand: a sign-in page, a terminal and Remote Desktop in the browser, behind Cloudflare, with no open port. Turned on or off with one click in Portunia (see [Web portal](#web-portal)). |
| **Other clients** | Any SSH client: OpenSSH, PuTTY, MobaXterm, WinSCP (SFTP). |

## Install

Two ways to install, with the same setup wizard:

| | **Debian package** (recommended) | **Docker** |
|---|---|---|
| Install time | 1 to 2 minutes: package already built | 10 to 30 minutes: built on the server |
| Suggested server | 1 CPU, 2 GB RAM, 10 GB disk | 2 CPUs, 4 GB RAM, 20 GB disk |
| LXC container | Nothing to enable | *nesting* and *keyctl* options required |
| How it runs | Hardened systemd service, the distribution's PostgreSQL | Two containers (Heimdia and PostgreSQL) |
| Updating | `sudo bash installer.sh update` (downloads the latest version) | `sudo ./installer.sh update` (`git pull`, then rebuild) |
| Processors | x86-64 (amd64) | x86-64 and ARM |

Either way: a **Debian 12 or 13** or **Ubuntu 22.04 or later** server (virtual machine or LXC container) with root or sudo access, and ports **2222** (SSH) and **8443** (API for Portunia) reachable from users' computers.

### Debian package

```bash
curl -fsSLO https://github.com/jpiperault/Heimdia-releases/releases/latest/download/installer.sh
sudo bash installer.sh
```

The wizard downloads the latest Heimdia version, checks its SHA-256 fingerprint, installs the package and PostgreSQL, creates the database (local socket access, no password) and the `heimdia` service.

Installed files:

| | |
|---|---|
| `/usr/lib/heimdia/heimdia` | The program |
| `/usr/bin/heimdia` | The administration command (`sudo heimdia …`) |
| `/etc/heimdia/heimdia.env` | Settings: ports, time zone, database access |
| `/var/lib/heimdia/` | Keys, API certificate, session recordings |
| PostgreSQL database `heimdia` | Accounts, servers, rules, sessions, audit log |

The service runs under a dedicated system account (`_heimdia`), writes only to `/var/lib/heimdia` and sees neither home folders nor the rest of the system. Useful commands: `sudo systemctl status heimdia`, `sudo journalctl -u heimdia -f`.

Install a specific package (no Internet access, or an older version): `sudo bash installer.sh --package heimdia_0.4.0_amd64.deb`.

### Docker

```bash
git clone https://github.com/jpiperault/Heimdia.git
cd Heimdia
sudo ./installer.sh --docker
```

The repository is private: `git clone` asks for your GitHub username and, as the password, an access token (GitHub › Settings › Developer settings › Personal access tokens, read access to the repository). The wizard installs Docker if needed and, with less than 4 GB of RAM, offers a temporary swap file for the build. In a Proxmox LXC container, first enable *nesting* and *keyctl* (Options › Features), then restart the container.

### The questions

The wizard asks five questions; Enter keeps the suggested value:

| Question | Suggested value | |
|---|---|---|
| Bastion name | Heimdia | Shown in Portunia and in the authenticator app. |
| Administrator login | admin | Your account to administer the bastion from Portunia. |
| SSH port | 2222 | |
| API port | 8443 | |
| Time zone | the server's | Used by the time ranges of access rules. |

It then creates the keys, the certificate, the database and the administrator account, starts the bastion and shows what to enter in Portunia: address, certificate fingerprint, login and a **temporary password**. Portunia then asks the administrator to choose a password and scan a QR code with an authenticator app (leave the Code field empty on the first sign-in).

The bastion restarts on its own with the server.

### Back up the vault key, right away

The **vault key** encrypts server passwords and TOTP secrets. Without it, a restore loses all those secrets. The wizard puts a copy in your home folder (`~/heimdia-coffre.key`): copy it off the server (password manager, company vault), then delete that copy. The wizard shows the exact commands, for example:

```bash
scp julien@192.168.1.20:/home/julien/heimdia-coffre.key .   # from your computer
rm ~/heimdia-coffre.key                                      # on the server
```

### Running the wizard again

`sudo bash installer.sh` on an installed bastion opens a menu:

| Choice | Direct command | |
|---|---|---|
| Information for Portunia | `sudo bash installer.sh info` | Address and fingerprint to give to users. |
| Update | `sudo bash installer.sh update` | Installs the latest version and restarts. **Open sessions are cut.** |
| Create an administrator | `sudo bash installer.sh admin julien` | Backup administrator with a temporary password, for example if the only administrator lost their phone. |
| Web portal | `sudo bash installer.sh portal` | Installs Cloudflare Tunnel (see [Web portal](#web-portal)). |

With Docker, run the wizard from the repository folder (`sudo ./installer.sh`).

An interrupted install (power cut, error) resumes when you run the wizard again: settings already entered are offered again.

### Unattended install

Without a terminal, the wizard uses the suggested values, or those of the `HEIMDIA_NOM`, `HEIMDIA_ADMIN`, `HEIMDIA_SSH_PORT`, `HEIMDIA_API_PORT` and `TZ` variables:

```bash
sudo HEIMDIA_ADMIN=julien HEIMDIA_NOM="ACME bastion" bash installer.sh </dev/null
```

### Company certificate

The API certificate is self-signed: Portunia recognises it by its fingerprint, which is enough. To use a company certificate instead (PEM files, certificate followed by its chain):

Debian package:

```bash
sudo install -o _heimdia -g _heimdia -m 600 cert.pem /var/lib/heimdia/entreprise.crt
sudo install -o _heimdia -g _heimdia -m 600 key.pem /var/lib/heimdia/entreprise.key
echo 'HEIMDIA_TLS_CERT=/var/lib/heimdia/entreprise.crt' | sudo tee -a /etc/heimdia/heimdia.env
echo 'HEIMDIA_TLS_KEY=/var/lib/heimdia/entreprise.key' | sudo tee -a /etc/heimdia/heimdia.env
sudo systemctl restart heimdia
```

Docker, from the repository folder:

```bash
sudo docker compose cp cert.pem heimdia:/var/lib/heimdia/entreprise.crt
sudo docker compose cp key.pem heimdia:/var/lib/heimdia/entreprise.key
echo 'HEIMDIA_TLS_CERT=/var/lib/heimdia/entreprise.crt' | sudo tee -a .env
echo 'HEIMDIA_TLS_KEY=/var/lib/heimdia/entreprise.key' | sudo tee -a .env
sudo docker compose up -d
```

The fingerprint changes: users will have to accept the new one (`sudo heimdia info`).

## Adding the bastion to Portunia

1. **Enable the extension**: Portunia › Extensions › Heimdia › Enable. The **Bastions** section appears in the sidebar.
2. **Add the bastion**: Bastions › **+** › type the address given by the wizard (`192.168.1.20`, or `192.168.1.20:9443` if you changed the API port).
3. **Check the fingerprint**: Portunia shows the bastion certificate's fingerprint. Compare it with the one given by the wizard (or `sudo heimdia info` on the server, "API certificate" line). If it differs, stop: someone may be impersonating the bastion.
4. **Sign in**: login and password; **leave the Code field empty** on the first sign-in.
5. **First sign-in**: Portunia asks you to choose a new password (at least 10 characters), then shows a QR code. Scan it with your authenticator app and type the 6-digit code it shows.
6. **Open a server**: allowed servers appear under the bastion, by folder. One click opens the session, without typing the code again (one-time token):
   - **vault**: direct connection, the bastion supplies the account;
   - **recorded**: the server asks for your credentials in the terminal;
   - **jump**: Portunia asks for your server credentials; the connection is end-to-end encrypted.
7. **Administer** (Portunia Teams, administrator account): bastion **⋯** menu › **Administer**. A tab opens with servers and vault, accounts, groups, rules, web portal and settings.
8. **Audit** (Portunia Teams, administrator or auditor account): bastion **⋯** menu › **Audit**. A tab opens with sessions and the log (see [Replaying sessions](#replaying-sessions)).

Further accounts are created from the administration tab: Portunia shows a temporary password to give to the user, who then follows steps 2 to 5.

Nothing shows under the bastion? No rule grants access to a server yet: create a server, a group containing the account, then a rule linking them.

## Replaying sessions

Bastion **⋯** menu › **Audit** › **Sessions** (administrator and auditor roles).

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
| Exports | **.cast recording** (readable by asciinema) and **Transcript** (time-stamped text). |

**Masked input**: keystrokes not echoed on screen (sudo, su, ssh passwords…) are replaced by fixed-length dots, in the player as in search. They remain in the signed file: an administrator can **reveal** them (button in the player), and that replay is written to the log (`enregistrement.revele`). The `.cast` export of a masked replay is an unsigned copy; that of a revealed replay is the original, signed file.

**Sessions without keystrokes** (rule recording the screen only): no subtitles; the panel lists the commands detected on screen, after the prompt.

**Every replay is written to the log** (`enregistrement.consulte`), and the player shows the watching account as a watermark.

**Replaying one's own sessions**: Administer › Settings › "Each account can replay its own sessions". "User" accounts then see **My sessions** in the bastion menu, without being able to reveal masked input.

**Sensitive commands**: Administer › Settings, one per line (by default `rm -rf`, `mkfs`, `dd if=`, `shutdown`, `reboot`, `DROP TABLE`…).

Sessions recorded before version 0.5 can be replayed but are not included in search.

## Remote Desktop (RDP)

Windows servers are declared like the others: Administer › Servers and vault › **Add a server**, protocol **Remote Desktop (RDP)**, port 3389. They appear under the bastion in Portunia with an **RDP** badge and open in a Remote Desktop tab.

In both modes, users type their Windows credentials each time; neither Portunia nor the bastion keeps them.

| | **Jump** (0.6) | **Recorded** (0.8) |
|---|---|---|
| Path | Tunnel through the bastion's SSH port (2222), with a one-time token; the RDP connection is end-to-end encrypted. | The bastion's gateway (RDCleanPath, on the API or portal port) with a one-time token: the bastion opens the encrypted connection to the Windows server and relays the session. |
| What the bastion sees | None of the content; it checks the rule and logs (`rebond.ouvert`, duration, bytes). | The session (to record it), but not the password: Windows authentication (NLA) happens between the client and the server. |
| Recording | No. | Yes, signed file (`.rdpcap`); replay in a later version. |
| Clients | Portunia. | Portunia and the **web portal** (Remote Desktop in the browser). |
| Server certificate | Checked by the client. | Checked by the bastion: fingerprint kept on first connection, connection refused if it changes (`cible.empreinte_differente`). |

The bastion must reach port 3389 of the Windows servers. In Portunia, the Remote Desktop extension must be enabled; otherwise RDP servers stay visible, greyed out. An RDP server does not appear in the bastion's `ssh` menu and does not open as a terminal.

**Vault** mode (Windows account supplied by the bastion, nothing to type) and RDP session replay come in later versions.

## Web portal

A web page to open your servers from any browser, without Portunia: sign-in, list of allowed servers, SSH terminal or Remote Desktop in a tab. It is not used for administration. SSH goes through the bastion's own SSH server with a one-time token: same rules, same vault, same recording, same log. Remote Desktop goes through the bastion's RDCleanPath gateway (servers in Recorded mode, see [Remote Desktop](#remote-desktop-rdp)). A web session is replayed in the audit like any other; its address is followed by "(web)".

**Security**

| | |
|---|---|
| Exposure | **Cloudflare Tunnel** (recommended): the `cloudflared` service opens an outbound connection to Cloudflare, no inbound port. Or **Cloudflare proxy**: HTTPS on port 8446, accepting Cloudflare addresses only. |
| Sign-in | Password **and** code always required, even for an account that does without in Portunia. Five attempts per account and twenty per address in ten minutes. **Cloudflare Turnstile** anti-bot check when its keys are set. |
| Accounts | Members of the **chosen group** only ("Accès web" by default). First sign-in and lost code: not on the portal, but with Portunia or the administrator. |
| Session | "HttpOnly, Secure, SameSite=Strict" cookie, 1 hour by default; closed after 15 minutes without typing (warning 90 s before). |
| Page | Nothing loaded from outside (except Turnstile), strict content security policy, cannot be framed by another site, public address checked on every sign-in. |
| Servers | SSH in Vault or Recorded mode; Remote Desktop in Recorded mode (IronRDP web client in the page; Windows credentials typed in the page and sent to the server, never to the bastion). Jump servers (end-to-end) stay with Portunia. |
| Audit log | `portail.connexion`, `portail.echec`, `portail.active`, `portail.desactive`, `portail.modifie`, `portail.sessions_fermees`. |

**Setup**

1. **Create the tunnel** in Cloudflare Zero Trust › Networks › Tunnels › *Create a tunnel* (Cloudflared type) and copy its token (the long string after `--token`).
2. **Install it on the bastion**: `sudo bash installer.sh portal` (package) or `sudo ./installer.sh portal` (Docker), then paste the token.
3. **Publish the address**: in the tunnel's *Public Hostname* tab, add the address (e.g. `access.your-domain.com`), type **HTTP**, URL `localhost:8445` (package) or `heimdia:8445` (Docker).
4. **Recommended: Cloudflare Access** on that address (company account required before the sign-in page is even shown), and **Turnstile** (keys entered in Portunia).
5. **Turn it on** in Portunia: bastion **⋯** menu › **Administer** › **Web portal**: public address, allowed group, durations, copy and paste, then the switch. Create the group and add the relevant accounts.

Turning the portal off (switch) shows "Portal closed" and immediately closes open web sessions; **Close all web sessions** closes them without turning the portal off.

Cloudflare proxy instead of the tunnel: in `/etc/heimdia/heimdia.env`, `HEIMDIA_PORTAL_TLS_LISTEN=0.0.0.0:8446` (package), or `HEIMDIA_PORTAL_PORT=0.0.0.0:8446` in `.env` (Docker), then restart; in Cloudflare, the proxied address points to that port over HTTPS ("Full" SSL mode).

## Connecting without Portunia

```bash
ssh -p 2222 julien@bastion              # menu of allowed servers
ssh -p 2222 julien%web-01@bastion       # straight to web-01
ssh -J julien@bastion:2222 admin@fw-01  # end-to-end jump (servers in Jump mode)
sftp -P 2222 julien%web-01@bastion      # files (Vault mode, if the rule allows SFTP)
```

The TOTP code must have been enrolled first, in Portunia or with `sudo heimdia user totp julien`.

## Command-line administration

Everything can also be done from Portunia. On the server, the wizard installs the `heimdia` command, used with sudo from any folder:

```bash
# Information
sudo heimdia info                                            # version, fingerprints, accounts

# Accounts
sudo heimdia user add marc --temporary                       # temporary password, code enrolled in Portunia
sudo heimdia user add marc                                   # password and code entered here
sudo heimdia user add contractor --policy "key+totp"         # SSH key and code required
sudo heimdia user key marc "ssh-ed25519 AAAA… marc@pc"
sudo heimdia user role marc auditor                          # user, auditor (replay and log) or admin
sudo heimdia user list | passwd marc | totp marc | disable marc | delete marc

# Groups
sudo heimdia group add "Linux admins"
sudo heimdia group member "Linux admins" marc julien

# Servers (modes: coffre = vault, enregistre = recorded, rebond = jump)
sudo heimdia target add web-01 --host 10.0.1.11 --mode coffre --account admin --password --folder Production
sudo heimdia target add stg-app --host 10.0.2.5 --mode enregistre --folder Staging
sudo heimdia target add fw-edge --host 10.0.0.1 --mode rebond --folder Network
sudo heimdia target add srv-ad-01 --host 10.0.3.10 --protocol rdp --mode enregistre --folder Windows
sudo heimdia target list

# Rules
sudo heimdia rule add prod --group "Linux admins" --targets web-01,stg-app --sftp --days mon-fri --hours 7-20
sudo heimdia rule add contractor-db --group Contractors --targets db-01 --expires 2026-12-31

# Settings
sudo heimdia setting auth_policy "password+totp,key+totp"    # global policy
sudo heimdia setting banner "Authorised access only. Sessions are recorded."
sudo heimdia setting name "ACME bastion"
sudo heimdia setting language fr                           # en, fr, or "" for the system language

# Checks
sudo heimdia audit --verify --last 50
sudo heimdia sessions --last 20
```

`sudo heimdia --help` and `sudo heimdia user --help` list every option.

See also [docs/operations.md](docs/operations.md): backups, updates, logs, troubleshooting.

## Roadmap

1. **Core**: SSH proxy, three modes, vault, accounts and TOTP, permissions, signed recording, chained audit log, Docker Compose.
2. **Portunia integration**: API, adding the bastion in Portunia, servers in the sidebar, one-time tokens, first sign-in, full administration, keys generated and installed on vault servers. Setup wizard (0.3), Debian package (0.4).
3. **Audit**: replay and search (0.5), live view and session termination, on-demand MP4 video, detachable player, configurable retention with disk estimate, syslog and CSV.
4. **Remote Desktop**: jump (0.6), recorded with signed recording (0.8), then replay, vault (the bastion opens the Windows session with the vault account), rules (clipboard, sound).
5. **Web portal**: SSH (0.7) and Remote Desktop (0.8) in the browser behind Cloudflare, then passkeys, branding.
6. **Operations**: built-in backup, apt repository for updates, ARM package, imports (Portunia, CSV), optional web console.
7. **Master console**: a central Heimdia for service providers, relays at customers' sites.
