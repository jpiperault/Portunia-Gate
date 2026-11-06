# Portunia Gate — command-line reference

*Portunia Gate 0.26 and later; Remote Desktop file copy: 0.28 and later.* [Version française](ligne-de-commande.md)

Everything Portunia's **Administer** menu does on a Gate can also be done on the Gate's server with the `portunia-gate` command, so a Gate can be run entirely from a Linux or macOS workstation over SSH: accounts, groups, servers, rules, settings, the web portal, Let's Encrypt, remote assistance, the audit log and session search. Only **replaying sessions** stays in Portunia (video player, revealing masked input).

## Basics

```bash
sudo portunia-gate --help                 # every command
sudo portunia-gate user --help            # options of a command
sudo portunia-gate rule edit --help
```

- Debian package: the command is `/usr/bin/portunia-gate`; it runs under the service account `_portunia_gate` with the Gate's configuration. Use `sudo`.
- Docker: the installer adds the same `sudo portunia-gate …` command on the host (`/usr/local/bin/portunia-gate`), which runs it in the container.
- Messages follow the system language (English or French), or `PORTUNIA_GATE_LANG=en|fr`.
- Every change is written to the **audit log** with the actor `console`, exactly as from Portunia.
- A command takes effect in the database at once. What it changes for **open sessions** (closing them, rights withdrawn, portal closed, language) is applied by the service **within 30 seconds**.
- Switches take `on` or `off` (also `yes`/`no`, `oui`/`non`, `true`/`false`).
- Days: `mon-fri`, `mon,wed,fri`, `sat,sun` (French `lun-ven` also accepted). Hours: `7-20`, or `22-6` across midnight. Dates: `YYYY-MM-DD`.

## Installation and information

```bash
sudo portunia-gate init --admin julien --temporary --name "ACME Gate"   # database, keys, administrator; safe to run again
sudo portunia-gate init --no-admin                       # database and keys only
sudo portunia-gate info                                  # version, SSH and API fingerprints to compare in Portunia, accounts
sudo portunia-gate hardening                             # server hardening state and alerts
```

`serve` runs the Gate; the `portunia-gate` service does it, do not start it by hand. Installing, updating and hardening the server go through `installer.sh` (see the [administration guide](https://github.com/jpiperault/Portunia-Gate-releases/blob/main/docs/guide-administration.md)).

## Accounts

```bash
sudo portunia-gate user add marc                          # password and TOTP code entered here
sudo portunia-gate user add marc --temporary              # temporary password shown; the user finishes in Portunia
sudo portunia-gate user add sophie --role admin           # user (default), auditor or admin
sudo portunia-gate user add robot --no-password --policy key   # technical account, SSH key only
sudo portunia-gate user list                              # role, code, keys, combinations, groups, temporary, disabled
sudo portunia-gate user role marc auditor
sudo portunia-gate user policy marc "key+totp"            # accepted combinations; "" = global setting
sudo portunia-gate user key marc "ssh-ed25519 AAAA… marc@pc"   # or the path of a .pub file
sudo portunia-gate user totp marc                         # enrols (or re-enrols) the code: QR code in the terminal
sudo portunia-gate user passwd marc                       # sets the password (no longer temporary)
sudo portunia-gate user reset-password marc               # new temporary password, shown once
sudo portunia-gate user reset-code marc                   # erases the code: a new one is enrolled at the next sign-in
sudo portunia-gate user rdp-password marc                 # RDP password for mstsc without Portunia (shown once; --remove takes it away)
sudo portunia-gate user disable marc                      # --undo re-enables
sudo portunia-gate user delete marc                       # past sessions stay in the log
```

- `reset-password`, `reset-code` and `disable` end the account's sign-ins; its open sessions close within 30 seconds.
- A **temporary password** works only in Portunia, where the user chooses theirs. SSH and the web portal refuse it. Without Portunia: `user passwd`, and `user totp` for the code.

## Groups

```bash
sudo portunia-gate group add "Linux admins"
sudo portunia-gate group member "Linux admins" marc julien
sudo portunia-gate group remove "Linux admins" marc       # sessions they lose close within 30 s
sudo portunia-gate group list                             # groups and members
sudo portunia-gate group delete Interns                   # also deletes the rules giving it access
```

## Servers

Modes: `coffre` (vault: the Gate holds the account's secret), `enregistre` (recorded: users type their own credentials), `rebond` (jump: end-to-end, not recorded). English aliases: `vault`, `recorded`, `jump`.

```bash
sudo portunia-gate target add web-01 --host 10.0.1.11 --mode coffre --account root --password --folder Production
sudo portunia-gate target add app-02 --host 10.0.1.12 --mode coffre --account deploy --key-file /root/deploy_ed25519
sudo portunia-gate target add stg --host 10.0.2.5 --mode enregistre --folder Staging
sudo portunia-gate target add fw-edge --host 10.0.0.1 --mode rebond --folder Network
sudo portunia-gate target add srv-ad-01 --host 10.0.3.10 --protocol rdp --mode enregistre --folder Windows
sudo portunia-gate target list                            # protocol, address, mode, account, fingerprint
sudo portunia-gate target edit web-01 --folder Prod --account admin    # also --rename, --host, --port, --mode
sudo portunia-gate target edit web-01 --host 10.0.1.21 --password      # new address: secret given again, fingerprint forgotten
sudo portunia-gate target edit mail --description "Agency mail"       # text of the tile in the portal and Portunia (0.33; empty: automatic text)
sudo portunia-gate target secret web-01 --password        # replaces the vault secret (or --key-file FILE)
sudo portunia-gate target secret app-02 --generate        # SSH: the Gate creates a key and installs it with the current password, then forgets it
sudo portunia-gate target forget srv-ad-01                # server reinstalled: forget its fingerprint
sudo portunia-gate target delete fw-edge                  # secret erased; sessions and recordings stay
```

- Web interface (`--protocol https` or `http`, 0.30): port 443 or 80; the Gate relays every request and logs the pages opened (`web.page`). Recorded mode (taken by default without `--password`): credentials are typed in the page. Vault mode (0.32): `--mode vault --account … --password`; the Gate signs the user in and the password never reaches the browser. `--web-login auto` (default: fills the sign-in form, JavaScript applications included, and submits it; HTTP authentication when the server asks for it), `fill` (fills only, the user clicks) or `basic` (HTTP authentication on every request). Each use of the vault password is logged (`web.coffre`, with the path). Examples: `sudo portunia-gate target add vcenter --host 10.0.4.10 --protocol https`, `sudo portunia-gate target add mail --host 192.168.1.16 --protocol https --mode vault --account admin --password`, `sudo portunia-gate target edit mail --web-login fill`.
- Remote Desktop (`--protocol rdp`): `--mode enregistre`, `--mode rebond`, or `--mode coffre` (0.29) with `--account` and `--password` (a vault RDP server keeps a password, not a key). Port 3389 by default.
- The web portal shows `coffre` (SSH) and `enregistre` (SSH and RDP) servers; `rebond` servers open from Portunia, or with `ssh -J` / `ssh -L`.

## Access rules

```bash
sudo portunia-gate rule add prod --group "Linux admins" --targets web-01,stg --sftp --tunnels --days mon-fri --hours 7-20
sudo portunia-gate rule add contractor --group Contractors --targets db-01 --record-input --expires 2026-12-31
sudo portunia-gate rule add windows --group Accounting --targets srv-ad-01 --files   # Remote Desktop: file copy allowed
sudo portunia-gate rule list                              # with their state now: active, outside hours, expired
sudo portunia-gate rule edit prod --sftp off --targets web-01,web-02   # switches: on or off
sudo portunia-gate rule edit contractor --expires 2027-03-31 --hours ""  # "" clears days, hours or expiry
sudo portunia-gate rule edit prod --rename production --group Admins
sudo portunia-gate rule edit windows --files off             # file copy blocked again
sudo portunia-gate rule delete contractor                 # sessions it allowed close within 30 s
```

`--sftp`, `--tunnels` (vault SSH servers) and `--record-input` (careful: captures typed passwords) apply to SSH.

`--files` applies to Remote Desktop in recorded mode: copying files through the clipboard, in both directions (from the web portal: drop files on the desktop or « Send files », then paste in Windows; copy files in Windows to download them). Without it, the Gate blocks file copy; copied text still passes. With it, each file is written to the audit log (`fichier.copie`: direction, name, size, SHA-256) and shows in the recording; blocked attempts are logged as `fichier.bloque`. In jump mode the stream is encrypted end to end: the Gate can neither see nor block it (use a Windows group policy).

## General settings

```bash
sudo portunia-gate setting                                # all settings with their value
sudo portunia-gate setting name "ACME Gate"
sudo portunia-gate setting language fr                    # en, fr, or "" for the system language
sudo portunia-gate setting auth_policy "password+totp,key+totp"
sudo portunia-gate setting banner "Authorised access only. Sessions are recorded."
sudo portunia-gate setting session_hours 8                # Portunia sign-in duration, 1 to 168 hours
sudo portunia-gate setting remember_password off          # Portunia may remember the Gate password on workstations
sudo portunia-gate setting own_replay off                 # each account may replay its own sessions
sudo portunia-gate setting sensitive_commands "rm -rf,shutdown,DROP TABLE"   # marked on the player's timeline
sudo portunia-gate setting file_copies_mb 200             # keep copied files, up to 200 MB per session (0: none)
sudo portunia-gate setting session_hours                  # without a value: shows it
```

French names are accepted too: `nom`, `langue`, `banniere`, `duree_session_h`, `memo_mot_de_passe`, `relecture_propres`, `commandes_sensibles`, `copies_fichiers_mo`.

Kept file copies go next to the recording, in `/var/lib/portunia-gate/enregistrements/YYYY/MM/<session>-fichiers/`; their SHA-256 is in the signed recording and in the audit log.

## Web portal

```bash
sudo portunia-gate portal show                            # state, settings, live state, exposure
sudo portunia-gate portal set --url https://access.acme.com --group "Web access" --duration 4 --idle 30 --clipboard on
sudo portunia-gate portal set --code off                  # no authenticator code, except accounts whose own combinations demand it
sudo portunia-gate user policy marc password              # or: this account only signs in without a code
sudo portunia-gate portal set --turnstile-site 0x4AAA… --turnstile-secret   # secret key asked (empty entry: erases it)
sudo portunia-gate portal on                              # opens the portal
sudo portunia-gate portal off                             # closes it; open web sessions close within 30 s
sudo portunia-gate portal close-sessions                  # ends web sessions without closing the portal
sudo portunia-gate portal test                            # does this Gate answer at the public address?
```

How browsers reach the portal:

```bash
sudo portunia-gate portal expose cloudflare               # cloudflare, internal, direct, proxy or relay
sudo portunia-gate portal expose internal --networks 10.0.0.0/8,192.168.0.0/16
sudo portunia-gate portal expose proxy --trusted 10.0.5.10,10.0.5.11 --header X-Forwarded-For
sudo portunia-gate portal tunnel -                        # Cloudflare tunnel token read on standard input; --remove stops it
sudo portunia-gate portal tunnel                          # tunnel state
sudo portunia-gate portal https 8446                      # HTTPS listener (internal, direct, proxy); --off closes it
sudo portunia-gate portal cert                            # shows the HTTPS listener's certificate
sudo portunia-gate portal cert --import portal.pfx        # or --import cert.pem --key key.pem; --remove: self-signed
sudo portunia-gate portal relay-add dmz-01 10.0.5.20:8447 # dedicated relay: prints its pairing command
sudo portunia-gate portal relay-list
sudo portunia-gate portal relay-remove dmz-01
```

Let's Encrypt for the HTTPS listener:

```bash
sudo portunia-gate portal acme --domains access.acme.com --email it@acme.com --method tls-alpn --accept-terms
sudo portunia-gate portal acme --domains "*.acme.com" --method dns-cloudflare --cloudflare-token --accept-terms
sudo portunia-gate portal acme                            # state, last and next renewal, error
sudo portunia-gate portal acme --renew                    # renews now
sudo portunia-gate portal acme --staging on               # test authority (certificates not trusted)
sudo portunia-gate portal acme --off
```

`tls-alpn` needs the HTTPS listener open and public port 443 redirected to it; `dns-cloudflare` needs a Cloudflare API token (Zone › DNS › Edit) and allows wildcard names. Read the [Let's Encrypt Subscriber Agreement](https://letsencrypt.org/repository/) before `--accept-terms`.

A dedicated relay is installed on its own machine with `sudo bash installer.sh relay CODE public-name`; its certificate is replaced with `sudo runuser -u _portunia_gate -- /usr/lib/portunia-gate/portunia-gate edge certificate cert.pem key.pem`, then `sudo systemctl restart portunia-gate-relais`.

## Remote assistance

```bash
sudo portunia-gate assist set --group Technicians --duration 4   # technicians' group, maximum duration (1 to 12 h)
sudo portunia-gate assist on                              # the Gate fetches Portunia Assistance within 30 s
sudo portunia-gate assist off                             # sessions under way stop within 30 s
sudo portunia-gate assist show                            # state, program ready, people waiting
```

The page for the person helped is `https://<portal address>/assistance`: set the portal's public address first.

## Native RDP

Ordinary RDP clients (mstsc, Windows App, Remmina, FreeRDP) with a single-use .rdp file prepared by Portunia. Closed by default.

```bash
sudo portunia-gate rdp set --port 3390 --modes rebond,coffre,enregistre --ticket-seconds 120
sudo portunia-gate rdp set --address gate.example.com:3390   # address written in the files, if it differs (NAT, DNS name)
sudo portunia-gate rdp on                                   # listening within 3 s; open the port on the firewall
sudo portunia-gate rdp off                                  # sessions under way continue
sudo portunia-gate rdp show                                 # state, port, modes, certificate shown to the clients
```

Without Portunia (0.34): in mstsc, computer = the Gate's address and the native RDP port, user = `login%server` (or `login%server%code`), password = the account's RDP password (`user rdp-password`, or the web portal). Vault and Recorded servers; Recorded ones must accept a connection without NLA.

With Docker, keep port 3390 inside the container and change the published one (`PORTUNIA_GATE_RDP_PORT` in `.env`), then `--address`. `PORTUNIA_GATE_RDP_BIND` limits listening to one address (0.0.0.0 by default).

## Audit log and sessions

```bash
sudo portunia-gate audit --last 50                        # latest events
sudo portunia-gate audit --search marc --last 200         # account, event or detail containing the text
sudo portunia-gate audit --verify                         # checks the whole chain: a deleted or edited event shows
sudo portunia-gate audit --last 5000 --csv journal.csv    # export for a spreadsheet (same format as Portunia)
sudo portunia-gate sessions --last 20
sudo portunia-gate sessions --user marc --server web-01 --since 2026-11-01 --until 2026-11-30
sudo portunia-gate sessions --text "rm -rf"               # text shown on screen or typed
sudo portunia-gate sessions --input                       # sessions whose keystrokes are recorded
sudo portunia-gate sessions --files                       # Remote Desktop sessions where files were copied
sudo portunia-gate sessions show 3f2a9c1e                 # details, recording file, signature check
```

`sessions show` prints the recording's path and checks its signature (`✓ Signature verified` or `⚠ ALTERED FILE`). An SSH recording (`.cast`, asciicast v2) can be played in a terminal with `sudo asciinema play <file>`. That replay is **not logged** and shows masked input: keep it to system administrators, and use Portunia for auditors. Remote Desktop recordings (`.rdpcap`) are replayed in Portunia only.

## Without Portunia, from scratch

```bash
sudo bash installer.sh                                    # installs the Gate; note the fingerprint and temporary password
sudo portunia-gate user totp admin                        # enrol your code
sudo portunia-gate user passwd admin                      # replace the temporary password
sudo portunia-gate target add web-01 --host 10.0.1.11 --mode enregistre
sudo portunia-gate group add Admins && sudo portunia-gate group member Admins admin
sudo portunia-gate rule add admins --group Admins --targets web-01
ssh -p 2222 admin@gate.acme.com                           # password, then code
```
