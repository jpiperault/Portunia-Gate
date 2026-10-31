# Running Portunia Gate

**English** · [Français](exploitation.fr.md)

The `portunia-gate` command, installed by the wizard, works from any folder, with the Debian package as with Docker. `docker compose` commands are run from the repository folder.

## What to back up

| Item | Where | Why |
|---|---|---|
| **Vault key** | `/var/lib/portunia-gate/coffre.key` | Decrypts server secrets and TOTP secrets. **Lost = secrets lost.** Keep it off the server, separate from the database. |
| SSH host key | `/var/lib/portunia-gate/ssh_host_ed25519_key` | Without it, users see a new fingerprint and must accept it again. |
| API certificate | `/var/lib/portunia-gate/api.crt` and `api.key` | Without it, Portunia shows a new fingerprint to accept. |
| Signing key | `/var/lib/portunia-gate/signature.key` | Signs recordings. |
| PostgreSQL database | `portunia-gate` database | Accounts, servers, rules, sessions, audit log. |
| Recordings | `/var/lib/portunia-gate/enregistrements/YYYY/MM/` | `.cast` (SSH) and `.rdpcap` (Remote Desktop) session files. |
| Settings | `/etc/portunia-gate/portunia-gate.env` (package) or the repository's `.env` (Docker) | Ports, time zone, database access. |

With Docker, `/var/lib/portunia-gate` lives in the container (`donnees` volume).

**Debian package:**

```bash
sudo -u postgres pg_dump portunia_gate | gzip > portunia-gate-db-$(date +%F).sql.gz
sudo tar czf portunia-gate-data-$(date +%F).tar.gz -C /var/lib portunia-gate -C /etc portunia-gate
```

**Docker**, from the repository folder:

```bash
sudo docker compose exec -T postgres pg_dump -U portunia_gate portunia_gate | gzip > portunia-gate-db-$(date +%F).sql.gz
sudo docker cp "$(sudo docker compose ps -q portunia-gate)":/var/lib/portunia-gate - | gzip > portunia-gate-data-$(date +%F).tar.gz
```

Store these files off the server. The data archive contains the vault key: protect it like a password.

## Updating

```bash
sudo bash installer.sh update       # Debian package
sudo ./installer.sh update          # Docker, from the repository folder
```

With the package, the wizard downloads the latest version, checks its fingerprint and installs it. With Docker, it fetches the latest version (`git pull`) and rebuilds. Either way, the Gate restarts and updates the database schema. **Open sessions are cut**: warn users.

After an update, the web portal loads its new pages by itself (their files carry the version number).

## Finding the connection details

```bash
sudo portunia-gate info              # name, version, SSH and API fingerprints, number of accounts
sudo bash installer.sh info    # the same, with the address and ports to enter in Portunia
```

## Logs

- Service: `sudo journalctl -u portunia-gate -f` (package) or `sudo docker compose logs -f portunia-gate` (Docker)
- Audit log: `sudo portunia-gate audit --last 100`
- Log integrity: `sudo portunia-gate audit --verify` (shows the first missing or altered event)

The audit log can also be read in Portunia (Gate menu › Audit › Log), with CSV export.

Main events: `auth.reussie` (the `via` field is `portunia` for an API sign-in; the factors `jeton Portunia` or `portail web` for a session opened by Portunia or the web portal), `auth.echec` (with the reason), `session.ouverte`, `session.fermee`, `rebond.ouvert`, `sftp.ouvert`, `tunnel.ouvert`, `acces.refuse`, `cible.empreinte_memorisee`, `cible.empreinte_differente`, `cible.identifiants_refuses`, `compte.*`, `groupe.*`, `cible.creee`, `regle.creee`, `reglage.modifie`, `portail.*`, `enregistrement.consulte`, `enregistrement.revele`, `installation`, `service.demarre`.

## Built-in monitoring

Every 20 seconds the Gate checks that its database answers and that its SSH server greets new connections; an independent thread also checks that its internal task scheduler keeps running. If the Gate stays stuck for about a minute, it writes the cause to the service log (`surveillance : …`, with the state of its database connections) and stops, so that systemd (`Restart=on-failure`) or Docker (`restart: unless-stopped`) restarts it. If this happens, send the lines before the restart: `sudo journalctl -u portunia-gate -n 100` or `sudo docker compose logs --tail 100 portunia-gate`.

## Checking a recording

Each recorded session has in the database its SHA-256 fingerprint and the Ed25519 signature of this text:

```
portunia-gate-enregistrement-v1
<session id>
<sha256 fingerprint of the file>
```

The public signing key is kept in the database (`signature_publique` setting) and shown by `sudo portunia-gate init`, which can safely be run again.

Portunia's player (Gate menu › Audit) runs this check on every opening and flags an altered file. At the end of each SSH session, the Gate also stores the session text in the database (screen and keystrokes, without masked input) for search: roughly the size of the displayed text.

## Server fingerprint

On the first connection, Portunia Gate remembers the server's key (SSH) or certificate (Remote Desktop) fingerprint. If it changes later, the connection is refused and the `cible.empreinte_differente` event is logged. Check that the server was really reinstalled, then clear the stored fingerprint in Portunia (Administer › Servers › Forget fingerprint). The next one is remembered on the next connection.

## Troubleshooting

### Installation

| Symptom | Likely cause |
|---|---|
| "Docker does not start" in an LXC container | Enable *nesting* and *keyctl* on the container (Proxmox › Options › Features), restart it, run `sudo ./installer.sh` again. |
| The build stops (`killed`, `signal 9`, `out of memory`) | Not enough memory: 4 GB recommended. Add memory or swap, then run `sudo ./installer.sh` again: the install resumes where it stopped. |
| "Port 2222 is already in use" | Another service uses it: pick another port when asked. |
| "Download failed" | The server cannot reach github.com: download `portunia-gate_amd64.deb` from a computer, copy it to the server and run `sudo bash installer.sh --package portunia-gate_amd64.deb`. |
| "The downloaded package is altered" | Corrupted or intercepted download: retry; if the message persists, do not install and report it. |
| The `portunia-gate` service does not start (package) | `sudo journalctl -u portunia-gate -n 50`. In an unprivileged LXC container without *nesting*, systemd hardening can fail: enable *nesting* (Proxmox › Options › Features) and restart the container. |
| "Illegal instruction" during initialisation | Package 0.5.0 only: it required a CPU with AVX, missing from Proxmox's default virtual CPU (kvm64). Fixed in 0.5.1: run `sudo bash installer.sh` again, which resumes the install with the latest version. |
| "Docker Compose v2 is missing" | Distribution too old: install Docker from https://docs.docker.com/engine/install/ and try again. |
| `git clone` rejects the password | GitHub expects an access token instead of the password (see README). |

### Connecting from Portunia

| Symptom | Likely cause |
|---|---|
| Portunia cannot reach the Gate | API port (8443) blocked by a firewall, or wrong address: `sudo bash installer.sh info`. |
| The fingerprint shown by Portunia differs from `portunia-gate info` | Do not sign in: you may not be on the right Gate. Check the address. |
| "Wrong login, password or code" | The exact reason is in the log: `sudo portunia-gate audit --last 10` (unknown account, wrong password, wrong code…). |
| The code is refused on the first sign-in | Delete the old Portunia Gate entry from the authenticator app, empty the Code field and sign in again to get a new QR code. |
| `Wrong code` although it is right | Phone or server clock out of sync (synchronise them, NTP), or code already used: wait for the next one (30 s). |
| "Too many attempts" | 5 failures in 10 minutes: wait a few minutes. |
| Lost code (new phone) | An administrator resets the code (Administer › Accounts, or `sudo portunia-gate user totp <account>`). |
| No administrator can sign in any more | On the server: `sudo bash installer.sh admin rescue` creates an administrator with a temporary password. |
| "Gate session expired" | Sign in again from the Gates section. |
| "No server is allowed to you right now" or empty list | No rule for your groups, or outside the rule's days, hours or dates. Hours follow the `TZ` time zone. |
| "The vault account was refused" | The account's password or key changed on the server: replace its secret (Portunia › Administer › Servers). |
| The Gate restarted on its own | Built-in monitoring found it stuck: see [Built-in monitoring](#built-in-monitoring) and send the log lines. |

## Known limitations

- Single command (`ssh login%server@Gate "command"`), SFTP and tunnels: Vault-mode servers only, since the Gate must connect without asking anything.
- Remote forwarding (`ssh -R`) is refused.
- Sign-in from Portunia: accounts using a password (with or without a code). An "SSH key only" account connects with a standard SSH client.
- One install per server for the `portunia-gate` command (it points to the last installed folder).
- Remote Desktop: Vault mode and session replay are not available yet.

## Limits and session closing

**Sign-in attempts.** Counted together for SSH, Portunia and the portal, over 10 minutes: 5 for an account from one address, 20 for an address, 30 for an account across all addresses. The log records `auth.bloquee`. Limits are kept in memory: restarting the service clears them. An HTTP request has 10 seconds for its headers and 2 minutes in all. An SSH connection has 60 seconds to authenticate, and unauthenticated connections are capped (16 per address, 512 in total).

If Docker hides the clients' real address, they all seem to come from one address and share these limits: check the addresses in the log.

**Access withdrawn.** Rights are checked every 30 seconds, and immediately after a change made from Portunia. A session closes when the account is disabled or deleted, the server deleted, or the rule removed, expired or **outside its hours**. A portal session also closes with the portal or when leaving its group. The log records `session.coupee`.

**Recording.** A recorded session does not open if recording is impossible, and closes if a write fails (`enregistrement.echec`). Below `PORTUNIA_GATE_MIN_FREE_MB` (512 MB by default), new recorded sessions are refused (`disque.presque_plein`). Below half that threshold, ongoing ones close. Set up an alert on these events, and preferably a separate disk for `/var/lib/portunia-gate/enregistrements`.
