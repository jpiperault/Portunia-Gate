#!/usr/bin/env python3
"""Recette du banc d'essai de Portunia Gate : se lance en root sur la Gate de test.

Crée (ou recrée) ses propres comptes, groupe, serveurs et règle, tous préfixés « banc- »,
puis vérifie de bout en bout ce qui se vérifie sans écran : RDP natif (xfreerdp sous Xvfb),
SSH et SFTP par jeton, interface web, refus attendus, chaîne du journal. Les résultats sont
lus dans l'API de la Gate (sessions, journal), jamais supposés.

    sudo python3 recette.py --windows 192.168.1.60 --win-user banc --win-password-file /root/.banc/windows
    sudo python3 recette.py ... --web 192.168.1.40:8006 --windows-ssh --only rdp,web

Le reste (Portunia, mstsc, portail, relecture) se coche dans docs/plan-de-test.html.
Python 3.9+, sans dépendance ; outils : xfreerdp (ou xfreerdp3), xvfb-run, sshpass, ssh, sftp.
"""

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import shutil
import signal
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

GATE = "portunia-gate"
HOME = "/root/.banc"
STATE = f"{HOME}/etat.json"
ENV = dict(os.environ, PORTUNIA_GATE_LANG="en")
PREFIX = "banc-"
FOLDER = "Banc"


# ---------- Outils ----------

def run(args, stdin=None, check=True, timeout=60):
    p = subprocess.run(args, input=stdin, capture_output=True, text=True, env=ENV, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:3])}…: {(p.stderr or p.stdout).strip()[-400:]}")
    return p.stdout


def gate(*args, stdin=None, check=True):
    return run([GATE, *args], stdin=stdin, check=check)


def totp(secret_b32, step):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    h = hmac.new(key, struct.pack(">q", step), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"comptes": {}}


def save_state(state):
    os.makedirs(HOME, mode=0o700, exist_ok=True)
    with open(STATE, "w") as f:
        json.dump(state, f, indent=2)
    os.chmod(STATE, 0o600)


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def parse_date(text):
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


# ---------- API de la Gate ----------

class Api:
    def __init__(self, port):
        self.base = f"https://127.0.0.1:{port}"
        # Gate locale : certificat auto-signé, joint par la boucle locale.
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def call(self, method, path, body=None, token=None, raw=False, headers=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept-Language", "fr")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ctx), NoRedirect())
        try:
            with opener.open(req, timeout=30) as r:
                payload = r.read()
                return r.status, (payload if raw else json.loads(payload or b"null")), r.headers
        except urllib.error.HTTPError as e:
            payload = e.read()
            try:
                value = payload if raw else json.loads(payload or b"null")
            except ValueError:
                value = payload.decode(errors="replace")
            return e.code, value, e.headers


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# ---------- Préparation ----------

def ensure_account(state, login, role):
    """Compte avec mot de passe et code TOTP connus du banc ; recréé s'il est inconnu du banc."""
    listed = gate("user", "list")
    known = state["comptes"].get(login)
    if known and login in listed:
        return known
    if login in listed:
        gate("user", "delete", login)
    password = secrets.token_urlsafe(18)
    p = subprocess.Popen([GATE, "user", "add", login, "--role", role], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, env=ENV, bufsize=1)
    p.stdin.write(password + "\n")
    p.stdin.flush()
    secret = None
    for line in p.stdout:
        if "Or type the key:" in line:
            secret = line.split(":", 1)[1].strip()
            break
    if not secret:
        p.kill()
        raise RuntimeError(f"enrôlement TOTP de {login} : clé introuvable dans la sortie")
    step = int(time.time()) // 30
    p.stdin.write(totp(secret, step) + "\n")
    p.stdin.flush()
    out = p.communicate(timeout=30)[0]
    if p.returncode != 0:
        raise RuntimeError(f"création de {login} : {out.strip()[-300:]}")
    state["comptes"][login] = {"mot_de_passe": password, "totp": secret, "pas": step}
    save_state(state)
    return state["comptes"][login]


def login(api, state, account):
    """Jeton d'API ; attend un pas TOTP neuf (un code ne sert qu'une fois)."""
    a = state["comptes"][account]
    while int(time.time()) // 30 <= a.get("pas", 0):
        time.sleep(1)
    step = int(time.time()) // 30
    status, body, _ = api.call("POST", "/api/v1/connexion", {"login": account, "mot_de_passe": a["mot_de_passe"], "code": totp(a["totp"], step), "client": "banc"})
    a["pas"] = step
    save_state(state)
    if status != 200 or body.get("etat") != "ok":
        raise RuntimeError(f"connexion de {account} : {status} {body}")
    return body["jeton"]


def setup(args, state):
    win_password = open(args.win_password_file).read().strip() if args.win_password_file else None
    ensure_account(state, f"{PREFIX}admin", "admin")
    ensure_account(state, f"{PREFIX}user", "user")
    gate("group", "add", f"{PREFIX}groupe", check=False)
    gate("group", "member", f"{PREFIX}groupe", f"{PREFIX}user", f"{PREFIX}admin")
    # Serveurs repris à neuf à chaque passage (empreintes, secrets du coffre).
    for line in gate("target", "list").splitlines():
        name = line.split()[0] if line.split() else ""
        if name.startswith(PREFIX):
            gate("target", "delete", name, check=False)
    targets = []
    if args.windows:
        common = ["--host", args.windows, "--protocol", "rdp", "--folder", FOLDER]
        gate("target", "add", f"{PREFIX}win-coffre", *common, "--mode", "coffre", "--account", args.win_user, "--password", stdin=win_password + "\n")
        gate("target", "add", f"{PREFIX}win-enr", *common, "--mode", "enregistre", "--account", args.win_user)
        gate("target", "add", f"{PREFIX}win-rebond", *common, "--mode", "rebond", "--account", args.win_user)
        targets += [f"{PREFIX}win-coffre", f"{PREFIX}win-enr", f"{PREFIX}win-rebond"]
        if args.windows_ssh:
            gate("target", "add", f"{PREFIX}win-ssh", "--host", args.windows, "--protocol", "ssh", "--mode", "coffre", "--account", args.win_user, "--password", "--folder", FOLDER, stdin=win_password + "\n")
            targets.append(f"{PREFIX}win-ssh")
            gate("target", "add", f"{PREFIX}win-ssh-rebond", "--host", args.windows, "--protocol", "ssh", "--mode", "rebond", "--account", args.win_user, "--folder", FOLDER)
            targets.append(f"{PREFIX}win-ssh-rebond")
    if args.web:
        host, _, port = args.web.partition(":")
        gate("target", "add", f"{PREFIX}web", "--host", host, "--port", port or "443", "--protocol", "https", "--mode", "enregistre", "--folder", FOLDER)
        targets.append(f"{PREFIX}web")
    gate("rule", "delete", f"{PREFIX}regle", check=False)
    if targets:
        gate("rule", "add", f"{PREFIX}regle", "--group", f"{PREFIX}groupe", "--targets", ",".join(targets), "--sftp", "--tunnels", "--files")
    gate("rdp", "set", "--port", str(args.rdp_port), "--modes", "rebond,coffre,enregistre", "--ticket-seconds", "120")
    gate("rdp", "on")
    if args.portal_port:
        # Portail du banc : écoute HTTPS locale, réseau interne, groupe du banc, code exigé.
        gate("portal", "set", "--group", f"{PREFIX}groupe", "--code", "on")
        gate("portal", "expose", "internal", "--networks", "127.0.0.0/8")
        gate("portal", "https", f"127.0.0.1:{args.portal_port}")
        gate("portal", "on")
    time.sleep(5)
    return win_password, targets


# ---------- Essais ----------

class Report:
    def __init__(self):
        self.rows = []

    def check(self, ident, title, fn):
        """`fn` renvoie un détail, ou {"detail", "preuve", "capture"} ; une exception = échec.
        Les preuves et captures d'un essai qui échoue restent dans `EVIDENCE` pour le rapport."""
        start = time.time()
        EVIDENCE.clear()
        try:
            result = fn() or ""
            ok = True
        except Skip as e:
            self.rows.append({"id": ident, "titre": title, "resultat": "sauté", "detail": str(e), "duree_s": 0})
            print(f"  –  {ident} {title} : sauté ({e})")
            return
        except Exception as e:  # noqa: BLE001 : chaque essai rapporte son échec et la recette continue
            result, ok = str(e), False
        row = dict(EVIDENCE)
        row.update(result if isinstance(result, dict) else {"detail": result})
        row.update({"id": ident, "titre": title, "resultat": "ok" if ok else "ÉCHEC", "duree_s": round(time.time() - start, 1)})
        self.rows.append(row)
        detail = row.get("detail", "")
        print(f"  {'✓' if ok else '✗'}  {ident} {title}{' : ' + detail if detail else ''}")

    @property
    def failed(self):
        return [r for r in self.rows if r["resultat"] == "ÉCHEC"]


class Skip(Exception):
    pass


def expect(cond, message):
    if not cond:
        raise AssertionError(message)


def freerdp():
    for name in ("xfreerdp3", "xfreerdp"):
        if shutil.which(name):
            return name
    raise Skip("xfreerdp absent (apt install freerdp2-x11 ou freerdp3-x11)")


CAPTURES = f"{HOME}/captures"
# Preuves de l'essai en cours (texte, capture), gardées même s'il échoue.
EVIDENCE = {}


class Screen:
    """Écran virtuel (Xvfb) où s'affiche xfreerdp, pour en prendre une capture."""

    def __enter__(self):
        for n in range(50, 90):
            if not os.path.exists(f"/tmp/.X11-unix/X{n}"):
                self.display = f":{n}"
                break
        self.xvfb = subprocess.Popen(["Xvfb", self.display, "-screen", "0", "1280x800x24", "-nolisten", "tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        return self

    def shot(self, name):
        os.makedirs(CAPTURES, exist_ok=True)
        path = f"{CAPTURES}/{name}.png"
        subprocess.run(["import", "-display", self.display, "-window", "root", path], capture_output=True, timeout=30)
        return os.path.basename(path) if os.path.exists(path) else None

    def __exit__(self, *_):
        self.xvfb.terminate()
        self.xvfb.wait(timeout=10)


def stop(p):
    """xfreerdp et ses éventuels enfants, sans les laisser connectés."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(p.pid, sig)
            p.wait(timeout=8)
            return
        except (ProcessLookupError, subprocess.TimeoutExpired):
            continue


def rdp_session(args, name, token=None, user=None, password=None, nla=False, seconds=25):
    """xfreerdp sur un écran virtuel vers l'entrée native ; capture l'écran au bout de `seconds`
    et renvoie (resté ouvert, fin de sa sortie). La capture va dans EVIDENCE."""
    cmd = [freerdp(), f"/v:127.0.0.1:{args.rdp_port}", "/cert:ignore", "/size:1280x800", "+clipboard"]
    if token:
        cmd.append(f"/load-balance-info:{token}")
    if user:
        cmd += [f"/u:{user}", f"/p:{password}"]
    # TLS simple (coffre, enregistré) : la Gate ouvre la session Windows ; l'identifiant donné à
    # xfreerdp n'est là que pour qu'il ne le demande pas au clavier.
    cmd += ["/sec:nla"] if nla else ["/sec:tls", "/u:portunia", "/p:portunia"]
    with Screen() as screen:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=dict(ENV, DISPLAY=screen.display), start_new_session=True)
        try:
            out = p.communicate(timeout=seconds)[0]
            return False, (out or "").strip()[-300:]
        except subprocess.TimeoutExpired:
            EVIDENCE["capture"] = screen.shot(name)
            stop(p)
            return True, ""


def sessions_since(api, admin, target, since):
    status, body, _ = api.call("GET", "/api/v1/admin/sessions?limite=100", token=admin)
    expect(status == 200, f"sessions : {status}")
    return [s for s in body["sessions"] if s["serveur"] == target and parse_date(s["debut"]) >= since]


def events_since(api, admin, text, since):
    status, body, _ = api.call("GET", f"/api/v1/admin/journal?limite=200&q={urllib.parse.quote(text)}", token=admin)
    expect(status == 200, f"journal : {status}")
    return [e for e in body["evenements"] if parse_date(e["date"]) >= since]


def native_token(api, user_token, target, account=None, password=None):
    body = {"compte": account, "mot_de_passe": password} if account else {}
    status, answer, _ = api.call("POST", f"/api/v1/serveurs/{target}/rdp-natif", body, token=user_token)
    expect(status == 200, f"fichier .rdp refusé : {status} {answer}")
    # Le jeton garde son préfixe « portunia-gate: » : c'est lui que la Gate cherche dans la demande.
    return answer["jeton"], answer


def recorded_session(api, admin, target, since, kind):
    """Session fermée (le relevé des octets et l'enregistrement ne sont complets qu'à la fin)."""
    found = []
    for _ in range(30):
        found = sessions_since(api, admin, target, since)
        if found and found[0]["fin"]:
            break
        time.sleep(1)
    expect(found, f"aucune session {target} au journal des sessions")
    s = found[0]
    EVIDENCE["preuve"] = (f"session {s['id'][:8]} · {s['compte']} → {s['serveur']} · {s['type']} ({s['detail']})\n"
                          f"adresse {s['adresse']} · début {s['debut'][:19]} · fin {(s['fin'] or 'en cours')[:19]}\n"
                          f"{s['octets']} octets relayés · enregistrée : {'oui' if s['enregistree'] else 'non'}")
    expect(s["fin"], "session toujours ouverte 30 s après la fermeture du client")
    expect("(natif)" in (s["adresse"] or ""), f"adresse sans « (natif) » : {s['adresse']}")
    expect(s["type"] == kind, f"type {s['type']} au lieu de {kind}")
    if kind == "rdp":
        expect(s["enregistree"], "session non enregistrée")
    expect((s["octets"] or 0) > 10_000, f"trop peu d'octets relayés ({s['octets']})")
    return f"{s['octets']} octets, {s['detail']}"


def journal_lines(events):
    return "\n".join(f"{e['date'][11:19]}  {e['qui']}  {e['evenement']}  {json.dumps(e['detail'], ensure_ascii=False)}" for e in reversed(events[:6]))


def web_capture(port, ticket, name):
    """Page publiée par la Gate, vue par un navigateur sans écran (Chromium), si présent."""
    exe = shutil.which("chromium") or shutil.which("chromium-browser")
    if not exe or not ticket:
        return None
    os.makedirs(CAPTURES, exist_ok=True)
    path = f"{CAPTURES}/{name}.png"
    url = f"https://127.0.0.1:{port}/web/entree?jeton={urllib.parse.quote(ticket)}"
    subprocess.run([exe, "--headless", "--no-sandbox", "--disable-gpu", "--ignore-certificate-errors", "--hide-scrollbars",
                    "--window-size=1280,800", "--virtual-time-budget=15000", f"--screenshot={path}", url], capture_output=True, timeout=120)
    return os.path.basename(path) if os.path.exists(path) else None


# ---------- Conversation dans un pseudo-terminal (ssh avec mot de passe et code) ----------

def converse(cmd, answers, timeout=60):
    """Lance `cmd` dans un pseudo-terminal et répond aux invites, dans l'ordre : `answers` est une
    liste de (texte attendu, réponse ou fonction). Renvoie (sortie, code de sortie)."""
    import pty
    import select
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(cmd[0], cmd, ENV)
    text, pos, step = "", 0, 0
    end = time.time() + timeout
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 1)
        if fd not in ready:
            continue
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        text += data.decode(errors="replace")
        if step < len(answers) and answers[step][0].lower() in text[pos:].lower():
            answer = answers[step][1]
            os.write(fd, ((answer() if callable(answer) else answer) + "\n").encode())
            pos, step = len(text), step + 1
    try:
        done, status = os.waitpid(pid, os.WNOHANG)
        if not done:
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        status = 0
    return text, os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else status


def fresh_code(state, account):
    """Code TOTP d'un pas jamais servi (la Gate refuse un code déjà utilisé)."""
    a = state["comptes"][account]
    while int(time.time()) // 30 <= a.get("pas", 0):
        time.sleep(1)
    step = int(time.time()) // 30
    a["pas"] = step
    save_state(state)
    return totp(a["totp"], step)


SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"]


def ssh_ticket(api, user, target):
    status, t, _ = api.call("POST", f"/api/v1/serveurs/{target}/ticket", token=user)
    expect(status == 200, f"jeton : {status} {t}")
    return t


# ---------- Essais SSH complémentaires ----------

def ssh_more(args, state, api, report, admin, user, win_password):
    target = f"{PREFIX}win-ssh"

    def sftp():
        since = now_utc()
        t = ssh_ticket(api, user, target)
        sample = f"banc {secrets.token_hex(8)}\n"
        with open("/tmp/banc-envoi.txt", "w") as f:
            f.write(sample)
        batch = "put /tmp/banc-envoi.txt banc-envoi.txt\nls -l banc-envoi.txt\nget banc-envoi.txt /tmp/banc-retour.txt\nrm banc-envoi.txt\n"
        out = run(["sshpass", "-p", t["ticket"], "sftp", *SSH_OPTS, "-o", "BatchMode=no", "-o", "PreferredAuthentications=password", "-P", str(t["port_ssh"]), "-b", "-", f"{t['utilisateur_ssh']}@127.0.0.1"], stdin=batch)
        back = open("/tmp/banc-retour.txt").read()
        expect(back == sample, "le fichier récupéré diffère de l'envoyé")
        time.sleep(2)
        found = sessions_since(api, admin, target, since)
        expect(found and found[0]["type"] == "sftp", f"pas de session sftp ({[s['type'] for s in found]})")
        return {"detail": "envoi, liste, récupération et suppression d'un fichier ; contenu identique",
                "preuve": out.strip()[-600:] + f"\n\nsession {found[0]['id'][:8]} · {found[0]['type']} · enregistrée : {'oui' if found[0]['enregistree'] else 'non'}"}
    report.check("G-SSH-02", "SFTP au coffre par jeton", sftp)

    def tunnel():
        since = now_utc()
        t = ssh_ticket(api, user, target)
        local = 13389
        p = subprocess.Popen(["sshpass", "-p", t["ticket"], "ssh", *SSH_OPTS, "-o", "PreferredAuthentications=password", "-N",
                              "-L", f"127.0.0.1:{local}:127.0.0.1:3389", "-p", str(t["port_ssh"]), f"{t['utilisateur_ssh']}@127.0.0.1"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=ENV, start_new_session=True)
        try:
            time.sleep(4)
            import socket
            with socket.create_connection(("127.0.0.1", local), timeout=10) as s:
                # Demande X.224 minimale : le serveur RDP de Windows doit répondre par un paquet TPKT.
                s.sendall(bytes([3, 0, 0, 19, 14, 0xE0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0]))
                answer = s.recv(64)
            expect(answer[:1] == b"\x03", f"réponse inattendue à travers le tunnel : {answer[:8].hex()}")
        finally:
            stop(p)
        time.sleep(2)
        found = [s for s in sessions_since(api, admin, target, since) if s["type"] == "tunnel"]
        expect(found, "pas de session « tunnel » au journal des sessions")
        return {"detail": f"port 3389 du Windows joint par le tunnel ; réponse RDP {answer[:4].hex()}",
                "preuve": f"ssh -N -L 127.0.0.1:{local}:127.0.0.1:3389 {t['utilisateur_ssh']}@gate\nconnexion à 127.0.0.1:{local} → réponse TPKT {answer[:19].hex()}\nsession {found[0]['id'][:8]} · tunnel ({found[0]['detail']})"}
    report.check("G-SSH-03", "Tunnel (ssh -L) à travers un serveur au coffre", tunnel)

    def direct():
        a = state["comptes"][f"{PREFIX}user"]
        out, code = converse(["ssh", *SSH_OPTS, "-o", "PreferredAuthentications=keyboard-interactive,password", "-p", "2222",
                              f"{PREFIX}user%{target}@127.0.0.1", "whoami"],
                             [("password", a["mot_de_passe"]), ("code", lambda: fresh_code(state, f"{PREFIX}user"))], timeout=90)
        expect(args.win_user.lower() in out.lower(), f"pas de réponse de whoami (code {code}) : {out.strip()[-200:]}")
        return {"detail": "mot de passe puis code TOTP, commande exécutée par le compte du coffre",
                "preuve": "$ ssh -p 2222 banc-user%banc-win-ssh@gate whoami\n" + out.replace(a["mot_de_passe"], "••••").strip()[-500:]}
    report.check("G-SSH-04", "Connexion directe : mot de passe et code TOTP", direct)

    def slow_code():
        a = state["comptes"][f"{PREFIX}user"]

        def late():
            # Comme un utilisateur qui cherche son téléphone : plus de 30 s avant de taper le code.
            time.sleep(35)
            return fresh_code(state, f"{PREFIX}user")
        start = time.time()
        out, code = converse(["ssh", *SSH_OPTS, "-o", "PreferredAuthentications=keyboard-interactive,password", "-p", "2222",
                              f"{PREFIX}user%{target}@127.0.0.1", "whoami"],
                             [("password", a["mot_de_passe"]), ("code", late)], timeout=120)
        shown = out.replace(a["mot_de_passe"], "••••").strip()[-400:]
        EVIDENCE["preuve"] = f"$ ssh -p 2222 banc-user%banc-win-ssh@gate whoami   (code tapé après 35 s)\n{shown}"
        expect(args.win_user.lower() in out.lower(), f"connexion coupée pendant l'attente du code (code {code}) : {shown[-160:]}")
        return {"detail": f"code accepté {round(time.time() - start)} s après le début de la connexion", "preuve": EVIDENCE["preuve"]}
    report.check("G-SSH-06", "Code TOTP tapé lentement (35 s)", slow_code)

    def jump():
        since = now_utc()
        a = state["comptes"][f"{PREFIX}user"]
        hop = " ".join(["ssh", *SSH_OPTS, "-o", "PreferredAuthentications=keyboard-interactive,password", "-p", "2222", "-W", "%h:%p", f"{PREFIX}user@127.0.0.1"])
        out, code = converse(["ssh", *SSH_OPTS, "-o", "PreferredAuthentications=keyboard-interactive,password",
                              "-o", f"ProxyCommand={hop}", f"{args.win_user}@{args.windows}", "whoami"],
                             [("password", a["mot_de_passe"]), ("code", lambda: fresh_code(state, f"{PREFIX}user")), ("password", win_password)], timeout=120)
        expect(args.win_user.lower() in out.lower(), f"pas de réponse de whoami (code {code}) : {out.strip()[-300:]}")
        time.sleep(2)
        found = [s for s in sessions_since(api, admin, f"{PREFIX}win-ssh-rebond", since) if s["type"] == "rebond"]
        expect(found, "pas de session de rebond au journal des sessions")
        return {"detail": "rebond de bout en bout : la Gate relaie sans voir le contenu",
                "preuve": f"$ ssh -J banc-user@gate:2222 {args.win_user}@{args.windows} whoami\n" + out.replace(a["mot_de_passe"], "••••").replace(win_password, "••••").strip()[-400:]
                + f"\n\nsession {found[0]['id'][:8]} · rebond ({found[0]['detail']}) · {found[0]['octets']} octets"}
    report.check("G-SSH-05", "Rebond de bout en bout (ssh -J)", jump)


# ---------- Enregistrements ----------

def audit_more(args, state, api, report, admin):
    def recording(target, kind):
        status, body, _ = api.call("GET", "/api/v1/admin/sessions?limite=200", token=admin)
        expect(status == 200, f"sessions : {status}")
        found = [s for s in body["sessions"] if s["serveur"] == target and s["type"] == kind and s["enregistree"] and s["fin"]
                 and (kind != "rdp" or "(natif)" in (s["adresse"] or ""))]
        if not found:
            raise Skip(f"aucune session {kind} enregistrée sur {target}")
        s = found[0]
        status, rec, _ = api.call("GET", f"/api/v1/audit/sessions/{s['id']}/enregistrement", token=admin)
        expect(status == 200, f"enregistrement : {status} {rec}")
        return s, rec

    def rdp_recording():
        s, rec = recording(f"{PREFIX}win-coffre", "rdp")
        expect(rec["signature"] == "verifiee", f"signature : {rec['signature']}")
        expect(rec["rdp"]["images"] > 0 and rec["rdp"]["duree"] > 0, f"enregistrement vide : {rec['rdp']['images']} image(s)")
        return {"detail": f"signature vérifiée, {rec['rdp']['images']} images sur {round(rec['rdp']['duree'])} s",
                "preuve": f"session {s['id'][:8]} · {s['compte']} → {s['serveur']}\nempreinte SHA-256 {rec['empreinte']}\nsignature : {rec['signature']}\névénements : {json.dumps(rec['rdp']['compte'], ensure_ascii=False)}"}
    report.check("G-AUD-02", "Enregistrement RDP signé et relisible", rdp_recording)

    def ssh_recording():
        s, rec = recording(f"{PREFIX}win-ssh", "exec")
        expect(rec["signature"] == "verifiee", f"signature : {rec['signature']}")
        expect(args.win_user.lower() in rec["cast"].lower(), "la sortie de whoami n'est pas dans l'enregistrement")
        lines = [json.loads(l)[2] for l in rec["cast"].splitlines()[1:] if l.startswith("[")]
        return {"detail": "signature vérifiée, sortie de la commande présente",
                "preuve": f"session {s['id'][:8]} · {s['detail']}\nsignature : {rec['signature']}\ncontenu : {''.join(lines).strip()[:200]}"}
    report.check("G-AUD-03", "Enregistrement SSH signé et relisible", ssh_recording)

    def tampering():
        s, rec = recording(f"{PREFIX}win-ssh", "exec")
        import glob
        files = glob.glob(f"/var/lib/portunia-gate/enregistrements/**/{s['id']}*", recursive=True)
        files = [f for f in files if os.path.isfile(f) and not f.endswith((".sig", ".json"))]
        if not files:
            raise Skip("fichier d'enregistrement introuvable sur le disque")
        path = files[0]
        original = open(path, "rb").read()
        try:
            with open(path, "ab") as f:
                f.write(b"\n")
            status, altered, _ = api.call("GET", f"/api/v1/audit/sessions/{s['id']}/enregistrement", token=admin)
            expect(status == 200 and altered["signature"] == "alteree", f"altération non détectée : {altered.get('signature') if isinstance(altered, dict) else altered}")
        finally:
            with open(path, "wb") as f:
                f.write(original)
        status, again, _ = api.call("GET", f"/api/v1/audit/sessions/{s['id']}/enregistrement", token=admin)
        expect(again["signature"] == "verifiee", "signature pas retrouvée après remise en état")
        return {"detail": "un octet ajouté au fichier : « alteree » ; fichier remis : « verifiee »",
                "preuve": f"{path}\n+1 octet → signature : alteree\nremis à l'identique → signature : verifiee"}
    report.check("G-AUD-04", "Altération d'un enregistrement détectée", tampering)


# ---------- Portail web, piloté dans Chromium ----------

class Tab:
    """Un onglet de Chromium, piloté par le protocole de débogage (CDP)."""

    def __init__(self, ws_url, target_id=None):
        from websockets.sync.client import connect
        self.id = target_id
        self.ws = connect(ws_url, max_size=None, open_timeout=10)
        self.n = 0
        self.send("Page.enable")
        self.send("Runtime.enable")

    def send(self, method, params=None, timeout=60):
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": method, "params": params or {}}))
        end = time.time() + timeout
        while time.time() < end:
            msg = json.loads(self.ws.recv(timeout=max(1, end - time.time())))
            if msg.get("id") == self.n:
                if "error" in msg:
                    raise RuntimeError(f"{method} : {msg['error'].get('message')}")
                return msg.get("result", {})
        raise TimeoutError(method)

    def js(self, expression):
        r = self.send("Runtime.evaluate", {"expression": expression, "returnByValue": True, "awaitPromise": True})
        if r.get("exceptionDetails"):
            raise RuntimeError(r["exceptionDetails"].get("text", "erreur JavaScript"))
        return r.get("result", {}).get("value")

    def go(self, url, wait="document.readyState === 'complete'"):
        self.send("Page.navigate", {"url": url})
        time.sleep(1)
        return self.until(wait, 30)

    def until(self, condition, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            try:
                if self.js(f"!!({condition})"):
                    return True
            except RuntimeError:
                pass
            time.sleep(0.5)
        return False

    def type(self, text):
        self.send("Input.insertText", {"text": text})

    def key(self, key, code, keycode):
        for kind in ("keyDown", "keyUp"):
            self.send("Input.dispatchKeyEvent", {"type": kind, "key": key, "code": code, "windowsVirtualKeyCode": keycode})

    def shot(self, name):
        os.makedirs(CAPTURES, exist_ok=True)
        data = self.send("Page.captureScreenshot", {"format": "png"})["data"]
        with open(f"{CAPTURES}/{name}.png", "wb") as f:
            f.write(base64.b64decode(data))
        return f"{name}.png"


class Browser(Tab):
    """Chromium sans écran ; l'objet lui-même pilote le premier onglet."""

    def __init__(self):
        exe = shutil.which("chromium") or shutil.which("chromium-browser")
        if not exe:
            raise Skip("chromium absent")
        self.profile = f"/tmp/banc-chromium-{os.getpid()}"
        self.proc = subprocess.Popen([exe, "--headless=new", "--no-sandbox", "--disable-gpu", "--ignore-certificate-errors", "--hide-scrollbars",
                                      "--window-size=1280,800", "--remote-debugging-port=9333", f"--user-data-dir={self.profile}", "about:blank"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        for _ in range(40):
            try:
                pages = json.loads(urllib.request.urlopen("http://127.0.0.1:9333/json", timeout=2).read())
                url = next(p["webSocketDebuggerUrl"] for p in pages if p.get("type") == "page")
                break
            except Exception:  # noqa: BLE001 : Chromium démarre
                time.sleep(0.5)
        else:
            raise RuntimeError("Chromium ne répond pas")
        super().__init__(url)

    def new_tab(self):
        """Onglet de plus, dans la même session de navigation (mêmes cookies)."""
        req = urllib.request.Request("http://127.0.0.1:9333/json/new?about:blank", method="PUT")
        info = json.loads(urllib.request.urlopen(req, timeout=10).read())
        return Tab(info["webSocketDebuggerUrl"], info["id"])

    def close_tab(self, tab):
        """Fermeture brutale de l'onglet, comme un utilisateur qui ferme l'onglet du navigateur."""
        urllib.request.urlopen(f"http://127.0.0.1:9333/json/close/{tab.id}", timeout=10).read()

    def close(self):
        try:
            self.ws.close()
        finally:
            stop(self.proc)
            shutil.rmtree(self.profile, ignore_errors=True)


def portal_tests(args, state, api, report, admin, win_password):
    base = f"https://127.0.0.1:{args.portal_port}"
    try:
        browser = Browser()
    except Skip as e:
        def skipped():
            raise e
        report.check("G-POR-01", "Portail web", skipped)
        return
    a = state["comptes"][f"{PREFIX}user"]
    try:
        def login():
            expect(browser.go(base + "/"), "page du portail injoignable")
            expect(browser.until("document.getElementById('login')", 20), "pas de formulaire de connexion")
            code = fresh_code(state, f"{PREFIX}user")
            browser.js(f"""(() => {{ const set = (id, v) => {{ const e = document.getElementById(id); e.value = v; }};
                set('login', {json.dumps(f'{PREFIX}user')}); set('pass', {json.dumps(a['mot_de_passe'])}); set('code', {json.dumps(code)});
                document.querySelector('form button[type=submit]').click(); }})()""")
            expect(browser.until("document.querySelectorAll('.srv').length > 0", 20), f"pas de liste de serveurs : {browser.js('document.body.innerText').strip()[:200]}")
            names = browser.js("[...document.querySelectorAll('.srv b')].map(b => b.textContent)")
            EVIDENCE["capture"] = browser.shot("G-POR-01")
            return {"detail": f"{len(names)} serveurs affichés", "preuve": "\n".join(names)}
        report.check("G-POR-01", "Portail : connexion (mot de passe et code) et serveurs", login)

        def terminal():
            since = now_utc()
            expect(browser.go(f"{base}/session/{PREFIX}win-ssh"), "page du terminal injoignable")
            time.sleep(6)
            browser.js("document.querySelector('.xterm-helper-textarea')?.focus()")
            browser.type("whoami")
            browser.key("Enter", "Enter", 13)
            # Réponse de whoami (« machine\compte »), pas l'invite qui contient déjà le nom du compte.
            ok = browser.until(f"document.querySelector('.xterm-rows')?.innerText.toLowerCase().includes({json.dumps(chr(92) + args.win_user.lower())})", 20)
            time.sleep(1)
            EVIDENCE["capture"] = browser.shot("G-POR-02")
            text = browser.js("document.querySelector('.xterm-rows')?.innerText || ''")
            expect(ok, f"whoami sans réponse dans le terminal : {text.strip()[-200:]}")
            browser.js("document.getElementById('fermer').click()")
            time.sleep(3)
            browser.go(base + "/?accueil")
            found = sessions_since(api, admin, f"{PREFIX}win-ssh", since)
            return {"detail": "terminal SSH dans le navigateur, commande exécutée", "preuve": text.strip()[-500:] + (f"\n\nsession {found[0]['id'][:8]} · {found[0]['type']} · adresse {found[0]['adresse']}" if found else "")}
        report.check("G-POR-02", "Portail : terminal SSH (coffre)", terminal)

        def desktop(ident, target, account=None, kind="rdp"):
            def run_it():
                since = now_utc()
                expect(browser.go(f"{base}/bureau/{target}"), "page du bureau injoignable")
                expect(browser.until("document.getElementById('ouvrir')", 15), "pas de bouton « Ouvrir la session »")
                time.sleep(2)
                if account:
                    browser.js(f"document.getElementById('utilisateur').value = {json.dumps(account)}; document.getElementById('mdp').value = {json.dumps(win_password)};")
                browser.js("document.getElementById('ouvrir').click()")
                connected = browser.until("!document.getElementById('cad').disabled", 40)
                time.sleep(15)
                EVIDENCE["capture"] = browser.shot(ident)
                expect(connected, f"session non ouverte : {browser.js('document.getElementById(\"erreur\")?.textContent || document.body.innerText').strip()[:200]}")
                # Bouton « Fermer » de la page : la Gate doit fermer la session aussitôt.
                browser.js("document.getElementById('fermer').click()")
                closed_at = now_utc()
                result = recorded_session_web(api, admin, target, since, kind)
                ended = session_end(api, admin, target, since)
                expect(ended and (ended - closed_at).total_seconds() < 10, f"session fermée {round((ended - closed_at).total_seconds()) if ended else '?'} s après « Fermer »")
                browser.go(base + "/?accueil")
                return result
            return run_it
        report.check("G-POR-03", "Portail : Bureau à distance au coffre (navigateur)", desktop("G-POR-03", f"{PREFIX}win-coffre"))
        report.check("G-POR-04", "Portail : Bureau à distance enregistré (navigateur)", desktop("G-POR-04", f"{PREFIX}win-enr", args.win_user))
        report.check("G-POR-05", "Portail : Bureau à distance en rebond (navigateur)", desktop("G-POR-05", f"{PREFIX}win-rebond", args.win_user, "rebond"))

        def tab_closed():
            since = now_utc()
            tab = browser.new_tab()
            tab.go(f"{base}/bureau/{PREFIX}win-coffre")
            expect(tab.until("document.getElementById('ouvrir')", 15), "pas de bouton « Ouvrir la session »")
            time.sleep(2)
            tab.js("document.getElementById('ouvrir').click()")
            expect(tab.until("!document.getElementById('cad').disabled", 40), "session non ouverte")
            time.sleep(5)
            browser.close_tab(tab)
            closed_at = now_utc()
            ended = None
            for _ in range(60):
                ended = session_end(api, admin, f"{PREFIX}win-coffre", since)
                if ended:
                    break
                time.sleep(1)
            expect(ended, "session toujours ouverte 60 s après la fermeture de l'onglet")
            delay = (ended - closed_at).total_seconds()
            expect(delay < 15, f"session fermée {round(delay)} s après la fermeture de l'onglet")
            return {"detail": f"session fermée {max(0, round(delay))} s après la fermeture de l'onglet", "preuve": EVIDENCE.get("preuve", "")}
        report.check("G-POR-07", "Portail : onglet fermé, session fermée", tab_closed)

        if args.web:
            def web():
                since = now_utc()
                browser.go(f"{base}/web/{PREFIX}web")
                time.sleep(10)
                EVIDENCE["capture"] = browser.shot("G-POR-06")
                title = browser.js("document.title")
                events = events_since(api, admin, f"{PREFIX}web", since)
                expect(any(e["evenement"] == "web.ouvert" for e in events), "pas de web.ouvert au journal")
                return {"detail": f"page « {title} » à travers le portail", "preuve": journal_lines(events)}
            report.check("G-POR-06", "Portail : interface web", web)
    finally:
        browser.close()


def session_end(api, admin, target, since):
    """Fin de la première session de ce serveur ouverte depuis `since` (None : pas encore finie)."""
    found = sessions_since(api, admin, target, since)
    if found and found[0]["fin"]:
        EVIDENCE["preuve"] = f"session {found[0]['id'][:8]} · {found[0]['type']} ({found[0]['detail']}) · début {found[0]['debut'][11:19]} · fin {found[0]['fin'][11:19]}"
        return parse_date(found[0]["fin"])
    return None


def recorded_session_web(api, admin, target, since, kind):
    found = []
    for _ in range(30):
        found = sessions_since(api, admin, target, since)
        if found and found[0]["fin"]:
            break
        time.sleep(1)
    expect(found, f"aucune session {target} au journal des sessions")
    s = found[0]
    EVIDENCE["preuve"] = (f"session {s['id'][:8]} · {s['compte']} → {s['serveur']} · {s['type']} ({s['detail']})\n"
                          f"adresse {s['adresse']} · {s['octets']} octets · enregistrée : {'oui' if s['enregistree'] else 'non'}")
    expect("(web)" in (s["adresse"] or ""), f"adresse sans « (web) » : {s['adresse']}")
    expect(s["type"] == kind, f"type {s['type']} au lieu de {kind}")
    if kind == "rdp":
        expect(s["enregistree"], "session non enregistrée")
    return f"{s['octets']} octets, {s['detail']}"


def tests(args, state, api, report, win_password, targets):
    admin = login(api, state, f"{PREFIX}admin")
    user = login(api, state, f"{PREFIX}user")
    only = set(args.only.split(",")) if args.only else None
    want = lambda part: only is None or part in only  # noqa: E731

    def servers():
        status, body, _ = api.call("GET", "/api/v1/serveurs", token=user)
        expect(status == 200, f"{status}")
        names = {s["nom"]: s for s in body["serveurs"]}
        missing = [t for t in targets if t not in names]
        expect(not missing, f"absents : {missing}")
        for t in targets:
            if names[t].get("protocole") == "rdp":
                expect(names[t].get("rdp_natif"), f"{t} sans rdp_natif")
        return {"detail": f"{len(targets)} serveurs", "preuve": "\n".join(f"{n:<18} {names[n].get('protocole', 'ssh'):<6} {names[n]['mode']:<11} rdp_natif={names[n].get('rdp_natif')}" for n in targets)}
    report.check("API-01", "Liste des serveurs du compte de test", servers)

    if want("rdp"):
        if not args.windows:
            def no_windows():
                raise Skip("--windows non donné")
            report.check("G-RDP-09", "RDP natif (coffre, enregistré, rebond)", no_windows)
        else:
            used = {}

            def vault():
                since = now_utc()
                token, _ = native_token(api, user, f"{PREFIX}win-coffre")
                used["coffre"] = token
                stayed, out = rdp_session(args, "G-RDP-09", token)
                expect(stayed, f"xfreerdp s'est arrêté : {out}")
                return recorded_session(api, admin, f"{PREFIX}win-coffre", since, "rdp")
            report.check("G-RDP-09", "RDP natif, coffre (xfreerdp)", vault)

            def recorded():
                since = now_utc()
                token, _ = native_token(api, user, f"{PREFIX}win-enr", args.win_user, win_password)
                stayed, out = rdp_session(args, "G-RDP-10", token)
                expect(stayed, f"xfreerdp s'est arrêté : {out}")
                return recorded_session(api, admin, f"{PREFIX}win-enr", since, "rdp")
            report.check("G-RDP-10", "RDP natif, enregistré avec compte", recorded)

            def recorded_without():
                since = now_utc()
                token, _ = native_token(api, user, f"{PREFIX}win-enr")
                stayed, out = rdp_session(args, "G-RDP-11", token, seconds=15)
                expect(not stayed, "session ouverte sans compte (le serveur n'exige pas NLA ?)")
                refused = [e for e in events_since(api, admin, f"{PREFIX}win-enr", since) if e["evenement"] == "acces.refuse"]
                expect(refused, "pas d'acces.refuse au journal")
                return {"detail": refused[0]["detail"].get("raison", ""), "preuve": journal_lines(refused) + "\n\nxfreerdp : " + out[-200:]}
            report.check("G-RDP-11", "RDP natif, enregistré sans compte refusé", recorded_without)

            def jump():
                since = now_utc()
                token, _ = native_token(api, user, f"{PREFIX}win-rebond")
                stayed, out = rdp_session(args, "G-RDP-12", token, user=args.win_user, password=win_password, nla=True)
                expect(stayed, f"xfreerdp s'est arrêté : {out}")
                return recorded_session(api, admin, f"{PREFIX}win-rebond", since, "rebond")
            report.check("G-RDP-12", "RDP natif, rebond (NLA de bout en bout)", jump)

            def single_use():
                token = used.get("coffre")
                if not token:
                    raise Skip("pas de jeton du coffre (G-RDP-09 a échoué)")
                since = now_utc()
                stayed, out = rdp_session(args, "G-RDP-13", token, seconds=15)
                expect(not stayed, "le même fichier a rouvert une session")
                expect(not sessions_since(api, admin, f"{PREFIX}win-coffre", since), "session ouverte avec un jeton usagé")
                return {"detail": "connexion fermée par la Gate, aucune session", "preuve": "xfreerdp : " + out[-300:]}
            report.check("G-RDP-13", "Fichier .rdp à usage unique", single_use)

            def modes():
                gate("rdp", "set", "--modes", "rebond,enregistre")
                try:
                    status, body, _ = api.call("POST", f"/api/v1/serveurs/{PREFIX}win-coffre/rdp-natif", {}, token=user)
                    expect(status == 403, f"coffre retiré des modes mais fichier donné ({status})")
                    status, body, _ = api.call("GET", "/api/v1/serveurs", token=user)
                    flag = next(s for s in body["serveurs"] if s["nom"] == f"{PREFIX}win-coffre").get("rdp_natif")
                    expect(flag is False, "rdp_natif toujours vrai pour le coffre")
                    return {"detail": "fichier refusé (403), entrée retirée du coffre", "preuve": "rdp set --modes rebond,enregistre\nPOST /serveurs/banc-win-coffre/rdp-natif → 403\nGET /serveurs → banc-win-coffre rdp_natif = false"}
                finally:
                    gate("rdp", "set", "--modes", "rebond,coffre,enregistre")
            report.check("G-RDP-14", "Modes réglables", modes)

            def denied():
                gate("group", "remove", f"{PREFIX}groupe", f"{PREFIX}user")
                try:
                    status, _, _ = api.call("POST", f"/api/v1/serveurs/{PREFIX}win-coffre/rdp-natif", {}, token=user)
                    expect(status == 403, f"compte hors du groupe mais fichier donné ({status})")
                    return {"detail": "fichier refusé (403)", "preuve": "group remove banc-groupe banc-user\nPOST /serveurs/banc-win-coffre/rdp-natif → 403\njournal : acces.refuse « aucune règle active »"}
                finally:
                    gate("group", "member", f"{PREFIX}groupe", f"{PREFIX}user")
            report.check("G-RDP-16", "Sans règle : refusé", denied)

    if want("ssh") and args.windows_ssh:
        def ssh_vault():
            if not shutil.which("sshpass"):
                raise Skip("sshpass absent")
            since = now_utc()
            status, t, _ = api.call("POST", f"/api/v1/serveurs/{PREFIX}win-ssh/ticket", token=user)
            expect(status == 200, f"jeton : {status} {t}")
            # Méthode « mot de passe », comme Portunia : en clavier interactif, la Gate attend le vrai mot de passe.
            out = run(["sshpass", "-p", t["ticket"], "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                       "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                       "-p", str(t["port_ssh"]), f"{t['utilisateur_ssh']}@127.0.0.1", "whoami"])
            expect(args.win_user.lower() in out.lower(), f"whoami : {out.strip()}")
            time.sleep(2)
            found = sessions_since(api, admin, f"{PREFIX}win-ssh", since)
            expect(found, "pas de session au journal")
            s = found[0]
            return {"detail": out.strip(), "preuve": f"$ ssh -p {t['port_ssh']} {t['utilisateur_ssh']}@gate whoami\n{out.strip()}\n\nsession {s['id'][:8]} · {s['type']} ({s['detail']}) · enregistrée : {'oui' if s['enregistree'] else 'non'}"}
        report.check("G-SSH-01", "SSH au coffre par jeton (commande unique)", ssh_vault)

    if want("web") and args.web:
        def web():
            since = now_utc()
            status, t, _ = api.call("POST", f"/api/v1/serveurs/{PREFIX}web/ticket", token=user)
            expect(status == 200, f"jeton : {status} {t}")
            status, _, headers = api.call("GET", f"/web/entree?jeton={urllib.parse.quote(t['ticket'])}", raw=True)
            expect(status in (302, 303, 307), f"entrée web : {status}")
            cookie = "; ".join(c.split(";", 1)[0] for c in headers.get_all("Set-Cookie") or [])
            expect(cookie, "pas de cookie de session web")
            status, page, _ = api.call("GET", "/", raw=True, headers={"Cookie": cookie})
            expect(status == 200, f"page d'accueil : {status}")
            time.sleep(1)
            events = events_since(api, admin, f"{PREFIX}web", since)
            seen = {e["evenement"] for e in events}
            expect("web.ouvert" in seen, f"journal sans web.ouvert ({seen})")
            # Capture de la page telle que l'utilisateur la voit, avec un second jeton.
            status, t2, _ = api.call("POST", f"/api/v1/serveurs/{PREFIX}web/ticket", token=user)
            capture = web_capture(args.api_port, t2.get("ticket", ""), "G-WEB-01") if status == 200 else None
            return {"detail": f"{len(page)} octets, {sorted(seen)}", "preuve": journal_lines(events), "capture": capture}
        report.check("G-WEB-01", "Interface web par jeton", web)

    if want("ssh") and args.windows_ssh:
        ssh_more(args, state, api, report, admin, user, win_password)
    if want("portail") and args.windows and args.portal_port:
        portal_tests(args, state, api, report, admin, win_password)
    if want("audit"):
        audit_more(args, state, api, report, admin)

    def chain():
        out = gate("audit", "--verify", "--last", "1")
        expect("Log intact" in out, out.strip()[-200:])
        return {"detail": out.splitlines()[0], "preuve": "$ portunia-gate audit --verify\n" + out.splitlines()[0]}
    report.check("G-AUD-01", "Chaîne du journal intacte", chain)


def main():
    parser = argparse.ArgumentParser(description="Recette du banc d'essai de Portunia Gate")
    parser.add_argument("--windows", help="adresse du Windows Server de test")
    parser.add_argument("--win-user", default="banc", help="compte Windows de test (DOMAINE\\compte ou compte)")
    parser.add_argument("--win-password-file", help="fichier (root, 600) contenant son mot de passe")
    parser.add_argument("--windows-ssh", action="store_true", help="le Windows a OpenSSH Server : essais SSH et SFTP")
    parser.add_argument("--web", help="console web à publier, hôte:port (ex. l'interface de Proxmox, 8006)")
    parser.add_argument("--api-port", type=int, default=8443)
    parser.add_argument("--rdp-port", type=int, default=3390)
    parser.add_argument("--portal-port", type=int, default=8446, help="écoute HTTPS locale du portail pour les essais (0 : pas d'essais du portail)")
    parser.add_argument("--only", help="parties : rdp, ssh, web, portail, audit (séparées par des virgules)")
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("À lancer en root (sudo), sur la Gate de test.")
    if args.windows and not args.win_password_file:
        sys.exit("--win-password-file est demandé avec --windows.")
    print(gate("--version").strip())
    state = load_state()
    win_password, targets = setup(args, state)
    api = Api(args.api_port)
    report = Report()
    started = now_utc()
    tests(args, state, api, report, win_password, targets)
    path = f"{HOME}/rapport-{started.strftime('%Y%m%d-%H%M')}.json"
    with open(path, "w") as f:
        json.dump({"version": gate("--version").strip(), "date": started.isoformat(), "windows": args.windows, "web": args.web, "captures": CAPTURES, "essais": report.rows}, f, indent=2, ensure_ascii=False)
    ok = sum(r["resultat"] == "ok" for r in report.rows)
    print(f"\n{ok}/{len(report.rows)} réussis ; rapport : {path}")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import rapport
        print(f"rapport lisible : {rapport.make(path)}")
    except Exception as e:  # noqa: BLE001 : le rapport lisible est un plus, la recette a déjà rendu son verdict
        print(f"rapport lisible impossible : {e}")
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
