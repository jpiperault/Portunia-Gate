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
    if args.web:
        host, _, port = args.web.partition(":")
        gate("target", "add", f"{PREFIX}web", "--host", host, "--port", port or "443", "--protocol", "https", "--mode", "enregistre", "--folder", FOLDER)
        targets.append(f"{PREFIX}web")
    gate("rule", "delete", f"{PREFIX}regle", check=False)
    if targets:
        gate("rule", "add", f"{PREFIX}regle", "--group", f"{PREFIX}groupe", "--targets", ",".join(targets), "--sftp", "--tunnels", "--files")
    gate("rdp", "set", "--port", str(args.rdp_port), "--modes", "rebond,coffre,enregistre", "--ticket-seconds", "120")
    gate("rdp", "on")
    time.sleep(4)
    return win_password, targets


# ---------- Essais ----------

class Report:
    def __init__(self):
        self.rows = []

    def check(self, ident, title, fn):
        start = time.time()
        try:
            detail = fn() or ""
            ok = True
        except Skip as e:
            self.rows.append({"id": ident, "titre": title, "resultat": "sauté", "detail": str(e), "duree_s": 0})
            print(f"  –  {ident} {title} : sauté ({e})")
            return
        except Exception as e:  # noqa: BLE001 : chaque essai rapporte son échec et la recette continue
            detail, ok = str(e), False
        self.rows.append({"id": ident, "titre": title, "resultat": "ok" if ok else "ÉCHEC", "detail": detail, "duree_s": round(time.time() - start, 1)})
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


def rdp_session(args, token=None, user=None, password=None, nla=False, seconds=25):
    """xfreerdp sous Xvfb vers l'entrée native ; renvoie (resté ouvert, fin de sa sortie)."""
    cmd = ["xvfb-run", "-a", freerdp(), f"/v:127.0.0.1:{args.rdp_port}", "/cert:ignore", "/size:1280x800", "+clipboard"]
    if token:
        cmd.append(f"/load-balance-info:{token}")
    if user:
        cmd += [f"/u:{user}", f"/p:{password}"]
    cmd.append("/sec:nla" if nla else "/sec:tls")
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=ENV)
    try:
        out = p.communicate(timeout=seconds)[0]
        return False, (out or "").strip()[-300:]
    except subprocess.TimeoutExpired:
        p.terminate()
        try:
            p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
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
    time.sleep(3)
    found = sessions_since(api, admin, target, since)
    expect(found, f"aucune session {target} au journal des sessions")
    s = found[0]
    expect("(natif)" in (s["adresse"] or ""), f"adresse sans « (natif) » : {s['adresse']}")
    expect(s["type"] == kind, f"type {s['type']} au lieu de {kind}")
    if kind == "rdp":
        expect(s["enregistree"], "session non enregistrée")
    expect((s["octets"] or 0) > 10_000, f"trop peu d'octets relayés ({s['octets']})")
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
        return f"{len(targets)} serveurs"
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
                stayed, out = rdp_session(args, token)
                expect(stayed, f"xfreerdp s'est arrêté : {out}")
                return recorded_session(api, admin, f"{PREFIX}win-coffre", since, "rdp")
            report.check("G-RDP-09", "RDP natif, coffre (xfreerdp)", vault)

            def recorded():
                since = now_utc()
                token, _ = native_token(api, user, f"{PREFIX}win-enr", args.win_user, win_password)
                stayed, out = rdp_session(args, token)
                expect(stayed, f"xfreerdp s'est arrêté : {out}")
                return recorded_session(api, admin, f"{PREFIX}win-enr", since, "rdp")
            report.check("G-RDP-10", "RDP natif, enregistré avec compte", recorded)

            def recorded_without():
                since = now_utc()
                token, _ = native_token(api, user, f"{PREFIX}win-enr")
                stayed, _ = rdp_session(args, token, seconds=15)
                expect(not stayed, "session ouverte sans compte (le serveur n'exige pas NLA ?)")
                refused = [e for e in events_since(api, admin, f"{PREFIX}win-enr", since) if e["evenement"] == "acces.refuse"]
                expect(refused, "pas d'acces.refuse au journal")
                return refused[0]["detail"].get("raison", "")
            report.check("G-RDP-11", "RDP natif, enregistré sans compte refusé", recorded_without)

            def jump():
                since = now_utc()
                token, _ = native_token(api, user, f"{PREFIX}win-rebond")
                stayed, out = rdp_session(args, token, user=args.win_user, password=win_password, nla=True)
                expect(stayed, f"xfreerdp s'est arrêté : {out}")
                return recorded_session(api, admin, f"{PREFIX}win-rebond", since, "rebond")
            report.check("G-RDP-12", "RDP natif, rebond (NLA de bout en bout)", jump)

            def single_use():
                token = used.get("coffre")
                if not token:
                    raise Skip("pas de jeton du coffre (G-RDP-09 a échoué)")
                since = now_utc()
                stayed, _ = rdp_session(args, token, seconds=15)
                expect(not stayed, "le même fichier a rouvert une session")
                expect(not sessions_since(api, admin, f"{PREFIX}win-coffre", since), "session ouverte avec un jeton usagé")
            report.check("G-RDP-13", "Fichier .rdp à usage unique", single_use)

            def modes():
                gate("rdp", "set", "--modes", "rebond,enregistre")
                try:
                    status, body, _ = api.call("POST", f"/api/v1/serveurs/{PREFIX}win-coffre/rdp-natif", {}, token=user)
                    expect(status == 403, f"coffre retiré des modes mais fichier donné ({status})")
                    status, body, _ = api.call("GET", "/api/v1/serveurs", token=user)
                    flag = next(s for s in body["serveurs"] if s["nom"] == f"{PREFIX}win-coffre").get("rdp_natif")
                    expect(flag is False, "rdp_natif toujours vrai pour le coffre")
                finally:
                    gate("rdp", "set", "--modes", "rebond,coffre,enregistre")
            report.check("G-RDP-14", "Modes réglables", modes)

            def denied():
                gate("group", "remove", f"{PREFIX}groupe", f"{PREFIX}user")
                try:
                    status, _, _ = api.call("POST", f"/api/v1/serveurs/{PREFIX}win-coffre/rdp-natif", {}, token=user)
                    expect(status == 403, f"compte hors du groupe mais fichier donné ({status})")
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
            out = run(["sshpass", "-p", t["ticket"], "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                       "-p", str(t["port_ssh"]), f"{t['utilisateur_ssh']}@127.0.0.1", "whoami"])
            expect(args.win_user.lower() in out.lower(), f"whoami : {out.strip()}")
            time.sleep(2)
            expect(sessions_since(api, admin, f"{PREFIX}win-ssh", since), "pas de session au journal")
            return out.strip()
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
            seen = {e["evenement"] for e in events_since(api, admin, f"{PREFIX}web", since)}
            expect("web.ouvert" in seen, f"journal sans web.ouvert ({seen})")
            return f"{len(page)} octets, {sorted(seen)}"
        report.check("G-WEB-01", "Interface web par jeton", web)

    def chain():
        out = gate("audit", "--verify", "--last", "1")
        expect("Log intact" in out, out.strip()[-200:])
        return out.splitlines()[0]
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
    parser.add_argument("--only", help="parties : rdp, ssh, web (séparées par des virgules)")
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
        json.dump({"version": gate("--version").strip(), "date": started.isoformat(), "essais": report.rows}, f, indent=2, ensure_ascii=False)
    ok = sum(r["resultat"] == "ok" for r in report.rows)
    print(f"\n{ok}/{len(report.rows)} réussis ; rapport : {path}")
    sys.exit(1 if report.failed else 0)


if __name__ == "__main__":
    main()
