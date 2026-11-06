"""Rapport de recette du banc d'essai : HTML autonome (captures intégrées) imprimé en PDF par
Chromium. Appelé par recette.py à la fin, ou seul pour refaire un rapport :

    python3 rapport.py /root/.banc/rapport-AAAAMMJJ-HHMM.json [--notes notes.json]

`notes.json` : {"G-RDP-12": "commentaire", ...}, ajouté au commentaire automatique.
"""

import base64
import html
import json
import os
import shutil
import subprocess
import sys

# Pour chaque essai : objectif, méthode, résultat attendu.
DESCRIPTIONS = {
    "API-01": ("Le compte de test voit exactement les serveurs que lui donne sa règle, et l'entrée RDP native est signalée pour les serveurs Windows.",
               "Connexion à l'API de la Gate (mot de passe + code TOTP calculé), puis liste des serveurs du compte.",
               "Les 5 serveurs du banc (3 Windows en RDP, 1 Windows en SSH, 1 interface web) ; « rdp_natif » vrai pour les 3 serveurs RDP."),
    "G-RDP-09": ("Un client RDP ordinaire ouvre un serveur au coffre sans connaître son mot de passe.",
                 "Fichier .rdp à usage unique demandé à l'API ; xfreerdp se connecte au port 3390 de la Gate avec le jeton dans « loadbalanceinfo », en TLS simple ; capture de l'écran au bout de 25 s.",
                 "Bureau Windows ouvert avec le compte du coffre ; session « rdp / coffre » depuis « (natif) », enregistrée, avec des octets relayés."),
    "G-RDP-10": ("Mode enregistré : la Gate ouvre la session avec le compte Windows donné en préparant le fichier.",
                 "Même chose, le compte Windows de test étant envoyé à l'API avec la demande de fichier (gardé en mémoire par la Gate le temps du jeton).",
                 "Bureau Windows du compte de test ; session « rdp / enregistré » depuis « (natif) », enregistrée."),
    "G-RDP-11": ("Mode enregistré sans compte, vers un serveur qui exige NLA : refus clair.",
                 "Fichier demandé sans compte Windows, puis connexion xfreerdp.",
                 "Connexion refusée ; « acces.refuse » au journal avec la raison « le serveur exige NLA »."),
    "G-RDP-12": ("Mode rebond : la Gate laisse passer la connexion telle quelle, chiffrement et authentification Windows de bout en bout.",
                 "Fichier demandé, puis xfreerdp en NLA avec le compte Windows de test ; capture au bout de 25 s.",
                 "Bureau Windows ; session « rebond / rdp (natif) » fermée par le client, avec le nombre d'octets relayés."),
    "G-RDP-13": ("Un fichier .rdp ne sert qu'une fois.",
                 "Nouvelle connexion avec le jeton déjà utilisé en G-RDP-09.",
                 "Connexion fermée par la Gate ; aucune nouvelle session."),
    "G-RDP-14": ("Les modes accessibles par l'entrée native se règlent.",
                 "« rdp set --modes rebond,enregistre », puis demande d'un fichier pour le serveur au coffre et liste des serveurs ; réglage remis ensuite.",
                 "Fichier refusé (403) ; « rdp_natif » faux pour le serveur au coffre."),
    "G-RDP-16": ("Sans règle active, pas de fichier.",
                 "Compte de test retiré de son groupe, demande d'un fichier, compte remis.",
                 "Fichier refusé (403) ; « acces.refuse » au journal."),
    "G-SSH-01": ("SSH au coffre par jeton, comme Portunia : la Gate ouvre la session avec le mot de passe du coffre.",
                 "Jeton SSH demandé à l'API, puis « ssh compte%serveur@gate whoami » avec le jeton comme mot de passe (OpenSSH de Windows).",
                 "Réponse « machine\\test » ; session « exec » enregistrée."),
    "G-WEB-01": ("Interface web publiée par la Gate (ici l'interface de Proxmox).",
                 "Jeton web, entrée /web/entree, cookie de session, page d'accueil relayée ; capture par un navigateur sans écran.",
                 "Page de connexion de Proxmox affichée à travers la Gate ; « web.ouvert » au journal, certificat du serveur mémorisé."),
    "G-SSH-02": ("Transfert de fichiers SFTP vers un serveur au coffre, avec un jeton.",
                 "sftp par la Gate : envoi d'un fichier, liste, récupération, suppression ; comparaison des contenus.",
                 "Fichier récupéré identique à l'envoyé ; session « sftp » au journal des sessions."),
    "G-SSH-03": ("Tunnel (ssh -L) à travers un serveur au coffre, quand la règle l'autorise.",
                 "Tunnel local vers le port 3389 du Windows, puis demande RDP minimale à travers lui.",
                 "Le serveur RDP de Windows répond à travers le tunnel ; session « tunnel » au journal."),
    "G-SSH-04": ("Connexion SSH directe d'un utilisateur, sans Portunia : mot de passe puis code TOTP.",
                 "ssh -p 2222 compte%serveur@gate whoami, réponses aux invites dans un pseudo-terminal.",
                 "Commande exécutée sur le Windows par le compte du coffre."),
    "G-SSH-05": ("Rebond SSH de bout en bout (ssh -J) : la Gate relaie sans voir le contenu.",
                 "ssh -J compte@gate:2222 test@windows whoami : mot de passe et code pour la Gate, mot de passe Windows pour le serveur.",
                 "Commande exécutée ; session « rebond » au journal, non enregistrée."),
    "G-SSH-06": ("Un utilisateur peut prendre son temps pour taper son code (moins de 60 s).",
                 "Connexion SSH directe ; mot de passe tout de suite, code TOTP 35 s plus tard.",
                 "Connexion acceptée et commande exécutée ; la limite de 60 s pour s'authentifier n'est pas atteinte."),
    "G-AUD-02": ("Un enregistrement de Bureau à distance est signé et relisible.",
                 "Lecture par l'API d'audit de l'enregistrement de la dernière session au coffre par RDP natif (G-RDP-09).",
                 "Signature « verifiee », images et durée non nulles."),
    "G-AUD-03": ("Un enregistrement SSH est signé et contient ce qui s'est passé.",
                 "Lecture par l'API d'audit de l'enregistrement de la commande whoami (G-SSH-01).",
                 "Signature « verifiee », sortie de la commande présente."),
    "G-AUD-04": ("Une altération d'un enregistrement est détectée.",
                 "Un octet ajouté au fichier d'enregistrement sur le disque, relecture, puis remise en état.",
                 "Signature « alteree » tant que le fichier est modifié, « verifiee » une fois remis."),
    "G-POR-01": ("Connexion au portail web avec mot de passe et code TOTP.",
                 "Chromium sans écran, piloté par son protocole de débogage : formulaire du portail rempli et envoyé.",
                 "Liste des serveurs autorisés affichée."),
    "G-POR-02": ("Terminal SSH dans le navigateur, vers un serveur au coffre.",
                 "Ouverture de /session/serveur, frappe de « whoami » dans le terminal.",
                 "Réponse du Windows affichée dans le terminal ; session ouverte depuis « (web) »."),
    "G-POR-03": ("Bureau à distance dans le navigateur, serveur au coffre (passage RDCleanPath, le même que l'onglet de Portunia).",
                 "Ouverture de /bureau/serveur, bouton « Ouvrir la session » ; capture au bout de 15 s, puis bouton « Fermer ».",
                 "Bureau Windows dans la page ; session « rdp / coffre » depuis « (web) », enregistrée, fermée moins de 10 s après « Fermer »."),
    "G-POR-04": ("Bureau à distance dans le navigateur, mode enregistré : identifiants Windows tapés dans la page.",
                 "Formulaire du bureau rempli avec le compte de test, puis ouverture.",
                 "Bureau Windows ; session « rdp / enregistré » depuis « (web) », enregistrée."),
    "G-POR-05": ("Bureau à distance dans le navigateur, mode rebond : la Gate relaie sans enregistrer.",
                 "Formulaire du bureau rempli avec le compte de test, puis ouverture.",
                 "Bureau Windows ; session « rebond / rdp (web) », non enregistrée."),
    "G-POR-06": ("Interface web publiée dans le portail.",
                 "Ouverture de /web/serveur dans le navigateur ; capture au bout de 10 s.",
                 "Page de connexion de Proxmox ; « web.ouvert » au journal."),
    "G-POR-07": ("Fermer l'onglet du navigateur ferme la session sur la Gate.",
                 "Bureau à distance au coffre ouvert dans un second onglet, puis onglet fermé brutalement.",
                 "Session fermée par la Gate dans les secondes qui suivent (moins de 15 s)."),
    "G-AUD-01": ("Le journal d'audit n'a pas été altéré.",
                 "« portunia-gate audit --verify » à la fin de la recette.",
                 "« Log intact » et le nombre d'événements chaînés."),
}

STYLE = """
@page { size: A4; margin: 16mm 14mm; }
body { font-family: 'DejaVu Sans', sans-serif; font-size: 10.5pt; color: #1d2330; line-height: 1.45; }
h1 { font-size: 20pt; margin: 0 0 4px; } h2 { font-size: 13pt; margin: 0; }
.muted { color: #5b6475; } .small { font-size: 9pt; }
table.sum { border-collapse: collapse; width: 100%; margin: 12px 0 20px; }
.sum th, .sum td { border-bottom: 1px solid #d9dde5; padding: 5px 6px; text-align: left; vertical-align: top; font-size: 9.5pt; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-weight: bold; font-size: 9pt; }
.ok { background: #dff3e6; color: #17663a; } .ko { background: #fbe1e1; color: #9b1c1c; } .skip { background: #eceff3; color: #4b5563; }
.card { page-break-inside: avoid; border: 1px solid #d9dde5; border-radius: 6px; padding: 10px 12px; margin: 0 0 14px; }
.card h2 { display: flex; justify-content: space-between; gap: 8px; }
dl { display: grid; grid-template-columns: 34mm 1fr; gap: 3px 10px; margin: 8px 0; }
dt { color: #5b6475; } dd { margin: 0; }
pre { background: #f4f6f9; border-radius: 4px; padding: 6px 8px; font-size: 8pt; white-space: pre-wrap; word-break: break-all; margin: 6px 0; }
img { max-width: 100%; border: 1px solid #d9dde5; border-radius: 4px; margin-top: 6px; }
.totals { display: flex; gap: 10px; margin: 10px 0; } .totals div { padding: 6px 12px; border-radius: 6px; }
.brk { page-break-before: always; }
"""


def esc(text):
    return html.escape(str(text or ""))


def badge(result):
    cls = {"ok": "ok", "ÉCHEC": "ko"}.get(result, "skip")
    label = {"ok": "Réussi", "ÉCHEC": "Échec"}.get(result, "Sauté")
    return f'<span class="badge {cls}">{label}</span>'


def build(report, captures_dir, notes):
    rows = report["essais"]
    ok = sum(r["resultat"] == "ok" for r in rows)
    ko = sum(r["resultat"] == "ÉCHEC" for r in rows)
    out = [f"<!doctype html><html lang='fr'><head><meta charset='utf-8'><title>Recette Portunia Gate</title><style>{STYLE}</style></head><body>"]
    out.append("<h1>Recette du banc d'essai</h1>")
    out.append(f"<p class='muted'>{esc(report['version'])} · {esc(report['date'][:16].replace('T', ' '))} UTC · Windows Server {esc(report.get('windows'))} · console web {esc(report.get('web'))}</p>")
    out.append(f"<div class='totals'><div class='ok'><b>{ok}</b> réussis</div><div class='ko'><b>{ko}</b> en échec</div><div class='skip'><b>{len(rows) - ok - ko}</b> sautés</div></div>")
    out.append("<p>Essais automatiques lancés sur la Gate de test par <code>tests/banc/recette.py</code>. Les résultats sont lus dans l'API de la Gate (liste des sessions, journal d'audit), jamais supposés. "
               "Les captures sont celles de l'écran reçu par le client RDP (xfreerdp sur un écran virtuel) et de la page vue par un navigateur sans écran. "
               "Ce qui demande des yeux (Portunia, mstsc, portail web, relecture) se vérifie avec le plan de test.</p>")
    if notes.get("_synthese"):
        out.append(f"<h2 style='margin-top:14px'>Synthèse</h2><p>{esc(notes['_synthese']).replace(chr(10), '<br>')}</p>")
    out.append("<table class='sum'><tr><th>Essai</th><th>Titre</th><th>Résultat</th><th>Durée</th></tr>")
    for r in rows:
        out.append(f"<tr><td>{esc(r['id'])}</td><td>{esc(r['titre'])}</td><td>{badge(r['resultat'])}</td><td>{r.get('duree_s', 0)} s</td></tr>")
    out.append("</table>")
    out.append("<div class='brk'></div>")
    for r in rows:
        goal, method, expected = DESCRIPTIONS.get(r["id"], ("", "", ""))
        comment = r.get("detail", "")
        if notes.get(r["id"]):
            comment = f"{comment}\n\n{notes[r['id']]}" if comment else notes[r["id"]]
        out.append(f"<div class='card'><h2><span>{esc(r['id'])} · {esc(r['titre'])}</span>{badge(r['resultat'])}</h2><dl>")
        for label, value in (("Objectif", goal), ("Méthode", method), ("Résultat attendu", expected)):
            if value:
                out.append(f"<dt>{label}</dt><dd>{esc(value)}</dd>")
        out.append(f"<dt>Commentaire</dt><dd>{esc(comment).replace(chr(10), '<br>')}</dd></dl>")
        if r.get("preuve"):
            out.append(f"<div class='small muted'>Preuve relevée sur la Gate</div><pre>{esc(r['preuve'])}</pre>")
        capture = r.get("capture")
        path = os.path.join(captures_dir, capture) if capture else None
        if path and os.path.exists(path):
            data = base64.b64encode(open(path, "rb").read()).decode()
            out.append(f"<div class='small muted'>Capture du résultat obtenu</div><img src='data:image/png;base64,{data}'>")
        out.append("</div>")
    out.append("</body></html>")
    return "".join(out)


def make(json_path, notes_path=None):
    report = json.load(open(json_path, encoding="utf-8"))
    notes = json.load(open(notes_path, encoding="utf-8")) if notes_path else {}
    base = json_path[:-5] if json_path.endswith(".json") else json_path
    with open(base + ".html", "w", encoding="utf-8") as f:
        f.write(build(report, report.get("captures", os.path.dirname(json_path)), notes))
    exe = shutil.which("chromium") or shutil.which("chromium-browser")
    if not exe:
        return base + ".html"
    subprocess.run([exe, "--headless", "--no-sandbox", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={base}.pdf", "file://" + os.path.abspath(base + ".html")],
                   capture_output=True, timeout=120)
    return base + ".pdf" if os.path.exists(base + ".pdf") else base + ".html"


if __name__ == "__main__":
    args = sys.argv[1:]
    notes = args[args.index("--notes") + 1] if "--notes" in args else None
    print(make(args[0], notes))
