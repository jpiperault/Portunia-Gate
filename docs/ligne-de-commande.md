# Portunia Gate — référence de la ligne de commande

*Portunia Gate 0.26 et suivantes ; copie de fichiers en Bureau à distance : 0.28 et suivantes.* [English version](command-line.md)

Tout ce que fait le menu **Administrer** de Portunia sur une Gate se fait aussi sur le serveur de la Gate avec la commande `portunia-gate`. Une Gate s'exploite donc entièrement depuis un poste Linux ou macOS, en SSH : comptes, groupes, serveurs, règles, réglages, portail web, Let's Encrypt, assistance à distance, journal d'audit et recherche de sessions. Seule la **relecture des sessions** reste dans Portunia (lecteur vidéo, révélation des saisies masquées).

## L'essentiel

```bash
sudo portunia-gate --help                 # toutes les commandes
sudo portunia-gate user --help            # les options d'une commande
sudo portunia-gate rule edit --help
```

- Paquet Debian : la commande `/usr/bin/portunia-gate` tourne sous le compte de service `_portunia_gate`, avec la configuration de la Gate. Lancez-la avec `sudo`.
- Docker : l'installateur ajoute la même commande `sudo portunia-gate …` sur l'hôte (`/usr/local/bin/portunia-gate`), qui la lance dans le conteneur.
- Les messages suivent la langue du système (anglais ou français), ou `PORTUNIA_GATE_LANG=en|fr`.
- Chaque changement est inscrit au **journal d'audit** avec l'acteur `console`, comme depuis Portunia.
- Une commande s'applique tout de suite en base. Ce qu'elle change pour les **sessions ouvertes** (fermeture, droits retirés, portail fermé, langue) est appliqué par le service **sous 30 secondes**.
- Les interrupteurs prennent `on` ou `off` (aussi `oui`/`non`, `yes`/`no`, `true`/`false`).
- Jours : `lun-ven`, `lun,mer,ven`, `sam,dim` (ou en anglais `mon-fri`). Heures : `7-20`, ou `22-6` à cheval sur minuit. Dates : `AAAA-MM-JJ`.

## Installation et informations

```bash
sudo portunia-gate init --admin julien --temporary --name "Gate ACME"   # base, clés, administrateur ; relançable sans risque
sudo portunia-gate init --no-admin                       # base et clés seulement
sudo portunia-gate info                                  # version, empreintes SSH et de l'API à comparer dans Portunia, comptes
sudo portunia-gate hardening                             # état du durcissement du serveur et alertes
sudo portunia-gate status                                # état de la Gate : santé, matériel, services, stockage, activité (--json : tout)
```

Mise à jour (0.39, paquet Debian) :

```bash
sudo portunia-gate update check                          # version installée et dernière publiée
sudo portunia-gate update apply                          # tout de suite : sauvegarde, installation, retour si la nouvelle version ne démarre pas
sudo portunia-gate update apply --at 03:00 --notice      # cette nuit à 3 h, utilisateurs prévenus 5 minutes avant
sudo portunia-gate update apply --wait                   # attend et affiche chaque étape
sudo portunia-gate update status                         # mise à jour programmée et dernière exécution
sudo portunia-gate update cancel                         # annule la mise à jour programmée
```

`--version 0.40.0` choisit une version (plus récente que celle installée seulement). `--no-rollback` sert quand le paquet de la version installée n'est plus publié. L'exécution est faite par `portunia-gate-update.service` (root) : `sudo journalctl -u portunia-gate-update`. Avec Docker : `sudo ./installer.sh mise-a-jour`.

`serve` lance la Gate : c'est le service `portunia-gate` qui s'en charge, ne la lancez pas à la main. L'installation, la mise à jour et le durcissement du serveur passent par `installer.sh` (voir le [guide d'administration](https://github.com/jpiperault/Portunia-Gate-releases/blob/main/docs/guide-administration.md)).

## Comptes

```bash
sudo portunia-gate user add marc                          # mot de passe et code TOTP saisis ici
sudo portunia-gate user add marc --temporary              # mot de passe provisoire affiché ; l'utilisateur termine dans Portunia
sudo portunia-gate user add sophie --role admin           # user (défaut), auditor ou admin
sudo portunia-gate user add robot --no-password --policy key   # compte technique, clé SSH seule
sudo portunia-gate user list                              # rôle, code, clés, combinaisons, groupes, provisoire, désactivé
sudo portunia-gate user role marc auditor
sudo portunia-gate user policy marc "key+totp"            # combinaisons acceptées ; "" = réglage général
sudo portunia-gate user key marc "ssh-ed25519 AAAA… marc@pc"   # ou le chemin d'un fichier .pub
sudo portunia-gate user totp marc                         # enrôle (ou réenrôle) le code : code QR dans le terminal
sudo portunia-gate user passwd marc                       # fixe le mot de passe (il n'est plus provisoire)
sudo portunia-gate user reset-password marc               # nouveau mot de passe provisoire, affiché une fois
sudo portunia-gate user reset-code marc                   # efface le code : un nouveau s'enrôle à la prochaine connexion
sudo portunia-gate user rdp-password marc                 # mot de passe RDP pour mstsc sans Portunia (affiché une fois ; --remove le retire)
sudo portunia-gate user disable marc                      # --undo réactive
sudo portunia-gate user delete marc                       # les sessions passées restent au journal
```

- `reset-password`, `reset-code` et `disable` terminent les connexions du compte ; ses sessions ouvertes se ferment sous 30 secondes.
- Un **mot de passe provisoire** ne sert que dans Portunia, où l'utilisateur choisit le sien. Le SSH et le portail web le refusent. Sans Portunia : `user passwd`, et `user totp` pour le code.

## Groupes

```bash
sudo portunia-gate group add "Admins Linux"
sudo portunia-gate group member "Admins Linux" marc julien
sudo portunia-gate group remove "Admins Linux" marc       # les sessions qu'ils perdent se ferment sous 30 s
sudo portunia-gate group list                             # groupes et membres
sudo portunia-gate group delete Stagiaires                # supprime aussi les règles qui lui donnent accès
```

## Serveurs

Modes : `coffre` (la Gate garde le secret du compte), `enregistre` (l'utilisateur tape ses propres identifiants), `rebond` (de bout en bout, sans enregistrement). Noms anglais acceptés : `vault`, `recorded`, `jump`.

```bash
sudo portunia-gate target add web-01 --host 10.0.1.11 --mode coffre --account root --password --folder Production
sudo portunia-gate target add app-02 --host 10.0.1.12 --mode coffre --account deploy --key-file /root/deploy_ed25519
sudo portunia-gate target add rec --host 10.0.2.5 --mode enregistre --folder Recette
sudo portunia-gate target add fw-edge --host 10.0.0.1 --mode rebond --folder Réseau
sudo portunia-gate target add srv-ad-01 --host 10.0.3.10 --protocol rdp --mode enregistre --folder Windows
sudo portunia-gate target list                            # protocole, adresse, mode, compte, empreinte
sudo portunia-gate target edit web-01 --folder Prod --account admin    # aussi --rename, --host, --port, --mode
sudo portunia-gate target edit web-01 --host 10.0.1.21 --password      # nouvelle adresse : secret à redonner, empreinte oubliée
sudo portunia-gate target edit mail --description "Messagerie de l'agence"   # texte de la vignette dans le portail et Portunia (0.33 ; vide : texte automatique)
sudo portunia-gate target secret web-01 --password        # remplace le secret du coffre (ou --key-file FICHIER)
sudo portunia-gate target secret app-02 --generate        # SSH : la Gate crée une clé, l'installe avec le mot de passe actuel, puis l'oublie
sudo portunia-gate target forget srv-ad-01                # serveur réinstallé : oublie son empreinte
sudo portunia-gate target delete fw-edge                  # secret effacé ; sessions et enregistrements gardés
```

- Interface web (`--protocol https` ou `http`, 0.30) : port 443 ou 80 ; la Gate relaie chaque requête et journalise les pages ouvertes (`web.page`). Mode enregistré (pris d'office sans `--password`) : les identifiants se tapent dans la page. Mode coffre (0.32) : `--mode coffre --account … --password` ; la Gate connecte l'utilisateur et le mot de passe n'arrive jamais dans le navigateur. `--web-login auto` (par défaut : remplit le formulaire de connexion, applications JavaScript comprises, et le valide ; authentification HTTP si le serveur la demande), `remplir` (remplit seulement, l'utilisateur clique) ou `basic` (authentification HTTP à chaque requête). Chaque usage du mot de passe du coffre est noté au journal (`web.coffre`, avec le chemin). Exemples : `sudo portunia-gate target add vcenter --host 10.0.4.10 --protocol https`, `sudo portunia-gate target add mail --host 192.168.1.16 --protocol https --mode coffre --account admin --password`, `sudo portunia-gate target edit mail --web-login remplir`.
- Bureau à distance (`--protocol rdp`) : `--mode enregistre`, `--mode rebond`, ou `--mode coffre` (0.29) avec `--account` et `--password` (un serveur RDP au coffre garde un mot de passe, pas une clé). Port 3389 par défaut.
- Le portail web affiche les serveurs en `coffre` (SSH) et `enregistre` (SSH et RDP) ; les serveurs en `rebond` s'ouvrent depuis Portunia, ou avec `ssh -J` / `ssh -L`.

## Règles d'accès

```bash
sudo portunia-gate rule add prod --group "Admins Linux" --targets web-01,rec --sftp --tunnels --days lun-ven --hours 7-20
sudo portunia-gate rule add presta --group Prestataires --targets db-01 --record-input --expires 2026-12-31
sudo portunia-gate rule add windows --group Comptabilité --targets srv-ad-01 --files   # Bureau à distance : copie de fichiers permise
sudo portunia-gate rule list                              # avec leur état : active, hors plage, expirée
sudo portunia-gate rule edit prod --sftp off --targets web-01,web-02   # interrupteurs : on ou off
sudo portunia-gate rule edit presta --expires 2027-03-31 --hours ""    # "" efface les jours, les heures ou l'expiration
sudo portunia-gate rule edit prod --rename production --group Admins
sudo portunia-gate rule edit windows --files off             # copie de fichiers de nouveau bloquée
sudo portunia-gate rule delete presta                     # les sessions qu'elle permettait se ferment sous 30 s
sudo portunia-gate rule approval prod on --approvers Responsables   # accès seulement après approbation ("" : administrateurs)
```

Approbation des accès (0.38) :

```bash
sudo portunia-gate approval list                          # demandes en attente et accès en cours
sudo portunia-gate approval grant 3f2a9c1e --minutes 120 --comment "changement CHG-42"
sudo portunia-gate approval deny 3f2a9c1e --comment "pas pendant la clôture"
sudo portunia-gate approval revoke 3f2a9c1e               # retire un accès accordé : ses sessions se ferment sous 30 s
```

`--sftp`, `--tunnels` (serveurs SSH en coffre) et `--record-input` (attention : capte les mots de passe tapés) concernent le SSH.

`--files` concerne le Bureau à distance en mode enregistré : copie de fichiers par le presse-papiers, dans les deux sens (depuis le portail web : déposer des fichiers sur le bureau ou « Envoyer des fichiers », puis coller dans Windows ; copier des fichiers dans Windows pour les télécharger). Sans elle, la Gate bloque la copie de fichiers ; le texte copié passe toujours. Avec elle, chaque fichier est inscrit au journal (`fichier.copie` : sens, nom, taille, SHA-256) et apparaît dans l'enregistrement ; les tentatives bloquées sont notées `fichier.bloque`. En mode rebond, le flux est chiffré de bout en bout : la Gate ne peut ni le voir ni le bloquer (stratégie de groupe Windows).

## Notifications

```bash
sudo portunia-gate notify show
sudo portunia-gate notify set --smtp-host smtp.exemple.fr --smtp-port 587 --smtp-security starttls \
  --smtp-user gate --smtp-password --from "Portunia Gate <gate@exemple.fr>"
sudo portunia-gate notify set --teams-url https://… --webhook-url https://… --webhook-secret   # secret affiché une fois
sudo portunia-gate notify test vous@exemple.fr            # courriel, puis Teams et webhook s'ils sont réglés
sudo portunia-gate user email marc marc@exemple.fr        # adresse d'un compte ("" la retire)
```

Sécurité : `starttls` (587), `tls` (465) ou `aucune` (25). Utilisées par l'approbation des accès (courriel aux approbateurs et au demandeur).

## Réglages généraux

```bash
sudo portunia-gate setting                                # tous les réglages avec leur valeur
sudo portunia-gate setting name "Gate ACME"
sudo portunia-gate setting language fr                    # en, fr, ou "" pour la langue du système
sudo portunia-gate setting auth_policy "password+totp,key+totp"
sudo portunia-gate setting banner "Accès réservé. Les sessions sont enregistrées."
sudo portunia-gate setting session_hours 8                # durée d'une connexion Portunia, 1 à 168 heures
sudo portunia-gate setting remember_password off          # Portunia peut retenir le mot de passe de la Gate sur les postes
sudo portunia-gate setting own_replay off                 # chaque compte peut relire ses propres sessions
sudo portunia-gate setting live_notice on                 # prévenir l'utilisateur SSH quand sa session est suivie en direct
sudo portunia-gate setting sensitive_commands "rm -rf,shutdown,DROP TABLE"   # repérées sur la barre de temps du lecteur
sudo portunia-gate setting file_copies_mb 200             # garde les fichiers copiés, jusqu'à 200 Mo par session (0 : aucun)
sudo portunia-gate setting recording_days 180             # supprime les enregistrements des sessions terminées depuis plus de 180 jours (0 : garder)
sudo portunia-gate setting session_hours                  # sans valeur : l'affiche
```

Les noms français sont acceptés aussi : `nom`, `langue`, `banniere`, `duree_session_h`, `memo_mot_de_passe`, `relecture_propres`, `commandes_sensibles`, `copies_fichiers_mo`, `conservation_jours`.

Les copies gardées sont rangées à côté de l'enregistrement, dans `/var/lib/portunia-gate/enregistrements/AAAA/MM/<session>-fichiers/` ; leur SHA-256 figure dans l'enregistrement signé et au journal.

## Portail web

```bash
sudo portunia-gate portal show                            # état, réglages, état en direct, exposition
sudo portunia-gate portal set --url https://acces.acme.fr --group "Accès web" --duration 4 --idle 30 --clipboard on
sudo portunia-gate portal set --code off                  # plus de code, sauf comptes dont les combinaisons propres l'imposent
sudo portunia-gate user policy marc password              # ou : ce compte seul se connecte sans code
sudo portunia-gate portal set --turnstile-site 0x4AAA… --turnstile-secret   # clé secrète demandée (vide : l'efface)
sudo portunia-gate portal on                              # ouvre le portail
sudo portunia-gate portal off                             # le ferme ; les sessions web se ferment sous 30 s
sudo portunia-gate portal close-sessions                  # termine les sessions web sans fermer le portail
sudo portunia-gate portal test                            # la Gate répond-elle à l'adresse publique ?
```

Comment les navigateurs atteignent le portail : une entrée externe (Cloudflare, HTTPS direct, proxy ou relais) et, en même temps, une entrée interne pour le réseau de l'entreprise. La Gate décide de l'entrée d'après la connexion (les proxys de confiance et les adresses de Cloudflare sont toujours externes) ; Turnstile ne vaut que pour l'entrée externe, et chaque connexion au portail note son entrée au journal.

```bash
sudo portunia-gate portal expose cloudflare               # entrée externe : cloudflare, direct, proxy ou relay
sudo portunia-gate portal expose --internal on            # entrée interne en plus (réseaux vides : réseaux privés)
sudo portunia-gate portal expose --internal-networks 10.0.0.0/8,192.168.10.0/24
sudo portunia-gate portal set --internal-url https://gate.lan:8446 --internal-code off   # adresse sur le réseau ; code selon le compte
sudo portunia-gate portal expose internal                 # pas d'entrée externe : entrée interne seulement
sudo portunia-gate portal expose proxy --trusted 10.0.5.10,10.0.5.11 --header X-Forwarded-For
sudo portunia-gate portal tunnel -                        # jeton du tunnel Cloudflare lu sur l'entrée standard ; --remove l'arrête
sudo portunia-gate portal tunnel                          # état du tunnel
sudo portunia-gate portal tcp --api gate-api.acme.fr --ssh gate-ssh.acme.fr --rdp gate-rdp.acme.fr --publish
                                                          # accès de l'extérieur par Cloudflare en TCP (Portunia, SSH, mstsc) :
                                                          # routes TCP du tunnel + enregistrements DNS, avec un jeton d'API
                                                          # Cloudflare demandé une fois et jamais gardé ; sans --publish, noms enregistrés seulement
sudo portunia-gate portal https 8446                      # écoute HTTPS (internal, direct, proxy) ; --off la ferme
sudo portunia-gate portal cert                            # certificat de l'écoute HTTPS
sudo portunia-gate portal cert --import portail.pfx       # ou --import cert.pem --key cle.pem ; --remove : auto-signé
sudo portunia-gate portal relay-add dmz-01 10.0.5.20:8447 # relais dédié : affiche sa commande d'appairage
sudo portunia-gate portal relay-list
sudo portunia-gate portal relay-remove dmz-01
```

Let's Encrypt pour l'écoute HTTPS :

```bash
sudo portunia-gate portal acme --domains acces.acme.fr --email it@acme.fr --method tls-alpn --accept-terms
sudo portunia-gate portal acme --domains "*.acme.fr" --method dns-cloudflare --cloudflare-token --accept-terms
sudo portunia-gate portal acme                            # état, dernier et prochain renouvellement, erreur
sudo portunia-gate portal acme --renew                    # renouvelle maintenant
sudo portunia-gate portal acme --staging on               # autorité d'essai (certificats non reconnus)
sudo portunia-gate portal acme --off
```

`tls-alpn` demande l'écoute HTTPS ouverte et le port 443 public redirigé vers elle ; `dns-cloudflare` demande un jeton d'API Cloudflare (Zone › DNS › Edit) et permet les noms génériques. Lisez les [conditions d'utilisation de Let's Encrypt](https://letsencrypt.org/repository/) avant `--accept-terms`.

Un relais dédié s'installe sur sa propre machine avec `sudo bash installer.sh relais CODE nom-public` ; son certificat se remplace avec `sudo runuser -u _portunia_gate -- /usr/lib/portunia-gate/portunia-gate edge certificate cert.pem cle.pem`, puis `sudo systemctl restart portunia-gate-relais`.

## Assistance à distance

```bash
sudo portunia-gate assist set --group Dépanneurs --duration 4   # groupe des dépanneurs, durée maximale (1 à 12 h)
sudo portunia-gate assist on                              # la Gate récupère Portunia Assistance sous 30 s
sudo portunia-gate assist off                             # les sessions en cours s'arrêtent sous 30 s
sudo portunia-gate assist show                            # état, programme prêt, personnes en attente
```

La page de la personne aidée est `https://<adresse du portail>/assistance` : réglez d'abord l'adresse publique du portail.

## RDP natif

Clients RDP ordinaires (mstsc, Windows App, Remmina, FreeRDP) avec un fichier .rdp à usage unique préparé par Portunia. Fermé par défaut.

```bash
sudo portunia-gate rdp set --port 3390 --modes rebond,coffre,enregistre --ticket-seconds 120
sudo portunia-gate rdp set --address gate.exemple.fr:3390   # adresse écrite dans les fichiers, si elle diffère (NAT, nom DNS)
sudo portunia-gate rdp on                                  # en écoute sous 3 s ; ouvrez le port sur le pare-feu
sudo portunia-gate rdp off                                 # les sessions en cours continuent
sudo portunia-gate rdp show                                # état, port, modes, certificat présenté aux clients
```

Sans Portunia (0.34) : dans mstsc, ordinateur = adresse de la Gate et port du RDP natif, utilisateur = `compte%serveur` (ou `compte%serveur%code`), mot de passe = mot de passe RDP du compte (`user rdp-password`, ou le portail web). Serveurs en coffre et en enregistré ; ceux en enregistré doivent accepter une connexion sans NLA.

Avec Docker, gardez le port 3390 dans le conteneur et changez celui qui est publié (`PORTUNIA_GATE_RDP_PORT` dans `.env`), puis `--address`. `PORTUNIA_GATE_RDP_BIND` limite l'écoute à une adresse (0.0.0.0 par défaut).

## Journal d'audit et sessions

```bash
sudo portunia-gate audit --last 50                        # derniers événements
sudo portunia-gate audit --search marc --last 200         # compte, événement ou détail contenant le texte
sudo portunia-gate audit --verify                         # vérifie toute la chaîne : un événement supprimé ou modifié se voit
sudo portunia-gate audit --last 5000 --csv journal.csv    # export pour un tableur (même format que Portunia)
sudo portunia-gate sessions --last 20
sudo portunia-gate sessions --user marc --server web-01 --since 2026-11-01 --until 2026-11-30
sudo portunia-gate sessions --text "rm -rf"               # texte affiché à l'écran ou tapé
sudo portunia-gate sessions --input                       # sessions dont la frappe est enregistrée
sudo portunia-gate sessions --files                       # sessions Bureau à distance avec des fichiers copiés
sudo portunia-gate sessions show 3f2a9c1e                 # détail, fichier d'enregistrement, contrôle de la signature
sudo portunia-gate sessions cut 3f2a9c1e                  # coupe une session ouverte sous 30 s (--disable : désactive aussi le compte)
```

`sessions show` donne le chemin de l'enregistrement et vérifie sa signature (`✓ Signature vérifiée` ou `⚠ FICHIER ALTÉRÉ`). Un enregistrement SSH (`.cast`, asciicast v2) se relit dans un terminal avec `sudo asciinema play <fichier>`. Cette relecture **n'est pas journalisée** et montre les saisies masquées : réservez-la aux administrateurs système, et passez par Portunia pour les auditeurs. Les enregistrements Bureau à distance (`.rdpcap`) ne se relisent que dans Portunia. Pour une session web (`.weblog`, 0.35), `sessions show` liste aussi ses actions (temps, nature, méthode, statut, chemin).

## Sans Portunia, de zéro

```bash
sudo bash installer.sh                                    # installe la Gate ; notez l'empreinte et le mot de passe provisoire
sudo portunia-gate user totp admin                        # enrôlez votre code
sudo portunia-gate user passwd admin                      # remplacez le mot de passe provisoire
sudo portunia-gate target add web-01 --host 10.0.1.11 --mode enregistre
sudo portunia-gate group add Admins && sudo portunia-gate group member Admins admin
sudo portunia-gate rule add admins --group Admins --targets web-01
ssh -p 2222 admin@gate.acme.fr                            # mot de passe, puis code
```
