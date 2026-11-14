# Portunia Gate

[English](README.md) · **Français**

Passerelle SSH et Bureau à distance de [Portunia](https://github.com/jpiperault/Portunia) : les utilisateurs passent par Portunia Gate pour atteindre les serveurs ; Portunia Gate vérifie qui ils sont, décide où ils peuvent aller, fournit si besoin le compte du serveur sans le leur montrer, enregistre les sessions et trace tout dans un journal infalsifiable.

> État : **version 0.8, Bureau à distance enregistré**, aussi dans le navigateur (portail web) ; portail web SSH (0.7), Bureau à distance en rebond (0.6), relecture des sessions SSH (0.5). Voir la [Feuille de route](#feuille-de-route).

## Ce que fait Portunia Gate

| | |
|---|---|
| **Trois modes par serveur** | **Rebond** : relais de bout en bout (`ssh -J`), la Gate ne voit pas le contenu, elle journalise la connexion. **Enregistré** : la Gate relaie et enregistre la session ; l'utilisateur tape ses propres identifiants. **Coffre** : comme Enregistré, et la Gate fournit le compte du serveur, que l'utilisateur ne connaît jamais. |
| **Connexion à la Gate** | Mot de passe, clé SSH et code TOTP (Google Authenticator, Microsoft Authenticator…), combinables au choix : politique générale et politique par compte. Un code ne sert qu'une fois. |
| **Droits** | Des règles relient un groupe à des serveurs, avec jours, heures, date d'expiration, SFTP et tunnels autorisés ou non. Tout ce qui n'est pas permis est refusé. |
| **Enregistrement** | Format asciicast (lisible par Portunia et asciinema), affichage seul ou aussi la frappe selon la règle. Chaque fichier est signé par la Gate. |
| **Relecture** | Dans Portunia, comme une vidéo : la frappe en sous-titres, les pauses sautées, les commandes sensibles repérées, la recherche dans toutes les sessions. Les mots de passe tapés sont masqués ; chaque relecture est inscrite au journal. |
| **Journal d'audit** | Connexions, échecs, sessions, changements d'administration. Chaque événement contient l'empreinte du précédent : une ligne supprimée ou modifiée se voit (`portunia-gate audit --verify`). |
| **Portunia** | Extension Portunia Gate : la Gate s'ajoute dans la barre latérale, ses serveurs s'ouvrent avec un jeton à usage unique, les administrateurs gèrent tout depuis Portunia (serveurs et coffre, comptes, groupes, règles, réglages) et les auditeurs relisent les sessions et le journal. |
| **Bureau à distance** | Serveurs Windows (RDP) derrière la Gate, ouverts depuis Portunia ou le portail web. Modes rebond, enregistré et coffre (voir [Bureau à distance](#bureau-à-distance-rdp)). |
| **Portail web** | Pour qui n'a pas Portunia sous la main : une page de connexion et un terminal dans le navigateur, derrière Cloudflare, sans port ouvert. Activé ou coupé d'un clic dans Portunia (voir [Portail web](#portail-web)). |
| **Autres clients** | N'importe quel client SSH : OpenSSH, PuTTY, MobaXterm, WinSCP (SFTP). |

## Installer

Deux façons d'installer, avec le même assistant :

| | **Paquet Debian** (recommandé) | **Docker** |
|---|---|---|
| Installation | 1 à 2 minutes : paquet déjà compilé | 10 à 30 minutes : compilation sur le serveur |
| Serveur conseillé | 1 processeur, 2 Go de mémoire, 10 Go de disque | 2 processeurs, 4 Go de mémoire, 20 Go de disque |
| Container LXC | Rien à activer | Options *nesting* et *keyctl* obligatoires |
| Fonctionnement | Service systemd durci, PostgreSQL de la distribution | Deux conteneurs (Portunia Gate et PostgreSQL) |
| Mise à jour | `sudo bash installer.sh mise-a-jour` (télécharge la dernière version) | `sudo ./installer.sh mise-a-jour` (`git pull` puis recompilation) |
| Processeurs | x86-64 (amd64) | x86-64 et ARM |

Dans les deux cas : un serveur **Debian 12 ou 13** ou **Ubuntu 22.04 ou plus récent** (machine virtuelle ou container LXC) avec un accès root ou sudo, et les ports **2222** (SSH) et **8443** (API pour Portunia) joignables depuis les postes des utilisateurs.

### Installation en paquet Debian

```bash
curl -fsSLO https://github.com/jpiperault/Portunia-Gate-releases/releases/latest/download/installer.sh
sudo bash installer.sh
```

L'assistant télécharge la dernière version de Portunia Gate, vérifie son empreinte SHA-256, installe le paquet et PostgreSQL, crée la base (accès local par socket, sans mot de passe) et le service `portunia-gate`.

Fichiers installés :

| | |
|---|---|
| `/usr/lib/portunia-gate/portunia-gate` | Le programme |
| `/usr/bin/portunia-gate` | La commande d'administration (`sudo portunia-gate …`) |
| `/etc/portunia-gate/portunia-gate.env` | Réglages : ports, fuseau, accès à la base |
| `/var/lib/portunia-gate/` | Clés, certificat de l'API, enregistrements des sessions |
| Base PostgreSQL `portunia-gate` | Comptes, serveurs, règles, sessions, journal |

Le service tourne sous un compte système dédié (`_portunia_gate`), n'écrit que dans `/var/lib/portunia-gate` et ne voit ni les dossiers personnels ni le reste du système. Commandes utiles : `sudo systemctl status portunia-gate`, `sudo journalctl -u portunia-gate -f`.

Installer un paquet précis (sans accès à Internet, ou une version antérieure) : `sudo bash installer.sh --paquet portunia-gate_0.4.0_amd64.deb`.

### Installation avec Docker

```bash
git clone https://github.com/jpiperault/Portunia-Gate.git
cd Portunia-Gate
sudo ./installer.sh --docker
```

Le dépôt est privé : `git clone` demande votre identifiant GitHub et, en guise de mot de passe, un jeton d'accès (GitHub › Settings › Developer settings › Personal access tokens, droit de lecture sur le dépôt). L'assistant installe Docker s'il manque et, avec moins de 4 Go de mémoire, propose un fichier d'échange temporaire pour la compilation. Dans un container LXC Proxmox, activez d'abord *nesting* et *keyctl* (Options › Features) puis redémarrez le container.

### Les questions

L'assistant pose cinq questions ; la touche Entrée garde la valeur proposée :

| Question | Valeur proposée | |
|---|---|---|
| Nom de la Gate | Portunia Gate | Affiché dans Portunia et dans l'application d'authentification. |
| Identifiant de l'administrateur | admin | Votre compte pour administrer la Gate depuis Portunia. |
| Port SSH | 2222 | |
| Port de l'API | 8443 | |
| Fuseau horaire | celui du serveur | Sert aux plages horaires des règles d'accès. |

Il crée ensuite les clés, le certificat, la base et le compte administrateur, démarre la Gate et affiche ce qu'il faut saisir dans Portunia :

```
  ┌──────────────────────────────────────────────────────────────────────────
  │ Dans Portunia : Extensions › activer Portunia Gate, puis Gates › Ajouter une Gate
  │
  │   Adresse      192.168.1.20
  │   Empreinte    38:D8:AF:22:01:C1:9E:8B:…:61:07:27:C9
  │   Identifiant  admin
  │   Mot de passe Kq7m-P2xR-t9wA  (provisoire)
  │
  │ Portunia vous fera choisir votre mot de passe, puis scanner le code QR
  │ avec votre application d'authentification. Laissez le champ Code vide.
  └──────────────────────────────────────────────────────────────────────────
```

La Gate redémarre seul avec le serveur.

### Sauvegarder la clé du coffre, tout de suite

La **clé du coffre** chiffre les mots de passe des serveurs et les codes TOTP. Sans elle, une restauration perd tous ces secrets. L'assistant en dépose une copie dans votre dossier personnel (`~/portunia-gate-vault.key`) : copiez-la hors du serveur (gestionnaire de mots de passe, coffre de l'entreprise), puis effacez cette copie. L'assistant affiche les commandes exactes, par exemple :

```bash
scp julien@192.168.1.20:/home/julien/portunia-gate-vault.key .   # depuis votre poste
rm ~/portunia-gate-vault.key                                      # sur le serveur
```

### Relancer l'assistant

`sudo bash installer.sh` sur une Gate déjà installé ouvre un menu :

| Choix | Commande directe | |
|---|---|---|
| Informations pour Portunia | `sudo bash installer.sh info` | Adresse et empreinte à donner aux utilisateurs. |
| Mettre à jour | `sudo bash installer.sh mise-a-jour` | Installe la dernière version et redémarre. **Les sessions ouvertes sont coupées.** |
| Créer un administrateur | `sudo bash installer.sh admin julien` | Administrateur de secours avec un mot de passe provisoire, par exemple si le seul administrateur a perdu son téléphone. |

En mode Docker, lancez l'assistant depuis le dossier du dépôt (`sudo ./installer.sh`).

Une installation interrompue (coupure, erreur) se reprend en relançant l'assistant : les réglages déjà saisis sont proposés de nouveau.

### Durcir le serveur (facultatif)

Sur un serveur dédié à la Gate, l'assistant peut ne garder que le nécessaire : pare-feu fermé sauf les ports utiles, services inutiles arrêtés, SSH du système et noyau resserrés, mises à jour de sécurité automatiques. Répondez oui à la question de l'installation, ou utilisez `--durcir`, ou plus tard :

```bash
sudo bash installer.sh durcir simulation
sudo bash installer.sh durcir
```

La simulation ne change rien. Si une nouvelle connexion SSH n'est pas confirmée sous 5 minutes, le pare-feu et le SSH du système sont remis comme avant. Détails et annulation : [exploitation](docs/exploitation.fr.md).

### Sans questions (automatisation)

Hors terminal, l'assistant prend les valeurs proposées, ou celles des variables `PORTUNIA_GATE_NOM`, `PORTUNIA_GATE_ADMIN`, `PORTUNIA_GATE_SSH_PORT`, `PORTUNIA_GATE_API_PORT` et `TZ` :

```bash
sudo PORTUNIA_GATE_ADMIN=julien PORTUNIA_GATE_NOM="Gate ACME" bash installer.sh </dev/null
```

### Certificat de l'entreprise

Le certificat de l'API est auto-signé : Portunia le reconnaît par son empreinte, ce qui suffit. Celui que voient les navigateurs sur le portail est distinct, réglé dans Administrer › Portail web (voir *Certificat du portail*). Pour utiliser un certificat de l'entreprise pour l'API (fichiers PEM, certificat suivi de sa chaîne) :

Paquet Debian :

```bash
sudo install -o _portunia_gate -g _portunia_gate -m 600 cert.pem /var/lib/portunia-gate/entreprise.crt
sudo install -o _portunia_gate -g _portunia_gate -m 600 cle.pem /var/lib/portunia-gate/entreprise.key
echo 'PORTUNIA_GATE_TLS_CERT=/var/lib/portunia-gate/entreprise.crt' | sudo tee -a /etc/portunia-gate/portunia-gate.env
echo 'PORTUNIA_GATE_TLS_KEY=/var/lib/portunia-gate/entreprise.key' | sudo tee -a /etc/portunia-gate/portunia-gate.env
sudo systemctl restart portunia-gate
```

Docker, depuis le dossier du dépôt :

```bash
sudo docker compose cp cert.pem portunia-gate:/var/lib/portunia-gate/entreprise.crt
sudo docker compose cp cle.pem portunia-gate:/var/lib/portunia-gate/entreprise.key
echo 'PORTUNIA_GATE_TLS_CERT=/var/lib/portunia-gate/entreprise.crt' | sudo tee -a .env
echo 'PORTUNIA_GATE_TLS_KEY=/var/lib/portunia-gate/entreprise.key' | sudo tee -a .env
sudo docker compose up -d
```

L'empreinte change : les utilisateurs devront valider la nouvelle (`sudo portunia-gate info`).

## Ajouter la Gate dans Portunia

1. **Activer l'extension** : Portunia › Extensions › Portunia Gate › Activer. La section **Gates** apparaît dans la barre latérale.
2. **Ajouter la Gate** : Gates › **+** › tapez l'adresse donnée par l'assistant (`192.168.1.20`, ou `192.168.1.20:9443` si vous avez changé le port de l'API).
3. **Vérifier l'empreinte** : Portunia affiche l'empreinte du certificat de la Gate. Comparez-la à celle donnée par l'assistant (ou `sudo portunia-gate info` sur le serveur, ligne « Certificat de l'API »). Si elle diffère, n'allez pas plus loin : quelqu'un se fait peut-être passer pour la Gate.
4. **Se connecter** : identifiant et mot de passe ; **laissez le champ Code vide** lors de la première connexion.
5. **Première connexion** : Portunia demande de choisir un nouveau mot de passe (10 caractères au moins), puis affiche un code QR. Scannez-le avec votre application d'authentification et tapez le code à 6 chiffres qu'elle affiche.
6. **Ouvrir un serveur** : les serveurs autorisés apparaissent sous la Gate, rangés par dossier. Un clic ouvre la session, sans retaper le code (jeton à usage unique) :
   - **coffre** : connexion directe, la Gate fournit le compte ;
   - **enregistré** : le serveur demande vos identifiants dans le terminal ;
   - **rebond** : Portunia demande vos identifiants du serveur, la connexion est chiffrée de bout en bout.
7. **Administrer** (Portunia Équipes, compte administrateur) : menu **⋯** de la Gate › **Administrer**. Un onglet s'ouvre avec les serveurs et le coffre, les comptes, les groupes, les règles et les réglages.
8. **Auditer** (Portunia Équipes, compte administrateur ou auditeur) : menu **⋯** de la Gate › **Audit**. Un onglet s'ouvre avec les sessions et le journal (voir [Relire les sessions](#relire-les-sessions)).

Les comptes suivants se créent depuis l'onglet d'administration : Portunia affiche un mot de passe provisoire à transmettre à l'utilisateur, qui suivra les étapes 2 à 5.

Rien ne s'affiche sous la Gate ? Aucune règle ne donne encore accès à un serveur : créez un serveur, un groupe contenant le compte, puis une règle qui les relie.

## Relire les sessions

**En direct (0.36)** : **Audit** › **En direct** liste les sessions ouvertes en ce moment (SSH, Bureau à distance, interfaces web), mises à jour toutes les 10 secondes. **Suivre** ouvre le lecteur à la fin de la session, qui s'allonge au fil de la session (● EN DIRECT) : l'écran, la frappe si la règle l'enregistre, les clics, les actions web. **Couper** ferme la session tout de suite ; un administrateur peut désactiver le compte en même temps. Le suivi est noté au journal (`session.suivie`), la coupure aussi (`session.coupee_par`). Avec le réglage `live_notice` (actif par défaut), l'utilisateur SSH est prévenu dans son terminal que sa session est suivie. Pas de prise en main du clavier. En ligne de commande : `sudo portunia-gate sessions cut ID [--disable]`.

Menu **⋯** de la Gate › **Audit** › **Sessions** (rôles administrateur et auditeur).

**Trouver une session** : filtres par compte, serveur et période, case « Avec frappe ». La recherche porte sur la frappe et sur le texte affiché de toutes les sessions enregistrées : la colonne « Trouvé » donne le moment et l'extrait, un clic ouvre la relecture à cet endroit.

**Le lecteur**, dans un onglet :

| | |
|---|---|
| Lecture | Lecture et pause (barre d'espace), ±10 s (flèches : ±5 s), vitesse 1× à 16×, plein écran. Un clic sur la barre de temps ou sur une ligne du panneau y saute. |
| Pauses | Les moments sans activité de plus de 5 s sont hachurés sur la barre et sautés pendant la lecture (bouton « Sauter les pauses »). |
| Sous-titres | Bouton **CC Frappe** : ce que la personne tape, touches spéciales comprises (Entrée, Tab, ⌫, Ctrl+C, flèches). |
| Repères | Chaque commande ; en orange sudo, Ctrl+C et les saisies masquées ; en rouge les commandes sensibles ; en bas, les erreurs affichées. |
| Panneau | **Frappe** : les lignes tapées, horodatées, avec recherche. **Informations** : compte, serveur, mode, adresse, durée, empreinte, signature, relectures précédentes. |
| Signature | Vérifiée à chaque ouverture. Un fichier modifié depuis la session est signalé en rouge. |
| Exports | **Enregistrement .cast** (lisible par asciinema), **Transcription** (texte horodaté) et, avec Portunia 0.76, **Vidéo** (MP4 fabriqué sur le poste, frappe en sous-titres et fichier .srt, filigrane). Chaque export est noté au journal depuis la 0.37 (`enregistrement.exporte`). |
| Détacher | **⧉ Détacher** ouvre le lecteur dans sa propre fenêtre. |

**Saisies masquées** : une frappe qui ne s'affiche pas à l'écran (mot de passe de sudo, su, ssh…) est remplacée par des points de longueur fixe, dans le lecteur comme dans la recherche. Elle reste dans le fichier signé : un administrateur peut la **révéler** (bouton dans le lecteur), et cette relecture est inscrite au journal (`enregistrement.revele`). L'export `.cast` d'une relecture masquée est une copie non signée ; celui d'une relecture révélée est le fichier d'origine, signé.

**Sessions sans frappe** (règle qui n'enregistre que l'écran) : pas de sous-titres ; le panneau liste les commandes repérées à l'écran, après l'invite.

**Chaque relecture est inscrite au journal** (`enregistrement.consulte`), et le lecteur affiche en filigrane le compte qui regarde.

**Relire ses propres sessions** : Administrer › Réglages › « Chaque compte peut relire ses propres sessions ». Les comptes « utilisateur » voient alors **Mes sessions** dans le menu de la Gate, sans pouvoir révéler les saisies masquées.

**Commandes sensibles** : Administrer › Réglages, une par ligne (par défaut `rm -rf`, `mkfs`, `dd if=`, `shutdown`, `reboot`, `DROP TABLE`…).

Les sessions enregistrées avant la version 0.5 se relisent, mais n'entrent pas dans la recherche.

## Bureau à distance (RDP)

Les serveurs Windows se déclarent comme les autres : Administrer › Serveurs et coffre › **Ajouter un serveur**, protocole **Bureau à distance (RDP)**, port 3389. Ils apparaissent sous la Gate dans Portunia avec un badge **RDP** et s'ouvrent dans un onglet Bureau à distance.

En rebond et en enregistré, l'utilisateur tape ses identifiants Windows à chaque ouverture ; ni Portunia ni la Gate ne les gardent. En coffre (0.29), la Gate ouvre la session Windows elle-même avec le compte qu'elle garde : l'utilisateur ne tape rien et ne voit jamais le mot de passe.

| | **Rebond** (0.6) | **Enregistré** (0.8) | **Coffre** (0.29) |
|---|---|---|---|
| Chemin | Tunnel par le port SSH de la Gate (2222), avec un jeton à usage unique ; la connexion RDP est chiffrée de bout en bout. | Passage de la Gate (RDCleanPath, sur le port de l'API ou du portail) avec un jeton à usage unique : la Gate ouvre la connexion chiffrée avec le serveur Windows et relaie la session. | Comme en enregistré. |
| Ce que voit la Gate | Rien du contenu ; elle vérifie la règle et journalise (`rebond.ouvert`, durée, octets). | La session (pour l'enregistrer), mais pas le mot de passe : l'authentification Windows (NLA) se fait entre le client et le serveur. | La session ; la Gate mène l'authentification Windows (NLA, NTLM) avec le compte du coffre, et le client s'authentifie auprès d'elle avec son jeton à usage unique. Le serveur doit proposer NLA. |
| Enregistrement | Non. | Oui, fichier signé (`.rdpcap`) : l'image envoyée par le serveur, les clics, les copier-coller (texte masqué tant qu'un administrateur ne le révèle pas) et la frappe si la règle l'enregistre. Relecture dans Portunia (0.47 ou suivant), comme une session SSH. | Oui, comme en enregistré. |
| Clients | Portunia ; le **portail web** aussi depuis la 0.29, où la Gate relaie sans enregistrer (un navigateur ne peut pas faire de tunnel de bout en bout). | Portunia et le **portail web** (Bureau à distance dans le navigateur). | Portunia et le portail web. |
| Certificat du serveur | Vérifié par le client. | Vérifié par la Gate : empreinte gardée à la première connexion, connexion refusée si elle change (`cible.empreinte_differente`). | Vérifié par la Gate, comme en enregistré. |

La Gate doit joindre le port 3389 des serveurs Windows. Dans Portunia, l'extension Bureau à distance doit être activée ; sinon les serveurs RDP restent visibles, grisés. Un serveur RDP n'apparaît pas dans le menu `ssh` de la Gate et ne s'ouvre pas en terminal.

Un serveur RDP au coffre garde un mot de passe (compte local ou `DOMAINE\compte`), pas une clé. Si le mot de passe change sur le serveur, la connexion échoue avec `cible.coffre_refuse` : remplacez le secret.

### Clients RDP ordinaires (RDP natif, 0.31)

Les serveurs Windows de la Gate s'ouvrent aussi dans un client RDP ordinaire : **mstsc**, **Windows App** (Mac), **Remmina** ou **FreeRDP**. Portunia prépare un **fichier .rdp à usage unique** (clic droit sur le serveur › *Ouvrir dans le client Windows (mstsc)*) ; le jeton voyage dans le champ `loadbalanceinfo` du fichier, que ces clients envoient dès leur premier paquet, avant tout chiffrement. Portunia et le portail web fonctionnent comme avant.

L'entrée écoute sur son propre port (**3390**), **fermée par défaut** : Portunia › Administrer › **RDP natif**, ou `sudo portunia-gate rdp on`. Tout s'y règle : port, adresse écrite dans les fichiers, modes accessibles ainsi, validité d'un fichier (2 minutes par défaut).

| | **Rebond** | **Coffre** | **Enregistré** |
|---|---|---|---|
| Ce que fait la Gate | Retire le jeton, puis laisse passer la connexion telle quelle : TLS et authentification Windows (NLA) de bout en bout, rien n'est enregistré. | Ouvre la session Windows (NLA) avec le compte du coffre, puis relaie et enregistre. | Pareil, avec le compte Windows tapé dans Portunia en préparant le fichier : gardé **en mémoire** jusqu'à la connexion du client, jamais sur disque. Sans compte, seulement pour un serveur qui accepte TLS sans NLA (l'utilisateur le tape dans l'écran de connexion de Windows). |
| Certificat vu par le client | Celui du serveur Windows. | Celui de l'API de la Gate (un avertissement une fois sans certificat d'entreprise : comparez-le avec `sudo portunia-gate info`). | Comme en coffre. |

Le journal note `rdp_natif.fichier` (fichier préparé), puis les événements habituels de la session (`session.ouverte`, `rebond.ouvert`…) avec `(natif)` après l'adresse. Ouvrez le port sur le pare-feu (le durcissement l'ouvre quand l'entrée est ouverte) ; avec Docker, il est publié sous `PORTUNIA_GATE_RDP_PORT` (3390). Un fichier ne sert qu'une fois : un client RDP qui se reconnecte tout seul après une coupure réseau est refusé ; préparez un nouveau fichier.

**Sans Portunia (0.34).** Dans mstsc, Windows App ou Remmina, tapez comme ordinateur l'adresse de la Gate et le port du RDP natif, comme utilisateur `compte%serveur` (`compte%serveur%123456` avec le code à 6 chiffres quand la politique du compte en demande un) et comme mot de passe le **mot de passe RDP** du compte. La Gate vérifie le tout par NLA (elle joue le serveur Windows face au client), puis ouvre le serveur comme en coffre ou en enregistré ; les serveurs en rebond restent accessibles seulement avec le fichier .rdp de Portunia. Le mot de passe RDP est distinct du mot de passe du compte : l'utilisateur le crée dans le portail web (*Se connecter avec mstsc ou Windows App*, qui propose aussi un raccourci .rdp prêt à l'emploi par serveur) ou un administrateur avec `sudo portunia-gate user rdp-password COMPTE` ; il est scellé par la Gate (NTLM doit pouvoir le relire), affiché une seule fois, et `--remove` le retire. Un serveur en enregistré doit alors accepter une connexion sans NLA : l'utilisateur ouvre sa session dans l'écran de connexion de Windows. Les refus sont notés au journal (`acces.refuse`, type « rdp natif », avec la raison), la création ou le retrait d'un mot de passe aussi (`rdp_natif.mot_de_passe`).

**Sessions natives et relecture (0.34.1).** Les sessions natives en coffre et en enregistré sont toujours enregistrées : la Gate retire donc l'annonce du pipeline graphique RDP 8 (GFX) faite par le client. Windows envoie alors l'image en mises à jour classiques, que la relecture décode. Par le canal GFX, la relecture restait noire.

## État et mise à jour de la Gate

Depuis la 0.39, l'**état de la Gate** (Portunia : menu de la Gate › *État de la Gate*, ou la section *État* de l'administration ; `sudo portunia-gate status`) montre d'un coup d'œil : la santé générale, la version, la durée de service, le processeur, la mémoire, le disque et le réseau (avec les courbes des dernières 24 heures dans Portunia), les services (base, certificat HTTPS, relais dédiés, heure, notifications, durcissement), le stockage (enregistrements, base, rythme de remplissage et « disque plein dans N jours »), l'activité (sessions ouvertes, sessions du jour, connexions refusées, approbations en attente) et l'intégrité du journal signé (vérifiée toutes les 6 heures). Dans Portunia, la pastille de la Gate dans la barre latérale passe à l'orange ou au rouge quand quelque chose demande votre attention.

- **Mise à jour en un clic** (paquet Debian, Portunia Pro) : *Mettre à jour…*, tout de suite ou à une heure choisie (cette nuit à 3 h par défaut), en prévenant au besoin les utilisateurs connectés 5 minutes avant. Un service système à part, lancé en root (`portunia-gate-update`), sauvegarde la base, télécharge le nouveau paquet et celui installé (pour le retour) et vérifie leur SHA-256 publié, installe, puis attend que la nouvelle version démarre. Si elle ne démarre pas en 3 minutes : **retour en arrière automatique** (ancien paquet réinstallé, base restaurée). Il n'accepte qu'une version plus récente que celle installée. Les administrateurs sont prévenus du résultat (et de la publication d'une nouvelle version) par courriel, Teams ou webhook.
- **En ligne de commande** : `update check`, `update apply [--at 03:00] [--notice] [--wait]`, `update status`, `update cancel`. Avec Docker : `sudo ./installer.sh mise-a-jour`, comme avant.
- **Conservation des enregistrements** : `sudo portunia-gate setting recording_days 180` (ou Portunia : Réglages, ou la page État). Au-delà, les enregistrements des sessions terminées sont supprimés chaque heure ; les sessions restent dans la liste et la suppression est notée au journal (`enregistrement.purge`). 0 : gardés toujours (par défaut).
- **Alerte disque** : au-delà de 85 % de remplissage, les administrateurs sont prévenus (une fois par jour au plus).
- **Compression** (0.42) : un jour après la fin d'une session, son enregistrement est compressé (gzip) : 5 à 10 fois moins de place en SSH. Empreinte et signature inchangées (`enregistrement.compresse`).
- **Conservation du journal** (0.42) : `sudo portunia-gate setting audit_days 365` (ou Portunia : Réglages, ou la page État). 0 : gardé toujours (par défaut), sinon au moins 90 jours. La chaîne est vérifiée avant chaque purge quotidienne, et une ancre signée la garde vérifiable (`journal.purge`).
- **Journal** : `mise_a_jour.programmee`, `.lancee`, `.reussie`, `.retour_arriere`, `.echec`, `.annulee`, `.disponible` ; `disque.presque_plein` ; `journal.altere`.

## Approbation des accès

Depuis la 0.38, une règle peut exiger une approbation : ses serveurs ne s'ouvrent qu'une fois l'accès accordé par un approbateur, pour une durée. Réglage : dans la règle, *Accès seulement après approbation* et le groupe des **approbateurs** (vide : les administrateurs) ; `sudo portunia-gate rule approval NOM on --approvers GROUPE`.

- **Demander** : l'utilisateur donne un motif (et un numéro de ticket facultatif) dans Portunia (menu de la Gate › **Approbations**) ou dans le portail web (*Serveurs sur approbation*). Les approbateurs sont prévenus (courriel, Teams, webhook, et Portunia, qui interroge la Gate chaque minute).
- **Décider** : un approbateur accorde pour une durée (30 minutes à 3 jours dans Portunia, 5 minutes à 7 jours en ligne de commande) ou refuse, avec un commentaire. Personne n'approuve sa propre demande. Une demande sans réponse expire au bout de 24 heures.
- **Fin** : l'utilisateur est prévenu 10 minutes avant (dans le terminal SSH), puis ses sessions se ferment. Un approbateur peut **retirer** un accès à tout moment ; l'utilisateur peut annuler sa demande.
- **Journal** : `approbation.demandee`, `approbation.accordee`, `approbation.refusee`, `approbation.annulee`, `approbation.terminee`, `approbation.sans_reponse`.
- **En ligne de commande** : `approval list`, `approval grant ID --minutes 60`, `approval deny ID`, `approval revoke ID` (la console agit comme un administrateur).

## Notifications

Courriel (SMTP), Microsoft Teams (webhook « Workflows » d'un canal) et webhook JSON signé, utilisés par l'approbation des accès : Administrer › Réglages › **Notifications** (avec un essai), ou `sudo portunia-gate notify set --smtp-host smtp.exemple.fr --smtp-user gate --smtp-password --from "Portunia Gate <gate@exemple.fr>"`, puis `notify test vous@exemple.fr`. L'adresse e-mail de chaque compte se règle dans sa fiche ou avec `user email COMPTE ADRESSE`. Le webhook reçoit `{"evenement", "date", "gate", "detail"}` avec `X-Portunia-Gate-Date` (secondes Unix) et `X-Portunia-Gate-Signature: sha256=<HMAC-SHA256 de "date.corps">`. Un envoi qui échoue est noté au journal (`notification.echec`) et ne bloque jamais rien.

## Interfaces web

Depuis la 0.30, les consoles d'administration (vCenter, iDRAC, iLO, pare-feu, NAS…) se déclarent comme des serveurs de protocole `https` ou `http`, en mode enregistré. La Gate relaie chaque requête (règle revérifiée toutes les 30 s), note chaque page ouverte (`web.page`) et épingle le certificat du serveur comme pour le Bureau à distance. Depuis Portunia, elles s'ouvrent dans une fenêtre dédiée par un relais local vers l'API de la Gate (session web de 8 heures) ; depuis le portail web, dans un onglet à l'adresse `/web/<nom>/` (une interface web à la fois par navigateur ; l'application partage l'adresse du portail, n'y publiez que des applications de confiance). Les cookies de la Gate et l'adresse du visiteur n'atteignent jamais le serveur ; les WebSocket passent. Depuis la 0.32, le mode coffre aussi : la Gate connecte l'utilisateur avec le compte du coffre. Elle remplit le formulaire de connexion dans la page (applications JavaScript comprises) avec un jeton à usage unique au lieu du mot de passe, et remplace le jeton par le mot de passe en route vers le serveur : le mot de passe n'arrive jamais dans le navigateur. Ou bien elle envoie l'authentification HTTP (Basic). Chaque usage est noté au journal (`web.coffre`).

Depuis la 0.35, chaque compte a une **session web** par serveur, listée avec les autres sessions (type `web`) : elle s'ouvre à la première requête et se ferme après 15 minutes sans requête, quand l'accès prend fin ou quand elle est coupée. Son journal d'actions signé note les pages ouvertes, les envois (formulaires, modifications : méthodes autres que GET), les WebSocket et les usages du coffre, avec le chemin (sans paramètres) et le statut ; jamais ce qui est saisi. Il se lit dans Portunia › Audit (*Actions*) ou avec `sudo portunia-gate sessions show ID`, et se cherche par chemin.

## Sortie web (naviguer par la Gate)

Depuis la 0.48, un serveur au protocole `sortie` laisse les membres d'un groupe naviguer sur Internet depuis Portunia (0.93, édition Pro) par la Gate : Portunia ouvre un Edge, un Chrome ou un Brave dédié dont tout le trafic passe par un proxy SOCKS5 sur le poste, relié au SSH de la Gate. Les sites voient l'adresse de la Gate ; la vidéo passe à pleine vitesse (la Gate relaie le TCP sans le réencoder). Le serveur porte son filtre : domaines autorisés (vide : tout Internet), domaines bloqués, ports permis (80 et 443 par défaut). La Gate résout chaque nom elle-même et **refuse toujours les réseaux internes** (boucle locale, privés, lien local, CGNAT…) : la sortie n'atteint jamais un serveur du réseau sans ses propres règles. Journal : `navigation.ouverte`, `navigation.refusee`, `navigation.fermee` (sites avec connexions et octets ; le HTTPS n'est pas déchiffré). Couper la session, retirer la règle ou désactiver le compte ferme le navigateur. `sudo portunia-gate target add internet --protocol sortie [--domains …] [--block-domains …] [--ports …]`.

Depuis la 0.53, une sortie peut aussi s'ouvrir **dans un onglet du portail web** (option `--portal`, ou « Aussi dans le portail web » dans Portunia) : un Chromium sans écran tourne sur la Gate, dans son propre service (`portunia-gate-navigateur`, compte `_portunia_gate_nav`) sans aucun réseau à lui, et ne sort que par le même filtre. Désactivé par défaut ; `sudo bash installer.sh navigateur` installe Chromium et le démarre (paquet Debian seulement). Téléchargements et envois de fichiers sont refusés. Depuis la 0.55, il s'active ou s'arrête depuis Portunia (Administrer › Portail web › Navigateur du portail), et une mise à jour le garde complet. Depuis la 0.54, la vidéo et le son passent aussi (H.264 et Opus décodés par l'onglet, environ 3 Mbit/s en 720p) : YouTube passe à 30 images par seconde.

## Portail web

Une page web pour ouvrir ses serveurs depuis n'importe quel navigateur, sans Portunia : connexion, liste des serveurs autorisés, terminal SSH ou Bureau à distance dans un onglet. Elle ne sert pas à l'administration. Le Bureau à distance passe par le passage RDCleanPath de la Gate (tous les modes, voir [Bureau à distance](#bureau-à-distance-rdp)). Le portail passe par le serveur SSH de la Gate, avec un jeton à usage unique : mêmes règles, même coffre, même enregistrement, même journal. Une session web se relit dans l'audit comme une autre ; son adresse est suivie de « (web) ».

**Téléphone et tablette (0.46).** Sur un écran tactile, le terminal a une barre de touches sous l'écran : Échap, Tab, flèches, Début, Fin, Pg↑, Pg↓, quelques symboles, A− et A+ pour la taille du texte ; Ctrl et Alt s'appliquent à la touche suivante (Ctrl puis c envoie Ctrl+C). Le Bureau à distance se pilote au doigt : un appui pour cliquer, un appui long ou un appui à deux doigts pour le clic droit, glisser pour déplacer en tenant le bouton, deux doigts pour faire défiler. Le bouton **Clavier** ouvre le clavier du téléphone : le texte part en Unicode, quelle que soit la disposition du clavier Windows ; une barre ajoute Échap, Tab, Ctrl, Alt, Win, flèches, Suppr, Début, Fin et la touche Windows. Pour les raccourcis (Ctrl+C, Win+R…), la barre indique la disposition du clavier Windows (AZERTY ou QWERTY, retenue par le navigateur). L'application Android **Portunia Gate** (`fr.portunia.gate`, livrée avec Portunia 0.91) ouvre ce même portail : adresse retenue, écran gardé allumé pendant une session, plein écran, liens vers d'autres sites ouverts dans le navigateur. Rien à régler côté Gate.

**Connexion par empreinte (0.47).** Juste après une connexion par mot de passe et code dans l'application Android (Android 11 et plus), l'utilisateur peut enrôler son téléphone : l'application crée une clé ECDSA P-256 dans la puce sécurisée du téléphone (Keystore, StrongBox s'il existe), qui ne sort jamais du téléphone et ne signe qu'après l'empreinte ; la Gate garde la clé publique (`appareil.enrole`, titulaire et administrateurs prévenus par courriel, Teams ou webhook). Ensuite, l'empreinte suffit : la Gate envoie un défi à usage unique (90 s), le téléphone le signe, la Gate ouvre la session du portail (`portail.connexion`, facteurs « téléphone » et « empreinte »). Au plus 5 téléphones par compte ; retirés après 90 jours sans usage, avec un mot de passe ou un code réinitialisé, un compte désactivé, ou à la demande : dans l'application, dans Portunia (Administrer › Comptes › *Téléphones*) ou avec `sudo portunia-gate user devices COMPTE --remove ID` (`--remove-all`). Une nouvelle empreinte ajoutée au téléphone invalide la clé (il faut réenrôler). Journal : `appareil.enrole`, `appareil.retire`, `appareil.expire`.

**Sécurité**

| | |
|---|---|
| Exposition | **Cloudflare Tunnel** (conseillé) : la Gate lance elle-même `cloudflared` (connexion sortante vers Cloudflare, aucun port entrant, rien à installer en root). Ou **proxy Cloudflare** : HTTPS sur le port 8446, n'accepte que les adresses de Cloudflare. |
| Connexion | Mot de passe **et** code toujours exigés, même pour un compte qui s'en passe dans Portunia. Cinq essais par compte et vingt par adresse en dix minutes. Anti-robots **Cloudflare Turnstile** si ses clés sont réglées. |
| Comptes | Seuls les membres du **groupe choisi** (« Accès web » par défaut). Première connexion et code perdu : pas sur le portail, mais avec Portunia ou l'administrateur. |
| Session | Cookie « HttpOnly, Secure, SameSite=Strict », 1 heure par défaut ; fermeture après 15 minutes sans frappe (avertissement 90 s avant). |
| Page | Rien de chargé depuis l'extérieur (sauf Turnstile), politique de contenu stricte, pas d'affichage dans un cadre d'un autre site, adresse publique vérifiée à chaque connexion. |
| Serveurs | SSH en mode coffre ou enregistré ; Bureau à distance dans tous les modes (client RDP d'IronRDP dans la page) : enregistré et rebond avec les identifiants Windows tapés dans la page et envoyés au serveur, jamais à la Gate (rebond : relayé sans enregistrement) ; coffre sans rien taper. Les serveurs SSH en rebond (de bout en bout) restent avec Portunia. |
| Journal | `portail.connexion`, `portail.echec`, `portail.active`, `portail.desactive`, `portail.modifie`, `portail.sessions_fermees`. |

**Mise en place**

1. **Créer le tunnel** dans Cloudflare : **Networking › Tunnels › Create Tunnel**, un nom (ex. `portunia-gate`), puis copier la commande d'installation affichée, pour n'importe quel système. Elle contient le jeton ; ne pas l'exécuter.
2. **La donner à la Gate** : dans Portunia, Administrer › Portail web › mode Cloudflare, coller la commande ou le jeton et enregistrer. Ou depuis le serveur : `sudo bash installer.sh portail`, ou `sudo portunia-gate portal tunnel -` (jeton sur l'entrée standard ; `--remove` l'arrête). La Gate télécharge `cloudflared` depuis le GitHub de Cloudflare (2026.10.7 au moins), vérifie son empreinte SHA-256, le lance sous son propre compte et le relance s'il s'arrête. Depuis la 0.45, elle le tient à jour : toutes les 6 heures, elle lit la dernière version de Cloudflare, exige que l'empreinte donnée par GitHub pour le fichier soit celle des notes de version de Cloudflare, le télécharge et le vérifie, puis relance le tunnel dessus quand aucune session n'est ouverte (après un jour d'attente : la nuit, de 3 h à 5 h, en prévenant les personnes connectées). `sudo portunia-gate portal tunnel-update` montre les versions, `now` met à jour tout de suite, `manual` se contente de signaler les nouvelles versions, `auto` est le réglage par défaut ; mêmes réglages dans Administrer › Portail web. Journal : `portail.cloudflared`, `portail.tunnel_maj`. Le jeton est chiffré par le coffre. Serveur sans accès à GitHub : `PORTUNIA_GATE_CLOUDFLARED=/usr/bin/cloudflared`.
   Le tunnel passe alors à **Healthy** dans Cloudflare.
3. **Publier l'adresse** : dans le tunnel, onglet **Routes** › **Add route** › **Published application**. **Subdomain** et **Domain** (le *Full hostname*, ex. `acces.votre-domaine.fr`, est l'adresse publique), **Path** vide, **Service URL** `http://localhost:8445`, puis **Add route** (Cloudflare crée l'enregistrement DNS). Jamais de route `ssh://` ou `rdp://` vers vos serveurs : elle contournerait la Gate (ni contrôle, ni coffre, ni enregistrement, ni journal).
4. **Vérifier** : dans l'onglet Portail web, adresse publique `https://` + Full hostname, **Enregistrer**, puis **Tester l'adresse publique** : la Gate appelle sa propre adresse publique à travers Cloudflare et vérifie que c'est elle qui répond.
5. **Conseillé : Cloudflare Access** sur cette adresse (compte de l'entreprise exigé avant même la page de connexion), et **Turnstile** (clés à saisir dans Portunia).
6. **Activer** dans Portunia : menu **⋯** de la Gate › **Administrer** › **Portail web** : adresse publique, groupe autorisé, durées, copier-coller, puis l'interrupteur. Créer le groupe et y ajouter les comptes concernés.

Couper le portail (interrupteur) affiche « Portail fermé » et ferme aussitôt les sessions web en cours ; **Fermer toutes les sessions web** les ferme sans couper le portail.

**Mode d'exposition** (Portunia 0.52 et Portunia Gate 0.17 et suivants) : Administrer › Portail web, ou `sudo portunia-gate portal expose` (`portal show` l'affiche, appliqué sous 30 secondes).

| Mode | Qui joint le portail | Adresse du visiteur |
|---|---|---|
| `cloudflare` (défaut) | Tunnel ; HTTPS depuis les adresses de Cloudflare seulement | `CF-Connecting-IP`, venant de la machine elle-même ou de Cloudflare seulement |
| `proxy` | Les proxys de confiance déclarés, personne d'autre | En-tête choisi (`X-Forwarded-For` par défaut), lu de droite à gauche |
| `interne` | Réseaux privés, ou les réseaux indiqués | Adresse de la connexion |
| `direct` | Tout le monde, ou les réseaux indiqués | Adresse de la connexion |
| `relais` | Les relais dédiés seulement | Donnée par le relais |

```bash
sudo portunia-gate portal expose proxy --trusted 10.0.5.10,10.0.5.11 --header X-Forwarded-For
```

**Relais dédié** (Portunia 0.53 et Portunia Gate 0.18 et suivants) : une machine à part, en DMZ le plus souvent, publie le portail pendant que la Gate reste sur le réseau interne. La Gate ouvre les connexions vers le relais : aucun flux ne va de la DMZ vers le réseau interne. Le relais ne contient ni coffre, ni comptes, ni base, seulement un secret partagé avec la Gate et ses certificats. Son HTTPS se termine sur le relais : s'il est compromis, ce qui transite pendant la présence de l'attaquant est lisible (mots de passe, codes, terminaux), révoquez-le aussitôt.

1. Dans Portunia, Administrer › Portail web › Relais dédié, indiquez un nom et l'adresse où la Gate le joint (par ex. `10.0.5.20:8447`), puis **Ajouter un relais**. La commande n'est affichée qu'une fois. Ou `sudo portunia-gate portal relay-add dmz-01 10.0.5.20:8447`.
2. Sur la machine du relais (Debian amd64) : `sudo bash installer.sh relais CODE acces.votre-domaine.fr`.
3. Pare-feu : port 443 des navigateurs vers le relais, port 8447 de la Gate vers le relais **et de nulle part ailleurs** (le relais limite les poignées de main par adresse, mais seul le pare-feu écarte les inconnus de ce port), rien du relais vers le réseau interne.
4. Dans Portunia, sélectionnez **Relais dédié** et enregistrez : la Gate refuse alors tout accès direct au portail.

Le relais présente un certificat auto-signé. Pour le vôtre : `portunia-gate edge certificate CERT CLE` sous le compte `_portunia_gate`, puis `systemctl restart portunia-gate-relais`. Mise à jour : `sudo bash installer.sh mise-a-jour` sur le relais. Plusieurs relais peuvent se placer derrière un répartiteur. Journal d'audit : `relais.ajoute`, `relais.revoque`.

Les modes `proxy`, `interne` et `direct` passent par l'écoute HTTPS : ouvrez-la dans Administrer › Portail web (**Écoute HTTPS**, un port ou `adresse:port`, ex. `8446`), ou `sudo portunia-gate portal https 8446` (`--off` la ferme). La Gate l'ouvre, la déplace ou la ferme sous quelques secondes, sans redémarrer. Les ports sous 1024 sont refusés par le système : redirigez le 443 vers le 8446 sur le pare-feu ou la box. Le pare-feu durci autorise toujours le 8446. `PORTUNIA_GATE_PORTAL_TLS_LISTEN` dans le fichier de configuration, s'il est réglé, l'emporte (l'onglet l'affiche alors sans permettre de la changer). Le WebSocket doit traverser le proxy ou le WAF.

**Certificat du portail** (écoute HTTPS), distinct du certificat de l'API que les consoles Portunia épinglent : le changer ne les touche jamais. Dans Administrer › Portail web › **Certificat du portail** :

- **Importer un certificat** d'une PKI interne ou publique : certificat PEM avec sa chaîne et sa clé non chiffrée, ou fichier PFX (.pfx, .p12) et son mot de passe. Appliqué sous quelques secondes, sans redémarrer. En ligne de commande : `sudo portunia-gate portal cert --import cert.pem --key cle.pem` (ou `--import portail.pfx`), `sudo portunia-gate portal cert` l'affiche, `--remove` revient à l'auto-signé.
- **Let's Encrypt** (Pro) : noms de domaine, e-mail de contact, puis la vérification. *TLS-ALPN-01* : écoute HTTPS ouverte et port 443 de l'adresse publique redirigé vers elle ; rien d'autre à ouvrir. *DNS-01 par Cloudflare* : un jeton d'API avec Zone › DNS › Edit sur la zone (My Profile › API Tokens › Create Token › Edit zone DNS) ; rien à ouvrir, noms génériques (`*.exemple.fr`) permis. La Gate obtient le certificat, puis le renouvelle 30 jours avant son échéance ; après un échec, elle réessaie toutes les 6 heures, ou tout de suite avec **Renouveler maintenant**. Le compte et le jeton sont gardés chiffrés par le coffre. L'autorité d'essai délivre des certificats de test sans entamer les limites de Let's Encrypt.
- Fichiers gérés hors de la Gate (renouvelés par un autre outil) : `PORTUNIA_GATE_PORTAL_TLS_CERT` et `PORTUNIA_GATE_PORTAL_TLS_KEY` dans le fichier de configuration ; ils l'emportent, et de nouveaux fichiers sont pris sous quelques secondes. Sans rien, le portail prend `PORTUNIA_GATE_TLS_CERT` s'il est réglé (comportement précédent), sinon un certificat auto-signé.

Journal d'audit : `portail.certificat`, `portail.acme`, `portail.acme_obtenu`, `portail.acme_echec`, `portail.acme_renouveler`. `cloudflared` sur une autre machine que la Gate : indiquez son réseau dans `PORTUNIA_GATE_PORTAL_TUNNEL_PEERS`, sinon son en-tête est ignoré.

Proxy Cloudflare au lieu du tunnel : `sudo portunia-gate portal https 8446` (paquet), ou `PORTUNIA_GATE_PORTAL_PORT=0.0.0.0:8446` dans `.env` (Docker), puis redémarrer ; dans Cloudflare, l'adresse proxifiée pointe vers ce port en HTTPS (mode SSL « Full »).

## Assistance à distance

Prendre la main sur le PC d'un proche ou d'un client avec **Portunia Assistance** (Portunia Gate 0.11 et suivants, Portunia 0.48 et suivants). La personne va sur `https://adresse-du-portail/assistance`, télécharge Portunia Assistance (un seul programme, sans installation ni compte) et vous lit un code à 9 chiffres ; vous le tapez dans Portunia (**Assistance à distance** dans la barre latérale). Elle voit votre nom et choisit : voir seulement, ou voir et contrôler. Son écran s'ouvre dans un onglet Bureau à distance.

| | |
|---|---|
| Relais | La Gate ne fait que mettre en relation et transmettre : la liaison est chiffrée de bout en bout à partir du code (échange de clés SPAKE2, ChaCha20-Poly1305). La Gate ne voit ni l'écran ni la frappe, et ne les enregistre pas. |
| Code | À usage unique, donné par la Gate à l'ouverture de Portunia Assistance ; un code faux met fin à la tentative et la personne en reçoit un nouveau. |
| Qui | Les membres du **groupe des dépanneurs** seulement (« Dépanneurs » par défaut), connectés à la Gate depuis Portunia. |
| Personne aidée | Un cadre et une barre **Arrêter** restent sur son écran (invisibles dans l'image partagée) ; Échap trois fois arrête aussi. L'assistance s'arrête au bout de la durée maximale (4 heures par défaut). |
| Programme | La Gate télécharge `portunia-assistance.exe` depuis les versions de Portunia à l'activation de l'assistance, puis cherche une nouvelle version chaque heure (seule l'empreinte publiée est relue tant qu'elle n'a pas changé), et vérifie son empreinte SHA-256. Il n'est pas encore signé : Windows SmartScreen avertit à la première ouverture (« Informations complémentaires » › « Exécuter quand même »). |
| Coupure du réseau | Depuis la 0.43 (avec Portunia 0.81 et Portunia Assistance 0.81) : si le réseau d'un des deux côtés tombe, la session attend jusqu'à 2 minutes et reprend toute seule, sans nouveau code ; ce qui était en route est renvoyé. |
| Fichiers | Depuis la 0.44 (avec Portunia 0.82 et Portunia Assistance 0.82) : des fichiers dans les deux sens, dans la liaison chiffrée. Le relais ne voit ni les noms ni le contenu ; Portunia signale chaque fichier pour le journal (sens, taille, issue). |
| Journal | `assistance.ouverte`, `assistance.fermee`, `assistance.coupure`, `assistance.reprise`, `assistance.fichier`, `assistance.reglage`, `assistance.place_inconnue`, `assistance.programme`. |

**Mise en place** : la page et le relais utilisent l'adresse du portail web (voir [Portail web](#portail-web), étapes 1 à 3 ; le portail lui-même peut rester coupé). Dans Portunia, activer l'extension **Assistance à distance**, puis menu **⋯** de la Gate › **Administrer** › **Assistance** : groupe des dépanneurs, durée maximale, puis l'interrupteur. Créer le groupe et y ajouter les comptes des dépanneurs.

## Se connecter sans Portunia

```bash
ssh -p 2222 julien@gate              # menu des serveurs autorisés
ssh -p 2222 julien%web-01@gate       # directement sur web-01
ssh -J julien@gate:2222 admin@fw-01  # rebond de bout en bout (serveurs en mode rebond)
sftp -P 2222 julien%web-01@gate      # fichiers (mode coffre, si la règle autorise SFTP)
```

Le code TOTP doit avoir été enrôlé avant, dans Portunia ou avec `sudo portunia-gate user totp julien`.

Les serveurs Windows s'ouvrent aussi dans mstsc, Windows App ou Remmina, avec un fichier .rdp à usage unique préparé par Portunia : voir [Clients RDP ordinaires](#clients-rdp-ordinaires-rdp-natif-031).

## Administrer en ligne de commande

Tout se fait au choix dans Portunia ou ici ; seule la relecture des sessions reste dans Portunia. Sur le serveur, l'assistant installe la commande `portunia-gate`, qui s'utilise avec sudo depuis n'importe quel dossier :

```bash
# Informations
sudo portunia-gate info                                            # version, empreintes, comptes

# Comptes
sudo portunia-gate user add marc --provisoire                      # mot de passe provisoire, code enrôlé dans Portunia
sudo portunia-gate user add marc                                   # mot de passe et code saisis ici
sudo portunia-gate user add presta --policy "key+totp"             # clé SSH et code obligatoires
sudo portunia-gate user key marc "ssh-ed25519 AAAA… marc@pc"
sudo portunia-gate user role marc auditor                          # user, auditor (relecture et journal) ou admin
sudo portunia-gate user list | passwd marc | totp marc | disable marc | delete marc
sudo portunia-gate user policy marc "key+totp" | reset-password marc | reset-code marc

# Groupes
sudo portunia-gate group add "Admins Linux"
sudo portunia-gate group member "Admins Linux" marc julien
sudo portunia-gate group remove "Admins Linux" marc
sudo portunia-gate group list | delete "Admins Linux"

# Serveurs
sudo portunia-gate target add web-01 --host 10.0.1.11 --mode coffre --account admin --password --folder Production
sudo portunia-gate target add rec-app --host 10.0.2.5 --mode enregistre --folder Recette
sudo portunia-gate target add fw-edge --host 10.0.0.1 --mode rebond --folder Réseau
sudo portunia-gate target add srv-ad-01 --host 10.0.3.10 --protocol rdp --mode rebond --folder Windows
sudo portunia-gate target list
sudo portunia-gate target edit web-01 --folder Production --account root   # --rename, --host, --port, --mode, --password, --key-file
sudo portunia-gate target secret web-01 --generate                 # ou --password, --key-file : remplace le secret du coffre
sudo portunia-gate target forget web-01                            # serveur réinstallé : oublie son empreinte
sudo portunia-gate target delete fw-edge

# Règles
sudo portunia-gate rule add prod --group "Admins Linux" --targets web-01,rec-app --sftp --days lun-ven --hours 7-20
sudo portunia-gate rule add presta-db --group Prestataires --targets db-01 --expires 2026-12-31
sudo portunia-gate rule list                                       # avec leur état en ce moment
sudo portunia-gate rule edit prod --sftp off --hours ""            # "" efface les jours, les heures ou l'expiration
sudo portunia-gate rule delete presta-db
sudo portunia-gate rule add windows --group Comptabilité --targets srv-ad-01 --files   # copie de fichiers en Bureau à distance (journalisée, SHA-256)

# Portail web et assistance
sudo portunia-gate portal set --url https://acces.acme.fr --group "Accès web" --duration 4 --idle 30 --clipboard on
sudo portunia-gate portal on                                       # off le ferme ; close-sessions termine les sessions web
sudo portunia-gate portal show
sudo portunia-gate assist set --group Dépanneurs --duration 4
sudo portunia-gate assist on                                       # off, show

# Réglages
sudo portunia-gate setting auth_policy "password+totp,key+totp"    # politique générale
sudo portunia-gate setting banniere "Accès réservé. Les sessions sont enregistrées."
sudo portunia-gate setting nom "Gate ACME"
sudo portunia-gate setting langue fr                             # en, fr, ou "" pour la langue du système

# Contrôle
sudo portunia-gate audit --verify --last 50
sudo portunia-gate sessions --last 20
sudo portunia-gate audit --search marc --csv journal.csv
sudo portunia-gate sessions --user marc --since 2026-11-01   # sessions show ID : enregistrement et signature
```

Référence complète, avec toutes les commandes et options : [docs/ligne-de-commande.md](docs/ligne-de-commande.md). `sudo portunia-gate --help` et `sudo portunia-gate user --help` les listent sur le serveur.

Voir aussi [docs/exploitation.fr.md](docs/exploitation.fr.md) : sauvegardes, mise à jour, journaux, dépannage.

## Feuille de route

1. **Socle** : proxy SSH, trois modes, coffre, comptes et TOTP, droits, enregistrement signé, journal chaîné, Docker Compose.
2. **Intégration Portunia** : API, ajout de la Gate dans Portunia, serveurs dans la barre latérale, jetons à usage unique, première connexion, administration complète, clé générée et installée sur les serveurs du coffre. Assistant d'installation (0.3), paquet Debian (0.4).
3. **Audit** : relecture et recherche (0.5), vue en direct et coupure, vidéo MP4 à la demande, lecteur détachable, conservation réglable avec estimation du disque, syslog et CSV.
4. **Bureau à distance** : rebond (0.6), enregistré avec enregistrement signé (0.8), relecture (0.10), coffre (0.29 : la Gate ouvre la session Windows avec le compte du coffre), clients RDP ordinaires (0.31 : mstsc, Windows App, Remmina avec un fichier .rdp à usage unique), puis règles (presse-papiers, son).
5. **Portail web** : SSH (0.7) et Bureau à distance (0.8) dans le navigateur derrière Cloudflare, puis clés d'accès (passkeys), personnalisation.
6. **Assistance à distance** : relais Portunia Assistance avec un code (0.11), discussion, pause, reprise de la main et reprise après une coupure du réseau (0.43), transfert de fichiers (0.44), puis plusieurs écrans, lien d'invitation, accès sans surveillance à ses propres PC.
7. **Exploitation** : sauvegarde intégrée, dépôt apt pour les mises à jour, paquet ARM, imports (Portunia, CSV), console web activable.
8. **Console maître** : un Portunia Gate central pour les prestataires, des relais chez les clients.
