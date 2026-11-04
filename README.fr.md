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
| **Bureau à distance** | Serveurs Windows (RDP) derrière la Gate, ouverts depuis Portunia ou le portail web. Modes rebond et enregistré (voir [Bureau à distance](#bureau-à-distance-rdp)). |
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
| Exports | **Enregistrement .cast** (lisible par asciinema) et **Transcription** (texte horodaté). |

**Saisies masquées** : une frappe qui ne s'affiche pas à l'écran (mot de passe de sudo, su, ssh…) est remplacée par des points de longueur fixe, dans le lecteur comme dans la recherche. Elle reste dans le fichier signé : un administrateur peut la **révéler** (bouton dans le lecteur), et cette relecture est inscrite au journal (`enregistrement.revele`). L'export `.cast` d'une relecture masquée est une copie non signée ; celui d'une relecture révélée est le fichier d'origine, signé.

**Sessions sans frappe** (règle qui n'enregistre que l'écran) : pas de sous-titres ; le panneau liste les commandes repérées à l'écran, après l'invite.

**Chaque relecture est inscrite au journal** (`enregistrement.consulte`), et le lecteur affiche en filigrane le compte qui regarde.

**Relire ses propres sessions** : Administrer › Réglages › « Chaque compte peut relire ses propres sessions ». Les comptes « utilisateur » voient alors **Mes sessions** dans le menu de la Gate, sans pouvoir révéler les saisies masquées.

**Commandes sensibles** : Administrer › Réglages, une par ligne (par défaut `rm -rf`, `mkfs`, `dd if=`, `shutdown`, `reboot`, `DROP TABLE`…).

Les sessions enregistrées avant la version 0.5 se relisent, mais n'entrent pas dans la recherche.

## Bureau à distance (RDP)

Les serveurs Windows se déclarent comme les autres : Administrer › Serveurs et coffre › **Ajouter un serveur**, protocole **Bureau à distance (RDP)**, port 3389. Ils apparaissent sous la Gate dans Portunia avec un badge **RDP** et s'ouvrent dans un onglet Bureau à distance.

Dans les deux modes, l'utilisateur tape ses identifiants Windows à chaque ouverture ; ni Portunia ni la Gate ne les gardent.

| | **Rebond** (0.6) | **Enregistré** (0.8) |
|---|---|---|
| Chemin | Tunnel par le port SSH de la Gate (2222), avec un jeton à usage unique ; la connexion RDP est chiffrée de bout en bout. | Passage de la Gate (RDCleanPath, sur le port de l'API ou du portail) avec un jeton à usage unique : la Gate ouvre la connexion chiffrée avec le serveur Windows et relaie la session. |
| Ce que voit la Gate | Rien du contenu ; elle vérifie la règle et journalise (`rebond.ouvert`, durée, octets). | La session (pour l'enregistrer), mais pas le mot de passe : l'authentification Windows (NLA) se fait entre le client et le serveur. |
| Enregistrement | Non. | Oui, fichier signé (`.rdpcap`) : l'image envoyée par le serveur, les clics, les copier-coller (texte masqué tant qu'un administrateur ne le révèle pas) et la frappe si la règle l'enregistre. Relecture dans Portunia (0.47 ou suivant), comme une session SSH. |
| Clients | Portunia. | Portunia et le **portail web** (Bureau à distance dans le navigateur). |
| Certificat du serveur | Vérifié par le client. | Vérifié par la Gate : empreinte gardée à la première connexion, connexion refusée si elle change (`cible.empreinte_differente`). |

La Gate doit joindre le port 3389 des serveurs Windows. Dans Portunia, l'extension Bureau à distance doit être activée ; sinon les serveurs RDP restent visibles, grisés. Un serveur RDP n'apparaît pas dans le menu `ssh` de la Gate et ne s'ouvre pas en terminal.

Le mode **coffre** (compte Windows fourni par la Gate, sans rien taper) et la relecture des sessions RDP arrivent dans les versions suivantes.
Le mode **coffre** (compte Windows fourni par la Gate, sans rien taper) arrive dans une prochaine version.
## Portail web

Une page web pour ouvrir ses serveurs depuis n'importe quel navigateur, sans Portunia : connexion, liste des serveurs autorisés, terminal SSH ou Bureau à distance dans un onglet. Elle ne sert pas à l'administration. Le Bureau à distance passe par le passage RDCleanPath de la Gate (serveurs en mode enregistré, voir [Bureau à distance](#bureau-à-distance-rdp)). Le portail passe par le serveur SSH de la Gate, avec un jeton à usage unique : mêmes règles, même coffre, même enregistrement, même journal. Une session web se relit dans l'audit comme une autre ; son adresse est suivie de « (web) ».

**Sécurité**

| | |
|---|---|
| Exposition | **Cloudflare Tunnel** (conseillé) : la Gate lance elle-même `cloudflared` (connexion sortante vers Cloudflare, aucun port entrant, rien à installer en root). Ou **proxy Cloudflare** : HTTPS sur le port 8446, n'accepte que les adresses de Cloudflare. |
| Connexion | Mot de passe **et** code toujours exigés, même pour un compte qui s'en passe dans Portunia. Cinq essais par compte et vingt par adresse en dix minutes. Anti-robots **Cloudflare Turnstile** si ses clés sont réglées. |
| Comptes | Seuls les membres du **groupe choisi** (« Accès web » par défaut). Première connexion et code perdu : pas sur le portail, mais avec Portunia ou l'administrateur. |
| Session | Cookie « HttpOnly, Secure, SameSite=Strict », 1 heure par défaut ; fermeture après 15 minutes sans frappe (avertissement 90 s avant). |
| Page | Rien de chargé depuis l'extérieur (sauf Turnstile), politique de contenu stricte, pas d'affichage dans un cadre d'un autre site, adresse publique vérifiée à chaque connexion. |
| Serveurs | SSH en mode coffre ou enregistré ; Bureau à distance en mode enregistré (client RDP d'IronRDP dans la page, identifiants Windows tapés dans la page et envoyés au serveur, jamais à la Gate). Les serveurs en rebond (de bout en bout) restent avec Portunia. |
| Journal | `portail.connexion`, `portail.echec`, `portail.active`, `portail.desactive`, `portail.modifie`, `portail.sessions_fermees`. |

**Mise en place**

1. **Créer le tunnel** dans Cloudflare : **Networking › Tunnels › Create Tunnel**, un nom (ex. `portunia-gate`), puis copier la commande d'installation affichée, pour n'importe quel système. Elle contient le jeton ; ne pas l'exécuter.
2. **La donner à la Gate** : dans Portunia, Administrer › Portail web › mode Cloudflare, coller la commande ou le jeton et enregistrer. Ou depuis le serveur : `sudo bash installer.sh portail`, ou `sudo portunia-gate portal tunnel -` (jeton sur l'entrée standard ; `--remove` l'arrête). La Gate télécharge `cloudflared` 2026.9.1 depuis le GitHub de Cloudflare, vérifie son empreinte SHA-256, le lance sous son propre compte et le relance s'il s'arrête. Le jeton est chiffré par le coffre. Serveur sans accès à GitHub : `PORTUNIA_GATE_CLOUDFLARED=/usr/bin/cloudflared`.
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

Le relais présente un certificat auto-signé. Pour le vôtre : `portunia-gate edge certificate CERT CLE` sous le compte `_portunia_gate`, puis `systemctl restart portunia-gate-relais`. Mise à jour : `sudo bash installer.sh update` sur le relais. Plusieurs relais peuvent se placer derrière un répartiteur. Journal d'audit : `relais.ajoute`, `relais.revoque`.

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
| Programme | La Gate télécharge `portunia-assistance.exe` depuis les versions de Portunia à l'activation de l'assistance, puis une fois par jour, et vérifie son empreinte SHA-256. Il n'est pas encore signé : Windows SmartScreen avertit à la première ouverture (« Informations complémentaires » › « Exécuter quand même »). |
| Journal | `assistance.ouverte`, `assistance.fermee`, `assistance.reglage`, `assistance.place_inconnue`, `assistance.programme`. |

**Mise en place** : la page et le relais utilisent l'adresse du portail web (voir [Portail web](#portail-web), étapes 1 à 3 ; le portail lui-même peut rester coupé). Dans Portunia, activer l'extension **Assistance à distance**, puis menu **⋯** de la Gate › **Administrer** › **Assistance** : groupe des dépanneurs, durée maximale, puis l'interrupteur. Créer le groupe et y ajouter les comptes des dépanneurs.

## Se connecter sans Portunia

```bash
ssh -p 2222 julien@gate              # menu des serveurs autorisés
ssh -p 2222 julien%web-01@gate       # directement sur web-01
ssh -J julien@gate:2222 admin@fw-01  # rebond de bout en bout (serveurs en mode rebond)
sftp -P 2222 julien%web-01@gate      # fichiers (mode coffre, si la règle autorise SFTP)
```

Le code TOTP doit avoir été enrôlé avant, dans Portunia ou avec `sudo portunia-gate user totp julien`.

## Administrer en ligne de commande

Tout se fait au choix dans Portunia ou ici, sauf la relecture des sessions et Let's Encrypt (Portunia seulement). Sur le serveur, l'assistant installe la commande `portunia-gate`, qui s'utilise avec sudo depuis n'importe quel dossier :

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
```

`sudo portunia-gate --help` et `sudo portunia-gate user --help` listent toutes les options.

Voir aussi [docs/exploitation.fr.md](docs/exploitation.fr.md) : sauvegardes, mise à jour, journaux, dépannage.

## Feuille de route

1. **Socle** : proxy SSH, trois modes, coffre, comptes et TOTP, droits, enregistrement signé, journal chaîné, Docker Compose.
2. **Intégration Portunia** : API, ajout de la Gate dans Portunia, serveurs dans la barre latérale, jetons à usage unique, première connexion, administration complète, clé générée et installée sur les serveurs du coffre. Assistant d'installation (0.3), paquet Debian (0.4).
3. **Audit** : relecture et recherche (0.5), vue en direct et coupure, vidéo MP4 à la demande, lecteur détachable, conservation réglable avec estimation du disque, syslog et CSV.
4. **Bureau à distance** : rebond (0.6), enregistré avec enregistrement signé (0.8), relecture (0.10), puis coffre (la Gate ouvre la session Windows avec le compte du coffre), règles (presse-papiers, son).
5. **Portail web** : SSH (0.7) et Bureau à distance (0.8) dans le navigateur derrière Cloudflare, puis clés d'accès (passkeys), personnalisation.
6. **Assistance à distance** : relais Portunia Assistance avec un code (0.11), puis lien d'invitation, accès sans surveillance à ses propres PC, transfert de fichiers, discussion.
7. **Exploitation** : sauvegarde intégrée, dépôt apt pour les mises à jour, paquet ARM, imports (Portunia, CSV), console web activable.
8. **Console maître** : un Portunia Gate central pour les prestataires, des relais chez les clients.
