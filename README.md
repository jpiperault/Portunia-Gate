# Heimdia

Bastion SSH de [Portunia](https://github.com/jpiperault/Portunia) : les utilisateurs passent par Heimdia pour atteindre les serveurs ; Heimdia vérifie qui ils sont, décide où ils peuvent aller, fournit si besoin le compte du serveur sans le leur montrer, enregistre les sessions et trace tout dans un journal infalsifiable.

> État : **version 0.8, Bureau à distance enregistré**, aussi dans le navigateur (portail web) ; portail web SSH (0.7), Bureau à distance en rebond (0.6), relecture des sessions SSH (0.5). Voir la [Feuille de route](#feuille-de-route).

## Ce que fait Heimdia

| | |
|---|---|
| **Trois modes par serveur** | **Rebond** : relais de bout en bout (`ssh -J`), le bastion ne voit pas le contenu, il journalise la connexion. **Enregistré** : le bastion relaie et enregistre la session ; l'utilisateur tape ses propres identifiants. **Coffre** : comme Enregistré, et le bastion fournit le compte du serveur, que l'utilisateur ne connaît jamais. |
| **Connexion au bastion** | Mot de passe, clé SSH et code TOTP (Google Authenticator, Microsoft Authenticator…), combinables au choix : politique générale et politique par compte. Un code ne sert qu'une fois. |
| **Droits** | Des règles relient un groupe à des serveurs, avec jours, heures, date d'expiration, SFTP et tunnels autorisés ou non. Tout ce qui n'est pas permis est refusé. |
| **Enregistrement** | Format asciicast (lisible par Portunia et asciinema), affichage seul ou aussi la frappe selon la règle. Chaque fichier est signé par le bastion. |
| **Relecture** | Dans Portunia, comme une vidéo : la frappe en sous-titres, les pauses sautées, les commandes sensibles repérées, la recherche dans toutes les sessions. Les mots de passe tapés sont masqués ; chaque relecture est inscrite au journal. |
| **Journal d'audit** | Connexions, échecs, sessions, changements d'administration. Chaque événement contient l'empreinte du précédent : une ligne supprimée ou modifiée se voit (`heimdia audit --verify`). |
| **Portunia** | Extension Heimdia : le bastion s'ajoute dans la barre latérale, ses serveurs s'ouvrent avec un jeton à usage unique, les administrateurs gèrent tout depuis Portunia (serveurs et coffre, comptes, groupes, règles, réglages) et les auditeurs relisent les sessions et le journal. |
| **Bureau à distance** | Serveurs Windows (RDP) derrière le bastion, ouverts depuis Portunia ou le portail web. Modes rebond et enregistré (voir [Bureau à distance](#bureau-à-distance-rdp)). |
| **Portail web** | Pour qui n'a pas Portunia sous la main : une page de connexion et un terminal dans le navigateur, derrière Cloudflare, sans port ouvert. Activé ou coupé d'un clic dans Portunia (voir [Portail web](#portail-web)). |
| **Autres clients** | N'importe quel client SSH : OpenSSH, PuTTY, MobaXterm, WinSCP (SFTP). |

## Installer

Deux façons d'installer, avec le même assistant :

| | **Paquet Debian** (recommandé) | **Docker** |
|---|---|---|
| Installation | 1 à 2 minutes : paquet déjà compilé | 10 à 30 minutes : compilation sur le serveur |
| Serveur conseillé | 1 processeur, 2 Go de mémoire, 10 Go de disque | 2 processeurs, 4 Go de mémoire, 20 Go de disque |
| Container LXC | Rien à activer | Options *nesting* et *keyctl* obligatoires |
| Fonctionnement | Service systemd durci, PostgreSQL de la distribution | Deux conteneurs (Heimdia et PostgreSQL) |
| Mise à jour | `sudo bash installer.sh mise-a-jour` (télécharge la dernière version) | `sudo ./installer.sh mise-a-jour` (`git pull` puis recompilation) |
| Processeurs | x86-64 (amd64) | x86-64 et ARM |

Dans les deux cas : un serveur **Debian 12 ou 13** ou **Ubuntu 22.04 ou plus récent** (machine virtuelle ou container LXC) avec un accès root ou sudo, et les ports **2222** (SSH) et **8443** (API pour Portunia) joignables depuis les postes des utilisateurs.

### Installation en paquet Debian

```bash
curl -fsSLO https://github.com/jpiperault/Heimdia-releases/releases/latest/download/installer.sh
sudo bash installer.sh
```

L'assistant télécharge la dernière version de Heimdia, vérifie son empreinte SHA-256, installe le paquet et PostgreSQL, crée la base (accès local par socket, sans mot de passe) et le service `heimdia`.

Fichiers installés :

| | |
|---|---|
| `/usr/lib/heimdia/heimdia` | Le programme |
| `/usr/bin/heimdia` | La commande d'administration (`sudo heimdia …`) |
| `/etc/heimdia/heimdia.env` | Réglages : ports, fuseau, accès à la base |
| `/var/lib/heimdia/` | Clés, certificat de l'API, enregistrements des sessions |
| Base PostgreSQL `heimdia` | Comptes, serveurs, règles, sessions, journal |

Le service tourne sous un compte système dédié (`_heimdia`), n'écrit que dans `/var/lib/heimdia` et ne voit ni les dossiers personnels ni le reste du système. Commandes utiles : `sudo systemctl status heimdia`, `sudo journalctl -u heimdia -f`.

Installer un paquet précis (sans accès à Internet, ou une version antérieure) : `sudo bash installer.sh --paquet heimdia_0.4.0_amd64.deb`.

### Installation avec Docker

```bash
git clone https://github.com/jpiperault/Heimdia.git
cd Heimdia
sudo ./installer.sh --docker
```

Le dépôt est privé : `git clone` demande votre identifiant GitHub et, en guise de mot de passe, un jeton d'accès (GitHub › Settings › Developer settings › Personal access tokens, droit de lecture sur le dépôt). L'assistant installe Docker s'il manque et, avec moins de 4 Go de mémoire, propose un fichier d'échange temporaire pour la compilation. Dans un container LXC Proxmox, activez d'abord *nesting* et *keyctl* (Options › Features) puis redémarrez le container.

### Les questions

L'assistant pose cinq questions ; la touche Entrée garde la valeur proposée :

| Question | Valeur proposée | |
|---|---|---|
| Nom du bastion | Heimdia | Affiché dans Portunia et dans l'application d'authentification. |
| Identifiant de l'administrateur | admin | Votre compte pour administrer le bastion depuis Portunia. |
| Port SSH | 2222 | |
| Port de l'API | 8443 | |
| Fuseau horaire | celui du serveur | Sert aux plages horaires des règles d'accès. |

Il crée ensuite les clés, le certificat, la base et le compte administrateur, démarre le bastion et affiche ce qu'il faut saisir dans Portunia :

```
  ┌──────────────────────────────────────────────────────────────────────────
  │ Dans Portunia : Extensions › activer Heimdia, puis Bastions › Ajouter un bastion
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

Le bastion redémarre seul avec le serveur.

### Sauvegarder la clé du coffre, tout de suite

La **clé du coffre** chiffre les mots de passe des serveurs et les codes TOTP. Sans elle, une restauration perd tous ces secrets. L'assistant en dépose une copie dans votre dossier personnel (`~/heimdia-coffre.key`) : copiez-la hors du serveur (gestionnaire de mots de passe, coffre de l'entreprise), puis effacez cette copie. L'assistant affiche les commandes exactes, par exemple :

```bash
scp julien@192.168.1.20:/home/julien/heimdia-coffre.key .   # depuis votre poste
rm ~/heimdia-coffre.key                                      # sur le serveur
```

### Relancer l'assistant

`sudo bash installer.sh` sur un bastion déjà installé ouvre un menu :

| Choix | Commande directe | |
|---|---|---|
| Informations pour Portunia | `sudo bash installer.sh info` | Adresse et empreinte à donner aux utilisateurs. |
| Mettre à jour | `sudo bash installer.sh mise-a-jour` | Installe la dernière version et redémarre. **Les sessions ouvertes sont coupées.** |
| Créer un administrateur | `sudo bash installer.sh admin julien` | Administrateur de secours avec un mot de passe provisoire, par exemple si le seul administrateur a perdu son téléphone. |

En mode Docker, lancez l'assistant depuis le dossier du dépôt (`sudo ./installer.sh`).

Une installation interrompue (coupure, erreur) se reprend en relançant l'assistant : les réglages déjà saisis sont proposés de nouveau.

### Sans questions (automatisation)

Hors terminal, l'assistant prend les valeurs proposées, ou celles des variables `HEIMDIA_NOM`, `HEIMDIA_ADMIN`, `HEIMDIA_SSH_PORT`, `HEIMDIA_API_PORT` et `TZ` :

```bash
sudo HEIMDIA_ADMIN=julien HEIMDIA_NOM="Bastion ACME" bash installer.sh </dev/null
```

### Certificat de l'entreprise

Le certificat de l'API est auto-signé : Portunia le reconnaît par son empreinte, ce qui suffit. Pour utiliser plutôt un certificat de l'entreprise (fichiers PEM, certificat suivi de sa chaîne) :

Paquet Debian :

```bash
sudo install -o _heimdia -g _heimdia -m 600 cert.pem /var/lib/heimdia/entreprise.crt
sudo install -o _heimdia -g _heimdia -m 600 cle.pem /var/lib/heimdia/entreprise.key
echo 'HEIMDIA_TLS_CERT=/var/lib/heimdia/entreprise.crt' | sudo tee -a /etc/heimdia/heimdia.env
echo 'HEIMDIA_TLS_KEY=/var/lib/heimdia/entreprise.key' | sudo tee -a /etc/heimdia/heimdia.env
sudo systemctl restart heimdia
```

Docker, depuis le dossier du dépôt :

```bash
sudo docker compose cp cert.pem heimdia:/var/lib/heimdia/entreprise.crt
sudo docker compose cp cle.pem heimdia:/var/lib/heimdia/entreprise.key
echo 'HEIMDIA_TLS_CERT=/var/lib/heimdia/entreprise.crt' | sudo tee -a .env
echo 'HEIMDIA_TLS_KEY=/var/lib/heimdia/entreprise.key' | sudo tee -a .env
sudo docker compose up -d
```

L'empreinte change : les utilisateurs devront valider la nouvelle (`sudo heimdia info`).

## Ajouter le bastion dans Portunia

1. **Activer l'extension** : Portunia › Extensions › Heimdia › Activer. La section **Bastions** apparaît dans la barre latérale.
2. **Ajouter le bastion** : Bastions › **+** › tapez l'adresse donnée par l'assistant (`192.168.1.20`, ou `192.168.1.20:9443` si vous avez changé le port de l'API).
3. **Vérifier l'empreinte** : Portunia affiche l'empreinte du certificat du bastion. Comparez-la à celle donnée par l'assistant (ou `sudo heimdia info` sur le serveur, ligne « Certificat de l'API »). Si elle diffère, n'allez pas plus loin : quelqu'un se fait peut-être passer pour le bastion.
4. **Se connecter** : identifiant et mot de passe ; **laissez le champ Code vide** lors de la première connexion.
5. **Première connexion** : Portunia demande de choisir un nouveau mot de passe (10 caractères au moins), puis affiche un code QR. Scannez-le avec votre application d'authentification et tapez le code à 6 chiffres qu'elle affiche.
6. **Ouvrir un serveur** : les serveurs autorisés apparaissent sous le bastion, rangés par dossier. Un clic ouvre la session, sans retaper le code (jeton à usage unique) :
   - **coffre** : connexion directe, le bastion fournit le compte ;
   - **enregistré** : le serveur demande vos identifiants dans le terminal ;
   - **rebond** : Portunia demande vos identifiants du serveur, la connexion est chiffrée de bout en bout.
7. **Administrer** (Portunia Équipes, compte administrateur) : menu **⋯** du bastion › **Administrer**. Un onglet s'ouvre avec les serveurs et le coffre, les comptes, les groupes, les règles et les réglages.
8. **Auditer** (Portunia Équipes, compte administrateur ou auditeur) : menu **⋯** du bastion › **Audit**. Un onglet s'ouvre avec les sessions et le journal (voir [Relire les sessions](#relire-les-sessions)).

Les comptes suivants se créent depuis l'onglet d'administration : Portunia affiche un mot de passe provisoire à transmettre à l'utilisateur, qui suivra les étapes 2 à 5.

Rien ne s'affiche sous le bastion ? Aucune règle ne donne encore accès à un serveur : créez un serveur, un groupe contenant le compte, puis une règle qui les relie.

## Relire les sessions

Menu **⋯** du bastion › **Audit** › **Sessions** (rôles administrateur et auditeur).

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

**Relire ses propres sessions** : Administrer › Réglages › « Chaque compte peut relire ses propres sessions ». Les comptes « utilisateur » voient alors **Mes sessions** dans le menu du bastion, sans pouvoir révéler les saisies masquées.

**Commandes sensibles** : Administrer › Réglages, une par ligne (par défaut `rm -rf`, `mkfs`, `dd if=`, `shutdown`, `reboot`, `DROP TABLE`…).

Les sessions enregistrées avant la version 0.5 se relisent, mais n'entrent pas dans la recherche.

## Bureau à distance (RDP)

Les serveurs Windows se déclarent comme les autres : Administrer › Serveurs et coffre › **Ajouter un serveur**, protocole **Bureau à distance (RDP)**, port 3389. Ils apparaissent sous le bastion dans Portunia avec un badge **RDP** et s'ouvrent dans un onglet Bureau à distance.

Dans les deux modes, l'utilisateur tape ses identifiants Windows à chaque ouverture ; ni Portunia ni le bastion ne les gardent.

| | **Rebond** (0.6) | **Enregistré** (0.8) |
|---|---|---|
| Chemin | Tunnel par le port SSH du bastion (2222), avec un jeton à usage unique ; la connexion RDP est chiffrée de bout en bout. | Passage du bastion (RDCleanPath, sur le port de l'API ou du portail) avec un jeton à usage unique : le bastion ouvre la connexion chiffrée avec le serveur Windows et relaie la session. |
| Ce que voit le bastion | Rien du contenu ; il vérifie la règle et journalise (`rebond.ouvert`, durée, octets). | La session (pour l'enregistrer), mais pas le mot de passe : l'authentification Windows (NLA) se fait entre le client et le serveur. |
| Enregistrement | Non. | Oui, fichier signé (`.rdpcap`) ; relecture dans une prochaine version. |
| Clients | Portunia. | Portunia et le **portail web** (Bureau à distance dans le navigateur). |
| Certificat du serveur | Vérifié par le client. | Vérifié par le bastion : empreinte gardée à la première connexion, connexion refusée si elle change (`cible.empreinte_differente`). |

Le bastion doit joindre le port 3389 des serveurs Windows. Dans Portunia, l'extension Bureau à distance doit être activée ; sinon les serveurs RDP restent visibles, grisés. Un serveur RDP n'apparaît pas dans le menu `ssh` du bastion et ne s'ouvre pas en terminal.

Le mode **coffre** (compte Windows fourni par le bastion, sans rien taper) et la relecture des sessions RDP arrivent dans les versions suivantes.

## Portail web

Une page web pour ouvrir ses serveurs depuis n'importe quel navigateur, sans Portunia : connexion, liste des serveurs autorisés, terminal SSH ou Bureau à distance dans un onglet. Elle ne sert pas à l'administration. Le Bureau à distance passe par le passage RDCleanPath du bastion (serveurs en mode enregistré, voir [Bureau à distance](#bureau-à-distance-rdp)). Le portail passe par le serveur SSH du bastion, avec un jeton à usage unique : mêmes règles, même coffre, même enregistrement, même journal. Une session web se relit dans l'audit comme une autre ; son adresse est suivie de « (web) ».

**Sécurité**

| | |
|---|---|
| Exposition | **Cloudflare Tunnel** (conseillé) : le service `cloudflared` ouvre une connexion sortante vers Cloudflare, aucun port entrant. Ou **proxy Cloudflare** : HTTPS sur le port 8446, n'accepte que les adresses de Cloudflare. |
| Connexion | Mot de passe **et** code toujours exigés, même pour un compte qui s'en passe dans Portunia. Cinq essais par compte et vingt par adresse en dix minutes. Anti-robots **Cloudflare Turnstile** si ses clés sont réglées. |
| Comptes | Seuls les membres du **groupe choisi** (« Accès web » par défaut). Première connexion et code perdu : pas sur le portail, mais avec Portunia ou l'administrateur. |
| Session | Cookie « HttpOnly, Secure, SameSite=Strict », 1 heure par défaut ; fermeture après 15 minutes sans frappe (avertissement 90 s avant). |
| Page | Rien de chargé depuis l'extérieur (sauf Turnstile), politique de contenu stricte, pas d'affichage dans un cadre d'un autre site, adresse publique vérifiée à chaque connexion. |
| Serveurs | SSH en mode coffre ou enregistré ; Bureau à distance en mode enregistré (client RDP d'IronRDP dans la page, identifiants Windows tapés dans la page et envoyés au serveur, jamais au bastion). Les serveurs en rebond (de bout en bout) restent avec Portunia. |
| Journal | `portail.connexion`, `portail.echec`, `portail.active`, `portail.desactive`, `portail.modifie`, `portail.sessions_fermees`. |

**Mise en place**

1. **Créer le tunnel** dans Cloudflare Zero Trust › Networks › Tunnels › *Create a tunnel* (type Cloudflared), et copier son jeton (la longue suite après `--token`).
2. **L'installer sur le bastion** : `sudo bash installer.sh portail` (paquet) ou `sudo ./installer.sh portail` (Docker), puis coller le jeton.
3. **Publier l'adresse** : dans l'onglet *Public Hostname* du tunnel, ajouter l'adresse (ex. `acces.votre-domaine.fr`), type **HTTP**, URL `localhost:8445` (paquet) ou `heimdia:8445` (Docker).
4. **Conseillé : Cloudflare Access** sur cette adresse (compte de l'entreprise exigé avant même la page de connexion), et **Turnstile** (clés à saisir dans Portunia).
5. **Activer** dans Portunia : menu **⋯** du bastion › **Administrer** › **Portail web** : adresse publique, groupe autorisé, durées, copier-coller, puis l'interrupteur. Créer le groupe et y ajouter les comptes concernés.

Couper le portail (interrupteur) affiche « Portail fermé » et ferme aussitôt les sessions web en cours ; **Fermer toutes les sessions web** les ferme sans couper le portail.

Proxy Cloudflare au lieu du tunnel : dans `/etc/heimdia/heimdia.env`, `HEIMDIA_PORTAL_TLS_LISTEN=0.0.0.0:8446` (paquet), ou `HEIMDIA_PORTAL_PORT=0.0.0.0:8446` dans `.env` (Docker), puis redémarrer ; dans Cloudflare, l'adresse proxifiée pointe vers ce port en HTTPS (mode SSL « Full »).

## Se connecter sans Portunia

```bash
ssh -p 2222 julien@bastion              # menu des serveurs autorisés
ssh -p 2222 julien%web-01@bastion       # directement sur web-01
ssh -J julien@bastion:2222 admin@fw-01  # rebond de bout en bout (serveurs en mode rebond)
sftp -P 2222 julien%web-01@bastion      # fichiers (mode coffre, si la règle autorise SFTP)
```

Le code TOTP doit avoir été enrôlé avant, dans Portunia ou avec `sudo heimdia user totp julien`.

## Administrer en ligne de commande

Tout se fait aussi depuis Portunia. Sur le serveur, l'assistant installe la commande `heimdia`, qui s'utilise avec sudo depuis n'importe quel dossier :

```bash
# Informations
sudo heimdia info                                            # version, empreintes, comptes

# Comptes
sudo heimdia user add marc --provisoire                      # mot de passe provisoire, code enrôlé dans Portunia
sudo heimdia user add marc                                   # mot de passe et code saisis ici
sudo heimdia user add presta --policy "key+totp"             # clé SSH et code obligatoires
sudo heimdia user key marc "ssh-ed25519 AAAA… marc@pc"
sudo heimdia user role marc auditor                          # user, auditor (relecture et journal) ou admin
sudo heimdia user list | passwd marc | totp marc | disable marc | delete marc

# Groupes
sudo heimdia group add "Admins Linux"
sudo heimdia group member "Admins Linux" marc julien

# Serveurs
sudo heimdia target add web-01 --host 10.0.1.11 --mode coffre --account admin --password --folder Production
sudo heimdia target add rec-app --host 10.0.2.5 --mode enregistre --folder Recette
sudo heimdia target add fw-edge --host 10.0.0.1 --mode rebond --folder Réseau
sudo heimdia target add srv-ad-01 --host 10.0.3.10 --protocol rdp --mode rebond --folder Windows
sudo heimdia target list

# Règles
sudo heimdia rule add prod --group "Admins Linux" --targets web-01,rec-app --sftp --days lun-ven --hours 7-20
sudo heimdia rule add presta-db --group Prestataires --targets db-01 --expires 2026-12-31

# Réglages
sudo heimdia setting auth_policy "password+totp,key+totp"    # politique générale
sudo heimdia setting banniere "Accès réservé. Les sessions sont enregistrées."
sudo heimdia setting nom "Bastion ACME"

# Contrôle
sudo heimdia audit --verify --last 50
sudo heimdia sessions --last 20
```

`sudo heimdia --help` et `sudo heimdia user --help` listent toutes les options.

Voir aussi [docs/exploitation.md](docs/exploitation.md) : sauvegardes, mise à jour, journaux, dépannage.

## Feuille de route

1. **Socle** : proxy SSH, trois modes, coffre, comptes et TOTP, droits, enregistrement signé, journal chaîné, Docker Compose.
2. **Intégration Portunia** : API, ajout du bastion dans Portunia, serveurs dans la barre latérale, jetons à usage unique, première connexion, administration complète, clé générée et installée sur les serveurs du coffre. Assistant d'installation (0.3), paquet Debian (0.4).
3. **Audit** : relecture et recherche (0.5), vue en direct et coupure, vidéo MP4 à la demande, lecteur détachable, conservation réglable avec estimation du disque, syslog et CSV.
4. **Bureau à distance** : rebond (0.6), enregistré avec enregistrement signé (0.8), puis relecture, coffre (le bastion ouvre la session Windows avec le compte du coffre), règles (presse-papiers, son).
5. **Portail web** : SSH (0.7) et Bureau à distance (0.8) dans le navigateur derrière Cloudflare, puis clés d'accès (passkeys), personnalisation.
6. **Exploitation** : sauvegarde intégrée, dépôt apt pour les mises à jour, paquet ARM, imports (Portunia, CSV), console web activable.
7. **Console maître** : un Heimdia central pour les prestataires, des relais chez les clients.
