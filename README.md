# Heimdia

Bastion SSH de [Portunia](https://github.com/jpiperault/Portunia) : les utilisateurs passent par Heimdia pour atteindre les serveurs ; Heimdia vérifie qui ils sont, décide où ils peuvent aller, fournit si besoin le compte du serveur sans le leur montrer, enregistre les sessions et trace tout dans un journal infalsifiable.

> État : **version 0.4, paquet Debian et assistant d'installation**. La relecture et la vue en direct arrivent à l'étape 3 (voir [Feuille de route](#feuille-de-route)).

## Ce que fait Heimdia

| | |
|---|---|
| **Trois modes par serveur** | **Rebond** : relais de bout en bout (`ssh -J`), le bastion ne voit pas le contenu, il journalise la connexion. **Enregistré** : le bastion relaie et enregistre la session ; l'utilisateur tape ses propres identifiants. **Coffre** : comme Enregistré, et le bastion fournit le compte du serveur, que l'utilisateur ne connaît jamais. |
| **Connexion au bastion** | Mot de passe, clé SSH et code TOTP (Google Authenticator, Microsoft Authenticator…), combinables au choix : politique générale et politique par compte. Un code ne sert qu'une fois. |
| **Droits** | Des règles relient un groupe à des serveurs, avec jours, heures, date d'expiration, SFTP et tunnels autorisés ou non. Tout ce qui n'est pas permis est refusé. |
| **Enregistrement** | Format asciicast (lisible par Portunia et asciinema), affichage seul ou aussi la frappe selon la règle. Chaque fichier est signé par le bastion. |
| **Journal d'audit** | Connexions, échecs, sessions, changements d'administration. Chaque événement contient l'empreinte du précédent : une ligne supprimée ou modifiée se voit (`heimdia audit --verify`). |
| **Portunia** | Extension Heimdia : le bastion s'ajoute dans la barre latérale, ses serveurs s'ouvrent avec un jeton à usage unique, et les administrateurs gèrent tout depuis Portunia (serveurs et coffre, comptes, groupes, règles, journal, sessions, réglages). |
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
7. **Administrer** (Portunia Équipes, compte administrateur) : menu **⋯** du bastion › **Administrer**. Un onglet s'ouvre avec les serveurs et le coffre, les comptes, les groupes, les règles, le journal, les sessions et les réglages.

Les comptes suivants se créent depuis cet onglet : Portunia affiche un mot de passe provisoire à transmettre à l'utilisateur, qui suivra les étapes 2 à 5.

Rien ne s'affiche sous le bastion ? Aucune règle ne donne encore accès à un serveur : créez un serveur, un groupe contenant le compte, puis une règle qui les relie.

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
sudo heimdia user role marc admin                            # user, auditor (journal en lecture) ou admin
sudo heimdia user list | passwd marc | totp marc | disable marc | delete marc

# Groupes
sudo heimdia group add "Admins Linux"
sudo heimdia group member "Admins Linux" marc julien

# Serveurs
sudo heimdia target add web-01 --host 10.0.1.11 --mode coffre --account admin --password --folder Production
sudo heimdia target add rec-app --host 10.0.2.5 --mode enregistre --folder Recette
sudo heimdia target add fw-edge --host 10.0.0.1 --mode rebond --folder Réseau
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
3. **Audit** : relecture et recherche, vue en direct et coupure, conservation réglable avec estimation du disque, syslog et CSV.
4. **Exploitation** : sauvegarde intégrée, dépôt apt pour les mises à jour, paquet ARM, imports (Portunia, CSV), console web activable.
5. **Console maître** : un Heimdia central pour les prestataires, des relais chez les clients.
