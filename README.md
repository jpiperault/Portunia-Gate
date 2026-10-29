# Heimdia

Bastion SSH de [Portunia](https://github.com/jpiperault/Portunia) : les utilisateurs passent par Heimdia pour atteindre les serveurs ; Heimdia vérifie qui ils sont, décide où ils peuvent aller, fournit si besoin le compte du serveur sans le leur montrer, enregistre les sessions et trace tout dans un journal infalsifiable.

> État : **étape 2, intégration dans Portunia**. La relecture et la vue en direct arrivent à l'étape 3 (voir [Feuille de route](#feuille-de-route)).

## Ce que fait le socle

| | |
|---|---|
| **Trois modes par serveur** | **Rebond** : relais de bout en bout (`ssh -J`), le bastion ne voit pas le contenu, il journalise la connexion. **Enregistré** : le bastion relaie et enregistre la session ; l'utilisateur tape ses propres identifiants. **Coffre** : comme Enregistré, et le bastion fournit le compte du serveur, que l'utilisateur ne connaît jamais. |
| **Connexion au bastion** | Mot de passe, clé SSH et code TOTP (Google Authenticator, Microsoft Authenticator…), combinables au choix : politique générale et politique par compte. Un code ne sert qu'une fois. |
| **Droits** | Des règles relient un groupe à des serveurs, avec jours, heures, date d'expiration, SFTP et tunnels autorisés ou non. Tout ce qui n'est pas permis est refusé. |
| **Enregistrement** | Format asciicast (lisible par Portunia et asciinema), affichage seul ou aussi la frappe selon la règle. Chaque fichier est signé par le bastion. |
| **Journal d'audit** | Connexions, échecs, sessions, changements d'administration. Chaque événement contient l'empreinte du précédent : une ligne supprimée ou modifiée se voit (`heimdia audit --verify`). |
| **Clients** | N'importe quel client SSH : OpenSSH, PuTTY, MobaXterm, WinSCP (SFTP). |
| **Portunia** | Extension Heimdia : le bastion s'ajoute dans la barre latérale (empreinte du certificat vérifiée, mot de passe et code), ses serveurs s'ouvrent avec un jeton à usage unique, et les administrateurs gèrent tout depuis Portunia (serveurs et coffre, comptes, groupes, règles, journal, sessions, réglages). |
| **Première connexion** | Un compte créé par l'administrateur reçoit un mot de passe provisoire ; à sa première connexion dans Portunia, l'utilisateur le change puis enrôle lui-même son code par code QR. |

## Installer

Prérequis : un serveur Linux avec Docker et Docker Compose (2 vCPU, 4 Go de RAM et 40 Go de disque pour une petite équipe). Dans un container LXC Proxmox, activez les options *nesting* et *keyctl*.

```bash
git clone https://github.com/jpiperault/Heimdia.git && cd Heimdia
cp .env.example .env
sed -i "s|^HEIMDIA_DB_PASSWORD=.*|HEIMDIA_DB_PASSWORD=$(openssl rand -hex 24)|" .env
docker compose build
docker compose run --rm heimdia init      # clés, base, compte administrateur et son code TOTP
docker compose up -d
```

Ports : **2222** (SSH) et **8443** (API HTTPS pour Portunia), modifiables dans `.env`. Le certificat de l'API est auto-signé ; Portunia le reconnaît par son empreinte. Pour un certificat d'entreprise, indiquez `HEIMDIA_TLS_CERT` et `HEIMDIA_TLS_KEY` (fichiers PEM).

`init` affiche l'empreinte SSH du bastion et celle du certificat de l'API : notez-les, les utilisateurs les compareront à leur première connexion.

**Sauvegardez tout de suite la clé du coffre** hors du serveur. Sans elle, les secrets des serveurs et les codes TOTP sont perdus :

```bash
docker compose cp heimdia:/var/lib/heimdia/coffre.key ./coffre.key   # puis rangez ce fichier en lieu sûr
```

## Se connecter

```bash
ssh -p 2222 julien@bastion              # menu des serveurs autorisés
ssh -p 2222 julien%web-01@bastion       # directement sur web-01
ssh -J julien@bastion:2222 admin@fw-01  # rebond de bout en bout (serveurs en mode rebond)
sftp -P 2222 julien%web-01@bastion      # fichiers (mode coffre, si la règle autorise SFTP)
```

## Administrer

Les commandes s'exécutent sur le serveur du bastion : `docker compose exec heimdia heimdia <commande>`.

```bash
# Comptes
heimdia user add marc                                   # mot de passe, puis code TOTP à scanner
heimdia user add presta --policy "key+totp"             # clé SSH et code obligatoires
heimdia user key marc "ssh-ed25519 AAAA… marc@pc"
heimdia user list | passwd marc | totp marc | disable marc

# Groupes
heimdia group add "Admins Linux"
heimdia group member "Admins Linux" marc julien

# Serveurs
heimdia target add web-01 --host 10.0.1.11 --mode coffre --account admin --password --folder Production
heimdia target add rec-app --host 10.0.2.5 --mode enregistre --folder Recette
heimdia target add fw-edge --host 10.0.0.1 --mode rebond --folder Réseau
heimdia target list

# Règles
heimdia rule add prod --group "Admins Linux" --targets web-01,rec-app --sftp --days lun-ven --hours 7-20
heimdia rule add presta-db --group Prestataires --targets db-01 --expires 2026-12-31

# Réglages
heimdia setting auth_policy "password+totp,key+totp"    # politique générale
heimdia setting banniere "Accès réservé. Les sessions sont enregistrées."
heimdia setting nom "Bastion ACME"

# Contrôle
heimdia audit --verify --last 50
heimdia sessions --last 20
```

Voir aussi [docs/exploitation.md](docs/exploitation.md) : sauvegardes, mise à jour, journaux, dépannage.

## Feuille de route

1. **Socle** : proxy SSH, trois modes, coffre, comptes et TOTP, droits, enregistrement signé, journal chaîné, Docker Compose.
2. **Intégration Portunia** (cette version) : API, ajout du bastion dans Portunia, serveurs dans la barre latérale, jetons à usage unique, première connexion, administration complète, clé générée et installée sur les serveurs du coffre.
3. **Audit** : relecture et recherche, vue en direct et coupure, conservation réglable avec estimation du disque, syslog et CSV.
4. **Exploitation** : sauvegarde intégrée, imports (Portunia, CSV), console web activable.
5. **Console maître** : un Heimdia central pour les prestataires, des relais chez les clients.
