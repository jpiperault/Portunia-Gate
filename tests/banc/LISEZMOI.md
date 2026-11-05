# Banc d'essai de Portunia Gate

Une Gate de test sur un LXC dédié, un Windows Server de test, et `recette.py` qui vérifie de
bout en bout ce qui se vérifie sans écran. Le reste se coche dans `docs/plan-de-test.html`
(dépôt de Portunia). Jamais sur la Gate de production.

## Machines

**LXC de la Gate** (Proxmox) : Debian 12, 2 cœurs, 2 Go de mémoire, 16 Go de disque, adresse
fixe, conteneur non privilégié suffisant (paquet .deb, pas de Docker). Clé publique du banc
dans `/root/.ssh/authorized_keys`.

**Windows Server 2022 d'évaluation** (VM Proxmox) : 2 cœurs, 4 Go, adresse fixe.

- Bureau à distance activé, avec NLA exigé (réglage par défaut).
- Un compte local de test, membre de « Utilisateurs du Bureau à distance » (et des
  administrateurs si l'OpenSSH ci-dessous doit pouvoir changer des réglages).
- Facultatif, pour les essais SSH et SFTP : la fonctionnalité « Serveur OpenSSH » démarrée
  (`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`, puis
  `Start-Service sshd; Set-Service sshd -StartupType Automatic`).
- Le pare-feu laisse entrer 3389 (et 22) depuis le LXC.

## Préparer le LXC

```bash
apt update && apt install -y curl python3 xvfb sshpass openssh-client freerdp2-x11
curl -fsSLO https://github.com/jpiperault/Portunia-Gate-releases/releases/latest/download/installer.sh
bash installer.sh            # paquet .deb, répondre aux questions
install -d -m 700 /root/.banc
printf '%s\n' 'MOT_DE_PASSE_WINDOWS' > /root/.banc/windows && chmod 600 /root/.banc/windows
```

## Lancer la recette

```bash
python3 recette.py --windows 10.0.0.60 --win-user banc --win-password-file /root/.banc/windows \
  --windows-ssh --web 10.0.0.40:8006
```

`--only rdp,ssh,web` pour une partie seulement. Le script crée ou recrée ses comptes
(`banc-admin`, `banc-user`, mots de passe et codes TOTP gardés dans `/root/.banc/etat.json`),
le groupe `banc-groupe`, les serveurs `banc-*` et la règle `banc-regle`, ouvre l'entrée RDP
native, puis lit les résultats dans l'API (sessions, journal). Rapport :
`/root/.banc/rapport-AAAAMMJJ-HHMM.json`. Code de sortie 1 au premier échec constaté.
