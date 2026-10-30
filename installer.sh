#!/usr/bin/env bash
# Portunia Gate setup assistant (Debian 12/13, Ubuntu 22.04 and later).
# Assistant d'installation de Portunia Gate (Debian 12/13, Ubuntu 22.04 et suivantes).
#
#   ./installer.sh                     first install (Debian package), or menu if already installed
#   ./installer.sh --docker            first install with Docker (from a copy of the repository)
#   ./installer.sh --package FILE      installs this .deb file instead of downloading the latest version
#   ./installer.sh info                details to type in Portunia
#   ./installer.sh update              installs the latest version and restarts the Gate
#   ./installer.sh admin LOGIN         creates a backup administrator (temporary password)
#   ./installer.sh portal              installs Cloudflare Tunnel for the web portal (token asked)
#
# French names are kept: --paquet, mise-a-jour, portail.
# Messages are in French when the system's language is French (LANG=fr_…), in English otherwise;
# HEIMDIA_LANG=en or fr chooses.
#
# Without a terminal (automation), answers come from HEIMDIA_NOM, HEIMDIA_ADMIN, HEIMDIA_SSH_PORT,
# HEIMDIA_API_PORT and TZ, or the defaults.
set -euo pipefail

RELEASES=${HEIMDIA_RELEASES:-https://github.com/jpiperault/Heimdia-releases/releases/latest/download}
ENV_NATIVE=/etc/heimdia/heimdia.env
DOCKER_WRAPPER=/usr/local/bin/heimdia

SELF=$(readlink -f "$0")
DIR=$(dirname "$SELF")
cd "$DIR"

# Langue : HEIMDIA_LANG, sinon celle du système.
lang_of() {
  local v
  for v in "${HEIMDIA_LANG:-}" "${LC_ALL:-}" "${LC_MESSAGES:-}" "${LANG:-}"; do
    [ -n "$v" ] || continue
    case $v in fr*) echo fr ;; *) echo en ;; esac
    return
  done
  echo en
}
L=$(lang_of)
export HEIMDIA_LANG=$L
# t "English" "Français" : le texte dans la langue de l'assistant.
t() { if [ "$L" = fr ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

if [ -t 1 ]; then B=$'\e[1m' G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' D=$'\e[2m' N=$'\e[0m'; else B='' G='' Y='' R='' D='' N=''; fi
ok() { echo "  ${G}✓${N} $*"; }
step() { echo; echo "${B}$*${N}"; }
warn() { echo "  ${Y}!${N} $*"; }
die() { echo "  ${R}✗ $*${N}" >&2; exit 1; }
interactive() { [ -t 0 ]; }
# ask "Question" "défaut" : réponse sur la sortie standard.
ask() {
  local answer=''
  if interactive; then read -r -p "  $1 [${D}$2${N}]$(t ':' ' :') " answer; fi
  echo "${answer:-$2}"
}
confirm() {
  local answer=''
  interactive || return 0
  read -r -p "  $1 $(t '[Y/n]:' '[O/n] :') " answer
  [[ ! "$answer" =~ ^[nN] ]]
}

# ---------- Arguments ----------

ARGS=("$@")
MODE='' PACKAGE='' ACTION='' ACTION_ARG=''
while [ $# -gt 0 ]; do
  case $1 in
    --docker) MODE=docker ;;
    --package | --paquet) PACKAGE=$(readlink -f "${2:?$(t "$1 expects a .deb file" "$1 attend un fichier .deb")}"); shift ;;
    info | admin) ACTION=$1; ACTION_ARG=${2:-}; [ -z "$ACTION_ARG" ] || shift ;;
    update | mise-a-jour) ACTION=update ;;
    portal | portail) ACTION=portal ;;
    *) die "$(t "Usage: $0 [--docker] [--package FILE.deb] [info | update | admin LOGIN | portal]" "Usage : $0 [--docker] [--paquet FICHIER.deb] [info | mise-a-jour | admin IDENTIFIANT | portail]")" ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || die "$(t "Run the assistant as root." "Lancez l'assistant en root.")"
  exec sudo --preserve-env=HEIMDIA_NOM,HEIMDIA_ADMIN,HEIMDIA_SSH_PORT,HEIMDIA_API_PORT,TZ,HEIMDIA_RELEASES,HEIMDIA_TUNNEL_TOKEN,HEIMDIA_LANG -- "$SELF" "${ARGS[@]}"
fi
BACKUP_OWNER=${SUDO_USER:-root}

address() { hostname -I 2>/dev/null | awk '{print $1}'; }
container() { [ "$(systemd-detect-virt -c 2>/dev/null)" != none ]; }
port_busy() { ss -Hltn "sport = :$1" 2>/dev/null | grep -q .; }
compose() { docker compose "$@"; }

# Le service n'est activé qu'une fois l'initialisation réussie : sinon, l'installation est à reprendre.
installed_native() { [ -f "$ENV_NATIVE" ] && systemctl is-enabled --quiet heimdia 2>/dev/null; }
installed_docker() {
  [ -f .env ] && command -v docker >/dev/null && compose ps -a --format '{{.Service}}' 2>/dev/null | grep -qx heimdia
}

# Mode d'une installation existante, et ses réglages.
ENV_FILE=''
use_mode() {
  MODE=$1
  if [ "$MODE" = docker ]; then ENV_FILE=$DIR/.env; else ENV_FILE=$ENV_NATIVE; fi
}
env_value() { [ ! -f "$ENV_FILE" ] || sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1; }
# Commande d'administration de la Gate, quel que soit le mode, dans la langue de l'assistant.
hcmd() {
  if [ "$MODE" = docker ]; then compose exec -T -e HEIMDIA_LANG="$L" heimdia heimdia "$@"; else /usr/bin/heimdia "$@"; fi
}
# Valeurs lues dans la sortie de heimdia, en anglais comme en français.
fingerprint_of() { awk '/^(API certificate|Certificat de l)/{print $NF}'; }
password_of() { sed -n 's/.*\(Temporary password: \|Mot de passe provisoire : \)\([^ ]*\).*/\2/p'; }

# ---------- Prérequis ----------

check_system() {
  command -v apt-get >/dev/null || die "$(t "Unsupported distribution: Debian 12/13 or Ubuntu 22.04 and later." "Distribution non prise en charge : Debian 12/13 ou Ubuntu 22.04 et suivantes.")"
  [ -d /run/systemd/system ] || die "$(t "systemd is required." "systemd est nécessaire.")"
  local mem cpus disk os
  mem=$(awk '/^MemTotal/{print int($2/1024)}' /proc/meminfo)
  cpus=$(nproc)
  disk=$(df -Pm /var | awk 'NR==2{print int($4/1024)}')
  os=$(. /etc/os-release && echo "$PRETTY_NAME")
  ok "$(t "$os, $cpus CPU(s), $((mem / 1024)) GB of memory, $disk GB of free disk" "$os, $cpus processeur(s), $((mem / 1024)) Go de mémoire, $disk Go de disque libre")"
  [ "$disk" -ge 5 ] || warn "$(t "Less than 5 GB free: little room for session recordings." "Moins de 5 Go libres : peu de place pour les enregistrements des sessions.")"
  [ "$mem" -ge 900 ] || warn "$(t "Less than 1 GB of memory: Portunia Gate and PostgreSQL will be cramped." "Moins de 1 Go de mémoire : Portunia Gate et PostgreSQL seront à l'étroit.")"
}

install_docker() {
  confirm "$(t "Docker is not installed. Install it from the distribution's packages?" "Docker n'est pas installé. L'installer depuis les paquets de la distribution ?")" ||
    die "$(t "Docker is required in Docker mode." "Docker est nécessaire en mode Docker.")"
  apt-get update -qq
  local pkgs=(docker.io)
  for p in docker-buildx docker-compose-v2; do apt-cache show "$p" >/dev/null 2>&1 && pkgs+=("$p"); done
  [[ " ${pkgs[*]} " == *docker-compose-v2* ]] || pkgs+=(docker-compose)
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" >/dev/null
  systemctl enable --now docker >/dev/null 2>&1 || true
  docker compose version >/dev/null 2>&1 ||
    die "$(t "Docker Compose v2 is missing from this distribution's packages: install Docker from https://docs.docker.com/engine/install/ then run again." "Docker Compose v2 manque dans les paquets de cette distribution : installez Docker depuis https://docs.docker.com/engine/install/ puis relancez.")"
  ok "$(t "Docker installed" "Docker installé") ($(docker --version | awk '{print $3}' | tr -d ,))"
}

check_docker() {
  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || t present présent), Compose $(docker compose version --short 2>/dev/null)"
  else
    install_docker
  fi
  if ! docker info >/dev/null 2>&1; then
    if [ "$(systemd-detect-virt -c 2>/dev/null)" = lxc ]; then
      die "$(t "Docker does not start. In a Proxmox LXC container, enable the nesting and keyctl options, restart the container and run again." "Docker ne démarre pas. Dans un container LXC Proxmox, activez les options nesting et keyctl, redémarrez le container et relancez.")"
    fi
    die "$(t "Docker is not answering: systemctl status docker" "Docker ne répond pas : systemctl status docker")"
  fi
}

# Mode Docker : la compilation a besoin de mémoire ; fichier d'échange temporaire si elle manque.
SWAPFILE=''
check_build_memory() {
  local mem swap
  mem=$(awk '/^MemTotal/{print int($2/1024)}' /proc/meminfo)
  swap=$(awk '/^SwapTotal/{print int($2/1024)}' /proc/meminfo)
  [ "$(nproc)" -ge 2 ] || warn "$(t "A single CPU: the build will take 20 to 30 minutes." "Un seul processeur : la compilation prendra 20 à 30 minutes.")"
  [ $((mem + swap)) -lt 3500 ] || return 0
  warn "$(t "Low memory for the build (about 3.5 GB needed, memory and swap included)." "Mémoire faible pour compiler (il faut environ 3,5 Go, mémoire et échange compris).")"
  if ! container && confirm "$(t "Add a 2 GB swap file for the duration of the build?" "Ajouter un fichier d'échange de 2 Go le temps de la compilation ?")"; then
    SWAPFILE=/heimdia-compilation.swap
    if fallocate -l 2G "$SWAPFILE" && chmod 600 "$SWAPFILE" && mkswap -q "$SWAPFILE" && swapon "$SWAPFILE"; then
      ok "$(t "Temporary swap file added" "Fichier d'échange temporaire ajouté")"
    else
      warn "$(t "Cannot add the swap file" "Impossible d'ajouter le fichier d'échange")"; rm -f "$SWAPFILE"; SWAPFILE=''
    fi
  fi
}
remove_swap() {
  if [ -n "$SWAPFILE" ]; then swapoff "$SWAPFILE" 2>/dev/null || true; rm -f "$SWAPFILE"; SWAPFILE=''; fi
}
trap remove_swap EXIT

# ---------- Paquet Debian ----------

fetch() {
  if command -v curl >/dev/null; then curl -fsSL -o "$2" "$1"; else wget -q -O "$2" "$1"; fi
}

# Installe (ou met à jour) le paquet : fichier fourni, ou dernière version publiée.
install_package() {
  [ "$(dpkg --print-architecture)" = amd64 ] || die "$(t "Package available for amd64 only: use --docker." "Paquet disponible pour amd64 uniquement : utilisez --docker.")"
  local work deb
  work=$(mktemp -d)
  chmod 755 "$work"
  if [ -n "$PACKAGE" ]; then
    [ -f "$PACKAGE" ] || die "$(t "File not found: $PACKAGE" "Fichier introuvable : $PACKAGE")"
    deb=$work/$(basename "$PACKAGE")
    cp "$PACKAGE" "$deb"
  else
    command -v curl >/dev/null || command -v wget >/dev/null || { apt-get update -qq; apt-get install -y -qq curl >/dev/null; }
    deb=$work/heimdia_amd64.deb
    fetch "$RELEASES/heimdia_amd64.deb" "$deb" || die "$(t "Download failed:" "Téléchargement impossible :") $RELEASES/heimdia_amd64.deb"
    fetch "$RELEASES/SHA256SUMS" "$work/SHA256SUMS" || die "$(t "Download failed:" "Téléchargement impossible :") $RELEASES/SHA256SUMS"
    (cd "$work" && grep ' heimdia_amd64.deb$' SHA256SUMS | sha256sum -c --quiet -) ||
      die "$(t "The downloaded package is altered (different SHA-256 checksum)." "Le paquet téléchargé est altéré (empreinte SHA-256 différente).")"
    ok "$(t "Package downloaded and checked" "Paquet téléchargé et vérifié")"
  fi
  chmod 644 "$deb"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$deb" postgresql >/dev/null 2>"$work/apt.log" ||
    { cat "$work/apt.log" >&2; die "$(t "Cannot install the package." "Installation du paquet impossible.")"; }
  rm -rf "$work"
  local v pgv
  v=$(dpkg-query -W -f '${Version}' heimdia)
  pgv=$(pg_lsclusters -h 2>/dev/null | awk 'NR==1{print $1}')
  ok "$(t "Portunia Gate $v and PostgreSQL $pgv installed" "Portunia Gate $v et PostgreSQL $pgv installés")"
}

# Base PostgreSQL locale, sans mot de passe : le compte de service _heimdia s'y connecte par socket.
pg() { (cd / && runuser -u postgres -- "$@"); }
prepare_database() {
  systemctl enable --now postgresql >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do pg psql -qtAc 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
  pg psql -qtAc "SELECT 1 FROM pg_roles WHERE rolname = '_heimdia'" | grep -q 1 || pg createuser _heimdia
  pg psql -qtAc "SELECT 1 FROM pg_database WHERE datname = 'heimdia'" | grep -q 1 || pg createdb -O _heimdia heimdia
  ok "$(t "PostgreSQL database « heimdia » ready" "Base PostgreSQL « heimdia » prête")"
}

# ---------- Étapes communes ----------

build_image() {
  step "$(t "Building Portunia Gate" "Compilation de Portunia Gate") ${D}$(t "(10 to 30 minutes the first time)" "(10 à 30 minutes la première fois)")${N}"
  compose build || die "$(t "The build failed. Out of memory? See docs/operations.md, Troubleshooting section." "La compilation a échoué. Manque de mémoire ? Voir docs/exploitation.fr.md, section Dépannage.")"
  remove_swap
  ok "$(t "Image built" "Image construite")"
}

install_docker_wrapper() {
  cat >"$DOCKER_WRAPPER" <<EOF
#!/bin/sh
# Commande heimdia du serveur : relaie vers la Gate dans son conteneur ($DIR).
# Installée par installer.sh. .env (mot de passe de la base) n'est lisible que par root.
if [ "\$(id -u)" -ne 0 ]; then exec sudo -- "\$0" "\$@"; fi
cd "$DIR" || exit 1
# Messages dans la langue de qui tape la commande.
case "\${HEIMDIA_LANG:-\${LC_ALL:-\${LC_MESSAGES:-\${LANG:-}}}}" in fr*) lang=fr ;; *) lang=en ;; esac
if ! docker compose ps --status running --format '{{.Service}}' | grep -qx heimdia; then
  if [ "\$lang" = fr ]; then
    echo "La Gate est arrêté. Démarrez-le : cd $DIR && docker compose up -d" >&2
  else
    echo "The Gate is stopped. Start it: cd $DIR && docker compose up -d" >&2
  fi
  exit 1
fi
if [ -t 0 ]; then exec docker compose exec -e HEIMDIA_LANG=\$lang heimdia heimdia "\$@"; fi
exec docker compose exec -T -e HEIMDIA_LANG=\$lang heimdia heimdia "\$@"
EOF
  chmod 755 "$DOCKER_WRAPPER"
}

# Copie de la clé du coffre au nom de celui qui a lancé sudo, à récupérer par scp.
BACKUP=''
save_vault_key() {
  local home
  home=$(getent passwd "$BACKUP_OWNER" | cut -d: -f6)
  BACKUP=${home:-/root}/heimdia-coffre.key
  if [ "$MODE" = docker ]; then
    compose cp heimdia:/var/lib/heimdia/coffre.key "$BACKUP" >/dev/null 2>&1 || die "$(t "Cannot copy the vault key." "Copie de la clé du coffre impossible.")"
  else
    cp /var/lib/heimdia/coffre.key "$BACKUP"
  fi
  chown "$BACKUP_OWNER" "$BACKUP"
  chmod 600 "$BACKUP"
}

wait_api() {
  local port
  port=$(env_value HEIMDIA_API_PORT)
  for _ in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port:-8443}") 2>/dev/null; then return 0; fi
    sleep 1
  done
  if [ "$MODE" = docker ]; then
    die "$(t "The Gate is not answering on port ${port:-8443}: docker compose logs heimdia" "La Gate ne répond pas sur le port ${port:-8443} : docker compose logs heimdia")"
  fi
  journalctl -u heimdia -n 15 --no-pager >&2 || true
  die "$(t "The Gate is not answering on port ${port:-8443}: journalctl -u heimdia" "La Gate ne répond pas sur le port ${port:-8443} : journalctl -u heimdia")"
}

open_firewall() {
  local ssh_port=$1 api_port=$2
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
    if confirm "$(t "The ufw firewall is active. Open ports $ssh_port and $api_port?" "Le pare-feu ufw est actif. Ouvrir les ports $ssh_port et $api_port ?")"; then
      ufw allow "$ssh_port/tcp" >/dev/null && ufw allow "$api_port/tcp" >/dev/null && ok "$(t "Ports opened in ufw" "Ports ouverts dans ufw")"
    fi
  fi
}

# Ce qu'il faut saisir dans Portunia.
summary() {
  local login=${1:-} password=${2:-} fingerprint api_port ssh_port addr
  fingerprint=$(hcmd info | fingerprint_of)
  api_port=$(env_value HEIMDIA_API_PORT)
  ssh_port=$(env_value HEIMDIA_SSH_PORT)
  addr=$(address)
  [ "${api_port:-8443}" = 8443 ] || addr="$addr:$api_port"
  echo
  echo "  ┌──────────────────────────────────────────────────────────────────────────"
  if [ "$L" = fr ]; then
    echo "  │ ${B}Dans Portunia${N} : Extensions › activer Portunia Gate, puis Gates › Ajouter une Gate"
    echo "  │"
    echo "  │   Adresse      ${B}$addr${N}"
    echo "  │   Empreinte    ${B}$fingerprint${N}"
    if [ -n "$login" ]; then
      echo "  │   Identifiant  ${B}$login${N}"
      echo "  │   Mot de passe ${B}$password${N}  ${D}(provisoire)${N}"
      echo "  │"
      echo "  │ Portunia vous fera choisir votre mot de passe, puis scanner le code QR"
      echo "  │ avec votre application d'authentification. Laissez le champ Code vide."
    fi
    echo "  │"
    echo "  │ Accès SSH direct : ssh -p ${ssh_port:-2222} <identifiant>@$(address)"
  else
    echo "  │ ${B}In Portunia${N}: Extensions › enable Portunia Gate, then Gates › Add a Gate"
    echo "  │"
    echo "  │   Address      ${B}$addr${N}"
    echo "  │   Fingerprint  ${B}$fingerprint${N}"
    if [ -n "$login" ]; then
      echo "  │   Login        ${B}$login${N}"
      echo "  │   Password     ${B}$password${N}  ${D}(temporary)${N}"
      echo "  │"
      echo "  │ Portunia will have you choose your password, then scan the QR code"
      echo "  │ with your authenticator app. Leave the Code field empty."
    fi
    echo "  │"
    echo "  │ Direct SSH access: ssh -p ${ssh_port:-2222} <login>@$(address)"
  fi
  echo "  └──────────────────────────────────────────────────────────────────────────"
}

# ---------- Première installation ----------

questions() {
  step "$(t "Configuration" "Configuration") ${D}$(t "(Enter keeps the suggested value)" "(Entrée pour garder la valeur proposée)")${N}"
  # Installation interrompue : on reprend ses réglages.
  HEIMDIA_SSH_PORT=${HEIMDIA_SSH_PORT:-$(env_value HEIMDIA_SSH_PORT)}
  HEIMDIA_API_PORT=${HEIMDIA_API_PORT:-$(env_value HEIMDIA_API_PORT)}
  TZ=${TZ:-$(env_value TZ)}
  NOM=$(ask "$(t "Gate name, shown in Portunia" "Nom de la Gate, affiché dans Portunia")" "${HEIMDIA_NOM:-Portunia Gate}")
  while :; do
    ADMIN=$(ask "$(t "Administrator login" "Identifiant de l'administrateur")" "${HEIMDIA_ADMIN:-admin}")
    [[ "$ADMIN" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] && break
    warn "$(t "Lowercase letters, digits, dot, hyphen or underscore (32 characters at most)." "Lettres minuscules, chiffres, point, tiret ou souligné (32 caractères au plus).")"
    interactive || die "$(t "Invalid login: $ADMIN" "Identifiant invalide : $ADMIN")"
  done
  while :; do
    SSH_PORT=$(ask "$(t "Gate SSH port" "Port SSH de la Gate")" "${HEIMDIA_SSH_PORT:-2222}")
    port_busy "$SSH_PORT" || break
    warn "$(t "Port $SSH_PORT is already used on this server." "Le port $SSH_PORT est déjà utilisé sur ce serveur.")"
    interactive || die "$(t "Port $SSH_PORT in use" "Port $SSH_PORT occupé")"
  done
  while :; do
    API_PORT=$(ask "$(t "API port for Portunia" "Port de l'API pour Portunia")" "${HEIMDIA_API_PORT:-8443}")
    [ "$API_PORT" != "$SSH_PORT" ] || { warn "$(t "Choose a port different from the SSH port." "Choisissez un port différent du port SSH.")"; interactive || die "$(t "Same ports" "Ports identiques")"; continue; }
    port_busy "$API_PORT" || break
    warn "$(t "Port $API_PORT is already used on this server." "Le port $API_PORT est déjà utilisé sur ce serveur.")"
    interactive || die "$(t "Port $API_PORT in use" "Port $API_PORT occupé")"
  done
  local tz
  tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || true)
  ZONE=$(ask "$(t "Time zone of the access rules" "Fuseau horaire des règles d'accès")" "${TZ:-${tz:-Europe/Paris}}")
}

# Initialisation : clés, certificat, base et administrateur au mot de passe provisoire.
initialize() {
  local out
  out=$(hcmd_init 2>&1) || { echo "$out"; die "$(t "Initialisation failed." "Échec de l'initialisation.")"; }
  PASSWORD=$(password_of <<<"$out")
  ok "$(t "Keys, certificate and database created" "Clés, certificat et base créés")"
  if [ -n "$PASSWORD" ]; then
    ok "$(t "Administrator account $ADMIN created" "Compte administrateur $ADMIN créé")"
  else
    warn "$(t "An administrator already existed (previous install): no account created." "Un administrateur existait déjà (installation précédente) : aucun compte créé.")"
    warn "$(t "If needed, create another one: sudo ./installer.sh admin <login>" "Au besoin, créez-en un autre : sudo ./installer.sh admin <identifiant>")"
    ADMIN=''
  fi
}
hcmd_init() {
  if [ "$MODE" = docker ]; then
    compose run --rm -T -e HEIMDIA_LANG="$L" heimdia init --admin "$ADMIN" --temporary --name "$NOM"
  else
    /usr/bin/heimdia init --admin "$ADMIN" --temporary --name "$NOM"
  fi
}

finish() {
  save_vault_key
  open_firewall "$SSH_PORT" "$API_PORT"
  summary "$ADMIN" "$PASSWORD"
  echo
  if [ "$L" = fr ]; then
    echo "  ${Y}${B}À faire maintenant :${N} copiez la clé du coffre hors du serveur, puis effacez cette copie."
    echo "  Sans elle, une restauration perd les secrets des serveurs et les codes."
    echo "    depuis votre poste : scp $BACKUP_OWNER@$(address):$BACKUP ."
    echo "    puis sur le serveur : rm $BACKUP"
  else
    echo "  ${Y}${B}Do it now:${N} copy the vault key off the server, then delete this copy."
    echo "  Without it, a restore loses the servers' secrets and the codes."
    echo "    from your computer: scp $BACKUP_OWNER@$(address):$BACKUP ."
    echo "    then on the server: rm $BACKUP"
  fi
  echo
}

install_native() {
  use_mode paquet
  echo "${B}$(t "Portunia Gate — installation" "Portunia Gate — installation")${N} ${D}$(t "(Debian package)" "(paquet Debian)")${N}"
  step "$(t "Checks" "Vérifications")"
  check_system
  questions

  step "$(t "Installation" "Installation")"
  install_package
  prepare_database
  (
    umask 027
    cat >"$ENV_NATIVE" <<EOF
# Réglages de Portunia Gate, créés par installer.sh. Après modification : sudo systemctl restart heimdia
# Portunia Gate settings, created by installer.sh. After a change: sudo systemctl restart heimdia
HEIMDIA_DATABASE_URL=postgres://_heimdia@localhost/heimdia?host=/var/run/postgresql
HEIMDIA_SSH_PORT=$SSH_PORT
HEIMDIA_API_PORT=$API_PORT
TZ=$ZONE
EOF
  )
  chgrp _heimdia "$ENV_NATIVE"
  ok "$(t "Settings saved in $ENV_NATIVE" "Réglages enregistrés dans $ENV_NATIVE")"
  initialize
  set_language
  systemctl enable --now heimdia >/dev/null 2>&1 || true
  wait_api
  ok "$(t "Gate started (heimdia service, restarts with the server)" "Gate démarré (service heimdia, redémarre seul avec le serveur)")"
  finish
}

# La Gate parle la langue de l'assistant (modifiable ensuite dans Portunia, Administrer › Réglages).
set_language() {
  if [ "$MODE" = docker ]; then
    compose run --rm -T -e HEIMDIA_LANG="$L" heimdia setting language "$L" >/dev/null
  else
    /usr/bin/heimdia setting language "$L" >/dev/null
  fi
}

install_with_docker() {
  use_mode docker
  [ -f "$DIR/Dockerfile" ] || die "$(t "Docker mode runs from a copy of the repository: git clone https://github.com/jpiperault/Heimdia.git" "Le mode Docker s'utilise depuis une copie du dépôt : git clone https://github.com/jpiperault/Heimdia.git")"
  echo "${B}$(t "Portunia Gate — installation" "Portunia Gate — installation")${N} ${D}(Docker, $DIR)${N}"
  step "$(t "Checks" "Vérifications")"
  check_system
  check_docker
  check_build_memory
  questions
  local db_password
  db_password=$(env_value HEIMDIA_DB_PASSWORD)
  (
    umask 077
    cat >.env <<EOF
# Créé par installer.sh le $(date '+%d/%m/%Y'). Modifiez puis : docker compose up -d
# Created by installer.sh on $(date '+%Y-%m-%d'). Change then: docker compose up -d
HEIMDIA_DB_PASSWORD=${db_password:-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')}
HEIMDIA_SSH_PORT=$SSH_PORT
HEIMDIA_API_PORT=$API_PORT
TZ=$ZONE
EOF
  )
  ok "$(t "Settings saved in .env (database password generated)" "Réglages enregistrés dans .env (mot de passe de la base généré)")"
  build_image
  step "$(t "Preparing the Gate" "Préparation de la Gate")"
  initialize
  set_language
  local out
  out=$(compose up -d 2>&1) || { echo "$out"; die "$(t "The Gate does not start." "La Gate ne démarre pas.")"; }
  wait_api
  ok "$(t "Gate started (restarts with the server)" "Gate démarré (redémarre seul avec le serveur)")"
  install_docker_wrapper
  ok "$(t "Command ${B}heimdia${N} installed (e.g. sudo heimdia user list)" "Commande ${B}heimdia${N} installée (ex. sudo heimdia user list)")"
  finish
}

# ---------- Gate déjà installé ----------

update() {
  echo "${B}$(t "Portunia Gate — update" "Portunia Gate — mise à jour")${N}"
  warn "$(t "The Gate restarts at the end: open sessions will be cut." "La Gate redémarre à la fin : les sessions ouvertes seront coupées.")"
  confirm "$(t "Continue?" "Continuer ?")" || exit 0
  local before
  before=$(hcmd info | sed -n 1p)
  if [ "$MODE" = docker ]; then
    if [ -d .git ]; then
      step "$(t "Fetching the latest version" "Récupération de la dernière version")"
      sudo -u "$(stat -c %U .)" git pull --ff-only || die "$(t "git pull failed." "git pull a échoué.")"
    fi
    check_build_memory
    build_image
    local out
    out=$(compose up -d 2>&1) || { echo "$out"; die "$(t "The Gate does not restart." "La Gate ne redémarre pas.")"; }
    install_docker_wrapper
  else
    install_package   # le paquet redémarre le service
  fi
  wait_api
  ok "$(t "Before:" "Avant :") $before"
  ok "$(t "After:" "Après :") $(hcmd info | sed -n 1p)"
}

add_admin() {
  local login=${1:-} out
  [ -n "$login" ] || login=$(ask "$(t "Login of the new administrator" "Identifiant du nouvel administrateur")" "")
  [ -n "$login" ] || die "$(t "Login missing." "Identifiant manquant.")"
  # --provisoire : compris aussi par les versions antérieures à --temporary.
  out=$(hcmd user add "$login" --role admin --provisoire 2>&1) || { echo "$out"; die "$(t "Account not created." "Compte non créé.")"; }
  summary "$login" "$(password_of <<<"$out")"
}

info() {
  hcmd info | sed 's/^/  /'
  summary
}

# ---------- Portail web (Cloudflare Tunnel) ----------

# Remplace ou ajoute un réglage du fichier .env (mode Docker).
set_env() {
  if grep -q "^$1=" "$ENV_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"; else echo "$1=$2" >>"$ENV_FILE"; fi
}

# cloudflared depuis le dépôt de Cloudflare (mis à jour avec le système).
install_cloudflared() {
  if command -v cloudflared >/dev/null; then ok "$(t "cloudflared already installed" "cloudflared déjà installé")"; return; fi
  install -d -m 755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg ||
    die "$(t "Cannot download the Cloudflare repository key." "Téléchargement de la clé du dépôt Cloudflare impossible.")"
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
    >/etc/apt/sources.list.d/cloudflared.list
  { apt-get update -qq && apt-get install -y -qq cloudflared; } >/dev/null || die "$(t "Cannot install cloudflared." "Installation de cloudflared impossible.")"
  ok "$(t "cloudflared installed (Cloudflare repository)" "cloudflared installé (dépôt Cloudflare)")"
}

# Tunnel sortant vers Cloudflare pour le portail web : aucun port entrant à ouvrir.
setup_portal() {
  echo "${B}$(t "Portunia Gate — web portal through Cloudflare Tunnel" "Portunia Gate — portail web par Cloudflare Tunnel")${N}"
  if [ "$L" = fr ]; then
    echo "  Dans Cloudflare Zero Trust › Networks › Tunnels, créez un tunnel « Cloudflared »,"
    echo "  puis copiez le jeton de sa commande d'installation (la longue suite après --token)."
  else
    echo "  In Cloudflare Zero Trust › Networks › Tunnels, create a « Cloudflared » tunnel,"
    echo "  then copy the token from its install command (the long string after --token)."
  fi
  local token=${HEIMDIA_TUNNEL_TOKEN:-} service
  if [ -z "$token" ] && interactive; then read -r -s -p "  $(t "Tunnel token:" "Jeton du tunnel :") " token; echo; fi
  token=$(tr -d '[:space:]' <<<"$token")
  [ -n "$token" ] || die "$(t "Tunnel token missing." "Jeton du tunnel manquant.")"
  [[ "$token" =~ ^[A-Za-z0-9+/=_-]+$ ]] || die "$(t "This does not look like a Cloudflare tunnel token." "Ce jeton ne ressemble pas à un jeton de tunnel Cloudflare.")"
  if [ "$MODE" = docker ]; then
    set_env HEIMDIA_TUNNEL_TOKEN "$token"
    set_env COMPOSE_PROFILES portail
    local out
    out=$(compose up -d 2>&1) || { echo "$out"; die "$(t "The tunnel does not start." "Le tunnel ne démarre pas.")"; }
    service=heimdia:8445
  else
    install_cloudflared
    cloudflared service uninstall >/dev/null 2>&1 || true
    cloudflared service install "$token" >/dev/null 2>&1 || die "$(t "Cannot install the cloudflared service." "Installation du service cloudflared impossible.")"
    service=localhost:8445
  fi
  ok "$(t "Tunnel installed: outgoing connection to Cloudflare, no port to open" "Tunnel installé : connexion sortante vers Cloudflare, aucun port à ouvrir")"
  echo
  if [ "$L" = fr ]; then
    echo "  Dans Cloudflare, onglet « Public Hostname » du tunnel : ajoutez votre adresse"
    echo "  (ex. acces.votre-domaine.fr), type ${B}HTTP${N}, URL ${B}$service${N}."
    echo "  Puis dans Portunia : Administrer › Portail web › activez le portail."
  else
    echo "  In Cloudflare, the tunnel's « Public Hostname » tab: add your address"
    echo "  (e.g. access.your-domain.com), type ${B}HTTP${N}, URL ${B}$service${N}."
    echo "  Then in Portunia: Administer › Web portal › enable the portal."
  fi
}

menu() {
  local where
  if [ "$MODE" = docker ]; then where="Docker, $DIR"; else where=$(t "Debian package" "paquet Debian"); fi
  echo "${B}$(t "Portunia Gate is already installed" "Portunia Gate est déjà installé")${N} ${D}($where)${N}"
  echo
  echo "  1) $(t "Show the details for Portunia" "Afficher les informations pour Portunia")"
  echo "  2) $(t "Update" "Mettre à jour")"
  echo "  3) $(t "Create an administrator (temporary password)" "Créer un administrateur (mot de passe provisoire)")"
  echo "  4) $(t "Install the web portal (Cloudflare Tunnel)" "Installer le portail web (Cloudflare Tunnel)")"
  echo "  5) $(t "Quit" "Quitter")"
  echo
  case $(ask "$(t "Your choice" "Votre choix")" 1) in
    1) info ;;
    2) update ;;
    3) add_admin ;;
    4) setup_portal ;;
    *) exit 0 ;;
  esac
}

if installed_native; then
  [ "$MODE" != docker ] || die "$(t "Portunia Gate is already installed as a Debian package on this server." "Portunia Gate est déjà installé en paquet Debian sur ce serveur.")"
  use_mode paquet
elif installed_docker; then
  use_mode docker
  install_docker_wrapper
else
  case $ACTION in
    '') if [ "$MODE" = docker ]; then install_with_docker; else install_native; fi; exit 0 ;;
    *) die "$(t "Portunia Gate is not installed on this server: first run sudo $0" "Portunia Gate n'est pas installé sur ce serveur : lancez d'abord sudo $0")" ;;
  esac
fi

case $ACTION in
  info) info ;;
  update) update ;;
  admin) add_admin "$ACTION_ARG" ;;
  portal) setup_portal ;;
  '') menu ;;
esac
