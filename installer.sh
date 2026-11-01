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
#   ./installer.sh --harden            first install, then hardens this server (dedicated to the Gate)
#   ./installer.sh harden [plan|status|undo]   hardens this server, shows the plan or the state, or undoes it
#
# French names are kept: --paquet, mise-a-jour, portail, --durcir, durcir [simulation|etat|annuler].
# Messages are in French when the system's language is French (LANG=fr_…), in English otherwise;
# PORTUNIA_GATE_LANG=en or fr chooses.
#
# Without a terminal (automation), answers come from PORTUNIA_GATE_NOM, PORTUNIA_GATE_ADMIN, PORTUNIA_GATE_SSH_PORT,
# PORTUNIA_GATE_API_PORT and TZ, or the defaults. PORTUNIA_GATE_DURCIR=oui allows hardening without a terminal
# (access then unchecked), PORTUNIA_GATE_GARDER lists services to keep, PORTUNIA_GATE_DURCIR_PAQUETS=oui removes packages.
set -euo pipefail

RELEASES=${PORTUNIA_GATE_RELEASES:-https://github.com/jpiperault/Portunia-Gate-releases/releases/latest/download}
ENV_NATIVE=/etc/portunia-gate/portunia-gate.env
DOCKER_WRAPPER=/usr/local/bin/portunia-gate

SELF=$(readlink -f "$0")
DIR=$(dirname "$SELF")
cd "$DIR"

# Langue : PORTUNIA_GATE_LANG, sinon celle du système.
lang_of() {
  local v
  for v in "${PORTUNIA_GATE_LANG:-}" "${LC_ALL:-}" "${LC_MESSAGES:-}" "${LANG:-}"; do
    [ -n "$v" ] || continue
    case $v in fr*) echo fr ;; *) echo en ;; esac
    return
  done
  echo en
}
L=$(lang_of)
export PORTUNIA_GATE_LANG=$L
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
MODE='' PACKAGE='' ACTION='' ACTION_ARG='' HARDEN=''
while [ $# -gt 0 ]; do
  case $1 in
    --docker) MODE=docker ;;
    --harden | --durcir) HARDEN=1 ;;
    --package | --paquet) PACKAGE=$(readlink -f "${2:?$(t "$1 expects a .deb file" "$1 attend un fichier .deb")}"); shift ;;
    info | admin) ACTION=$1; ACTION_ARG=${2:-}; [ -z "$ACTION_ARG" ] || shift ;;
    harden | durcir) ACTION=harden; ACTION_ARG=${2:-}; [ -z "$ACTION_ARG" ] || shift ;;
    update | mise-a-jour) ACTION=update ;;
    portal | portail) ACTION=portal ;;
    *) die "$(t "Usage: $0 [--docker] [--package FILE.deb] [--harden] [info | update | admin LOGIN | portal | harden]" "Usage : $0 [--docker] [--paquet FICHIER.deb] [info | mise-a-jour | admin IDENTIFIANT | portail]")" ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || die "$(t "Run the assistant as root." "Lancez l'assistant en root.")"
  exec sudo --preserve-env=PORTUNIA_GATE_NOM,PORTUNIA_GATE_ADMIN,PORTUNIA_GATE_SSH_PORT,PORTUNIA_GATE_API_PORT,TZ,PORTUNIA_GATE_RELEASES,PORTUNIA_GATE_TUNNEL_TOKEN,PORTUNIA_GATE_LANG,PORTUNIA_GATE_DURCIR,PORTUNIA_GATE_GARDER,PORTUNIA_GATE_DURCIR_PAQUETS -- "$SELF" "${ARGS[@]}"
fi
BACKUP_OWNER=${SUDO_USER:-root}

address() { hostname -I 2>/dev/null | awk '{print $1}'; }
container() { [ "$(systemd-detect-virt -c 2>/dev/null)" != none ]; }
port_busy() { ss -Hltn "sport = :$1" 2>/dev/null | grep -q .; }
compose() { docker compose "$@"; }

# Le service n'est activé qu'une fois l'initialisation réussie : sinon, l'installation est à reprendre.
installed_native() { [ -f "$ENV_NATIVE" ] && systemctl is-enabled --quiet portunia-gate 2>/dev/null; }
installed_docker() {
  [ -f .env ] && command -v docker >/dev/null && compose ps -a --format '{{.Service}}' 2>/dev/null | grep -qx portunia-gate
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
  if [ "$MODE" = docker ]; then compose exec -T -e PORTUNIA_GATE_LANG="$L" portunia-gate portunia-gate "$@"; else /usr/bin/portunia-gate "$@"; fi
}
# Valeurs lues dans la sortie de portunia-gate, en anglais comme en français.
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
    SWAPFILE=/portunia-gate-compilation.swap
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
    deb=$work/portunia-gate_amd64.deb
    fetch "$RELEASES/portunia-gate_amd64.deb" "$deb" || die "$(t "Download failed:" "Téléchargement impossible :") $RELEASES/portunia-gate_amd64.deb"
    fetch "$RELEASES/SHA256SUMS" "$work/SHA256SUMS" || die "$(t "Download failed:" "Téléchargement impossible :") $RELEASES/SHA256SUMS"
    (cd "$work" && grep ' portunia-gate_amd64.deb$' SHA256SUMS | sha256sum -c --quiet -) ||
      die "$(t "The downloaded package is altered (different SHA-256 checksum)." "Le paquet téléchargé est altéré (empreinte SHA-256 différente).")"
    ok "$(t "Package downloaded and checked" "Paquet téléchargé et vérifié")"
  fi
  chmod 644 "$deb"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$deb" postgresql >/dev/null 2>"$work/apt.log" ||
    { cat "$work/apt.log" >&2; die "$(t "Cannot install the package." "Installation du paquet impossible.")"; }
  rm -rf "$work"
  local v pgv
  v=$(dpkg-query -W -f '${Version}' portunia-gate)
  pgv=$(pg_lsclusters -h 2>/dev/null | awk 'NR==1{print $1}')
  ok "$(t "Portunia Gate $v and PostgreSQL $pgv installed" "Portunia Gate $v et PostgreSQL $pgv installés")"
}

# Base PostgreSQL locale, sans mot de passe : le compte de service _portunia_gate s'y connecte par socket.
pg() { (cd / && runuser -u postgres -- "$@"); }
prepare_database() {
  systemctl enable --now postgresql >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do pg psql -qtAc 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
  pg psql -qtAc "SELECT 1 FROM pg_roles WHERE rolname = '_portunia_gate'" | grep -q 1 || pg createuser _portunia_gate
  pg psql -qtAc "SELECT 1 FROM pg_database WHERE datname = 'portunia_gate'" | grep -q 1 || pg createdb -O _portunia_gate portunia_gate
  ok "$(t "PostgreSQL database « portunia_gate » ready" "Base PostgreSQL « portunia_gate » prête")"
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
# Commande portunia-gate du serveur : relaie vers la Gate dans son conteneur ($DIR).
# Installée par installer.sh. .env (mot de passe de la base) n'est lisible que par root.
if [ "\$(id -u)" -ne 0 ]; then exec sudo -- "\$0" "\$@"; fi
cd "$DIR" || exit 1
# Messages dans la langue de qui tape la commande.
case "\${PORTUNIA_GATE_LANG:-\${LC_ALL:-\${LC_MESSAGES:-\${LANG:-}}}}" in fr*) lang=fr ;; *) lang=en ;; esac
if ! docker compose ps --status running --format '{{.Service}}' | grep -qx portunia-gate; then
  if [ "\$lang" = fr ]; then
    echo "La Gate est arrêtée. Démarrez-la : cd $DIR && docker compose up -d" >&2
  else
    echo "The Gate is stopped. Start it: cd $DIR && docker compose up -d" >&2
  fi
  exit 1
fi
if [ -t 0 ]; then exec docker compose exec -e PORTUNIA_GATE_LANG=\$lang portunia-gate portunia-gate "\$@"; fi
exec docker compose exec -T -e PORTUNIA_GATE_LANG=\$lang portunia-gate portunia-gate "\$@"
EOF
  chmod 755 "$DOCKER_WRAPPER"
}

# Copie de la clé du coffre au nom de celui qui a lancé sudo, à récupérer par scp.
BACKUP=''
save_vault_key() {
  local home
  home=$(getent passwd "$BACKUP_OWNER" | cut -d: -f6)
  BACKUP=${home:-/root}/portunia-gate-vault.key
  if [ "$MODE" = docker ]; then
    compose cp portunia-gate:/var/lib/portunia-gate/vault.key "$BACKUP" >/dev/null 2>&1 || die "$(t "Cannot copy the vault key." "Copie de la clé du coffre impossible.")"
  else
    cp /var/lib/portunia-gate/vault.key "$BACKUP"
  fi
  chown "$BACKUP_OWNER" "$BACKUP"
  chmod 600 "$BACKUP"
}

wait_api() {
  local port
  port=$(env_value PORTUNIA_GATE_API_PORT)
  for _ in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port:-8443}") 2>/dev/null; then return 0; fi
    sleep 1
  done
  if [ "$MODE" = docker ]; then
    die "$(t "The Gate is not answering on port ${port:-8443}: docker compose logs portunia-gate" "La Gate ne répond pas sur le port ${port:-8443} : docker compose logs portunia-gate")"
  fi
  journalctl -u portunia-gate -n 15 --no-pager >&2 || true
  die "$(t "The Gate is not answering on port ${port:-8443}: journalctl -u portunia-gate" "La Gate ne répond pas sur le port ${port:-8443} : journalctl -u portunia-gate")"
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
  api_port=$(env_value PORTUNIA_GATE_API_PORT)
  ssh_port=$(env_value PORTUNIA_GATE_SSH_PORT)
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
  PORTUNIA_GATE_SSH_PORT=${PORTUNIA_GATE_SSH_PORT:-$(env_value PORTUNIA_GATE_SSH_PORT)}
  PORTUNIA_GATE_API_PORT=${PORTUNIA_GATE_API_PORT:-$(env_value PORTUNIA_GATE_API_PORT)}
  TZ=${TZ:-$(env_value TZ)}
  NOM=$(ask "$(t "Gate name, shown in Portunia" "Nom de la Gate, affiché dans Portunia")" "${PORTUNIA_GATE_NOM:-Portunia Gate}")
  while :; do
    ADMIN=$(ask "$(t "Administrator login" "Identifiant de l'administrateur")" "${PORTUNIA_GATE_ADMIN:-admin}")
    [[ "$ADMIN" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] && break
    warn "$(t "Lowercase letters, digits, dot, hyphen or underscore (32 characters at most)." "Lettres minuscules, chiffres, point, tiret ou souligné (32 caractères au plus).")"
    interactive || die "$(t "Invalid login: $ADMIN" "Identifiant invalide : $ADMIN")"
  done
  while :; do
    SSH_PORT=$(ask "$(t "Gate SSH port" "Port SSH de la Gate")" "${PORTUNIA_GATE_SSH_PORT:-2222}")
    port_busy "$SSH_PORT" || break
    warn "$(t "Port $SSH_PORT is already used on this server." "Le port $SSH_PORT est déjà utilisé sur ce serveur.")"
    interactive || die "$(t "Port $SSH_PORT in use" "Port $SSH_PORT occupé")"
  done
  while :; do
    API_PORT=$(ask "$(t "API port for Portunia" "Port de l'API pour Portunia")" "${PORTUNIA_GATE_API_PORT:-8443}")
    [ "$API_PORT" != "$SSH_PORT" ] || { warn "$(t "Choose a port different from the SSH port." "Choisissez un port différent du port SSH.")"; interactive || die "$(t "Same ports" "Ports identiques")"; continue; }
    port_busy "$API_PORT" || break
    warn "$(t "Port $API_PORT is already used on this server." "Le port $API_PORT est déjà utilisé sur ce serveur.")"
    interactive || die "$(t "Port $API_PORT in use" "Port $API_PORT occupé")"
  done
  local tz
  tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || true)
  ZONE=$(ask "$(t "Time zone of the access rules" "Fuseau horaire des règles d'accès")" "${TZ:-${tz:-Europe/Paris}}")
  if [ -z "$HARDEN" ] && interactive; then
    local answer=''
    read -r -p "  $(t "Harden this server at the end? Only if it is dedicated to the Gate [y/N]:" "Durcir ce serveur à la fin ? Seulement s'il est dédié à la Gate [o/N] :") " answer || answer=''
    case $answer in o* | O* | y* | Y*) HARDEN=1 ;; esac
  fi
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
    compose run --rm -T -e PORTUNIA_GATE_LANG="$L" portunia-gate init --admin "$ADMIN" --temporary --name "$NOM"
  else
    /usr/bin/portunia-gate init --admin "$ADMIN" --temporary --name "$NOM"
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
# Réglages de Portunia Gate, créés par installer.sh. Après modification : sudo systemctl restart portunia-gate
# Portunia Gate settings, created by installer.sh. After a change: sudo systemctl restart portunia-gate
PORTUNIA_GATE_DATABASE_URL=postgres://_portunia_gate@localhost/portunia_gate?host=/var/run/postgresql
PORTUNIA_GATE_SSH_PORT=$SSH_PORT
PORTUNIA_GATE_API_PORT=$API_PORT
TZ=$ZONE
EOF
  )
  chgrp _portunia_gate "$ENV_NATIVE"
  ok "$(t "Settings saved in $ENV_NATIVE" "Réglages enregistrés dans $ENV_NATIVE")"
  initialize
  set_language
  systemctl enable --now portunia-gate >/dev/null 2>&1 || true
  wait_api
  ok "$(t "Gate started (portunia-gate service, restarts with the server)" "Gate démarrée (service portunia-gate, redémarre seul avec le serveur)")"
  finish
}

# La Gate parle la langue de l'assistant (modifiable ensuite dans Portunia, Administrer › Réglages).
set_language() {
  if [ "$MODE" = docker ]; then
    compose run --rm -T -e PORTUNIA_GATE_LANG="$L" portunia-gate setting language "$L" >/dev/null
  else
    /usr/bin/portunia-gate setting language "$L" >/dev/null
  fi
}

install_with_docker() {
  use_mode docker
  [ -f "$DIR/Dockerfile" ] || die "$(t "Docker mode runs from a copy of the repository: git clone https://github.com/jpiperault/Portunia-Gate.git" "Le mode Docker s'utilise depuis une copie du dépôt : git clone https://github.com/jpiperault/Portunia-Gate.git")"
  echo "${B}$(t "Portunia Gate — installation" "Portunia Gate — installation")${N} ${D}(Docker, $DIR)${N}"
  step "$(t "Checks" "Vérifications")"
  check_system
  check_docker
  check_build_memory
  questions
  local db_password
  db_password=$(env_value PORTUNIA_GATE_DB_PASSWORD)
  (
    umask 077
    cat >.env <<EOF
# Créé par installer.sh le $(date '+%d/%m/%Y'). Modifiez puis : docker compose up -d
# Created by installer.sh on $(date '+%Y-%m-%d'). Change then: docker compose up -d
PORTUNIA_GATE_DB_PASSWORD=${db_password:-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')}
PORTUNIA_GATE_SSH_PORT=$SSH_PORT
PORTUNIA_GATE_API_PORT=$API_PORT
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
  ok "$(t "Command ${B}portunia-gate${N} installed (e.g. sudo portunia-gate user list)" "Commande ${B}portunia-gate${N} installée (ex. sudo portunia-gate user list)")"
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
  local token=${PORTUNIA_GATE_TUNNEL_TOKEN:-} service
  if [ -z "$token" ] && interactive; then read -r -s -p "  $(t "Tunnel token:" "Jeton du tunnel :") " token; echo; fi
  token=$(tr -d '[:space:]' <<<"$token")
  [ -n "$token" ] || die "$(t "Tunnel token missing." "Jeton du tunnel manquant.")"
  [[ "$token" =~ ^[A-Za-z0-9+/=_-]+$ ]] || die "$(t "This does not look like a Cloudflare tunnel token." "Ce jeton ne ressemble pas à un jeton de tunnel Cloudflare.")"
  if [ "$MODE" = docker ]; then
    set_env PORTUNIA_GATE_TUNNEL_TOKEN "$token"
    set_env COMPOSE_PROFILES portail
    local out
    out=$(compose up -d 2>&1) || { echo "$out"; die "$(t "The tunnel does not start." "Le tunnel ne démarre pas.")"; }
    service=portunia-gate:8445
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

# ---------- Durcissement du serveur ----------
#
# Facultatif : à réserver à un serveur dédié à la Gate. Ne garde que ce qu'il lui faut : pare-feu
# fermé sauf les ports utiles, services inutiles arrêtés, SSH du système resserré, réglages du
# noyau. Tout changement qui pourrait couper l'accès est annulé seul si une nouvelle connexion
# n'est pas confirmée à temps.

HARDEN_DIR=/etc/portunia-gate/durcissement
HARDEN_SSH=/etc/ssh/sshd_config.d/10-portunia-gate.conf
HARDEN_SYSCTL=/etc/sysctl.d/90-portunia-gate.conf
HARDEN_MODPROBE=/etc/modprobe.d/portunia-gate.conf
HARDEN_UNIT=/etc/systemd/system/portunia-gate-pare-feu.service
HARDEN_STATE=/var/lib/portunia-gate/durcissement.json
HARDEN_STATE_UNIT=/etc/systemd/system/portunia-gate-etat
HARDEN_DELAY=300
# Paquets réseau jamais utiles à la Gate, retirés seulement sur confirmation.
HARDEN_PACKAGES="telnetd inetutils-telnetd rsh-server vsftpd proftpd-basic tftpd-hpa xinetd avahi-daemon cups samba rpcbind nfs-kernel-server bluez snmpd apache2 nginx exim4-daemon-light postfix modemmanager"

# >>> fonctions testables
# Règles du pare-feu. Sa table lui est propre : celles de Docker et des autres outils restent.
# harden_nft_rules "ports d'administration" "ports de la Gate" (séparés par des virgules)
harden_nft_rules() {
  cat <<EOF
table inet portunia_gate
delete table inet portunia_gate
table inet portunia_gate {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto { icmp, ipv6-icmp } accept
    udp sport 67 udp dport 68 accept
    udp sport 547 udp dport 546 accept
    tcp dport { $1 } ct state new limit rate 30/minute burst 30 packets accept
    tcp dport { $2 } accept
  }
}
EOF
}

# Le service fait-il tourner le système ou la Gate ? Tout ce qui n'est pas ici est arrêté.
harden_keeps() {
  case ${1%.*} in
    ssh | sshd | ssh@* | portunia-gate* | postgresql* | docker | containerd | cloudflared*) return 0 ;;
    systemd-* | dbus* | getty@* | serial-getty@* | container-getty@* | console-* | autovt@* | user@* | user-runtime-dir@*) return 0 ;;
    networking | NetworkManager* | netplan* | ifup* | resolvconf*) return 0 ;;
    cron | crond | anacron | rsyslog | syslog | chrony* | ntp* | nftables | netfilter-persistent | ufw | fail2ban | crowdsec* | apparmor | auditd | kmod* | keyboard-setup | setvtrgb) return 0 ;;
    unattended-upgrades | apt-daily* | e2scrub* | fstrim | logrotate | lvm2* | blk-availability | dm-event* | multipathd* | mdmonitor* | zfs*) return 0 ;;
    qemu-guest-agent | open-vm-tools | vmtoolsd | vgauth | hv-* | waagent | walinuxagent | google-* | cloud-* | snapd* | pve* | lxc* | lxd*) return 0 ;;
    grub-* | iscsid* | uuidd* | ufw-*) return 0 ;;
  esac
  return 1
}

# Réglages du SSH du système. $1 = « cle » : le compte a une clé, les mots de passe sont retirés.
harden_sshd_conf() {
  cat <<EOF
# Durcissement de Portunia Gate : sudo bash installer.sh harden undo pour le retirer.
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
  if [ "$1" = cle ]; then
    cat <<EOF
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
  fi
}

# Script lancé par root toutes les 15 minutes : la Gate, sans droits, ne fait que lire son résultat.
# harden_state_script dossier fichier-ssh fichier-noyau unité-pare-feu "commande d'écriture"
harden_state_script() {
  cat <<EOF
#!/bin/sh
umask 022
yes() { if "\$@" >/dev/null 2>&1; then echo true; else echo false; fi; }
stopped=0
back=''
if [ -f $1/services ]; then
  while read -r unit; do
    stopped=\$((stopped + 1))
    if [ "\$(systemctl is-active "\$unit" 2>/dev/null)" = active ]; then back="\$back\"\$unit\","; fi
  done <$1/services
fi
tmp=\$(mktemp)
printf '{"date":"%s","pare_feu":%s,"pare_feu_prevu":%s,"ssh":%s,"noyau":%s,"mises_a_jour":%s,"services_arretes":%s,"services_relances":[%s]}\n' \\
  "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" "\$(yes nft list table inet portunia_gate)" "\$(yes test -f $4)" "\$(yes test -f $2)" \\
  "\$(yes test -f $3)" "\$(yes test -f /etc/apt/apt.conf.d/20auto-upgrades)" "\$stopped" "\${back%,}" >"\$tmp"
chmod 644 "\$tmp"
$5
rm -f "\$tmp"
EOF
}
# <<< fonctions testables

harden_sysctl_conf() {
  cat <<EOF
# Durcissement de Portunia Gate
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2
kernel.randomize_va_space = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF
}

harden_modprobe_conf() {
  local m
  echo "# Durcissement de Portunia Gate : modules jamais utiles à la Gate."
  for m in cramfs freevxfs jffs2 hfs hfsplus udf usb-storage firewire-core bluetooth dccp sctp rds tipc; do
    echo "install $m /bin/false"
  done
}

harden_admin_ports() {
  local ports
  ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' || true)
  # Le port de la connexion en cours reste ouvert, quoi que dise la configuration.
  [ -z "${SSH_CONNECTION:-}" ] || ports="$ports ${SSH_CONNECTION##* }"
  [ -n "${ports// /}" ] || ports=22
  # shellcheck disable=SC2086
  printf '%s\n' $ports | sort -un | paste -sd, -
}

harden_gate_ports() {
  local ssh api tls
  ssh=$(env_value PORTUNIA_GATE_SSH_PORT)
  api=$(env_value PORTUNIA_GATE_API_PORT)
  tls=$(env_value PORTUNIA_GATE_PORTAL_TLS_LISTEN)
  printf '%s\n' "${ssh:-2222}" "${api:-8443}" ${tls:+"${tls##*:}"} | sort -un | paste -sd, -
}

# Le compte qui administre a-t-il une clé SSH déjà installée ?
harden_has_key() {
  local home
  home=$(getent passwd "$BACKUP_OWNER" | cut -d: -f6)
  [ -s "${home:-/root}/.ssh/authorized_keys" ]
}

harden_extra_kept() { echo " ${PORTUNIA_GATE_GARDER:-} ${HARDEN_KEEP:-} " | tr ',' ' '; }

# Services et sockets activés qui ne servent ni au système ni à la Gate.
harden_unneeded() {
  local unit kept
  kept=$(harden_extra_kept)
  while read -r unit; do
    [ -n "$unit" ] || continue
    harden_keeps "$unit" && continue
    case $kept in *" $unit "* | *" ${unit%.*} "*) continue ;; esac
    echo "$unit"
  done < <(systemctl list-unit-files --type=service,socket --state=enabled --no-legend 2>/dev/null | awk '{print $1}')
}

harden_packages_present() {
  local p
  for p in $HARDEN_PACKAGES; do
    if dpkg-query -W -f '${Status}' "$p" 2>/dev/null | grep -q 'install ok installed'; then echo "$p"; fi
  done
}

harden_plan() {
  local admin gate
  admin=$(harden_admin_ports)
  gate=$(harden_gate_ports)
  step "$(t "Hardening plan" "Plan du durcissement")"
  echo "  $(t "Firewall: incoming traffic closed, except" "Pare-feu : entrées fermées, sauf")"
  echo "    $(t "system SSH (administration):" "SSH du système (administration) :") $admin"
  echo "    $(t "Gate:" "Gate :") $gate"
  [ "$MODE" != docker ] || warn "$(t "Docker manages its published ports itself: this firewall does not filter them." "Docker gère lui-même ses ports publiés : ce pare-feu ne les filtre pas.")"
  echo "  $(t "Services that will be stopped:" "Services qui seront arrêtés :")"
  local list
  list=$(harden_unneeded)
  if [ -n "$list" ]; then sed 's/^/    /' <<<"$list"; else echo "    $(t "none" "aucun")"; fi
  echo "  $(t "Packages that can be removed, after a separate confirmation:" "Paquets qui peuvent être retirés, après une confirmation à part :")"
  list=$(harden_packages_present)
  if [ -n "$list" ]; then sed 's/^/    /' <<<"$list"; else echo "    $(t "none" "aucun")"; fi
  if harden_has_key; then
    echo "  $(t "System SSH: keys only, no forwarding." "SSH du système : clés seulement, pas de redirections.")"
  else
    warn "$(t "No SSH key for $BACKUP_OWNER: password sign-in stays enabled on the system SSH." "Pas de clé SSH pour $BACKUP_OWNER : la connexion par mot de passe reste active sur le SSH du système.")"
  fi
  if container; then
    warn "$(t "Container: the kernel belongs to the host, so kernel settings are skipped. The firewall may be refused too: then use the host's." "Conteneur : le noyau est celui de l'hôte, ses réglages sont ignorés. Le pare-feu peut aussi être refusé : utilisez alors celui de l'hôte.")"
  else
    echo "  $(t "Kernel: network and memory protections, unused modules blocked." "Noyau : protections réseau et mémoire, modules inutiles bloqués.")"
  fi
  echo "  $(t "Automatic security updates." "Mises à jour de sécurité automatiques.")"
}

# Annule ce qui peut couper l'accès.
harden_write_rollback() {
  cat >"$HARDEN_DIR/retour.sh" <<EOF
#!/bin/sh
nft delete table inet portunia_gate 2>/dev/null
rm -f $HARDEN_SSH
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
exit 0
EOF
  chmod 700 "$HARDEN_DIR/retour.sh"
}

harden_reload_ssh() { systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true; }

# Pare-feu et SSH, à confirmer par une nouvelle connexion. Vrai si tout est validé.
harden_access() {
  local firewall=0
  apt-get install -y -qq nftables >/dev/null || die "$(t "Cannot install nftables." "Installation de nftables impossible.")"
  harden_nft_rules "$(harden_admin_ports)" "$(harden_gate_ports)" >"$HARDEN_DIR/pare-feu.nft"
  chmod 600 "$HARDEN_DIR/pare-feu.nft"
  harden_write_rollback
  if interactive; then
    systemd-run --quiet --unit=portunia-gate-retour --on-active="$HARDEN_DELAY" /bin/sh "$HARDEN_DIR/retour.sh" ||
      die "$(t "Cannot schedule the automatic rollback: nothing was changed." "Retour automatique impossible à prévoir : rien n'a été modifié.")"
  fi
  if nft -f "$HARDEN_DIR/pare-feu.nft" 2>/dev/null; then
    firewall=1
    ok "$(t "Firewall applied" "Pare-feu appliqué")"
  else
    warn "$(t "Firewall refused on this system (container?): use the host's firewall." "Pare-feu refusé sur ce système (conteneur ?) : utilisez celui de l'hôte.")"
  fi
  if [ -d /etc/ssh/sshd_config.d ] && grep -qsE '^[[:space:]]*Include[[:space:]].*sshd_config\.d' /etc/ssh/sshd_config; then
    if harden_has_key; then harden_sshd_conf cle >"$HARDEN_SSH"; else harden_sshd_conf mot-de-passe >"$HARDEN_SSH"; fi
    if sshd -t 2>/dev/null; then
      harden_reload_ssh
      ok "$(t "System SSH tightened" "SSH du système resserré")"
    else
      rm -f "$HARDEN_SSH"
      warn "$(t "System SSH left unchanged: settings refused by sshd." "SSH du système inchangé : réglages refusés par sshd.")"
    fi
  else
    warn "$(t "System SSH left unchanged: no sshd_config.d." "SSH du système inchangé : pas de sshd_config.d.")"
  fi
  if interactive; then
    echo
    echo "  ${Y}${B}$(t "Check your access now" "Vérifiez votre accès maintenant")${N}"
    echo "  $(t "Keep this window open and, in ANOTHER window, connect again:" "Gardez cette fenêtre ouverte et, dans une AUTRE fenêtre, reconnectez-vous :")"
    echo "    ssh $BACKUP_OWNER@$(address)"
    echo "  $(t "Also check that Portunia reaches the Gate." "Vérifiez aussi que Portunia joint la Gate.")"
    echo "  $(t "Without an answer within $((HARDEN_DELAY / 60)) minutes, these changes are undone." "Sans réponse sous $((HARDEN_DELAY / 60)) minutes, ces changements sont annulés.")"
    local answer=''
    read -r -t "$((HARDEN_DELAY - 20))" -p "  $(t "Does the new connection work? Type yes:" "La nouvelle connexion fonctionne ? Tapez oui :") " answer || answer=''
    case $answer in
      oui | OUI | Oui | yes | YES | Yes) systemctl stop portunia-gate-retour.timer portunia-gate-retour.service 2>/dev/null || true ;;
      *)
        systemctl stop portunia-gate-retour.timer 2>/dev/null || true
        /bin/sh "$HARDEN_DIR/retour.sh"
        warn "$(t "Firewall and system SSH restored as they were." "Pare-feu et SSH du système remis comme avant.")"
        return 1
        ;;
    esac
  else
    warn "$(t "No terminal: access was not checked." "Sans terminal : l'accès n'a pas été vérifié.")"
  fi
  if [ "$firewall" = 1 ]; then
    cat >"$HARDEN_UNIT" <<EOF
[Unit]
Description=Pare-feu de Portunia Gate
After=nftables.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $HARDEN_DIR/pare-feu.nft
ExecStop=-/usr/sbin/nft delete table inet portunia_gate

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable portunia-gate-pare-feu >/dev/null 2>&1
  fi
}

harden_services() {
  local unit list
  list=$(harden_unneeded)
  [ -n "$list" ] || { ok "$(t "No unneeded service" "Aucun service inutile")"; return 0; }
  while read -r unit; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl mask "$unit" >/dev/null 2>&1 || true
    echo "$unit" >>"$HARDEN_DIR/services"
    ok "$(t "Stopped:" "Arrêté :") $unit"
  done <<<"$list"
}

harden_packages() {
  local list
  list=$(harden_packages_present | paste -sd' ' -)
  [ -n "$list" ] || return 0
  local answer=${PORTUNIA_GATE_DURCIR_PAQUETS:-non}
  if interactive; then
    read -r -p "  $(t "Remove these packages for good? ($list) [y/N]:" "Retirer ces paquets définitivement ? ($list) [o/N] :") " answer || answer=''
  fi
  case $answer in
    o* | O* | y* | Y*)
      # shellcheck disable=SC2086
      DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq $list >/dev/null
      ok "$(t "Packages removed" "Paquets retirés")"
      ;;
    *) warn "$(t "Packages kept (their services stay stopped)." "Paquets gardés (leurs services restent arrêtés).")" ;;
  esac
}

harden_system() {
  if container; then return 0; fi
  harden_sysctl_conf >"$HARDEN_SYSCTL"
  sysctl -e -q -p "$HARDEN_SYSCTL" >/dev/null 2>&1 || true
  harden_modprobe_conf >"$HARDEN_MODPROBE"
  ok "$(t "Kernel settings applied" "Réglages du noyau appliqués")"
}

harden_updates() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades >/dev/null || { warn "$(t "Automatic updates not installed." "Mises à jour automatiques non installées.")"; return 0; }
  printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' >/etc/apt/apt.conf.d/20auto-upgrades
  ok "$(t "Automatic security updates enabled" "Mises à jour de sécurité automatiques activées")"
}

harden_apply() {
  harden_plan
  echo
  warn "$(t "For a server dedicated to the Gate only: other programs may stop." "Pour un serveur dédié à la Gate uniquement : d'autres programmes peuvent s'arrêter.")"
  if interactive; then
    HARDEN_KEEP=$(ask "$(t "Services to keep, separated by spaces (monitoring, backup…)" "Services à garder, séparés par des espaces (supervision, sauvegarde…)")" "")
    confirm "$(t "Harden this server?" "Durcir ce serveur ?")" || { warn "$(t "Nothing was changed." "Rien n'a été modifié.")"; return 0; }
  elif [ "${PORTUNIA_GATE_DURCIR:-}" != oui ]; then
    die "$(t "Without a terminal, set PORTUNIA_GATE_DURCIR=oui." "Sans terminal, indiquez PORTUNIA_GATE_DURCIR=oui.")"
  fi
  install -d -m 700 "$HARDEN_DIR"
  step "$(t "Access" "Accès")"
  harden_access || return 0
  step "$(t "Services" "Services")"
  harden_services
  harden_packages
  step "$(t "System" "Système")"
  harden_system
  harden_updates
  harden_state_install
  echo
  ok "$(t "Server hardened. Undo: sudo bash installer.sh harden undo" "Serveur durci. Pour annuler : sudo bash installer.sh durcir annuler")"
}

# État lisible dans Portunia (Administrer › Durcissement).
harden_state_install() {
  local write
  if [ "$MODE" = docker ]; then
    write="cd $DIR && docker compose cp \"\$tmp\" portunia-gate:$HARDEN_STATE"
  else
    write="cp \"\$tmp\" $HARDEN_STATE"
  fi
  harden_state_script "$HARDEN_DIR" "$HARDEN_SSH" "$HARDEN_SYSCTL" "$HARDEN_UNIT" "$write" >"$HARDEN_DIR/etat.sh"
  chmod 700 "$HARDEN_DIR/etat.sh"
  cat >"$HARDEN_STATE_UNIT.service" <<EOF
[Unit]
Description=État du durcissement de Portunia Gate

[Service]
Type=oneshot
ExecStart=/bin/sh $HARDEN_DIR/etat.sh
EOF
  cat >"$HARDEN_STATE_UNIT.timer" <<EOF
[Unit]
Description=État du durcissement de Portunia Gate, toutes les 15 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now portunia-gate-etat.timer >/dev/null 2>&1 || warn "$(t "Hardening state not scheduled." "État du durcissement non planifié.")"
  systemctl start portunia-gate-etat.service >/dev/null 2>&1 || true
}

harden_status() {
  step "$(t "Hardening" "Durcissement")"
  local yes no
  yes=$(t "active" "actif") no=$(t "absent" "absent")
  if nft list table inet portunia_gate >/dev/null 2>&1; then echo "  $(t "Firewall:" "Pare-feu :") $yes"; else echo "  $(t "Firewall:" "Pare-feu :") $no"; fi
  if [ -f "$HARDEN_SSH" ]; then echo "  $(t "System SSH:" "SSH du système :") $yes"; else echo "  $(t "System SSH:" "SSH du système :") $no"; fi
  if [ -f "$HARDEN_SYSCTL" ]; then echo "  $(t "Kernel:" "Noyau :") $yes"; else echo "  $(t "Kernel:" "Noyau :") $no"; fi
  local n=0
  [ ! -f "$HARDEN_DIR/services" ] || n=$(wc -l <"$HARDEN_DIR/services")
  echo "  $(t "Services stopped:" "Services arrêtés :") $n"
}

harden_undo() {
  systemctl disable --now portunia-gate-pare-feu portunia-gate-etat.timer >/dev/null 2>&1 || true
  rm -f "$HARDEN_STATE_UNIT.service" "$HARDEN_STATE_UNIT.timer"
  if [ "$MODE" = docker ]; then compose exec -T portunia-gate rm -f "$HARDEN_STATE" >/dev/null 2>&1 || true; else rm -f "$HARDEN_STATE"; fi
  nft delete table inet portunia_gate 2>/dev/null || true
  rm -f "$HARDEN_UNIT" "$HARDEN_SSH" "$HARDEN_SYSCTL" "$HARDEN_MODPROBE" /etc/apt/apt.conf.d/20auto-upgrades
  systemctl daemon-reload
  harden_reload_ssh
  local unit
  if [ -f "$HARDEN_DIR/services" ]; then
    while read -r unit; do
      systemctl unmask "$unit" >/dev/null 2>&1 || true
      systemctl enable --now "$unit" >/dev/null 2>&1 || warn "$(t "Cannot restart:" "Redémarrage impossible :") $unit"
    done <"$HARDEN_DIR/services"
  fi
  rm -rf "$HARDEN_DIR"
  ok "$(t "Hardening removed. Kernel settings go back at the next restart; removed packages are not reinstalled." "Durcissement retiré. Les réglages du noyau reviennent au prochain redémarrage ; les paquets retirés ne sont pas réinstallés.")"
}

harden() {
  case ${1:-} in
    '') harden_apply ;;
    plan | simulation) harden_plan ;;
    status | etat) harden_status ;;
    undo | annuler) harden_undo ;;
    *) die "$(t "Usage: $0 harden [plan | status | undo]" "Usage : $0 durcir [simulation | etat | annuler]")" ;;
  esac
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
  echo "  5) $(t "Harden this server" "Durcir ce serveur")"
  echo "  6) $(t "Quit" "Quitter")"
  echo
  case $(ask "$(t "Your choice" "Votre choix")" 1) in
    1) info ;;
    2) update ;;
    3) add_admin ;;
    4) setup_portal ;;
    5) harden ;;
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
    '')
      if [ "$MODE" = docker ]; then install_with_docker; else install_native; fi
      [ -z "$HARDEN" ] || harden
      exit 0
      ;;
    *) die "$(t "Portunia Gate is not installed on this server: first run sudo $0" "Portunia Gate n'est pas installé sur ce serveur : lancez d'abord sudo $0")" ;;
  esac
fi

case $ACTION in
  info) info ;;
  update) update ;;
  admin) add_admin "$ACTION_ARG" ;;
  portal) setup_portal ;;
  harden) harden "$ACTION_ARG" ;;
  '') menu ;;
esac
