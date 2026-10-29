#!/usr/bin/env bash
# Assistant d'installation de Heimdia (Debian 12/13, Ubuntu 22.04 et suivantes).
#
#   ./installer.sh                   première installation (paquet Debian), ou menu si déjà installé
#   ./installer.sh --docker          première installation avec Docker (depuis une copie du dépôt)
#   ./installer.sh --paquet FICHIER  installe ce fichier .deb au lieu de télécharger la dernière version
#   ./installer.sh info              informations à saisir dans Portunia
#   ./installer.sh mise-a-jour       installe la dernière version et redémarre le bastion
#   ./installer.sh admin LOGIN       crée un administrateur de secours (mot de passe provisoire)
#   ./installer.sh portail          installe Cloudflare Tunnel pour le portail web (jeton demandé)
#
# Sans terminal (automatisation), les réponses viennent des variables HEIMDIA_NOM, HEIMDIA_ADMIN,
# HEIMDIA_SSH_PORT, HEIMDIA_API_PORT et TZ, ou des valeurs par défaut.
set -euo pipefail

RELEASES=${HEIMDIA_RELEASES:-https://github.com/jpiperault/Heimdia-releases/releases/latest/download}
ENV_NATIVE=/etc/heimdia/heimdia.env
DOCKER_WRAPPER=/usr/local/bin/heimdia

SELF=$(readlink -f "$0")
DIR=$(dirname "$SELF")
cd "$DIR"

if [ -t 1 ]; then B=$'\e[1m' G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' D=$'\e[2m' N=$'\e[0m'; else B='' G='' Y='' R='' D='' N=''; fi
ok() { echo "  ${G}✓${N} $*"; }
step() { echo; echo "${B}$*${N}"; }
warn() { echo "  ${Y}!${N} $*"; }
die() { echo "  ${R}✗ $*${N}" >&2; exit 1; }
interactive() { [ -t 0 ]; }
# ask "Question" "défaut" : réponse sur la sortie standard.
ask() {
  local answer=''
  if interactive; then read -r -p "  $1 [${D}$2${N}] : " answer; fi
  echo "${answer:-$2}"
}
confirm() {
  local answer=''
  interactive || return 0
  read -r -p "  $1 [O/n] : " answer
  [[ ! "$answer" =~ ^[nN] ]]
}

# ---------- Arguments ----------

ARGS=("$@")
MODE='' PACKAGE='' ACTION='' ACTION_ARG=''
while [ $# -gt 0 ]; do
  case $1 in
    --docker) MODE=docker ;;
    --paquet) PACKAGE=$(readlink -f "${2:?--paquet attend un fichier .deb}"); shift ;;
    info | mise-a-jour | admin | portail) ACTION=$1; ACTION_ARG=${2:-}; [ -z "$ACTION_ARG" ] || shift ;;
    *) die "Usage : $0 [--docker] [--paquet FICHIER.deb] [info | mise-a-jour | admin IDENTIFIANT | portail]" ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || die "Lancez l'assistant en root."
  exec sudo --preserve-env=HEIMDIA_NOM,HEIMDIA_ADMIN,HEIMDIA_SSH_PORT,HEIMDIA_API_PORT,TZ,HEIMDIA_RELEASES,HEIMDIA_TUNNEL_TOKEN -- "$SELF" "${ARGS[@]}"
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
# Commande d'administration du bastion, quel que soit le mode.
hcmd() {
  if [ "$MODE" = docker ]; then compose exec -T heimdia heimdia "$@"; else /usr/bin/heimdia "$@"; fi
}

# ---------- Prérequis ----------

check_system() {
  command -v apt-get >/dev/null || die "Distribution non prise en charge : Debian 12/13 ou Ubuntu 22.04 et suivantes."
  [ -d /run/systemd/system ] || die "systemd est nécessaire."
  local mem cpus disk
  mem=$(awk '/^MemTotal/{print int($2/1024)}' /proc/meminfo)
  cpus=$(nproc)
  disk=$(df -Pm /var | awk 'NR==2{print int($4/1024)}')
  ok "$(. /etc/os-release && echo "$PRETTY_NAME"), $cpus processeur(s), $((mem / 1024)) Go de mémoire, $disk Go de disque libre"
  [ "$disk" -ge 5 ] || warn "Moins de 5 Go libres : peu de place pour les enregistrements des sessions."
  [ "$mem" -ge 900 ] || warn "Moins de 1 Go de mémoire : Heimdia et PostgreSQL seront à l'étroit."
}

install_docker() {
  confirm "Docker n'est pas installé. L'installer depuis les paquets de la distribution ?" || die "Docker est nécessaire en mode Docker."
  apt-get update -qq
  local pkgs=(docker.io)
  for p in docker-buildx docker-compose-v2; do apt-cache show "$p" >/dev/null 2>&1 && pkgs+=("$p"); done
  [[ " ${pkgs[*]} " == *docker-compose-v2* ]] || pkgs+=(docker-compose)
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" >/dev/null
  systemctl enable --now docker >/dev/null 2>&1 || true
  docker compose version >/dev/null 2>&1 ||
    die "Docker Compose v2 manque dans les paquets de cette distribution : installez Docker depuis https://docs.docker.com/engine/install/ puis relancez."
  ok "Docker installé ($(docker --version | awk '{print $3}' | tr -d ,))"
}

check_docker() {
  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo présent), Compose $(docker compose version --short 2>/dev/null)"
  else
    install_docker
  fi
  if ! docker info >/dev/null 2>&1; then
    if [ "$(systemd-detect-virt -c 2>/dev/null)" = lxc ]; then
      die "Docker ne démarre pas. Dans un container LXC Proxmox, activez les options nesting et keyctl, redémarrez le container et relancez."
    fi
    die "Docker ne répond pas : systemctl status docker"
  fi
}

# Mode Docker : la compilation a besoin de mémoire ; fichier d'échange temporaire si elle manque.
SWAPFILE=''
check_build_memory() {
  local mem swap
  mem=$(awk '/^MemTotal/{print int($2/1024)}' /proc/meminfo)
  swap=$(awk '/^SwapTotal/{print int($2/1024)}' /proc/meminfo)
  [ "$(nproc)" -ge 2 ] || warn "Un seul processeur : la compilation prendra 20 à 30 minutes."
  [ $((mem + swap)) -lt 3500 ] || return 0
  warn "Mémoire faible pour compiler (il faut environ 3,5 Go, mémoire et échange compris)."
  if ! container && confirm "Ajouter un fichier d'échange de 2 Go le temps de la compilation ?"; then
    SWAPFILE=/heimdia-compilation.swap
    if fallocate -l 2G "$SWAPFILE" && chmod 600 "$SWAPFILE" && mkswap -q "$SWAPFILE" && swapon "$SWAPFILE"; then
      ok "Fichier d'échange temporaire ajouté"
    else
      warn "Impossible d'ajouter le fichier d'échange"; rm -f "$SWAPFILE"; SWAPFILE=''
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
  [ "$(dpkg --print-architecture)" = amd64 ] || die "Paquet disponible pour amd64 uniquement : utilisez --docker."
  local work deb
  work=$(mktemp -d)
  chmod 755 "$work"
  if [ -n "$PACKAGE" ]; then
    [ -f "$PACKAGE" ] || die "Fichier introuvable : $PACKAGE"
    deb=$work/$(basename "$PACKAGE")
    cp "$PACKAGE" "$deb"
  else
    command -v curl >/dev/null || command -v wget >/dev/null || { apt-get update -qq; apt-get install -y -qq curl >/dev/null; }
    deb=$work/heimdia_amd64.deb
    fetch "$RELEASES/heimdia_amd64.deb" "$deb" || die "Téléchargement impossible : $RELEASES/heimdia_amd64.deb"
    fetch "$RELEASES/SHA256SUMS" "$work/SHA256SUMS" || die "Téléchargement impossible : $RELEASES/SHA256SUMS"
    (cd "$work" && grep ' heimdia_amd64.deb$' SHA256SUMS | sha256sum -c --quiet -) || die "Le paquet téléchargé est altéré (empreinte SHA-256 différente)."
    ok "Paquet téléchargé et vérifié"
  fi
  chmod 644 "$deb"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$deb" postgresql >/dev/null 2>"$work/apt.log" ||
    { cat "$work/apt.log" >&2; die "Installation du paquet impossible."; }
  rm -rf "$work"
  ok "Heimdia $(dpkg-query -W -f '${Version}' heimdia) et PostgreSQL $(pg_lsclusters -h 2>/dev/null | awk 'NR==1{print $1}') installés"
}

# Base PostgreSQL locale, sans mot de passe : le compte de service _heimdia s'y connecte par socket.
pg() { (cd / && runuser -u postgres -- "$@"); }
prepare_database() {
  systemctl enable --now postgresql >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do pg psql -qtAc 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
  pg psql -qtAc "SELECT 1 FROM pg_roles WHERE rolname = '_heimdia'" | grep -q 1 || pg createuser _heimdia
  pg psql -qtAc "SELECT 1 FROM pg_database WHERE datname = 'heimdia'" | grep -q 1 || pg createdb -O _heimdia heimdia
  ok "Base PostgreSQL « heimdia » prête"
}

# ---------- Étapes communes ----------

build_image() {
  step "Compilation de Heimdia ${D}(10 à 30 minutes la première fois)${N}"
  compose build || die "La compilation a échoué. Manque de mémoire ? Voir docs/exploitation.md, section Dépannage."
  remove_swap
  ok "Image construite"
}

install_docker_wrapper() {
  cat >"$DOCKER_WRAPPER" <<EOF
#!/bin/sh
# Commande heimdia du serveur : relaie vers le bastion dans son conteneur ($DIR).
# Installée par installer.sh. .env (mot de passe de la base) n'est lisible que par root.
if [ "\$(id -u)" -ne 0 ]; then exec sudo -- "\$0" "\$@"; fi
cd "$DIR" || exit 1
if ! docker compose ps --status running --format '{{.Service}}' | grep -qx heimdia; then
  echo "Le bastion est arrêté. Démarrez-le : cd $DIR && docker compose up -d" >&2
  exit 1
fi
if [ -t 0 ]; then exec docker compose exec heimdia heimdia "\$@"; fi
exec docker compose exec -T heimdia heimdia "\$@"
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
    compose cp heimdia:/var/lib/heimdia/coffre.key "$BACKUP" >/dev/null 2>&1 || die "Copie de la clé du coffre impossible."
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
    die "Le bastion ne répond pas sur le port ${port:-8443} : docker compose logs heimdia"
  fi
  journalctl -u heimdia -n 15 --no-pager >&2 || true
  die "Le bastion ne répond pas sur le port ${port:-8443} : journalctl -u heimdia"
}

open_firewall() {
  local ssh_port=$1 api_port=$2
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
    if confirm "Le pare-feu ufw est actif. Ouvrir les ports $ssh_port et $api_port ?"; then
      ufw allow "$ssh_port/tcp" >/dev/null && ufw allow "$api_port/tcp" >/dev/null && ok "Ports ouverts dans ufw"
    fi
  fi
}

# Ce qu'il faut saisir dans Portunia.
summary() {
  local login=${1:-} password=${2:-} fingerprint api_port ssh_port addr
  fingerprint=$(hcmd info | awk '/^Certificat de l/{print $NF}')
  api_port=$(env_value HEIMDIA_API_PORT)
  ssh_port=$(env_value HEIMDIA_SSH_PORT)
  addr=$(address)
  [ "${api_port:-8443}" = 8443 ] || addr="$addr:$api_port"
  echo
  echo "  ┌──────────────────────────────────────────────────────────────────────────"
  echo "  │ ${B}Dans Portunia${N} : Extensions › activer Heimdia, puis Bastions › Ajouter un bastion"
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
  echo "  └──────────────────────────────────────────────────────────────────────────"
}

# ---------- Première installation ----------

questions() {
  step "Configuration ${D}(Entrée pour garder la valeur proposée)${N}"
  # Installation interrompue : on reprend ses réglages.
  HEIMDIA_SSH_PORT=${HEIMDIA_SSH_PORT:-$(env_value HEIMDIA_SSH_PORT)}
  HEIMDIA_API_PORT=${HEIMDIA_API_PORT:-$(env_value HEIMDIA_API_PORT)}
  TZ=${TZ:-$(env_value TZ)}
  NOM=$(ask "Nom du bastion, affiché dans Portunia" "${HEIMDIA_NOM:-Heimdia}")
  while :; do
    ADMIN=$(ask "Identifiant de l'administrateur" "${HEIMDIA_ADMIN:-admin}")
    [[ "$ADMIN" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] && break
    warn "Lettres minuscules, chiffres, point, tiret ou souligné (32 caractères au plus)."
    interactive || die "Identifiant invalide : $ADMIN"
  done
  while :; do
    SSH_PORT=$(ask "Port SSH du bastion" "${HEIMDIA_SSH_PORT:-2222}")
    port_busy "$SSH_PORT" || break
    warn "Le port $SSH_PORT est déjà utilisé sur ce serveur."
    interactive || die "Port $SSH_PORT occupé"
  done
  while :; do
    API_PORT=$(ask "Port de l'API pour Portunia" "${HEIMDIA_API_PORT:-8443}")
    [ "$API_PORT" != "$SSH_PORT" ] || { warn "Choisissez un port différent du port SSH."; interactive || die "Ports identiques"; continue; }
    port_busy "$API_PORT" || break
    warn "Le port $API_PORT est déjà utilisé sur ce serveur."
    interactive || die "Port $API_PORT occupé"
  done
  local tz
  tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || true)
  ZONE=$(ask "Fuseau horaire des règles d'accès" "${TZ:-${tz:-Europe/Paris}}")
}

# Initialisation : clés, certificat, base et administrateur au mot de passe provisoire.
initialize() {
  local out
  out=$(hcmd_init 2>&1) || { echo "$out"; die "Échec de l'initialisation."; }
  PASSWORD=$(sed -n 's/.*Mot de passe provisoire : \([^ ]*\).*/\1/p' <<<"$out")
  ok "Clés, certificat et base créés"
  if [ -n "$PASSWORD" ]; then
    ok "Compte administrateur $ADMIN créé"
  else
    warn "Un administrateur existait déjà (installation précédente) : aucun compte créé."
    warn "Au besoin, créez-en un autre : sudo ./installer.sh admin <identifiant>"
    ADMIN=''
  fi
}
hcmd_init() {
  if [ "$MODE" = docker ]; then
    compose run --rm -T heimdia init --admin "$ADMIN" --provisoire --nom "$NOM"
  else
    /usr/bin/heimdia init --admin "$ADMIN" --provisoire --nom "$NOM"
  fi
}

finish() {
  save_vault_key
  open_firewall "$SSH_PORT" "$API_PORT"
  summary "$ADMIN" "$PASSWORD"
  echo
  echo "  ${Y}${B}À faire maintenant :${N} copiez la clé du coffre hors du serveur, puis effacez cette copie."
  echo "  Sans elle, une restauration perd les secrets des serveurs et les codes."
  echo "    depuis votre poste : scp $BACKUP_OWNER@$(address):$BACKUP ."
  echo "    puis sur le serveur : rm $BACKUP"
  echo
}

install_native() {
  use_mode paquet
  echo "${B}Heimdia — installation${N} ${D}(paquet Debian)${N}"
  step "Vérifications"
  check_system
  questions

  step "Installation"
  install_package
  prepare_database
  (
    umask 027
    cat >"$ENV_NATIVE" <<EOF
# Réglages de Heimdia, créés par installer.sh. Après modification : sudo systemctl restart heimdia
HEIMDIA_DATABASE_URL=postgres://_heimdia@localhost/heimdia?host=/var/run/postgresql
HEIMDIA_SSH_PORT=$SSH_PORT
HEIMDIA_API_PORT=$API_PORT
TZ=$ZONE
EOF
  )
  chgrp _heimdia "$ENV_NATIVE"
  ok "Réglages enregistrés dans $ENV_NATIVE"
  initialize
  systemctl enable --now heimdia >/dev/null 2>&1 || true
  wait_api
  ok "Bastion démarré (service heimdia, redémarre seul avec le serveur)"
  finish
}

install_with_docker() {
  use_mode docker
  [ -f "$DIR/Dockerfile" ] || die "Le mode Docker s'utilise depuis une copie du dépôt : git clone https://github.com/jpiperault/Heimdia.git"
  echo "${B}Heimdia — installation${N} ${D}(Docker, $DIR)${N}"
  step "Vérifications"
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
HEIMDIA_DB_PASSWORD=${db_password:-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')}
HEIMDIA_SSH_PORT=$SSH_PORT
HEIMDIA_API_PORT=$API_PORT
TZ=$ZONE
EOF
  )
  ok "Réglages enregistrés dans .env (mot de passe de la base généré)"
  build_image
  step "Préparation du bastion"
  initialize
  local out
  out=$(compose up -d 2>&1) || { echo "$out"; die "Le bastion ne démarre pas."; }
  wait_api
  ok "Bastion démarré (redémarre seul avec le serveur)"
  install_docker_wrapper
  ok "Commande ${B}heimdia${N} installée (ex. sudo heimdia user list)"
  finish
}

# ---------- Bastion déjà installé ----------

update() {
  echo "${B}Heimdia — mise à jour${N}"
  warn "Le bastion redémarre à la fin : les sessions ouvertes seront coupées."
  confirm "Continuer ?" || exit 0
  local before
  before=$(hcmd info | sed -n 1p)
  if [ "$MODE" = docker ]; then
    if [ -d .git ]; then
      step "Récupération de la dernière version"
      sudo -u "$(stat -c %U .)" git pull --ff-only || die "git pull a échoué."
    fi
    check_build_memory
    build_image
    local out
    out=$(compose up -d 2>&1) || { echo "$out"; die "Le bastion ne redémarre pas."; }
    install_docker_wrapper
  else
    install_package   # le paquet redémarre le service
  fi
  wait_api
  ok "Avant : $before"
  ok "Après : $(hcmd info | sed -n 1p)"
}

add_admin() {
  local login=${1:-} out
  [ -n "$login" ] || login=$(ask "Identifiant du nouvel administrateur" "")
  [ -n "$login" ] || die "Identifiant manquant."
  out=$(hcmd user add "$login" --role admin --provisoire 2>&1) || { echo "$out"; die "Compte non créé."; }
  summary "$login" "$(sed -n 's/.*Mot de passe provisoire : \([^ ]*\).*/\1/p' <<<"$out")"
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
  if command -v cloudflared >/dev/null; then ok "cloudflared déjà installé"; return; fi
  install -d -m 755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg ||
    die "Téléchargement de la clé du dépôt Cloudflare impossible."
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
    >/etc/apt/sources.list.d/cloudflared.list
  { apt-get update -qq && apt-get install -y -qq cloudflared; } >/dev/null || die "Installation de cloudflared impossible."
  ok "cloudflared installé (dépôt Cloudflare)"
}

# Tunnel sortant vers Cloudflare pour le portail web : aucun port entrant à ouvrir.
setup_portal() {
  echo "${B}Heimdia — portail web par Cloudflare Tunnel${N}"
  echo "  Dans Cloudflare Zero Trust › Networks › Tunnels, créez un tunnel « Cloudflared »,"
  echo "  puis copiez le jeton de sa commande d'installation (la longue suite après --token)."
  local token=${HEIMDIA_TUNNEL_TOKEN:-} service
  if [ -z "$token" ] && interactive; then read -r -s -p "  Jeton du tunnel : " token; echo; fi
  token=$(tr -d '[:space:]' <<<"$token")
  [ -n "$token" ] || die "Jeton du tunnel manquant."
  [[ "$token" =~ ^[A-Za-z0-9+/=_-]+$ ]] || die "Ce jeton ne ressemble pas à un jeton de tunnel Cloudflare."
  if [ "$MODE" = docker ]; then
    set_env HEIMDIA_TUNNEL_TOKEN "$token"
    set_env COMPOSE_PROFILES portail
    local out
    out=$(compose up -d 2>&1) || { echo "$out"; die "Le tunnel ne démarre pas."; }
    service=heimdia:8445
  else
    install_cloudflared
    cloudflared service uninstall >/dev/null 2>&1 || true
    cloudflared service install "$token" >/dev/null 2>&1 || die "Installation du service cloudflared impossible."
    service=localhost:8445
  fi
  ok "Tunnel installé : connexion sortante vers Cloudflare, aucun port à ouvrir"
  echo
  echo "  Dans Cloudflare, onglet « Public Hostname » du tunnel : ajoutez votre adresse"
  echo "  (ex. acces.votre-domaine.fr), type ${B}HTTP${N}, URL ${B}$service${N}."
  echo "  Puis dans Portunia : Administrer › Portail web › activez le portail."
}

menu() {
  echo "${B}Heimdia est déjà installé${N} ${D}($([ "$MODE" = docker ] && echo "Docker, $DIR" || echo "paquet Debian"))${N}"
  echo
  echo "  1) Afficher les informations pour Portunia"
  echo "  2) Mettre à jour"
  echo "  3) Créer un administrateur (mot de passe provisoire)"
  echo "  4) Installer le portail web (Cloudflare Tunnel)"
  echo "  5) Quitter"
  echo
  case $(ask "Votre choix" 1) in
    1) info ;;
    2) update ;;
    3) add_admin ;;
    4) setup_portal ;;
    *) exit 0 ;;
  esac
}

if installed_native; then
  [ "$MODE" != docker ] || die "Heimdia est déjà installé en paquet Debian sur ce serveur."
  use_mode paquet
elif installed_docker; then
  use_mode docker
  install_docker_wrapper
else
  case $ACTION in
    '') if [ "$MODE" = docker ]; then install_with_docker; else install_native; fi; exit 0 ;;
    *) die "Heimdia n'est pas installé sur ce serveur : lancez d'abord sudo $0" ;;
  esac
fi

case $ACTION in
  info) info ;;
  mise-a-jour) update ;;
  admin) add_admin "$ACTION_ARG" ;;
  portail) setup_portal ;;
  '') menu ;;
esac
