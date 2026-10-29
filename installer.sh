#!/usr/bin/env bash
# Assistant d'installation de Heimdia (Debian 12/13, Ubuntu 22.04 et suivantes).
#
#   ./installer.sh               première installation, ou menu si Heimdia est déjà installé
#   ./installer.sh info          informations à saisir dans Portunia
#   ./installer.sh mise-a-jour   reconstruit et redémarre le bastion
#   ./installer.sh admin LOGIN   crée un administrateur de secours (mot de passe provisoire)
#
# Sans terminal (automatisation), les réponses viennent des variables HEIMDIA_NOM, HEIMDIA_ADMIN,
# HEIMDIA_SSH_PORT, HEIMDIA_API_PORT et TZ, ou des valeurs par défaut.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"
DIR=$PWD
WRAPPER=/usr/local/bin/heimdia

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

if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || die "Lancez l'assistant en root."
  exec sudo --preserve-env=HEIMDIA_NOM,HEIMDIA_ADMIN,HEIMDIA_SSH_PORT,HEIMDIA_API_PORT,TZ -- "$0" "$@"
fi

env_value() { [ ! -f .env ] || sed -n "s/^$1=//p" .env | tail -n1; }
address() { hostname -I 2>/dev/null | awk '{print $1}'; }
compose() { docker compose "$@"; }
installed() { [ -f .env ] && compose ps -a --format '{{.Service}}' 2>/dev/null | grep -qx heimdia; }

# ---------- Prérequis ----------

install_docker() {
  command -v apt-get >/dev/null || die "Installez Docker et Docker Compose (https://docs.docker.com/engine/install/), puis relancez l'assistant."
  confirm "Docker n'est pas installé. L'installer depuis les paquets de la distribution ?" || die "Docker est nécessaire."
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
    ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo présent), $(docker compose version --short 2>/dev/null | sed 's/^/Compose /')"
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

# Mémoire pour la compilation : un fichier d'échange temporaire si elle manque.
SWAPFILE=''
check_resources() {
  local mem swap cpus disk
  mem=$(awk '/^MemTotal/{print int($2/1024)}' /proc/meminfo)
  swap=$(awk '/^SwapTotal/{print int($2/1024)}' /proc/meminfo)
  cpus=$(nproc)
  disk=$(df -Pm "$DIR" | awk 'NR==2{print int($4/1024)}')
  ok "$cpus processeur(s), $((mem / 1024)) Go de mémoire, $disk Go de disque libre"
  [ "$disk" -ge 8 ] || warn "Moins de 8 Go libres : la compilation et les enregistrements risquent de manquer de place."
  [ "$cpus" -ge 2 ] || warn "Un seul processeur : la compilation prendra 20 à 30 minutes."
  if [ $((mem + swap)) -lt 3500 ]; then
    warn "Mémoire faible pour compiler (il faut environ 3,5 Go, mémoire et échange compris)."
    if [ "$(systemd-detect-virt -c 2>/dev/null)" = none ] && confirm "Ajouter un fichier d'échange de 2 Go le temps de la compilation ?"; then
      SWAPFILE=/heimdia-compilation.swap
      fallocate -l 2G "$SWAPFILE" && chmod 600 "$SWAPFILE" && mkswap -q "$SWAPFILE" && swapon "$SWAPFILE" &&
        ok "Fichier d'échange temporaire ajouté" || { warn "Impossible d'ajouter le fichier d'échange"; rm -f "$SWAPFILE"; SWAPFILE=''; }
    fi
  fi
}
remove_swap() {
  if [ -n "$SWAPFILE" ]; then swapoff "$SWAPFILE" 2>/dev/null || true; rm -f "$SWAPFILE"; fi
}
trap remove_swap EXIT

port_busy() { ss -Hltn "sport = :$1" 2>/dev/null | grep -q .; }

# ---------- Étapes communes ----------

build() {
  step "Compilation de Heimdia ${D}(10 à 30 minutes la première fois)${N}"
  if ! compose build; then
    die "La compilation a échoué. Manque de mémoire ? Voir docs/exploitation.md, section Dépannage."
  fi
  remove_swap
  SWAPFILE=''
  ok "Image construite"
}

install_wrapper() {
  cat >"$WRAPPER" <<EOF
#!/bin/sh
# Commande heimdia du serveur : relaie vers le bastion dans son conteneur ($DIR).
# Installée par installer.sh.
# .env (mot de passe de la base) n'est lisible que par root.
if [ "\$(id -u)" -ne 0 ]; then exec sudo -- "\$0" "\$@"; fi
cd "$DIR" || exit 1
if ! docker compose ps --status running --format '{{.Service}}' | grep -qx heimdia; then
  echo "Le bastion est arrêté. Démarrez-le : cd $DIR && docker compose up -d" >&2
  exit 1
fi
if [ -t 0 ]; then exec docker compose exec heimdia heimdia "\$@"; fi
exec docker compose exec -T heimdia heimdia "\$@"
EOF
  chmod 755 "$WRAPPER"
}

save_vault_key() {
  install -d -m 700 sauvegarde
  compose cp heimdia:/var/lib/heimdia/coffre.key sauvegarde/coffre.key >/dev/null 2>&1 ||
    die "Copie de la clé du coffre impossible : docker compose cp heimdia:/var/lib/heimdia/coffre.key ."
  chmod 600 sauvegarde/coffre.key
  # Copie au nom de celui qui a lancé sudo, pour qu'il la récupère par scp sans passer par root.
  chown -R "$BACKUP_OWNER" sauvegarde
}
BACKUP_OWNER=${SUDO_USER:-root}

wait_api() {
  local port
  port=$(env_value HEIMDIA_API_PORT)
  for _ in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port:-8443}") 2>/dev/null; then return 0; fi
    sleep 1
  done
  die "Le bastion ne répond pas sur le port ${port:-8443} : docker compose logs heimdia"
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
  fingerprint=$(compose exec -T heimdia heimdia info | awk '/^Certificat de l/{print $NF}')
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

first_install() {
  echo "${B}Heimdia — installation${N} ${D}($DIR)${N}"
  step "Vérifications"
  check_docker
  check_resources

  step "Configuration ${D}(Entrée pour garder la valeur proposée)${N}"
  local nom admin ssh_port api_port tz db_password
  # Installation interrompue : on reprend ses réglages, et surtout le mot de passe de la base déjà créée.
  db_password=$(env_value HEIMDIA_DB_PASSWORD)
  [ -z "$db_password" ] || ok "Reprise de l'installation précédente (.env existant)"
  HEIMDIA_SSH_PORT=${HEIMDIA_SSH_PORT:-$(env_value HEIMDIA_SSH_PORT)}
  HEIMDIA_API_PORT=${HEIMDIA_API_PORT:-$(env_value HEIMDIA_API_PORT)}
  TZ=${TZ:-$(env_value TZ)}
  nom=$(ask "Nom du bastion, affiché dans Portunia" "${HEIMDIA_NOM:-Heimdia}")
  while :; do
    admin=$(ask "Identifiant de l'administrateur" "${HEIMDIA_ADMIN:-admin}")
    [[ "$admin" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] && break
    warn "Lettres minuscules, chiffres, point, tiret ou souligné (32 caractères au plus)."
    interactive || die "Identifiant invalide : $admin"
  done
  while :; do
    ssh_port=$(ask "Port SSH du bastion" "${HEIMDIA_SSH_PORT:-2222}")
    port_busy "$ssh_port" || break
    warn "Le port $ssh_port est déjà utilisé sur ce serveur."
    interactive || die "Port $ssh_port occupé"
  done
  while :; do
    api_port=$(ask "Port de l'API pour Portunia" "${HEIMDIA_API_PORT:-8443}")
    port_busy "$api_port" || break
    warn "Le port $api_port est déjà utilisé sur ce serveur."
    interactive || die "Port $api_port occupé"
  done
  tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || true)
  tz=$(ask "Fuseau horaire des règles d'accès" "${TZ:-${tz:-Europe/Paris}}")

  (
    umask 077
    cat >.env <<EOF
# Créé par installer.sh le $(date '+%d/%m/%Y'). Modifiez puis : docker compose up -d
HEIMDIA_DB_PASSWORD=${db_password:-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')}
HEIMDIA_SSH_PORT=$ssh_port
HEIMDIA_API_PORT=$api_port
TZ=$tz
EOF
  )
  ok "Réglages enregistrés dans .env (mot de passe de la base généré)"

  build

  step "Préparation du bastion"
  local out password
  out=$(compose run --rm -T heimdia init --admin "$admin" --provisoire --nom "$nom" 2>&1) || { echo "$out"; die "Échec de l'initialisation."; }
  password=$(sed -n 's/.*Mot de passe provisoire : \([^ ]*\).*/\1/p' <<<"$out")
  ok "Clés, certificat et base créés"
  if [ -n "$password" ]; then
    ok "Compte administrateur $admin créé"
  else
    warn "Un administrateur existait déjà (installation précédente) : aucun compte créé."
    warn "Au besoin, créez-en un autre : ./installer.sh admin <identifiant>"
    admin=''
  fi
  out=$(compose up -d 2>&1) || { echo "$out"; die "Le bastion ne démarre pas."; }
  wait_api
  ok "Bastion démarré (redémarre seul avec le serveur)"
  install_wrapper
  ok "Commande ${B}heimdia${N} installée (ex. heimdia user list)"
  save_vault_key
  open_firewall "$ssh_port" "$api_port"

  summary "$admin" "$password"
  echo
  echo "  ${Y}${B}À faire maintenant :${N} copiez la clé du coffre hors du serveur, puis effacez cette copie."
  echo "  Sans elle, une restauration perd les secrets des serveurs et les codes."
  echo "    depuis votre poste : scp $BACKUP_OWNER@$(address):$DIR/sauvegarde/coffre.key ."
  echo "    puis sur le serveur : rm $DIR/sauvegarde/coffre.key"
  echo
}

# ---------- Bastion déjà installé ----------

update() {
  echo "${B}Heimdia — mise à jour${N}"
  warn "Le bastion redémarre à la fin : les sessions ouvertes seront coupées."
  confirm "Continuer ?" || exit 0
  if [ -d .git ]; then
    step "Récupération de la dernière version"
    sudo -u "$(stat -c %U .)" git pull --ff-only || die "git pull a échoué."
  fi
  check_resources
  build
  local out
  out=$(compose up -d 2>&1) || { echo "$out"; die "Le bastion ne redémarre pas."; }
  wait_api
  install_wrapper
  ok "Bastion à jour : $(compose exec -T heimdia heimdia info | head -n1)"
}

add_admin() {
  local login=${1:-}
  [ -n "$login" ] || login=$(ask "Identifiant du nouvel administrateur" "")
  [ -n "$login" ] || die "Identifiant manquant."
  local out
  out=$(compose exec -T heimdia heimdia user add "$login" --role admin --provisoire 2>&1) || { echo "$out"; die "Compte non créé."; }
  summary "$login" "$(sed -n 's/.*Mot de passe provisoire : \([^ ]*\).*/\1/p' <<<"$out")"
}

info() {
  compose exec -T heimdia heimdia info | sed 's/^/  /'
  summary
}

menu() {
  echo "${B}Heimdia est déjà installé${N} ${D}($DIR)${N}"
  echo
  echo "  1) Afficher les informations pour Portunia"
  echo "  2) Mettre à jour"
  echo "  3) Créer un administrateur (mot de passe provisoire)"
  echo "  4) Quitter"
  echo
  case $(ask "Votre choix" 1) in
    1) info ;;
    2) update ;;
    3) add_admin ;;
    *) exit 0 ;;
  esac
}

case ${1:-} in
  info) installed || die "Heimdia n'est pas installé ici."; install_wrapper; info ;;
  mise-a-jour) installed || die "Heimdia n'est pas installé ici."; update ;;
  admin) installed || die "Heimdia n'est pas installé ici."; add_admin "${2:-}" ;;
  '')
    if installed; then
      check_docker >/dev/null
      install_wrapper
      menu
    else
      first_install
    fi
    ;;
  *) die "Usage : $0 [info | mise-a-jour | admin IDENTIFIANT]" ;;
esac
