#!/bin/sh
# Commande heimdia (paquet Debian) : administre la Gate sous son compte de service,
# avec les réglages de /etc/heimdia/heimdia.env.
if [ "$(id -u)" -ne 0 ]; then exec sudo -- "$0" "$@"; fi
if [ ! -r /etc/heimdia/heimdia.env ]; then
  echo "Portunia Gate n'est pas encore configuré : lancez l'assistant d'installation (installer.sh)." >&2
  exit 1
fi
set -a
. /etc/heimdia/heimdia.env
set +a
exec runuser -u _heimdia -- /usr/lib/heimdia/heimdia "$@"
