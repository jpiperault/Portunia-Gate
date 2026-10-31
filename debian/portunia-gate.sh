#!/bin/sh
# Commande portunia-gate (paquet Debian) : administre la Gate sous son compte de service,
# avec les réglages de /etc/portunia-gate/portunia-gate.env.
if [ "$(id -u)" -ne 0 ]; then exec sudo -- "$0" "$@"; fi
if [ ! -r /etc/portunia-gate/portunia-gate.env ]; then
  echo "Portunia Gate n'est pas encore configurée : lancez l'assistant d'installation (installer.sh)." >&2
  exit 1
fi
set -a
. /etc/portunia-gate/portunia-gate.env
set +a
exec runuser -u _portunia_gate -- /usr/lib/portunia-gate/portunia-gate "$@"
