#!/usr/bin/env bash
# Vérifie les fonctions sans effet du durcissement (installer.sh), sans toucher au système :
#   bash tests/durcissement.sh
set -euo pipefail
cd "$(dirname "$0")/.."

source <(sed -n '/^# >>> fonctions testables$/,/^# <<< fonctions testables$/p' installer.sh)

fails=0
check() {
  if "$@"; then echo "ok    $*"; else echo "ÉCHEC $*"; fails=$((fails + 1)); fi
}
keeps() { harden_keeps "$1"; }
stops() { ! harden_keeps "$1"; }
has() { grep -qF -- "$2" <<<"$1"; }
lacks() { ! grep -qF -- "$2" <<<"$1"; }

# Ce sans quoi le serveur ou la Gate ne tourne plus.
for unit in ssh.service ssh.socket sshd.service portunia-gate.service portunia-gate-pare-feu.service postgresql.service \
  postgresql@17-main.service docker.service docker.socket containerd.service cloudflared.service systemd-networkd.service \
  systemd-resolved.service systemd-timesyncd.service dbus.service getty@.service networking.service NetworkManager.service \
  cron.service rsyslog.service chrony.service qemu-guest-agent.service cloud-init.service unattended-upgrades.service nftables.service; do
  check keeps "$unit"
done
# Ce qui n'a rien à faire sur une Gate.
for unit in avahi-daemon.service avahi-daemon.socket cups.service cups.socket rpcbind.service rpcbind.socket bluetooth.service \
  apache2.service nginx.service smbd.service postfix.service ModemManager.service vsftpd.service snmpd.service telnet.socket; do
  check stops "$unit"
done

rules=$(harden_nft_rules 22 2222,8443)
check has "$rules" 'policy drop'
check has "$rules" 'tcp dport { 22 } ct state new limit rate'
check has "$rules" 'tcp dport { 2222,8443 } accept'
check has "$rules" 'ct state established,related accept'
check has "$rules" 'iif lo accept'
check lacks "$rules" 'flush ruleset'

with_key=$(harden_sshd_conf cle)
without=$(harden_sshd_conf mot-de-passe)
check has "$with_key" 'PasswordAuthentication no'
check lacks "$without" 'PasswordAuthentication'
check lacks "$without" 'PermitRootLogin'
check has "$without" 'X11Forwarding no'

[ "$fails" = 0 ] && echo "Tout est bon." || { echo "$fails échec(s)"; exit 1; }
