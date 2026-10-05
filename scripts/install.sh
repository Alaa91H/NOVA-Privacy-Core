#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$SOURCE_ROOT/scripts/lib/common.sh"
require_root
load_defaults

if [[ "$SOURCE_ROOT" != "$NOVA_INSTALL_ROOT" ]]; then
  log "staging NOVA into $NOVA_INSTALL_ROOT"
  mkdir -p "$NOVA_INSTALL_ROOT"
  tar --exclude=.git --exclude=.build --exclude=dist -C "$SOURCE_ROOT" -cf - . |     tar -C "$NOVA_INSTALL_ROOT" -xf -
fi

ROOT="$NOVA_INSTALL_ROOT"
find "$ROOT/scripts" -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod 0755 {} +
chmod 0755 "$ROOT/src/privacyctl"

log "T04 bootstrap"
bash "$ROOT/scripts/bootstrap.sh"

log "T05 host hardening"
bash "$ROOT/scripts/harden.sh"

log "T06 fail-closed firewall bootstrap"
bash "$ROOT/scripts/install-firewall.sh"

log "T08 AmneziaWG installation"
bash "$ROOT/scripts/install-awg.sh"

log "T08 AmneziaWG configuration"
bash "$ROOT/scripts/configure-awg.sh" "${NOVA_AWG_MODE:-balanced}"

log "T13-T17 DNS privacy/filtering stack"
bash "$ROOT/scripts/install-dns.sh"

log "refreshing firewall after service installation"
bash "$ROOT/scripts/render-firewall.sh"

ln -sfn "$ROOT/src/privacyctl" /usr/local/bin/privacyctl

log "running host verification"
if ! "$ROOT/src/privacyctl" health; then
  die "installation completed with failed health checks"
fi

cat <<'EOF'

NOVA Privacy Core is installed.

NEXT STEPS:
  1. Create a management peer:
       sudo privacyctl peer add laptop PRIVATE --management

  2. Import /root/nova-peers/laptop.conf on that device and connect.

  3. Confirm a recent handshake:
       sudo privacyctl status

  4. From the VPN-connected management device, remove the temporary public SSH rule:
       sudo privacyctl lockdown

  5. Run:
       sudo privacyctl leaks test

Do not close your original bootstrap SSH session before step 3 succeeds.
EOF
