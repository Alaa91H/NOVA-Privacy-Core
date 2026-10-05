#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

mode="${1:---dry-run}"
case "$mode" in
  --dry-run|--execute) ;;
  *) die "usage: failure-injection.sh [--dry-run|--execute]" ;;
esac

steps=(
  "stop PRIVATE AdGuard; verify PRIVATE DNS fails closed; restart"
  "stop Unbound; verify gateway DNS fails rather than using ISP DNS; restart"
  "stop AWG; verify physical client lockdown blocks all traffic; restart"
  "reboot host; verify nova-firewall loads before network and protected clients reconnect"
)

if [[ "$mode" == "--dry-run" ]]; then
  printf 'NOVA failure-injection plan (no changes made):\n'
  printf ' - %s\n' "${steps[@]}"
  cat <<'EOF'

Execution is intentionally blocked unless:
  NOVA_OOB_CONFIRMED=1
is set and you have an Oracle Console/serial/out-of-band path.

The AWG test can sever the very management path used to run it. Run client-side
traffic observation from a second device while executing.
EOF
  exit 0
fi

[[ "${NOVA_OOB_CONFIRMED:-0}" == "1" ]] ||
  die "refusing destructive test without NOVA_OOB_CONFIRMED=1"
[[ -t 0 ]] || die "destructive test requires an interactive terminal"

printf 'Type EXACTLY: INJECT-FAILURES\n> '
read -r confirm
[[ "$confirm" == "INJECT-FAILURES" ]] || die "confirmation mismatch"

restore_services() {
  systemctl start unbound.service nova-adguard-private.service nova-adguard-strict.service nova-awg.service 2>/dev/null || true
}
trap restore_services EXIT INT TERM

log "phase 1: PRIVATE AdGuard failure"
systemctl stop nova-adguard-private.service
sleep 2
if dig +time=2 +tries=1 @"${NOVA_VPN_ADDR%/*}" -p "$NOVA_ADGUARD_PRIVATE_PORT" example.com A >/dev/null 2>&1; then
  die "PRIVATE DNS unexpectedly answered while its service was stopped"
fi
systemctl start nova-adguard-private.service

log "phase 2: Unbound failure"
systemctl stop unbound.service
sleep 2
if dig +time=2 +tries=1 @"${NOVA_VPN_ADDR%/*}" -p "$NOVA_ADGUARD_PRIVATE_PORT" example.com A >/dev/null 2>&1; then
  die "DNS unexpectedly resolved while Unbound was stopped"
fi
systemctl start unbound.service

cat <<'EOF'

Server-local DNS failure tests passed.

AWG failure and reboot tests require simultaneous observation from a physical
client. For safety, this script does not automatically stop AWG or reboot.
Run these two controlled actions from the Oracle Console while watching the
client:
  systemctl stop nova-awg.service
  systemctl start nova-awg.service
  systemctl reboot

Record whether the protected client can send ANY packet directly while AWG is
down. It must not.
EOF
