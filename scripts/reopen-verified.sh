#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
acquire_nova_lock

[[ -z "${NOVA_BOOTSTRAP_SSH_CIDR:-}" ]] ||
  die "refusing automatic reopen while public bootstrap SSH is configured"
[[ ! -e /var/run/reboot-required ]] ||
  die "refusing automatic reopen while reboot is pending"

"$ROOT/scripts/live-acceptance.sh" preflight
"$ROOT/src/privacyctl" health
"$ROOT/scripts/verify-leaks.sh"

rollback() {
  warn "post-change acceptance failed; forcing protected forwarding CLOSED"
  write_runtime_kv NOVA_TRAFFIC_GATE closed
  NOVA_TRAFFIC_GATE=closed "$ROOT/scripts/render-firewall.sh" >/dev/null 2>&1 || true
}
trap rollback ERR

write_runtime_kv NOVA_TRAFFIC_GATE open
NOVA_TRAFFIC_GATE=open "$ROOT/scripts/render-firewall.sh"
"$ROOT/scripts/live-acceptance.sh" server

trap - ERR
log "all post-change acceptance gates passed; protected forwarding OPEN"
