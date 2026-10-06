#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
# shellcheck source=scripts/lib/peer.sh
source "$ROOT/scripts/lib/peer.sh"
require_root
load_runtime
acquire_nova_lock

previous_gate="${NOVA_TRAFFIC_GATE:-closed}"
if [[ "$previous_gate" == "open" ]]; then
  "$ROOT/scripts/atomic-safety-gate.sh" close peer-revoke
  load_runtime
fi

name="${1:-}"
valid_peer_name "$name" || die "invalid peer name"
peer="$(peer_path "$name")"
[[ -f "$peer" ]] || die "peer not found: $name"

disabled="$peer.disabled"
mv "$peer" "$disabled"
restore() {
  mv -f "$disabled" "$peer" 2>/dev/null || true
  "$ROOT/scripts/rebuild-awg-peers.sh" >/dev/null 2>&1 || true
  "$ROOT/scripts/render-firewall.sh" >/dev/null 2>&1 || true
}
trap restore ERR

"$ROOT/scripts/rebuild-awg-peers.sh"
"$ROOT/scripts/render-firewall.sh"

rm -f "$disabled"
rm -rf "$(peer_secret_dir "$name")"
rm -f "/root/nova-peers/$name.conf" "/root/nova-peers/$name.qr.png"
trap - ERR
if [[ "$previous_gate" == "open" ]]; then
  "$ROOT/scripts/reopen-verified.sh"
fi

log "peer revoked: $name"
