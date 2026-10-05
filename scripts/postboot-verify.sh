#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
acquire_nova_lock

marker="$NOVA_STATE/maintenance/reopen-after-boot"
[[ -f "$marker" ]] || exit 0

# The early firewall reads the persisted closed gate.  Only reopen after every
# local privacy/security invariant is proven again on the newly booted kernel.
"$ROOT/src/privacyctl" health
"$ROOT/scripts/verify-leaks.sh"

write_runtime_kv NOVA_TRAFFIC_GATE open
NOVA_TRAFFIC_GATE=open "$ROOT/scripts/render-firewall.sh"
rm -f "$marker"
log "post-boot validation passed; protected forwarding reopened"
