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

# The early firewall reads the persisted closed gate.  The common reopen helper
# verifies the new kernel, OS/security baseline, services, leak controls and
# final OPEN-state acceptance before committing the transition.
"$ROOT/scripts/reopen-verified.sh"
rm -f "$marker"
log "post-boot validation passed"
