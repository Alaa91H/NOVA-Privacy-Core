#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
acquire_nova_lock

apt-get clean
systemd-tmpfiles --clean || true
journalctl --vacuum-time=1d --vacuum-size=32M >/dev/null 2>&1 || true

rollback="$NOVA_STATE/rollback"
if [[ -d "$rollback" ]]; then
  # Keep the two newest source rollback archives only.
  mapfile -t old < <(find "$rollback" -maxdepth 1 -type f -name 'source-*.tar.gz'     -printf '%T@ %p\n' | sort -nr | awk 'NR>2 {$1=""; sub(/^ /,""); print}')
  (("${#old[@]}" == 0)) || rm -f -- "${old[@]}"
fi

find /var/tmp -xdev -type f -mtime +7 -delete 2>/dev/null || true
log "periodic cleanup completed"
