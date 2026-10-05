#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
require_cmd curl
require_cmd jq

latest_stable_tag() {
  local api="$1"
  curl --proto '=https' --tlsv1.2 -fsSL     --connect-timeout 10 --max-time 30 "$api" |
    jq -er '
      select(.draft == false and .prerelease == false)
      | .tag_name
    '
}

if [[ "${1:-all}" == "all" || "${1:-}" == "adguard" ]]; then
  agh="$(latest_stable_tag "https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest")"
  [[ "$agh" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    die "refusing unexpected AdGuard stable tag: $agh"
  write_runtime_kv NOVA_ADGUARD_VERSION "$agh"
  log "resolved latest stable AdGuard Home: $agh"
fi

if [[ "${1:-all}" == "all" || "${1:-}" == "nova" ]]; then
  nova="$(latest_stable_tag "https://api.github.com/repos/${NOVA_REPOSITORY}/releases/latest" 2>/dev/null || true)"
  if [[ -n "$nova" ]]; then
    [[ "$nova" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
      die "refusing unexpected NOVA stable tag: $nova"
    printf '%s\n' "$nova"
  else
    warn "no stable NOVA release is published yet"
  fi
fi
