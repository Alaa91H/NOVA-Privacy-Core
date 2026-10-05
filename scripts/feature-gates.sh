#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
load_runtime
# shellcheck disable=SC1091
source "$ROOT/config/features.env"

status=0

show_binary() {
  local name="$1" cmd="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    local line
    line="$("$cmd" version 2>&1 | head -n1 || true)"
    [[ -n "$line" ]] || line="$("$cmd" --version 2>&1 | head -n1 || true)"
    printf 'AVAILABLE  %-12s %s\n' "$name" "${line:-version-unknown}"
  else
    printf 'ABSENT     %-12s\n' "$name"
  fi
}

require_feature_binary() {
  local state="$1" label="$2" binary="$3"
  [[ "$state" == "enabled" ]] || return 0
  if ! command -v "$binary" >/dev/null 2>&1; then
    printf 'FAIL %-12s marked enabled but %s is unavailable\n' "$label" "$binary" >&2
    status=1
  fi
}

printf 'Configured optional-feature states:\n'
printf '  MASQUE:      %s\n' "$NOVA_FEATURE_MASQUE"
printf '  NaiveProxy:  %s\n' "$NOVA_FEATURE_NAIVE"
printf '  Hysteria2:   %s\n' "$NOVA_FEATURE_HYSTERIA2"
printf '  TOR-ANON:    %s\n' "$NOVA_FEATURE_TOR_ANON"
printf '  MAX-MIX:     %s\n' "$NOVA_FEATURE_MAX_MIX"
printf '\nRuntime capability discovery:\n'
show_binary "sing-box" sing-box
show_binary "naive" naive
show_binary "hysteria" hysteria
show_binary "tor" tor
show_binary "nym-vpn" nym-vpn

require_feature_binary "$NOVA_FEATURE_MASQUE" "MASQUE" sing-box
require_feature_binary "$NOVA_FEATURE_NAIVE" "NaiveProxy" naive
require_feature_binary "$NOVA_FEATURE_HYSTERIA2" "Hysteria2" hysteria

if [[ "$NOVA_FEATURE_TOR_ANON" != "client" ]]; then
  printf 'FAIL TOR-ANON must remain client-originated in the v1 trust model\n' >&2
  status=1
fi
if [[ "$NOVA_FEATURE_MAX_MIX" != "client" ]]; then
  printf 'FAIL MAX-MIX must remain client-originated in the v1 trust model\n' >&2
  status=1
fi

cat <<'EOF'

Feature gates do not equate “binary present” with “privacy verified”.
Activation additionally requires:
- valid TLS identity/domain where the transport requires one;
- server/client interoperability;
- fail-closed routing test;
- memory/CPU benchmark;
- DPI/transport behavior review;
- post-quantum handshake evidence if that profile is labelled PQ/T.

No optional transport may silently downgrade to direct egress.
EOF

exit "$status"
