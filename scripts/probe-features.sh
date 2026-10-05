#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
load_defaults

printf 'NOVA optional-feature capability probe\n\n'

probe_cmd() {
  local name="$1" cmd="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    printf 'AVAILABLE  %-18s %s\n' "$name" "$(command -v "$cmd")"
  else
    printf 'MISSING    %-18s\n' "$name"
  fi
}

probe_cmd "sing-box/MASQUE" sing-box
probe_cmd "NaiveProxy" naive
probe_cmd "Hysteria 2" hysteria
probe_cmd "Tor" tor
probe_cmd "Nym" nym-cli

if command -v sing-box >/dev/null 2>&1; then
  version="$(sing-box version 2>/dev/null | head -n1 || true)"
  printf 'INFO       sing-box version   %s\n' "${version:-unknown}"
  if sing-box help 2>/dev/null | grep -qi masque; then
    printf 'INFO       MASQUE keyword visible in sing-box help\n'
  else
    printf 'INFO       verify MASQUE endpoint support with current >=1.15 docs/config parser\n'
  fi
fi

if command -v openssl >/dev/null 2>&1; then
  printf 'INFO       OpenSSL            %s\n' "$(openssl version)"
  if openssl list -tls1_3 -tls-groups 2>/dev/null | grep -qi 'X25519MLKEM768'; then
    printf 'AVAILABLE  TLS X25519MLKEM768 locally advertised\n'
  else
    printf 'UNVERIFIED TLS X25519MLKEM768 not advertised by local OpenSSL\n'
  fi
fi

cat <<'EOF'

A capability probe is not an acceptance result.

T24 MASQUE passes only after a real client/server CONNECT-IP tunnel is verified.
T25 PQ/TLS passes only after captured/verified negotiation shows X25519MLKEM768
(or another explicitly approved standardized hybrid group).
T26 ECH passes only after a supporting client+destination test confirms ECH.
T27/T28 require real network benchmarks.
T29/T30 belong on the endpoint: Tor/Nym should originate before Oracle for the
zero-trust anonymity modes.
EOF
