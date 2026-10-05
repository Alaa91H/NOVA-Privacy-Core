#!/usr/bin/env bash
set -Eeuo pipefail

hostport="${1:-}"
[[ -n "$hostport" ]] || { echo "usage: verify-pqtls.sh HOST:PORT" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL is required" >&2; exit 2; }

if ! openssl list -tls-groups 2>/dev/null | tr ' ' '\n' | grep -qx 'X25519MLKEM768'; then
  echo "local OpenSSL does not expose X25519MLKEM768; cannot verify PQ/T negotiation" >&2
  exit 3
fi

host="$hostport"
host="${host#[}"
host="${host%]}"
server_name="${NOVA_PQTLS_SNI:-${hostport%%:*}}"

out="$(timeout 15 openssl s_client   -connect "$hostport"   -servername "$server_name"   -tls1_3   -groups X25519MLKEM768   -brief < /dev/null 2>&1 || true)"

printf '%s\n' "$out"

if printf '%s\n' "$out" | grep -qi 'X25519MLKEM768'; then
  echo "PASS: X25519MLKEM768 appears in the negotiated TLS session evidence."
  exit 0
fi

echo "FAIL: no verified X25519MLKEM768 negotiation evidence." >&2
exit 1
