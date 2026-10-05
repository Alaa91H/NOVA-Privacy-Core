#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
acquire_nova_lock
require_cmd awg
require_cmd awg-quick

conf="$NOVA_ETC/${NOVA_VPN_IF}.conf"
[[ -s "$conf" ]] || die "AWG config missing: $conf"

candidate="$(mktemp "$NOVA_ETC/.awg.XXXXXX")"
trap 'rm -f "$candidate"' EXIT

awk '/^# BEGIN NOVA PEERS$/{exit} {print}' "$conf" >"$candidate"
printf '\n# BEGIN NOVA PEERS\n' >>"$candidate"

shopt -s nullglob
for f in "$NOVA_ETC"/peers.d/*.env; do
  unset NAME IP PROFILE MANAGEMENT PUBLIC_KEY PSK_FILE
  # shellcheck disable=SC1090
  source "$f"
  [[ -n "${NAME:-}" && -n "${IP:-}" && -n "${PUBLIC_KEY:-}" && -n "${PSK_FILE:-}" ]] || die "invalid peer registry: $f"
  [[ -r "$PSK_FILE" ]] || die "missing PSK for peer $NAME"
  cat >>"$candidate" <<EOF

# NOVA_PEER:$NAME
[Peer]
PublicKey = $PUBLIC_KEY
PresharedKey = $(cat "$PSK_FILE")
AllowedIPs = $IP/32
EOF
done

chmod 0600 "$candidate"
awg-quick strip "$candidate" >/dev/null
mv -f "$candidate" "$conf"

if ip link show "$NOVA_VPN_IF" >/dev/null 2>&1; then
  awg syncconf "$NOVA_VPN_IF" <(awg-quick strip "$conf")
fi

log "AWG peer set rebuilt atomically"
