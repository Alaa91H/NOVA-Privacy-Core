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
new_stripped="$(mktemp "$NOVA_ETC/.awg-new.XXXXXX")"
old_stripped="$(mktemp "$NOVA_ETC/.awg-old.XXXXXX")"
trap 'rm -f "$candidate" "$new_stripped" "$old_stripped"' EXIT

awk '/^# BEGIN NOVA PEERS$/{exit} {print}' "$conf" >"$candidate"
printf '\n# BEGIN NOVA PEERS\n' >>"$candidate"

shopt -s nullglob
for f in "$NOVA_ETC"/peers.d/*.env; do
  load_peer_registry "$f"
  cat >>"$candidate" <<EOF

# NOVA_PEER:$PEER_NAME
[Peer]
PublicKey = $PEER_PUBLIC_KEY
PresharedKey = $(cat "$PEER_PSK_FILE")
AllowedIPs = $PEER_IP/32
EOF
done

chmod 0600 "$candidate"
awg-quick strip "$candidate" >"$new_stripped"
chmod 0600 "$new_stripped"

active=0
if ip link show "$NOVA_VPN_IF" >/dev/null 2>&1; then
  active=1
  awg-quick strip "$conf" >"$old_stripped"
  chmod 0600 "$old_stripped"

  # Apply to the live interface first.  If netlink/config validation fails,
  # the persistent file remains untouched.
  awg syncconf "$NOVA_VPN_IF" "$new_stripped" ||
    die "failed to apply AWG peer transaction; persistent config unchanged"
fi

if ! mv -f "$candidate" "$conf"; then
  if [[ "$active" -eq 1 && -s "$old_stripped" ]]; then
    awg syncconf "$NOVA_VPN_IF" "$old_stripped" >/dev/null 2>&1 || true
  fi
  die "failed to commit AWG peer config; live state rolled back where possible"
fi
chmod 0600 "$conf"

log "AWG peer set rebuilt transactionally"
