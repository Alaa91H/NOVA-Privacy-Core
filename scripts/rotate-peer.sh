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
  "$ROOT/scripts/atomic-safety-gate.sh" close peer-rotate
  load_runtime
fi

name="${1:-}"
valid_peer_name "$name" || die "invalid peer name"
peer="$(peer_path "$name")"
[[ -f "$peer" ]] || die "peer not found: $name"

load_peer_registry "$peer"
old_peer="$(mktemp)"
old_psk="$(mktemp)"
cp "$peer" "$old_peer"
cp "$PEER_PSK_FILE" "$old_psk"
rollback() {
  cp "$old_peer" "$peer"
  cp "$old_psk" "$PEER_PSK_FILE"
  "$ROOT/scripts/rebuild-awg-peers.sh" >/dev/null 2>&1 || true
  rm -f "$old_peer" "$old_psk"
}
trap rollback ERR

client_private="$(awg genkey)"
client_public="$(printf '%s\n' "$client_private" | awg pubkey)"
psk="$(awg genpsk)"
printf '%s\n' "$psk" >"$PEER_PSK_FILE"
chmod 0600 "$PEER_PSK_FILE"

python3 - "$peer" "$client_public" <<'PY'
import pathlib,sys,shlex
p=pathlib.Path(sys.argv[1]); pub=sys.argv[2]
out=[]; done=False
for line in p.read_text().splitlines():
    if line.startswith("PUBLIC_KEY="):
        out.append("PUBLIC_KEY="+shlex.quote(pub)); done=True
    else:
        out.append(line)
if not done:
    out.append("PUBLIC_KEY="+shlex.quote(pub))
p.write_text("\n".join(out)+"\n")
PY
chmod 0600 "$peer"

"$ROOT/scripts/rebuild-awg-peers.sh"
conf="$(write_client_config "$name" "$PEER_IP" "$client_private" "$psk")"

rm -f "$old_peer" "$old_psk"
trap - ERR
if [[ "$previous_gate" == "open" ]]; then
  "$ROOT/scripts/reopen-verified.sh"
fi
log "peer credentials rotated: $name"
printf 'client_config=%s\n' "$conf"
