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

name="${1:-}"
[[ -n "$name" ]] || die "usage: create-peer.sh NAME [PROFILE] [--management]"
shift || true

profile="PRIVATE"
management=0
if [[ $# -gt 0 && "$1" != --* ]]; then
  profile="$1"
  shift
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --management) management=1 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

valid_peer_name "$name" || die "invalid peer name"
valid_profile "$profile" || die "invalid profile"
[[ "$profile" != "LOCKDOWN" || "$management" -eq 0 ]] || die "management peer cannot be created locked down"

mkdir -p "$NOVA_ETC/peers.d" "$NOVA_ETC/peer-secrets"
peer="$(peer_path "$name")"
[[ ! -e "$peer" ]] || die "peer already exists: $name"

ip="$(allocate_peer_ip "$management")"
secret_dir="$(peer_secret_dir "$name")"
install -d -m 0700 "$secret_dir"

client_private="$(awg genkey)"
client_public="$(printf '%s\n' "$client_private" | awg pubkey)"
psk="$(awg genpsk)"
printf '%s\n' "$psk" >"$secret_dir/psk"
chmod 0600 "$secret_dir/psk"

cat >"$peer" <<EOF
NAME=$(printf '%q' "$name")
IP=$(printf '%q' "$ip")
PROFILE=$(printf '%q' "$profile")
MANAGEMENT=$management
PUBLIC_KEY=$(printf '%q' "$client_public")
PSK_FILE=$(printf '%q' "$secret_dir/psk")
EOF
chmod 0600 "$peer"

rollback() {
  rm -f "$peer"
  rm -rf "$secret_dir"
}
trap rollback ERR

"$ROOT/scripts/render-firewall.sh"
"$ROOT/scripts/rebuild-awg-peers.sh"
conf="$(write_client_config "$name" "$ip" "$client_private" "$psk")"

trap - ERR
log "peer created: $name ($ip, $profile)"
printf 'client_config=%s\n' "$conf"
