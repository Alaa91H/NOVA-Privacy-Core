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
profile="${2:-}"
valid_peer_name "$name" || die "invalid peer name"
valid_profile "$profile" || die "invalid profile"
peer="$(peer_path "$name")"
[[ -f "$peer" ]] || die "peer not found: $name"

MANAGEMENT=0
# shellcheck disable=SC1090
source "$peer"
if [[ "$profile" == "LOCKDOWN" && "${MANAGEMENT:-0}" == "1" ]]; then
  die "management peers cannot be placed in LOCKDOWN; revoke management access explicitly instead"
fi

old="$(mktemp)"
cp "$peer" "$old"
trap 'cp "$old" "$peer"; rm -f "$old"' ERR

python3 - "$peer" "$profile" <<'PY'
import pathlib,sys,shlex
p=pathlib.Path(sys.argv[1]); profile=sys.argv[2]
lines=p.read_text().splitlines()
out=[]; done=False
for line in lines:
    if line.startswith("PROFILE="):
        out.append("PROFILE="+shlex.quote(profile)); done=True
    else:
        out.append(line)
if not done:
    out.append("PROFILE="+shlex.quote(profile))
p.write_text("\n".join(out)+"\n")
PY
chmod 0600 "$peer"

"$ROOT/scripts/render-firewall.sh"
rm -f "$old"
trap - ERR
log "profile updated: $name -> $profile"
