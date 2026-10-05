#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
require_cmd curl
require_cmd python3

state_dir="$NOVA_STATE/doh"
current="$state_dir/doh-ipv4.txt"
tmp="$(mktemp)"
validated="$(mktemp)"
trap 'rm -f "$tmp" "$validated"' EXIT
install -d -m 0755 "$state_dir"

curl --proto '=https' --tlsv1.2 -fsSL   --connect-timeout 10 --max-time 60   "$NOVA_HAGEZI_DOH_IPS" -o "$tmp"

python3 - "$tmp" "$validated" <<'PY'
import ipaddress, pathlib, sys
src=pathlib.Path(sys.argv[1])
dst=pathlib.Path(sys.argv[2])
ips=set()
for n,raw in enumerate(src.read_text(errors="strict").splitlines(),1):
    s=raw.strip()
    if not s or s.startswith("#"):
        continue
    try:
        ip=ipaddress.ip_address(s)
    except ValueError as exc:
        raise SystemExit(f"invalid IP entry on line {n}: {s!r}") from exc
    if ip.version != 4:
        raise SystemExit(f"non-IPv4 entry on line {n}: {s!r}")
    ips.add(ip)
if len(ips) < 100:
    raise SystemExit(f"refusing suspiciously small encrypted-DNS IP list: {len(ips)} entries")
ordered=sorted(ips, key=int)
dst.write_text("\n".join(map(str, ordered))+"\n")
print(f"validated {len(ordered)} encrypted-DNS IPv4 addresses")
PY

chmod 0644 "$validated"
if [[ -s "$current" ]] && cmp -s "$current" "$validated"; then
  log "encrypted-DNS IP set unchanged"
  exit 0
fi

install -m 0644 "$validated" "$current"

# Re-render only after a complete, validated list has replaced the previous
# snapshot.  If download/validation fails, set -e preserves the last good set.
if nft list table inet nova >/dev/null 2>&1; then
  "$ROOT/scripts/render-firewall.sh"
fi

log "encrypted-DNS IP set updated"
