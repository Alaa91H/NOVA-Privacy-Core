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
require_cmd unbound-checkconf
id nova-dns >/dev/null 2>&1 || die "nova-dns user missing; run bootstrap first"

vpn_ip="${NOVA_VPN_ADDR%/*}"
mgmt_ip="${NOVA_MGMT_ADDR%/*}"

mkdir -p "$NOVA_ETC/unbound" "$NOVA_ETC/adguard" "$NOVA_STATE/dns/private" "$NOVA_STATE/dns/strict"
chown -R nova-dns:nova-dns "$NOVA_STATE/dns"
chmod 0700 "$NOVA_STATE/dns/private" "$NOVA_STATE/dns/strict"

export VPN_IP="$vpn_ip"
export MGMT_IP="$mgmt_ip"
export UNBOUND_PORT="$NOVA_UNBOUND_PORT"
python3 "$ROOT/scripts/render-template.py" "$ROOT/config/unbound/nova.conf.in" "$NOVA_ETC/unbound/nova.conf"
chmod 0644 "$NOVA_ETC/unbound/nova.conf"
install -m 0644 "$NOVA_ETC/unbound/nova.conf" /etc/unbound/unbound.conf.d/nova.conf
unbound-checkconf /etc/unbound/unbound.conf

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) agh_arch=amd64 ;;
  aarch64|arm64) agh_arch=arm64 ;;
  armv7l) agh_arch=armv7 ;;
  *) die "unsupported AdGuard Home architecture: $arch" ;;
esac

version="$NOVA_ADGUARD_VERSION"
filename="AdGuardHome_linux_${agh_arch}.tar.gz"
base="https://github.com/AdguardTeam/AdGuardHome/releases/download/${version}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL --connect-timeout 10 --max-time 120 "$base/$filename" -o "$tmp/$filename"
curl -fsSL --connect-timeout 10 --max-time 30 "$base/checksums.txt" -o "$tmp/checksums.txt"

python3 - "$tmp/checksums.txt" "$tmp/$filename" "$filename" <<'PY'
import hashlib,pathlib,sys
checks=pathlib.Path(sys.argv[1]).read_text().splitlines()
archive=pathlib.Path(sys.argv[2]); name=sys.argv[3]
expected=None
for line in checks:
    parts=line.split()
    if len(parts) >= 2 and parts[-1].lstrip("*") == name:
        expected=parts[0].lower()
        break
if not expected:
    raise SystemExit(f"checksum entry missing for {name}")
h=hashlib.sha256()
with archive.open("rb") as f:
    for chunk in iter(lambda:f.read(1024*1024), b""):
        h.update(chunk)
actual=h.hexdigest()
if actual != expected:
    raise SystemExit(f"checksum mismatch: expected {expected}, got {actual}")
print(actual)
PY

tar -xzf "$tmp/$filename" -C "$tmp"
install -d -m 0755 /usr/local/lib/nova-adguard
install -m 0755 "$tmp/AdGuardHome/AdGuardHome" /usr/local/lib/nova-adguard/AdGuardHome
agh=/usr/local/lib/nova-adguard/AdGuardHome
"$agh" --version

render_profile() {
  local profile="$1" dns_port="$2" ui_port="$3" main_filter="$4"
  local cfg="$NOVA_ETC/adguard/${profile}.yaml"
  local work="$NOVA_STATE/dns/${profile}"

  export VPN_IP="$vpn_ip" MGMT_IP="$mgmt_ip" DNS_PORT="$dns_port" UI_PORT="$ui_port"
  export UNBOUND_PORT="$NOVA_UNBOUND_PORT" MAIN_FILTER="$main_filter" TIF_FILTER="$NOVA_HAGEZI_TIF_MINI"
  python3 "$ROOT/scripts/render-template.py" "$ROOT/config/adguard/profile.yaml.in" "$cfg"
  chmod 0644 "$cfg"

  "$agh" --check-config -c "$cfg" -w "$work"

  export PROFILE="$profile" BINARY="$agh" CONFIG="$cfg" WORKDIR="$work"
  python3 "$ROOT/scripts/render-template.py" "$ROOT/config/systemd/nova-adguard.service.in"     "/etc/systemd/system/nova-adguard-${profile}.service"
  chmod 0644 "/etc/systemd/system/nova-adguard-${profile}.service"
}

render_profile private "$NOVA_ADGUARD_PRIVATE_PORT" "$NOVA_ADGUARD_PRIVATE_UI" "$NOVA_HAGEZI_PRO_MINI"
render_profile strict "$NOVA_ADGUARD_STRICT_PORT" "$NOVA_ADGUARD_STRICT_UI" "$NOVA_HAGEZI_ULTIMATE_MINI"

systemctl daemon-reload
systemctl enable --now unbound.service
systemctl enable --now nova-adguard-private.service nova-adguard-strict.service

systemctl is-active --quiet unbound.service || die "Unbound failed to start"
systemctl is-active --quiet nova-adguard-private.service || die "private AdGuard failed to start"
systemctl is-active --quiet nova-adguard-strict.service || die "strict AdGuard failed to start"

log "DNS stack installed and validated"
