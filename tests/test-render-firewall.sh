#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf 'SKIP test-render-firewall: root required for control-plane lock semantics\n'
  exit 0
fi

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

export NOVA_ETC="$tmp/etc"
export NOVA_STATE="$tmp/state"
export NOVA_RUN="$tmp/run"
export NOVA_INSTALL_ROOT="$ROOT"
export NOVA_WAN_IF=eth0
export NOVA_VPN_IF=awg0
export NOVA_VPN_ADDR=10.77.0.1/24
export NOVA_VPN_NET=10.77.0.0/24
export NOVA_MGMT_ADDR=10.77.10.1/24
export NOVA_MGMT_NET=10.77.10.0/24
export NOVA_AWG_PORT=51820
export NOVA_BOOTSTRAP_SSH_CIDR=198.51.100.10/32
export NOVA_UNBOUND_PORT=5335
export NOVA_ADGUARD_PRIVATE_PORT=5300
export NOVA_ADGUARD_STRICT_PORT=5301
export NOVA_TRAFFIC_GATE=closed

mkdir -p   "$NOVA_ETC/peers.d"   "$NOVA_ETC/peer-secrets/strict"   "$NOVA_ETC/peer-secrets/management"   "$NOVA_STATE/doh"   "$NOVA_RUN"
chmod 0700 "$NOVA_ETC/peer-secrets/strict" "$NOVA_ETC/peer-secrets/management"

printf '%s\n' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' >"$NOVA_ETC/peer-secrets/strict/psk"
printf '%s\n' 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=' >"$NOVA_ETC/peer-secrets/management/psk"
chmod 0600 "$NOVA_ETC/peer-secrets/strict/psk" "$NOVA_ETC/peer-secrets/management/psk"

cat >"$NOVA_ETC/peers.d/strict.env" <<EOF
NAME=strict
IP=10.77.0.20
PROFILE=STRICT
MANAGEMENT=0
PUBLIC_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PSK_FILE=$NOVA_ETC/peer-secrets/strict/psk
EOF

cat >"$NOVA_ETC/peers.d/management.env" <<EOF
NAME=management
IP=10.77.10.20
PROFILE=PRIVATE
MANAGEMENT=1
PUBLIC_KEY=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
PSK_FILE=$NOVA_ETC/peer-secrets/management/psk
EOF
chmod 0600 "$NOVA_ETC/peers.d/strict.env" "$NOVA_ETC/peers.d/management.env"

python3 - "$NOVA_STATE/doh/doh-ipv4.txt" <<'PY'
import ipaddress, pathlib, sys
p=pathlib.Path(sys.argv[1])
base=int(ipaddress.ip_address("203.0.113.1"))
p.write_text("\n".join(str(ipaddress.ip_address(base+i)) for i in range(120))+"\n")
PY

cat >"$tmp/fake-nft" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
file="${@: -1}"
[[ -r "$file" ]]
! grep -q '@@[A-Z0-9_]\+@@' "$file"
grep -q '10.77.0.20' "$file"
grep -q '203.0.113.1' "$file"
grep -q '203.0.113.120' "$file"
grep -q 'ip saddr @strict4 ip daddr @doh4 drop' "$file"
exit 0
EOF
chmod 0755 "$tmp/fake-nft"
export NOVA_NFT_BIN="$tmp/fake-nft"

bash "$ROOT/scripts/render-firewall.sh"

rendered="$NOVA_ETC/nftables/nova.nft"
[[ -s "$rendered" ]]
grep -q '198.51.100.10/32 tcp dport 22 accept' "$rendered"
grep -q 'elements = { 10.77.0.20 }' "$rendered"
grep -q 'elements = { 10.77.10.20 }' "$rendered"
grep -q 'NOVA_TRAFFIC_GATE_CLOSED' "$rendered"
grep -q 'NOVA_EMERGENCY_KILLSWITCH' "$rendered"

export NOVA_TRAFFIC_GATE=open
export NOVA_GATE_TOKEN=0123456789abcdef0123456789abcdef
open_candidate="$tmp/open.nft"
bash "$ROOT/scripts/render-firewall.sh" --stage "$open_candidate"
rendered="$open_candidate"
if grep -q 'NOVA_TRAFFIC_GATE_CLOSED' "$rendered"; then
  printf 'FAIL open traffic gate still rendered CLOSED marker\n' >&2
  exit 1
fi
if grep -q 'NOVA_EMERGENCY_KILLSWITCH' "$rendered"; then
  printf 'FAIL open traffic gate still contains emergency kill-switch\n' >&2
  exit 1
fi
grep -q 'NOVA_GATE_OPEN_0123456789abcdef0123456789abcdef' "$rendered"
grep -q 'destroy table inet nova_emergency' "$rendered"

printf 'PASS test-render-firewall closed/open atomic gate rendering\n'
