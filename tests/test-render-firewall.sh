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

mkdir -p "$NOVA_ETC/peers.d" "$NOVA_STATE/doh" "$NOVA_RUN"

cat >"$NOVA_ETC/peers.d/strict.env" <<'EOF'
NAME=strict
IP=10.77.0.20
PROFILE=STRICT
MANAGEMENT=0
PUBLIC_KEY=test
EOF

cat >"$NOVA_ETC/peers.d/management.env" <<'EOF'
NAME=management
IP=10.77.10.20
PROFILE=PRIVATE
MANAGEMENT=1
PUBLIC_KEY=test2
EOF

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

printf 'PASS test-render-firewall runtime rendering\n'
