#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
acquire_nova_lock
require_cmd python3
nft_bin="${NOVA_NFT_BIN:-nft}"
if [[ "$nft_bin" == */* ]]; then
  [[ -x "$nft_bin" ]] || die "NOVA_NFT_BIN is not executable: $nft_bin"
else
  require_cmd "$nft_bin"
fi

PEER_DIR="${NOVA_ETC}/peers.d"
mkdir -p "$PEER_DIR" "${NOVA_ETC}/nftables"

collect_ips() {
  local wanted="$1" mode="${2:-profile}" f
  local -a out=()
  shopt -s nullglob
  for f in "$PEER_DIR"/*.env; do
    load_peer_registry "$f"
    if [[ "$mode" == "profile" && "${PROFILE:-PRIVATE}" == "$wanted" ]]; then
      out+=("$IP")
    elif [[ "$mode" == "management" && "${MANAGEMENT:-0}" == "1" ]]; then
      out+=("$IP")
    fi
  done
  local IFS=", "
  printf '%s' "${out[*]:-}"
}

collect_doh_ips() {
  local file="$NOVA_STATE/doh/doh-ipv4.txt"
  [[ -s "$file" ]] || return 0

  python3 - "$file" <<'PY'
import ipaddress
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
out = []
for n, raw in enumerate(p.read_text(errors="strict").splitlines(), 1):
    s = raw.strip()
    if not s or s.startswith("#"):
        continue
    try:
        ip = ipaddress.ip_address(s)
    except ValueError as exc:
        raise SystemExit(f"invalid DoH firewall IP at line {n}: {s!r}") from exc
    if ip.version != 4:
        raise SystemExit(f"non-IPv4 DoH firewall entry at line {n}: {s!r}")
    out.append(str(ip))

# Avoid loading a suspicious/truncated set in production once the list exists.
if out and len(set(out)) < 100:
    raise SystemExit(f"refusing suspiciously small DoH firewall set: {len(set(out))}")
print(", ".join(sorted(set(out), key=lambda x: int(ipaddress.ip_address(x)))), end="")
PY
}

WAN_IF="${NOVA_WAN_IF}"
VPN_IF="${NOVA_VPN_IF}"
AWG_PORT="${NOVA_AWG_PORT}"
VPN_NET="${NOVA_VPN_NET}"
MGMT_NET="${NOVA_MGMT_NET}"
PRIVATE_DNS_PORT="${NOVA_ADGUARD_PRIVATE_PORT}"
STRICT_DNS_PORT="${NOVA_ADGUARD_STRICT_PORT}"
UNBOUND_PORT="${NOVA_UNBOUND_PORT}"
COMPAT_ELEMENTS="$(collect_ips COMPAT)"
STRICT_ELEMENTS="$(collect_ips STRICT)"
MGMT_ELEMENTS="$(collect_ips ignored management)"
LOCKDOWN_ELEMENTS="$(collect_ips LOCKDOWN)"
DOH_IP_ELEMENTS="$(collect_doh_ips)"
export WAN_IF VPN_IF AWG_PORT VPN_NET MGMT_NET PRIVATE_DNS_PORT STRICT_DNS_PORT UNBOUND_PORT
export COMPAT_ELEMENTS STRICT_ELEMENTS MGMT_ELEMENTS LOCKDOWN_ELEMENTS DOH_IP_ELEMENTS

case "${NOVA_TRAFFIC_GATE:-closed}" in
  open)
    TRAFFIC_GATE_DROP=""
    ;;
  closed)
    TRAFFIC_GATE_DROP="    iifname \"${NOVA_VPN_IF}\" ip saddr { ${NOVA_VPN_NET}, ${NOVA_MGMT_NET} } drop comment \"NOVA_TRAFFIC_GATE_CLOSED\""
    ;;
  *)
    die "invalid NOVA_TRAFFIC_GATE=${NOVA_TRAFFIC_GATE:-unset}"
    ;;
esac
export TRAFFIC_GATE_DROP

if [[ -n "${NOVA_BOOTSTRAP_SSH_CIDR:-}" ]]; then
  if [[ "$NOVA_BOOTSTRAP_SSH_CIDR" == *:* ]]; then
    BOOTSTRAP_SSH_RULE="    iifname \"${NOVA_WAN_IF}\" ip6 saddr ${NOVA_BOOTSTRAP_SSH_CIDR} tcp dport 22 accept"
  else
    BOOTSTRAP_SSH_RULE="    iifname \"${NOVA_WAN_IF}\" ip saddr ${NOVA_BOOTSTRAP_SSH_CIDR} tcp dport 22 accept"
  fi
else
  BOOTSTRAP_SSH_RULE=""
fi
export BOOTSTRAP_SSH_RULE

candidate="${NOVA_ETC}/nftables/nova.nft.candidate"
final="${NOVA_ETC}/nftables/nova.nft"
python3 "$ROOT/scripts/render-template.py" "$ROOT/config/nftables/nova.nft.in" "$candidate"
chmod 0600 "$candidate"

# nft -c parses the complete transaction without changing the active ruleset.
# The final nft -f call then replaces NOVA's table in one transaction.
"$nft_bin" -c -f "$candidate"
mv -f "$candidate" "$final"
"$nft_bin" -f "$final"
log "atomic nftables policy loaded"
