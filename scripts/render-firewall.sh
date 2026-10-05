#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

PEER_DIR="${NOVA_ETC}/peers.d"
mkdir -p "$PEER_DIR" "${NOVA_ETC}/nftables"

collect_ips() {
  local wanted="$1" mode="${2:-profile}" f
  local -a out=()
  shopt -s nullglob
  for f in "$PEER_DIR"/*.env; do
    unset NAME IP PROFILE MANAGEMENT PUBLIC_KEY
    # shellcheck disable=SC1090
    source "$f"
    if [[ "$mode" == "profile" && "${PROFILE:-PRIVATE}" == "$wanted" ]]; then
      out+=("$IP")
    elif [[ "$mode" == "management" && "${MANAGEMENT:-0}" == "1" ]]; then
      out+=("$IP")
    fi
  done
  local IFS=", "
  printf '%s' "${out[*]:-}"
}

export WAN_IF="${NOVA_WAN_IF}"
export VPN_IF="${NOVA_VPN_IF}"
export AWG_PORT="${NOVA_AWG_PORT}"
export VPN_NET="${NOVA_VPN_NET}"
export MGMT_NET="${NOVA_MGMT_NET}"
export PRIVATE_DNS_PORT="${NOVA_ADGUARD_PRIVATE_PORT}"
export STRICT_DNS_PORT="${NOVA_ADGUARD_STRICT_PORT}"
export UNBOUND_PORT="${NOVA_UNBOUND_PORT}"
export COMPAT_ELEMENTS="$(collect_ips COMPAT)"
export STRICT_ELEMENTS="$(collect_ips STRICT)"
export MGMT_ELEMENTS="$(collect_ips ignored management)"
export LOCKDOWN_ELEMENTS="$(collect_ips LOCKDOWN)"

if [[ -n "${NOVA_BOOTSTRAP_SSH_CIDR:-}" ]]; then
  if [[ "$NOVA_BOOTSTRAP_SSH_CIDR" == *:* ]]; then
    export BOOTSTRAP_SSH_RULE="    iifname \"${NOVA_WAN_IF}\" ip6 saddr ${NOVA_BOOTSTRAP_SSH_CIDR} tcp dport 22 accept"
  else
    export BOOTSTRAP_SSH_RULE="    iifname \"${NOVA_WAN_IF}\" ip saddr ${NOVA_BOOTSTRAP_SSH_CIDR} tcp dport 22 accept"
  fi
else
  export BOOTSTRAP_SSH_RULE=""
fi

candidate="${NOVA_ETC}/nftables/nova.nft.candidate"
final="${NOVA_ETC}/nftables/nova.nft"
python3 "$ROOT/scripts/render-template.py" "$ROOT/config/nftables/nova.nft.in" "$candidate"
chmod 0600 "$candidate"

nft -c -f "$candidate"
mv -f "$candidate" "$final"
nft -f "$final"
log "atomic nftables policy loaded"
