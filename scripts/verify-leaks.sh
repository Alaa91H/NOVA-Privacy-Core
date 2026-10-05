#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

fail=0
check() {
  local desc="$1"
  shift
  if "$@"; then
    printf 'PASS  %s\n' "$desc"
  else
    printf 'FAIL  %s\n' "$desc"
    fail=1
  fi
}

chain_policy_drop() {
  nft list chain inet nova "$1" 2>/dev/null | grep -Eq 'policy drop'
}

no_public_sensitive_listener() {
  ! ss -H -lntup 2>/dev/null | awk '{print $5}' | grep -E '(^|:)(53|3000|3001|5300|5301|5335)$' | grep -Eq '(^|\[?::\]?:|0\.0\.0\.0:)'
}

private_dns_responds() {
  dig +time=3 +tries=1 @"${NOVA_VPN_ADDR%/*}" -p "$NOVA_ADGUARD_PRIVATE_PORT" example.com A >/dev/null
}

strict_dns_responds() {
  dig +time=3 +tries=1 @"${NOVA_VPN_ADDR%/*}" -p "$NOVA_ADGUARD_STRICT_PORT" example.com A >/dev/null
}

unbound_responds() {
  dig +time=3 +tries=1 @"${NOVA_VPN_ADDR%/*}" -p "$NOVA_UNBOUND_PORT" example.com A >/dev/null
}

no_adguard_querylog() {
  grep -A3 '^querylog:' "$NOVA_ETC/adguard/private.yaml" | grep -q 'enabled: false' &&
  grep -A3 '^querylog:' "$NOVA_ETC/adguard/strict.yaml" | grep -q 'enabled: false'
}

secrets_modes_safe() {
  local bad
  bad="$(find "$NOVA_ETC" -type f \( -name '*.key' -o -name '*.psk' -o -path '*/peer-secrets/*' -o -name 'server.key' -o -name 'admin.password' -o -name 'awg.params' \) -perm /077 2>/dev/null || true)"
  [[ -z "$bad" ]]
}


doh_guard_ready() {
  local file="$NOVA_STATE/doh/doh-ipv4.txt" count sample
  systemctl is-active --quiet nova-doh-ips.timer || return 1
  [[ -s "$file" ]] || return 1
  count="$(grep -cvE '^[[:space:]]*(#|$)' "$file" || true)"
  (( count >= 100 )) || return 1
  sample="$(grep -vE '^[[:space:]]*(#|$)' "$file" | head -n1)"
  [[ -n "$sample" ]] || return 1
  nft list set inet nova doh4 2>/dev/null | grep -Fq "$sample"
}

check "nft input defaults to DROP" chain_policy_drop input
check "nft forward defaults to DROP" chain_policy_drop forward
check "nft output defaults to DROP" chain_policy_drop output
check "AWG interface exists" ip link show "$NOVA_VPN_IF"
check "IPv4 forwarding enabled" test "$(sysctl -n net.ipv4.ip_forward)" = "1"
check "IPv6 forwarding disabled" test "$(sysctl -n net.ipv6.conf.all.forwarding)" = "0"
check "sensitive ports are not wildcard-public" no_public_sensitive_listener
check "Unbound answers through VPN address" unbound_responds
check "PRIVATE DNS answers" private_dns_responds
check "STRICT DNS answers" strict_dns_responds
check "AdGuard query history disabled" no_adguard_querylog
check "stored private key material is mode-safe" secrets_modes_safe
check "STRICT encrypted-DNS IP guard is active" doh_guard_ready
check "public DNS/DoT not explicitly accepted on WAN" bash -c "! nft list chain inet nova input | grep -E 'iifname \"$NOVA_WAN_IF\".*dport (53|853)' >/dev/null"

if [[ "$fail" -ne 0 ]]; then
  printf '\nNOVA server-side privacy verification FAILED.\n' >&2
  exit 1
fi

cat <<'EOF'

All server-side checks passed.

Client-side checks are still required on each physical device:
- verify the visible public IP equals the expected protected exit;
- verify DNS never falls back to the ISP;
- verify IPv6 is tunneled or fails closed;
- disable the VPN and confirm Android/OS lockdown blocks traffic;
- force the server tunnel down and confirm no direct fallback.

NOVA deliberately does not fake those client results from the server.
EOF
