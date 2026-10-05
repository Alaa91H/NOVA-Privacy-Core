#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

mode="${1:-server}"
case "$mode" in
  preflight|server|report) ;;
  *) die "usage: live-acceptance.sh [preflight|server|report]" ;;
esac

pass=0
fail=0
warns=0

ok()   { printf 'PASS  %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf 'FAIL  %s\n' "$*"; fail=$((fail+1)); }
note() { printf 'WARN  %s\n' "$*"; warns=$((warns+1)); }

run_check() {
  local desc="$1"
  shift
  if "$@"; then ok "$desc"; else bad "$desc"; fi
}

is_debian_13() {
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "debian" && "${VERSION_ID%%.*}" == "13" ]]
}

ram_ok() {
  awk '/MemTotal:/ {exit !($2 >= 850000)}' /proc/meminfo
}

no_swap_disk() {
  local bad
  bad="$(swapon --noheadings --show=TYPE 2>/dev/null | grep -v '^partition$' || true)"
  # zram is reported as partition by some util-linux versions; inspect names too.
  if swapon --noheadings --show=NAME 2>/dev/null | grep -vE '^/dev/zram[0-9]+$' | grep -q .; then
    return 1
  fi
  [[ -z "$bad" || "$(swapon --noheadings --show=NAME 2>/dev/null | grep -vE '^/dev/zram[0-9]+$' || true)" == "" ]]
}

server_services() {
  local s
  for s in nova-firewall.service nova-awg.service unbound.service            nova-adguard-private.service nova-adguard-strict.service; do
    systemctl is-active --quiet "$s" || return 1
  done
}

doh_timer_ok() {
  systemctl is-active --quiet nova-doh-ips.timer
}

firewall_ok() {
  nft list table inet nova >/dev/null 2>&1 &&
  nft list chain inet nova input 2>/dev/null | grep -q 'policy drop' &&
  nft list chain inet nova forward 2>/dev/null | grep -q 'policy drop' &&
  nft list chain inet nova output 2>/dev/null | grep -q 'policy drop'
}

no_public_sensitive_ports() {
  ! ss -H -lntup 2>/dev/null |
    awk '{print $5}' |
    grep -E ':(22|53|853|3000|3001|5300|5301|5335)$' |
    grep -Eq '^(0\.0\.0\.0|\[::\]|\*):'
}

awg_interface_ok() {
  ip link show "$NOVA_VPN_IF" >/dev/null 2>&1
}

secret_modes_ok() {
  local bad
  bad="$(find "$NOVA_ETC" -type f \(       -name '*.key' -o -name '*.psk' -o -name 'server.key' -o       -name 'admin.password' -o -path '*/peer-secrets/*'     \) -perm /077 2>/dev/null || true)"
  [[ -z "$bad" ]]
}

journal_volatile() {
  systemd-analyze cat-config systemd/journald.conf 2>/dev/null |
    grep -Eq '^[[:space:]]*Storage=volatile[[:space:]]*$'
}

ipv6_fail_closed() {
  [[ "$(sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]]
}

ipv4_forwarding() {
  [[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]]
}

dns_stack_ok() {
  dig +time=3 +tries=1 @"${NOVA_VPN_ADDR%/*}" -p "$NOVA_ADGUARD_PRIVATE_PORT" example.com A >/dev/null &&
  dig +time=3 +tries=1 @"${NOVA_VPN_ADDR%/*}" -p "$NOVA_ADGUARD_STRICT_PORT" example.com A >/dev/null &&
  dig +time=3 +tries=1 @"${NOVA_VPN_ADDR%/*}" -p "$NOVA_UNBOUND_PORT" example.com A >/dev/null
}

doh_set_ok() {
  local f="$NOVA_STATE/doh/doh-ipv4.txt" n sample
  [[ -s "$f" ]] || return 1
  n="$(grep -cvE '^[[:space:]]*(#|$)' "$f" || true)"
  (( n >= 100 )) || return 1
  sample="$(grep -vE '^[[:space:]]*(#|$)' "$f" | head -n1)"
  nft list set inet nova doh4 2>/dev/null | grep -Fq "$sample"
}

ssh_passwords_disabled() {
  sshd -T 2>/dev/null | grep -Eq '^passwordauthentication no$' &&
  sshd -T 2>/dev/null | grep -Eq '^permitrootlogin no$'
}

querylogs_disabled() {
  grep -A4 '^querylog:' "$NOVA_ETC/adguard/private.yaml" | grep -q 'enabled: false' &&
  grep -A4 '^querylog:' "$NOVA_ETC/adguard/strict.yaml" | grep -q 'enabled: false'
}

preflight() {
  run_check "Debian 13 baseline" is_debian_13
  run_check ">= 850 MiB visible RAM" ram_ok
  if command -v nft >/dev/null 2>&1; then ok "nftables installed"; else bad "nftables missing"; fi
  if command -v awg >/dev/null 2>&1; then ok "AmneziaWG tools installed"; else bad "AmneziaWG tools missing"; fi
  if command -v unbound >/dev/null 2>&1; then ok "Unbound installed"; else bad "Unbound missing"; fi
  if command -v age >/dev/null 2>&1; then ok "age installed"; else bad "age missing"; fi
  run_check "only zram/no disk swap" no_swap_disk
}

server_checks() {
  run_check "core services active" server_services
  run_check "DoH guard timer active" doh_timer_ok
  run_check "firewall input/forward/output default DROP" firewall_ok
  run_check "AWG interface exists" awg_interface_ok
  run_check "IPv4 forwarding enabled after firewall" ipv4_forwarding
  run_check "IPv6 forwarding disabled" ipv6_fail_closed
  run_check "no wildcard-sensitive service listener" no_public_sensitive_ports
  run_check "VPN DNS stack responds" dns_stack_ok
  run_check "STRICT encrypted-DNS IP set loaded" doh_set_ok
  run_check "AdGuard query logs disabled" querylogs_disabled
  run_check "secret files are not group/world accessible" secret_modes_ok
  run_check "SSH passwords/root login disabled" ssh_passwords_disabled
  if journal_volatile; then ok "journald configured volatile"; else note "could not prove Storage=volatile"; fi
}

preflight
if [[ "$mode" != "preflight" ]]; then
  server_checks
fi

printf '\nSummary: %d passed, %d failed, %d warnings\n' "$pass" "$fail" "$warns"
if (( fail > 0 )); then
  exit 1
fi

if [[ "$mode" == "report" ]]; then
  cat <<'EOF'

Physical-client gates still require observation from each endpoint:
- visible public IPv4/IPv6;
- DNS resolver path;
- Android Always-on + Block connections without VPN;
- Windows sleep/wake and Wi-Fi/network transition;
- forced server/tunnel failure with client traffic blocked;
- Tor Browser exit and DNS path;
- mixnet latency/compatibility if MAX-MIX is used.
EOF
fi
