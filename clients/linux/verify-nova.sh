#!/usr/bin/env bash
set -Eeuo pipefail

expected_if="${NOVA_EXPECTED_IF:-}"
expected_dns="${NOVA_DNS_IP:-10.77.0.1}"
fail=0

pass(){ printf 'PASS  %s\n' "$*"; }
bad(){ printf 'FAIL  %s\n' "$*" >&2; fail=1; }
warn(){ printf 'WARN  %s\n' "$*"; }

command -v ip >/dev/null 2>&1 || { echo "iproute2 required" >&2; exit 2; }

v4route="$(ip -4 route get 1.1.1.1 2>/dev/null | head -n1 || true)"
[[ -n "$v4route" ]] || bad "no IPv4 route"
if [[ -n "$expected_if" ]]; then
  if grep -Eq "(^|[[:space:]])dev[[:space:]]+$expected_if([[:space:]]|$)" <<<"$v4route"; then
    pass "IPv4 test route uses $expected_if"
  else
    bad "IPv4 test route does not use expected interface $expected_if: $v4route"
  fi
else
  warn "NOVA_EXPECTED_IF unset; IPv4 route observed: $v4route"
fi

if ip -6 route show default 2>/dev/null | grep -q .; then
  v6defaults="$(ip -6 route show default)"
  if [[ -n "$expected_if" ]] && grep -vq "dev $expected_if" <<<"$v6defaults"; then
    bad "direct/non-NOVA IPv6 default route exists: $v6defaults"
  else
    warn "IPv6 default route exists; verify it belongs to the protected tunnel: $v6defaults"
  fi
else
  pass "no IPv6 default route (fail-closed IPv6 mode)"
fi

dns_text=""
if command -v resolvectl >/dev/null 2>&1; then
  dns_text="$(resolvectl dns 2>/dev/null || true)"
elif [[ -r /etc/resolv.conf ]]; then
  dns_text="$(cat /etc/resolv.conf)"
fi

if grep -Fq "$expected_dns" <<<"$dns_text"; then
  pass "NOVA DNS address $expected_dns present"
else
  bad "expected NOVA DNS $expected_dns not found in active DNS configuration"
fi

if command -v awg >/dev/null 2>&1; then
  if awg show 2>/dev/null | grep -q '^interface:'; then
    pass "AmneziaWG interface visible to awg tools"
  else
    warn "awg tools installed but no interface visible"
  fi
fi

cat <<'EOF'

This local verifier intentionally does not contact a third-party "what is my IP"
site. To verify the visible public IP, use a destination you trust and compare it
with the Oracle exit. During the forced AWG-down test, this script is not enough:
the OS/client kill switch must make all application traffic fail.
EOF

exit "$fail"
