#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
load_runtime

[[ "${1:-}" == "--check" ]] ||
  die "usage: update-components.sh --check"

printf 'NOVA repository version: %s\n' "$(cat "$ROOT/VERSION")"
printf 'Configured repository: %s\n' "${NOVA_REPOSITORY:-unknown}"
printf 'Traffic gate: %s\n' "${NOVA_TRAFFIC_GATE:-closed}"
printf 'Kernel: %s\n' "$(uname -r)"
printf 'Kernel track: %s\n' "${NOVA_KERNEL_TRACK:-unknown}"
printf 'OpenSSH: %s\n' "$(ssh -V 2>&1 | head -n1 || true)"
printf 'Unbound: %s\n' "$(unbound -V 2>/dev/null | head -n1 || true)"
printf 'AWG tools: %s\n' "$(awg --version 2>/dev/null || echo not-installed)"
printf 'AWG userspace: %s\n' "$(/usr/local/sbin/amneziawg-go --version 2>/dev/null | head -n1 || echo not-installed)"
printf 'AWG userspace hash: %s\n' "${NOVA_AWG_GO_SHA256:-unknown}"
printf 'AdGuard installed: %s\n' "$(/usr/local/lib/nova-adguard/AdGuardHome --version 2>/dev/null || echo not-installed)"
printf 'AdGuard target: %s\n' "${NOVA_ADGUARD_VERSION:-unknown}"
printf 'Encrypted swap: %s MiB\n' "${NOVA_SWAP_MIB:-0}"

if command -v apt-cache >/dev/null 2>&1; then
  printf '\nAPT candidates:\n'
  apt-cache policy amneziawg-tools unbound openssh-server linux-oracle linux-generic 2>/dev/null || true
fi

latest_agh="$(
  curl --proto '=https' --tlsv1.2 -fsSL     --connect-timeout 5 --max-time 10     https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest 2>/dev/null |
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name","unknown"))' 2>/dev/null ||
    true
)"
printf '\nAdGuard latest stable: %s\n' "${latest_agh:-unavailable}"

latest_nova="$(
  curl --proto '=https' --tlsv1.2 -fsSL     --connect-timeout 5 --max-time 10     "https://api.github.com/repos/${NOVA_REPOSITORY}/releases/latest" 2>/dev/null |
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name","unreleased"))' 2>/dev/null ||
    true
)"
printf 'NOVA latest stable: %s\n' "${latest_nova:-unavailable}"

latest_awg_go="$(
  curl --proto '=https' --tlsv1.2 -fsSL     --connect-timeout 5 --max-time 10     https://proxy.golang.org/github.com/amnezia-vpn/amneziawg-go/v3/@v/list 2>/dev/null |
    grep -E '^v3\.1\.[0-9]+$' |
    sort -V |
    tail -n1 ||
    true
)"
printf 'AmneziaWG-go latest allowed v3.1: %s\n' "${latest_awg_go:-unavailable}"

printf '\nAutomation:\n'
systemctl list-timers --all --no-pager   nova-release-update.timer nova-maintenance.timer nova-cleanup.timer nova-doh-ips.timer 2>/dev/null ||
  true

cat <<'EOF'

Updates are applied only through NOVA's fail-closed maintenance/release paths.
Use:
  privacyctl update system
  privacyctl update release
EOF
