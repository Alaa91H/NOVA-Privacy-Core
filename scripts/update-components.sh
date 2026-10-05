#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
load_runtime

[[ "${1:-}" == "--check" ]] || die "only --check is supported; NOVA never blindly auto-upgrades security components"

printf 'NOVA repository version: %s\n' "$(cat "$ROOT/VERSION")"
printf 'Kernel: %s\n' "$(uname -r)"
printf 'OpenSSH: %s\n' "$(ssh -V 2>&1 | head -n1 || true)"
printf 'Unbound: %s\n' "$(unbound -V 2>/dev/null | head -n1 || true)"
printf 'AmneziaWG: %s\n' "$(awg --version 2>/dev/null || echo not-installed)"
printf 'AdGuard installed: %s\n' "$(/usr/local/lib/nova-adguard/AdGuardHome --version 2>/dev/null || echo not-installed)"

if command -v apt-cache >/dev/null 2>&1; then
  printf '\nAPT candidates:\n'
  apt-cache policy amneziawg amneziawg-tools unbound openssh-server 2>/dev/null || true
fi

latest_agh="$(curl -fsSL --connect-timeout 5 --max-time 10 https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name","unknown"))' 2>/dev/null || true)"
printf '\nAdGuard pinned: %s\nAdGuard latest stable reported by GitHub: %s\n' "$NOVA_ADGUARD_VERSION" "${latest_agh:-unavailable}"

cat <<'EOF'

This command only reports. Upgrade decisions must pass changelog/security review,
configuration validation, leak tests, resource tests, and rollback validation.
EOF
