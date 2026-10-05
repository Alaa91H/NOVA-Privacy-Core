#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
acquire_nova_lock

[[ "${NOVA_AUTO_SYSTEM_UPDATE:-on}" == "on" ]] || {
  log "automatic system maintenance disabled"
  exit 0
}

previous_gate="${NOVA_TRAFFIC_GATE:-closed}"
marker_dir="$NOVA_STATE/maintenance"
marker="$marker_dir/reopen-after-boot"
install -d -m 0700 "$marker_dir"

close_gate() {
  write_runtime_kv NOVA_TRAFFIC_GATE closed
  NOVA_TRAFFIC_GATE=closed "$ROOT/scripts/render-firewall.sh"
}

reopen_gate() {
  [[ "$previous_gate" == "open" ]] || return 0
  "$ROOT/scripts/reopen-verified.sh"
}

export DEBIAN_FRONTEND=noninteractive

# Refresh metadata before closing user forwarding.  If mirrors/network are
# unavailable, abort without disrupting currently accepted protected traffic.
apt-get -o DPkg::Lock::Timeout=600 update

close_gate
trap 'warn "maintenance failed; traffic gate remains CLOSED"' ERR

apt-get -o DPkg::Lock::Timeout=600 -y full-upgrade

if is_oci_host; then
  apt-get -o DPkg::Lock::Timeout=600 install -y --no-install-recommends linux-oracle linux-headers-oracle
else
  apt-get -o DPkg::Lock::Timeout=600 install -y --no-install-recommends linux-generic linux-headers-generic
fi

# Re-verify every non-Ubuntu trust path after the package transaction before
# any protected forwarding can reopen.
"$ROOT/scripts/install-github-cli.sh"
"$ROOT/scripts/resolve-versions.sh" adguard
"$ROOT/scripts/install-awg.sh"
"$ROOT/scripts/install-dns.sh"
"$ROOT/scripts/install-doh-guard.sh"
"$ROOT/scripts/configure-memory.sh"

apt-get -o DPkg::Lock::Timeout=600 -y autoremove --purge
apt-get clean
systemd-tmpfiles --clean || true

if [[ -f /var/run/reboot-required ]]; then
  if [[ "$previous_gate" == "open" ]]; then
    printf 'open\n' >"$marker"
    chmod 0600 "$marker"
  else
    rm -f "$marker"
  fi

  if [[ "${NOVA_AUTO_REBOOT:-on}" == "on" ]]; then
    log "kernel/system reboot required; traffic remains closed until post-boot verification"
    systemctl reboot
    exit 0
  fi

  warn "reboot required but NOVA_AUTO_REBOOT is disabled; traffic remains CLOSED"
  exit 0
fi

reopen_gate
rm -f "$marker"
trap - ERR
log "scheduled system/application maintenance completed"
