#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
require_cmd nft

have_management=0
shopt -s nullglob
for f in "$NOVA_ETC"/peers.d/*.env; do
  load_peer_registry "$f"
  [[ "$PEER_MANAGEMENT" == "1" ]] && have_management=1
done

if [[ -n "${SSH_CONNECTION:-}" && -z "${NOVA_BOOTSTRAP_SSH_CIDR:-}" && "$have_management" -ne 1 ]]; then
  die "refusing remote firewall activation: no bootstrap SSH CIDR and no management peer"
fi

install -m 0644 "$ROOT/config/systemd/nova-firewall.service" /etc/systemd/system/nova-firewall.service

# Every installation/re-install starts from the independent emergency CLOSED
# state; forwarding is opened only later by the atomic acceptance protocol.
"$ROOT/scripts/atomic-safety-gate.sh" boot-close

install -m 0644 "$ROOT/config/sysctl/99-nova-routing.conf" /etc/sysctl.d/99-nova-routing.conf
sysctl -p /etc/sysctl.d/99-nova-routing.conf >/dev/null

systemctl daemon-reload
systemctl enable --now nova-firewall.service
systemctl is-enabled --quiet nova-firewall.service || die "firewall persistence failed"
systemctl is-active --quiet nova-firewall.service || die "firewall service failed to become active"

log "NOVA firewall installed"
