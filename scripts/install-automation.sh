#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

units=(
  nova-release-update.service
  nova-release-update.timer
  nova-maintenance.service
  nova-maintenance.timer
  nova-cleanup.service
  nova-cleanup.timer
  nova-postboot-verify.service
  nova-encrypted-swap.service
)

for unit in "${units[@]}"; do
  install -m 0644 "$ROOT/config/systemd/$unit" "/etc/systemd/system/$unit"
done

systemctl daemon-reload
systemctl enable nova-postboot-verify.service
systemctl enable --now nova-release-update.timer nova-maintenance.timer nova-cleanup.timer

for timer in nova-release-update.timer nova-maintenance.timer nova-cleanup.timer; do
  systemctl is-enabled --quiet "$timer" || die "failed to enable $timer"
  systemctl is-active --quiet "$timer" || die "failed to start $timer"
done

log "automatic release/system/kernel/application updates and cleanup are enabled"
