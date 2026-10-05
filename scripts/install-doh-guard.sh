#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

install -m 0644 "$ROOT/config/systemd/nova-doh-ips.service" /etc/systemd/system/nova-doh-ips.service
install -m 0644 "$ROOT/config/systemd/nova-doh-ips.timer" /etc/systemd/system/nova-doh-ips.timer
chmod 0755 "$ROOT/scripts/update-doh-ips.sh"

systemctl daemon-reload

# Seed a validated set before enabling the timer.  A fresh install should not
# advertise STRICT encrypted-DNS IP protection until the first set exists.
"$ROOT/scripts/update-doh-ips.sh"

systemctl enable --now nova-doh-ips.timer
systemctl is-enabled --quiet nova-doh-ips.timer || die "DoH IP refresh timer was not enabled"

log "STRICT encrypted-DNS IP guard installed"
