#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
acquire_nova_lock

[[ -z "${NOVA_BOOTSTRAP_SSH_CIDR:-}" ]] ||
  die "refusing automatic reopen while public bootstrap SSH is configured"
[[ ! -e /var/run/reboot-required ]] ||
  die "refusing automatic reopen while reboot is pending"

exec "$ROOT/scripts/atomic-safety-gate.sh" open automatic
