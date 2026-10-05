#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$SOURCE_ROOT/scripts/lib/common.sh"
require_root
load_defaults

# Serialize manual installs/upgrades with all timer-driven maintenance jobs.
acquire_nova_lock

existing_install=0
if [[ -r "$NOVA_ETC/nova.env" ]]; then
  existing_install=1
  load_runtime
  if [[ "${NOVA_TRAFFIC_GATE:-closed}" == "open" &&
        -x "$NOVA_INSTALL_ROOT/scripts/render-firewall.sh" ]]; then
    log "existing production node detected; closing protected forwarding before upgrade"
    write_runtime_kv NOVA_TRAFFIC_GATE closed
    NOVA_TRAFFIC_GATE=closed "$NOVA_INSTALL_ROOT/scripts/render-firewall.sh"
  fi
fi

if [[ "$SOURCE_ROOT" != "$NOVA_INSTALL_ROOT" ]]; then
  log "staging NOVA into $NOVA_INSTALL_ROOT"
  mkdir -p "$NOVA_INSTALL_ROOT"

  if command -v rsync >/dev/null 2>&1; then
    # Exact mirror: deleted repository files must not survive an upgrade and
    # continue to be reachable by systemd/root tooling.
    rsync -a --delete       --exclude='.git/'       --exclude='.build/'       --exclude='dist/'       "$SOURCE_ROOT/" "$NOVA_INSTALL_ROOT/"
  else
    # A first install can safely use tar when the target is empty.  Updating a
    # non-empty installation without --delete semantics is refused because
    # stale privileged scripts are a supply-chain risk.
    if find "$NOVA_INSTALL_ROOT" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
      die "rsync is required to update a non-empty NOVA installation safely"
    fi
    tar --exclude=.git --exclude=.build --exclude=dist -C "$SOURCE_ROOT" -cf - . |
      tar -C "$NOVA_INSTALL_ROOT" -xf -
  fi
fi

ROOT="$NOVA_INSTALL_ROOT"
find "$ROOT/scripts" -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod 0755 {} +
chmod 0755 "$ROOT/src/privacyctl"

log "T04 bootstrap"
bash "$ROOT/scripts/bootstrap.sh"

log "T04.5 dynamic memory pressure protection"
bash "$ROOT/scripts/configure-memory.sh"

log "T05 host hardening"
bash "$ROOT/scripts/harden.sh"

log "T06 fail-closed firewall bootstrap"
bash "$ROOT/scripts/install-firewall.sh"

log "T08 AmneziaWG installation"
bash "$ROOT/scripts/install-awg.sh"

log "T08 AmneziaWG configuration"
bash "$ROOT/scripts/configure-awg.sh" "${NOVA_AWG_MODE:-balanced}"

log "resolving latest signed stable application releases"
bash "$ROOT/scripts/resolve-versions.sh" adguard

log "T13-T17 DNS privacy/filtering stack"
bash "$ROOT/scripts/install-dns.sh"

log "T18 STRICT encrypted-DNS bypass guard"
bash "$ROOT/scripts/install-doh-guard.sh"

log "installing automatic system/kernel/application update and cleanup policy"
bash "$ROOT/scripts/install-automation.sh"

log "refreshing fail-closed firewall after service installation"
bash "$ROOT/scripts/render-firewall.sh"

ln -sfn "$ROOT/src/privacyctl" /usr/local/bin/privacyctl

log "running host verification with protected forwarding still CLOSED"
if ! "$ROOT/src/privacyctl" health; then
  die "installation completed with failed health checks"
fi

cat <<'EOF'

NOVA Privacy Core is installed.

NEXT STEPS:
  1. Create a management peer:
       sudo privacyctl peer add laptop PRIVATE --management

  2. Import /root/nova-peers/laptop.conf on that device and connect.

  3. Confirm a recent handshake:
       sudo privacyctl status

  4. Run the pre-activation checks:
       sudo privacyctl health
       sudo privacyctl leaks test
       sudo privacyctl acceptance preflight

  5. Activate production forwarding atomically:
       sudo privacyctl activate

     This requires a recent management-peer handshake, removes the temporary
     public SSH rule, and opens the traffic gate only after all server gates pass.

  6. Confirm:
       sudo privacyctl gate status
       sudo privacyctl acceptance server

If /var/run/reboot-required exists, reboot first and rerun the checks.
A manual upgrade of an already-active node intentionally leaves the traffic gate
CLOSED until you run "privacyctl activate" again.
Do not close your original bootstrap SSH session before the management peer succeeds.
EOF
