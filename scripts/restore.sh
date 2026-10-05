#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
acquire_nova_lock
require_cmd age
require_cmd python3

backup="${1:-}"
[[ -n "$backup" && -r "$backup" ]] || die "usage: restore.sh FILE.tar.age"

tmpdir="$(mktemp -d /run/nova-restore.XXXXXX)"
old="$tmpdir/old"
trap 'rm -rf "$tmpdir"' EXIT

if [[ -n "${NOVA_AGE_IDENTITY:-}" ]]; then
  age -d -i "$NOVA_AGE_IDENTITY" -o "$tmpdir/archive.tar" "$backup"
else
  [[ -t 0 && -t 1 ]] || die "non-interactive restore requires NOVA_AGE_IDENTITY"
  age -d -o "$tmpdir/archive.tar" "$backup"
fi

python3 - "$tmpdir/archive.tar" "$tmpdir/extracted" <<'PY'
import pathlib,sys,tarfile
src=pathlib.Path(sys.argv[1])
dst=pathlib.Path(sys.argv[2])
dst.mkdir(mode=0o700)
with tarfile.open(src, "r:") as tf:
    members=tf.getmembers()
    if not members:
        raise SystemExit("empty backup")
    for m in members:
        name=pathlib.PurePosixPath(m.name)
        if name.is_absolute() or ".." in name.parts:
            raise SystemExit(f"unsafe path: {m.name}")
        if m.issym() or m.islnk() or m.isdev():
            raise SystemExit(f"unsafe archive member type: {m.name}")
        if not (m.name == "MANIFEST" or m.name == "etc/nova-privacy" or m.name.startswith("etc/nova-privacy/")):
            raise SystemExit(f"unexpected backup path: {m.name}")
    tf.extractall(dst, members=members, filter="data")
PY

restored="$tmpdir/extracted/etc/nova-privacy"
[[ -s "$restored/nova.env" ]] || die "backup is missing nova.env"
[[ -s "$restored/keys/server.key" ]] || die "backup is missing server private key"

# Recovery is always fail-closed, even if the source server was OPEN.
write_runtime_kv NOVA_TRAFFIC_GATE closed
NOVA_TRAFFIC_GATE=closed "$ROOT/scripts/render-firewall.sh" 2>/dev/null || true

systemctl stop   nova-adguard-private.service   nova-adguard-strict.service   nova-awg.service 2>/dev/null || true

if [[ -d "$NOVA_ETC" ]]; then
  mv "$NOVA_ETC" "$old"
fi
install -d -m 0700 "$(dirname "$NOVA_ETC")"
cp -a "$restored" "$NOVA_ETC"
chown root:nova-dns "$NOVA_ETC"
chmod 0710 "$NOVA_ETC"

rollback() {
  warn "restore failed; restoring previous configuration with traffic CLOSED"
  rm -rf "$NOVA_ETC"
  [[ -d "$old" ]] && mv "$old" "$NOVA_ETC"
  if [[ -r "$NOVA_ETC/nova.env" ]]; then
    write_runtime_kv NOVA_TRAFFIC_GATE closed
  fi
  NOVA_TRAFFIC_GATE=closed "$ROOT/scripts/render-firewall.sh" >/dev/null 2>&1 || true
  systemctl start     nova-awg.service     nova-adguard-private.service     nova-adguard-strict.service 2>/dev/null || true
}
trap rollback ERR

# Reload restored policy/preferences, then overwrite host-specific runtime facts
# with facts from the new recovery host.
# shellcheck disable=SC1091
source "$NOVA_ETC/nova.env"
write_runtime_kv NOVA_TRAFFIC_GATE closed
write_runtime_kv NOVA_BOOTSTRAP_SSH_CIDR ""
write_runtime_kv NOVA_OS_BASELINE "ubuntu-26.04"
if is_oci_host; then
  write_runtime_kv NOVA_PLATFORM "oci"
  write_runtime_kv NOVA_KERNEL_TRACK "linux-oracle"
else
  write_runtime_kv NOVA_PLATFORM "generic"
  write_runtime_kv NOVA_KERNEL_TRACK "linux-generic"
fi
load_runtime

# Reconstruct host-bound components from trusted current source.  Never trust
# a backed-up binary hash/version over what is installed and probed now.
bash "$ROOT/scripts/install-awg.sh"
bash "$ROOT/scripts/configure-awg.sh" "${NOVA_AWG_MODE:-balanced}"
bash "$ROOT/scripts/rebuild-awg-peers.sh"
bash "$ROOT/scripts/configure-memory.sh"
bash "$ROOT/scripts/install-dns.sh"
bash "$ROOT/scripts/install-doh-guard.sh"
bash "$ROOT/scripts/install-automation.sh"
NOVA_TRAFFIC_GATE=closed bash "$ROOT/scripts/render-firewall.sh"

"$ROOT/src/privacyctl" health
"$ROOT/scripts/live-acceptance.sh" preflight
"$ROOT/scripts/verify-leaks.sh"

rm -rf "$old"
trap - ERR
log "restore reconstructed successfully with protected forwarding CLOSED"
log "connect a management peer, then run: privacyctl activate"
