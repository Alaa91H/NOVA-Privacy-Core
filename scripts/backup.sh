#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
require_cmd age
require_cmd tar

output="${1:-/root/nova-privacy-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.age}"
[[ -d "$NOVA_ETC" ]] || die "NOVA configuration directory not found"

tmpdir="$(mktemp -d /run/nova-backup.XXXXXX)"
trap 'rm -rf "$tmpdir"' EXIT
cat >"$tmpdir/MANIFEST" <<EOF
format=1
created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
nova_version=$(cat "$ROOT/VERSION" 2>/dev/null || echo unknown)
hostname=$(hostname)
EOF
chmod 0600 "$tmpdir/MANIFEST"

archive_stream() {
  tar --numeric-owner --xattrs --acls -C / -cf - "etc/nova-privacy" -C "$tmpdir" MANIFEST
}

if [[ -n "${NOVA_BACKUP_RECIPIENT:-}" ]]; then
  archive_stream | age -r "$NOVA_BACKUP_RECIPIENT" -o "$output"
else
  [[ -t 0 && -t 1 ]] || die "non-interactive backup requires NOVA_BACKUP_RECIPIENT"
  log "no NOVA_BACKUP_RECIPIENT set; using interactive age passphrase encryption"
  archive_stream | age -p -o "$output"
fi

chmod 0600 "$output"
age -d --help >/dev/null 2>&1 || true
log "encrypted backup created: $output"
printf '%s\n' "$output"
