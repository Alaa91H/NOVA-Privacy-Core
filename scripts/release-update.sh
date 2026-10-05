#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
acquire_nova_lock

[[ "${NOVA_AUTO_RELEASE_UPDATE:-on}" == "on" ]] || {
  log "automatic NOVA release updates disabled"
  exit 0
}

require_cmd gh
require_cmd jq
require_cmd sha256sum
require_cmd python3
require_cmd rsync

release_json="$(gh release view --repo "$NOVA_REPOSITORY"   --json tagName,isDraft,isPrerelease 2>/dev/null || true)"
[[ -n "$release_json" ]] || {
  warn "no published NOVA release available"
  exit 0
}

tag="$(jq -er 'select(.isDraft==false and .isPrerelease==false) | .tagName' <<<"$release_json")"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  die "refusing unexpected NOVA release tag: $tag"

current="$(cat "$ROOT/VERSION" 2>/dev/null || echo 0.0.0)"
if ! dpkg --compare-versions "${tag#v}" gt "$current"; then
  log "NOVA is current: installed=$current latest=${tag#v}"
  exit 0
fi

previous_gate="${NOVA_TRAFFIC_GATE:-closed}"
tmp="$(mktemp -d /run/nova-release.XXXXXX)"
rollback_dir="$NOVA_STATE/rollback"
config_snapshot="$tmp/etc-nova-privacy"
install -d -m 0700 "$rollback_dir"
trap 'rm -rf "$tmp"' EXIT

# Close forwarding before changing any privileged code or package state.
write_runtime_kv NOVA_TRAFFIC_GATE closed
NOVA_TRAFFIC_GATE=closed "$ROOT/scripts/render-firewall.sh"

cp -a "$NOVA_ETC" "$config_snapshot"
rollback_archive="$rollback_dir/source-${current}-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
tar -C "$NOVA_INSTALL_ROOT" -czf "$rollback_archive" .
chmod 0600 "$rollback_archive"

rollback() {
  warn "release update failed; restoring previous NOVA source/config with traffic CLOSED"
  rm -rf "$NOVA_INSTALL_ROOT"
  install -d -m 0755 "$NOVA_INSTALL_ROOT"
  tar -C "$NOVA_INSTALL_ROOT" -xzf "$rollback_archive" || true

  rm -rf "$NOVA_ETC"
  cp -a "$config_snapshot" "$NOVA_ETC" || true
  # Never restore the previous open state after a failed upgrade.
  if [[ -x "$NOVA_INSTALL_ROOT/src/privacyctl" ]]; then
    source "$NOVA_INSTALL_ROOT/scripts/lib/common.sh"
    load_runtime
    write_runtime_kv NOVA_TRAFFIC_GATE closed
    NOVA_TRAFFIC_GATE=closed "$NOVA_INSTALL_ROOT/scripts/render-firewall.sh" >/dev/null 2>&1 || true
  fi
}
trap rollback ERR

archive="NOVA-Privacy-Core-${tag}.tar.gz"
gh release download "$tag" --repo "$NOVA_REPOSITORY"   --pattern "$archive" --pattern SHA256SUMS --dir "$tmp"

(
  cd "$tmp"
  grep -F "  $archive" SHA256SUMS >SHA256SUMS.selected
  sha256sum -c SHA256SUMS.selected
)

gh attestation verify "$tmp/$archive"   --repo "$NOVA_REPOSITORY"   --signer-workflow "$NOVA_REPOSITORY/.github/workflows/release.yml"   --source-ref "refs/tags/$tag" >/dev/null

python3 - "$tmp/$archive" "$tmp/extracted" "$tag" <<'PY'
import pathlib,sys,tarfile
src=pathlib.Path(sys.argv[1])
dst=pathlib.Path(sys.argv[2])
tag=sys.argv[3]
prefix=f"NOVA-Privacy-Core-{tag}"
dst.mkdir(mode=0o700)
with tarfile.open(src, "r:gz") as tf:
    members=tf.getmembers()
    if not members:
        raise SystemExit("empty NOVA release archive")
    for m in members:
        p=pathlib.PurePosixPath(m.name)
        if p.is_absolute() or ".." in p.parts:
            raise SystemExit(f"unsafe release path: {m.name}")
        if not (m.name == prefix or m.name.startswith(prefix + "/")):
            raise SystemExit(f"unexpected release prefix: {m.name}")
        if m.issym() or m.islnk() or m.isdev():
            raise SystemExit(f"unsafe release member type: {m.name}")
    tf.extractall(dst, members=members, filter="data")
PY

source_root="$tmp/extracted/NOVA-Privacy-Core-$tag"
[[ "$(cat "$source_root/VERSION")" == "${tag#v}" ]] ||
  die "release VERSION does not match tag"

(
  cd "$source_root"
  bash tests/run.sh
  sudo -E bash tests/test-render-firewall.sh
)

bash "$source_root/scripts/install.sh"

# install.sh intentionally leaves a pre-existing closed gate closed.  A
# previously accepted production node may reopen only after the upgraded system
# proves its server-side invariants again.
if [[ "$previous_gate" == "open" ]]; then
  "$NOVA_INSTALL_ROOT/src/privacyctl" health
  "$NOVA_INSTALL_ROOT/scripts/verify-leaks.sh"
  write_runtime_kv NOVA_TRAFFIC_GATE open
  NOVA_TRAFFIC_GATE=open "$NOVA_INSTALL_ROOT/scripts/render-firewall.sh"
fi

trap - ERR
log "NOVA updated successfully: $current -> ${tag#v}"
