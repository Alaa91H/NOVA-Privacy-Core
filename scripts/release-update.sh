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

for cmd in curl gh jq sha256sum python3 rsync tar; do
  require_cmd "$cmd"
done

release_json="$(
  curl --proto '=https' --tlsv1.2 -fsSL     --connect-timeout 10 --max-time 30     "https://api.github.com/repos/$NOVA_REPOSITORY/releases/latest" 2>/dev/null || true
)"
[[ -n "$release_json" ]] || {
  warn "no published NOVA stable release available"
  exit 0
}

tag="$(jq -er 'select(.draft==false and .prerelease==false) | .tag_name' <<<"$release_json")"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  die "refusing unexpected NOVA release tag: $tag"

current="$(cat "$ROOT/VERSION" 2>/dev/null || echo 0.0.0)"
if ! dpkg --compare-versions "${tag#v}" gt "$current"; then
  log "NOVA is current: installed=$current latest=${tag#v}"
  exit 0
fi

asset_url() {
  local name="$1"
  jq -er --arg name "$name"     '.assets[] | select(.name==$name) | .browser_download_url'     <<<"$release_json"
}

archive="NOVA-Privacy-Core-${tag}.tar.gz"
bundle="NOVA-Privacy-Core-${tag}.attestation.jsonl"
previous_gate="${NOVA_TRAFFIC_GATE:-closed}"
tmp="$(mktemp -d /run/nova-release.XXXXXX)"
rollback_dir="$NOVA_STATE/rollback"
config_snapshot="$tmp/etc-nova-privacy"
install -d -m 0700 "$rollback_dir"
trap 'rm -rf "$tmp"' EXIT

# Download and cryptographically authenticate the complete candidate before
# changing active code or disrupting accepted user forwarding.
for asset in "$archive" SHA256SUMS "$bundle"; do
  url="$(asset_url "$asset")"
  curl --proto '=https' --tlsv1.2 -fsSL     --connect-timeout 10 --max-time 180     "$url" -o "$tmp/$asset"
done

(
  cd "$tmp"
  grep -F "  $archive" SHA256SUMS >SHA256SUMS.selected
  [[ -s SHA256SUMS.selected ]]
  sha256sum -c SHA256SUMS.selected
)

gh attestation verify "$tmp/$archive"   --bundle "$tmp/$bundle"   --repo "$NOVA_REPOSITORY"   --signer-workflow "$NOVA_REPOSITORY/.github/workflows/release.yml"   --source-ref "refs/tags/$tag" >/dev/null

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
  bash tests/test-render-firewall.sh
)

# Only now enter maintenance mode, through the single atomic gate.
"$ROOT/scripts/atomic-safety-gate.sh" close release-update
load_runtime

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

  if [[ -x "$NOVA_INSTALL_ROOT/src/privacyctl" ]]; then
    # shellcheck disable=SC1090
    source "$NOVA_INSTALL_ROOT/scripts/lib/common.sh"
    load_runtime
    "$NOVA_INSTALL_ROOT/scripts/atomic-safety-gate.sh" close release-rollback >/dev/null 2>&1 || true
  fi
}
trap rollback ERR

bash "$source_root/scripts/install.sh"

# A previously accepted production node reopens only after the new code proves
# its invariants.  Pending reboot always wins and leaves the gate closed.
if [[ "$previous_gate" == "open" && ! -e /var/run/reboot-required ]]; then
  "$NOVA_INSTALL_ROOT/scripts/reopen-verified.sh"
elif [[ "$previous_gate" == "open" && -e /var/run/reboot-required ]]; then
  install -d -m 0700 "$NOVA_STATE/maintenance"
  printf 'open\n' >"$NOVA_STATE/maintenance/reopen-after-boot"
  chmod 0600 "$NOVA_STATE/maintenance/reopen-after-boot"
  warn "release update requires reboot; traffic remains CLOSED until post-boot verification"
fi

trap - ERR
log "NOVA updated successfully: $current -> ${tag#v}"
