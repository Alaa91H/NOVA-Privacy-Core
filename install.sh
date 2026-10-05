#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

REPO="Alaa91H/NOVA-Privacy-Core"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf 'Run this bootstrap installer as root, for example: sudo bash install.sh\n' >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  printf 'Cannot identify operating system.\n' >&2
  exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "26.04" ]]; then
  printf 'NOVA requires Ubuntu Server/Minimal 26.04 LTS; detected %s\n' "${PRETTY_NAME:-unknown}" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates gh jq tar gzip coreutils python3

tmp="$(mktemp -d /tmp/nova-bootstrap.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

source_mode="${NOVA_SOURCE:-release}"
if [[ "$source_mode" == "release" ]]; then
  meta="$(gh release view --repo "$REPO" --json tagName,isDraft,isPrerelease 2>/dev/null || true)"
  [[ -n "$meta" ]] || {
    printf 'No stable NOVA release exists yet. For an explicit audited development deployment set NOVA_SOURCE=main.\n' >&2
    exit 1
  }
  tag="$(jq -er 'select(.isDraft==false and .isPrerelease==false) | .tagName' <<<"$meta")"
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    printf 'Unexpected release tag: %s\n' "$tag" >&2
    exit 1
  }

  archive="NOVA-Privacy-Core-${tag}.tar.gz"
  gh release download "$tag" --repo "$REPO"     --pattern "$archive" --pattern SHA256SUMS --dir "$tmp"

  (
    cd "$tmp"
    grep -F "  $archive" SHA256SUMS >SHA256SUMS.selected
    sha256sum -c SHA256SUMS.selected
  )

  gh attestation verify "$tmp/$archive"     --repo "$REPO"     --signer-workflow "$REPO/.github/workflows/release.yml"     --source-ref "refs/tags/$tag" >/dev/null

  tar -C "$tmp" -xzf "$tmp/$archive"
  src="$tmp/NOVA-Privacy-Core-$tag"
elif [[ "$source_mode" == "main" ]]; then
  printf 'WARNING: NOVA_SOURCE=main is a development deployment and is not release-attested.\n' >&2
  git_pkg=git
  apt-get install -y --no-install-recommends "$git_pkg"
  git clone --depth 1 "https://github.com/$REPO.git" "$tmp/source"
  src="$tmp/source"
else
  printf 'Unsupported NOVA_SOURCE=%s\n' "$source_mode" >&2
  exit 1
fi

exec bash "$src/scripts/install.sh"
