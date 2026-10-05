#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

REPO="Alaa91H/NOVA-Privacy-Core"
GH_KEYRING_SHA256="6084d5d7bd8e288441e0e94fc6275570895da18e6751f70f057485dc2d1a811b"
GH_KEY_FPRS="2C6106201985B60E6C7AC87323F3D4EA75716059,7F38BBB59D064DBCB3D84D725612B36462313325"

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
  printf 'NOVA requires Ubuntu Server/Minimal 26.04 LTS; detected %s\n'     "${PRETTY_NAME:-unknown}" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends   ca-certificates curl gnupg jq tar gzip coreutils python3 git

install_official_gh() (
  set -Eeuo pipefail
  local keyring actual arch candidate trusted found allowed
  local -a allowed_fprs=()
  keyring="$(mktemp)"
  trap 'rm -f "$keyring"' EXIT

  curl --proto '=https' --tlsv1.2 -fsSL     --connect-timeout 10 --max-time 30     https://cli.github.com/packages/githubcli-archive-keyring.gpg     -o "$keyring"

  actual="$(sha256sum "$keyring" | awk '{print $1}')"
  [[ "$actual" == "$GH_KEYRING_SHA256" ]] || {
    printf 'GitHub CLI keyring SHA-256 mismatch.\n' >&2
    return 1
  }

  IFS=',' read -r -a allowed_fprs <<<"$GH_KEY_FPRS"
  trusted=0
  while read -r found; do
    for allowed in "${allowed_fprs[@]}"; do
      [[ "$found" == "${allowed^^}" ]] && trusted=1
    done
  done < <(
    gpg --batch --show-keys --with-colons "$keyring" 2>/dev/null |
      awk -F: '$1=="fpr"{print toupper($10)}'
  )
  [[ "$trusted" -eq 1 ]] || {
    printf 'GitHub CLI keyring fingerprint not in bootstrap trust set.\n' >&2
    return 1
  }

  install -d -m 0755 /etc/apt/keyrings /etc/apt/sources.list.d /etc/apt/preferences.d
  install -m 0644 "$keyring" /etc/apt/keyrings/githubcli-archive-keyring.gpg
  arch="$(dpkg --print-architecture)"

  cat >/etc/apt/sources.list.d/github-cli.list <<EOF
deb [arch=$arch signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main
EOF

  cat >/etc/apt/preferences.d/nova-github-cli <<'EOF'
Package: *
Pin: origin cli.github.com
Pin-Priority: 1

Package: gh
Pin: origin cli.github.com
Pin-Priority: 700
EOF

  apt-get update
  candidate="$(apt-cache policy gh | awk '/Candidate:/{print $2; exit}')"
  [[ -n "$candidate" && "$candidate" != "(none)" ]] || {
    printf 'Official GitHub CLI repository has no gh candidate.\n' >&2
    return 1
  }
  apt-get install -y --no-install-recommends gh
  gh_attestation_help="$(gh attestation verify --help 2>&1 || true)"
  grep -q -- '--bundle' <<<"$gh_attestation_help" || {
    printf 'Installed GitHub CLI lacks attestation bundle support.\n' >&2
    return 1
  }
)

install_official_gh

tmp="$(mktemp -d /tmp/nova-bootstrap.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

source_mode="${NOVA_SOURCE:-release}"
if [[ "$source_mode" == "release" ]]; then
  meta="$(
    curl --proto '=https' --tlsv1.2 -fsSL       --connect-timeout 10 --max-time 30       "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || true
  )"
  [[ -n "$meta" ]] || {
    printf 'No stable NOVA release exists yet. For an explicit audited development deployment set NOVA_SOURCE=main.\n' >&2
    exit 1
  }

  tag="$(jq -er 'select(.draft==false and .prerelease==false) | .tag_name' <<<"$meta")"
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    printf 'Unexpected release tag: %s\n' "$tag" >&2
    exit 1
  }

  asset_url() {
    local name="$1"
    jq -er --arg name "$name"       '.assets[] | select(.name==$name) | .browser_download_url' <<<"$meta"
  }

  archive="NOVA-Privacy-Core-${tag}.tar.gz"
  bundle="NOVA-Privacy-Core-${tag}.attestation.jsonl"

  for asset in "$archive" SHA256SUMS "$bundle"; do
    url="$(asset_url "$asset")"
    curl --proto '=https' --tlsv1.2 -fsSL       --connect-timeout 10 --max-time 180       "$url" -o "$tmp/$asset"
  done

  (
    cd "$tmp"
    grep -F "  $archive" SHA256SUMS >SHA256SUMS.selected
    [[ -s SHA256SUMS.selected ]]
    sha256sum -c SHA256SUMS.selected
  )

  gh attestation verify "$tmp/$archive"     --bundle "$tmp/$bundle"     --repo "$REPO"     --signer-workflow "$REPO/.github/workflows/release.yml"     --source-ref "refs/tags/$tag" >/dev/null

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

  src="$tmp/extracted/NOVA-Privacy-Core-$tag"
  [[ "$(cat "$src/VERSION")" == "${tag#v}" ]] || {
    printf 'Release VERSION does not match tag.\n' >&2
    exit 1
  }
elif [[ "$source_mode" == "main" ]]; then
  printf 'WARNING: NOVA_SOURCE=main is an explicit development deployment and is not release-attested.\n' >&2
  git clone --depth 1 "https://github.com/$REPO.git" "$tmp/source"
  src="$tmp/source"
else
  printf 'Unsupported NOVA_SOURCE=%s\n' "$source_mode" >&2
  exit 1
fi

exec bash "$src/scripts/install.sh"
