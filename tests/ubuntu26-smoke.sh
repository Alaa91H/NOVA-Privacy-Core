#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$SOURCE_ROOT"
cd "$ROOT"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf 'ubuntu26-smoke.sh must run as root inside the target container\n' >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends   bash git shellcheck nftables python3 python3-yaml ca-certificates   openssh-server unbound systemd-zram-generator cryptsetup-bin   curl gnupg jq iproute2 procps golang-go gcc libc6-dev

# Exact platform baseline.
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "26.04" ]] ||
  { printf 'unexpected target image: %s\n' "${PRETTY_NAME:-unknown}" >&2; exit 1; }

unbound_version="$(dpkg-query -W unbound | awk '{print $2}')"
dpkg --compare-versions "$unbound_version" ge "1.24.2-1ubuntu2.1"

ssh -Q kex | grep -qx mlkem768x25519-sha256
apt-cache show linux-oracle-7.0 >/dev/null

# Ubuntu's gh package may lag attestation support. Validate the same signed
# official GitHub CLI repository path used by production.
bash "$ROOT/scripts/install-github-cli.sh"
gh attestation verify --help | grep -q -- '--bundle'

# Validate the exact third-party package trust boundary used by production.
expected_fpr="75C9DD72C799870E310542E24166F2C257290828"
tmp_key="$(mktemp)"
tmp_gnupg="$(mktemp -d)"
trap 'rm -f "$tmp_key"; rm -rf "$tmp_gnupg"' EXIT
chmod 0700 "$tmp_gnupg"

curl --proto '=https' --tlsv1.2 -4 -fsSL   --connect-timeout 10 --max-time 30   "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$expected_fpr"   -o "$tmp_key"

mapfile -t fprs < <(
  gpg --homedir "$tmp_gnupg" --batch --show-keys --with-colons "$tmp_key" 2>/dev/null |
    awk -F: '$1=="fpr"{print toupper($10)}'
)
printf '%s\n' "${fprs[@]}" | grep -qx "$expected_fpr"

install -d -m 0755 /etc/apt/keyrings
gpg --homedir "$tmp_gnupg" --batch --dearmor --yes   -o /etc/apt/keyrings/amnezia.gpg "$tmp_key"
chmod 0644 /etc/apt/keyrings/amnezia.gpg

cat >/etc/apt/sources.list.d/nova-amnezia.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/amnezia.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main
EOF

cat >/etc/apt/preferences.d/nova-amnezia <<'EOF'
Package: *
Pin: release o=LP-PPA-amnezia
Pin-Priority: 1

Package: amneziawg-tools
Pin: release o=LP-PPA-amnezia
Pin-Priority: 700

Package: amneziawg amneziawg-dkms
Pin: release o=LP-PPA-amnezia
Pin-Priority: -1
EOF

apt-get update
tools_candidate="$(apt-cache policy amneziawg-tools | awk '/Candidate:/{print $2; exit}')"
[[ -n "$tools_candidate" && "$tools_candidate" != "(none)" ]]

dkms_candidate="$(apt-cache policy amneziawg-dkms 2>/dev/null | awk '/Candidate:/{print $2; exit}' || true)"
[[ -z "$dkms_candidate" || "$dkms_candidate" == "(none)" ]]

apt-get install -y --no-install-recommends amneziawg-tools
command -v awg >/dev/null
command -v awg-quick >/dev/null
awg --version >/dev/null

# Validate Go/toolchain compatibility and checksum-backed userspace build.
go_version="$(go env GOVERSION)"
python3 - "$go_version" <<'PY'
import re,sys
m=re.fullmatch(r"go(\d+)\.(\d+)(?:\.\d+)?", sys.argv[1])
if not m or tuple(map(int, m.groups())) < (1,25):
    raise SystemExit(f"Go >= 1.25 required; got {sys.argv[1]!r}")
PY

target_go="$(
  curl --proto '=https' --tlsv1.2 -fsSL     --connect-timeout 10 --max-time 30     https://proxy.golang.org/github.com/amnezia-vpn/amneziawg-go/v3/@v/list |
    grep -E '^v3\.1\.[0-9]+$' |
    sort -V |
    tail -n1
)"
[[ -n "$target_go" ]]

module="github.com/amnezia-vpn/amneziawg-go/v3@$target_go"
download_json="$(
  GOPROXY="https://proxy.golang.org"   GOSUMDB="sum.golang.org"   GOTOOLCHAIN="local"     go mod download -json "$module"
)"
module_dir="$(jq -er '.Dir' <<<"$download_json")"
module_sum="$(jq -er '.Sum' <<<"$download_json")"
go_mod_sum="$(jq -er '.GoModSum' <<<"$download_json")"
[[ -d "$module_dir" && "$module_sum" == h1:* && "$go_mod_sum" == h1:* ]]

build_dir="$(mktemp -d)"
trap 'rm -f "$tmp_key"; rm -rf "$tmp_gnupg" "$build_dir"' EXIT
cp -a "$module_dir/." "$build_dir/"
cat >"$build_dir/version.go" <<EOF
package main

const Version = "$target_go"
EOF

(
  cd "$build_dir"
  GOPROXY="https://proxy.golang.org"   GOSUMDB="sum.golang.org"   GOTOOLCHAIN="local"   GOMAXPROCS=1   GOFLAGS="-trimpath -buildvcs=false -p=1"     go build -o "$build_dir/amneziawg-go" .
)

[[ -x "$build_dir/amneziawg-go" ]]
reported="$("$build_dir/amneziawg-go" --version 2>/dev/null | awk 'NR==1{print $2}')"
[[ "$reported" == "$target_go" ]]

# Re-run repository contracts under the actual production userspace.
bash tests/run.sh
bash tests/test-render-firewall.sh

printf 'PASS Ubuntu 26.04 target smoke: unbound=%s awg-tools=%s awg-go=%s go=%s\n'   "$unbound_version" "$tools_candidate" "$target_go" "$go_version"
