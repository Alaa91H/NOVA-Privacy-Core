#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
require_cmd ip
require_cmd curl
require_cmd gpg
require_cmd sha256sum

[[ "${NOVA_AWG_BACKEND:-userspace}" == "userspace" ]] ||
  die "Ubuntu 26.04 production supports only NOVA_AWG_BACKEND=userspace until the upstream kernel-7.0 regressions are resolved"

export DEBIAN_FRONTEND=noninteractive

resolve_awg_go_version() {
  if [[ "${NOVA_AWG_GO_VERSION:-auto}" != "auto" ]]; then
    [[ "$NOVA_AWG_GO_VERSION" =~ ^v3\.1\.[0-9]+$ ]] ||
      die "NOVA_AWG_GO_VERSION must be auto or a v3.1.x tag"
    printf '%s\n' "$NOVA_AWG_GO_VERSION"
    return 0
  fi

  curl --proto '=https' --tlsv1.2 -fsSL     --connect-timeout 10 --max-time 30     "https://proxy.golang.org/github.com/amnezia-vpn/amneziawg-go/v3/@v/list" |
    grep -E '^v3\.1\.[0-9]+$' |
    sort -V |
    tail -n1
}

probe_awg31_userspace() (
  set -Eeuo pipefail
  require_cmd awg
  require_cmd /usr/local/sbin/amneziawg-go

  local dev="nova-awg-probe"
  local cfg
  cfg="$(mktemp)"
  local key header
  key="$(awg genkey)"
  header="$(awg genkey)"
  trap 'ip link del "$dev" >/dev/null 2>&1 || true; rm -f "$cfg"' EXIT

  ip link del "$dev" >/dev/null 2>&1 || true
  LOG_LEVEL=error /usr/local/sbin/amneziawg-go "$dev" >/dev/null 2>&1

  for _ in {1..50}; do
    ip link show "$dev" >/dev/null 2>&1 && break
    sleep 0.1
  done
  ip link show "$dev" >/dev/null 2>&1 || exit 1

  cat >"$cfg" <<EOF
[Interface]
PrivateKey = $key
Jc = 4
Jmin = 8
Jmax = 80
S1 = 31
S2 = 47
S3 = 63
S4 = 79
H1 = 101
H2 = 103
H3 = 107
H4 = 109
HeaderProtectionKey = $header
ContentPaddingAddition = 10-50
RandomTrailers = off
DisableCookies = off
EOF
  chmod 0600 "$cfg"

  awg setconf "$dev" "$cfg" >/dev/null 2>&1
  awg show "$dev" >/dev/null 2>&1
)

old_tools="$(dpkg-query -W -f='${Version}' amneziawg-tools 2>/dev/null || true)"
old_go="$(/usr/local/sbin/amneziawg-go --version 2>/dev/null | awk 'NR==1{print $2}' || true)"

# Only the userspace CLI package is accepted from the signed Amnezia PPA.
# The kernel module/meta packages are deliberately excluded on Ubuntu 26.04.
apt-get -o DPkg::Lock::Timeout=600 update
apt-get -o DPkg::Lock::Timeout=600 install -y --no-install-recommends   curl ca-certificates gnupg golang-go make gcc libc6-dev

mkdir -p /etc/apt/keyrings
tmp_key="$(mktemp)"
build_dir="$(mktemp -d)"
trap 'rm -f "$tmp_key"; rm -rf "$build_dir"' EXIT

key_url="https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${NOVA_AMNEZIA_APT_FPR}"
curl --proto '=https' --tlsv1.2 -4 -fsSL   --connect-timeout 10 --max-time 30 "$key_url" -o "$tmp_key"

mapfile -t fingerprints < <(
  gpg --batch --show-keys --with-colons "$tmp_key" 2>/dev/null |
    awk -F: '$1=="fpr"{print toupper($10)}'
)
[[ "${#fingerprints[@]}" -ge 1 ]] || die "no fingerprint found in downloaded Amnezia key"
found=0
for fpr in "${fingerprints[@]}"; do
  [[ "$fpr" == "${NOVA_AMNEZIA_APT_FPR^^}" ]] && found=1
done
[[ "$found" -eq 1 ]] || die "Amnezia repository signing-key fingerprint mismatch"

gpg --batch --dearmor --yes -o /etc/apt/keyrings/amnezia.gpg "$tmp_key"
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

apt-get -o DPkg::Lock::Timeout=600 update
candidate="$(apt-cache policy amneziawg-tools 2>/dev/null | awk '/Candidate:/{print $2; exit}')"
[[ -n "$candidate" && "$candidate" != "(none)" ]] ||
  die "signed Amnezia PPA has no amneziawg-tools candidate"

apt-get -o DPkg::Lock::Timeout=600 install -y --no-install-recommends amneziawg-tools
require_cmd awg
require_cmd awg-quick

target_go="$(resolve_awg_go_version)"
[[ -n "$target_go" ]] || die "could not resolve a stable AmneziaWG-go v3.1 tag"

GOBIN="$build_dir/bin" GOPROXY="https://proxy.golang.org" GOSUMDB="sum.golang.org" GOTOOLCHAIN="local" GOMAXPROCS=1 GOFLAGS="-trimpath -buildvcs=false -p=1"   go install "github.com/amnezia-vpn/amneziawg-go/v3@$target_go"

[[ -x "$build_dir/bin/amneziawg-go" ]] || die "AmneziaWG-go build produced no binary"
new_report="$("$build_dir/bin/amneziawg-go" --version 2>/dev/null | awk 'NR==1{print $2}')"
[[ "$new_report" == "$target_go" ]] ||
  die "AmneziaWG-go version mismatch: requested=$target_go built=${new_report:-unknown}"

install -m 0755 "$build_dir/bin/amneziawg-go" /usr/local/sbin/amneziawg-go
new_hash="$(sha256sum /usr/local/sbin/amneziawg-go | awk '{print $1}')"

probe_awg31_userspace ||
  die "official AmneziaWG-go $target_go failed NOVA's AWG 3.1 userspace capability probe"

new_tools="$(dpkg-query -W -f='${Version}' amneziawg-tools 2>/dev/null || echo unknown)"
write_runtime_kv NOVA_AWG_BACKEND "userspace"
write_runtime_kv NOVA_AWG_GO_INSTALLED_VERSION "$target_go"
write_runtime_kv NOVA_AWG_GO_SHA256 "$new_hash"
write_runtime_kv NOVA_AWG_TOOLS_PACKAGE_VERSION "$new_tools"

if ip link show "$NOVA_VPN_IF" >/dev/null 2>&1 &&
   { [[ -n "$old_go" && "$old_go" != "$target_go" ]] ||
     [[ -n "$old_tools" && "$old_tools" != "$new_tools" ]]; }; then
  touch /var/run/reboot-required
  {
    printf 'amneziawg-go\n'
    printf 'amneziawg-tools\n'
  } >/var/run/reboot-required.pkgs
  warn "AWG userspace/tools changed while tunnel is active; reboot required before reopening protected forwarding"
fi

log "AmneziaWG userspace path verified: go=$target_go tools=$new_tools sha256=$new_hash"
