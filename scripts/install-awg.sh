#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
require_cmd ip

probe_awg31() (
  set -Eeuo pipefail
  command -v awg >/dev/null 2>&1 || exit 1
  command -v awg-quick >/dev/null 2>&1 || exit 1
  modinfo amneziawg >/dev/null 2>&1 || exit 1

  dev="nova-awg-probe"
  cfg="$(mktemp)"
  key="$(awg genkey)"
  header="$(awg genkey)"
  trap 'ip link del "$dev" >/dev/null 2>&1 || true; rm -f "$cfg"' EXIT

  ip link del "$dev" >/dev/null 2>&1 || true
  ip link add dev "$dev" type amneziawg >/dev/null 2>&1 || exit 1

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

  awg setconf "$dev" "$cfg" >/dev/null 2>&1 || exit 1
  awg show "$dev" >/dev/null 2>&1
)


if command -v awg >/dev/null 2>&1 && modinfo amneziawg >/dev/null 2>&1; then
  modprobe amneziawg || true
  if probe_awg31; then
    log "compatible AmneziaWG 3.1 tool/module path already available"
    awg --version || true
    exit 0
  fi
  warn "existing AmneziaWG path does not pass NOVA's AWG 3.1 capability probe; upgrading"
fi

[[ "${NOVA_AWG_INSTALL_MODE}" == "ppa" ]] ||
  die "AmneziaWG is missing/incompatible and NOVA_AWG_INSTALL_MODE is not ppa"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends   curl ca-certificates gnupg dkms "linux-headers-$(uname -r)"

mkdir -p /etc/apt/keyrings
tmp_key="$(mktemp)"
trap 'rm -f "$tmp_key"' EXIT

key_url="https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${NOVA_AMNEZIA_APT_FPR}"
curl --proto '=https' --tlsv1.2 -4 -fsSL --connect-timeout 10 --max-time 30   "$key_url" -o "$tmp_key"

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

# This is the Debian installation path documented by upstream Amnezia.
cat >/etc/apt/sources.list.d/nova-amnezia.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/amnezia.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main
EOF

# Constrain the third-party repository to the exact package family NOVA needs.
# Even a correctly signed PPA must not be allowed to override unrelated Debian
# security/base packages.
cat >/etc/apt/preferences.d/nova-amnezia <<'EOF'
Package: *
Pin: release o=LP-PPA-amnezia
Pin-Priority: 1

Package: amneziawg amneziawg-tools amneziawg-dkms
Pin: release o=LP-PPA-amnezia
Pin-Priority: 700
EOF

apt-get update
candidate="$(apt-cache policy amneziawg 2>/dev/null | awk '/Candidate:/{print $2; exit}')"
[[ -n "$candidate" && "$candidate" != "(none)" ]] ||
  die "AmneziaWG PPA has no install candidate for this host/kernel"

packages=(amneziawg amneziawg-tools)
if apt-cache show amneziawg-dkms >/dev/null 2>&1; then
  packages+=(amneziawg-dkms)
fi
apt-get install -y --no-install-recommends "${packages[@]}"

# A metapackage can leave an already-loaded old DKMS module resident.  Reload
# only when NOVA's interface is not active; never tear down a production tunnel
# implicitly during an upgrade.
if lsmod | awk '{print $1}' | grep -qx amneziawg &&
   ! ip link show "$NOVA_VPN_IF" >/dev/null 2>&1; then
  modprobe -r amneziawg || true
fi
modprobe amneziawg
modinfo amneziawg >/dev/null
require_cmd awg
require_cmd awg-quick

if ! probe_awg31; then
  module_disk="$(modinfo -F version amneziawg 2>/dev/null || echo unknown)"
  module_loaded="$(cat /sys/module/amneziawg/version 2>/dev/null || echo unknown)"
  die "installed AmneziaWG failed 3.1 capability probe (disk=$module_disk loaded=$module_loaded); do not deploy incompatible 3.1 parameters"
fi

tools_version="$(dpkg-query -W -f='${Version}' amneziawg-tools 2>/dev/null || echo unknown)"
meta_version="$(dpkg-query -W -f='${Version}' amneziawg 2>/dev/null || echo unknown)"
dkms_version="$(dpkg-query -W -f='${Version}' amneziawg-dkms 2>/dev/null || echo unavailable)"
write_runtime_kv NOVA_AWG_TOOLS_PACKAGE_VERSION "$tools_version"
write_runtime_kv NOVA_AWG_META_PACKAGE_VERSION "$meta_version"
write_runtime_kv NOVA_AWG_DKMS_PACKAGE_VERSION "$dkms_version"

log "AmneziaWG 3.1 capability probe passed"
log "recorded package versions: tools=$tools_version meta=$meta_version dkms=$dkms_version"
awg --version || true
