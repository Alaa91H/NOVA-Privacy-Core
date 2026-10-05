#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

if command -v awg >/dev/null 2>&1 && modinfo amneziawg >/dev/null 2>&1; then
  log "AmneziaWG tools and kernel module already available"
  awg --version || true
  exit 0
fi

[[ "${NOVA_AWG_INSTALL_MODE}" == "ppa" ]] || die "AmneziaWG is missing and NOVA_AWG_INSTALL_MODE is not ppa"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates gnupg dkms "linux-headers-$(uname -r)"

mkdir -p /etc/apt/keyrings
tmp_key="$(mktemp)"
trap 'rm -f "$tmp_key"' EXIT

key_url="https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${NOVA_AMNEZIA_APT_FPR}"
curl -4 -fsSL --connect-timeout 10 --max-time 30 "$key_url" -o "$tmp_key"

mapfile -t fingerprints < <(gpg --batch --show-keys --with-colons "$tmp_key" 2>/dev/null | awk -F: '$1=="fpr"{print toupper($10)}')
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

apt-get update
apt-get install -y amneziawg amneziawg-tools

modprobe amneziawg
modinfo amneziawg >/dev/null
require_cmd awg
require_cmd awg-quick

log "AmneziaWG installed"
awg --version || true
