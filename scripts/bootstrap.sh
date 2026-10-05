#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_defaults

export DEBIAN_FRONTEND=noninteractive

is_ubuntu_2604 ||
  die "NOVA production baseline requires Ubuntu Server/Minimal 26.04 LTS; detected $(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}")"

if [[ -n "${SSH_CONNECTION:-}" && "${SSH_CONNECTION%% *}" == *:* ]]; then
  die "active SSH session uses IPv6 but NOVA v1 is fail-closed for IPv6; reconnect over IPv4 or use Oracle Console"
fi

# Ubuntu Minimal may not expose Universe by default.  Enable it through Ubuntu's
# own signed archive before installing Unbound/zram utilities.
apt-get update
apt-get install -y --no-install-recommends   ca-certificates software-properties-common ubuntu-keyring
add-apt-repository -y universe
apt-get update

# Bring the base image, including kernel/security fixes, current before NOVA
# installs kernel modules or starts protected services.
apt-get -y full-upgrade

packages=(
  ca-certificates curl jq gnupg openssl python3 util-linux rsync sudo git gh
  nftables unbound dns-root-data bind9-dnsutils
  openssh-server qrencode age apache2-utils
  apparmor apparmor-utils unattended-upgrades needrestart
  systemd-zram-generator cryptsetup-bin dmsetup
  dkms iproute2 procps
)
apt-get install -y --no-install-recommends "${packages[@]}"

# Keep the host on Canonical's Oracle-tuned GA kernel when running in OCI.
if is_oci_host; then
  apt-get install -y --no-install-recommends linux-oracle linux-headers-oracle
  write_runtime_kv NOVA_PLATFORM "oci"
  write_runtime_kv NOVA_KERNEL_TRACK "linux-oracle"
else
  apt-get install -y --no-install-recommends linux-generic linux-headers-generic
  write_runtime_kv NOVA_PLATFORM "generic"
  write_runtime_kv NOVA_KERNEL_TRACK "linux-generic"
fi

# DKMS must be able to build for the currently running kernel as well.
if apt-cache show "linux-headers-$(uname -r)" >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends "linux-headers-$(uname -r)"
else
  warn "running-kernel headers are unavailable; a reboot into the installed GA kernel may be required before AWG can build"
fi

unbound_pkg="$(dpkg-query -W -f='${Version}' unbound 2>/dev/null || true)"
[[ -n "$unbound_pkg" ]] || die "Unbound package is not installed"
# Ubuntu 26.04 fixes the 2026 Unbound security issues in this package line.
dpkg --compare-versions "$unbound_pkg" ge "1.24.2-1ubuntu2.1" ||
  die "Ubuntu 26.04 security-fixed Unbound is required; installed: $unbound_pkg"

mkdir -p "$NOVA_ETC" "$NOVA_STATE" "$NOVA_RUN" "$NOVA_INSTALL_ROOT"
chmod 0700 "$NOVA_ETC" "$NOVA_STATE"
chmod 0755 "$NOVA_RUN" "$NOVA_INSTALL_ROOT"

if ! id nova-dns >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/nova-privacy/dns --create-home     --shell /usr/sbin/nologin nova-dns
fi

chown root:nova-dns "$NOVA_ETC"
chmod 0710 "$NOVA_ETC"

wan="${NOVA_WAN_IF:-}"
[[ -n "$wan" ]] || wan="$(detect_wan_if)"
[[ -n "$wan" ]] || die "unable to detect WAN interface; set NOVA_WAN_IF"

endpoint="${NOVA_PUBLIC_ENDPOINT:-}"
if [[ -z "$endpoint" ]]; then
  endpoint="$(detect_oci_public_ip || true)"
fi
if [[ -z "$endpoint" ]]; then
  warn "public endpoint not detected; peer export will require NOVA_PUBLIC_ENDPOINT"
fi

bootstrap_cidr="${NOVA_BOOTSTRAP_SSH_CIDR:-}"
if [[ -z "$bootstrap_cidr" ]]; then
  bootstrap_cidr="$(capture_bootstrap_ssh_cidr || true)"
fi
[[ -n "$bootstrap_cidr" ]] ||
  warn "SSH source not detected; do not activate the firewall remotely without Oracle Console/OOB access"

runtime="$NOVA_ETC/nova.env"
first_install=0
[[ -e "$runtime" ]] || first_install=1
touch "$runtime"
chmod 0600 "$runtime"

write_runtime_kv NOVA_WAN_IF "$wan"
write_runtime_kv NOVA_PUBLIC_ENDPOINT "$endpoint"
write_runtime_kv NOVA_BOOTSTRAP_SSH_CIDR "$bootstrap_cidr"
write_runtime_kv NOVA_REPOSITORY "$NOVA_REPOSITORY"
write_runtime_kv NOVA_REPOSITORY_URL "$NOVA_REPOSITORY_URL"
write_runtime_kv NOVA_OS_BASELINE "ubuntu-26.04"

if [[ "$first_install" -eq 1 ]]; then
  # No protected forwarding is permitted until a real management peer exists,
  # all core health checks pass, and the operator explicitly activates NOVA.
  write_runtime_kv NOVA_TRAFFIC_GATE "closed"
fi

log "bootstrap complete: Ubuntu 26.04 LTS WAN=$wan endpoint=${endpoint:-unset} platform=$(is_oci_host && echo oci || echo generic)"
