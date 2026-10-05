#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_defaults

export DEBIAN_FRONTEND=noninteractive

if [[ ! -r /etc/os-release ]]; then
  die "cannot identify operating system"
fi
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "debian" ]] || warn "target baseline is Debian; detected ${ID:-unknown}"

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl jq gnupg openssl python3 \
  nftables unbound dns-root-data bind9-dnsutils \
  openssh-server qrencode zram-tools age \
  "linux-headers-$(uname -r)"

mkdir -p "$NOVA_ETC" "$NOVA_STATE" "$NOVA_RUN" "$NOVA_INSTALL_ROOT"
chmod 0700 "$NOVA_ETC" "$NOVA_STATE"
chmod 0755 "$NOVA_RUN" "$NOVA_INSTALL_ROOT"

if ! id nova-dns >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/nova-privacy/dns --create-home \
    --shell /usr/sbin/nologin nova-dns
fi

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
[[ -n "$bootstrap_cidr" ]] || warn "SSH source not detected; do not enable firewall remotely without an alternate management path"

runtime="$NOVA_ETC/nova.env"
cat >"$runtime" <<EOF
NOVA_WAN_IF=$(printf '%q' "$wan")
NOVA_PUBLIC_ENDPOINT=$(printf '%q' "$endpoint")
NOVA_BOOTSTRAP_SSH_CIDR=$(printf '%q' "$bootstrap_cidr")
EOF
chmod 0600 "$runtime"

cat >/etc/default/zramswap <<'EOF'
ALGO=zstd
PERCENT=25
PRIORITY=100
EOF
systemctl enable --now zramswap.service 2>/dev/null || warn "zram service could not be started"

log "bootstrap complete: WAN=$wan endpoint=${endpoint:-unset}"
