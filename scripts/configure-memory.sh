#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

require_cmd awk
require_cmd df
require_cmd fallocate
require_cmd systemctl

ram_mib="$(awk '/MemTotal:/ {printf "%d\n", $2/1024}' /proc/meminfo)"
[[ "$ram_mib" =~ ^[0-9]+$ && "$ram_mib" -ge 256 ]] ||
  die "unable to determine usable RAM"

# zram-generator's official default sizing is min(ram/2, 4096 MiB).  Keep that
# conservative, well-tested curve and give zram much higher swap priority than
# encrypted disk swap.
if [[ "$NOVA_ZRAM_POLICY" == "auto" ]]; then
  cat >/etc/systemd/zram-generator.conf <<'EOF'
[zram0]
zram-size = min(ram / 2, 4096)
compression-algorithm = zstd
swap-priority = 200
EOF
elif [[ "$NOVA_ZRAM_POLICY" == "off" ]]; then
  rm -f /etc/systemd/zram-generator.conf
else
  die "unsupported NOVA_ZRAM_POLICY=$NOVA_ZRAM_POLICY"
fi

install -d -m 0700 "$NOVA_STATE/swap"

calculate_swap_mib() {
  local ram="$1" wanted
  if (( ram <= 2048 )); then
    wanted=2048
  elif (( ram <= 4096 )); then
    wanted="$ram"
  else
    wanted=$((ram / 2))
  fi
  (( wanted > NOVA_SWAP_MAX_MIB )) && wanted="$NOVA_SWAP_MAX_MIB"
  printf '%d\n' "$wanted"
}

if [[ "$NOVA_SWAP_POLICY" == "auto" ]]; then
  wanted_mib="$(calculate_swap_mib "$ram_mib")"
  free_mib="$(df -Pm "$NOVA_STATE" | awk 'NR==2 {print $4}')"
  max_by_disk=$((free_mib - NOVA_SWAP_MIN_FREE_MIB))

  if (( max_by_disk < 512 )); then
    warn "not enough free disk for privacy-safe encrypted swap; zram remains available"
    wanted_mib=0
  elif (( wanted_mib > max_by_disk )); then
    wanted_mib="$max_by_disk"
  fi

  if (( wanted_mib > 0 )); then
    current_bytes=0
    [[ -f "$NOVA_STATE/swap/swapfile" ]] &&
      current_bytes="$(stat -c %s "$NOVA_STATE/swap/swapfile" 2>/dev/null || echo 0)"
    wanted_bytes=$((wanted_mib * 1024 * 1024))

    if [[ "$current_bytes" -ne "$wanted_bytes" ]]; then
      systemctl stop nova-encrypted-swap.service 2>/dev/null || true
      rm -f "$NOVA_STATE/swap/swapfile"
      fallocate -l "${wanted_mib}M" "$NOVA_STATE/swap/swapfile"
      chmod 0600 "$NOVA_STATE/swap/swapfile"
    fi
    write_runtime_kv NOVA_SWAP_MIB "$wanted_mib"
  fi
elif [[ "$NOVA_SWAP_POLICY" == "off" ]]; then
  systemctl disable --now nova-encrypted-swap.service 2>/dev/null || true
  rm -f "$NOVA_STATE/swap/swapfile"
  write_runtime_kv NOVA_SWAP_MIB "0"
else
  die "unsupported NOVA_SWAP_POLICY=$NOVA_SWAP_POLICY"
fi

install -m 0644 "$ROOT/config/systemd/nova-encrypted-swap.service"   /etc/systemd/system/nova-encrypted-swap.service

systemctl daemon-reload
if [[ "$NOVA_ZRAM_POLICY" == "auto" ]]; then
  systemctl start dev-zram0.swap 2>/dev/null ||
    warn "zram will become active at next boot if generator activation is deferred"
fi
if [[ "${wanted_mib:-0}" -gt 0 ]]; then
  systemctl enable --now nova-encrypted-swap.service
fi

zram_bytes="$(zramctl --bytes --noheadings --output DISKSIZE /dev/zram0 2>/dev/null | tr -d ' ' || echo 0)"
log "memory policy: RAM=${ram_mib}MiB zram-bytes=${zram_bytes:-0} encrypted-swap=${wanted_mib:-0}MiB"
