#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
require_cmd cryptsetup
require_cmd losetup
require_cmd mkswap
require_cmd swapon
require_cmd swapoff

backing_dir="$NOVA_STATE/swap"
backing_file="$backing_dir/swapfile"
mapping="nova-swap"
mapper="/dev/mapper/$mapping"
loop_state="$NOVA_RUN/swap.loop"

start_swap() {
  [[ -s "$backing_file" ]] || die "encrypted swap backing file missing: $backing_file"
  install -d -m 0700 "$NOVA_RUN"

  if swapon --noheadings --show=NAME 2>/dev/null | grep -Fxq "$mapper"; then
    log "encrypted disk swap already active"
    return 0
  fi

  if [[ -e "$mapper" ]]; then
    cryptsetup close "$mapping" || die "stale encrypted swap mapping could not be closed"
  fi

  local loopdev
  loopdev="$(losetup --find --show "$backing_file")"
  printf '%s\n' "$loopdev" >"$loop_state"
  chmod 0600 "$loop_state"

  rollback() {
    swapoff "$mapper" >/dev/null 2>&1 || true
    cryptsetup close "$mapping" >/dev/null 2>&1 || true
    losetup -d "$loopdev" >/dev/null 2>&1 || true
    rm -f "$loop_state"
  }
  trap rollback ERR

  # Plain dm-crypt with an ephemeral 512-bit XTS key sourced directly from the
  # kernel CSPRNG.  The key is never persisted, so old swap ciphertext becomes
  # unrecoverable after shutdown/reboot.
  cryptsetup open     --type plain     --cipher aes-xts-plain64     --key-size 512     --key-file /dev/urandom     "$loopdev" "$mapping"

  mkswap -f "$mapper" >/dev/null
  swapon -p 10 "$mapper"
  trap - ERR
  log "ephemeral encrypted disk swap enabled on $mapper"
}

stop_swap() {
  if swapon --noheadings --show=NAME 2>/dev/null | grep -Fxq "$mapper"; then
    swapoff "$mapper"
  fi
  if [[ -e "$mapper" ]]; then
    cryptsetup close "$mapping"
  fi
  if [[ -r "$loop_state" ]]; then
    loopdev="$(cat "$loop_state")"
    [[ -n "$loopdev" ]] && losetup -d "$loopdev" >/dev/null 2>&1 || true
    rm -f "$loop_state"
  fi
}

case "${1:-start}" in
  start) start_swap ;;
  stop) stop_swap ;;
  *) die "usage: encrypted-swap.sh [start|stop]" ;;
esac
