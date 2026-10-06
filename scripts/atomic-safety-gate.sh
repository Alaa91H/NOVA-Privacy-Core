#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

cmd="${1:-status}"
case "$cmd" in
  watchdog|deadman) ;;
  *) acquire_nova_lock ;;
esac

for bin in nft python3 sha256sum; do
  require_cmd "$bin"
done

gate_dir="$NOVA_STATE/gate"
seal="$gate_dir/accepted.env"
pending="$NOVA_RUN/gate.pending"
boot_id_file="/proc/sys/kernel/random/boot_id"
install -d -m 0700 "$gate_dir" "$NOVA_RUN"

boot_id() {
  tr -d '\n' <"$boot_id_file"
}

atomic_record() {
  local path="$1"
  shift
  (( $# > 0 && $# % 2 == 0 )) || die "atomic_record requires KEY VALUE pairs"
  python3 - "$path" "$@" <<'PY'
import os, pathlib, re, sys, tempfile
p=pathlib.Path(sys.argv[1]); args=sys.argv[2:]
pairs=list(zip(args[0::2], args[1::2]))
key_re=re.compile(r"^[A-Z][A-Z0-9_]*$")
for k,_ in pairs:
    if not key_re.fullmatch(k):
        raise SystemExit(f"invalid record key: {k!r}")
p.parent.mkdir(parents=True, exist_ok=True)
fd,tmp=tempfile.mkstemp(prefix="."+p.name+".", dir=p.parent)
try:
    os.fchmod(fd,0o600)
    data=("\n".join(f"{k}={v}" for k,v in pairs)+"\n").encode()
    with os.fdopen(fd,"wb",closefd=True) as fh:
        fh.write(data); fh.flush(); os.fsync(fh.fileno())
    os.replace(tmp,p)
    dfd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(dfd)
    finally: os.close(dfd)
finally:
    try: os.unlink(tmp)
    except FileNotFoundError: pass
PY
}

record_field() {
  local path="$1" wanted="$2"
  [[ -f "$path" && ! -L "$path" ]] || return 1
  [[ "$(stat -c %u "$path")" == "0" ]] || return 1
  local perm
  perm="$(stat -c %a "$path")"
  (( (8#$perm & 077) == 0 )) || return 1
  awk -F= -v k="$wanted" '$1==k{print substr($0,length(k)+2); found=1; exit} END{if(!found) exit 1}' "$path"
}

emergency_kernel_close() {
  valid_ifname "$NOVA_VPN_IF" || die "unsafe VPN interface name"
  local emergency
  emergency="$(mktemp "$NOVA_RUN/emergency.XXXXXX.nft")"
  cat >"$emergency" <<EOF
destroy table inet nova_emergency

table inet nova_emergency {
  chain forward {
    type filter hook forward priority -300; policy accept;
    iifname "$NOVA_VPN_IF" drop comment "NOVA_EMERGENCY_KILLSWITCH"
  }
}
EOF
  chmod 0600 "$emergency"
  nft -c -f "$emergency"
  nft -f "$emergency"
  rm -f "$emergency"
}

clear_records() {
  rm -f "$seal" "$pending"
}

full_close() {
  local reason="${1:-unspecified}"
  emergency_kernel_close

  # Best effort full policy render.  The independent emergency table above is
  # already active, so even corrupted higher-level inputs cannot cause a leak.
  if NOVA_TRAFFIC_GATE=closed NOVA_GATE_TOKEN=""       "$ROOT/scripts/render-firewall.sh"; then
    :
  else
    warn "full CLOSED policy render failed; emergency forwarding kill-switch remains active"
  fi

  write_runtime_batch     NOVA_TRAFFIC_GATE closed     NOVA_GATE_TOKEN ""     NOVA_GATE_TXN_ID ""     NOVA_GATE_COMMITTED_AT ""     NOVA_GATE_LAST_CLOSE_REASON "$reason"
  clear_records
}

firewall_default_drop() {
  nft list chain inet nova input 2>/dev/null | grep -q 'policy drop' &&
    nft list chain inet nova forward 2>/dev/null | grep -q 'policy drop' &&
    nft list chain inet nova output 2>/dev/null | grep -q 'policy drop'
}

firewall_closed_live() {
  nft list chain inet nova forward 2>/dev/null | grep -Fq 'NOVA_TRAFFIC_GATE_CLOSED' &&
    nft list table inet nova_emergency 2>/dev/null | grep -Fq 'NOVA_EMERGENCY_KILLSWITCH' &&
    firewall_default_drop
}

firewall_open_live() {
  local token="$1"
  [[ "$token" =~ ^[a-f0-9]{32}$ ]] || return 1
  ! nft list table inet nova_emergency >/dev/null 2>&1 &&
    nft list chain inet nova forward 2>/dev/null | grep -Fq "NOVA_GATE_OPEN_$token" &&
    ! nft list chain inet nova forward 2>/dev/null | grep -Fq 'NOVA_TRAFFIC_GATE_CLOSED' &&
    firewall_default_drop
}

recent_management_handshake() {
  local now key ts f
  now="$(date +%s)"
  declare -A hs=()
  while read -r key ts; do
    [[ -n "$key" ]] && hs["$key"]="$ts"
  done < <(awg show "$NOVA_VPN_IF" latest-handshakes 2>/dev/null || true)

  shopt -s nullglob
  for f in "$NOVA_ETC"/peers.d/*.env; do
    load_peer_registry "$f"
    if [[ "$PEER_MANAGEMENT" == "1" ]]; then
      ts="${hs[$PEER_PUBLIC_KEY]:-0}"
      if [[ "$ts" =~ ^[0-9]+$ ]] && (( ts > 0 && now - ts <= 300 )); then
        return 0
      fi
    fi
  done
  return 1
}

peer_registry_consistent() {
  local f management_count=0
  declare -A ips=() keys=() names=()
  shopt -s nullglob
  local files=("$NOVA_ETC"/peers.d/*.env)
  (("${#files[@]}" > 0)) || return 1

  for f in "${files[@]}"; do
    load_peer_registry "$f"
    [[ -z "${ips[$PEER_IP]:-}" ]] || return 1
    [[ -z "${keys[$PEER_PUBLIC_KEY]:-}" ]] || return 1
    [[ -z "${names[$PEER_NAME]:-}" ]] || return 1
    ips["$PEER_IP"]=1
    keys["$PEER_PUBLIC_KEY"]=1
    names["$PEER_NAME"]=1
    [[ "$PEER_MANAGEMENT" == "1" ]] && management_count=$((management_count + 1))
  done
  (( management_count >= 1 ))
}

systemd_units_valid() {
  require_cmd systemd-analyze
  local -a units=()
  mapfile -t units < <(find /etc/systemd/system -maxdepth 1 -type f     \( -name 'nova-*.service' -o -name 'nova-*.timer' \) -print | sort)
  (("${#units[@]}" > 0)) || return 1
  systemd-analyze verify "${units[@]}" >/dev/null 2>&1
}

dns_configs_valid() {
  require_cmd unbound-checkconf
  unbound-checkconf /etc/unbound/unbound.conf >/dev/null

  local agh=/usr/local/lib/nova-adguard/AdGuardHome
  [[ -x "$agh" ]] || return 1
  "$agh" --check-config -c "$NOVA_ETC/adguard/private.yaml"     -w "$NOVA_STATE/dns/private" >/dev/null 2>&1 &&
  "$agh" --check-config -c "$NOVA_ETC/adguard/strict.yaml"     -w "$NOVA_STATE/dns/strict" >/dev/null 2>&1
}

awg_config_valid() {
  require_cmd awg-quick
  local conf="$NOVA_ETC/${NOVA_VPN_IF}.conf"
  [[ -s "$conf" && ! -L "$conf" ]] || return 1
  awg-quick strip "$conf" >/dev/null
}

install_tree_safe() {
  [[ -d "$NOVA_INSTALL_ROOT" ]] || return 1
  local bad
  bad="$(find "$NOVA_INSTALL_ROOT" -xdev     \( ! -user root -o -perm /022 \) -print -quit 2>/dev/null || true)"
  [[ -z "$bad" ]]
}

storage_ready() {
  local free_kb free_inodes
  free_kb="$(df -Pk "$NOVA_STATE" | awk 'NR==2{print $4}')"
  free_inodes="$(df -Pi "$NOVA_STATE" | awk 'NR==2{print $4}')"
  [[ "$free_kb" =~ ^[0-9]+$ && "$free_inodes" =~ ^[0-9]+$ ]] || return 1
  (( free_kb >= NOVA_GATE_MIN_FREE_MIB * 1024 )) &&
    (( free_inodes >= NOVA_GATE_MIN_FREE_INODES ))
}

package_manager_idle() {
  ! systemctl is-active --quiet apt-daily.service 2>/dev/null &&
    ! systemctl is-active --quiet apt-daily-upgrade.service 2>/dev/null
}

network_identity_valid() {
  valid_ifname "$NOVA_WAN_IF" &&
    valid_ifname "$NOVA_VPN_IF" &&
    ip link show "$NOVA_WAN_IF" >/dev/null 2>&1 &&
    ip link show "$NOVA_VPN_IF" >/dev/null 2>&1 &&
    ip -4 route show default dev "$NOVA_WAN_IF" | grep -q '^default'
}

stage_policies() {
  local token="$1" dir="$2" bootstrap="$3"
  NOVA_TRAFFIC_GATE=closed NOVA_GATE_TOKEN="" NOVA_BOOTSTRAP_SSH_CIDR="$bootstrap"     "$ROOT/scripts/render-firewall.sh" --stage "$dir/closed.nft"
  NOVA_TRAFFIC_GATE=open NOVA_GATE_TOKEN="$token" NOVA_BOOTSTRAP_SSH_CIDR=""     "$ROOT/scripts/render-firewall.sh" --stage "$dir/open.nft"
}

deep_preopen_verify() {
  local token="$1" mode="$2" txn_dir="$3" bootstrap="$4"

  [[ ! -e /var/run/reboot-required ]] || die "reboot pending"
  [[ "$mode" == "interactive" || -z "$bootstrap" ]] ||
    die "automatic reopen is forbidden while public bootstrap SSH exists"

  "$ROOT/scripts/live-acceptance.sh" preflight
  "$ROOT/src/privacyctl" health
  "$ROOT/scripts/verify-leaks.sh"
  sshd -t
  peer_registry_consistent || die "peer registry is inconsistent or lacks a management peer"
  systemd_units_valid || die "systemd unit verification failed"
  dns_configs_valid || die "DNS configuration validation failed"
  awg_config_valid || die "AWG configuration validation failed"
  install_tree_safe || die "installation tree is not root-owned/read-only to non-root"
  storage_ready || die "insufficient free space/inodes for safe operation"
  package_manager_idle || die "package manager transaction is still active"
  network_identity_valid || die "WAN/VPN interface or default-route identity mismatch"

  if [[ "$mode" == "interactive" ]]; then
    recent_management_handshake || die "no management peer handshake in the last 5 minutes"
  fi

  stage_policies "$token" "$txn_dir" "$bootstrap"
}

schedule_deadman() {
  local token="$1"
  require_cmd systemd-run
  local unit="nova-gate-deadman-${token:0:12}"
  systemd-run --quiet --collect     --unit="$unit"     --on-active="${NOVA_GATE_DEADMAN_SECONDS}s"     --timer-property=AccuracySec=1s     "$ROOT/scripts/atomic-safety-gate.sh" deadman "$token" >/dev/null
  printf '%s\n' "$unit"
}

cancel_deadman() {
  local unit="$1"
  systemctl stop "$unit.timer" "$unit.service" >/dev/null 2>&1 || true
  systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
}

open_gate() {
  local mode="${1:-interactive}"
  [[ "$mode" == "interactive" || "$mode" == "automatic" ]] ||
    die "open mode must be interactive or automatic"

  local old_bootstrap="${NOVA_BOOTSTRAP_SSH_CIDR:-}"
  local token txn_dir deadline deadman committed=0
  token="$(openssl rand -hex 16)"
  [[ "$token" =~ ^[a-f0-9]{32}$ ]] || die "failed to generate gate token"
  txn_dir="$(mktemp -d "$NOVA_RUN/gate-txn.XXXXXX")"
  chmod 0700 "$txn_dir"
  trap 'rm -rf "$txn_dir"' EXIT

  # Begin from a known closed kernel state before validating the OPEN candidate.
  full_close "pre-open"
  load_runtime
  deep_preopen_verify "$token" "$mode" "$txn_dir" "$old_bootstrap"

  deadline=$(( $(date +%s) + NOVA_GATE_DEADMAN_SECONDS ))
  atomic_record "$pending"     TOKEN "$token"     BOOT_ID "$(boot_id)"     PID "$$"     DEADLINE "$deadline"
  deadman="$(schedule_deadman "$token")"

  rollback() {
    local rc=$?
    if [[ "$committed" -ne 1 ]]; then
      warn "atomic gate transaction failed; forcing emergency CLOSED state"
      emergency_kernel_close || true
      NOVA_TRAFFIC_GATE=closed NOVA_GATE_TOKEN="" NOVA_BOOTSTRAP_SSH_CIDR="$old_bootstrap"         "$ROOT/scripts/render-firewall.sh" >/dev/null 2>&1 || true
      write_runtime_batch         NOVA_TRAFFIC_GATE closed         NOVA_GATE_TOKEN ""         NOVA_GATE_TXN_ID ""         NOVA_GATE_COMMITTED_AT ""         NOVA_BOOTSTRAP_SSH_CIDR "$old_bootstrap"         NOVA_GATE_LAST_CLOSE_REASON "transaction-rollback" || true
      clear_records
      cancel_deadman "$deadman"
    fi
    return "$rc"
  }
  trap rollback ERR HUP INT TERM EXIT

  # Kernel transition is one nftables transaction: emergency table removal and
  # OPEN policy installation are committed together or not at all.
  nft -f "$txn_dir/open.nft"
  firewall_open_live "$token" || die "OPEN firewall transaction did not match token/invariants"

  write_runtime_batch     NOVA_TRAFFIC_GATE open     NOVA_GATE_TOKEN "$token"     NOVA_GATE_TXN_ID "$token"     NOVA_GATE_COMMITTED_AT ""     NOVA_BOOTSTRAP_SSH_CIDR ""

  load_runtime
  NOVA_GATE_TRANSACTION=1 "$ROOT/scripts/live-acceptance.sh" server
  "$ROOT/scripts/verify-leaks.sh"

  local committed_at
  committed_at="$(date +%s)"
  atomic_record "$seal"     TOKEN "$token"     BOOT_ID "$(boot_id)"     COMMITTED_AT "$committed_at"
  write_runtime_batch NOVA_GATE_COMMITTED_AT "$committed_at"

  rm -f "$pending"
  cancel_deadman "$deadman"
  committed=1
  trap - ERR HUP INT TERM EXIT
  rm -rf "$txn_dir"
  log "ATOMIC SAFETY GATE COMMITTED OPEN token=$token"
}

pending_valid() {
  local token="$1" ptoken pboot pid deadline now
  ptoken="$(record_field "$pending" TOKEN 2>/dev/null || true)"
  pboot="$(record_field "$pending" BOOT_ID 2>/dev/null || true)"
  pid="$(record_field "$pending" PID 2>/dev/null || true)"
  deadline="$(record_field "$pending" DEADLINE 2>/dev/null || true)"
  now="$(date +%s)"
  [[ "$ptoken" == "$token" && "$pboot" == "$(boot_id)" ]] || return 1
  [[ "$pid" =~ ^[0-9]+$ && "$deadline" =~ ^[0-9]+$ ]] || return 1
  (( deadline >= now )) || return 1
  kill -0 "$pid" 2>/dev/null
}

seal_valid() {
  local token="$1" stoken sboot
  stoken="$(record_field "$seal" TOKEN 2>/dev/null || true)"
  sboot="$(record_field "$seal" BOOT_ID 2>/dev/null || true)"
  [[ "$stoken" == "$token" && "$sboot" == "$(boot_id)" ]]
}

watchdog() {
  local live_token runtime_token
  if nft list chain inet nova forward 2>/dev/null | grep -Fq 'NOVA_TRAFFIC_GATE_CLOSED'; then
    nft list table inet nova_emergency 2>/dev/null | grep -Fq 'NOVA_EMERGENCY_KILLSWITCH' ||
      emergency_kernel_close
    if [[ "${NOVA_TRAFFIC_GATE:-closed}" != "closed" ]]; then
      write_runtime_batch NOVA_TRAFFIC_GATE closed NOVA_GATE_TOKEN "" NOVA_GATE_TXN_ID "" NOVA_GATE_COMMITTED_AT ""
      clear_records
    fi
    exit 0
  fi

  live_token="$(
    nft list chain inet nova forward 2>/dev/null |
      grep -oE 'NOVA_GATE_OPEN_[a-f0-9]{32}' |
      head -n1 |
      sed 's/^NOVA_GATE_OPEN_//' || true
  )"
  runtime_token="${NOVA_GATE_TOKEN:-}"

  if [[ "${NOVA_TRAFFIC_GATE:-closed}" == "open" ]] &&
     [[ "$live_token" =~ ^[a-f0-9]{32}$ ]] &&
     [[ "$live_token" == "$runtime_token" ]] &&
     firewall_open_live "$live_token" &&
     { seal_valid "$live_token" || pending_valid "$live_token"; }; then
    exit 0
  fi

  warn "watchdog detected ambiguous/unsafe gate state; forcing emergency CLOSED"
  emergency_kernel_close
  NOVA_TRAFFIC_GATE=closed NOVA_GATE_TOKEN="" "$ROOT/scripts/render-firewall.sh" >/dev/null 2>&1 || true
  write_runtime_batch     NOVA_TRAFFIC_GATE closed     NOVA_GATE_TOKEN ""     NOVA_GATE_TXN_ID ""     NOVA_GATE_COMMITTED_AT ""     NOVA_GATE_LAST_CLOSE_REASON watchdog
  clear_records
}

deadman() {
  local token="${1:-}"
  [[ "$token" =~ ^[a-f0-9]{32}$ ]] || exit 0
  load_runtime
  if [[ "${NOVA_TRAFFIC_GATE:-closed}" == "open" ]] &&
     [[ "${NOVA_GATE_TOKEN:-}" == "$token" ]] &&
     seal_valid "$token" &&
     firewall_open_live "$token"; then
    exit 0
  fi
  warn "dead-man rollback fired for uncommitted gate transaction"
  emergency_kernel_close
  NOVA_TRAFFIC_GATE=closed NOVA_GATE_TOKEN="" "$ROOT/scripts/render-firewall.sh" >/dev/null 2>&1 || true
  write_runtime_batch     NOVA_TRAFFIC_GATE closed     NOVA_GATE_TOKEN ""     NOVA_GATE_TXN_ID ""     NOVA_GATE_COMMITTED_AT ""     NOVA_GATE_LAST_CLOSE_REASON deadman
  clear_records
}

status() {
  printf 'runtime_gate=%s\n' "${NOVA_TRAFFIC_GATE:-closed}"
  printf 'runtime_token=%s\n' "${NOVA_GATE_TOKEN:-}"
  if firewall_closed_live; then
    printf 'kernel_gate=closed\n'
  elif [[ "${NOVA_GATE_TOKEN:-}" =~ ^[a-f0-9]{32}$ ]] &&
       firewall_open_live "$NOVA_GATE_TOKEN"; then
    printf 'kernel_gate=open\n'
  else
    printf 'kernel_gate=ambiguous\n'
    return 1
  fi
  if [[ "${NOVA_TRAFFIC_GATE:-closed}" == "open" ]]; then
    seal_valid "${NOVA_GATE_TOKEN:-}" || return 1
    printf 'acceptance_seal=valid\n'
  else
    printf 'acceptance_seal=not-required\n'
  fi
}

case "$cmd" in
  open) open_gate "${2:-interactive}" ;;
  close) full_close "${2:-operator}" ;;
  boot-close) full_close boot ;;
  watchdog) watchdog ;;
  deadman) deadman "${2:-}" ;;
  status) status ;;
  verify)
    token="${NOVA_GATE_TOKEN:-$(openssl rand -hex 16)}"
    txn="$(mktemp -d "$NOVA_RUN/gate-verify.XXXXXX")"
    trap 'rm -rf "$txn"' EXIT
    deep_preopen_verify "$token" "${2:-interactive}" "$txn" "${NOVA_BOOTSTRAP_SSH_CIDR:-}"
    printf 'PASS atomic safety gate pre-open verification\n'
    ;;
  *) die "usage: atomic-safety-gate.sh open [interactive|automatic]|close [reason]|boot-close|watchdog|deadman TOKEN|status|verify [interactive|automatic]" ;;
esac
