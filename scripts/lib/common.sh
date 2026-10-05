#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

log() { printf '[nova] %s\n' "$*" >&2; }
warn() { printf '[nova][warn] %s\n' "$*" >&2; }
die() { printf '[nova][fatal] %s\n' "$*" >&2; exit 1; }

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root"
}

repo_root() {
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd
}

load_defaults() {
  local root
  root="$(repo_root)"
  # shellcheck disable=SC1091
  source "$root/config/defaults.env"
}

load_runtime() {
  load_defaults
  local runtime="${NOVA_ETC}/nova.env"
  if [[ -r "$runtime" ]]; then
    # shellcheck disable=SC1090
    source "$runtime"
  fi
}


acquire_nova_lock() {
  [[ "${NOVA_LOCK_HELD:-0}" == "1" ]] && return 0
  require_cmd flock
  mkdir -p "$NOVA_RUN"
  chmod 0755 "$NOVA_RUN"
  exec {NOVA_LOCK_FD}>"$NOVA_RUN/control.lock"
  flock -w "${NOVA_LOCK_TIMEOUT:-30}" "$NOVA_LOCK_FD" ||
    die "timed out waiting for NOVA control lock"
  export NOVA_LOCK_HELD=1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

detect_wan_if() {
  ip -4 route show default 2>/dev/null | awk 'NR==1 {print $5}'
}

detect_oci_public_ip() {
  local body
  body="$(curl -fsS --connect-timeout 2 --max-time 4 \
    -H 'Authorization: Bearer Oracle' \
    http://169.254.169.254/opc/v2/vnics/ 2>/dev/null || true)"
  [[ -n "$body" ]] || return 1
  python3 - "$body" <<'PY'
import json,sys
try:
    data=json.loads(sys.argv[1])
    for nic in data:
        ip=nic.get("publicIp")
        if ip:
            print(ip)
            raise SystemExit(0)
except Exception:
    pass
raise SystemExit(1)
PY
}

is_ubuntu_2604() {
  [[ -r /etc/os-release ]] || return 1
  (
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "26.04" ]]
  )
}

is_oci_host() {
  local vendor=""
  vendor="$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)"
  if grep -Eqi 'Oracle|OracleCloud' <<<"$vendor"; then
    return 0
  fi
  curl -fsS --connect-timeout 1 --max-time 2     -H 'Authorization: Bearer Oracle'     http://169.254.169.254/opc/v2/instance/ >/dev/null 2>&1
}

set_traffic_gate() {
  local state="$1"
  [[ "$state" == "open" || "$state" == "closed" ]] ||
    die "traffic gate state must be open or closed"
  write_runtime_kv NOVA_TRAFFIC_GATE "$state"
}

capture_bootstrap_ssh_cidr() {
  local ip="${SSH_CONNECTION%% *}"
  [[ -n "$ip" ]] || return 1
  if [[ "$ip" == *:* ]]; then
    printf '%s/128\n' "$ip"
  else
    printf '%s/32\n' "$ip"
  fi
}

valid_peer_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]]
}

valid_profile() {
  case "$1" in
    COMPAT|PRIVATE|STRICT|LOCKDOWN) return 0 ;;
    *) return 1 ;;
  esac
}


valid_peer_ip_for_role() {
  local ip="$1" management="$2"
  python3 - "$ip" "$management" "$NOVA_VPN_NET" "$NOVA_MGMT_NET" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
if ip.version != 4:
    raise SystemExit(1)
management=sys.argv[2] == "1"
net=ipaddress.ip_network(sys.argv[4] if management else sys.argv[3], strict=False)
if ip not in net or ip == net.network_address or ip == net.broadcast_address:
    raise SystemExit(1)
PY
}

load_peer_registry() {
  local file="$1" key value perm owner expected
  [[ -f "$file" && ! -L "$file" ]] || die "invalid peer registry file: $file"

  owner="$(stat -c %u "$file")"
  perm="$(stat -c %a "$file")"
  [[ "$owner" == "0" ]] || die "peer registry must be root-owned: $file"
  (( (8#$perm & 077) == 0 )) || die "peer registry must not be group/world accessible: $file"

  unset PEER_NAME PEER_IP PEER_PROFILE PEER_MANAGEMENT PEER_PUBLIC_KEY PEER_PSK_FILE
  while IFS='=' read -r key value; do
    [[ -n "$key" ]] || continue
    [[ "$key" =~ ^[A-Z_]+$ ]] || die "invalid peer registry key syntax in $file"
    case "$key" in
      NAME) PEER_NAME="$value" ;;
      IP) PEER_IP="$value" ;;
      PROFILE) PEER_PROFILE="$value" ;;
      MANAGEMENT) PEER_MANAGEMENT="$value" ;;
      PUBLIC_KEY) PEER_PUBLIC_KEY="$value" ;;
      PSK_FILE) PEER_PSK_FILE="$value" ;;
      *) die "unknown peer registry key '$key' in $file" ;;
    esac
  done <"$file"

  [[ -n "${PEER_NAME:-}" && -n "${PEER_IP:-}" && -n "${PEER_PROFILE:-}" &&
     -n "${PEER_MANAGEMENT:-}" && -n "${PEER_PUBLIC_KEY:-}" &&
     -n "${PEER_PSK_FILE:-}" ]] ||
    die "incomplete peer registry: $file"

  valid_peer_name "$PEER_NAME" || die "invalid peer name in registry: $file"
  valid_profile "$PEER_PROFILE" || die "invalid peer profile in registry: $file"
  [[ "$PEER_MANAGEMENT" == "0" || "$PEER_MANAGEMENT" == "1" ]] ||
    die "invalid management flag in registry: $file"
  [[ "$PEER_PUBLIC_KEY" =~ ^[A-Za-z0-9+/]{43}=$ ]] ||
    die "invalid peer public key encoding in registry: $file"
  valid_peer_ip_for_role "$PEER_IP" "$PEER_MANAGEMENT" ||
    die "peer IP does not belong to its assigned NOVA network: $file"

  expected="$NOVA_ETC/peer-secrets/$PEER_NAME/psk"
  [[ "$PEER_PSK_FILE" == "$expected" ]] ||
    die "unexpected peer PSK path in registry: $file"
  [[ -f "$PEER_PSK_FILE" && ! -L "$PEER_PSK_FILE" ]] ||
    die "peer PSK file missing or unsafe: $PEER_PSK_FILE"

  [[ "$(basename "$file")" == "$PEER_NAME.env" ]] ||
    die "peer registry filename/name mismatch: $file"
}

write_runtime_kv() {
  local key="$1" value="$2" file="${NOVA_ETC}/nova.env"
  mkdir -p "$NOVA_ETC"
  touch "$file"
  chmod 0600 "$file"
  python3 - "$file" "$key" "$value" <<'PY'
import pathlib,sys,shlex
p=pathlib.Path(sys.argv[1]); key=sys.argv[2]; value=sys.argv[3]
lines=p.read_text().splitlines() if p.exists() else []
out=[]; done=False
for line in lines:
    if line.startswith(key+"="):
        out.append(f"{key}={shlex.quote(value)}"); done=True
    else:
        out.append(line)
if not done:
    out.append(f"{key}={shlex.quote(value)}")
p.write_text("\n".join(out)+"\n")
PY
}

systemd_reload() {
  systemctl daemon-reload
}
