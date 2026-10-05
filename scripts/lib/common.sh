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
