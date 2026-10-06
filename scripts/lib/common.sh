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
  [[ -r "$runtime" ]] || return 0
  require_cmd python3

  local parsed key value
  parsed="$(mktemp)"
  chmod 0600 "$parsed"
  if ! python3 - "$runtime" >"$parsed" <<'PY'
import os
import pathlib
import shlex
import stat
import sys

p=pathlib.Path(sys.argv[1])
st=os.lstat(p)
if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
    raise SystemExit(f"unsafe runtime file type: {p}")
if st.st_uid != 0:
    raise SystemExit(f"runtime file must be root-owned: {p}")
if st.st_mode & 0o077:
    raise SystemExit(f"runtime file must be private (0600): {p}")

allowed={
    "NOVA_WAN_IF","NOVA_PUBLIC_ENDPOINT","NOVA_BOOTSTRAP_SSH_CIDR",
    "NOVA_REPOSITORY","NOVA_REPOSITORY_URL","NOVA_OS_BASELINE",
    "NOVA_PLATFORM","NOVA_KERNEL_TRACK","NOVA_TRAFFIC_GATE",
    "NOVA_GATE_TOKEN","NOVA_GATE_TXN_ID","NOVA_GATE_COMMITTED_AT",
    "NOVA_GATE_LAST_CLOSE_REASON","NOVA_AWG_MODE","NOVA_AWG_BACKEND",
    "NOVA_AWG_GO_INSTALLED_VERSION","NOVA_AWG_GO_SHA256",
    "NOVA_AWG_GO_MODULE_SUM","NOVA_AWG_GO_MOD_SUM",
    "NOVA_AWG_TOOLS_PACKAGE_VERSION","NOVA_SWAP_MIB",
    "NOVA_ADGUARD_VERSION","NOVA_GITHUB_CLI_VERSION",
}
seen=set()
for n,raw in enumerate(p.read_text(encoding="utf-8",errors="strict").splitlines(),1):
    if not raw or raw.startswith("#"):
        continue
    if "=" not in raw:
        raise SystemExit(f"invalid runtime record at line {n}")
    key,rhs=raw.split("=",1)
    if key not in allowed:
        raise SystemExit(f"unapproved runtime key at line {n}: {key}")
    if key in seen:
        raise SystemExit(f"duplicate runtime key at line {n}: {key}")
    seen.add(key)
    try:
        parts=shlex.split(rhs,posix=True)
    except ValueError as exc:
        raise SystemExit(f"invalid runtime value at line {n}") from exc
    if len(parts) != 1:
        raise SystemExit(f"runtime value must decode to exactly one scalar at line {n}")
    value=parts[0]
    sys.stdout.buffer.write(key.encode()+b"\0"+value.encode()+b"\0")
PY
  then
    rm -f "$parsed"
    die "runtime state validation failed"
  fi

  while IFS= read -r -d '' key && IFS= read -r -d '' value; do
    printf -v "$key" '%s' "$value"
  done <"$parsed"
  rm -f "$parsed"
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

valid_cidr() {
  python3 - "$1" <<'PY'
import ipaddress,sys
try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    raise SystemExit(1)
PY
}

valid_ifname() {
  [[ "$1" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]]
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
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] || continue
    [[ "$line" == *=* ]] || die "invalid peer registry line in $file"
    key="${line%%=*}"
    value="${line#*=}"
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

write_runtime_batch() {
  (( $# > 0 && $# % 2 == 0 )) ||
    die "write_runtime_batch requires KEY VALUE pairs"

  local file="${NOVA_ETC}/nova.env"
  mkdir -p "$NOVA_ETC"

  python3 - "$file" "$@" <<'PY'
import os
import pathlib
import re
import shlex
import stat
import sys
import tempfile

p = pathlib.Path(sys.argv[1])
args = sys.argv[2:]
pairs = list(zip(args[0::2], args[1::2]))
key_re = re.compile(r"^[A-Z][A-Z0-9_]*$")

for key, _ in pairs:
    if not key_re.fullmatch(key):
        raise SystemExit(f"invalid runtime key: {key!r}")

if p.exists() or p.is_symlink():
    st = os.lstat(p)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise SystemExit(f"unsafe runtime file type: {p}")
    if st.st_uid != 0:
        raise SystemExit(f"runtime file must be root-owned: {p}")
    lines = p.read_text(encoding="utf-8", errors="strict").splitlines()
    uid, gid = st.st_uid, st.st_gid
else:
    lines = []
    uid, gid = 0, 0

updates = dict(pairs)
out = []
seen = set()
for line in lines:
    if "=" in line:
        key = line.split("=", 1)[0]
        if key in updates:
            if key not in seen:
                out.append(f"{key}={shlex.quote(updates[key])}")
                seen.add(key)
            continue
    out.append(line)

for key, value in pairs:
    if key not in seen:
        out.append(f"{key}={shlex.quote(value)}")
        seen.add(key)

p.parent.mkdir(parents=True, exist_ok=True)
fd, tmp_name = tempfile.mkstemp(prefix=".nova.env.", dir=p.parent)
try:
    os.fchmod(fd, 0o600)
    os.fchown(fd, uid, gid)
    data = ("\n".join(out) + "\n").encode()
    with os.fdopen(fd, "wb", closefd=True) as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp_name, p)
    dfd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
finally:
    try:
        os.unlink(tmp_name)
    except FileNotFoundError:
        pass
PY
}

write_runtime_kv() {
  write_runtime_batch "$1" "$2"
}

systemd_reload() {
  systemctl daemon-reload
}
