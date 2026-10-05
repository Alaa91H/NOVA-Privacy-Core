#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
acquire_nova_lock
require_cmd awg
require_cmd awg-quick
require_cmd python3

mode="${1:-${NOVA_AWG_MODE:-balanced}}"
case "$mode" in balanced|max) ;; *) die "AWG mode must be balanced or max" ;; esac

mkdir -p "$NOVA_ETC/keys" "$NOVA_ETC/systemd"
chmod 0700 "$NOVA_ETC/keys"

server_key="$NOVA_ETC/keys/server.key"
server_pub="$NOVA_ETC/keys/server.pub"
header_key="$NOVA_ETC/keys/header-protection.key"
params="$NOVA_ETC/awg.params"
conf="$NOVA_ETC/${NOVA_VPN_IF}.conf"

if [[ ! -s "$server_key" ]]; then
  awg genkey >"$server_key"
  chmod 0600 "$server_key"
fi
awg pubkey <"$server_key" >"$server_pub"
chmod 0644 "$server_pub"

if [[ ! -s "$header_key" ]]; then
  awg genkey >"$header_key"
  chmod 0600 "$header_key"
fi

have_peers=0
shopt -s nullglob
peer_files=("$NOVA_ETC"/peers.d/*.env)
[[ "${#peer_files[@]}" -gt 0 ]] && have_peers=1

# Generate a per-server obfuscation identity once.  Fixed magic values make
# unrelated NOVA installations easier to fingerprint; changing them after
# provisioning peers would break interoperability.  The parameter file is
# therefore secret state and is included in encrypted backups.
if [[ ! -s "$params" ]]; then
  python3 - "$params" "$mode" "${NOVA_AWG_DISABLE_COOKIES:-off}"     "${NOVA_AWG_EXPERIMENTAL_RANDOM_TRAILERS:-off}" <<'PY'
import pathlib
import secrets
import sys

out = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
disable_cookies = sys.argv[3]
experimental_trailers = sys.argv[4]

def randint(lo: int, hi: int) -> int:
    return lo + secrets.randbelow(hi - lo + 1)

# Current upstream guidance recommends Jc 4..12, Jmin 8 and Jmax 80.
jc = randint(4, 12)
jmin = 8
jmax = 80

# Keep signature paddings in the conservative recommended 15..150 range.
# S1+56 must not equal S2.
s1 = randint(15, 150)
while True:
    s2 = randint(15, 150)
    if s1 + 56 != s2:
        break
s3 = randint(15, 150)
s4 = randint(15, 150)

# Header magic values must be unique.  Avoid tiny/obvious constants and draw
# from the documented positive 31-bit range.
hs = set()
while len(hs) < 4:
    hs.add(randint(5, 2_147_483_647))
h1, h2, h3, h4 = tuple(hs)

lines = [
    "AWG_PARAMS_VERSION=2",
    f"AWG_MODE={mode}",
    f"AWG_JC={jc}",
    f"AWG_JMIN={jmin}",
    f"AWG_JMAX={jmax}",
    f"AWG_S1={s1}",
    f"AWG_S2={s2}",
    f"AWG_S3={s3}",
    f"AWG_S4={s4}",
    f"AWG_H1={h1}",
    f"AWG_H2={h2}",
    f"AWG_H3={h3}",
    f"AWG_H4={h4}",
    "AWG_CONTENT_PADDING=10-50" if mode == "balanced" else "AWG_CONTENT_PADDING=10-100",
    # RandomTrailers has had active 3.1 interoperability/packet-classification
    # defects.  Keep it off unless an operator explicitly accepts that gate.
    f"AWG_RANDOM_TRAILERS={'on' if experimental_trailers == 'on' else 'off'}",
    f"AWG_DISABLE_COOKIES={disable_cookies}",
]
if mode == "max":
    lines += [
        "AWG_REKEY_AFTER=100-120",
        "AWG_REKEY_TIMEOUT=3-7",
        "AWG_REJECT_AFTER=150-180",
        "AWG_KEEPALIVE_TIMEOUT=5-15",
        "AWG_MAX_HANDSHAKE_ATTEMPTS=15-20",
    ]

out.write_text("\n".join(lines) + "\n")
out.chmod(0o600)
PY
else
  # shellcheck disable=SC1090
  source "$params"
  existing_mode="${AWG_MODE:-balanced}"
  if [[ "$existing_mode" != "$mode" ]]; then
    [[ "$have_peers" -eq 0 ]] || die "AWG mode change requires peer reprovisioning; revoke peers first"
    # Preserve the unique S/H identity, update only mode-dependent timing.
    python3 - "$params" "$mode" "${NOVA_AWG_EXPERIMENTAL_RANDOM_TRAILERS:-off}" <<'PY'
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
experimental = sys.argv[3]
kv = {}
order = []
for raw in p.read_text().splitlines():
    if not raw or "=" not in raw:
        continue
    k, v = raw.split("=", 1)
    if k not in kv:
        order.append(k)
    kv[k] = v

kv["AWG_MODE"] = mode
kv["AWG_CONTENT_PADDING"] = "10-50" if mode == "balanced" else "10-100"
kv["AWG_RANDOM_TRAILERS"] = "on" if experimental == "on" else "off"
for k in ("AWG_REKEY_AFTER", "AWG_REKEY_TIMEOUT", "AWG_REJECT_AFTER",
          "AWG_KEEPALIVE_TIMEOUT", "AWG_MAX_HANDSHAKE_ATTEMPTS"):
    kv.pop(k, None)
    if k in order:
        order.remove(k)
if mode == "max":
    extras = {
        "AWG_REKEY_AFTER": "100-120",
        "AWG_REKEY_TIMEOUT": "3-7",
        "AWG_REJECT_AFTER": "150-180",
        "AWG_KEEPALIVE_TIMEOUT": "5-15",
        "AWG_MAX_HANDSHAKE_ATTEMPTS": "15-20",
    }
    for k, v in extras.items():
        kv[k] = v
        if k not in order:
            order.append(k)

p.write_text("\n".join(f"{k}={kv[k]}" for k in order if k in kv) + "\n")
p.chmod(0o600)
PY
  fi
fi

chmod 0600 "$params"
# shellcheck disable=SC1090
source "$params"

# Reject legacy/static parameter files rather than silently advertising a
# hardened profile with weak/common magic constants.
[[ "${AWG_PARAMS_VERSION:-0}" -ge 2 ]] || die "legacy AWG parameter set detected; reprovision peers before regenerating"
[[ "$AWG_H1" != "$AWG_H2" && "$AWG_H1" != "$AWG_H3" && "$AWG_H1" != "$AWG_H4" &&
   "$AWG_H2" != "$AWG_H3" && "$AWG_H2" != "$AWG_H4" && "$AWG_H3" != "$AWG_H4" ]] ||
  die "AWG H1-H4 must be unique"
(( AWG_JC >= 4 && AWG_JC <= 12 )) || die "AWG_JC outside recommended range"
(( AWG_JMIN < AWG_JMAX )) || die "AWG Jmin/Jmax invalid"
(( AWG_S1 + 56 != AWG_S2 )) || die "AWG S1/S2 collision constraint violated"

peers_tmp="$(mktemp)"
trap 'rm -f "$peers_tmp"' EXIT
if [[ -f "$conf" ]]; then
  awk '/^# BEGIN NOVA PEERS$/{flag=1} flag{print}' "$conf" >"$peers_tmp"
fi
if [[ ! -s "$peers_tmp" ]]; then
  printf '# BEGIN NOVA PEERS\n' >"$peers_tmp"
fi

{
  cat <<EOF
[Interface]
Address = ${NOVA_VPN_ADDR}, ${NOVA_MGMT_ADDR}
ListenPort = ${NOVA_AWG_PORT}
PrivateKey = $(cat "$server_key")
Jc = ${AWG_JC}
Jmin = ${AWG_JMIN}
Jmax = ${AWG_JMAX}
S1 = ${AWG_S1}
S2 = ${AWG_S2}
S3 = ${AWG_S3}
S4 = ${AWG_S4}
H1 = ${AWG_H1}
H2 = ${AWG_H2}
H3 = ${AWG_H3}
H4 = ${AWG_H4}
HeaderProtectionKey = $(cat "$header_key")
ContentPaddingAddition = ${AWG_CONTENT_PADDING}
RandomTrailers = ${AWG_RANDOM_TRAILERS}
DisableCookies = ${AWG_DISABLE_COOKIES}
EOF
  if [[ "$mode" == "max" ]]; then
    cat <<EOF
RekeyAfterTime = ${AWG_REKEY_AFTER}
RekeyTimeout = ${AWG_REKEY_TIMEOUT}
RejectAfterTime = ${AWG_REJECT_AFTER}
KeepaliveTimeout = ${AWG_KEEPALIVE_TIMEOUT}
MaxHandshakeAttempts = ${AWG_MAX_HANDSHAKE_ATTEMPTS}
EOF
  fi
  printf '\n'
  cat "$peers_tmp"
} >"$conf"
chmod 0600 "$conf"

awg-quick strip "$conf" >/dev/null

export AWG_CONFIG="$conf"
python3 "$ROOT/scripts/render-template.py"   "$ROOT/config/systemd/nova-awg.service.in"   /etc/systemd/system/nova-awg.service
chmod 0644 /etc/systemd/system/nova-awg.service
systemctl daemon-reload

if systemctl is-active --quiet nova-awg.service &&
   ip link show "$NOVA_VPN_IF" >/dev/null 2>&1; then
  # Never bounce the management tunnel during an in-place update.  The
  # interface addresses are owned by awg-quick and must already match the
  # persisted design; changing them is a console/OOB maintenance operation.
  for required_addr in "$NOVA_VPN_ADDR" "$NOVA_MGMT_ADDR"; do
    ip -o addr show dev "$NOVA_VPN_IF" |
      awk '{print $4}' |
      grep -Fxq "$required_addr" ||
      die "active AWG address differs from requested design ($required_addr); use Oracle Console/OOB for network-address changes"
  done

  live_candidate="$(mktemp "$NOVA_ETC/.awg-live.XXXXXX")"
  trap 'rm -f "$peers_tmp" "${live_candidate:-}"' EXIT
  awg-quick strip "$conf" >"$live_candidate"
  chmod 0600 "$live_candidate"
  awg syncconf "$NOVA_VPN_IF" "$live_candidate" ||
    die "live AWG sync failed; active interface was not intentionally restarted"
  rm -f "$live_candidate"
  log "AmneziaWG updated in place without dropping the active tunnel"
else
  systemctl enable --now nova-awg.service
fi

write_runtime_kv NOVA_AWG_MODE "$mode"
log "AmneziaWG configured in $mode mode with per-server randomized obfuscation identity"
