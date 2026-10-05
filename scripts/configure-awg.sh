#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime
require_cmd awg
require_cmd awg-quick

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

cat >"$params" <<EOF
AWG_MODE=$mode
AWG_JC=4
AWG_JMIN=10
AWG_JMAX=50
AWG_S1=32
AWG_S2=32
AWG_S3=32
AWG_S4=32
AWG_H1=1
AWG_H2=2
AWG_H3=3
AWG_H4=4
AWG_CONTENT_PADDING=10-50
AWG_RANDOM_TRAILERS=off
AWG_DISABLE_COOKIES=${NOVA_AWG_DISABLE_COOKIES:-off}
EOF

if [[ "$mode" == "max" ]]; then
  cat >>"$params" <<'EOF'
AWG_JC=6
AWG_JMAX=80
AWG_CONTENT_PADDING=10-100
AWG_REKEY_AFTER=100-120
AWG_REKEY_TIMEOUT=3-7
AWG_REJECT_AFTER=150-180
AWG_KEEPALIVE_TIMEOUT=5-15
AWG_MAX_HANDSHAKE_ATTEMPTS=15-20
AWG_RANDOM_TRAILERS=on
EOF
fi
chmod 0600 "$params"

# shellcheck disable=SC1090
source "$params"

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
python3 "$ROOT/scripts/render-template.py" \
  "$ROOT/config/systemd/nova-awg.service.in" \
  /etc/systemd/system/nova-awg.service
chmod 0644 /etc/systemd/system/nova-awg.service
systemctl daemon-reload

if systemctl is-active --quiet nova-awg.service; then
  systemctl restart nova-awg.service
else
  systemctl enable --now nova-awg.service
fi

write_runtime_kv NOVA_AWG_MODE "$mode"
log "AmneziaWG configured in $mode mode"
