#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

peer_path() {
  printf '%s/peers.d/%s.env\n' "$NOVA_ETC" "$1"
}

peer_secret_dir() {
  printf '%s/peer-secrets/%s\n' "$NOVA_ETC" "$1"
}

allocate_peer_ip() {
  local management="$1"
  python3 - "$NOVA_ETC" "$management" "$NOVA_VPN_NET" "$NOVA_MGMT_NET" <<'PY'
import ipaddress,pathlib,sys
etc=pathlib.Path(sys.argv[1])
management=sys.argv[2]=="1"
network=ipaddress.ip_network(sys.argv[4] if management else sys.argv[3], strict=False)
used=set()
for p in (etc/"peers.d").glob("*.env"):
    for line in p.read_text().splitlines():
        if line.startswith("IP="):
            used.add(line.split("=",1)[1].strip().strip("'").strip('"'))
for host in list(network.hosts())[9:250]:
    s=str(host)
    if s not in used:
        print(s)
        raise SystemExit(0)
raise SystemExit("no free peer addresses")
PY
}

load_awg_params() {
  # Runtime-generated and root-owned; intentionally not present in the source tree.
  # shellcheck disable=SC1091
  source "$NOVA_ETC/awg.params"
}

endpoint_with_port() {
  local host="$NOVA_PUBLIC_ENDPOINT"
  [[ -n "$host" ]] || die "NOVA_PUBLIC_ENDPOINT is empty"
  if [[ "$host" == *:* && "$host" != [*] ]]; then
    printf '[%s]:%s\n' "$host" "$NOVA_AWG_PORT"
  else
    printf '%s:%s\n' "$host" "$NOVA_AWG_PORT"
  fi
}

emit_awg_interface_obfuscation() {
  load_awg_params
  cat <<EOF
Jc = $AWG_JC
Jmin = $AWG_JMIN
Jmax = $AWG_JMAX
S1 = $AWG_S1
S2 = $AWG_S2
S3 = $AWG_S3
S4 = $AWG_S4
H1 = $AWG_H1
H2 = $AWG_H2
H3 = $AWG_H3
H4 = $AWG_H4
HeaderProtectionKey = $(cat "$NOVA_ETC/keys/header-protection.key")
ContentPaddingAddition = $AWG_CONTENT_PADDING
RandomTrailers = $AWG_RANDOM_TRAILERS
DisableCookies = $AWG_DISABLE_COOKIES
EOF
  if [[ "${AWG_MODE:-balanced}" == "max" ]]; then
    cat <<EOF
RekeyAfterTime = $AWG_REKEY_AFTER
RekeyTimeout = $AWG_REKEY_TIMEOUT
RejectAfterTime = $AWG_REJECT_AFTER
KeepaliveTimeout = $AWG_KEEPALIVE_TIMEOUT
MaxHandshakeAttempts = $AWG_MAX_HANDSHAKE_ATTEMPTS
EOF
  fi
}

write_client_config() {
  local name="$1" ip="$2" client_private="$3" psk="$4"
  local export_dir="/root/nova-peers"
  local conf="$export_dir/$name.conf"
  local dns_ip="${NOVA_VPN_ADDR%/*}"
  local server_pub endpoint

  server_pub="$(cat "$NOVA_ETC/keys/server.pub")"
  endpoint="$(endpoint_with_port)"

  install -d -m 0700 "$export_dir"
  {
    cat <<EOF
[Interface]
Address = $ip/32
DNS = $dns_ip
MTU = ${NOVA_CLIENT_MTU:-1280}
PrivateKey = $client_private
EOF
    emit_awg_interface_obfuscation
    cat <<EOF

[Peer]
PublicKey = $server_pub
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $endpoint
PersistentKeepalive = 25
EOF
  } >"$conf"
  chmod 0600 "$conf"

  if command -v qrencode >/dev/null 2>&1; then
    qrencode -o "$export_dir/$name.qr.png" -t PNG <"$conf"
    chmod 0600 "$export_dir/$name.qr.png"
  fi

  printf '%s\n' "$conf"
}
