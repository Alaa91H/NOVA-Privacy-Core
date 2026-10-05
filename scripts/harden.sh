#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

install -D -m 0644 "$ROOT/config/sysctl/99-nova-privacy.conf" /etc/sysctl.d/99-nova-privacy.conf
sysctl --system >/dev/null

install -d -m 0755 /etc/systemd/journald.conf.d
install -m 0644 "$ROOT/config/systemd/90-nova-journald.conf" /etc/systemd/journald.conf.d/90-nova-privacy.conf
systemctl restart systemd-journald

have_key=0
if [[ -s /root/.ssh/authorized_keys ]]; then
  have_key=1
else
  while IFS= read -r f; do
    [[ -s "$f" ]] && have_key=1 && break
  done < <(find /home -maxdepth 3 -type f -path '*/.ssh/authorized_keys' 2>/dev/null || true)
fi

if [[ "$have_key" -eq 1 ]]; then
  install -d -m 0755 /etc/ssh/sshd_config.d
  install -m 0644 "$ROOT/config/ssh/90-nova-privacy.conf" /etc/ssh/sshd_config.d/90-nova-privacy.conf
  if sshd -t; then
    systemctl reload ssh || systemctl reload sshd
    log "SSH password authentication disabled after key preflight"
  else
    rm -f /etc/ssh/sshd_config.d/90-nova-privacy.conf
    die "sshd validation failed; hardening file removed"
  fi
else
  warn "no authorized_keys file detected; SSH password hardening not applied"
  warn "install an SSH key, then rerun scripts/harden.sh"
fi

# Core dumps are not useful on a privacy gateway unless explicitly debugging.
cat >/etc/security/limits.d/99-nova-core.conf <<'EOF'
* hard core 0
root hard core 0
EOF

install -d -m 0755 /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/90-nova-privacy.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

systemctl daemon-reload
log "OS hardening applied"
