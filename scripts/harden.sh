#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

[[ "${NOVA_IPV6_MODE:-block}" == "block" ]] ||
  die "NOVA v1 implements only fail-closed IPv6 mode: NOVA_IPV6_MODE=block"

install -D -m 0644 "$ROOT/config/sysctl/99-nova-privacy.conf" /etc/sysctl.d/99-nova-privacy.conf
sysctl --system >/dev/null

if systemctl list-unit-files apparmor.service >/dev/null 2>&1; then
  systemctl enable --now apparmor.service || warn "AppArmor could not be enabled; inspect kernel LSM configuration"
fi

# Security-only unattended upgrades.  Third-party VPN/DNS packages are not
# blindly upgraded because transport changes require interoperability tests.
# shellcheck disable=SC1091
source /etc/os-release
codename="${VERSION_CODENAME:-}"
[[ -n "$codename" ]] || die "Debian VERSION_CODENAME is unavailable"
cat >/etc/apt/apt.conf.d/52nova-security-upgrades <<EOF
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${codename}-security,label=Debian-Security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
EOF
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null ||
  warn "APT security-update timers could not be enabled"

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
    if sshd -T 2>/dev/null | awk '$1=="kexalgorithms"{print $2}' |
        tr ',' '\n' | grep -qx 'mlkem768x25519-sha256'; then
      log "OpenSSH hybrid post-quantum KEX available: mlkem768x25519-sha256"
    else
      warn "OpenSSH does not advertise mlkem768x25519-sha256; update OpenSSH before labeling SSH PQ-hybrid"
    fi
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
