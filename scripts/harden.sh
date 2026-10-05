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

find_keyed_sudo_admin() {
  local user uid home shell groups
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    (( uid >= 1000 && uid < 65534 )) || continue
    [[ "$shell" != */nologin && "$shell" != */false ]] || continue
    [[ -s "$home/.ssh/authorized_keys" ]] || continue
    groups="$(id -nG "$user" 2>/dev/null || true)"
    if tr ' ' '\n' <<<"$groups" | grep -qx sudo; then
      printf '%s\n' "$user"
      return 0
    fi
  done < <(getent passwd)
  return 1
}

admin_user="$(find_keyed_sudo_admin || true)"
[[ -n "$admin_user" ]] ||
  die "refusing SSH hardening: create a non-root Debian user with authorized_keys and sudo-group access first"

install -d -m 0755 /etc/ssh/sshd_config.d
install -m 0644 "$ROOT/config/ssh/90-nova-privacy.conf" /etc/ssh/sshd_config.d/90-nova-privacy.conf
if sshd -t; then
  systemctl reload ssh || systemctl reload sshd
  log "SSH hardened: root/password login disabled; recovery admin=$admin_user"
else
  rm -f /etc/ssh/sshd_config.d/90-nova-privacy.conf
  die "sshd validation failed; hardening file removed"
fi

sshd -T 2>/dev/null | grep -qx 'permitrootlogin no' ||
  die "effective SSH policy still permits root login"
sshd -T 2>/dev/null | grep -qx 'passwordauthentication no' ||
  die "effective SSH policy still permits password authentication"

if sshd -T 2>/dev/null | awk '$1=="kexalgorithms"{print $2}' |
    tr ',' '\n' | grep -qx 'mlkem768x25519-sha256'; then
  log "OpenSSH hybrid post-quantum KEX verified: mlkem768x25519-sha256"
else
  die "OpenSSH does not advertise required hybrid PQ KEX mlkem768x25519-sha256"
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
