#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    p = ROOT / path
    assert p.is_file(), f"missing {path}"
    return p.read_text()

def test_firewall():
    text = read("config/nftables/nova.nft.in")
    for chain in ("input", "forward", "output"):
        pattern = rf"chain {chain} .*?policy drop;"
        assert re.search(pattern, text, re.S), f"{chain} is not default-drop"
    assert "@@LOCKDOWN_ELEMENTS@@" in text
    assert "tcp dport 853 drop" in text
    assert "udp dport 853 drop" in text
    assert "masquerade" in text
    assert 'tcp dport 22 accept' in text
    assert '@@BOOTSTRAP_SSH_RULE@@' in text
    # A default-drop host firewall must not silently break the cloud DHCP lease.
    assert 'udp sport 68 udp dport 67 accept' in text
    assert 'udp sport 67 udp dport 68 accept' in text
    assert "set doh4" in text
    assert "ip saddr @strict4 ip daddr @doh4 drop" in text
    assert "@@TRAFFIC_GATE_DROP@@" in text

def test_lockdown_precedes_conntrack_accept():
    text = read("config/nftables/nova.nft.in")
    m = re.search(r"chain forward \{(.*?)\n  \}", text, re.S)
    assert m, "forward chain not found"
    forward = m.group(1)
    assert forward.index("@lockdown4 drop") < forward.index("ct state established,related accept"), (
        "LOCKDOWN must override already-established forwarding flows"
    )


def test_deployment_gate_precedes_conntrack_accept():
    text = read("config/nftables/nova.nft.in")
    m = re.search(r"chain forward \{(.*?)\n  \}", text, re.S)
    assert m, "forward chain not found"
    forward = m.group(1)
    assert forward.index("@@TRAFFIC_GATE_DROP@@") < forward.index("ct state established,related accept")



def test_dns_bypass_blocks_precede_conntrack_accept():
    text = read("config/nftables/nova.nft.in")
    m = re.search(r"chain forward \{(.*?)\n  \}", text, re.S)
    assert m, "forward chain not found"
    forward = m.group(1)
    established = forward.index("ct state established,related accept")
    assert forward.index("ip saddr @strict4 ip daddr @doh4 drop") < established
    assert forward.index("tcp dport 853 drop") < established
    assert forward.index("udp dport 853 drop") < established

def test_early_firewall_boot_order():
    unit = read("config/systemd/nova-firewall.service")
    assert "DefaultDependencies=no" in unit
    assert "Before=network-pre.target" in unit
    assert "WantedBy=network-pre.target" in unit
    assert "After=local-fs.target" in unit

def test_dns_privacy():
    adg = read("config/adguard/profile.yaml.in")
    unbound = read("config/unbound/nova.conf.in")
    assert "querylog:\n  enabled: false" in adg
    assert "statistics:\n  enabled: false" in adg
    assert "0.0.0.0" not in "\n".join(
        line for line in adg.splitlines() if "bind_hosts" in line or line.strip().startswith("- ")
    )
    assert "qname-minimisation: yes" in unbound
    assert "harden-dnssec-stripped: yes" in unbound
    assert "hide-version: yes" in unbound
    assert "do-ip6: no" in unbound
    assert "schema_version: 34" in adg
    assert "anonymize_client_ip: true" in adg
    assert "edns_client_subnet:\n    enabled: false" in adg
    assert "insecure_enabled: false" in adg
    assert "tls:\n  enabled: false" in adg
    assert "ignored_enabled: false" in adg
    assert "NOVA Encrypted DNS Bypass" in adg
    assert "enabled: @@DOH_FILTER_ENABLED@@" in adg

def test_adguard_least_privilege_auth():
    bootstrap = read("scripts/bootstrap.sh")
    installer = read("scripts/install-dns.sh")
    template = read("config/adguard/profile.yaml.in")
    assert "apache2-utils" in bootstrap
    assert 'chown root:nova-dns "$NOVA_ETC"' in bootstrap
    assert 'chmod 0710 "$NOVA_ETC"' in bootstrap
    assert "users:\n  - name: nova-admin" in template
    assert 'password: "@@ADMIN_HASH@@"' in template
    assert "htpasswd -bnBC 12" in installer
    assert 'chmod 0600 "$admin_secret"' in installer
    assert 'chown root:nova-dns "$cfg"' in installer
    assert 'chmod 0640 "$cfg"' in installer


def test_release_authenticity():
    defaults = read("config/defaults.env")
    installer = read("scripts/install-dns.sh")
    assert "28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6" in defaults
    assert "checksums.txt" in installer
    assert "--verify" in installer
    assert "AdGuardHome.sig" in installer
    assert "fingerprint mismatch" in installer
    assert "unsafe archive path" in installer

def test_strict_doh_guard():
    defaults = read("config/defaults.env")
    updater = read("scripts/update-doh-ips.sh")
    installer = read("scripts/install-doh-guard.sh")
    assert "adblock/doh.txt" in defaults
    assert "ips/doh.txt" in defaults
    assert "refusing suspiciously small encrypted-DNS IP list" in updater
    assert "ipaddress.ip_address" in updater
    assert "cmp -s" in updater
    assert "nova-doh-ips.timer" in installer


def test_awg_safety():
    cfg = read("scripts/configure-awg.sh")
    policy = read("docs/CRYPTO_POLICY.md")
    assert "HeaderProtectionKey" in cfg
    assert "ContentPaddingAddition" in cfg
    assert "RandomTrailers" in cfg
    assert "AWG_PARAMS_VERSION=2" in cfg
    assert "secrets.randbelow" in cfg
    assert "NOVA_AWG_EXPERIMENTAL_RANDOM_TRAILERS" in cfg
    assert "AWG_H1=1" not in cfg
    assert "AWG_H2=2" not in cfg
    assert "AWG_S1=32" not in cfg
    assert "X25519MLKEM768" in policy
    # CPS I1-I5 values are deliberately not fabricated by NOVA.
    assert not re.search(r"^I[1-5]\s*=", cfg, re.M)

def test_peer_key_separation():
    peer = read("scripts/create-peer.sh")
    helper = read("scripts/lib/peer.sh")
    assert "client_private" in peer
    registry_block = re.search(r'cat >"\$peer" <<EOF(.*?)EOF', peer, re.S)
    assert registry_block, "peer registry heredoc not found"
    assert "client_private" not in registry_block.group(1)
    assert "PresharedKey = $psk" in helper
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in helper

def test_forwarding_enabled_only_after_firewall():
    hardening = read("config/sysctl/99-nova-privacy.conf")
    routing = read("config/sysctl/99-nova-routing.conf")
    installer = read("scripts/install-firewall.sh")
    assert "net.ipv4.ip_forward = 1" not in hardening
    assert "net.ipv4.ip_forward = 1" in routing
    fw_pos = installer.index('"$ROOT/scripts/render-firewall.sh"')
    route_pos = installer.index("99-nova-routing.conf")
    assert fw_pos < route_pos, "packet forwarding must be enabled only after firewall load"


def test_installer_order():
    text = read("scripts/install.sh")
    expected = [
        "bootstrap.sh",
        "harden.sh",
        "install-firewall.sh",
        "install-awg.sh",
        "configure-awg.sh",
        "install-dns.sh",
        "install-doh-guard.sh",
    ]
    positions = [text.index(x) for x in expected]
    assert positions == sorted(positions), "security-sensitive installation order changed"

def test_no_tls_mitm():
    combined = "\n".join(read(p) for p in (
        "README.md", "docs/THREAT_MODEL.md", "docs/CRYPTO_POLICY.md"
    ))
    assert "end-to-end" in combined.lower()
    assert not list((ROOT / "config").rglob("*.crt"))
    assert not list((ROOT / "config").rglob("*.pem"))

def test_secret_ignores():
    text = read(".gitignore")
    for marker in ("*.key", "*.psk", "*.p12", "*.pfx", "*.tar.age", "secrets/"):
        assert marker in text, f"missing gitignore rule: {marker}"


def test_operator_overrides_are_preserved():
    defaults = read("config/defaults.env")
    assert 'NOVA_WAN_IF=${NOVA_WAN_IF:-}' in defaults
    assert 'NOVA_ETC=${NOVA_ETC:-/etc/nova-privacy}' in defaults
    assert 'NOVA_AWG_MODE=${NOVA_AWG_MODE:-balanced}' in defaults

def test_anonymity_modes_are_client_only():
    common = read("scripts/lib/common.sh")
    ctl = read("src/privacyctl")
    assert "COMPAT|PRIVATE|STRICT|LOCKDOWN" in common
    assert "TOR-ANON|MAX-MIX" not in common
    assert "anonymity guidance" in ctl
    assert "client-originated" in ctl

def test_peer_export_atomic_and_ipv6_safe():
    helper = read("scripts/lib/peer.sh")
    assert 'tmp_conf="$(mktemp' in helper
    assert 'mv -f "$tmp_conf" "$conf"' in helper
    assert 'tmp_qr="$(mktemp' in helper
    assert '${host:0:1}' in helper
    assert '${host: -1}' in helper

def test_awg_rebuild_is_transactional():
    rebuild = read("scripts/rebuild-awg-peers.sh")
    assert "new_stripped" in rebuild and "old_stripped" in rebuild
    assert "persistent config unchanged" in rebuild
    assert rebuild.index('awg syncconf "$NOVA_VPN_IF" "$new_stripped"') < rebuild.index('mv -f "$candidate" "$conf"')


def test_backup_restore_are_serialized_and_complete():
    backup = read("scripts/backup.sh")
    restore = read("scripts/restore.sh")
    ctl = read("src/privacyctl")
    leak = read("scripts/verify-leaks.sh")
    assert "acquire_nova_lock" in backup
    assert "acquire_nova_lock" in restore
    assert "install-doh-guard.sh" in restore
    assert "nova-doh-ips.timer" in ctl
    assert "doh-ipv4.txt" in ctl
    assert "STRICT encrypted-DNS IP guard is active" in leak


def test_host_hardening_baseline():
    bootstrap = read("scripts/bootstrap.sh")
    harden = read("scripts/harden.sh")
    sysctl = read("config/sysctl/99-nova-privacy.conf")
    assert "apparmor" in bootstrap
    assert "unattended-upgrades" in bootstrap
    assert "52nova-security-upgrades" in harden
    assert "Automatic-Reboot" in harden
    assert "mlkem768x25519-sha256" in harden
    assert "net.ipv6.conf.all.disable_ipv6 = 1" in sysctl
    assert "kernel.perf_event_paranoid = 3" in sysctl

def test_awg31_is_capability_probed():
    installer = read("scripts/install-awg.sh")
    defaults = read("config/defaults.env")
    unit = read("config/systemd/nova-awg.service.in")

    assert "probe_awg31_userspace()" in installer
    assert 'awg setconf "$dev" "$cfg"' in installer
    assert "github.com/amnezia-vpn/amneziawg-go/v3" in installer
    assert "proxy.golang.org" in installer
    assert "GOSUMDB=\"sum.golang.org\"" in installer
    assert "NOVA_AWG_BACKEND=userspace" in installer
    assert "amneziawg-dkms" in installer and "Pin-Priority: -1" in installer
    assert "NOVA_AWG_BACKEND=${NOVA_AWG_BACKEND:-userspace}" in defaults
    assert "NOVA_AWG_EXPERIMENTAL_RANDOM_TRAILERS=${NOVA_AWG_EXPERIMENTAL_RANDOM_TRAILERS:-off}" in defaults
    assert "WG_QUICK_USERSPACE_IMPLEMENTATION=/usr/local/sbin/amneziawg-go" in unit
    assert "modprobe amneziawg" not in unit


def test_firewall_service_starts_immediately():
    installer = read("scripts/install-firewall.sh")
    assert "systemctl enable --now nova-firewall.service" in installer
    assert "systemctl is-active --quiet nova-firewall.service" in installer

def test_ipv6_block_is_verified():
    leak = read("scripts/verify-leaks.sh")
    assert "net.ipv6.conf.all.disable_ipv6" in leak
    assert "net.ipv6.conf.default.disable_ipv6" in leak


def test_optional_features_fail_closed():
    gates = read("scripts/feature-gates.sh")
    features = read("config/features.env")
    assert "require_feature_binary" in gates
    assert "NOVA_FEATURE_NAIVE" in gates
    assert "TOR-ANON must remain client-originated" in gates
    assert "MAX-MIX must remain client-originated" in gates
    assert "NOVA_FEATURE_MASQUE=disabled" in features
    assert "NOVA_FEATURE_HYSTERIA2=disabled" in features


def test_live_acceptance_tooling():
    ctl = read("src/privacyctl")
    live = read("scripts/live-acceptance.sh")
    inject = read("scripts/failure-injection.sh")
    probe = read("scripts/probe-features.sh")
    docs = read("docs/LIVE_VALIDATION.md")

    assert "acceptance preflight|server|report" in ctl
    assert "failure-injection dry-run|execute" in ctl
    assert "features probe" in ctl
    assert "firewall input/forward/output default DROP" in live
    assert "physical-client" in live.lower()
    assert "NOVA_OOB_CONFIRMED" in inject
    assert "does not automatically stop AWG" in inject
    assert "X25519MLKEM768" in probe
    assert "MASQUE" in probe
    assert "Release gate" in docs


def test_client_acceptance_assets():
    linux = read("clients/linux/verify-nova.sh")
    windows = read("clients/windows/Test-NOVAPrivacy.ps1")
    android = read("clients/android/ACCEPTANCE.md")
    assert "NOVA_EXPECTED_IF" in linux
    assert "does not contact a third-party" in linux
    assert "Get-NetRoute" in windows
    assert "Get-DnsClientServerAddress" in windows
    assert "Always-on VPN" in android
    assert "Block connections without VPN" in android
    assert "systemctl stop nova-awg.service" in android


def test_deployment_baseline_gates():
    bootstrap = read("scripts/bootstrap.sh")
    harden = read("scripts/harden.sh")
    ssh = read("config/ssh/90-nova-privacy.conf")
    installer = read("scripts/install.sh")
    live = read("scripts/live-acceptance.sh")
    common = read("scripts/lib/common.sh")

    assert 'Ubuntu Server/Minimal 26.04 LTS' in bootstrap
    assert '1.24.2-1ubuntu2.1' in bootstrap
    assert 'linux-oracle' in bootstrap
    assert 'systemd-zram-generator' in bootstrap
    assert 'active SSH session uses IPv6' in bootstrap
    assert 'is_ubuntu_2604' in common
    assert 'is_oci_host' in common
    assert 'rsync is required to update a non-empty NOVA installation safely' in installer
    assert 'rsync -a --delete' in installer
    assert 'PermitRootLogin no' in ssh
    assert 'AuthenticationMethods publickey' in ssh
    assert 'find_keyed_sudo_admin' in harden
    assert 'origin=Ubuntu' in harden
    assert 'mlkem768x25519-sha256' in harden
    assert 'Ubuntu 26.04 LTS baseline' in live
    assert 'expected Canonical kernel track is installed/booted' in live
    assert 'public bootstrap SSH rule removed' in live

def test_ci_and_release_are_target_and_provenance_gated():
    ci = read(".github/workflows/ci.yml")
    release = read(".github/workflows/release.yml")
    digest = "sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78"

    assert "ubuntu:26.04@" + digest in ci
    assert "ubuntu:26.04@" + digest in release
    assert "bash tests/run.sh" in release
    assert "tests/test-render-firewall.sh" in release
    assert 'release tag must point exactly at current main' in release
    assert 'CHANGELOG.md has no released section' in release
    assert "needs: validate" in release
    assert "attest-build-provenance@" in release
    assert "gh attestation download" in release
    assert "attestation.jsonl" in release


def test_third_party_repo_is_constrained():
    installer = read("scripts/install-awg.sh")
    assert "Pin: release o=LP-PPA-amnezia" in installer
    assert "Pin-Priority: 1" in installer
    assert "Package: amneziawg-tools" in installer
    assert "Package: amneziawg amneziawg-dkms" in installer
    assert "Pin-Priority: -1" in installer
    assert "apt-get -o DPkg::Lock::Timeout=600 install -y --no-install-recommends amneziawg-tools" in installer
    assert "NOVA_AWG_TOOLS_PACKAGE_VERSION" in installer
    assert "NOVA_AWG_GO_INSTALLED_VERSION" in installer
    assert "NOVA_AWG_GO_SHA256" in installer


def test_live_acceptance_is_single_canonical_script():
    live = read("scripts/live-acceptance.sh")
    assert live.count("#!/usr/bin/env bash") == 1
    assert live.count("preflight() {") == 1
    assert live.count("server_checks() {") == 1
    assert live.count("no_public_sensitive_ports() {") == 1

def test_awg_updates_do_not_drop_management_tunnel():
    cfg = read("scripts/configure-awg.sh")
    active_block = cfg[cfg.index('if systemctl is-active --quiet nova-awg.service'):]
    assert 'awg syncconf "$NOVA_VPN_IF" "$live_candidate"' in active_block
    assert 'systemctl restart nova-awg.service' not in active_block
    assert "active AWG address differs from requested design" in active_block
    assert "updated in place without dropping the active tunnel" in active_block


def test_dynamic_memory_is_privacy_safe():
    cfg = read("scripts/configure-memory.sh")
    enc = read("scripts/encrypted-swap.sh")
    unit = read("config/systemd/nova-encrypted-swap.service")
    sysctl = read("config/sysctl/99-nova-privacy.conf")

    assert "zram-size = min(ram / 2, 4096)" in cfg
    assert "swap-priority = 200" in cfg
    assert "NOVA_SWAP_MAX_MIB" in cfg
    assert "NOVA_SWAP_MIN_FREE_MIB" in cfg
    assert "--key-file /dev/urandom" in enc
    assert "aes-xts-plain64" in enc
    assert "swapon -p 10" in enc
    assert "ExecStart=/opt/nova-privacy/scripts/encrypted-swap.sh start" in unit
    assert "vm.swappiness = 100" in sysctl
    assert "vm.page-cluster = 0" in sysctl

def test_periodic_maintenance_is_fail_closed():
    maint = read("scripts/system-maintenance.sh")
    post = read("scripts/postboot-verify.sh")
    auto = read("scripts/install-automation.sh")
    defaults = read("config/defaults.env")

    assert "full-upgrade" in maint
    assert "DPkg::Lock::Timeout=600" in maint
    assert "NOVA_TRAFFIC_GATE closed" in maint
    assert "reopen-after-boot" in maint
    assert "systemctl reboot" in maint
    assert "verify-leaks.sh" in maint
    assert "NOVA_TRAFFIC_GATE open" in post
    for timer in ("nova-release-update.timer", "nova-maintenance.timer", "nova-cleanup.timer"):
        assert timer in auto
    assert "NOVA_AUTO_SYSTEM_UPDATE" in defaults
    assert "NOVA_AUTO_REBOOT" in defaults

def test_release_self_update_requires_checksum_and_provenance():
    updater = read("scripts/release-update.sh")
    bootstrap = read("install.sh")
    defaults = read("config/defaults.env")

    for text in (updater, bootstrap):
        assert "SHA256SUMS" in text
        assert "sha256sum -c" in text
        assert "attestation.jsonl" in text
        assert "gh attestation verify" in text
        assert "--bundle" in text
        assert "--signer-workflow" in text
        assert "--source-ref" in text
    assert "Alaa91H/NOVA-Privacy-Core" in defaults
    assert "NOVA_AUTO_RELEASE_UPDATE" in defaults

def test_activation_gate_has_no_unverified_open_command():
    ctl = read("src/privacyctl")
    renderer = read("scripts/render-firewall.sh")
    firewall = read("config/nftables/nova.nft.in")

    assert "gate status|close" in ctl
    assert "gate status|open" not in ctl
    assert "recent_management_handshake" in ctl
    assert "/var/run/reboot-required" in ctl
    assert "verify-leaks.sh" in ctl
    assert "rollback_activation" in ctl
    assert "NOVA_TRAFFIC_GATE open" in ctl
    assert "TRAFFIC_GATE_DROP" in renderer
    assert "@@TRAFFIC_GATE_DROP@@" in firewall

def test_bootstrap_is_release_first_and_not_pipe_to_shell():
    bootstrap = read("install.sh")
    assert 'NOVA_SOURCE:-release' in bootstrap
    assert "No stable NOVA release exists yet" in bootstrap
    assert "NOVA_SOURCE=main" in bootstrap
    assert "exec bash" in bootstrap
    assert "curl" in bootstrap
    assert "| bash" not in bootstrap
    assert "| sh" not in bootstrap

def test_privacyctl_is_single_canonical_control_plane():
    ctl = read("src/privacyctl")
    assert ctl.count("#!/usr/bin/env bash") == 1
    assert len(re.findall(r'^case "\\${1:-}" in    assert ctl.count("cmd_health() {") == 1
    assert ctl.count("cmd_activate() {") == 1
    assert "valid_cidr" in ctl


def test_ubuntu_awg_path_avoids_known_kernel_module_risk():
    installer = read("scripts/install-awg.sh")
    service = read("config/systemd/nova-awg.service.in")
    defaults = read("config/defaults.env")

    assert "production supports only NOVA_AWG_BACKEND=userspace" in installer
    assert "apt-get" in installer and "amneziawg-tools" in installer
    assert "amneziawg-dkms" in installer and "Pin-Priority: -1" in installer
    assert "amneziawg-go" in service
    assert "ExecStartPre=/sbin/modprobe amneziawg" not in service
    assert "NOVA_AWG_GO_VERSION=${NOVA_AWG_GO_VERSION:-auto}" in defaults

def test_version():
    version = read("VERSION").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), version

def main():
    tests = [
        test_firewall,
        test_lockdown_precedes_conntrack_accept,
        test_deployment_gate_precedes_conntrack_accept,
        test_dns_bypass_blocks_precede_conntrack_accept,
        test_early_firewall_boot_order,
        test_dns_privacy,
        test_adguard_least_privilege_auth,
        test_release_authenticity,
        test_strict_doh_guard,
        test_awg_safety,
        test_peer_key_separation,
        test_forwarding_enabled_only_after_firewall,
        test_installer_order,
        test_no_tls_mitm,
        test_secret_ignores,
        test_operator_overrides_are_preserved,
        test_anonymity_modes_are_client_only,
        test_peer_export_atomic_and_ipv6_safe,
        test_awg_rebuild_is_transactional,
        test_backup_restore_are_serialized_and_complete,
        test_host_hardening_baseline,
        test_awg31_is_capability_probed,
        test_firewall_service_starts_immediately,
        test_ipv6_block_is_verified,
        test_optional_features_fail_closed,
        test_live_acceptance_tooling,
        test_client_acceptance_assets,
        test_deployment_baseline_gates,
        test_ci_and_release_are_target_and_provenance_gated,
        test_third_party_repo_is_constrained,
        test_live_acceptance_is_single_canonical_script,
        test_awg_updates_do_not_drop_management_tunnel,
        test_dynamic_memory_is_privacy_safe,
        test_periodic_maintenance_is_fail_closed,
        test_release_self_update_requires_checksum_and_provenance,
        test_activation_gate_has_no_unverified_open_command,
        test_bootstrap_is_release_first_and_not_pipe_to_shell,
        test_privacyctl_is_single_canonical_control_plane,
        test_ubuntu_awg_path_avoids_known_kernel_module_risk,
        test_version,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")

if __name__ == "__main__":
    main()
, ctl, re.M)) == 1
    assert ctl.count("cmd_health() {") == 1
    assert ctl.count("cmd_activate() {") == 1
    assert "valid_cidr" in ctl


def test_ubuntu_awg_path_avoids_known_kernel_module_risk():
    installer = read("scripts/install-awg.sh")
    service = read("config/systemd/nova-awg.service.in")
    defaults = read("config/defaults.env")

    assert "production supports only NOVA_AWG_BACKEND=userspace" in installer
    assert "apt-get" in installer and "amneziawg-tools" in installer
    assert "amneziawg-dkms" in installer and "Pin-Priority: -1" in installer
    assert "amneziawg-go" in service
    assert "ExecStartPre=/sbin/modprobe amneziawg" not in service
    assert "NOVA_AWG_GO_VERSION=${NOVA_AWG_GO_VERSION:-auto}" in defaults

def test_version():
    version = read("VERSION").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), version

def main():
    tests = [
        test_firewall,
        test_lockdown_precedes_conntrack_accept,
        test_deployment_gate_precedes_conntrack_accept,
        test_dns_bypass_blocks_precede_conntrack_accept,
        test_early_firewall_boot_order,
        test_dns_privacy,
        test_adguard_least_privilege_auth,
        test_release_authenticity,
        test_strict_doh_guard,
        test_awg_safety,
        test_peer_key_separation,
        test_forwarding_enabled_only_after_firewall,
        test_installer_order,
        test_no_tls_mitm,
        test_secret_ignores,
        test_operator_overrides_are_preserved,
        test_anonymity_modes_are_client_only,
        test_peer_export_atomic_and_ipv6_safe,
        test_awg_rebuild_is_transactional,
        test_backup_restore_are_serialized_and_complete,
        test_host_hardening_baseline,
        test_awg31_is_capability_probed,
        test_firewall_service_starts_immediately,
        test_ipv6_block_is_verified,
        test_optional_features_fail_closed,
        test_live_acceptance_tooling,
        test_client_acceptance_assets,
        test_deployment_baseline_gates,
        test_ci_and_release_are_target_and_provenance_gated,
        test_third_party_repo_is_constrained,
        test_live_acceptance_is_single_canonical_script,
        test_awg_updates_do_not_drop_management_tunnel,
        test_dynamic_memory_is_privacy_safe,
        test_periodic_maintenance_is_fail_closed,
        test_release_self_update_requires_checksum_and_provenance,
        test_activation_gate_has_no_unverified_open_command,
        test_bootstrap_is_release_first_and_not_pipe_to_shell,
        test_privacyctl_is_single_canonical_control_plane,
        test_ubuntu_awg_path_avoids_known_kernel_module_risk,
        test_version,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")

if __name__ == "__main__":
    main()
