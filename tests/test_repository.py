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
    gate_pos = installer.index('atomic-safety-gate.sh" boot-close')
    route_pos = installer.index("99-nova-routing.conf")
    assert gate_pos < route_pos, "packet forwarding must be enabled only after atomic CLOSED gate"
    service = read("config/systemd/nova-firewall.service")
    assert "atomic-safety-gate.sh boot-close" in service


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
    assert 'atomic-safety-gate.sh" close maintenance' in maint
    assert "write_runtime_kv NOVA_TRAFFIC_GATE" not in maint
    assert "reopen-after-boot" in maint
    assert "install-github-cli.sh" in maint
    assert "systemctl reboot" in maint
    assert "reopen-verified.sh" in maint
    assert "reopen-verified.sh" in post
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
    gate = read("scripts/atomic-safety-gate.sh")
    renderer = read("scripts/render-firewall.sh")
    firewall = read("config/nftables/nova.nft.in")

    assert "gate status|close" in ctl
    assert "gate status|open" not in ctl
    assert 'atomic-safety-gate.sh" open interactive' in ctl
    assert "rollback_activation" not in ctl
    assert "NOVA_TRAFFIC_GATE open" not in ctl

    for marker in (
        "recent_management_handshake",
        "/var/run/reboot-required",
        "deep_preopen_verify",
        "gate.pending",
        "schedule_deadman",
        "emergency_kernel_close",
        "NOVA_EMERGENCY_KILLSWITCH",
        "NOVA_GATE_OPEN_",
        "FIREWALL_DIGEST",
        "watchdog()",
        "seal_valid",
        "systemd-analyze verify",
        "unbound-checkconf",
        "awg-quick strip",
        "package_manager_idle",
        "storage_ready",
    ):
        assert marker in gate, marker

    assert "--stage" in renderer
    assert '"$nft_bin" -c -f "$candidate"' in renderer
    assert "@@EMERGENCY_GUARD_BLOCK@@" in firewall
    assert "@@GATE_ACCEPT_COMMENT@@" in firewall


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
    assert sum(1 for line in ctl.splitlines() if line == 'case "${1:-}" in') == 1
    assert ctl.count("cmd_health() {") == 1
    assert ctl.count("cmd_activate() {") == 1
    common = read("scripts/lib/common.sh")
    assert "valid_cidr()" in common
    assert 'atomic-safety-gate.sh" open interactive' in ctl


def test_ubuntu_awg_path_avoids_known_kernel_module_risk():
    installer = read("scripts/install-awg.sh")
    service = read("config/systemd/nova-awg.service.in")
    defaults = read("config/defaults.env")

    assert "production supports only NOVA_AWG_BACKEND=userspace" in installer
    assert "amneziawg-tools" in installer
    assert "amneziawg-dkms" in installer and "Pin-Priority: -1" in installer
    assert "amneziawg-go" in service
    assert "ExecStartPre=/sbin/modprobe amneziawg" not in service
    assert "NOVA_AWG_GO_VERSION=${NOVA_AWG_GO_VERSION:-auto}" in defaults


def test_verified_reopen_is_centralized_and_rollback_safe():
    helper = read("scripts/reopen-verified.sh")
    gate = read("scripts/atomic-safety-gate.sh")
    maint = read("scripts/system-maintenance.sh")
    post = read("scripts/postboot-verify.sh")
    release = read("scripts/release-update.sh")

    assert 'atomic-safety-gate.sh" open automatic' in helper
    assert "NOVA_BOOTSTRAP_SSH_CIDR" in helper
    assert "/var/run/reboot-required" in helper
    assert "deep_preopen_verify" in gate
    assert "verify-leaks.sh" in gate
    assert "live-acceptance.sh" in gate
    assert "rollback()" in gate
    assert "emergency_kernel_close" in gate
    assert "schedule_deadman" in gate
    assert 'reopen-verified.sh' in maint
    assert 'reopen-verified.sh' in post
    assert 'reopen-verified.sh' in release


def test_awg_userspace_integrity_is_a_gate():
    ctl = read("src/privacyctl")
    live = read("scripts/live-acceptance.sh")
    installer = read("scripts/install-awg.sh")

    assert "NOVA_AWG_GO_SHA256" in ctl
    assert "NOVA_AWG_GO_INSTALLED_VERSION" in ctl
    assert "sha256sum /usr/local/sbin/amneziawg-go" in ctl
    assert "AmneziaWG userspace SHA-256 mismatch" in ctl
    assert "awg_userspace_integrity" in live
    assert "AWG userspace version/hash integrity" in live
    assert "write_runtime_kv NOVA_AWG_GO_SHA256" in installer


def test_peer_registry_is_data_only():
    common = read("scripts/lib/common.sh")
    consumers = "\n".join(read(p) for p in (
        "scripts/render-firewall.sh",
        "scripts/rebuild-awg-peers.sh",
        "scripts/set-profile.sh",
        "scripts/rotate-peer.sh",
        "src/privacyctl",
        "scripts/install-firewall.sh",
    ))
    creator = read("scripts/create-peer.sh")

    assert "load_peer_registry()" in common
    assert "peer registry must be root-owned" in common
    assert "unknown peer registry key" in common
    assert "peer IP does not belong" in common
    assert "unexpected peer PSK path" in common
    assert 'source "$peer"' not in consumers
    assert 'source "$f"' not in consumers
    assert "load_peer_registry" in consumers
    assert "NAME=$name" in creator
    assert "PUBLIC_KEY=$client_public" in creator


def test_peer_registry_preserves_base64_padding():
    common = read("scripts/lib/common.sh")
    assert 'while IFS= read -r line' in common
    assert 'key="${line%%=*}"' in common
    assert 'value="${line#*=}"' in common
    assert "while IFS='=' read -r key value" not in common


def test_restore_is_always_fail_closed_and_host_revalidated():
    restore = read("scripts/restore.sh")
    assert "Recovery is always fail-closed" in restore
    assert 'atomic-safety-gate.sh" close restore-start' in restore
    assert "NOVA_GATE_TOKEN" in restore
    assert "NOVA_GATE_TXN_ID" in restore
    assert "NOVA_BOOTSTRAP_SSH_CIDR" in restore
    assert 'recovery_bootstrap_cidr="${NOVA_BOOTSTRAP_SSH_CIDR:-}"' in restore
    assert "write_runtime_batch" in restore
    assert "install-awg.sh" in restore
    assert "configure-memory.sh" in restore
    assert "install-automation.sh" in restore
    assert "load_runtime" in restore
    assert 'source "$NOVA_ETC/nova.env"' not in restore
    assert "privacyctl activate" in restore


def test_github_cli_attestation_path_is_official_and_pinned():
    helper = read("scripts/install-github-cli.sh")
    bootstrap = read("install.sh")
    defaults = read("config/defaults.env")
    smoke = read("tests/ubuntu26-smoke.sh")

    expected_hash = "6084d5d7bd8e288441e0e94fc6275570895da18e6751f70f057485dc2d1a811b"
    expected_fpr1 = "2C6106201985B60E6C7AC87323F3D4EA75716059"
    expected_fpr2 = "7F38BBB59D064DBCB3D84D725612B36462313325"

    for text in (bootstrap, defaults):
        assert expected_hash in text
        assert expected_fpr1 in text
        assert expected_fpr2 in text

    assert "NOVA_GITHUB_CLI_KEYRING_SHA256" in helper
    assert "NOVA_GITHUB_CLI_KEY_FPRS" in helper
    assert "https://cli.github.com/packages" in helper
    assert "Pin: origin cli.github.com" in helper
    assert "Package: gh" in helper
    assert "Pin-Priority: 700" in helper
    assert "gh attestation verify --help" in helper
    assert "gh_attestation_help=" in helper
    assert "gh_attestation_help=" in bootstrap
    assert "gh_attestation_help=" in smoke
    for text in (helper, bootstrap, smoke):
        assert "attestation verify --help 2>/dev/null | grep" not in text
        assert "attestation verify --help | grep" not in text
    assert "scripts/install-github-cli.sh" in smoke
    assert " gh " not in smoke.split("apt-get install", 1)[1].splitlines()[1] if "apt-get install" in smoke else True


def test_runtime_and_awg_state_are_data_only():
    common = read("scripts/lib/common.sh")
    bootstrap = read("scripts/bootstrap.sh")
    restore = read("scripts/restore.sh")
    awg = read("scripts/configure-awg.sh")

    assert 'source "$runtime"' not in common
    assert 'source "$runtime"' not in bootstrap
    assert 'source "$NOVA_ETC/nova.env"' not in restore
    assert 'source "$params"' not in awg
    assert "unapproved runtime key" in common
    assert "duplicate runtime key" in common
    assert "unapproved/duplicate AWG parameter" in awg
    assert "runtime state validation failed" in common
    assert "AWG parameter validation failed" in awg
    assert "NOVA_NFT_BIN" not in common[common.index("allowed={"):common.index("seen=set()", common.index("allowed={"))]


def test_runtime_writes_are_fsync_atomic():
    common = read("scripts/lib/common.sh")
    assert "write_runtime_batch()" in common
    assert "os.fsync" in common
    assert "os.replace" in common
    assert "O_DIRECTORY" in common
    assert "tempfile.mkstemp" in common


def test_atomic_gate_boot_watchdog_and_deadman():
    gate = read("scripts/atomic-safety-gate.sh")
    fw_unit = read("config/systemd/nova-firewall.service")
    wd_unit = read("config/systemd/nova-gate-watchdog.service")
    wd_timer = read("config/systemd/nova-gate-watchdog.timer")
    automation = read("scripts/install-automation.sh")

    assert "atomic-safety-gate.sh boot-close" in fw_unit
    assert "NOVA_EMERGENCY_KILLSWITCH" in gate
    assert "nova_emergency" in gate
    assert "gate.pending" in gate
    assert "systemd-run" in gate
    assert "deadman()" in gate
    assert "watchdog()" in gate
    assert "FIREWALL_DIGEST" in gate
    assert "nft --stateless list table inet nova" in gate
    assert "OnUnitActiveSec=10s" in wd_timer
    assert "AccuracySec=1s" in wd_timer
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in wd_unit
    assert "ProtectSystem=strict" in wd_unit
    assert "nova-gate-watchdog.timer" in automation


def test_mutations_close_before_change_and_reaccept():
    paths = (
        "scripts/create-peer.sh",
        "scripts/revoke-peer.sh",
        "scripts/rotate-peer.sh",
        "scripts/set-profile.sh",
        "scripts/update-doh-ips.sh",
        "scripts/system-maintenance.sh",
        "scripts/release-update.sh",
    )
    for path in paths:
        text = read(path)
        assert "atomic-safety-gate.sh" in text, path
        assert "close " in text, path
    for path in (
        "scripts/create-peer.sh",
        "scripts/revoke-peer.sh",
        "scripts/rotate-peer.sh",
        "scripts/set-profile.sh",
        "scripts/update-doh-ips.sh",
        "scripts/system-maintenance.sh",
        "scripts/release-update.sh",
    ):
        assert "reopen-verified.sh" in read(path), path


def test_apt_upgrade_acceptance_contract_is_consistent():
    live = read("scripts/live-acceptance.sh")
    start = live.index("automation_ready() {")
    end = live.index("independent_upgrader_disabled() {", start)
    automation = live[start:end]
    assert "apt-daily.timer" in automation
    assert "apt-daily-upgrade.timer" not in automation
    assert "apt-daily-upgrade.timer" in live[live.index("independent_upgrader_disabled() {"):]


def test_firewall_open_is_token_bound_and_staged():
    renderer = read("scripts/render-firewall.sh")
    template = read("config/nftables/nova.nft.in")
    assert "NOVA_GATE_TOKEN" in renderer
    assert "^[a-f0-9]{32}$" in renderer
    assert "NOVA_GATE_OPEN_" in renderer
    assert "NOVA_EMERGENCY_KILLSWITCH" in renderer
    assert "--stage" in renderer
    assert 'nft -c -f' in renderer or '"$nft_bin" -c -f' in renderer
    assert "@@EMERGENCY_GUARD_BLOCK@@" in template
    assert "@@GATE_ACCEPT_COMMENT@@" in template

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
        test_verified_reopen_is_centralized_and_rollback_safe,
        test_awg_userspace_integrity_is_a_gate,
        test_peer_registry_is_data_only,
        test_peer_registry_preserves_base64_padding,
        test_restore_is_always_fail_closed_and_host_revalidated,
        test_github_cli_attestation_path_is_official_and_pinned,
        test_runtime_and_awg_state_are_data_only,
        test_runtime_writes_are_fsync_atomic,
        test_atomic_gate_boot_watchdog_and_deadman,
        test_mutations_close_before_change_and_reaccept,
        test_apt_upgrade_acceptance_contract_is_consistent,
        test_firewall_open_is_token_bound_and_staged,
        test_version,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")

if __name__ == "__main__":
    main()
