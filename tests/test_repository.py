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

def test_lockdown_precedes_conntrack_accept():
    text = read("config/nftables/nova.nft.in")
    m = re.search(r"chain forward \{(.*?)\n  \}", text, re.S)
    assert m, "forward chain not found"
    forward = m.group(1)
    assert forward.index("@lockdown4 drop") < forward.index("ct state established,related accept"), (
        "LOCKDOWN must override already-established forwarding flows"
    )


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

def test_version():
    version = read("VERSION").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), version

def main():
    tests = [
        test_firewall,
        test_lockdown_precedes_conntrack_accept,
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
        test_version,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")

if __name__ == "__main__":
    main()
