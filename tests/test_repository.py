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

def test_release_authenticity():
    defaults = read("config/defaults.env")
    installer = read("scripts/install-dns.sh")
    assert "NOVA_ADGUARD_GPG_FPR=28645AC9776EC4C00BCE2AFC0FE641E7235E2EC6" in defaults
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

def test_version():
    version = read("VERSION").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), version

def main():
    tests = [
        test_firewall,
        test_lockdown_precedes_conntrack_accept,
        test_early_firewall_boot_order,
        test_dns_privacy,
        test_release_authenticity,
        test_strict_doh_guard,
        test_awg_safety,
        test_peer_key_separation,
        test_installer_order,
        test_no_tls_mitm,
        test_secret_ignores,
        test_version,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")

if __name__ == "__main__":
    main()
