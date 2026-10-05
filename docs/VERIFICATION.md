# Verification

## Pre-activation server checks

```bash
sudo privacyctl acceptance preflight
sudo privacyctl health
sudo privacyctl leaks test
sudo privacyctl firewall check
sudo privacyctl gate status
```

The gate must report `closed` before first production activation.

## Production activation

After a management peer has a recent handshake:

```bash
sudo privacyctl activate
sudo privacyctl gate status
sudo privacyctl acceptance server
sudo privacyctl leaks test
```

The final state must show `open` and no temporary public SSH firewall rule.

## Covered server invariants

- Ubuntu 26.04 LTS production baseline;
- expected Canonical kernel track;
- no pending reboot;
- synchronized clock;
- AppArmor enabled;
- zram + optional encrypted swap;
- fail-closed nftables input/forward/output;
- explicit deployment traffic gate;
- AWG userspace interface;
- IPv4 forwarding only behind the firewall;
- fail-closed IPv6;
- no wildcard-sensitive DNS/admin listeners;
- Unbound and both AdGuard profiles;
- disabled AdGuard query history;
- STRICT encrypted-DNS bypass guard;
- root-only secret modes;
- root/password SSH disabled;
- hybrid OpenSSH KEX;
- release/system/cleanup timers;
- independent Ubuntu package-upgrade timer disabled.

## Client-side

### Linux

```bash
sudo NOVA_EXPECTED_IF=awg0 NOVA_DNS_IP=10.77.0.1 \
  ./clients/linux/verify-nova.sh
```

### Windows

```powershell
.\clients\windows\Test-NOVAPrivacy.ps1 -ExpectedDns 10.77.0.1 -ExpectedAdapter "<NOVA adapter>"
```

### Android

Follow [clients/android/ACCEPTANCE.md](../clients/android/ACCEPTANCE.md), including **Always-on VPN** and **Block connections without VPN**.

The client verifiers intentionally do not contact an arbitrary third-party public-IP endpoint automatically.

## Automatic-maintenance verification

Inspect timer state:

```bash
systemctl list-timers 'nova-*'
sudo privacyctl status
```

Run controlled manual cycles on a test node:

```bash
sudo privacyctl update system
sudo privacyctl update release
sudo privacyctl cleanup run
```

Verify that package/application changes cannot occur through `apt-daily-upgrade.timer` outside NOVA's maintenance gate.

## Failure injection

```bash
sudo privacyctl failure-injection dry-run
sudo NOVA_OOB_CONFIRMED=1 privacyctl failure-injection execute
```

A protected endpoint must never gain a direct Internet path when the protected service fails.

## Optional privacy features

```bash
sudo privacyctl features probe
```

Binary presence is **not** acceptance. Do not label optional transports or PQ/TLS accepted without actual negotiated/path evidence.

Do not upload identifying DNS/IP test results, peer configs, keys, PSKs, or host metadata to the public repository.
