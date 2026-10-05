# Verification

## Server-side

Before the management peer is established:

```bash
sudo privacyctl acceptance preflight
sudo privacyctl health
sudo privacyctl leaks test
sudo privacyctl firewall check
```

After a management peer has a recent handshake and `sudo privacyctl lockdown` succeeds:

```bash
sudo privacyctl acceptance server
sudo privacyctl leaks test
```

The checks cover:

- fail-closed nftables chain policies;
- AWG interface availability;
- IPv4 forwarding only after firewall activation;
- disabled/fail-closed IPv6 in the default profile;
- no wildcard-public sensitive DNS/admin listeners;
- Unbound and both AdGuard profiles;
- disabled AdGuard query history;
- STRICT encrypted-DNS IP guard and refresh timer;
- private-key/secret file modes;
- SSH password/root-login policy;
- volatile-journal evidence where available.

## Client-side

### Linux

```bash
sudo NOVA_EXPECTED_IF=awg0 NOVA_DNS_IP=10.77.0.1 \
  ./clients/linux/verify-nova.sh
```

Use the actual interface name if the client differs.

### Windows

From an elevated PowerShell:

```powershell
.\clients\windows\Test-NOVAPrivacy.ps1 -ExpectedDns 10.77.0.1 -ExpectedAdapter "<NOVA adapter>"
```

### Android

Follow [clients/android/ACCEPTANCE.md](../clients/android/ACCEPTANCE.md), including **Always-on VPN** and **Block connections without VPN**.

The client verifiers intentionally avoid contacting a third-party public-IP service automatically. Verify visible exit IP only against a destination you explicitly trust.

## Failure injection

Inspect first:

```bash
sudo privacyctl failure-injection dry-run
```

With Oracle Console/serial/out-of-band recovery available:

```bash
sudo NOVA_OOB_CONFIRMED=1 privacyctl failure-injection execute
```

The automated portion validates DNS service fail-closed behavior. AWG-stop and reboot tests require simultaneous physical-client observation and are intentionally not executed blindly by a remote script.

A protected endpoint must never gain a direct-Internet path when the protected service fails.

## Optional privacy features

```bash
sudo privacyctl features probe
```

Binary presence is **not** acceptance. MASQUE, PQ/TLS, ECH, Tor and Nym remain gated until real path/handshake evidence exists.

Do not upload identifying DNS/IP test results to the public repository.
