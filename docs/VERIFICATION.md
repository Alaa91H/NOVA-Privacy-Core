# Verification

## Server-side

Run:

```bash
sudo privacyctl health
sudo privacyctl leaks test
sudo privacyctl firewall check
```

The checks verify:

- fail-closed nftables chain policies;
- AWG interface availability;
- IPv4 forwarding;
- blocked IPv6 forwarding in the default design;
- no wildcard-public sensitive DNS/admin listeners;
- Unbound and both AdGuard profiles;
- disabled AdGuard query history;
- private-key file modes.

## Failure injection

After a working management tunnel exists, test failures deliberately from a recovery-capable session.

Examples:

```bash
sudo systemctl stop nova-awg
sudo systemctl stop unbound
sudo systemctl stop nova-adguard-private
```

For a protected endpoint, a failure must not create a direct-Internet path.

Restore each service immediately after its test.

## Client-side

GitHub CI cannot prove client leak behavior.

On every Android/Windows/Linux endpoint verify:

- protected visible public IP;
- no ISP DNS;
- no direct IPv6;
- tunnel loss fails closed;
- network transitions do not create a bypass window.

Do not upload identifying DNS/IP test results to the public repository.
