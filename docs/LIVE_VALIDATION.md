# Live Validation and Acceptance

Repository CI can prove syntax, static security invariants, renderer behavior, workflow validity, Ubuntu 26.04 compatibility checks, and release-chain controls. It cannot prove a physical network path.

## Server acceptance sequence

Before the management peer is connected:

```bash
sudo privacyctl acceptance preflight
sudo privacyctl health
sudo privacyctl leaks test
```

Protected forwarding remains **CLOSED**.

After the management peer has a recent handshake:

```bash
sudo privacyctl activate
sudo privacyctl acceptance server
```

For the complete post-activation report:

```bash
sudo privacyctl acceptance report
```

`activate` is the only supported path to OPEN. It removes the temporary public SSH bootstrap rule and refuses to open forwarding if a reboot is pending or any health/leak check fails.

## Ubuntu 26.04 / AWG acceptance

The production path uses `amneziawg-go`, not the current kernel module.

Live evidence must include:

- `privacyctl status` reports userspace backend/version;
- a real management peer handshake;
- real data transfer through the userspace AWG path;
- no pending reboot after tool/daemon/kernel updates;
- reconnect after a reboot with post-boot gate verification.

## Update/reboot acceptance

Exercise at least one maintenance cycle on a test host:

```bash
sudo privacyctl update system
```

Observe:

1. traffic gate moves CLOSED before package changes;
2. package/kernel/app update completes;
3. if reboot-required is created, traffic stays CLOSED;
4. reboot occurs if configured;
5. post-boot verification executes;
6. traffic returns OPEN only after successful verification.

Also test:

```bash
sudo privacyctl update release
```

using a test release/candidate environment before production v1.0.0.

## Optional feature probe

```bash
sudo privacyctl features probe
```

Capability presence is not acceptance. MASQUE, PQ/TLS, ECH, Tor, Nym, NaiveProxy and Hysteria 2 remain gated until real interoperability/privacy/performance evidence exists.

## Failure injection

Inspect first:

```bash
sudo privacyctl failure-injection dry-run
```

Only with Oracle Console / serial / another out-of-band path:

```bash
sudo NOVA_OOB_CONFIRMED=1 privacyctl failure-injection execute
```

The automated portion validates DNS service fail-closed behavior. AWG-stop and reboot observation remain manual because blindly severing the active management path would be unsafe.

## Physical clients

### Android

1. Import the unique NOVA peer.
2. Enable Always-on VPN.
3. Enable Block connections without VPN.
4. Verify DNS uses NOVA.
5. Verify no direct IPv6 route exists.
6. Verify the visible exit is the expected protected exit.
7. Stop AWG from Oracle Console.
8. Confirm Android has **no Internet** rather than direct fallback.
9. Restore AWG and confirm recovery.

### Windows / Linux

Repeat public-IP, DNS, IPv6 and forced-failure checks, then test:

- sleep/wake;
- Wi-Fi/Ethernet/hotspot changes;
- route-table changes;
- DNS cache behavior;
- update/reboot/reconnect behavior.

## Release gate

Do not tag `v1.0.0` until the real Oracle host, physical clients, clean restore, failure injection, performance/1GB resource tests, automatic update/reboot cycle, and soak gates all have evidence.
