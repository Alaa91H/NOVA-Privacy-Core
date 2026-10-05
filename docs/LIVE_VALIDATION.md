# Live Validation and Acceptance

Repository CI proves syntax, static policy invariants, renderer behavior, and supply-chain checks. It cannot prove a physical network path.

## Server acceptance sequence

Before the management peer is connected:

```bash
sudo privacyctl acceptance preflight
sudo privacyctl health
```

After the management peer has a recent handshake:

```bash
sudo privacyctl lockdown
sudo privacyctl acceptance server
```

For the full post-lockdown report, including remaining physical-client gates:

```bash
sudo privacyctl acceptance report
```

The `server` and `report` modes intentionally fail while the temporary public SSH bootstrap rule still exists.

## Optional feature probe

```bash
sudo privacyctl features probe
```

This reports local capability only. It never marks MASQUE, PQ/TLS, ECH, Tor, or Nym as accepted merely because a binary is installed.

Current design facts verified against upstream documentation:

- sing-box 1.15+ exposes MASQUE CONNECT-IP client/server endpoints (RFC 9484).
- Tor Browser remains the preferred browser isolation surface for TOR-ANON.
- Nym mixnet clients use fixed-size Sphinx traffic, cover traffic and mix delays; this is a different latency/privacy tradeoff from a VPN.
- Hysteria 2 is QUIC-based and suitable as an optional degraded-network fallback, not the core trust layer.

## Failure injection

First inspect the plan:

```bash
sudo privacyctl failure-injection dry-run
```

Only with Oracle Console / serial / another out-of-band path:

```bash
sudo NOVA_OOB_CONFIRMED=1 privacyctl failure-injection execute
```

The script tests DNS-service fail-closed behavior. It deliberately leaves AWG-stop and reboot observation manual because automatically severing the active management tunnel would be unsafe.

## Physical clients

### Android

1. Import the peer profile.
2. Enable Always-on VPN.
3. Enable Block connections without VPN.
4. Verify public IPv4 equals the protected exit.
5. Verify no direct IPv6 path exists.
6. Verify DNS does not use the ISP.
7. Stop AWG on the server from Oracle Console and verify Android has no Internet.
8. Restore AWG and verify recovery.

### Windows / Linux

Repeat public-IP, DNS, IPv6 and tunnel-failure checks, then test:

- sleep/wake;
- Wi-Fi to Ethernet/hotspot changes;
- route-table changes;
- DNS cache behavior after reconnect.

## Release gate

Do not tag `v1.0.0` until T40-T47 have real evidence. The release workflow intentionally requires the tag to match `VERSION`.
