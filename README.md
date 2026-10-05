# NOVA Privacy Core

**NOVA Privacy Core** is a security-first, zero-trust privacy gateway for a constrained self-hosted VPS.

It targets a single Oracle-class VM with roughly **1 vCPU / 1 GB RAM**, with Android, Windows, and Linux clients. The architecture separates encryption, DNS privacy, tracker blocking, transport obfuscation, and anonymity instead of pretending that one VPN protocol solves all of them.

## Principles

- Assume the local network, ISP, hosting network, DNS infrastructure, and intermediate networks are untrusted.
- Fail closed: a protected path going down must not silently restore direct Internet access.
- Preserve end-to-end TLS. NOVA never installs a browsing MITM CA.
- Use one keypair and one PSK per device.
- Keep DNS and destination history out of persistent logs.
- Use stable, reviewed cryptography; do not invent ciphers.
- Keep anonymity client-originated where possible.
- Treat aggressive filtering and compatibility as separate profiles.
- Never claim mathematical untraceability.

## Profiles

| Profile | Purpose |
|---|---|
| `COMPAT` | Full tunnel, validating DNS, minimum breakage |
| `PRIVATE` | Full tunnel + balanced ad/tracker/threat blocking |
| `STRICT` | Full tunnel + aggressive blocking |
| `TOR-ANON` | **Client mode:** use Tor Browser over a PRIVATE outer tunnel |
| `MAX-MIX` | **Client mode:** optional endpoint-originated mixnet path |
| `LOCKDOWN` | No unprotected fallback |

## Quick deployment

> Production baseline: Debian 13, IPv4 SSH bootstrap, and a non-root SSH-keyed user with sudo access. Keep the original SSH session open until verification succeeds.

```bash
git clone https://github.com/Alaa91H/NOVA-Privacy-Core.git
cd NOVA-Privacy-Core
sudo NOVA_WAN_IF=ens3 ./scripts/install.sh
```

After installation, verify the host baseline first, then establish the management tunnel before the final production gate:

```bash
sudo privacyctl status
sudo privacyctl acceptance preflight
sudo privacyctl peer add laptop PRIVATE --management
```

Import `/root/nova-peers/laptop.conf`, connect that peer, confirm a recent handshake, then remove temporary public SSH access and run the final server checks:

```bash
sudo privacyctl lockdown
sudo privacyctl acceptance server
sudo privacyctl leaks test
sudo privacyctl peer add phone PRIVATE
```

## Important limitation

When `PRIVATE`/`STRICT` exits directly from Oracle, destination sites see an Oracle/datacenter IP. Encryption cannot turn a hosting ASN into a residential ASN. For stronger anonymity, use client-originated Tor or mixnet modes.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Cryptographic policy](docs/CRYPTO_POLICY.md)
- [Privacy model](docs/PRIVACY_MODEL.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Verification](docs/VERIFICATION.md)
- [Roadmap](docs/ROADMAP.md)
- [Live validation](docs/LIVE_VALIDATION.md)
- [Deployment readiness](docs/DEPLOYMENT_READINESS.md)

## Status

Repository-side implementation and CI validation are automated. Live gates requiring a real Oracle host or physical clients remain unverified until actually run.

## License

Apache-2.0.


### Anonymity-mode safety

`TOR-ANON` and `MAX-MIX` are deliberately **not assignable server peer profiles**. The gateway cannot prove an arbitrary application flow is Tor or mixnet traffic without inspecting it. Use `privacyctl anonymity guidance` and keep the outer NOVA peer on `PRIVATE` where appropriate.
