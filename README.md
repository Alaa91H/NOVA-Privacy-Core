# NOVA Privacy Core

**NOVA Privacy Core** is a security-first, zero-trust privacy gateway for a constrained self-hosted VPS.

The production baseline is **Ubuntu Server/Minimal 26.04 LTS**, including Oracle Cloud instances with roughly **1 vCPU / 1 GB RAM**, and Android, Windows, and Linux clients.

## Security model

- Assume the local network, ISP, hosting network, DNS infrastructure, package mirrors, and intermediate networks are untrusted.
- Fail closed: protected forwarding starts **closed** and cannot open until the host, tunnel, DNS stack, management peer, firewall, and leak checks pass.
- Preserve end-to-end TLS. NOVA never installs a browsing MITM CA.
- Use one tunnel keypair and one PSK per device.
- Keep DNS query history and browsing destination history out of persistent logs.
- Use stable, reviewed cryptography; do not invent ciphers.
- Keep anonymity client-originated where possible.
- Never claim mathematical untraceability.

## Ubuntu 26.04 / Oracle design

- Canonical `linux-oracle` is installed automatically when OCI is detected.
- AmneziaWG uses the **official userspace `amneziawg-go` backend** on Ubuntu 26.04.
- The current upstream kernel module is not part of the production path because recent Ubuntu 26.04/kernel 7.0 regressions are still under investigation.
- `amneziawg-tools` comes from the signed Amnezia PPA, with APT pinning that denies its kernel/meta packages and prevents the PPA from overriding unrelated Ubuntu packages.
- `amneziawg-go` is built from the latest allowed v3.1 Go module using `proxy.golang.org` and `sum.golang.org`.

## Memory policy

Small servers receive:

- zram: `min(RAM / 2, 4 GiB)`, zstd, high swap priority;
- dynamically sized disk swap only when useful/free space permits;
- disk swap encrypted with a fresh random dm-crypt key on every boot;
- zram is always preferred over disk swap.

## Automatic maintenance

NOVA installs timers for:

- verified NOVA stable-release checks every ~30 minutes;
- daily Ubuntu/system/kernel/application maintenance;
- encrypted-DNS blocklist refresh;
- weekly bounded cleanup.

Package/application maintenance closes protected forwarding first. It reopens only after verification. If a reboot is required, forwarding remains closed through reboot until post-boot checks pass.

NOVA stable releases are accepted only after:

1. HTTPS download from the configured GitHub repository;
2. SHA-256 verification;
3. GitHub build-provenance attestation verification;
4. local repository tests;
5. fail-closed installation/upgrade;
6. post-upgrade health and leak checks.

## Profiles

| Profile | Purpose |
|---|---|
| `COMPAT` | Full tunnel, validating DNS, minimum breakage |
| `PRIVATE` | Full tunnel + balanced ad/tracker/threat blocking |
| `STRICT` | Full tunnel + aggressive blocking |
| `TOR-ANON` | **Client mode:** Tor Browser over a PRIVATE outer tunnel |
| `MAX-MIX` | **Client mode:** optional endpoint-originated mixnet path |
| `LOCKDOWN` | No protected forwarding |

## Bootstrap deployment

The bootstrap script is intentionally downloaded first and executed as a separate file rather than piped directly into a shell:

```bash
curl -fsSLo /tmp/nova-install.sh \
  https://raw.githubusercontent.com/Alaa91H/NOVA-Privacy-Core/main/install.sh

sudo bash /tmp/nova-install.sh
```

The default bootstrap installs the latest **stable, attested release**. Before the first stable release exists, an explicit development deployment can be requested:

```bash
sudo NOVA_SOURCE=main bash /tmp/nova-install.sh
```

`NOVA_SOURCE=main` is intentionally marked as development and does not receive the same release-attestation guarantee.

## First activation

After installation, user forwarding is still **CLOSED**:

```bash
sudo privacyctl status
sudo privacyctl acceptance preflight
sudo privacyctl peer add laptop PRIVATE --management
```

Import the generated management peer and connect it. Then:

```bash
sudo privacyctl health
sudo privacyctl leaks test
sudo privacyctl activate
sudo privacyctl gate status
sudo privacyctl acceptance server
```

`privacyctl activate` requires a recent management handshake, no pending reboot, successful health/leak checks, removes the temporary public SSH rule, and then opens protected forwarding.

## Manual operations

```bash
sudo privacyctl update check
sudo privacyctl update system
sudo privacyctl update release
sudo privacyctl cleanup run
```

## Important limitation

When PRIVATE/STRICT exits directly from Oracle, destination sites see an Oracle/datacenter IP. Encryption cannot transform a hosting ASN into a residential ASN. For stronger anonymity, use client-originated Tor or a tested mixnet path.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Cryptographic policy](docs/CRYPTO_POLICY.md)
- [Privacy model](docs/PRIVACY_MODEL.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Verification](docs/VERIFICATION.md)
- [Operations](docs/OPERATIONS.md)
- [Disaster recovery](docs/DISASTER_RECOVERY.md)
- [Live validation](docs/LIVE_VALIDATION.md)
- [Deployment readiness](docs/DEPLOYMENT_READINESS.md)
- [Roadmap](docs/ROADMAP.md)

## Status

Repository-side implementation and automated CI can establish **repository readiness**. Production readiness still requires real Oracle-host, restore, failure-injection, and physical-client evidence.

## License

Apache-2.0.
