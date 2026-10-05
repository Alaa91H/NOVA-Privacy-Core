# Deployment Readiness

This document defines the difference between **repository readiness**, **deployment-candidate readiness**, and **production acceptance**.

## 1. Repository readiness

The repository is repository-ready only when all of the following are true:

- CI passes on Ubuntu runner validation.
- CI passes the same repository tests inside the pinned Debian 13.7 container.
- ShellCheck and Python compile checks pass.
- Firewall renderer integration test passes.
- GitHub Actions are pinned by full commit SHA.
- Release workflow re-runs validation before publishing.
- Release tag must match `VERSION`.
- Release tag must point exactly at current `main`.
- `CHANGELOG.md` must contain the release version.
- Release artifacts receive SHA-256 checksums and GitHub build provenance attestation.
- No private key, PSK, exported peer profile, or backup secret is tracked.

## 2. Host prerequisites

The production host must satisfy all of these before installation:

- Debian 13.
- Current security repositories enabled.
- At least about 1 GB RAM for the constrained baseline.
- Oracle Console/serial/out-of-band recovery available.
- Active installation SSH session uses IPv4; NOVA v1 intentionally disables IPv6.
- At least one non-root user has:
  - a valid SSH `authorized_keys` file;
  - membership in Debian's `sudo` group.
- Oracle Security List / NSG initially allows:
  - TCP/22 only from the administrator's current source IP;
  - the selected AmneziaWG UDP port.
- Oracle Security List / NSG does **not** expose DNS, DoT, AdGuard UI, Unbound, or internal management ports.

The installer intentionally fails rather than weakening these prerequisites.

## 3. Mandatory software/security baseline

NOVA production install requires:

- Debian 13 baseline.
- Unbound >= 1.26.1 security baseline.
- OpenSSH with `mlkem768x25519-sha256`.
- AmneziaWG server kernel/tools that pass NOVA's real 3.1 capability probe.
- AdGuard Home pinned stable release whose archive checksum and signing key are verified.

The Amnezia PPA is cryptographically pinned by signing-key fingerprint and APT policy limits that third-party origin to only:

- `amneziawg`
- `amneziawg-tools`
- `amneziawg-dkms`

All other packages remain sourced from Debian.

## 4. Deployment-candidate installation

From a reviewed commit or release candidate:

```bash
git clone https://github.com/Alaa91H/NOVA-Privacy-Core.git
cd NOVA-Privacy-Core
git checkout <reviewed-commit-or-release-tag>
sudo NOVA_WAN_IF=<wan-interface> bash ./scripts/install.sh
```

The installer:

1. mirrors code into `/opt/nova-privacy` with stale-file deletion on upgrades;
2. bootstraps the Debian security baseline;
3. verifies a non-root keyed sudo recovery account;
4. disables root/password SSH;
5. applies fail-closed IPv4/IPv6 host hardening;
6. loads firewall policy before forwarding;
7. installs and capability-probes AmneziaWG;
8. installs signed/checksummed AdGuard Home;
9. enables validating Unbound;
10. seeds STRICT encrypted-DNS bypass protection;
11. runs health verification.

Do not close the original SSH session until a management peer has completed a handshake.

## 5. Production acceptance

A successful installer is **not** enough to claim full production acceptance.

Before moving administration into the tunnel:

```bash
sudo privacyctl acceptance preflight
sudo privacyctl health
sudo privacyctl leaks test
sudo privacyctl features probe
```

Then create/import a management peer and confirm a recent handshake. From that protected management path:

```bash
sudo privacyctl lockdown
sudo privacyctl acceptance server
sudo privacyctl leaks test
```

`acceptance server` is intentionally a **post-lockdown** production gate: it must prove the temporary public SSH firewall rule is gone.

## 6. Physical-client gates

Every real client must pass its platform procedure.

### Android

- Always-on VPN enabled.
- Block connections without VPN enabled.
- no direct IPv6 fallback.
- no ISP DNS fallback.
- server AWG-down test produces **no Internet**, not direct fallback.

### Windows / Linux

- supplied local verifier passes;
- no direct IPv6 fallback;
- no ISP DNS fallback;
- sleep/wake passes;
- Wi-Fi/Ethernet/hotspot transitions do not create a bypass window;
- server AWG-down test fails closed.

## 7. Disaster-recovery gate

Before v1.0.0:

- create an encrypted backup;
- rebuild or use a clean Debian 13 test host;
- restore the backup;
- repeat server acceptance;
- verify at least one peer handshake;
- verify STRICT/PRIVATE DNS and firewall policy after restore.

A backup that has never been restored successfully is not considered a valid recovery plan.

## 8. Failure-injection gate

Only with Oracle Console/OOB recovery:

```bash
sudo privacyctl failure-injection dry-run
sudo NOVA_OOB_CONFIRMED=1 privacyctl failure-injection execute
```

Additionally stop AWG manually from Oracle Console while observing a physical protected client. The client must not gain a direct route.

## 9. Optional transports are not release blockers

MASQUE, NaiveProxy, Hysteria 2, Tor and Nym are deliberately feature-gated.

The stable core may be deployed without enabling them.

They may only be labelled accepted after their specific interoperability/performance/privacy tests pass. In particular:

- no PQ/TLS label without negotiated hybrid-handshake evidence;
- TOR-ANON remains client-originated through Tor Browser;
- MAX-MIX remains client-originated.

## 10. GitHub repository governance

For release-grade supply-chain protection, `main` should be protected by a GitHub branch rule/ruleset requiring:

- pull request before merge;
- CI `validate` status success;
- branch up to date before merge;
- force pushes disabled;
- branch deletion disabled;
- conversation resolution required;
- no bypass where practical.

Repository governance does not replace runtime verification, but an unprotected `main` weakens the release supply chain.

## 11. Readiness states

### Repository-ready

All automated repository/CI gates are green.

### Deployment-candidate-ready

Repository-ready + a reviewed commit has been selected + host prerequisites are satisfied.

### Production-ready

Deployment-candidate-ready + real Oracle acceptance + physical-client leak/failure tests + restore rehearsal pass.

### Release-ready

Production-ready + soak/performance gates pass + release version/changelog are finalized + release tag is created from protected current `main`.

NOVA must never collapse these states into a single misleading “all green” indicator.
