# Deployment Readiness

NOVA distinguishes repository, deployment-candidate, production, and release readiness.

## Repository-ready

All automated gates must pass:

- shell syntax and ShellCheck, including the root bootstrap;
- Python tests;
- static security audit;
- nftables renderer integration test in both CLOSED and OPEN gate states;
- workflow YAML parsing;
- pinned Ubuntu 26.04 container compatibility checks;
- Ubuntu security-fixed Unbound baseline;
- OpenSSH hybrid `mlkem768x25519-sha256` availability;
- Ubuntu Oracle-kernel package presence;
- GitHub CLI attestation bundle support;
- secret/generated-file tracking scan;
- release workflow validation and provenance generation.

## Host prerequisites

- Ubuntu Server/Minimal 26.04 LTS.
- Current Ubuntu security repositories.
- Oracle Console/serial/OOB recovery for OCI.
- IPv4 bootstrap SSH.
- Non-root keyed sudo administrator.
- Cloud firewall allowing only bootstrap SSH from the administrator plus the selected AWG UDP port.
- No public DNS/admin ports.

## Mandatory runtime baseline

- Canonical `linux-oracle` when OCI is detected, otherwise Ubuntu generic GA kernel.
- Security-fixed Ubuntu 26.04 Unbound.
- OpenSSH hybrid PQ KEX.
- AppArmor enabled.
- nftables default DROP on input/forward/output.
- IPv6 fail-closed.
- AmneziaWG userspace backend with real v3.1 capability probe.
- `amneziawg-tools` from a fingerprint-verified, tightly pinned PPA.
- PPA kernel/meta packages explicitly denied.
- `amneziawg-go` obtained through the Go module proxy/checksum database.
- Signed/checksummed AdGuard stable release.
- zram + ephemeral encrypted swap policy.
- release/system/cleanup timers enabled.
- Ubuntu's independent `apt-daily-upgrade` disabled so package changes cannot bypass NOVA's maintenance gate.

## Deployment-candidate-ready

A successful installer is only a candidate. Protected forwarding must still be CLOSED.

Required evidence:

```bash
sudo privacyctl health
sudo privacyctl leaks test
sudo privacyctl acceptance preflight
sudo privacyctl status
```

A real management peer must then complete a recent handshake.

## Production-ready

Run:

```bash
sudo privacyctl activate
sudo privacyctl gate status
sudo privacyctl acceptance server
```

The final state must prove:

- traffic gate OPEN;
- temporary public SSH rule gone;
- no reboot pending;
- expected kernel track booted;
- AWG/DNS/firewall services healthy;
- update and cleanup timers active;
- zram/encrypted swap state correct;
- no sensitive wildcard listener;
- STRICT encrypted-DNS guard loaded;
- query logging disabled;
- secrets have safe modes;
- SSH root/password login disabled.

Then complete physical-client tests and a clean-host encrypted-backup restore rehearsal.

## Automatic-update readiness

NOVA release updates must pass:

- stable non-draft/non-prerelease release selection;
- expected semantic tag;
- SHA256SUMS verification;
- local GitHub provenance bundle verification;
- signer workflow restriction;
- source tag restriction;
- safe archive extraction;
- local tests before privileged replacement;
- rollback archive + config snapshot;
- CLOSED traffic state during changes;
- health/leak verification before reopen.

System/kernel updates must similarly close forwarding before package installation and leave the gate closed across required reboots until post-boot verification.

## Failure-injection gate

Only with Oracle Console/OOB available:

```bash
sudo privacyctl failure-injection dry-run
sudo NOVA_OOB_CONFIRMED=1 privacyctl failure-injection execute
```

Manual AWG-stop observation from a physical protected client must prove that the endpoint does not acquire a direct fallback route.

## Release-ready

Before `v1.0.0`:

- production acceptance passes on the real Oracle host;
- Android and laptop leak/failure tests pass;
- backup restore rehearsal passes;
- performance/1GB-memory soak passes;
- automatic update/reboot/reopen cycle is exercised;
- release candidate soak passes;
- `VERSION` and `CHANGELOG.md` are finalized;
- tag points exactly at current `main`;
- release workflow succeeds.

## GitHub governance

For maximum supply-chain protection, repository rules should require PR review and the CI `validate` status for `main`, disallow force-push/deletion, require conversation resolution, and limit bypass. Repository governance is an account-level control and must be verified separately from repository code.

No automated repository test is allowed to claim production-ready status without real host/client evidence.
