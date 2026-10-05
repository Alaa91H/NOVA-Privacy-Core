# Deployment

## Production target

- Ubuntu Server/Minimal **26.04 LTS**.
- Oracle Cloud is the primary target; generic Ubuntu 26.04 is supported by the same design.
- Approximately 1 vCPU / 1 GB RAM is sufficient for the constrained baseline.
- Bootstrap administration must use IPv4 because the default policy disables IPv6 fail-closed.

Before installation, ensure a **non-root** administrator has:

- a valid SSH public key in `authorized_keys`;
- membership in Ubuntu's `sudo` group.

NOVA disables root SSH and password/keyboard-interactive authentication and refuses to apply that policy if no keyed non-root recovery administrator exists.

## Oracle network prerequisite

The Oracle Security List / NSG is outside the guest and must be prepared separately:

1. restrict TCP/22 to the administrator's current public IPv4;
2. permit the NOVA AmneziaWG UDP port, default 51820;
3. do not expose DNS/53, DoT/853, AdGuard UI, Unbound, or internal management ports;
4. keep Oracle Console/serial/OOB recovery available.

## Secure bootstrap

Download the bootstrap first:

```bash
curl -fsSLo /tmp/nova-install.sh \
  https://raw.githubusercontent.com/Alaa91H/NOVA-Privacy-Core/main/install.sh
sudo bash /tmp/nova-install.sh
```

The bootstrap:

- verifies Ubuntu 26.04;
- finds the latest stable NOVA release;
- downloads release archive + checksums + provenance bundle;
- validates SHA-256;
- validates GitHub provenance identity, signer workflow, and source tag;
- extracts only safe archive members;
- executes the internal installer.

For explicit development testing before a stable release:

```bash
sudo NOVA_SOURCE=main bash /tmp/nova-install.sh
```

## Installation behavior

The internal installer:

1. serializes itself against all maintenance jobs;
2. closes an existing production forwarding gate before upgrades;
3. mirrors privileged code into `/opt/nova-privacy` with stale-file deletion;
4. full-upgrades Ubuntu before installing the privacy stack;
5. installs `linux-oracle` automatically on OCI;
6. configures dynamic zram + ephemeral encrypted disk swap;
7. hardens SSH, kernel/sysctl, AppArmor, logs and crash dumps;
8. loads default-drop nftables before enabling forwarding;
9. installs AmneziaWG userspace + tools and executes a real AWG 3.1 capability probe;
10. resolves and verifies the latest stable AdGuard Home;
11. installs Unbound and both AdGuard profiles;
12. installs STRICT encrypted-DNS bypass protection;
13. enables fail-closed automatic updates/cleanup;
14. leaves protected forwarding **CLOSED**.

## First management peer

```bash
sudo privacyctl peer add laptop PRIVATE --management
```

Import:

```text
/root/nova-peers/laptop.conf
```

Connect the peer and confirm a recent handshake:

```bash
sudo privacyctl status
```

## Production activation

Before activation:

```bash
sudo privacyctl health
sudo privacyctl leaks test
sudo privacyctl acceptance preflight
```

Then:

```bash
sudo privacyctl activate
```

Activation is transactional. It:

- requires a recent management-peer handshake;
- refuses to run with a pending reboot;
- runs health and leak checks;
- removes the public bootstrap SSH rule;
- opens the forwarding gate;
- runs the final server acceptance suite;
- restores bootstrap SSH and forces the gate closed if final acceptance fails.

Confirm:

```bash
sudo privacyctl gate status
sudo privacyctl acceptance server
```

## Additional peers

```bash
sudo privacyctl peer add phone PRIVATE
sudo privacyctl peer add tablet STRICT
sudo privacyctl peer add bank COMPAT
```

Delete exported client private-key files after import if they are no longer needed:

```bash
sudo rm -f /root/nova-peers/phone.conf /root/nova-peers/phone.qr.png
```

## Automatic maintenance

Installed schedules include:

- NOVA release poll: every 30 minutes with jitter;
- system/kernel/app maintenance: daily with jitter;
- cleanup: weekly with jitter;
- encrypted-DNS IP refresh: existing NOVA timer.

System maintenance uses a strict state machine:

```text
OPEN -> close gate -> upgrade -> verify -> OPEN
                         |
                         +-> reboot required -> remain CLOSED
                                                |
                                                +-> post-boot verify -> OPEN
```

A failure never silently restores direct protected forwarding.
