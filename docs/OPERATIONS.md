# Operations

## Routine status

```bash
sudo privacyctl status
sudo privacyctl health
sudo privacyctl gate status
```

## Peer lifecycle

```bash
sudo privacyctl peer add phone PRIVATE
sudo privacyctl peer rotate phone
sudo privacyctl profile set phone STRICT
sudo privacyctl peer revoke phone
```

## Automatic updates

NOVA owns package/application update execution so no independent package installer can change the running privacy gateway outside the maintenance gate.

Schedules:

- stable NOVA release poll: every ~30 minutes;
- system/kernel/application maintenance: daily;
- cleanup: weekly;
- DoH-IP refresh: periodic NOVA timer.

During privileged changes, protected forwarding is CLOSED.

If a kernel/AWG update requires reboot, NOVA keeps forwarding closed, reboots when enabled, then uses `nova-postboot-verify.service` to run verification before reopening.

## Manual update commands

```bash
sudo privacyctl update check
sudo privacyctl update system
sudo privacyctl update release
```

`update release` accepts only a newer stable release and verifies SHA-256 and GitHub provenance before installation.

## Cleanup

```bash
sudo privacyctl cleanup run
```

Cleanup is bounded: package cache, tmpfiles, short journal vacuuming, stale temporary files, and old rollback archives. It does not erase active configuration/keys.

## Memory

Inspect:

```bash
swapon --show
zramctl
sudo privacyctl status
```

Expected on a constrained node:

- `/dev/zram0` at high priority;
- optional `/dev/mapper/nova-swap` at low priority;
- no plaintext NOVA-managed disk swap.

The encrypted swap mapping uses a fresh random key each boot.

## Closing forwarding manually

```bash
sudo privacyctl gate close
```

There is intentionally no raw `gate open` command. Reopening requires:

```bash
sudo privacyctl activate
```

## Backups

```bash
sudo privacyctl backup
```

For automated backups, use an externally held age recipient:

```bash
sudo NOVA_BACKUP_RECIPIENT=age1... privacyctl backup /root/nova.age
```

Never store the age private identity in the same backup.

## Logging

NOVA minimizes persistent metadata. Query history is disabled, journald is volatile, coredumps are disabled, and verbose debugging should only be enabled temporarily.
