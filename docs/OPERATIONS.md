# Operations

## Routine health

```bash
sudo privacyctl status
sudo privacyctl health
sudo privacyctl leaks test
```

## Peer lifecycle

```bash
sudo privacyctl peer add phone PRIVATE
sudo privacyctl peer rotate phone
sudo privacyctl profile set phone STRICT
sudo privacyctl peer revoke phone
```

Revocation is the correct response to a lost device. Do not rotate every other peer unnecessarily.

## Updates

```bash
sudo privacyctl update check
```

NOVA intentionally does not implement blind automatic upgrades of all third-party security components. Review upstream security notes, validate configuration, test leaks, then deploy.

## Backups

Interactive:

```bash
sudo privacyctl backup
```

Automated with an externally held age recipient:

```bash
sudo NOVA_BACKUP_RECIPIENT=age1... privacyctl backup /root/nova.age
```

The private age identity must not be stored in the same backup.

## Logging

Normal operations retain service health and aggregate counters, not intentional browsing/DNS history.

Temporary verbose debugging should be explicitly enabled for the shortest practical period and disabled afterward.
