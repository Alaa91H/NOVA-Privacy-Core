# Disaster Recovery

A trustworthy recovery rebuilds a clean server rather than preserving a potentially compromised OS image.

## Required external material

Keep separately:

- encrypted NOVA backup;
- age decryption identity/passphrase;
- repository/release location;
- Oracle account and Console recovery access;
- client-management/reprovisioning plan.

## Recovery sequence

1. Provision a clean Ubuntu Server/Minimal 26.04 LTS instance.
2. Restrict Oracle Security List/NSG.
3. Establish non-root keyed sudo administration.
4. Download and run the NOVA bootstrap.
5. Keep protected forwarding CLOSED.
6. Restore the encrypted NOVA backup.
7. Re-run memory, AWG, firewall and DNS installation/validation.
8. Verify nftables default DROP.
9. Connect a management peer.
10. Run health/leak/preflight tests.
11. Run `privacyctl activate`.
12. Run final server and physical-client acceptance.

## Restore rehearsal

Before a production release, perform the full sequence on a clean test VM. A backup that has never been restored successfully is not a validated recovery mechanism.

## Suspected key compromise

If the old host may have exposed tunnel secrets:

- do not treat restored server/peer secrets as final production credentials;
- rebuild from clean Ubuntu 26.04;
- generate a new server key;
- reprovision/rotate all peers;
- revoke the old instance and credentials.

A backup restores availability; it does not establish that old credentials remain trustworthy.
