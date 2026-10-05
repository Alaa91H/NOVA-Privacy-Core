# Disaster Recovery

A trustworthy recovery rebuilds a clean server rather than preserving a potentially compromised OS image.

## Required material

Keep externally:

- encrypted NOVA backup;
- age decryption identity or passphrase;
- GitHub repository URL/release;
- Oracle account recovery access;
- client-management plan.

## Recovery sequence

1. Provision a clean supported Debian VM.
2. Restrict Oracle Security List/NSG.
3. Install NOVA from a reviewed tag/commit.
4. Run the baseline installer.
5. Restore the encrypted backup.
6. Confirm AWG and DNS service health.
7. Verify nftables default-drop policy.
8. Connect a management peer.
9. Remove bootstrap public SSH.
10. Run server and client leak tests.

## Suspected key compromise

If the old VPS may have exposed tunnel secrets:

- do **not** restore old server/peer secrets as final production credentials;
- rebuild;
- generate a new server key;
- reprovision/rotate all peers;
- revoke the old instance and credentials.

A backup restores availability; it is not proof that old credentials remain trustworthy.
