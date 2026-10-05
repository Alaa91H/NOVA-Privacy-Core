# Cryptographic Policy

## Rules

1. No custom cryptography.
2. Generate secrets with the OS CSPRNG.
3. One VPN keypair and one 256-bit PSK per peer.
4. Do not reuse exported client private keys.
5. Secret file mode is `0600`.
6. Preserve end-to-end application TLS.
7. Do not label a path post-quantum unless actual negotiation is verified.

## Primary VPN

AmneziaWG 3.1 retains WireGuard's cryptographic core:

- Noise_IK;
- Curve25519;
- ChaCha20-Poly1305.

Its 3.1 additions are obfuscation and metadata-shaping mechanisms, not replacement payload cryptography.

## AWG 3.1 feature policy

Header protection, content padding, random trailers, and timing randomization are enabled only after server/client interoperability checks pass. Current 3.1 implementations have changed rapidly, so NOVA favors verified compatibility over untested “maximum” parameter values.

## Project-controlled TLS

Use TLS 1.3 only.

Where a current implementation supports standardized hybrid PQ/T key exchange, target:

```text
X25519MLKEM768
```

Verification must confirm the negotiated group.

## SSH

Prefer a current OpenSSH hybrid PQ key exchange when available, while retaining strong classical host authentication.

## Backups

Backups containing peer PSKs or server private keys must be encrypted with a separately held backup secret.
