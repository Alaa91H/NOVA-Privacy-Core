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

NOVA generates a unique, persistent obfuscation identity per server using the OS CSPRNG:

- Jc is randomized within the current recommended range;
- S1-S4 are generated inside conservative documented bounds;
- H1-H4 are unique high-entropy values rather than project-wide constants;
- the header-protection key is unique to the server;
- the parameter set is backed up with the encrypted server state and must not change while existing peers still use it.

Header protection and content padding are enabled in the supported profile. Experimental features are not equated with stronger security: RandomTrailers remains **off by default**, including MAX mode, until current 3.1 interoperability/packet-classification issues are demonstrably resolved on both server and client implementations. Operators can only enable it through an explicit experimental feature gate.

NOVA favors a verified, non-fingerprinted configuration over untested “maximum” values.

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
