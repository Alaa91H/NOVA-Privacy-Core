# Security Policy

Do not publish private keys, exported VPN profiles, server credentials, access tokens, or backup secrets in public issues.

## Guarantees

NOVA targets:

- encrypted client-to-gateway transport;
- strict egress and DNS routing;
- no silent direct fallback in protected profiles;
- per-peer credential isolation;
- minimal persistent metadata;
- preservation of end-to-end application TLS.

NOVA does not guarantee that a compromised endpoint remains private, that a datacenter IP looks residential, or that a global observer cannot perform traffic correlation.

## Secret handling

Never commit `*.key`, `*.psk`, generated peer `*.conf` files, Oracle credentials, access tokens, or backup decryption keys.
