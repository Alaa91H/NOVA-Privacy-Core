# Threat Model

NOVA follows a **minimize-trust** model.

## Assets

- real client IP and network location;
- DNS query contents;
- destination metadata;
- application payloads and credentials;
- peer private keys and PSKs;
- server control credentials;
- browsing history;
- profile membership and identity linkage.

## Adversaries

### Local network / ISP

May observe outer destination IP, timing, and traffic volume.

Mitigations:

- authenticated encrypted tunnel;
- AmneziaWG transport obfuscation;
- no plaintext DNS in protected profiles;
- fail-closed routing.

### Oracle / hosting network

Can know that the VM exists and can observe infrastructure-level ingress/egress.

Mitigations:

- no intentional browsing-history retention;
- client-originated Tor/Nym for stronger anonymity;
- end-to-end TLS preserved beyond the VPS.

### Compromised VPS service

Mitigations:

- least privilege;
- systemd sandboxing;
- service accounts;
- no public admin UI;
- minimal logs;
- no browsing TLS interception.

### Malicious DNS infrastructure

Mitigations:

- DNSSEC validation where applicable;
- QNAME minimization;
- optional encrypted/oblivious resolver path.

DNSSEC authenticates signed data; it does not provide DNS query confidentiality.

### Destination service

The destination necessarily receives what the user sends. A VPN cannot hide identity after the user signs into an identifying account.

### Compromised endpoint

A sufficiently privileged endpoint compromise can observe data before encryption. NOVA cannot solve this remotely.

## Observability by profile

| Observer | PRIVATE | TOR-ANON |
|---|---|---|
| Local ISP | Oracle outer connection | Oracle outer connection |
| Oracle guest | direct destination IPs | Tor next-hop/guard connection |
| Destination | Oracle IP | Tor exit IP |
| Gateway AdGuard | DNS names | not used for Tor Browser DNS |
| HTTPS intermediary | ciphertext | ciphertext |

## Failure rule

Protected profiles must fail closed.

Any change that turns `DROP` into direct unprotected egress is a security regression.
