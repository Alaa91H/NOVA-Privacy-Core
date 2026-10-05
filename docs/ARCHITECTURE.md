# Architecture

## Data plane

```text
client
  |
  | AmneziaWG 3.1 full tunnel
  v
amneziawg-go -> awg0 TUN on Oracle
  |
  +-- DNS/53 --> nftables source-profile dispatch
  |               +-- COMPAT  --> Unbound :5335
  |               +-- PRIVATE --> AdGuard :5300 --> Unbound
  |               +-- STRICT  --> AdGuard :5301 --> Unbound
  |
  +-- verified forwarding gate --> WAN masquerade
```

The peer's tunnel IP is the policy identity. No payload inspection is required.

## Ubuntu 26.04 transport backend

NOVA uses the official `amneziawg-go` userspace implementation by default on Ubuntu 26.04.

`awg-quick` officially supports userspace fallback. NOVA forces that path explicitly because current upstream kernel-module regressions on kernel 7.0 make the kernel backend unsuitable for the production baseline until separately requalified.

The userspace daemon is version-resolved from the v3.1 module line and built through the Go module proxy/checksum database. `amneziawg-tools` remains the configuration/UAPI client.

## Activation gate

The initial/maintenance firewall includes a forwarding rule marked `NOVA_TRAFFIC_GATE_CLOSED` before conntrack established-flow acceptance.

This means a connection that existed before maintenance cannot survive the gate as an already-established bypass.

Only `privacyctl activate` can transition to OPEN after verification.

## Management

Management peers use a distinct private range. SSH is accepted from that range over the AWG interface.

The temporary public bootstrap SSH rule is removed during final activation and is never automatically recreated by upgrades.

## DNS

- COMPAT -> validating Unbound;
- PRIVATE -> balanced AdGuard -> Unbound;
- STRICT -> aggressive AdGuard -> Unbound;
- DoT/853 is blocked for protected peers;
- STRICT additionally blocks known encrypted-DNS destination IPs.

## Anonymous paths

Preferred Tor model:

```text
Tor Browser -> Tor -> AmneziaWG outer tunnel -> Oracle -> Tor guard -> ...
```

Tor begins on the endpoint. The Oracle host therefore does not need to inspect application traffic to decide whether a flow is Tor.

## Resource policy

On a ~1 GB host the resident baseline is:

- `amneziawg-go`;
- nftables;
- Unbound;
- two small AdGuard instances;
- lightweight shell/Python control plane;
- zram;
- optional low-priority ephemeral encrypted disk swap.

Tor/Nym clients stay on endpoints by default.

## Persistent state

Only configuration/credentials required for operation are intended to persist:

- server tunnel key;
- peer public keys/PSKs;
- peer/profile registry;
- AWG obfuscation parameters;
- DNS policy;
- service configuration;
- encrypted rollback/backups when explicitly created.

Browsing destination history is not intentional persistent state.
