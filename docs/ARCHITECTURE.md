# Architecture

## Data plane

```text
client
  |
  | AmneziaWG 3.1 full tunnel
  v
awg0 on Oracle
  |
  +-- DNS/53 --> nftables source-profile dispatch
  |               +-- COMPAT  --> Unbound :5335
  |               +-- PRIVATE --> AdGuard :5300 --> Unbound
  |               +-- STRICT  --> AdGuard :5301 --> Unbound
  |
  +-- normal IP forwarding --> WAN masquerade
```

The peer's tunnel IP is the policy identity. No payload inspection is required.

## Management

Management peers use a distinct private range. SSH and administrative access are accepted only from that range over the VPN interface.

The public interface never intentionally exposes DNS or an admin UI.

## Anonymous paths

Preferred Tor model:

```text
Tor Browser -> Tor protocol -> AmneziaWG outer tunnel -> Oracle -> Tor guard -> ...
```

Tor encryption begins before traffic reaches Oracle, reducing the final destination information available to the VPS.

## Optional transports

MASQUE, NaiveProxy, and Hysteria 2 are feature-gated fallbacks. They are not mandatory and are not all kept resident.

## Resource policy

On a 1 GB host, the default resident stack is:

- one kernel tunnel;
- nftables;
- Unbound;
- two small AdGuard Home instances;
- lightweight shell control plane.

Tor/Nym clients stay on endpoints by default.

## Persistent state

Only configuration and credentials required for operation are persistent:

- server tunnel key;
- peer public keys/PSKs;
- peer/profile registry;
- DNS allowlists;
- service configuration.

Browsing destination history is not intentional persistent state.
