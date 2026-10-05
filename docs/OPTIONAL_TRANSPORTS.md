# Optional Transports

NOVA's default production path is AmneziaWG. Optional transports are separate feature gates, not a protocol stack that runs continuously.

## MASQUE

Current sing-box documentation exposes `masque-client` and `masque-server` endpoints. NOVA treats MASQUE as a candidate standards-based fallback transport.

Before enabling it in production:

- validate the exact sing-box release/config syntax;
- provision a real TLS identity;
- confirm server/client routing;
- confirm failure is fail-closed;
- measure RAM/CPU on the 1 GB VPS;
- verify actual PQ/T negotiation if the profile is advertised as post-quantum.

Source: https://sing-box.sagernet.org/configuration/endpoint/

## Hysteria 2

Hysteria 2 can masquerade as HTTP/3 traffic and normally expects a domain/TLS setup for a credible deployment.

NOVA will not fabricate a hostname or disable TLS verification merely to make an optional mode appear complete.

Source: https://v2.hysteria.network/docs/getting-started/Server/

## NaiveProxy

NaiveProxy is an optional HTTPS-like camouflage path. It is not installed by default because a second resident proxy increases attack surface and memory use.

## Tor / Nym

Tor and mixnet clients are endpoint-originated by default. This is a privacy decision: starting anonymity encryption before Oracle reduces final-destination knowledge available to the VPS.

## Feature-gate command

```bash
sudo bash scripts/feature-gates.sh
```

A gate only reports prerequisites. It never silently converts an unavailable privacy path into direct Internet access.
