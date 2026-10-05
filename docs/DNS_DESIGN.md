# DNS Design

## Three policies

### COMPAT

Peer DNS is transparently redirected to Unbound.

### PRIVATE

Peer DNS is redirected to the PRIVATE AdGuard instance, using HaGeZi Pro Mini + TIF Mini, then Unbound.

### STRICT

Peer DNS is redirected to the STRICT AdGuard instance, using HaGeZi Ultimate Mini + TIF Mini, then Unbound.

## Privacy controls

AdGuard query history and statistics are disabled. Runtime client-discovery sources are disabled. ECS is not intentionally enabled.

Unbound uses DNSSEC validation, QNAME minimization, aggressive NSEC, hardened DNSSEC-stripping checks, minimal responses, and bounded caches.

## Bypass policy

Plain DNS/53 is redirected inside the protected interface. DoT/DoQ on 853 is blocked for forwarded client traffic.

NOVA does not blindly block all HTTPS/443 because DoH and ordinary HTTPS share that port. STRICT may use maintained DoH endpoint policies later, but must not turn HTTPS into a fragile global blocklist.

## Zero-trust limitation

In PRIVATE/STRICT the Oracle guest processes the DNS query, even if it does not retain it. For sessions that must hide DNS from the VPS itself, use client-originated Tor or a properly separated encrypted/oblivious DNS architecture.
