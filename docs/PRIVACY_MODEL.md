# Privacy Model

## COMPAT

Encrypted full-device tunnel with validating recursive DNS and minimal filtering. Use when an application breaks under stricter blocking.

## PRIVATE

Default daily profile.

- real client IP hidden from destination sites;
- destination sees Oracle/datacenter IP;
- DNS goes through the gateway's private filtering path;
- application HTTPS remains end-to-end;
- no query-history retention.

## STRICT

Same encrypted transport with aggressive DNS filtering. False positives are an accepted tradeoff; it must never replace COMPAT.

## TOR-ANON

Tor begins on the endpoint, preferably Tor Browser for web activity.

Oracle can observe the outer client connection and the Tor-side next hop, but does not receive the browser's final destination from the Tor circuit.

## MAX-MIX

Optional client-originated mixnet mode. It trades latency and bandwidth for stronger resistance to timing/volume analysis.

## LOCKDOWN

The peer exists but the gateway drops its traffic. This is an emergency administrative state, not an anonymity network.

## Limits

NOVA cannot:

- make an Oracle ASN look residential;
- hide a user's identity from a service after the user identifies themselves to it;
- protect plaintext from malware that already controls the endpoint;
- guarantee defeat of a global traffic-correlation adversary;
- make all advertising disappear with DNS blocking when ad and content share the same origin.
