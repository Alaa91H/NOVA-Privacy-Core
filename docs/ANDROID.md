# Android

## Daily profile

Import the device's unique AmneziaWG configuration.

Enable Android's system VPN controls:

- **Always-on VPN**
- **Block connections without VPN**

These controls are essential to make tunnel failure fail closed on the endpoint.

## Profiles

Use a separate generated peer/profile according to the required policy:

- PRIVATE for daily use;
- STRICT when aggressive DNS blocking is desired;
- COMPAT for applications broken by strict filtering.

## Anonymous browsing

Use Tor Browser so Tor begins on the endpoint before traffic reaches Oracle.

Do not replace Tor Browser with a normal browser pointed at a raw Tor proxy and assume equivalent fingerprint protection.

## Android limitation

Android normally supports one active system VPN service per user/profile. NOVA therefore does not rely on stacking multiple independent system-VPN applications simultaneously.

## Test

Verify:

- Wi-Fi → mobile data;
- mobile data → Wi-Fi;
- sleep/wake;
- server tunnel failure;
- device reboot;
- DNS and IPv6 behavior.

A protected client must not regain direct Internet access when the tunnel fails.
