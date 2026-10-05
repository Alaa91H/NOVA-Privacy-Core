# Windows Client

Use one unique NOVA peer for each Windows installation.

## Required validation

- full-tunnel routing;
- DNS server/routing behavior;
- IPv6 fail-closed behavior;
- sleep/resume;
- Wi-Fi/Ethernet transitions;
- captive-portal behavior;
- tunnel/server failure;
- reboot/autostart behavior.

## Firewall

Use Windows firewall/AmneziaWG client kill-switch capabilities where available. The server-side firewall does not prevent a Windows client from using its physical connection if the local VPN application fails; endpoint lockdown must be tested separately.

## Anonymous browsing

Use Tor Browser as an isolated browser profile. Do not import personal cookies, extensions, or profiles into it.
