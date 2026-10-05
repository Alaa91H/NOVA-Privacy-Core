# Android Acceptance

NOVA uses the official/compatible AmneziaWG client profile and relies on Android's system VPN lockdown controls.

## Required settings

1. Import the unique NOVA peer profile.
2. Open Android VPN settings for the NOVA/AmneziaWG connection.
3. Enable **Always-on VPN**.
4. Enable **Block connections without VPN**.
5. Disable per-app bypass/split tunneling for the protected profile unless it is an explicit exception.
6. Ensure no second system VPN is expected to run concurrently.

## Acceptance test

With NOVA connected:

- browsing and apps work;
- the configured DNS is the NOVA gateway;
- no direct IPv6 path is present in the default fail-closed IPv6 design.

From Oracle Console/out-of-band management:

```bash
sudo systemctl stop nova-awg.service
```

The Android device must lose Internet connectivity rather than fall back to Wi-Fi/mobile data directly.

Restore:

```bash
sudo systemctl start nova-awg.service
```

For anonymous browsing, keep the outer NOVA connection active and use **Tor Browser**. Do not replace Tor Browser with an ordinary browser pointed at a raw SOCKS proxy and call it equivalent.

Android generally exposes one system VPN slot per user, so system-wide NymVPN and system-wide AmneziaWG are separate operating modes rather than simultaneously stacked VPN apps.
