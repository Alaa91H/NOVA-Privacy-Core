# Live client acceptance checklist

This checklist cannot be honestly automated from GitHub CI because it must observe the real Android/Windows/Linux endpoint.

For every production peer:

- [ ] visible public IPv4 is the intended protected exit;
- [ ] no ISP DNS resolver is observed;
- [ ] IPv6 is protected or unavailable, never direct;
- [ ] disabling the server tunnel does not restore direct access in a protected/lockdown client configuration;
- [ ] Android Always-on VPN is enabled;
- [ ] Android "Block connections without VPN" is enabled;
- [ ] Wi-Fi to mobile-data transition reconnects safely;
- [ ] sleep/resume does not create a direct-leak window;
- [ ] TOR-ANON uses Tor Browser/client-originated Tor;
- [ ] personal browser cookies are not copied into anonymous profiles.

Record the test date and client OS/version locally. Do not upload identifying network data to public CI logs.
