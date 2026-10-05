# Linux Client

Linux supports the most advanced NOVA endpoint isolation.

Baseline:

- one unique AmneziaWG peer;
- full tunnel;
- DNS through NOVA;
- fail-closed local firewall policy.

Advanced optional design:

- network namespace for anonymous applications;
- client-originated Tor/Nym;
- policy routing for explicitly separated application groups.

Complexity is not a privacy feature by itself. Add namespaces/routes only when their trust boundary and failure behavior are tested.

## Verification

Inspect:

```bash
ip route
ip -6 route
resolvectl status 2>/dev/null || true
ss -ntup
```

Then intentionally stop the protected tunnel and confirm that the local firewall blocks egress.
