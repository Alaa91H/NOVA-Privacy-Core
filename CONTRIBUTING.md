# Contributing

NOVA is a security-sensitive networking project. Every change must be reviewed for failure behavior, metadata exposure, and rollback.

Before a change merges, answer:

1. What metadata does it create?
2. Who can observe it?
3. Is it persisted?
4. Does it open a new socket?
5. Can failure bypass the kill switch?
6. Can it leak DNS or IPv6?
7. Does it weaken TLS/ECH?
8. Does it add a third party?
9. Can it run with less privilege?
10. How is rollback tested?

Run:

```bash
./tests/run.sh
./scripts/security-audit-static.sh
```

Experimental transports must remain feature-gated.
