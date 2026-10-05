# NOVA Privacy Core

Security-first, zero-trust privacy gateway for constrained self-hosted servers.

> Bootstrap commit. Full implementation is developed on a dedicated implementation branch and merged only after validation.

## Security model

NOVA Privacy Core assumes the access network, ISP, hosting network, DNS infrastructure, and intermediate networks are untrusted. It uses fail-closed routing, per-device keys, strict firewalling, privacy-preserving DNS policies, and optional client-originated anonymity paths.

The project does **not** claim mathematical untraceability or that a datacenter IP can be made indistinguishable from a residential IP.
