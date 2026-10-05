# Execution Roadmap

NOVA distinguishes **repository implementation** from **live acceptance**.

## Implemented in repository

- [x] T00 repository bootstrap
- [x] T01 threat model
- [x] T02 architecture specification
- [x] T03 cryptographic policy
- [x] T04 Ubuntu 26.04 bootstrap automation
- [x] T05 host-hardening automation
- [x] T06 firewall bootstrap
- [x] T07 management-plane policy
- [x] T08 AmneziaWG userspace installation/configuration automation
- [x] T09 peer provisioning tooling
- [x] T10 kill-switch policy
- [x] T11 IPv6 fail-closed default
- [ ] T12 network-namespace isolation — live-gated
- [x] T13–T18 DNS/filtering/enforcement implementation
- [x] T19–T21 client deployment guidance
- [x] T22 peer lifecycle automation
- [x] T23 policy-profile engine
- [x] T24–T30 optional capability/acceptance probes without false-positive pass states
- [x] T32 logging-minimization policy
- [x] T33 dynamic zram + ephemeral encrypted swap
- [x] T34 service sandboxing baseline
- [x] T35 privacyctl control plane
- [x] T36 static/live verification tooling
- [x] T37 encrypted backup/restore implementation
- [x] T38 supply-chain checks
- [x] T39 CI/release pipeline
- [x] T40 host-audit automation
- [x] T41 guarded failure-injection automation
- [x] T49 fail-closed deployment activation gate
- [x] T50 automatic Ubuntu/kernel/application maintenance
- [x] T51 provenance-verified NOVA self-update
- [x] T52 bounded periodic cleanup
- [x] T53 Ubuntu 26.04/OCI kernel detection and selection
- [x] T54 userspace-first AWG mitigation for current kernel-7.0 regressions

## Live validation still required

- [ ] real AWG userspace server/client interoperability on target Oracle VPS
- [ ] first real management peer handshake
- [ ] forced tunnel-failure client verification
- [ ] physical-client IPv6 leak test
- [ ] network-namespace routing/isolation validation if T12 is enabled
- [ ] Android lockdown validation
- [ ] Windows network-change validation
- [ ] Linux production validation
- [ ] MASQUE interoperability
- [ ] verified hybrid PQ/TLS negotiation
- [ ] ECH validation
- [ ] NaiveProxy benchmark
- [ ] Hysteria 2 degraded-network benchmark
- [ ] Tor profile live test
- [ ] Nym/mixnet feasibility benchmark
- [ ] separated zero-trust DNS evaluation
- [ ] clean Ubuntu 26.04 restore rehearsal
- [ ] automatic system/kernel update + reboot + post-boot reopen test
- [ ] automatic NOVA release-update test
- [ ] final host audit
- [ ] failure injection
- [ ] 1GB RAM/CPU/latency/throughput tuning
- [ ] Android production acceptance
- [ ] laptop production acceptance
- [ ] release-candidate freeze
- [ ] soak test
- [ ] v1.0.0 release

Repository CI must never mark these live gates passed merely because scripts/configuration exist.
