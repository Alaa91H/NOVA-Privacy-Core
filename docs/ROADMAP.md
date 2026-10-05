# Execution Roadmap

NOVA distinguishes **repository implementation** from **live acceptance**.

## Implemented in repository

- [x] T00 repository bootstrap
- [x] T01 threat model
- [x] T02 architecture specification
- [x] T03 cryptographic policy
- [x] T04 bootstrap automation
- [x] T05 host-hardening automation
- [x] T06 firewall bootstrap
- [x] T07 management-plane policy
- [x] T08 AWG installation/configuration automation
- [x] T09 peer provisioning tooling
- [x] T10 kill-switch policy
- [x] T11 IPv6 fail-closed default
- [ ] T12 network-namespace isolation — live-gated; service/process isolation is implemented, but namespace routing is not enabled without Oracle-host validation
- [x] T13–T18 DNS/filtering/enforcement implementation
- [x] T19–T21 client deployment guidance
- [x] T22 peer lifecycle automation
- [x] T23 policy-profile engine
- [x] T32 logging-minimization policy
- [x] T33 zram/memory baseline
- [x] T34 service sandboxing baseline
- [x] T35 privacyctl control plane
- [x] T36 static and live verification tooling
- [x] T37 encrypted backup/restore implementation
- [x] T38 supply-chain checks
- [x] T39 CI/release pipeline
- [x] T40 host-audit automation (live result still gated)
- [x] T41 guarded failure-injection automation (physical-client observation still gated)
- [x] T24–T30 capability/acceptance probes documented without false-positive "pass" states

## Feature-gated / live validation

These require a target Oracle kernel, external prerequisites, or physical clients and must not be marked “passed” merely because configuration exists:

- [ ] T08 AWG kernel/client interoperability on target VPS
- [ ] T09 first real peer handshake
- [ ] T10 forced tunnel-failure client verification
- [ ] T11 physical-client IPv6 leak test
- [ ] T12 network-namespace routing/isolation validation on the target host
- [ ] T19 Android lockdown validation
- [ ] T20 Windows network-change validation
- [ ] T21 Linux production validation
- [ ] T24 MASQUE current implementation gate
- [ ] T25 verified PQ/T handshake negotiation
- [ ] T26 ECH client/destination validation
- [ ] T27 NaiveProxy fallback benchmark
- [ ] T28 Hysteria 2 fallback benchmark
- [ ] T29 Tor profile live test
- [ ] T30 Nym/mixnet feasibility benchmark
- [ ] T31 separated zero-trust DNS evaluation
- [ ] T37 clean-host restore rehearsal
- [ ] T40 final host audit
- [ ] T41 failure injection
- [ ] T42 performance tuning
- [ ] T43 Android production acceptance
- [ ] T44 laptop production acceptance
- [ ] T46 release-candidate freeze
- [ ] T47 soak test
- [ ] T48 v1.0.0 release

No live box is available through this repository itself; those boxes remain intentionally unchecked until observed.
