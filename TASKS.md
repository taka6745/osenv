# Tasks

T001 — Goal: make the first harness milestone externally testable. Interface:
one JSON CLI using QMP, persistent GDB/MI and UART. Prerequisites: pinned local
toolchain, software QEMU and authenticated remote host tooling. Acceptance:
one command builds/boots, observes text, asserts a value, diagnoses #UD, captures
a hang and recovers; deliberate defects fail; evidence survives capture failure;
VMs and sockets stay isolated. Result: implemented and locally tested. Exact
16-bit boot/fault/hang/reset/recovery and 32/64-bit debug fixtures homelab verified.
The full OS, subsystem debug endpoints, validated record/replay and SMP are pending.

T002 — Goal: separate OS source from harness and enforce source integrity.
Interface: standalone module CLI, `audit --repo PATH [--os-only]`, mandatory
INTEGRITY.md contracts in both projects. Prerequisites: project-authored source,
stdlib runtime, external compiler/emulator/debugger executables. Acceptance:
no harness/fixtures in oslab; archived evidence retained; no package dependencies;
audit rejects deliberate stubs/imports/dependency declarations; guest formats its
computed result and rejects unknown commands; full VM gate and exact-image remote
validation. Provenance: source authored here; toolchain probe moved from our own
oslab; specifications referenced in README, no upstream source imported.
Result: source audits pass; six host regressions (including deliberate policy
violations), all 18 local VM gate cases and toolchain smoke pass. Updated exact
fixture image and both CPU-mode fixtures passed seven homelab checks. OS
implementation remains absent. CI verification is reported by the commit status.

T003 — Goal: control and externally accept actual OS builds and Internet runs.
Interface: project-build/test/deploy, explicit internet NIC mode, full-line OSL1
panic detection and independently reassembled pcap evidence. Prerequisites:
oslab Makefile/authored guest sources, pinned host tools and private SSH alias.
Acceptance: source/host mutation checks, full custom-disk OS gate, repeated live
requests matching wire bytes/hash; exact-image remote gate; fixture gate unchanged.
Provenance: controller changes authored here; guest code maintained in oslab;
no external library or implementation source imported. Result: OS and harness
checks locally pass; diagnostic image also homelab verified. Final commit
verification is reported by CI status, separate from release acceptance.


T016 — Goal: lower boot latency and verify minimum TCP exchange cost.
Interface: external packet counts and staged real-image timing. Prerequisites:
T015 release, full disk boot, independent packet peer. Acceptance: graceful
five-segment exchange, unchanged normal-client behavior, repeated boot evidence.
Provenance: RFC 9293 and emulator/firmware documentation; no code imported.
Result: production/debug peers passed; independent pcap confirms five frames
with ACK+GET+FIN and data+ACK+FIN. Ordinary socket/NAT clients still use eight.
Added strict boot/DHCP/TCP capture analyzer; 15 unit tests and harness gate passed.
Three actual BIOS-to-first-DHCP-send breakpoints measured 68.61, 68.63 and
69.59 ms, excluding host preparation/DHCP/debugger setup. Full service readiness
remains about 1.5 s: the emulator blocks RX for one second after RCTL writes.
No emulator timer bypass or acknowledgement removal. Our shared guest driver
now supports 82574 legacy DMA/PIC. Four matched final-image runs: e1000
1527/1523 ms and 1210/1192 req/s; e1000e 520/530 ms and 914/900 req/s. Keep
e1000 default for throughput; e1000e is optional. Both production/debug wire
peers and actual 82574 IRQ rearming passed, along with exact-image codec and
integrated OS gates. Reproduced actual VM preserved image/NIC/clock settings.
