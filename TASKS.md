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


T017 — Goal: identify actual OS instruction/idle/serving bottlenecks.
Interface: optional authored host QEMU plugin, ELF range input and CSV phase output.
Prerequisites: installed QEMU 11 SDK, one CPU, real profile-enabled OS image.
Acceptance: real idle/load runs, independent counter agreement, invalid-install
rejection and existing controller gates. Provenance: QEMU plugin API and Intel
optimization manual; no imported guest source or linked third-party libraries.
Result: inline/callback counts agree in all five phases before/after tuning;
unsupported CPU count, absent marker and existing output are rejected. Real
images verified 110,000 production responses. Dispatches/request 53402→12692;
final 6474 requests/s, median 143 µs, p99 231 µs, 12,800-byte image. Actual wire,
boot/fault/recovery and decoder gates passed; harness 18 gates, 15 unit tests,
source audits and deliberate copy/checksum mutants passed. Optional plugin SDK
is host-only; default controller needs no new dependency. Graphs/raw data remain
local outside oslab. No physical cycle/cache or homelab completion claim.

T018 — Goal: reproducible reset-to-serving and repeated performance comparisons.
Interface: controlled paused boot with forwarding prepared before resume; benchmark CLI.
Prerequisites: real production disk/ELF, pinned QEMU, independent HTTP verification.
Acceptance: repeated actual boots/load, explicit measurement scopes, unit/controller gates.
Provenance: existing authored stress controller; Cloudflare startup documentation.

Result: controlled reset-to-HTTP median 73.4 ms on supported 82574/no PXE ROM,
full controller launch ~550 ms; QMP kernel/DHCP milestones 61.6/64.4 ms.
Matched comparisons rejected checksum caching and a larger polling budget.
Fixed failed breakpoint insertion so it cannot resume the CPU; following valid
breakpoints no longer inherit stale MI errors. Actual query-status verifies
paused-on-failure; the live debugger gate now covers failure then valid recovery.
Real repeated HTTP comparison, successful probes and missing-symbol failure,
18 controller gates, 21 unit tests and audits passed. Guest bytes unchanged;
no Cloudflare-equivalent or physical-board performance claim.

Headless machine follow-up: explicit external minimal-devices mode removes unused
default devices/VGA. Same complete BIOS/disk/DHCP path and exact guest image:
three native runs, 15,000 verified responses; reset-to-HTTP 58.7–60.9 ms,
full controller launch 524–545 ms, 6369 requests/s, median 147–149 µs,
p99 210–242 µs. Real loss/window/wrap/checksum and five-frame wire gates passed.
Machine configuration is recorded and preserved by reproduce/recover. External
18 controller gates, 22 unit tests and source audits passed. Physical timing
and a matched Cloudflare comparison remain unverified.

T019 — Goal: measure unconventional cold entry and independently verified restore.
Interface: hash-bound optional PVH/qboot loader, paused snapshots, clock probe,
peer setup before resume and packet-capture serving intervals.
Prerequisites: authored real OS/ELF/provenance, pinned firmware/emulator, T018 gates.
Acceptance: native loader/HTTP, actual RAM restore/body equality, lost-tick mutant,
failed/tampered loader rejection, reproduction, full controller and source gates.
Provenance: QEMU snapshots/generic loader, Xen PVH, Intel HPET; no external source.
Result: four alternating three-run variants verified 120,000 actual responses
using the same final production disk hash. BIOS median resume-to-HTTP 59.23 ms;
PVH 21.52 ms in that comparison. A second matched comparison measured PVH
20.26 ms versus preload 20.05 ms, with throughput ratio 0.9985; preload has no
established material advantage. These include RPC and 1 ms DHCP observation.
Controller launch remains 462–519 ms for PVH; steady full-client median ~145 µs,
captured request-to-response median 20–21 µs. Snapshot restoration independently
restored mutated RAM and exact HTTP in five runs: load 6.08–6.86 ms, checked
restore through HTTP 10.58–11.21 ms. The <1 ms goal remains unmet.
Real lost-tick clock check recovered to HPET with zero observed lag; deliberate
sampling defect lagged 535 ms and failed with full capture. Peer launch now
connects before CPU resume, exposing rather than hiding fast-entry races.
All 18 controller checks (including actual snapshot RAM restoration), 30 unit tests,
source audits and nine actual loader boundary cases per variant passed.
Production wire gates passed for BIOS/e1000, BIOS/e1000e, PVH and preload.
Measurements and raw evidence are retained under local/t019. Alternate entry, full BIOS boot, capture service
time and warm restoration have distinct scopes. No homelab/physical-cycle claim.

Exact default 16 KiB production image separately passed 30,000 verified responses:
6671 requests/s, 59.77 ms median reset-to-HTTP, 136–140 µs warm medians and
19 µs captured service median. Saved preload reproduction preserved all hashes
and returned actual HTTP.
HPET-absent production wire gate passed with retained experimental wrapper/actual
QEMU argv; fallback retains PIT missed-tick limitations.
