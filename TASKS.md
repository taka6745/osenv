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

Homelab follow-up: authenticated SSH recovered. Exact 16 KiB default production
image passed the peer wire gate and 1,000 response/boundary/timeout stress gate
in dedicated homelab QEMU. Exact PVH image passed the peer gate with the recorded
local qboot firmware in a project-owned remote runtime; no global host installation.
The first remote peer failure was queued identical retransmissions, all captured
before the zero-window ACK. Peer handling now verifies known duplicate bytes and
rejects new sequence space/FIN while closed; a GDB RAM window-overwrite defect
was rejected with full capture. Full 18-check controller gate/30 tests passed
again. Raw failures, mutation actions, firmware/tool hashes and remote evidence
remain in local/t019; these are QEMU acceptance, not physical performance.

T020 — Goal: externally verify and compare readable and hand-encoded OS variants.
Interface: existing real-image gates/perf_bench, raw opcode/relocation inspection
and retained host protected-page/oracle/mutation evidence.
Prerequisites: matching authored sources, symbols, build/image hashes and machine.
Acceptance: actual boot/HTTP/fault/IRQ/loader bounds and deliberate opcode defects;
paired repeated service/reset timing, size accounting and homelab exact-image gate.
Provenance: no guest or external source imported; all artifacts stay here ignored.
Results: both real OS 16-case gates and the 18-check/30-host-test harness gate
passed. Exact production BIOS and corrected PVH homelab wire/1,000-request
checks passed; source/hash/tool/firmware evidence retained outside Git. Caught
raw +142 short-branch and source/stack-copy defects; compile-time signed checks
and three real overlap regressions now reject them. Build flags participate in
identity and explicitly select raw headers. Production TCG throughput remains
comparable; 45.1% fewer debug/no-LTO dispatches are not physical cycles/cache.
Reports/graphs/rejected attempts remain in local/t020 and sibling evidence dirs.


T021 — Goal: build and inspect an entirely hand-encoded OS without guest compilation.
Interface: raw-build/raw-test JSON CLI; external byte placement/fixups, separate
ELF symbols and CPU-mode ranges, immutable source snapshots and real-image gates.
Prerequisites: literal project-authored byte sources, pinned QEMU, actual CPU/NIC
and independent packet peer. Acceptance: reject malformed byte fields and branch
overflow; actual full BIOS boot, guarded execution, DMA/IRQ/clock, network faults,
CPU faults/hangs and preserved cold recovery; matched performance and homelab.
Provenance: Python standard library, existing authored controller/oracles; no
instruction generation, guest stubs or extracted compiled implementations.
Results: actual complete raw image boot/clock/primitive/DMA/IRQ/network/both-NIC
gates passed locally and on dedicated homelab QEMU; exact image/symbol hashes
matched. Homelab also passed 1,000 responses, boundaries and timeout recovery.
Literal placement rejects BSS/code aliases, overlapping state, address overflow,
bad fields and branch overflow; regression tests cover actual failures.
Acceptance refuses optimized Python assertions. Peer wall-time loss/window
probes now use realtime guest clocks; virtual-clock deadline expiration remains
captured as a diagnosed experiment, with unchanged assertions and guest deadlines.
Matched 30,000-response measurements, independent dispatch counts, compression
round trips and graphs are retained in local/t021 and t021-instructions.

T022 — Goal: deterministic raw-image bit accounting and honest boot/service timing.
Interface: raw_size saved-source reconstruction; integer QMP/client clock intervals.
Prerequisites: immutable build sources, actual disk bytes and matching test verdicts.
Acceptance: complete byte provenance and constrained minimum proof, corrupted
input rejection, distinct controller/CPU/client clocks, unchanged actual-image
gates, matched measurements and exact-image homelab.
Provenance: independent standard-library codec/accounting/clock logic from the
authored oslab format; no external guest implementation imported.
Results: exact image afef5c6cb0699f307bad28bc618c10432aca194afc2d3daa2b151c94b868437e
passed local raw/decoder gates and dedicated homelab QEMU acceptance. Its 8,192
bytes / 65,536 bits comprise BIOS512 + adapter187 + optimal stream7438 + fill55.
Recomputed full DP certificate proves the codec-family minimum for this fixed
kernel/adapter/sector layout; global shortest-program minimum remains unproved.
Host regressions reject corrupted streams, certificates, manifests and clock
intervals; source audits passed. Five matched local TCG runs verified 50,000
responses at 6680.7 RPS and 53.543 ms median CPU-release-to-complete-HTTP.
Separate QMP breakpoint probes measured raw_entry 48.605 ms and raw_loop 50.238 ms.
PCAP virtual time is kept separate from host epoch/monotonic time; physical
power-on and physical throughput are unmeasured. Evidence: local/t022.

T023 — Goal: bounded agent experiments for boot, instruction/layout, network and
parallel capacity. Interface: experiment JSON plan, raw-build --pvh, actual
PVH gates, resume/snapshot/parallel probes and explicit realtime KVM selection.
Prerequisites: exact authored OS sources/images, owned VMs, fixed seed/config;
KVM additionally Linux x86-64 and accessible /dev/kvm, otherwise explicit failure.
Acceptance: actual source/body/hash matching, integrated/decoder/direct gates,
serialized alternating runs, retained failures/source snapshots/paired intervals;
capacity counts errors and verifies recovery, warm probes verify real RAM/HTTP.
Implemented using Python standard library and documented QMP/ELF/Xen interfaces;
all literal guest bytes stay in oslab. Three low-context agents investigated
boot, checksum/page layout and packets. Host regressions, actual fixture gate,
raw OS/decoder gates,19 PVH boundaries and a rejected magic-check mutant passed.
Warm resume median3.038ms and snapshot9.960ms include control/RAM/client costs.
Separate VM capacity:1/2/4 replicas4467/6256/6117 verified aggregateRPS;2 clients
on one VM2568RPS, all128 replies correct. No guest SMP/affinity claim.
Exact release disk2c226df8...097d and PVH07e285d7...4218 passed homelab full raw,
decoder,19 direct boundaries and1000-response stress on each boot route.
Three matched KVM5000-response runs per route:12.820ms direct cold full HTTP
versus20.316ms BIOS;4043 versus3984 RPS, no general throughput-win claim.
Disk exhaustion interrupted one local final experiment; it remains failed.
Verified sparse rewrites freed15GiB without changing capture bytes/hash/length;
new capture storage runs that verification before atomic replacement and passed
actual boot/debug/fault/recovery plus dense/zero/tail/missing-file regressions.
Release validation uses external local/t023; frozen source and exact-head CI
verdicts stay separate from cold entry, powered state and physical power-on.
