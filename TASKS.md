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
