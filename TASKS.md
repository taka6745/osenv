# Tasks

T001 — Goal: make the first harness milestone externally testable. Interface:
one JSON CLI using QMP, persistent GDB/MI and UART. Prerequisites: pinned local
toolchain, software QEMU and authenticated remote host tooling. Acceptance:
one command builds/boots, observes text, asserts a value, diagnoses #UD, captures
a hang and recovers; deliberate defects fail; evidence survives capture failure;
VMs and sockets stay isolated. Result: implemented and locally tested. Exact
16-bit boot/fault/hang/reset/recovery and 32/64-bit debug fixtures homelab verified.
The full OS, subsystem debug endpoints, validated record/replay and SMP are pending.
