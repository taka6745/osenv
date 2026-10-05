# osenv

A text-first OS development environment for humans and AI tools. One JSON CLI
builds fixtures, owns QEMU VMs, observes boot, inspects the whole machine, drives
GDB/MI, captures failures and recovers. No guest network or guest agent is needed.

This is an early harness release. It includes small project-authored BIOS test
fixtures, not an operating system. OS-specific process, scheduler, filesystem
and networking inspection will use the kernel's symbols and debug interfaces.

```sh
git clone https://github.com/taka6745/osenv.git
cd osenv
brew install llvm lld nasm qemu gdb
python3 -m osenv doctor
python3 -m osenv test
```

Python 3.12+; standard library only, with no packaging or runtime dependencies.
Use `python3 -m osenv` from this checkout. Operations use the current project
directory, or `OSENV_ROOT`. Run fixture builds from this checkout or a project
containing the fixture sources. `run --manual --image ...` can inspect another
raw BIOS image without rebuilding it; pass its ELF with `--symbols`.
Custom images default to IDE; fixture images use floppy. Override with
`--disk-interface`. Manual observation reports `verified: false`; it never
claims an arbitrary guest has passed a test.

The build gate pins LLVM/LLD 23.1.2, NASM 3.02, QEMU 11.1.2, GDB 17.2 and the
`pc-i440fx-9.2` machine. Homebrew setup installs available releases; doctor fails
explicitly if they drift. Linux can run uploaded prebuilt images with its own
recorded tools; final validation used QEMU 10.1.2, GDB 16.3 and NASM 2.16.03.
That runtime variation is recorded, not claimed to be an identical environment.

```sh
python3 -m osenv run --scenario hang --paused --timeout 120
# Substitute the returned run_id for RUN:
python3 -m osenv debug RUN registers
python3 -m osenv debug RUN memory --address 0x7c00 --length 512
python3 -m osenv debug RUN breakpoint --address 0x7c00
python3 -m osenv debug RUN step
python3 -m osenv debug RUN evaluate --value '$cr3'
python3 -m osenv annotate RUN 'investigating allocator corruption'
python3 -m osenv logs RUN --stream annotations --cursor 0
python3 -m osenv capture RUN
python3 -m osenv recover RUN
```

`run`, `setup`, `deploy` and `test --background` return IDs. `status`, `wait`,
`logs` and `artifacts` inspect them. Exit codes: 0 success, 1 completed failed
verdict, 2 usage/tool/transport error. A launch acknowledgement does not mean
the guest passed; use `wait`. The synchronous integration gate is one command.

Available controls:

- `setup`, `doctor`, `build`, `run`, `wait`, `status`, `stop`, `recover`, `reproduce`
- `debug`: pause/resume, registers/control registers, register writes, memory
  reads/writes, expressions, symbols, backtraces, disassembly, instruction
  stepping, address/symbol breakpoints, hardware watchpoints, breakpoint
  listing/deletion and additional ELF symbol files with load addresses
- `inspect`, `connections`, `physical-memory`, `qmp query-*`, `trace`, `serial`
- `logs` with byte cursors, `annotate` with source/level, `capture`, `artifacts`
- `run --network isolated`, `network-link` and per-run packet capture
- `benchmark --repeat N`, `deploy --config local/deploy.json`

Each VM gets a private socket directory, retained QCOW2 overlay, raw input disk,
ELF symbols, source/image/firmware hashes, tool versions, QEMU arguments, inputs,
actions, logs and external verdict. Panic, reset and timeout capture preserves
logs before trying GDB or dumping RAM. Captures include registers, stack,
instruction-width-correct disassembly, RAM and the fixture's decoded #UD frame.
Capture errors are retained and reported; partial evidence is never discarded.

The local gate tests boot/assertions, real #UD, hang/reset capture and recovery,
bad result and wrong exit rejection, saved-image reproduction, malformed images,
seeded protocol fuzzing, stepping, persistent breakpoints/watchpoints, memory and
register writes, log annotations, isolated NIC/link/pcap controls, concurrent VM
isolation, capture-tool failure, dead-controller recovery and actual 16/32/64-bit
guests. The exact fixtures also passed dedicated homelab QEMU VM checks. Generated
evidence and private host details stay outside Git. See [DEBUGGING.md](DEBUGGING.md).

Deterministic tests use one TCG CPU, clean disks, fixed RTC/input/seed and no NIC.
Boot timings measure fixture process launch to serial READY under TCG; they are
not OS performance claims. Record/replay remains disabled until validated. SMP,
hardware acceleration, non-x86/UEFI targets and guest subsystem tests are future
work, not advertised capabilities.

QMP and GDB behavior follow the upstream [QMP reference](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html)
and [QEMU GDB documentation](https://www.qemu.org/docs/master/system/gdb.html).
The small bounded transport uses Python's standard library. Existing QMP
libraries were considered; no external guest code or driver was imported.

[INTEGRITY.md](INTEGRITY.md) is mandatory. `python3 -m osenv audit --repo PATH`
checks tracked source for external imports, dependency declarations and obvious
placeholder bodies. The integration gate runs this audit too. Toolchain smoke
checks live in `tools/check_toolchain.py`; they are host probes, not OS code.

## Real OS projects

`project-build --project ../oslab` builds the actual guest Makefile into immutable
external build directories, saves source/tool/image/symbol hashes and runs host
sanitizers plus a deliberately disabled checksum-validation mutant. No harness
fixture is substituted. `project-test --project ../oslab` verifies full BIOS disk
boot, real memory exhaustion, #UD/#PF and hang captures/recovery, corrupt/truncated
boot images, isolated DHCP, link down, absent DNS and GDB-injected RX errors.

`project-test --project ../oslab --internet-host example.com` explicitly adds five
real DNS/TCP/HTTP requests. `run --network internet` enables outbound emulator NAT
and wall-clock execution, separate from the isolated deterministic gate.
Independent TCP reassembly compares captured response lengths/hashes with guest
reports, including retransmissions and sequence wrap. Guest code belongs to oslab.

`project-deploy --project ../oslab --config local/deploy.json --internet-host example.com`
returns an ID, uploads the exact image and runs the same gate in dedicated owned
homelab QEMU VMs. Use status/wait/logs/artifacts to retrieve results. Deployments
retain private source/image uploads and raw evidence. The diagnostic OS image is
explicitly labelled; release builds need separate exact-image acceptance.

Run actual OS web stress with `python3 -m osenv.web_stress --image PATH
--symbols PATH --requests 5000`. Add `--profile` only for a guest built with
PROFILE=1. Seeded fragmentation, exact response comparisons, 767/768/769-byte
boundaries, malformed requests and slow-client timeout recovery preserve inputs,
latencies, packet captures and failures in each run. `--timing realtime` (default)
is a throughput experiment; `--timing virtual` retains deterministic icount.
Both keep networking isolated. TCG timings do not establish physical cycles,
cache misses or Raspberry Pi performance.

Test oslab's actual packed boot decoder with `python3 -m osenv.packed_test
--build build/oslab-prod`. This compiles the repository-authored host encoder
with sanitizers, checks short inputs against an exhaustive size oracle, compares
every expanded byte at the real kernel entry, and boots malformed disk images.
Bounds guards, expected halt addresses and full CPU/RAM captures are checked
externally. Fixtures never substitute for these actual OS images.

Web stress also saves connect/send/first-byte/completion samples and independently
reassembled TCP80 wire costs (frames, bytes, ACKs, FIN and retransmissions).
Boot readiness comes from captured DHCP ACK, followed by a complete HTTP reply.
Use `--production` for a release guest; `--no-nic-rom` is an opt-in experiment,
not the default. Captured Ethernet totals exclude physical FCS/preamble/IFG.

`python3 -m osenv.http_interop --image PATH --symbols PATH` checks a real
production response with the standard HTTP client and verifies that deliberate
truncation of that actual response raises IncompleteRead.
`python3 -m osenv.irq_test --image PATH --symbols PATH` requires a full debug
image and checks two real NIC interrupt deliveries, cause clearing and EOI
through GDB. Both retain run evidence and full failure captures.

`python3 -m osenv.boot_wire PCAP` reports captured DHCP timing and actual TCP
frames per connection; rejects truncated captures. Web peer acceptance now
independently verifies a five-frame graceful exchange when the client combines
handshake ACK, request and FIN. Normal socket clients may send additional frames.

`--nic-model e1000e` selects the guest's authored 82574 legacy interface in
`run`, `web-test`, `osenv.web_stress` and `osenv.irq_test`. Default remains e1000.
Saved reproduction/recovery preserves model, timing and ROM configuration.

Optional [host instruction profiling](tools/instruction_profile.md) counts real
QEMU dispatches by ELF symbol; it adds no guest code and is separate from speed tests.
