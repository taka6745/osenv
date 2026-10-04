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

Python 3.12+; no Python runtime dependencies. Optionally install the console
command with `python3 -m pip install -e .`. Operations use the current project
directory, or `OSENV_ROOT`. Run fixture builds from this checkout or a project
containing the fixture sources. `run --manual --image ...` can inspect another
raw BIOS image without rebuilding it; pass its ELF with `--symbols`.

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
