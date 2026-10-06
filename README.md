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
fixture is substituted. Optional `--machine-code --machine-http` selects oslab’s
separate authored opcode implementations and their protected-page/oracle tests.
Build configuration participates in the immutable build identity; readable and
raw-byte debug images cannot reuse each other’s manifest. `project-test --project ../oslab` verifies full BIOS disk
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

Repeated production boot/load comparisons (no guest markers needed):

```sh
python3 -m osenv.perf_bench --image build/oslab-prod/oslab.img --symbols build/oslab-prod/kernel.elf --output local/perf-new --repeat 3 --requests 5000 --nic-model e1000e --no-nic-rom
# Add --compare-image OLD.img --compare-symbols OLD.elf for alternating matched runs.
```

The controller prepares forwarding while paused, then measures resume-call to
first verified HTTP response separately from full controller launch. Both include
the selected boot route and DHCP; reset timing also includes the control RPC and DHCP
capture polling (1 ms resolution in controlled boot comparisons). Every repetition retains its inputs, hashes,
per-request timings, captures and boundary-test verdict. Output directories must
be new; failed runs cannot become successful aggregate reports.

Measure a named boot milestone without adding guest instrumentation:

```sh
python3 -m osenv.boot_probe --image build/oslab-prod/oslab.img --symbols build/oslab-prod/kernel.elf --breakpoint kernel_main
# Repeat with --breakpoint dhcp_send to include kernel/NIC initialization.
```

This probe uses actual QMP RESUME/STOP timestamps and a GDB breakpoint. It reports
its scope separately from launch/debugger preparation and preserves a stopped
machine capture. A milestone is not an HTTP-readiness result.

Add `--minimal-devices` to perf_bench, boot_probe, web-test or manual IDE runs
for a headless server: it disables unused default devices and VGA while retaining
explicit disk, UART/debug-exit, QMP/GDB and NIC devices. This is an optional,
recorded machine configuration, not a change to guest code or firmware timers.
Reproduce/recover preserve it. Fixtures and floppy boot do not support this mode.

Optional authored PVH entry uses `--boot-kernel BUILD/pvh.elf` in `run`,
`web-test`, `web_stress`, `perf_bench` and `boot_probe`. The adjacent
`pvh-inputs.json` must hash the supplied loader, complete disk image and symbols.
Preload builds also require their hashed `kernel.bin`; QEMU loads it without
changing the CPU entry point. Installed `qboot.rom` is mandatory and hashed.
The recorded routes are `bios-disk`, `pvh-qboot` and `pvh-qboot-preload`.
PVH bypasses the BIOS disk chain; the complete disk acceptance gate remains required.
Reproduce/recover retain and revalidate these inputs. For alternating comparisons,
pair `--compare-image`/`--compare-symbols` with optional `--compare-boot-kernel`;
omitting that last flag selects BIOS for the comparison image.

```sh
python3 -m osenv.restore_probe --image BUILD/oslab.img --symbols BUILD/kernel.elf --repeat 5
python3 -m osenv.clock_probe --image DEBUG/oslab.img --symbols DEBUG/kernel.elf
python3 -m osenv.pvh_test --image DEBUG/oslab.img --symbols DEBUG/kernel.elf --boot-kernel DEBUG/pvh.elf --report local/pvh-boundaries.json
```

`restore_probe` saves paused QCOW2 state, deliberately changes real RAM, then
requires restored bytes and an exact complete response from an independent HTTP
client. The owner's bounded snapshot operation accepts only paused save/load and
validated tags; raw results and hashes remain in each run. This measures warm
restoration, including control/client costs, rather than cold boot.
`clock_probe` checks HPET-derived time after forced lost software ticks;
`--defect` must fail. `pvh_test` injects malformed inputs into the real authored
adapter and verifies halt addresses, memory boundaries and actual copies.
Packet service intervals report capture request-to-response time separately from
full client latency. None establishes physical cycles or homelab completion.


`raw-build --project ../oslab --output build/raw` places the OS repository's
literal hex bytes and fixed-width address fields without invoking a guest
compiler, assembler or linker. It snapshots inputs, verifies ranges/overlaps,
records padding and hashes, and writes real disk bytes plus ELF symbol containers.
`raw-test --build build/raw --output local/raw-checks` exercises that actual image:
corrupt/truncated boot, absent NIC, CPU fault/hang recovery, guarded primitive
execution, real DMA/IRQ behavior, malformed protocol boundaries and both NIC wire
paths. The fixture gate remains separate. Optional individual `osenv.raw_*_test`
modules retain failures and isolated deliberate mutations. Raw guest service
limits are described in the OS checkout; host inspection invents no guest services.

Literal images exposing `nic_tx_buffer` also run the actual DMA ownership,
in-place padding/guard/wrap and packet-content oracle during `raw-test`.
`python3 -m osenv.raw_tx_test --build BUILD --output NEW.json` runs it separately;
add `--checksum-cache` for the implemented static-response cache interface, or
`--ownership-mutant` to prove a RAM-only missing ownership check is rejected.
Missing guest interfaces fail explicitly. Mutants are restored and never shipped.
`raw_queue_test --build BUILD --output NEW.json` checks the actual deferred-SYN
interface, malformed inputs, old connection preservation and full response;
`--queue-mutant` proves publication failure is detected. `raw_offload_test` checks
actual context/data ownership, seeds, padding fallback and descriptor bounds;
`--mutant` tests missing TXSM. Final wire insertion remains a separate NIC gate.

`python3 -m osenv.peer_bench --image IMAGE --symbols ELF --output NEW_DIR`
measures fresh, complete five-frame guest TCP exchanges through an owned packet
stream. Optional `--compare-image`/`--compare-symbols` alternate matched variants;
both routes may specify their PVH loaders. Every response and captured checksum,
sequence and FIN acknowledgement is checked. Construction/oracle costs are saved.
This separate cooperative-client backend must not be compared directly with NAT
benchmarks or physical line rates.
`--native-checksum` builds the authored host-only C helper, verifies20,000 seeded
vectors and records compiler/source/binary provenance. Select an installed host
compiler with `--checksum-compiler /usr/bin/cc`; otherwise configured Clang is used.
`--defer-http-oracle` checks a fully parsed warmup response byte-for-byte inline
and parses every captured response after load. Independent Python capture checks
remain mandatory before success. Both variants use the same options and helper.


Add `--packed` to `raw-build` for the authored bounded decoder and optimal
literal/back-reference stream. `raw-size --build BUILD --output NEW_DIR`
reconstructs saved sources and every disk byte, checks hashes/symbols/BSS and
recomputes the complete suffix-cost certificate. Expanded kernel bytes, ELF
containers and reserved BSS are accounted separately from disk storage. The
accepted T022 image is 8,192 bytes / 65,536 bits: 512-byte BIOS sector,
187-byte adapter, 7,438-byte optimal stream and 55-byte sector fill. This is a
proved minimum for this fixed kernel, codec grammar, adapter and sector layout;
a global shortest executable remains unproved.

Boot timing now uses integer host-epoch QMP RESUME to independently verified
complete client receipt, with paired monotonic samples and rejection of clock
drift, resets or stops. QEMU packet captures use a virtual clock and are never
subtracted from QMP epoch timestamps. Controller launch, CPU release, kernel
entry, network-loop entry and completed HTTP remain distinct measurements;
physical power-on is unmeasured.

The exact T022 image passed local raw/decoder gates and dedicated homelab QEMU
acceptance. Five matched local TCG runs returned 50,000 verified responses at
6,680.7 requests/s; median CPU release to complete HTTP was 53.543 ms. Separate
breakpoint runs measured 48.605 ms to raw_entry and 50.238 ms to raw_loop. These
are emulator measurements, not physical throughput. Saved evidence remains in
local/t022; TASKS.md records the accepted image identity and test scope.


Agent experiments use `experiment --plan PLAN.json --output NEW_DIR`. A plan has
`hypothesis`, `baseline`, `candidates`, `repeat` (3–9), `requests` (100–30,000)
and `seed`; each variant has unique `name` and actual `build`, optionally
`boot_kernel` and numeric `expected_bar`. The runner checks actual sources,
artifacts and identical website bytes, runs integrated/decoder/direct-entry gates,
then serializes alternating trials under a measurement lock. It retains frozen
harness source, failures and seeded paired bootstrap intervals. A throughput
interval crossing1 is inconclusive; fewer instructions are not a speed claim.

```sh
python3 -m osenv raw-build --project ../oslab --output build/raw-pvh --packed --pvh
python3 -m osenv.raw_pvh_test --build build/raw-pvh --report local/direct.json --expected-bar 0xc0000000
python3 -m osenv experiment --plan local/plan.json --output local/trial
python3 -m osenv parallel-probe --build build/raw-pvh --output local/capacity --replicas 4 --clients 1 --requests 512
python3 -m osenv.restore_probe --image build/raw-pvh/oslab.img --symbols build/raw-pvh/kernel.elf --mode resume --repeat 5
```

`parallel-probe` verifies actual full responses and post-load recovery, retaining
failed requests. Its replicas are separate one-vCPU VMs without affinity; it
implements neither guest SMP nor concurrent connections. Resume retains a paused,
powered service. Snapshot mode additionally restores deliberately changed RAM;
neither proves arbitrary external peer, lease or clock recovery after suspend.

Explicit `--acceleration kvm` is available in `run`, `web_stress` and `perf_bench`.
It requires manual realtime execution on Linux x86-64 with accessible `/dev/kvm`;
unsupported configurations fail without falling back. Default fixture and
deterministic gates remain one-CPU TCG. KVM and TCG series cannot be mixed.
The literal `raw-build --pvh` path stores disjoint authored segments, with no
executable bytes imported from qboot; firmware remains hashed host infrastructure.


Full raw memory captures retain their filenames, lengths and SHA256 hashes while
zero blocks are stored as sparse holes. Every rewrite verifies bytes before atomic
replacement; failure leaves the original dump and marks capture incomplete.
`memory-storage.json` records logical and allocated sizes. This reduces capture
storage, never guest memory or image size, and does not remove evidence.

Linux host profiling attaches only to a verified live owned QEMU process:
`python3 -m osenv.host_perf --run-id RUN --seconds 3 --output NEW_DIRECTORY`.
Default hardware events use `:H` to exclude KVM guest execution; software events
count host process scheduling. `--counter-scope guest` uses `:G`, requires actual
KVM and positive observed cycles/instructions, and retains the software events'
host scope. These filtered samples are not physical-board cycle measurements.
Existing QEMU task identities must remain stable throughout the sample.
`--kvm-exits` additionally requires an already readable `kvm:kvm_exit` tracepoint;
missing tracefs, events, permissions or PMU support fail explicitly. No mounts,
sysctl changes or installations occur. `--perf-executable /absolute/path/perf`
selects an installed/extracted tool; command/version/binary provenance, raw output
and counter running percentages are retained. Run profiling separately from
timing acceptance. Guest build provenance and harness source hashes have distinct
scopes; packet comparisons retain verified raw source snapshots before launch.
