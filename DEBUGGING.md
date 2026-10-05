# Inspecting a running OS

The host debugger operates independently of the guest. It can stop a broken
kernel, read/write accessible virtual memory and registers, inspect physical
RAM, use symbols and typed GDB expressions, breakpoint code, watch memory,
inspect emulated devices and capture evidence. It retains its connection so
inspection never implicitly resumes the CPU.

Modes: `real16`, `protected32`, `long64`. QEMU's x86-64 register packet layout
stays constant across modes; ELF class must not override it. NASM disassembles
bytes read through GDB at the selected instruction width and guest address.
Pass `--mode` when the guest transitions. ELF symbols must be linked at the
actual load address. `debug add-symbols --symbols path.elf --address TEXT_ADDR`
adds and records another ELF at its actual text address, so boot stages and a
kernel can coexist. ELF data/bss section relocation beyond its linked addresses
is not yet configurable.

```sh
osenv run --manual --image build/os.img --symbols build/kernel.elf --mode long64 --paused --timeout 120
osenv debug RUN write-register --value '$rax=0x1234'
osenv debug RUN write-memory --address 0x100000 --value cafebabe
osenv debug RUN watchpoint --address 0x100000
osenv debug RUN resume
osenv debug RUN breakpoints
osenv debug RUN evaluate --value '*(struct thread *)current_thread'
osenv inspect RUN
osenv physical-memory RUN --address 0x1000 --length 4096
osenv trace RUN --events guest_errors,int,cpu_reset
osenv logs RUN --stream trace
osenv artifacts RUN --file capture-001/memory.bin --hex --cursor 31738 --limit 16
```

Watchpoints persist until deleted or the owner exits. `breakpoint` adds a code
breakpoint and resumes to it; status includes GDB's stop notification. Writes
can change guest behavior; every request is saved in the run's action log.
Backtraces are only as good as frame/unwind information. Unmapped virtual memory,
absent symbols and unsupported QMP operations return explicit errors.

Guest output and host annotations are separate readable streams. `serial` writes
to the guest's UART input; `annotate` appends structured host diagnostic records.
This does not silently mutate a guest filesystem log. Physical RAM dumps and
retained overlays expose the underlying state when the guest cannot respond.

The current fixtures speak `OSE1`: `BOOT`, `LOG`, `READY`, `RESULT id=1 value=42`,
`DONE`, `PANIC vector=6` and `HANG`. Commands are `1P\n` (arithmetic assertion),
`1F\n` (#UD), `1H\n` (hang), `1R\n` (reset), `1B\n` (bad result), `1W\n` (wrong
exit). The external gate requires ordered completion records, the host assertion,
debug-exit status 33 and no unexpected reset/panic. A PASS string is insufficient.

## Kernel debug build interface

As kernel services are added, compile a diagnostic endpoint into the debug
build and leave it out of release builds. It belongs to the kernel, not an
external guest agent. Expose a versioned serial command/result protocol with
request IDs, explicit capabilities, bounded replies, cursor-based logs and
typed errors. Preserve host QMP/GDB fallback when the endpoint hangs.

Subsystem capabilities should cover CPU/interrupt state, address spaces/page
tables/allocators, threads/scheduler/locks, driver queues/DMA, disks/files/open
handles, sockets/routes/packet counters, timers and invariant checks. Enable
named fault injection and invariant checks in debug builds. Keep mutation
separate from inspection and acknowledge writes externally. These semantic
interfaces are requirements for the future OS, not implemented kernel services.

## Homelab validation

Keep `{"ssh_host":"your-authenticated-alias"}` in ignored `local/deploy.json`.
The SSH host needs Python 3.12+, QEMU, GDB and NASM. Deployment uploads hashed
prebuilt fixtures and the controller, runs dedicated 32 MiB QEMU TCG VMs, then
retrieves raw evidence. It does not alter existing Proxmox VM definitions. Host
capacity and authentication should be discovered before deploying. The current
remote directory is project-owned under `/var/lib/vz/osenv-harness/`; a configurable
non-Proxmox destination is future work. Runtime versions and firmware hashes
are recorded separately from build versions.

## oslab integration

Complete `OSL1 PANIC` records trigger raw capture like the fixture protocol.
Incomplete UART records do not prematurely freeze exception printing. Use the
kernel ELF for long-mode symbols and add stage1/stage2 ELF symbols at 0x7c00/0x8000
for boot debugging. The OS exposes DHCP/DNS/HTTP commands and network/page counters;
GDB/QMP still inspect registers, memory and DMA without a working guest endpoint.
The driver uses receive IRQ wakeups and bounded single-CPU DMA-ring draining;
no scheduler/process/filesystem inspection
is claimed. `--network internet` opts into live outbound NAT and disables icount
fast-forwarding. The default OS gate uses no Internet.
