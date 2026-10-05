# Host instruction profiling

`instruction_profile.c` is an authored, optional QEMU 11 plugin. It uses the
installed emulator SDK; no SDK code is vendored, no guest agent is added, and
normal osenv runs do not require the plugin. Compile as a shared library with
QEMU's include directory and the SDK's `pkg-config --cflags glib-2.0` include
flags. On macOS use `-dynamiclib -undefined dynamic_lookup`; on Linux use
`-shared -fPIC`. Enable exported plugin API symbols and hide other symbols.

Build a real compact debug OS with PROFILE=1. Convert `llvm-nm -S kernel.elf`
text symbols into `hex_address hex_size symbol` records. Pass these arguments:

```
-plugin LIBRARY,ranges=RANGES_FILE,output=NEW_CSV_FILE
```

Only x86-64 system emulation with one CPU is supported; missing `perf_reset`,
invalid input or an existing output file fails installation. Preserve the exact
plugin, ELF/image/source hashes, augmented argv and QEMU version with each run.
The output is CSV: phase, symbol, dispatched_instructions. The independent
callback total must equal the sum of inline symbol counters in each phase.

Each actual `perf_reset` entry snapshots and clears counters. With the current
OS: phase 0 ends during arch_init; phase 1 ends after network/bootstrap; phase 2
is idle; phase 3 is serving if the controller sends another reset immediately
after its load snapshot; the final phase contains later boundary tests. These
labels depend on actual commands, not numbers baked into the plugin.

Instruction callbacks run before dispatch, so faulting instructions may be
included. This is not a physical retired-instruction/cycle counter or a cache
simulator. LTO-inlined work belongs to its enclosing ELF symbol; outside_symbols
includes firmware/boot addresses. Exclude instrumented timings from production
speed comparisons. Source provenance: [QEMU plugin API](https://www.qemu.org/docs/master/devel/tcg-plugins.html),
implemented here without imported source.

T017 validation: real compact debug boot, 2,000 externally verified responses,
idle/load checkpoints and exact inline/callback agreement in all five phases.
Raw reports and graphs are local external artifacts, not tracked guest output.
