# Agent contract

Read README.md and DEBUGGING.md. Keep the CLI JSON, noninteractive and bounded.
Use one controller and persistent GDB/MI connection per VM. Preserve raw
evidence when diagnostics fail. Never kill a process without verifying its
ownership. Keep guest networking disabled in the deterministic gate.

Run `python3 -m osenv test` after relevant changes. Guest fixtures are authored
for this project and must stay clearly labelled; they are not an OS. Extend
tested interfaces before adding guest subsystem semantics. Keep tooling pins,
capabilities and verification claims current. Never commit generated images,
dumps, run artifacts, credentials or private host configuration.

## Mandatory source integrity

Read and obey [INTEGRITY.md](INTEGRITY.md) before editing. These requirements
are release-blocking. No exceptions may be inferred from a green test suite.
