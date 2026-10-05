"""Real ARM64 Pi 4 bring-up test; explicitly does not verify Ethernet serving."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
from .core import ROOT, digest, doctor, save, tool
from .integrity import audit


def pi4_test(project):
    project = Path(project).resolve()
    if re.search(r"[^A-Za-z0-9_./-]", str(project)):
        raise ValueError("Project path must not contain shell metacharacters")
    policy = audit(project, os_only=True)
    if not policy["ok"]:
        raise ValueError(json.dumps(policy))
    versions = doctor()
    qemu = tool("qemu-system-aarch64")
    version = subprocess.check_output([qemu, "--version"], text=True)
    if "version 11.1.2" not in version:
        raise RuntimeError("Pi gate requires QEMU 11.1.2")
    sources = {
        str(p.relative_to(project)): digest(p)
        for p in sorted(project.rglob("*"))
        if p.is_file()
        and ".git" not in p.parts
        and (
            p.suffix in [".c", ".h", ".asm", ".inc", ".ld", ".S", ".s"]
            or p.name == "Makefile"
        )
    }
    identity = hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest()[
        :16
    ]
    output = ROOT / "build" / ("pi4-" + identity)
    output.mkdir(parents=True, exist_ok=True)
    with (output / "build.log").open("w") as log:
        built = subprocess.run(
            [
                "make",
                "-C",
                str(project),
                "pi4-bringup",
                "OUT=" + str(output),
                "CC=" + tool("clang"),
                "LD=" + tool("ld.lld"),
                "OBJCOPY=" + tool("llvm-objcopy"),
                "PYTHON=" + sys.executable,
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
    if built.returncode:
        raise RuntimeError("Pi guest build failed; see " + str(output / "build.log"))
    run = ROOT / "runs" / str(uuid.uuid4())
    run.mkdir(parents=True, mode=0o700)
    args = [
        qemu,
        "-M",
        "raspi4b",
        "-kernel",
        str(output / "kernel8.img"),
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
    ]
    save(
        run / "manifest.json",
        {
            "schema": 1,
            "source_hashes": sources,
            "tools": versions,
            "qemu_aarch64": version,
            "command": args,
            "image_sha256": digest(output / "kernel8.img"),
            "symbols_sha256": digest(output / "pi4.elf"),
            "handoff": "QEMU -kernel handoff, not physical Pi firmware",
            "network_verified": False,
            "cache_enablement_implemented": False,
        },
    )
    with (run / "serial.log").open("wb") as stdout, (run / "qemu.log").open(
        "wb"
    ) as stderr:
        process = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr
        )
        try:
            deadline = time.monotonic() + 10
            while (
                b"OSL1 HTTP portable-code-ready"
                not in (run / "serial.log").read_bytes()
            ):
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("Pi bring-up failed; evidence: " + str(run))
                time.sleep(0.01)
            process.stdin.write(b"?")
            process.stdin.flush()
            while b"OSL1 STATUS board=pi4" not in (run / "serial.log").read_bytes():
                if time.monotonic() > deadline:
                    raise RuntimeError("Pi UART query timed out")
                time.sleep(0.01)
            raw = (run / "serial.log").read_bytes()
            expected = [
                b"BOOT pi4 aarch64 el1",
                b"COUNTER advancing",
                b"l1i_bytes=49152 l1d_bytes=32768 l2_bytes=1048576",
                b"network-driver-unimplemented board=pi4",
                b"network=unimplemented",
            ]
            if not all(marker in raw for marker in expected) or b"PANIC" in raw:
                raise RuntimeError("Pi markers rejected; evidence: " + str(run))
            result = {
                "ok": True,
                "run_id": run.name,
                "verdict": "pi4-emulated-bringup-only",
                "image_sha256": digest(output / "kernel8.img"),
                "image_bytes": (output / "kernel8.img").stat().st_size,
                "physical_verified": False,
                "network_verified": False,
                "cache_residency_verified": False,
            }
            save(run / "pi4-verdict.json", result)
            return result
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
