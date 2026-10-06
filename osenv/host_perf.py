"""Bounded Linux perf stat on independently verified, live owned QEMU processes.

Authored from Linux perf-stat's documented attach/timeout/CSV interfaces. Default
host PMU events exclude KVM guest execution (:H); optional :G requires KVM and
positive observed counters. Neither is a physical-board acceptance benchmark.
No VM launch, system configuration, package installation or permission changes.
"""

import argparse
import csv
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from .core import get_run, load, digest
from .__main__ import call

EVENTS = (
    "cycles:H",
    "instructions:H",
    "cache-references:H",
    "cache-misses:H",
    "branches:H",
    "branch-misses:H",
    "context-switches",
    "cpu-migrations",
)


def process(pid):
    if type(pid) is not int or pid <= 1:
        raise ValueError("Invalid owned process PID")
    root = Path("/proc") / str(pid)
    fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
    return {
        "pid": pid,
        "parent_pid": int(fields[1]),
        "start_ticks": int(fields[19]),
        "uid": root.stat().st_uid,
        "exe": str((root / "exe").resolve(strict=True)),
        "argv": [
            part.decode()
            for part in (root / "cmdline").read_bytes().split(b"\0")
            if part
        ],
    }


def owned(identity):
    directory = get_run(identity)
    manifest = load(directory / "manifest.json")
    status = call(identity, {"operation": "status"})
    if not status.get("ok") or status.get("state") != "running":
        raise ValueError(
            "Profiling requires the live running owner, never a saved/dead run"
        )
    qemu, owner = process(status["qemu_pid"]), process(status["owner_pid"])
    if owner["argv"][1:] != ["-m", "osenv", "_worker", identity]:
        raise ValueError("Owner process command does not match this run")
    if owner["pid"] != load(directory / "launch.json")["owner_pid"]:
        raise ValueError("Owner PID differs from retained launch")
    if (
        qemu["parent_pid"] != owner["pid"]
        or qemu["uid"] != owner["uid"]
        or owner["uid"] != os.getuid()
    ):
        raise ValueError("QEMU parent/UID ownership mismatch")
    arguments = manifest["qemu_argv"]
    if qemu["argv"][1:] != arguments[1:] or qemu["exe"] != str(
        Path(arguments[0]).resolve()
    ):
        raise ValueError("Live QEMU command/executable differs from retained machine")
    if digest(directory / "disk.img") != manifest["image_sha256"]:
        raise ValueError("Retained image hash mismatch")
    return directory, manifest, qemu, owner


def events_for_scope(scope, machine, kvm_exits=False):
    if scope not in ("host", "guest") or type(kvm_exits) is not bool:
        raise ValueError("Counter scope must be host/guest and exits flag boolean")
    if (scope == "guest" or kvm_exits) and machine.get("acceleration") != "kvm":
        raise ValueError(
            "Guest counters/KVM exits require an actual KVM run; TCG is rejected"
        )
    return tuple(
        event.replace(":H", ":G") if scope == "guest" else event for event in EVENTS
    ) + (("kvm:kvm_exit",) if kvm_exits else ())


def threads(pid):
    result = []
    for task in sorted(
        (Path("/proc") / str(pid) / "task").iterdir(), key=lambda p: int(p.name)
    ):
        fields = (task / "stat").read_text().rsplit(")", 1)[1].split()
        result.append(
            {
                "tid": int(task.name),
                "start_ticks": int(fields[19]),
                "name": (task / "comm").read_text().strip(),
            }
        )
    if not result:
        raise ValueError("Owned QEMU has no readable task IDs")
    return result


def exit_tracepoint():
    for root in (Path("/sys/kernel/tracing"), Path("/sys/kernel/debug/tracing")):
        event = root / "events/kvm/kvm_exit"
        if (event / "id").is_file():
            identity = int((event / "id").read_text().strip())
            if identity <= 0:
                raise ValueError("Invalid KVM exit tracepoint ID")
            return {
                "path": str(event),
                "id": identity,
                "format_sha256": digest(event / "format"),
            }
    raise RuntimeError(
        "KVM exit tracepoint unavailable: neither /sys/kernel/tracing/events/kvm/kvm_exit/id nor /sys/kernel/debug/tracing/events/kvm/kvm_exit/id is readable; no mount attempted"
    )


def parse_counters(path, expected=EVENTS):
    results = {}
    for row in csv.reader(Path(path).read_text().splitlines(), delimiter=";"):
        if (
            not row
            or row[0].startswith("#")
            or len(row) < 5
            or row[2].strip() not in expected
        ):
            continue
        value, unit, event, runtime, percent = [part.strip() for part in row[:5]]
        if event in results:
            raise ValueError("Unexpected repeated/aggregated counter: " + event)
        if value.startswith("<"):
            raise ValueError("Counter unavailable: " + event + " " + value)
        results[event] = {
            "value": float(value),
            "unit": unit,
            "runtime_ns": float(runtime),
            "percent_running": float(percent),
            "scaled_by_perf": True,
        }
        if any(
            not math.isfinite(results[event][key]) or results[event][key] < 0
            for key in ("value", "runtime_ns", "percent_running")
        ):
            raise ValueError("Invalid numeric counter data: " + event)
        if not 0 < results[event]["percent_running"] <= 100:
            raise ValueError("Invalid counter running percentage: " + event)
    missing = set(expected) - results.keys()
    if missing:
        raise ValueError("Missing perf events: " + ",".join(sorted(missing)))
    return results


def profile(
    run_id, seconds, output, perf_executable=None, counter_scope="host", kvm_exits=False
):
    if type(seconds) not in (int, float) or not 0.1 <= seconds <= 30:
        raise ValueError("seconds must be 0.1..30")
    directory = Path(output).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    report = {
        "ok": False,
        "run_id": run_id,
        "seconds": seconds,
        "scope": "Owned QEMU host PMU counters (:H excludes guest execution) and process software events. Profiling workload must be separate from timing acceptance; not physical guest cycles/cache.",
        "interface_provenance": [
            "https://raw.githubusercontent.com/torvalds/linux/v6.12/tools/perf/Documentation/perf-list.txt",
            "https://raw.githubusercontent.com/torvalds/linux/v6.12/tools/perf/util/thread_map.c",
            "https://www.linux-kvm.org/page/Perf_events",
        ],
    }
    try:
        if sys.platform != "linux":
            raise RuntimeError("Linux perf profiling unavailable on " + sys.platform)
        if perf_executable:
            chosen = Path(perf_executable)
            if (
                not chosen.is_absolute()
                or not chosen.is_file()
                or not os.access(chosen, os.X_OK)
            ):
                raise ValueError(
                    "Perf executable must be an absolute installed/extracted executable path"
                )
            executable = str(chosen.resolve())
        else:
            executable = shutil.which("perf")
        if not executable:
            raise RuntimeError("Missing perf executable; no install attempted")
        run, manifest, qemu, owner = owned(run_id)
        events = events_for_scope(counter_scope, manifest["machine"], kvm_exits)
        task_ids = threads(qemu["pid"])
        report.update(
            counter_scope=counter_scope,
            events=events,
            tasks_before=task_ids,
            attachment_scope="perf -p enumerates existing /proc/PID/task threads; task identities checked before and after",
            scope="Owned QEMU "
            + counter_scope
            + "-filtered PMU sample; process software events and optional KVM exit tracepoint remain host events. Separate from timing acceptance; not physical-board guest cycles/cache.",
        )
        if kvm_exits:
            report["kvm_exit_tracepoint"] = exit_tracepoint()
        report.update(
            owned_qemu=qemu,
            owned_controller=owner,
            machine=manifest["machine"],
            image_sha256=manifest["image_sha256"],
            source_hashes=manifest.get("source_hashes"),
            source_hashes_scope="External osenv controller/harness source hashes; not guest source provenance",
            guest_build_provenance={
                "scope": "Retained PVH build provenance hash when present; no guest source snapshot claimed here",
                "pvh_inputs_sha256": manifest.get("boot_provenance_sha256"),
            },
            runtime_tools=manifest.get("runtime_tools"),
            firmware_sha256=manifest.get("firmware_sha256"),
            symbols_sha256=digest(run / "boot.elf")
            if (run / "boot.elf").is_file()
            else None,
            profiler_source_sha256=digest(Path(__file__)),
            perf_binary_sha256=digest(executable),
            perf_version=subprocess.check_output(
                [executable, "--version"], text=True, timeout=5
            ).strip(),
        )
        arguments = [
            executable,
            "stat",
            "--no-big-num",
            "-x",
            ";",
            "-e",
            ",".join(events),
            "-p",
            str(qemu["pid"]),
            "--timeout",
            str(round(seconds * 1000)),
            "-o",
            str(directory / "perf-stat.csv"),
        ]
        report["command"] = arguments
        (directory / "inputs.json").write_text(json.dumps(report, indent=2))
        # Recheck process start identity immediately before attachment. Recheck
        # again afterward; process loss/PID reuse invalidates the whole sample.
        if process(qemu["pid"]) != qemu or process(owner["pid"]) != owner:
            raise RuntimeError("Owned process identity changed before perf attachment")
        if threads(qemu["pid"]) != task_ids:
            raise RuntimeError("QEMU thread topology changed before perf attachment")
        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        begun = time.monotonic()
        result = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            timeout=seconds + 10,
            env=environment,
        )
        report.update(
            returncode=result.returncode, elapsed_seconds=time.monotonic() - begun
        )
        (directory / "perf-stdout.txt").write_text(result.stdout)
        (directory / "perf-stderr.txt").write_text(result.stderr)
        if result.returncode:
            raise RuntimeError("perf failed: " + result.stderr.strip())
        if process(qemu["pid"]) != qemu or process(owner["pid"]) != owner:
            raise RuntimeError("Owned process exited/changed during perf sample")
        report["tasks_after"] = threads(qemu["pid"])
        if report["tasks_after"] != task_ids:
            raise RuntimeError(
                "QEMU thread topology changed during profiling; sample scope incomplete"
            )
        status = call(run_id, {"operation": "status"})
        if status.get("state") != "running" or status.get("qemu_pid") != qemu["pid"]:
            raise RuntimeError("VM was not still running after perf sample")
        report["counters"] = parse_counters(directory / "perf-stat.csv", events)
        for event, row in report["counters"].items():
            row["scope"] = (
                counter_scope + "-filtered KVM PMU"
                if event.endswith(":G")
                else "host-filtered PMU"
                if event.endswith(":H")
                else "host process/tracepoint"
            )
        if counter_scope == "guest":
            if any(
                report["counters"][event]["value"] <= 0
                for event in ("cycles:G", "instructions:G")
            ):
                raise RuntimeError(
                    "Guest filter produced no positive cycles/instructions; attribution remains unverified"
                )
            report["guest_filter_observed_positive"] = True
        report["multiplexed"] = any(
            row["percent_running"] < 100 for row in report["counters"].values()
        )
        report["ok"] = True
    except subprocess.TimeoutExpired as error:
        if error.stdout:
            (directory / "perf-stdout.txt").write_bytes(
                error.stdout
                if isinstance(error.stdout, bytes)
                else error.stdout.encode()
            )
        if error.stderr:
            (directory / "perf-stderr.txt").write_bytes(
                error.stderr
                if isinstance(error.stderr, bytes)
                else error.stderr.encode()
            )
        report["error"] = "Bounded perf/version command timed out: " + str(error)
    except Exception as error:
        report["error"] = str(error) or type(error).__name__
    finally:
        (directory / "verdict.json").write_text(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--output", required=True)
    parser.add_argument("--counter-scope", choices=["host", "guest"], default="host")
    parser.add_argument(
        "--kvm-exits",
        action="store_true",
        help="Require readable existing kvm:kvm_exit tracepoint; no mount/settings changes",
    )
    parser.add_argument(
        "--perf-executable",
        help="Absolute installed/extracted perf path; default searches PATH",
    )
    args = parser.parse_args()
    try:
        result = profile(**vars(args))
    except Exception as error:
        result = {"ok": False, "error": str(error)}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ok"] else 1)
