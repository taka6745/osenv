"""Real disk boot to a named breakpoint, measured with QMP event timestamps."""

import argparse
import json
import re
import time
from pathlib import Path
from .worker import start
from .core import get_run
from .__main__ import call


def interval(events):
    def stamp(event):
        t = event["timestamp"]
        return t["seconds"] + t["microseconds"] / 1e6

    resume = next(e for e in events if e["event"] == "RESUME")
    stop = next(e for e in events if e["event"] == "STOP" and stamp(e) >= stamp(resume))
    if any(
        e["event"] == "RESET" and stamp(resume) <= stamp(e) <= stamp(stop)
        for e in events
    ):
        raise ValueError("Unexpected reset during measured boot")
    return stamp(stop) - stamp(resume)


def probe(image, symbols, breakpoint, nic_model="e1000e", nic_rom=False):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*|0x[0-9a-fA-F]+", breakpoint):
        raise ValueError("Expected a symbol or hexadecimal address")
    begun = time.monotonic()
    rid = start(
        timeout=60,
        manual=True,
        paused=True,
        image=image,
        symbols=symbols,
        mode="long64",
        memory=64,
        network="isolated",
        timing="realtime",
        nic_model=nic_model,
        nic_rom=nic_rom,
    )["run_id"]
    run = get_run(rid)
    try:
        r = call(
            rid, {"operation": "debug", "action": "breakpoint", "address": breakpoint}
        )
        if not r["ok"] or "breakpoint-hit" not in r.get("mi", ""):
            raise RuntimeError("Breakpoint not reached: " + json.dumps(r))
        call(rid, {"operation": "status"})
        events = [
            json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()
        ]
        result = {
            "ok": True,
            "run_id": rid,
            "breakpoint": breakpoint,
            "reset_resume_to_breakpoint_seconds": interval(events),
            "launch_with_debugger_to_breakpoint_seconds": time.monotonic() - begun,
            "scope": "Real BIOS/disk boot to requested symbol; QMP RESUME/STOP; excludes host preparation. Not HTTP readiness or physical cycles.",
        }
    except Exception as e:
        result = {
            "ok": False,
            "run_id": rid,
            "error": str(e),
            "cpu_status_before_cleanup": call(
                rid, {"operation": "qmp", "command": "query-status"}
            ),
        }
    finally:
        try:
            stopped = call(rid, {"operation": "stop"})
            if not stopped.get("ok"):
                raise RuntimeError(str(stopped))
        except Exception as e:
            result = {
                "ok": False,
                "run_id": rid,
                "error": "Evidence/recovery failed: " + str(e),
            }
    (run / "boot-probe.json").write_text(json.dumps(result, indent=2))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", required=True)
    p.add_argument("--symbols", required=True)
    p.add_argument("--breakpoint", default="kernel_main")
    p.add_argument("--nic-model", choices=["e1000", "e1000e"], default="e1000e")
    p.add_argument("--nic-rom", action="store_true")
    a = p.parse_args()
    r = probe(**vars(a))
    print(json.dumps(r, indent=2))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1)
