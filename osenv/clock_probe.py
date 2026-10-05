"""Real HPET versus cached deadline clock, including a deliberate lost-tick defect."""

import argparse
import json
import time
from .worker import start
from .core import get_run
from .__main__ import call


def probe(image, symbols, defect=False):
    rid = start(
        timeout=60,
        manual=True,
        image=image,
        symbols=symbols,
        mode="long64",
        memory=64,
        timing="realtime",
        minimal_devices=True,
    )["run_id"]
    run = get_run(rid)
    result = {
        "ok": False,
        "run_id": rid,
        "defect": defect,
        "scope": "Real HPET/cached clock with forced lost software ticks; debug image, not wall-clock calibration.",
    }

    def evaluate(expression):
        r = call(rid, {"operation": "debug", "action": "evaluate", "value": expression})
        return int(r["values"][0].split()[0], 0)

    def write(address, value):
        return call(
            rid,
            {
                "operation": "debug",
                "action": "write-memory",
                "address": hex(address),
                "value": value.to_bytes(8, "little").hex(),
            },
        )

    try:
        deadline = time.monotonic() + 15
        while "OSL1 READY" not in (run / "serial.log").read_text():
            if time.monotonic() >= deadline:
                raise TimeoutError("Debug image did not become ready")
            time.sleep(0.01)
        time.sleep(0.5)
        call(rid, {"operation": "debug", "action": "pause"})
        pointer = evaluate("(unsigned long long)hpet")
        period = evaluate("hpet_period")
        if pointer != 0xFED00000 or not 0 < period <= 100000000:
            raise ValueError("Supported 64-bit HPET not active")
        tick_address = evaluate("(unsigned long long)&timer_ticks")
        before = evaluate("timer_ticks")
        if defect:
            write(evaluate("(unsigned long long)&hpet"), 0)
        write(tick_address, 0)
        if evaluate("timer_ticks") != 0:
            raise ValueError("Lost software ticks were not injected")
        call(rid, {"operation": "debug", "action": "resume"})
        time.sleep(0.1)
        call(rid, {"operation": "debug", "action": "pause"})
        count = evaluate("*(unsigned long long*)0xfed000f0")
        now = evaluate("timer_ticks")
        hardware = count * period // 1000000000000
        result.update(
            before_ms=before,
            cached_ms=now,
            hardware_ms=hardware,
            counter=count,
            period_fs=period,
            lag_ms=hardware - now,
        )
        if now < before or not 0 <= hardware - now <= 5:
            raise ValueError("Deadline clock failed to recover from lost ticks")
        result["ok"] = True
    except Exception as error:
        result["error"] = str(error)
        result["capture"] = call(rid, {"operation": "capture", "mode": "long64"})
    finally:
        call(rid, {"operation": "stop"})
        (run / "clock-probe.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", required=True)
    p.add_argument("--symbols", required=True)
    p.add_argument(
        "--defect",
        action="store_true",
        help="Disable HPET sampling to prove rejection; never a release build",
    )
    try:
        r = probe(**vars(p.parse_args()))
    except Exception as error:
        r = {"ok": False, "error": str(error)}
    print(json.dumps(r, indent=2))
    raise SystemExit(0 if r["ok"] else 1)
