"""Actual e1000 cause injection, PIC delivery/acknowledgment and rearming."""

import argparse
import json
import time
import traceback
from pathlib import Path
from .worker import start
from .core import get_run
from .__main__ import call


def test(image, symbols, nic_model="e1000", boot_kernel=None, minimal_devices=False):
    if not __debug__:
        raise RuntimeError("Acceptance requires Python assertions enabled")
    rid = start(
        timeout=45,
        manual=True,
        image=image,
        symbols=symbols,
        mode="long64",
        memory=64,
        network="isolated",
        nic_model=nic_model,
        boot_kernel=boot_kernel,
        minimal_devices=minimal_devices,
    )["run_id"]
    run = get_run(rid)
    result = {"ok": False, "run_id": rid}
    try:
        deadline = time.monotonic() + 15
        while b"OSL1 READY" not in (run / "serial.log").read_bytes():
            assert time.monotonic() < deadline
            time.sleep(0.01)

        def evaluate(value):
            r = call(rid, {"operation": "debug", "action": "evaluate", "value": value})
            assert r["ok"], r
            return int(r["values"][0].split()[0], 0)

        irq = evaluate("nic_irq_line")
        mmio = evaluate("(unsigned long long)mmio")
        assert 3 <= irq < 16 and mmio
        injections = []
        for _ in range(2):
            assert call(
                rid,
                {
                    "operation": "debug",
                    "action": "write-memory",
                    "address": hex(mmio + 0xC8),
                    "value": "80000000",
                },
            )["ok"]
            r = call(
                rid,
                {
                    "operation": "debug",
                    "action": "breakpoint",
                    "address": "nic_interrupt",
                },
            )
            assert (
                r["ok"] and "breakpoint-hit" in r["mi"] and "nic_interrupt" in r["mi"]
            ), r
            # The ISR receives the actual delivered PIC line, not a guest PASS.
            assert evaluate("$rdi") == irq
            call(rid, {"operation": "debug", "action": "delete-breakpoints"})
            call(rid, {"operation": "debug", "action": "resume"})
            time.sleep(0.02)
            assert evaluate("*(unsigned int*)((unsigned long long)mmio+0xc0)") == 0
            injections.append({"delivered_irq": irq, "cause_acknowledged": True})
        result = {
            "ok": True,
            "run_id": rid,
            "injections": injections,
            "scope": "actual emulated device ICS -> PIC -> guest ISR -> ICR clear, rearmed twice",
        }
    except Exception as error:
        (run / "irq-failure.txt").write_text(traceback.format_exc())
        result["error"] = str(error) or type(error).__name__
    finally:
        result["capture"] = call(rid, {"operation": "capture", "mode": "long64"})
        call(rid, {"operation": "stop"})
        (run / "irq-verdict.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--symbols", required=True)
    parser.add_argument("--nic-model", choices=["e1000", "e1000e"], default="e1000")
    parser.add_argument("--boot-kernel")
    parser.add_argument("--minimal-devices", action="store_true")
    args = parser.parse_args()
    result = test(**vars(args))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ok"] else 1)
