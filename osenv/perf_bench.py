"""Bounded real-image repetitions, separate host setup and reset-to-response."""

import argparse
import hashlib
import json
import statistics
from pathlib import Path
from .web_stress import stress


def summarize(results):
    if not results or not all(r.get("ok") for r in results):
        raise ValueError("Every real-image run must pass")
    if len({r["image_sha256"] for r in results}) != 1:
        raise ValueError("Image changed between repetitions")
    return {
        "ok": True,
        "image_sha256": results[0]["image_sha256"],
        "runs": [r["run_id"] for r in results],
        "requests": sum(r["requests"] for r in results),
        "requests_per_second": sum(r["requests"] for r in results)
        / sum(r["load_seconds"] for r in results),
        "launch_to_response_seconds": [r["boot_seconds"] for r in results],
        "resume_call_to_response_seconds": [
            r["resume_call_to_first_response_seconds"] for r in results
        ],
        "median_resume_call_to_response_seconds": statistics.median(
            r["resume_call_to_first_response_seconds"] for r in results
        ),
        "median_latency_seconds": [r["latency_seconds"]["median"] for r in results],
        "p99_latency_seconds": [r["latency_seconds"]["p99"] for r in results],
        "controller_ready_seconds": [r["controller_ready_seconds"] for r in results],
        "scope": "Full BIOS disk boot; resume includes control RPC and DHCP-observation polling. Host setup reported separately. TCG/NAT, not physical cycles or Cloudflare-equivalent cold start.",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", required=True)
    p.add_argument("--symbols", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--compare-image")
    p.add_argument("--compare-symbols")
    p.add_argument("--repeat", type=int, default=3)
    p.add_argument("--requests", type=int, default=5000)
    p.add_argument("--seed", type=int, default=24326)
    p.add_argument("--nic-model", choices=["e1000", "e1000e"], default="e1000")
    p.add_argument("--no-nic-rom", dest="nic_rom", action="store_false")
    a = p.parse_args()
    if not 1 <= a.repeat <= 20 or not 1 <= a.requests <= 100000:
        p.error("repeat must be 1..20 and requests 1..100000")
    if bool(a.compare_image) != bool(a.compare_symbols):
        p.error("compare-image and compare-symbols must be supplied together")
    directory = Path(a.output)
    directory.mkdir(parents=True, exist_ok=False)
    plan = vars(a)
    plan["image_sha256"] = hashlib.sha256(Path(a.image).read_bytes()).hexdigest()
    plan["symbols_sha256"] = hashlib.sha256(Path(a.symbols).read_bytes()).hexdigest()
    (directory / "plan.json").write_text(json.dumps(plan, indent=2))
    variants = {"candidate": (a.image, a.symbols)}
    if a.compare_image:
        variants["baseline"] = (a.compare_image, a.compare_symbols)
        plan["comparison_hashes"] = {
            "image": hashlib.sha256(Path(a.compare_image).read_bytes()).hexdigest(),
            "symbols": hashlib.sha256(Path(a.compare_symbols).read_bytes()).hexdigest(),
        }
        (directory / "plan.json").write_text(json.dumps(plan, indent=2))
    results = {name: [] for name in variants}
    for i in range(a.repeat):
        order = list(variants)
        if i & 1:
            order.reverse()
        for name in order:
            image, symbols = variants[name]
            r = stress(
                image,
                symbols,
                requests=a.requests,
                seed=a.seed + i,
                production=True,
                controlled_boot=True,
                nic_rom=a.nic_rom,
                nic_model=a.nic_model,
            )
            (directory / f"{name}-{i}.json").write_text(json.dumps(r, indent=2))
            if not r["ok"]:
                print(json.dumps(r))
                return 1
            results[name].append(r)
    report = {name: summarize(rows) for name, rows in results.items()}
    report["ok"] = True
    if "baseline" in report:
        report["throughput_ratio"] = (
            report["candidate"]["requests_per_second"]
            / report["baseline"]["requests_per_second"]
        )
    (directory / "summary.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1)
