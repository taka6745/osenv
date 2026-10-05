"""Paused same-process QCOW2 restoration, independently checked through RAM and HTTP.

Authored from QEMU's documented savevm/loadvm monitor interface. This is warm
state restoration, never a BIOS cold boot. Controller/RPC and client costs remain
inside the reported end-to-end interval.
"""

import argparse
import hashlib
import http.client
import json
import socket
import time
from .worker import start
from .core import get_run
from .__main__ import call
from .web_stress import dhcp_ack_seen


def validate_body(response, body, expected=None):
    if response.status != 200 or int(response.getheader("Content-Length", "-1")) != len(
        body
    ):
        raise ValueError("Incomplete or unsuccessful HTTP response")
    if response.headers.get_content_type() != "text/html" or not body.endswith(
        b"</html>"
    ):
        raise ValueError("Unexpected HTTP content")
    if expected is not None and body != expected:
        raise ValueError("Restored HTTP response differs")


def probe(image, symbols, repeat=3, mode='snapshot'):
    if type(repeat) is not int or not 1 <= repeat <= 20:
        raise ValueError("repeat must be 1..20")
    if mode not in ('snapshot','resume'):
        raise ValueError('mode must be snapshot or resume')
    rid = start(
        timeout=120,
        manual=True,
        image=image,
        symbols=symbols,
        mode="long64",
        memory=64,
        network="isolated",
        timing="realtime",
        nic_model="e1000e",
        nic_rom=False,
        minimal_devices=True,
    )["run_id"]
    run = get_run(rid)
    result = {
        "ok": False,
        "run_id": rid,
        "mode":mode,
        "scope": ("Same-process paused QCOW2 restore" if mode=='snapshot' else "Prepared paused live service resume; CPU/RAM/device power retained")
                 + "; verified RAM and complete HTTP; includes control/client costs. Not cold boot or physical cycles.",
    }

    def owner(**request):
        reply = call(rid, request)
        if not reply.get("ok"):
            raise RuntimeError(json.dumps(reply))
        return reply

    def fetch():
        client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            client.request("GET", "/")
            response = client.getresponse()
            body = response.read()
            validate_body(response, body)
            return body
        finally:
            client.close()

    try:
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        owner(operation="network-forward", host_port=port)
        deadline = time.monotonic() + 15
        while not dhcp_ack_seen(run / "network.pcap"):
            if time.monotonic() >= deadline:
                raise TimeoutError("No DHCP ACK")
            time.sleep(0.01)
        expected = fetch()
        (run / "restore-body.bin").write_bytes(expected)
        owner(operation="debug", action="pause")
        # Physical scratch RAM outside the current low linked kernel; original
        # bytes are observed, never assumed. CPU stays stopped during mutation.
        address = "0x3000000"
        original = owner(operation="physical-memory", address=address, length=16)["hex"]
        mutated = bytes(b ^ 0xFF for b in bytes.fromhex(original)).hex()
        result["ram_check"] = {
            "physical_address": address,
            "original_hex": original,
            "mutated_hex": mutated,
        }
        if mode=='snapshot':owner(operation="snapshot", action="save", tag="http-ready")
        event_offset = (run / "events.jsonl").stat().st_size
        rows = []
        for _ in range(repeat):
            if mode=='snapshot':
                owner(operation="debug", action="write-memory", address=address, value=mutated)
                observed = owner(operation="physical-memory", address=address, length=16)["hex"]
                if observed != mutated:raise ValueError("RAM mutation not observed")
            begun = time.monotonic()
            loaded = owner(operation="snapshot", action="load", tag="http-ready") if mode=='snapshot' else None
            restored = owner(operation="physical-memory", address=address, length=16)[
                "hex"
            ]
            if restored != original:
                raise ValueError("Snapshot did not restore actual RAM")
            owner(operation="debug", action="resume")
            body = fetch()
            if body != expected:
                raise ValueError("Restored HTTP response differs")
            rows.append(
                {
                    "load_owner_seconds": loaded["seconds"] if loaded else None,
                    "load_call_ram_check_resume_http_seconds": time.monotonic() - begun,
                    "ram_restored": True if mode=='snapshot' else None,
                    "retained_ram_verified": True,
                    "http_exact": True,
                }
            )
            owner(operation="debug", action="pause")
        owner(operation="status")
        events = [
            json.loads(line)
            for line in (run / "events.jsonl").read_text()[event_offset:].splitlines()
        ]
        if any(event["event"] in ("RESET", "SHUTDOWN") for event in events):
            raise ValueError("Unexpected reset/shutdown during restoration")
        if "PANIC" in (run / "serial.log").read_text():
            raise ValueError("Guest panic during restoration")
        result.update(
            ok=True, samples=rows, body_sha256=hashlib.sha256(expected).hexdigest()
        )
    except Exception as error:
        result["error"] = str(error) or type(error).__name__
        result["capture"] = call(rid, {"operation": "capture", "mode": "long64"})
    finally:
        stopped = call(rid, {"operation": "stop"})
        if not stopped.get("ok"):
            result.update(ok=False, cleanup_error=stopped)
        (run / "restore-probe.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--symbols", required=True)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument('--mode',choices=['snapshot','resume'],default='snapshot')
    try:
        result = probe(**vars(parser.parse_args()))
    except Exception as error:
        result = {"ok": False, "error": str(error)}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ok"] else 1)
