"""Seeded socket load against a real booted OS; results and failures stay external."""

import argparse
import hashlib
import http.client
import io
import json
import random
import socket
import statistics
import struct
import time
import traceback
from pathlib import Path
from .worker import start
from .core import get_run
from .__main__ import call
from .wire_cost import wire_cost
from .boot_timing import sample_clock, returned_request_timing


def dhcp_ack_seen(path):
    """Read actual captured DHCP ACKs without creating pending TCP clients."""
    raw = Path(path).read_bytes()
    if len(raw) < 24:
        return False
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(raw[:4])
    if endian is None or struct.unpack_from(endian + "I", raw, 20)[0] != 1:
        raise ValueError("Expected Ethernet pcap")
    cursor = 24
    while cursor + 16 <= len(raw):
        _, _, count, _ = struct.unpack_from(endian + "IIII", raw, cursor)
        cursor += 16
        if cursor + count > len(raw):
            break  # A live capture may end in an incomplete record.
        frame = raw[cursor : cursor + count]
        cursor += count
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        header = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], "big")
        if ip[9] != 17 or header < 20 or total > len(ip) or total < header + 248:
            continue
        udp = ip[header:total]
        if udp[:4] != b"\x00\x43\x00\x44":
            continue
        data = udp[8:]
        if data[0] != 2 or data[236:240] != b"\x63\x82\x53\x63":
            continue
        pos = 240
        while pos < len(data):
            tag = data[pos]
            pos += 1
            if tag == 255:
                break
            if tag == 0:
                continue
            if pos >= len(data):
                break
            length = data[pos]
            pos += 1
            if pos + length > len(data):
                break
            if tag == 53 and length == 1 and data[pos] == 5:
                return True
            pos += length
    return False


def stress(
    image,
    symbols,
    requests=1000,
    seed=0x5EED,
    profile=False,
    timing="realtime",
    production=False,
    nic_rom=True,
    nic_model="e1000",
    controlled_boot=False,
    minimal_devices=False,
    boot_kernel=None,
):
    if controlled_boot and not production:
        raise ValueError("Controlled boot requires production")
    if production and profile:
        raise ValueError("Production must not expose profiling")
    if not __debug__:
        raise RuntimeError("Stress requires Python assertions enabled")
    rng = random.Random(seed)
    begun = time.monotonic()
    rid = start(
        timeout=600,
        paused=controlled_boot,
        minimal_devices=minimal_devices,
        boot_kernel=boot_kernel,
        manual=True,
        image=image,
        symbols=symbols,
        mode="long64",
        memory=64,
        network="isolated",
        timing=timing,
        nic_rom=nic_rom,
        nic_model=nic_model,
    )["run_id"]
    run = get_run(rid)
    inputs = {
        "readiness_poll_seconds": 0.001 if controlled_boot else 0.01,
        "controlled_boot": controlled_boot,
        "minimal_devices": minimal_devices,
        "boot_route": json.loads((run / "manifest.json").read_text())["machine"][
            "boot_route"
        ],
        "seed": seed,
        "requests": requests,
        "profile": profile,
        "production": production,
        "timing": timing,
        "nic_rom": nic_rom,
        "nic_model": nic_model,
        "scope": "single CPU QEMU TCG, isolated NAT; no physical cycle claim",
    }
    (run / "stress-inputs.json").write_text(json.dumps(inputs, indent=2))
    samples = []
    phase_samples = []
    network_ready_seconds = None
    resume_started = None
    resume_to_response = None
    controller_ready = None
    boot_before = boot_complete = None
    cases = []
    try:
        while not production and "OSL1 SERVING" not in (run / "serial.log").read_text():
            if time.monotonic() - begun > 15:
                raise TimeoutError("No serving marker")
            time.sleep(0.01)
        boot_seconds = time.monotonic() - begun
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        assert call(rid, {"operation": "network-forward", "host_port": port})["ok"]

        if controlled_boot:
            controller_ready = time.monotonic() - begun
            boot_before = sample_clock()
            resume_started = time.monotonic()
            assert call(rid, {"operation": "debug", "action": "resume"})["ok"]

        def serial(text, marker):
            before = (run / "serial.log").stat().st_size
            assert call(rid, {"operation": "serial", "text": text + "\n"})["ok"]
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                added = (run / "serial.log").read_text()[before:]
                if marker in added and added.endswith("\n"):
                    return added
                time.sleep(0.005)
            raise TimeoutError("Serial command incomplete: " + text)

        def fetch(request, fragmented=False, reset=False, timeout=5, record=False):
            t = time.monotonic()
            with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
                connected = time.monotonic()
                sock.settimeout(timeout)
                offset = 0
                while offset < len(request):
                    n = rng.randint(1, 47) if fragmented else len(request)
                    sock.sendall(request[offset : offset + n])
                    offset += n
                data = bytearray()
                sent = time.monotonic()
                first = None
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        if first is None:
                            first = time.monotonic()
                        data.extend(chunk)
                        if len(data) > 4096:
                            raise AssertionError("Unbounded response")
                except ConnectionResetError:
                    if not reset:
                        raise
                if reset:
                    assert not data, "Oversize request unexpectedly returned content"
            finished = time.monotonic()
            if record:
                assert first is not None
                phase_samples.append(
                    {
                        "connect": connected - t,
                        "request_send": sent - connected,
                        "first_byte_after_request": first - sent,
                        "complete_after_request": finished - sent,
                        "total": finished - t,
                    }
                )
            return bytes(data), finished - t

        root = b"GET / HTTP/1.1\r\nHost: local\r\n\r\n"
        if production:
            deadline = time.monotonic() + 15
            while not dhcp_ack_seen(run / "network.pcap"):
                if time.monotonic() >= deadline:
                    raise TimeoutError("No captured DHCP ACK before HTTP readiness")
                time.sleep(inputs["readiness_poll_seconds"])
            network_ready_seconds = time.monotonic() - begun
            # One real readiness request, with the original overall deadline.
            # Abandoning repeated 100ms clients left delayed NAT SYN retries
            # competing with the load on the OS's single connection slot.
            expected, _ = fetch(root, timeout=max(0.001, deadline - time.monotonic()))
            boot_complete = sample_clock()
            finished_boot = time.monotonic()
            boot_seconds = finished_boot - begun
            if resume_started is not None:
                resume_to_response = finished_boot - resume_started
            assert call(
                rid,
                {
                    "operation": "serial",
                    "text": "selftest\ndhcp\nstats\nfault\npagefault\nhang\nexit\nperf-reset\nperf\nserve\n",
                },
            )["ok"]
            assert fetch(root)[0] == expected
        else:
            expected, _ = fetch(root)
        status_fields = expected.split(b"\r\n", 1)[0].split(b" ", 2)
        assert len(status_fields) == 3 and status_fields[:2] == [b"HTTP/1.0", b"200"]
        headers, body = expected.split(b"\r\n\r\n", 1)
        assert body.endswith(b"</html>") and len(body) > 0
        parsed = http.client.parse_headers(
            io.BytesIO(headers.split(b"\r\n", 1)[1] + b"\r\n\r\n")
        )
        assert parsed.get_content_type() == "text/html"
        assert parsed.get_content_charset() == "utf-8"
        assert parsed.get("Connection", "").lower() == "close"
        for header in headers.split(b"\r\n")[1:]:
            if header.lower().startswith(b"content-length:"):
                assert int(header.split(b":", 1)[1]) == len(body)
        if profile:
            serial("perf-reset", "OSL1 PERF_RESET")
            time.sleep(2)
            idle = serial("perf", "OSL1 PERF")
            serial("perf-reset", "OSL1 PERF_RESET")
        else:
            idle = None
        start_load = time.monotonic()
        for i in range(requests):
            data, elapsed = fetch(root, fragmented=i % 7 == 0, record=True)
            assert data == expected, ("Response changed", i)
            samples.append(elapsed)
            if (i + 1) % 100 == 0:
                (run / "stress-progress.json").write_text(
                    json.dumps(
                        {
                            "completed": i + 1,
                            "elapsed_seconds": time.monotonic() - start_load,
                        }
                    )
                )
        (run / "stress-latencies.json").write_text(json.dumps(samples))
        load_seconds = time.monotonic() - start_load
        load = serial("perf", "OSL1 PERF") if profile else None
        prefix = b"GET / HTTP/1.1\r\nHost: x\r\nX: "
        for length in (767, 768, 769):
            request = prefix + b"a" * (length - len(prefix) - 4) + b"\r\n\r\n"
            data, _ = fetch(request, reset=length == 769)
            assert not data if length == 769 else data == expected
            cases.append({"length": length, "accepted": length <= 768})
            assert fetch(root)[0] == expected
        for request in (
            b"GET / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            b"GET / HTTP/1.0\r\nContent-Length: 1\r\n\r\nx",
            b"GET / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"GET / HTTP/9.0\r\n\r\n",
            b"GET / HTTP/1.0\r\nX: \x00\r\n\r\n",
        ):
            assert fetch(request)[0][9:12] == b"400"
            cases.append({"malformed_hex": request.hex(), "status": 400})
            assert fetch(root)[0] == expected
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(b"GET /")
            time.sleep(11)
            sock.settimeout(5)
            try:
                assert not sock.recv(4096)
            except ConnectionResetError:
                pass
        assert fetch(root)[0] == expected
        if production:
            stats = None
            assert not (run / "serial.log").read_bytes()
            assert not (run / "early.log").read_bytes()
            assert json.loads((run / "status.json").read_text())["state"] == "running"
            assert not any(
                json.loads(line).get("event") == "RESET"
                for line in (run / "events.jsonl").read_text().splitlines()
            )
            assert call(rid, {"operation": "stop"})["ok"]
        else:
            stats = serial("stats", "OSL1 MEMORY")
            serial("exit", "OSL1 DONE")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status = json.loads((run / "status.json").read_text())
            if status.get("state") in ("finished", "error"):
                break
            time.sleep(0.01)
        log = (run / "serial.log").read_text()
        assert status.get("exit_code") == (0 if production else 33), status
        assert "OSL1 PANIC" not in log and "OSL1 RESET" not in log
        ordered = sorted(samples)
        wire = wire_cost(run / "network.pcap", expected)
        assert wire["matched_response_flows"] >= requests
        boot_timing = None
        if controlled_boot:
            events = [json.loads(line) for line in (run / 'events.jsonl').read_text().splitlines()]
            boot_timing = returned_request_timing(events, boot_before, boot_complete)
        result = {
            "ok": True,
            "run_id": rid,
            **inputs,
            "boot_seconds": boot_seconds,
            "controller_ready_seconds": controller_ready,
            "resume_call_to_first_response_seconds": resume_to_response,
            "cpu_release_to_returned_request": boot_timing,
            "launch_to_captured_DHCP_ACK_seconds": network_ready_seconds,
            "image_sha256": hashlib.sha256(Path(image).read_bytes()).hexdigest(),
            "response_sha256": hashlib.sha256(expected).hexdigest(),
            "load_seconds": load_seconds,
            "requests_per_second": requests / load_seconds,
            "response_header_bytes": len(headers) + 4,
            "response_body_bytes": len(body),
            "response_body_sha256": hashlib.sha256(body).hexdigest(),
            "http_response_goodput_Mbps": requests
            * len(expected)
            * 8
            / load_seconds
            / 1e6,
            "body_goodput_Mbps": requests * len(body) * 8 / load_seconds / 1e6,
            "phase_seconds": {
                name: {
                    "median": statistics.median(values),
                    "p99": sorted(values)[int(0.99 * (len(values) - 1))],
                }
                for name in phase_samples[0]
                for values in [[sample[name] for sample in phase_samples]]
            },
            "latency_seconds": {
                "median": statistics.median(samples),
                "p95": ordered[int(0.95 * (len(ordered) - 1))],
                "p99": ordered[int(0.99 * (len(ordered) - 1))],
                "max": max(samples),
            },
            "idle": idle,
            "load": load,
            "stats": stats,
            "boundaries": cases,
            "slow_client_timeout_recovery": True,
            "exit_code": status["exit_code"],
            "termination": "external-stop" if production else "guest-debug-exit",
            "wire": wire,
        }
        (run / "stress-latencies.json").write_text(json.dumps(samples))
        (run / "stress-phases.json").write_text(json.dumps(phase_samples))
    except Exception as error:
        (run / "stress-failure.txt").write_text(traceback.format_exc())
        result = {
            "ok": False,
            "run_id": rid,
            "error": str(error) or type(error).__name__,
        }
        try:
            result["capture"] = call(rid, {"operation": "capture", "mode": "long64"})
            call(rid, {"operation": "stop"})
        except Exception as recovery:
            result["recovery_error"] = str(recovery)
    (run / "stress-verdict.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--symbols", required=True)
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=0x5EED)
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--production", action="store_true")
    parser.add_argument("--controlled-boot", action="store_true")
    parser.add_argument("--minimal-devices", action="store_true")
    parser.add_argument("--boot-kernel")
    parser.add_argument("--no-nic-rom", dest="nic_rom", action="store_false")
    parser.add_argument("--nic-model", choices=["e1000", "e1000e"], default="e1000")
    parser.add_argument("--timing", choices=("virtual", "realtime"), default="realtime")
    args = parser.parse_args()
    if not 1 <= args.requests <= 100000:
        parser.error("requests must be 1..100000")
    verdict = stress(**vars(args))
    print(json.dumps(verdict, indent=2))
    raise SystemExit(0 if verdict["ok"] else 1)
