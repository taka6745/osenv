"""Matched real-image five-frame TCP benchmark over one QEMU packet-peer stream.

Authored from this project's web_test framing/DHCP exchange, reusing boot_wire
and wire_cost independently. No guest fixture, NAT, or per-request host socket.
Client packet construction and checks stay inside timing and are measured
separately. Optional deferred HTTP parsing retains exact-byte checks inline and
parses every captured response before success. Compare only this backend with
itself; it cannot substitute for normal HTTP socket performance.
"""

import argparse
import ctypes
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import random
import re
import socket
import statistics
import struct
import subprocess
import sys
import time
from .worker import start
from .core import get_run, digest, tool
from .__main__ import call
from .boot_wire import analyze
from .wire_cost import wire_cost
from .raw_primitives_test import checksum as independent_checksum


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!" + str(len(data) // 2) + "H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


class NativeChecksum:
    def __init__(self, path, metadata):
        self.library = ctypes.CDLL(str(path))
        self.function = self.library.peer_checksum
        self.function.argtypes = [ctypes.c_char_p, ctypes.c_uint]
        self.function.restype = ctypes.c_uint
        self.metadata = metadata

    def __call__(self, data):
        require(len(data) <= 1514, "Host checksum input exceeds Ethernet bound")
        result = self.function(bytes(data), len(data))
        require(result <= 65535, "Host checksum rejected its input")
        return result


def build_native_checksum(directory, compiler_path=None):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parent.parent / "tools/peer_checksum.c"
    target = directory / (
        "peer_checksum.dylib" if sys.platform == "darwin" else "peer_checksum.so"
    )
    if compiler_path:
        compiler = Path(compiler_path)
        require(
            compiler.is_absolute()
            and compiler.is_file()
            and os.access(compiler, os.X_OK),
            "Checksum compiler must be an absolute executable file path",
        )
        compiler = str(compiler.resolve())
    else:
        compiler = tool("clang")
    arguments = [
        compiler,
        "-O3",
        "-nostdinc",
        "-fno-builtin",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fPIC",
        "-dynamiclib" if sys.platform == "darwin" else "-shared",
        str(source),
        "-o",
        str(target),
    ]
    metadata = {
        "scope": "Authored bounded host checksum only; never guest code",
        "source": str(source),
        "source_sha256": digest(source),
        "compiler_argv": arguments,
        "compiler_version": subprocess.check_output(
            [compiler, "--version"], text=True, timeout=10
        ).splitlines()[0],
    }
    subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=30)
    metadata.update(binary=str(target), binary_sha256=digest(target))
    native = NativeChecksum(target, metadata)
    require(
        native.function(None, 1515) == 0xFFFFFFFF
        and native.function(None, 1) == 0xFFFFFFFF,
        "Native checksum failed invalid-input guard",
    )
    require(native.function(None, 0) == 65535, "Empty checksum mismatch")
    randomizer = random.Random(24326)
    boundaries = [0, 1, 2, 3, 53, 54, 1492, 1513, 1514]
    for index in range(20000):
        size = (
            boundaries[index] if index < len(boundaries) else randomizer.randrange(1515)
        )
        data = randomizer.randbytes(size)
        guarded = ctypes.create_string_buffer(b"LEFT" + data + b"RIGHT")
        prior = guarded.raw
        pointer = ctypes.cast(ctypes.byref(guarded, 4), ctypes.c_char_p)
        require(
            native.function(pointer, size) == independent_checksum(data),
            "Native checksum differential mismatch",
        )
        require(guarded.raw == prior, "Native checksum changed input/guards")
    metadata.update(
        differential_vectors=20000,
        differential_seed=24326,
        null_and_oversize_rejected=True,
        input_guards_unchanged=True,
    )
    (directory / "checksum-build.json").write_text(json.dumps(metadata, indent=2))
    return native


def validate_http(raw):
    require(
        len(raw) <= 1460 and b"\r\n\r\n" in raw,
        "Response must fit one negotiated segment",
    )
    headers, body = raw.split(b"\r\n\r\n", 1)
    require(
        headers.split(b"\r\n")[0].split(b" ")[:2] == [b"HTTP/1.0", b"200"],
        "Unexpected HTTP status",
    )
    parsed = http.client.parse_headers(
        io.BytesIO(headers.split(b"\r\n", 1)[1] + b"\r\n\r\n")
    )
    require(
        int(parsed.get("Content-Length", "-1")) == len(body), "Incomplete HTTP body"
    )
    require(
        parsed.get_content_type() == "text/html"
        and parsed.get_content_charset() == "utf-8",
        "Unexpected content type",
    )
    require(
        parsed.get("Connection", "").lower() == "close", "Unexpected connection policy"
    )
    require(
        body.startswith(b"<!doctype html>") and body.endswith(b"</html>"),
        "Incomplete HTML",
    )
    return body


def validate_capture(path, flows, expected=None):
    require(
        Path(path).stat().st_size <= 20 * 1024 * 1024,
        "Peer capture exceeds 20 MiB bound",
    )
    raw = Path(path).read_bytes()
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(raw[:4])
    require(endian and len(raw) >= 24, "Invalid pcap")
    cursor, checked, http_checked = 24, 0, 0
    while cursor < len(raw):
        require(cursor + 16 <= len(raw), "Truncated pcap record")
        _, _, size, original = struct.unpack_from(endian + "IIII", raw, cursor)
        cursor += 16
        require(
            size == original and cursor + size <= len(raw), "Truncated captured frame"
        )
        frame = raw[cursor : cursor + size]
        cursor += size
        if len(frame) < 34 or frame[12:14] != b"\x08\0":
            continue
        ip = frame[14:]
        h = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], "big")
        require(ip[0] >> 4 == 4 and 20 <= h <= total <= len(ip), "Captured IPv4 bounds")
        require(independent_checksum(ip[:h]) == 0, "Captured IPv4 checksum")
        if ip[9] == 6:
            tcp = ip[h:total]
            require(len(tcp) >= 20, "Captured TCP bounds")
            require(
                independent_checksum(
                    ip[12:20] + b"\0\6" + struct.pack("!H", len(tcp)) + tcp
                )
                == 0,
                "Captured TCP checksum, including client final ACK",
            )
            checked += 1
            header = (tcp[12] >> 4) * 4
            require(20 <= header <= len(tcp), "Captured TCP header bounds")
            if int.from_bytes(tcp[:2], "big") == 80 and len(tcp) > header:
                payload = tcp[header:]
                validate_http(payload)
                require(
                    expected is None or payload == expected,
                    "Captured HTTP response changed",
                )
                http_checked += 1
    for row in flows:
        frames = row["frames"]
        require(
            [f["flags"] for f in frames] == [2, 18, 25, 25, 16],
            "Capture is not exactly five frames",
        )
        syn, synack, request, response, final = frames
        c = (syn["sequence"] + 1) & 0xFFFFFFFF
        s = (synack["sequence"] + 1) & 0xFFFFFFFF
        end = (c + request["payload_bytes"] + 1) & 0xFFFFFFFF
        require(
            syn["payload_bytes"]
            == synack["payload_bytes"]
            == final["payload_bytes"]
            == 0,
            "Unexpected handshake/ACK payload",
        )
        require(
            synack["ack"] == c and request["sequence"] == c and request["ack"] == s,
            "Captured handshake/request sequence mismatch",
        )
        require(
            response["sequence"] == s and response["ack"] == end,
            "Captured response sequence mismatch",
        )
        require(
            final["sequence"] == end
            and final["ack"] == (s + response["payload_bytes"] + 1) & 0xFFFFFFFF,
            "Captured final FIN acknowledgement mismatch",
        )
    require(checked == len(flows) * 5, "Extra or missing captured TCP frames")
    require(http_checked == len(flows), "Missing captured complete HTTP responses")
    return checked


class Peer:
    def __init__(self, port, checksum_function=checksum):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket.settimeout(5)
        self.incoming = bytearray()
        self.mac = bytes.fromhex("020000000002")
        self.guest_mac = None
        self.host = socket.inet_aton("10.0.2.2")
        self.guest = socket.inet_aton("10.0.2.15")
        self.configured = False
        self.ident = 0
        self.checksum = checksum_function
        self.oracle_ns = 0
        self.construct_ns = 0

    def exact(self, size):
        while len(self.incoming) < size:
            data = self.socket.recv(65536)
            if not data:
                raise EOFError("Packet peer disconnected mid-frame")
            self.incoming.extend(data)
        result = bytes(self.incoming[:size])
        del self.incoming[:size]
        return result

    def send_ip(self, protocol, data, destination=None, destination_mac=None):
        begun = time.perf_counter_ns()
        self.ident = (self.ident + 1) & 65535
        ip = bytearray(
            struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                20 + len(data),
                self.ident,
                0,
                64,
                protocol,
                0,
                self.host,
                destination or self.guest,
            )
        )
        ip[10:12] = struct.pack("!H", self.checksum(ip))
        frame = (destination_mac or self.guest_mac) + self.mac + b"\x08\0" + ip + data
        self.construct_ns += time.perf_counter_ns() - begun
        self.socket.sendall(struct.pack("!I", len(frame)) + frame)

    def send_tcp(self, port, seq, ack, flags, data=b"", options=b""):
        begun = time.perf_counter_ns()
        tcp = bytearray(
            struct.pack(
                "!HHIIBBHHH",
                port,
                80,
                seq & 0xFFFFFFFF,
                ack & 0xFFFFFFFF,
                ((20 + len(options)) // 4) << 4,
                flags,
                4096,
                0,
                0,
            )
            + options
            + data
        )
        pseudo = self.host + self.guest + b"\0\6" + struct.pack("!H", len(tcp))
        tcp[16:18] = struct.pack("!H", self.checksum(pseudo + tcp))
        self.construct_ns += time.perf_counter_ns() - begun
        self.send_ip(6, tcp)

    def dhcp(self, udp):
        require(len(udp) >= 248, "Truncated DHCP")
        boot = udp[8:]
        require(boot[236:240] == bytes.fromhex("63825363"), "Invalid DHCP cookie")
        self.guest_mac = boot[28:34]
        options, position, message = boot[240:], 0, None
        while position < len(options):
            tag = options[position]
            position += 1
            if tag == 255:
                break
            if tag == 0:
                continue
            require(position < len(options), "Truncated DHCP option size")
            size = options[position]
            position += 1
            require(position + size <= len(options), "Truncated DHCP option")
            if tag == 53:
                require(size == 1, "Invalid DHCP message option")
                message = options[position]
            position += size
        require(message in (1, 3), "Unexpected DHCP message")
        reply = bytearray(240)
        reply[:4] = bytes([2, 1, 6, 0])
        reply[4:8] = boot[4:8]
        reply[16:20] = self.guest
        reply[28:34] = self.guest_mac
        reply[236:240] = bytes.fromhex("63825363")
        reply += bytes([53, 1, 2 if message == 1 else 5, 54, 4]) + self.host
        reply += (
            bytes([1, 4])
            + bytes.fromhex("ffffff00")
            + bytes([51, 4])
            + struct.pack("!I", 3600)
            + b"\xff"
        )
        packet = struct.pack("!HHHH", 67, 68, len(reply) + 8, 0) + reply
        self.send_ip(17, packet, b"\xff" * 4, b"\xff" * 6)
        self.configured = message == 3

    def receive(self):
        size = struct.unpack("!I", self.exact(4))[0]
        require(14 <= size <= 65536, "Invalid peer Ethernet frame length")
        frame = self.exact(size)
        if frame[12:14] == b"\x08\x06":
            # DHCP/subnet peers can still ask ARP; answer our actual address.
            arp = frame[14:]
            if (
                len(arp) >= 28
                and arp[:8] == bytes.fromhex("0001080006040001")
                and arp[24:28] == self.host
            ):
                answer = (
                    frame[6:12]
                    + self.mac
                    + b"\x08\x06"
                    + bytes.fromhex("0001080006040002")
                )
                answer += self.mac + self.host + arp[8:18]
                self.socket.sendall(struct.pack("!I", len(answer)) + answer)
            return None
        require(
            frame[12:14] == b"\x08\0" and len(frame) >= 34,
            "Unexpected Ethernet protocol",
        )
        begun = time.perf_counter_ns()
        ip = frame[14:]
        h = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], "big")
        require(ip[0] >> 4 == 4 and 20 <= h <= total <= len(ip), "Invalid IPv4 bounds")
        require(not int.from_bytes(ip[6:8], "big") & 0x3FFF, "Unexpected IPv4 fragment")
        require(self.checksum(ip[:h]) == 0, "Invalid IPv4 checksum")
        data = ip[h:total]
        self.oracle_ns += time.perf_counter_ns() - begun
        if ip[9] == 17:
            require(
                len(data) >= 8 and struct.unpack("!HH", data[:4]) == (68, 67),
                "Unexpected UDP service",
            )
            self.dhcp(data)
            return None
        require(ip[9] == 6, "Unexpected guest IP service")
        begun = time.perf_counter_ns()
        require(
            ip[12:16] == self.guest and ip[16:20] == self.host,
            "Incorrect peer IP endpoints",
        )
        require(len(data) >= 20, "Truncated TCP header")
        require(
            self.checksum(ip[12:20] + b"\0\6" + struct.pack("!H", len(data)) + data)
            == 0,
            "Invalid TCP checksum",
        )
        th = (data[12] >> 4) * 4
        require(20 <= th <= len(data), "Invalid TCP header length")
        result = (*struct.unpack("!HHII", data[:12]), data[13], data[th:])
        self.oracle_ns += time.perf_counter_ns() - begun
        return result

    def tcp(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            packet = self.receive()
            if packet is not None:
                return packet
        raise TimeoutError("No guest TCP response")

    def request(self, port, isn, expected=None, defer_http_oracle=False):
        request = b"GET / HTTP/1.1\r\nHost: peer\r\n\r\n"
        begun = time.perf_counter_ns()
        self.send_tcp(port, isn, 0, 2, options=bytes.fromhex("020405b4"))
        source, dest, seq, ack, flags, data = self.tcp()
        require(
            (source, dest, ack, flags, data)
            == (80, port, (isn + 1) & 0xFFFFFFFF, 0x12, b""),
            "Unexpected SYN/ACK",
        )
        server_seq = (seq + 1) & 0xFFFFFFFF
        client_seq = (isn + 1) & 0xFFFFFFFF
        self.send_tcp(port, client_seq, server_seq, 0x19, request)
        client_seq = (client_seq + len(request) + 1) & 0xFFFFFFFF
        source, dest, seq, ack, flags, data = self.tcp()
        check = time.perf_counter_ns()
        require(
            (source, dest, seq, ack, flags) == (80, port, server_seq, client_seq, 0x19),
            "Incorrect response/FIN sequence",
        )
        if not defer_http_oracle or expected is None:
            validate_http(data)
        require(expected is None or data == expected, "Actual response changed")
        self.oracle_ns += time.perf_counter_ns() - check
        self.send_tcp(port, client_seq, (server_seq + len(data) + 1) & 0xFFFFFFFF, 0x10)
        return data, (time.perf_counter_ns() - begun) / 1e9


def run(
    image,
    symbols,
    requests=1000,
    seed=24326,
    acceleration="tcg",
    boot_kernel=None,
    checksum_function=checksum,
    defer_http_oracle=False,
):
    require(
        type(requests) is int and 1 <= requests <= 10000, "requests must be 1..10000"
    )
    require(
        type(defer_http_oracle) is bool, "Deferred HTTP oracle flag must be boolean"
    )
    launched = start(
        timeout=180,
        paused=True,
        manual=True,
        image=image,
        symbols=symbols,
        mode="long64",
        memory=64,
        network="peer",
        timing="realtime",
        nic_model="e1000e",
        minimal_devices=True,
        nic_rom=False,
        acceleration=acceleration,
        boot_kernel=boot_kernel,
    )
    require(launched.get("ok"), "VM owner launch failed: " + json.dumps(launched))
    rid = launched["run_id"]
    directory = get_run(rid)
    result = {
        "ok": False,
        "run_id": rid,
        "scope": "Fresh five-frame guest TCP connections over one host packet-peer stream. Client construction/checks included; no NAT. Compare only this same backend.",
    }
    peer = None
    samples = []
    try:
        manifest = json.loads((directory / "manifest.json").read_text())
        peer = Peer(manifest["peer_port"], checksum_function)
        reply = call(rid, {"operation": "debug", "action": "resume"})
        require(reply.get("ok"), "VM could not resume")
        deadline = time.monotonic() + 15
        while not peer.configured:
            require(time.monotonic() < deadline, "DHCP configuration timeout")
            require(peer.receive() is None, "TCP before DHCP configuration")
        randomizer = random.Random(seed)
        inputs = [randomizer.getrandbits(32) for _ in range(requests + 1)]
        (directory / "peer-inputs.json").write_text(
            json.dumps(
                {
                    "seed": seed,
                    "client_isns": inputs,
                    "ports": list(range(40000, 40000 + requests + 1)),
                }
            )
        )
        expected, _ = peer.request(40000, inputs[0])
        (directory / "peer-response.bin").write_bytes(expected)
        peer.oracle_ns = peer.construct_ns = 0
        cpu = time.process_time()
        begun = time.perf_counter()
        samples = []
        for i in range(requests):
            _, elapsed = peer.request(
                40001 + i, inputs[i + 1], expected, defer_http_oracle
            )
            samples.append(elapsed)
        elapsed = time.perf_counter() - begun
        cpu = time.process_time() - cpu
        oracle, construct = peer.oracle_ns / 1e9, peer.construct_ns / 1e9
        peer.socket.close()
        peer = None
        stopped = call(rid, {"operation": "stop"})
        require(stopped.get("ok"), "Owned VM stop failed")
        deadline = time.monotonic() + 15
        while (
            json.loads((directory / "status.json").read_text())["state"] != "finished"
        ):
            require(time.monotonic() < deadline, "VM cleanup timeout")
            time.sleep(0.01)
        state = json.loads((directory / "status.json").read_text())
        require(state.get("ok") and state.get("exit_code") == 0, "Unexpected VM exit")
        wire = wire_cost(directory / "network.pcap", expected)
        flows = analyze(directory / "network.pcap")["tcp_connections"]
        require(len(flows) == requests + 1, "Incorrect connection capture count")
        capture_oracle_begun = time.perf_counter()
        captured_checked = validate_capture(directory / "network.pcap", flows, expected)
        capture_oracle_seconds = time.perf_counter() - capture_oracle_begun
        require(
            wire["matched_response_flows"] == requests + 1,
            "Capture response reconstruction failed",
        )
        require(
            not any(
                json.loads(line)["event"] == "RESET"
                for line in (directory / "events.jsonl").read_text().splitlines()
            ),
            "Unexpected guest reset",
        )
        require(
            not (directory / "serial.log").read_bytes()
            and not (directory / "early.log").read_bytes(),
            "Expected production image without guest diagnostic output",
        )
        result.update(
            ok=True,
            image_sha256=manifest["image_sha256"],
            symbols_sha256=digest(directory / "boot.elf"),
            boot_route=manifest["machine"]["boot_route"],
            requests=requests,
            seed=seed,
            elapsed_seconds=elapsed,
            requests_per_second=requests / elapsed,
            client_cpu_seconds=cpu,
            packet_oracle_seconds=oracle,
            packet_construct_seconds=construct,
            client_median_seconds=statistics.median(samples),
            client_p99_seconds=sorted(samples)[int(0.99 * (len(samples) - 1))],
            response_sha256=hashlib.sha256(expected).hexdigest(),
            wire=wire,
            five_frame_connections=requests + 1,
            captured_checksum_frames=captured_checked,
            checksum_backend="authored-native"
            if isinstance(checksum_function, NativeChecksum)
            else "python",
            checksum_helper=getattr(checksum_function, "metadata", None),
            http_oracle_scope=(
                "Warmup fully parsed; every measured reply byte-exact inline; every captured response parsed after load"
                if defer_http_oracle
                else "Every reply parsed inline and every captured response parsed after load"
            ),
            defer_http_oracle=defer_http_oracle,
            post_load_capture_oracle_seconds=capture_oracle_seconds,
            captured_http_parses=len(flows),
        )
    except Exception as error:
        result["error"] = str(error) or type(error).__name__
        result["capture"] = call(rid, {"operation": "capture", "mode": "long64"})
    finally:
        if peer:
            peer.socket.close()
        if not result["ok"]:
            result["stop"] = call(rid, {"operation": "stop"})
        (directory / "peer-samples.json").write_text(json.dumps(samples))
        (directory / "peer-verdict.json").write_text(json.dumps(result, indent=2))
    return result


def retain_build_provenance(image, symbols, boot_kernel, output):
    image, symbols, output = (
        Path(image).resolve(),
        Path(symbols).resolve(),
        Path(output),
    )
    output.mkdir(parents=True, exist_ok=False)
    record = {
        "image_sha256": digest(image),
        "symbols_sha256": digest(symbols),
        "retained_unix_seconds": time.time(),
        "retainer_source_sha256": digest(Path(__file__)),
        "scope": "Available build metadata only; no verified guest-source snapshot claimed",
        "metadata": {},
        "verified_guest_sources": {},
    }
    manifest = None
    for name in (
        "manifest.json",
        "source-inputs.json",
        "build-config",
        "packing-proof.json",
    ):
        path = image.parent / name
        if not path.exists():
            continue
        require(
            path.is_file()
            and not path.is_symlink()
            and path.stat().st_size <= 2 * 1024 * 1024,
            "Invalid/symlink/excessive build metadata: " + name,
        )
        content = path.read_bytes()
        (output / name).write_bytes(content)
        record["metadata"][name] = hashlib.sha256(content).hexdigest()
        if name == "manifest.json":
            manifest = json.loads(content)
    if boot_kernel:
        path = Path(boot_kernel).resolve().parent / "pvh-inputs.json"
        require(
            path.is_file()
            and not path.is_symlink()
            and path.stat().st_size <= 2 * 1024 * 1024,
            "Invalid PVH metadata",
        )
        content = path.read_bytes()
        (output / "pvh-inputs.json").write_bytes(content)
        record["metadata"]["pvh-inputs.json"] = hashlib.sha256(content).hexdigest()
    raw = isinstance(manifest, dict) and (
        "writer_sha256" in manifest
        or str(manifest.get("route", "")).startswith("hand-placed hexadecimal")
    )
    if raw:
        require(
            manifest.get("image_sha256") == record["image_sha256"],
            "Raw build manifest image SHA mismatch",
        )
        sources = manifest.get("sources")
        require(
            isinstance(sources, dict) and 0 < len(sources) <= 512,
            "Missing/excessive raw source manifest",
        )
        snapshot = image.parent / "sources"
        require(
            snapshot.is_dir() and not snapshot.is_symlink(),
            "Missing/symlink raw source snapshot",
        )
        total = 0
        for relative, expected in sources.items():
            require(
                isinstance(relative, str)
                and isinstance(expected, str)
                and re.fullmatch("[0-9a-f]{64}", expected),
                "Invalid raw source hash record",
            )
            parts = Path(relative).parts
            require(
                parts
                and not Path(relative).is_absolute()
                and ".." not in parts
                and parts[:2] == ("src", "raw"),
                "Raw source path escapes src/raw snapshot",
            )
            source = snapshot
            for part in parts:
                source = source / part
                require(not source.is_symlink(), "Symlink raw source import rejected")
            require(
                source.resolve().is_relative_to(snapshot.resolve())
                and source.is_file()
                and source.stat().st_size <= 2 * 1024 * 1024,
                "Raw source is outside/beyond bounded snapshot",
            )
            content = source.read_bytes()
            total += len(content)
            require(total <= 8 * 1024 * 1024, "Raw source snapshot exceeds 8 MiB")
            require(
                hashlib.sha256(content).hexdigest() == expected,
                "Raw source snapshot hash mismatch: " + relative,
            )
            target = output / "sources" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            record["verified_guest_sources"][relative] = expected
        record["scope"] = (
            "Raw build manifest image hash and every bounded non-symlink captured guest source verified and retained"
        )
    (output / "provenance.json").write_text(json.dumps(record, indent=2))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--defer-http-oracle",
        action="store_true",
        help="Parse warmup fully, compare every reply exactly inline, then parse every captured response outside load timing",
    )
    parser.add_argument(
        "--native-checksum",
        action="store_true",
        help="Build and verify authored host C checksum helper; default remains Python",
    )
    parser.add_argument(
        "--checksum-compiler",
        help="Absolute host compiler executable; requires --native-checksum",
    )
    parser.add_argument("--image", required=True)
    parser.add_argument("--symbols", required=True)
    parser.add_argument("--boot-kernel")
    parser.add_argument("--compare-image")
    parser.add_argument("--compare-symbols")
    parser.add_argument("--compare-boot-kernel")
    parser.add_argument("--output", required=True)
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--seed", type=int, default=24326)
    parser.add_argument("--acceleration", choices=["tcg", "kvm"], default="tcg")
    args = parser.parse_args()
    require(
        1 <= args.repeat <= 10 and 1 <= args.requests <= 10000,
        "repeat 1..10 and requests 1..10000 required",
    )
    require(
        bool(args.compare_image) == bool(args.compare_symbols),
        "Comparison requires both image and symbols",
    )
    require(
        not args.compare_boot_kernel or args.compare_image,
        "Comparison kernel requires comparison image",
    )
    require(
        not args.checksum_compiler or args.native_checksum,
        "checksum-compiler requires native-checksum",
    )
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    plan = vars(args).copy()
    checksum_function = (
        build_native_checksum(output / "tools", args.checksum_compiler)
        if args.native_checksum
        else checksum
    )
    if args.native_checksum:
        plan["checksum_helper"] = checksum_function.metadata
    for key in [
        "image",
        "symbols",
        "boot_kernel",
        "compare_image",
        "compare_symbols",
        "compare_boot_kernel",
    ]:
        if plan.get(key):
            plan[key + "_sha256"] = digest(plan[key])
    (output / "plan.json").write_text(json.dumps(plan, indent=2))
    variants = {"candidate": (args.image, args.symbols, args.boot_kernel)}
    if args.compare_image:
        variants["baseline"] = (
            args.compare_image,
            args.compare_symbols,
            args.compare_boot_kernel,
        )
    plan["build_provenance"] = {
        name: retain_build_provenance(
            image, symbols, kernel, output / "provenance" / name
        )
        for name, (image, symbols, kernel) in variants.items()
    }
    (output / "plan.json").write_text(json.dumps(plan, indent=2))
    results = {name: [] for name in variants}
    for repetition in range(args.repeat):
        order = list(variants)
        if repetition & 1:
            order.reverse()
        for name in order:
            image, symbols, kernel = variants[name]
            verdict = run(
                image,
                symbols,
                args.requests,
                args.seed + repetition,
                args.acceleration,
                kernel,
                checksum_function,
                args.defer_http_oracle,
            )
            (output / f"{name}-{repetition}.json").write_text(
                json.dumps(verdict, indent=2)
            )
            require(verdict["ok"], "Real peer benchmark failed: " + json.dumps(verdict))
            prefix = "compare_" if name == "baseline" else ""
            require(
                verdict["image_sha256"] == plan[prefix + "image_sha256"],
                "Image differs from retained comparison plan",
            )
            require(
                verdict["symbols_sha256"] == plan[prefix + "symbols_sha256"],
                "Symbols differ from retained comparison plan",
            )
            results[name].append(verdict)
    hashes = {row["response_sha256"] for rows in results.values() for row in rows}
    require(len(hashes) == 1, "Matched variants returned different actual responses")
    report = {
        "ok": True,
        "scope": "Matched packet-peer backend only; host packet construction/oracles included.",
        "variants": {},
    }
    for name, rows in results.items():
        require(
            len({row["image_sha256"] for row in rows}) == 1,
            "Image changed between repetitions",
        )
        report["variants"][name] = {
            "runs": [row["run_id"] for row in rows],
            "requests_per_second": sum(row["requests"] for row in rows)
            / sum(row["elapsed_seconds"] for row in rows),
            "client_median_seconds": [row["client_median_seconds"] for row in rows],
            "packet_oracle_seconds": [row["packet_oracle_seconds"] for row in rows],
            "packet_construct_seconds": [
                row["packet_construct_seconds"] for row in rows
            ],
        }
    if "baseline" in results:
        report["throughput_ratio"] = (
            report["variants"]["candidate"]["requests_per_second"]
            / report["variants"]["baseline"]["requests_per_second"]
        )
    (output / "summary.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1)
