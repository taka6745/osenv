import argparse, json, subprocess, time, random, math
from functools import lru_cache
from pathlib import Path
from osenv.worker import start
from osenv.core import get_run
from osenv.__main__ import call


def unpack(data):
    out = bytearray()
    cursor = 0
    while cursor < len(data):
        tag = data[cursor]
        cursor += 1
        if tag < 128:
            count = tag + 1
            if cursor + count > len(data):
                raise ValueError("literal truncated")
            out.extend(data[cursor : cursor + count])
            cursor += count
        else:
            count = (tag & 127) + 3
            if cursor + 2 > len(data):
                raise ValueError("offset truncated")
            offset = int.from_bytes(data[cursor : cursor + 2], "little")
            cursor += 2
            if not offset or offset > len(out):
                raise ValueError("offset outside output")
            for _ in range(count):
                out.append(out[-offset])
    return bytes(out)


def test(build, report):
    if not __debug__:
        raise RuntimeError("Acceptance requires Python assertions enabled")
    p = Path(build).resolve()
    size = (p / "kernel.bin").stat().st_size
    encoder = p / "pack-test"
    subprocess.run(
        [
            "/opt/homebrew/opt/llvm/bin/clang",
            "-std=c11",
            "-O1",
            "-g",
            "-fsanitize=address,undefined",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(Path("../oslab/boot/pack.c").resolve()),
            "-o",
            str(encoder),
        ],
        check=True,
    )
    rng = random.Random(0x5EED)
    # Independent exhaustive short-input oracle, including all legal offsets.
    optimal_cases = 0
    for count in range(1, 33):
        data = bytes(rng.randrange(3) for _ in range(count))

        @lru_cache(None)
        def minimum(cursor):
            if cursor == len(data):
                return 0
            result = min(
                1 + n + minimum(cursor + n)
                for n in range(1, min(128, len(data) - cursor) + 1)
            )
            for offset in range(1, cursor + 1):
                length = 0
                while (
                    length < min(130, len(data) - cursor)
                    and data[cursor + length] == data[cursor + length - offset]
                ):
                    length += 1
                for n in range(3, length + 1):
                    result = min(result, 3 + minimum(cursor + n))
            return result

        encoded = subprocess.run(
            [str(encoder)], input=data, capture_output=True, check=True
        ).stdout
        assert unpack(encoded) == data and len(encoded) == minimum(0)
        optimal_cases += 1
    roundtrips = []
    for invalid in (b"", bytes(524289)):
        result = subprocess.run([str(encoder)], input=invalid, capture_output=True)
        assert result.returncode != 0 and not result.stdout
    for n in (1, 2, 3, 127, 128, 129, 130, 131, 2048, 65535, 65536, 524288):
        data = (
            bytes(rng.randrange(256) for _ in range(n))
            if n < 3000
            else b"abcdefgh" * (n // 8) + b"abcdefgh"[: n % 8]
        )
        encoded = subprocess.run(
            [str(encoder)], input=data, capture_output=True, check=True
        ).stdout
        assert unpack(encoded) == data
        roundtrips.append({"bytes": n, "encoded_bytes": len(encoded)})
    # Force the maximum backward distance, then one byte outside the window.
    for offset in (65535, 65536):
        data = b"\x01\x02\x03" + bytes(offset - 3) + b"\x01\x02\x03"
        encoded = subprocess.run(
            [str(encoder)], input=data, capture_output=True, check=True
        ).stdout
        assert unpack(encoded) == data
        cursor = 0
        offsets = []
        while cursor < len(encoded):
            tag = encoded[cursor]
            cursor += 1
            if tag < 128:
                cursor += tag + 1
            else:
                offsets.append(int.from_bytes(encoded[cursor : cursor + 2], "little"))
                cursor += 2
        assert (65535 in offsets) == (offset == 65535)
        roundtrips.append(
            {
                "bytes": len(data),
                "encoded_bytes": len(encoded),
                "forced_distance": offset,
            }
        )
    original = (p / "oslab.img").read_bytes()
    payload = (p / "kernel.payload").read_bytes()
    n = len(payload)
    assert unpack(payload) == (p / "kernel.bin").read_bytes()
    rid = start(
        timeout=30,
        manual=True,
        paused=True,
        image=p / "oslab.img",
        symbols=p / "kernel.elf",
        mode="long64",
        memory=64,
        network="none",
    )["run_id"]
    assert call(
        rid, {"operation": "debug", "action": "breakpoint", "address": "0x100000"}
    )["ok"]
    time.sleep(0.6)
    pc = call(rid, {"operation": "debug", "action": "evaluate", "value": "$pc"})
    assert int(pc["values"][0].split()[0], 0) == 0x100000, pc
    memory = call(
        rid,
        {
            "operation": "debug",
            "action": "memory",
            "address": "0x100000",
            "length": size,
        },
    )
    assert (
        bytes.fromhex("".join(memory["memory_hex"])) == (p / "kernel.bin").read_bytes()
    )
    loaded_run = rid
    assert call(rid, {"operation": "stop"})["ok"]

    def address(name):
        text = subprocess.run(
            ["/opt/homebrew/opt/llvm/bin/llvm-nm", str(p / "stage2.elf")],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return next(
            int(x.split()[0], 16) for x in text.splitlines() if x.split()[-1] == name
        )

    entry = address("protected_entry")
    failed = address("protected_failed.halt") + 1
    out = Path("build/packed-malformed")
    out.mkdir(exist_ok=True)
    streams = {
        "zero-offset": b"\x80\0\0",
        "offset-before-output": b"\x80\1\0",
        "output-overflow": b"\0A" + b"\xff\1\0" * math.ceil(size / 130),
        "truncated-literal": b"\1\0\0" + b"\0\0" * ((n - 4) // 2) + b"\x7f",
    }
    wrong = bytearray(payload)
    wrong[1] ^= 1
    streams["decoded-hash-mismatch"] = wrong
    checks = []
    for label, stream in streams.items():
        altered = bytearray(original)
        encoded = bytes(stream).ljust(n, b"\0")
        assert len(encoded) == n
        base = (p / "stage1.bin").stat().st_size + (p / "stage2.bin").stat().st_size
        altered[base : base + n] = encoded
        image = out / (label + ".img")
        image.write_bytes(altered)
        rid = start(
            timeout=30,
            manual=True,
            paused=True,
            image=image,
            symbols=p / "kernel.elf",
            mode="long64",
            memory=64,
            network="none",
        )["run_id"]
        assert call(
            rid, {"operation": "debug", "action": "breakpoint", "address": hex(entry)}
        )["ok"]
        time.sleep(0.6)
        pc = call(rid, {"operation": "debug", "action": "evaluate", "value": "$pc"})
        assert int(pc["values"][0].split()[0], 0) == entry, pc
        guard = b"\xa5" * 32
        assert call(
            rid,
            {
                "operation": "debug",
                "action": "write-memory",
                "address": hex(0x100000 + size),
                "value": guard.hex(),
            },
        )["ok"]
        call(rid, {"operation": "debug", "action": "delete-breakpoints"})
        call(rid, {"operation": "debug", "action": "resume"})
        time.sleep(0.1)
        pc = call(rid, {"operation": "debug", "action": "evaluate", "value": "$pc"})
        assert int(pc["values"][0].split()[0], 0) == failed, (label, pc)
        memory = call(
            rid,
            {
                "operation": "debug",
                "action": "memory",
                "address": hex(0x100000 + size),
                "length": 32,
            },
        )
        assert bytes.fromhex("".join(memory["memory_hex"])) == guard, label
        capture = call(rid, {"operation": "capture", "mode": "protected32"})
        assert capture["ok"] and capture["complete"]
        assert not (get_run(rid) / "serial.log").read_bytes()
        call(rid, {"operation": "stop"})
        checks.append(
            {
                "case": label,
                "ok": True,
                "run_id": rid,
                "output_guard_unchanged": True,
                "capture": capture,
            }
        )
    report.write_text(
        json.dumps(
            {
                "ok": True,
                "host_roundtrips": roundtrips,
                "minimum_size_oracle_cases": optimal_cases,
                "invalid_encoder_inputs_rejected": True,
                "booted_bytes_matched": size,
                "loaded_run_id": loaded_run,
                "actual_decoder_checks": checks,
            },
            indent=2,
        )
    )
    print(
        "14 sanitizer round trips and five actual assembly decoder boundary failures passed"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Actual OS boot decoder boundary tests; no fixture substitutes"
    )
    parser.add_argument("--build", required=True)
    parser.add_argument("--report", default="local/packed-boundaries.json")
    args = parser.parse_args()
    test(args.build, Path(args.report))
