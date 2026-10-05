"""Host-only compression analysis of authored guest bytes; never a boot verdict."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

CODECS = {
    "xz-16k": (
        [
            "/opt/homebrew/bin/xz",
            "--lzma2=dict=16KiB,mode=normal,nice=273,mf=bt4",
            "--check=crc32",
            "-c",
        ],
        ["/opt/homebrew/bin/xz", "-d", "-c"],
    ),
    "gzip-9": (["/usr/bin/gzip", "-n", "-9", "-c"], ["/usr/bin/gzip", "-d", "-c"]),
    "bzip2-9": (["/usr/bin/bzip2", "-9", "-c"], ["/usr/bin/bzip2", "-d", "-c"]),
    "xz-9e": (
        ["/opt/homebrew/bin/xz", "-9e", "--check=crc32", "-c"],
        ["/opt/homebrew/bin/xz", "-d", "-c"],
    ),
    "lzma-9e": (
        ["/opt/homebrew/bin/xz", "--format=lzma", "-9e", "-c"],
        ["/opt/homebrew/bin/xz", "--format=lzma", "-d", "-c"],
    ),
    "zstd-3": (
        ["/opt/homebrew/bin/zstd", "-q", "-3", "-c"],
        ["/opt/homebrew/bin/zstd", "-q", "-d", "-c"],
    ),
    "zstd-19": (
        ["/opt/homebrew/bin/zstd", "-q", "-19", "-c"],
        ["/opt/homebrew/bin/zstd", "-q", "-d", "-c"],
    ),
    "lz4-fast": (
        ["/opt/homebrew/bin/lz4", "-q", "-1", "-c"],
        ["/opt/homebrew/bin/lz4", "-q", "-d", "-c"],
    ),
    "lz4-9": (
        ["/opt/homebrew/bin/lz4", "-q", "-9", "-c"],
        ["/opt/homebrew/bin/lz4", "-q", "-d", "-c"],
    ),
}


def run(argv, data):
    return subprocess.run(argv, input=data, capture_output=True, timeout=30)


def measure(name, data, out):
    rows = []
    for codec, (compress, decompress) in CODECS.items():
        encoded = run(compress, data)
        if encoded.returncode:
            raise RuntimeError(encoded.stderr.decode(errors="replace"))
        decoded = run(decompress, encoded.stdout)
        if decoded.returncode or decoded.stdout != data:
            raise RuntimeError("Round-trip failed: " + name + "/" + codec)
        repeated = run(compress, data)
        if repeated.returncode or repeated.stdout != encoded.stdout:
            raise RuntimeError("Non-deterministic encoding: " + codec)
        truncated = run(decompress, encoded.stdout[: len(encoded.stdout) // 2])
        if truncated.returncode == 0 and truncated.stdout == data:
            raise RuntimeError("Truncated compressed input falsely accepted")
        (out / (name + "." + codec)).write_bytes(encoded.stdout)
        rows.append(
            {
                "codec": codec,
                "bytes": len(encoded.stdout),
                "saved_bytes": len(data) - len(encoded.stdout),
                "reduction_percent": 100 * (1 - len(encoded.stdout) / len(data)),
                "round_trip": True,
                "deterministic": True,
                "truncated_stream_rejected": True,
                "compressed_sha256": hashlib.sha256(encoded.stdout).hexdigest(),
                "compress_argv": compress,
                "decompress_argv": decompress,
            }
        )
    return {
        "name": name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "results": rows,
    }


def check(web, diagnostic, output):
    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    inputs = {}
    files = {}
    for label, directory in [("web", Path(web)), ("diagnostic", Path(diagnostic))]:
        for name in ["oslab.img", "kernel.bin", "stage1.bin", "stage2.bin"]:
            data = (directory / name).read_bytes()
            inputs[label + "-" + name.replace(".", "-")] = data
            files[str((directory / name).resolve())] = hashlib.sha256(data).hexdigest()
        for section in ["text", "rodata", "data"]:
            path = out / (label + "-" + section + ".bin")
            command = [
                "/opt/homebrew/opt/llvm/bin/llvm-objcopy",
                "-O",
                "binary",
                "--only-section=." + section,
                str(directory / "kernel.elf"),
                str(path),
            ]
            result = subprocess.run(command, capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError(result.stderr.decode())
            inputs[label + "-" + section] = path.read_bytes()
    ro = inputs["web-rodata"]
    response = ro[ro.index(b"HTTP/1.0 200 OK\r\n") :].split(b"\0", 1)[0]
    page = response.split(b"\r\n\r\n", 1)[1]
    if not page.startswith(b"<!doctype html>") or not page.endswith(b"</html>"):
        raise RuntimeError("Could not extract the actual linked page")
    inputs["html-page"] = page
    inputs["http-response"] = response
    rows = [measure(name, data, out) for name, data in inputs.items()]
    budgets = []
    for label in ["web", "diagnostic"]:
        boot = len(inputs[label + "-stage1-bin"]) + len(inputs[label + "-stage2-bin"])
        raw = len(inputs[label + "-oslab-img"])
        kernel = next(x for x in rows if x["name"] == label + "-kernel-bin")
        for row in kernel["results"]:
            padded = ((boot + row["bytes"] + 511) // 512) * 512
            # Padding can absorb some decoder bytes. No decoder size is assumed.
            maximum_decoder = ((raw - 1) // 512) * 512 - boot - row["bytes"]
            budgets.append(
                {
                    "image": label,
                    "codec": row["codec"],
                    "uncompressed_boot_bytes": boot,
                    "compressed_kernel_bytes": row["bytes"],
                    "sector_padded_bytes_without_decoder": padded,
                    "maximum_decoder_bytes_to_save_at_least_one_sector": maximum_decoder,
                    "bootable": False,
                }
            )
    versions = {}
    for name, argv in [
        ("gzip", ["/usr/bin/gzip", "--version"]),
        ("bzip2", ["/usr/bin/bzip2", "--help"]),
        ("xz", ["/opt/homebrew/bin/xz", "--version"]),
        ("zstd", ["/opt/homebrew/bin/zstd", "--version"]),
        ("lz4", ["/opt/homebrew/bin/lz4", "--version"]),
    ]:
        r = run(argv, b"")
        versions[name] = (r.stdout + r.stderr).decode().splitlines()[0]
    report = {
        "ok": True,
        "scope": "host compression/byte verification only; no compressed guest boot, cache or speed claim",
        "source_files": files,
        "tools": versions,
        "measurements": rows,
        "kernel_storage_budgets": budgets,
        "note": "Whole-image compression is an archive, not BIOS-bootable. Kernel budgets omit the authored decoder and changed boot metadata. Runtime RAM is unchanged after decompression; HTTP compression requires valid content negotiation.",
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    table = [
        "| Input | Raw | " + " | ".join(CODECS) + " |",
        "|---|---:|" + "---:|" * len(CODECS),
    ]
    for row in rows:
        table.append(
            "| "
            + row["name"]
            + " | "
            + str(row["bytes"])
            + " | "
            + " | ".join(str(x["bytes"]) for x in row["results"])
            + " |"
        )
    (out / "sizes.md").write_text("\n".join(table) + "\n\n" + report["note"] + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--web", required=True)
    parser.add_argument("--diagnostic", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = check(**vars(args))
    print(
        json.dumps(
            {
                "ok": report["ok"],
                "report": str(Path(args.output).resolve() / "report.json"),
                "inputs": len(report["measurements"]),
                "round_trips": len(report["measurements"]) * len(CODECS),
            }
        )
    )
