"""Malformed loader/provenance rejection; not an OS boot acceptance substitute."""

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from osenv.worker import validate_pvh, start


class PVHValidationTests(unittest.TestCase):
    def inputs(self, root):
        # ELF metadata only: this cannot execute and is never booted.
        raw = bytearray(104)
        raw[:7] = b"\x7fELF\x01\x01\x01"
        struct.pack_into("<HHI", raw, 16, 2, 3, 1)
        struct.pack_into("<I", raw, 28, 52)
        struct.pack_into("<HH", raw, 42, 32, 1)
        struct.pack_into("<IIIII", raw, 52, 4, 84, 0, 0, 20)
        struct.pack_into("<III", raw, 84, 4, 4, 18)
        raw[96:100] = b"Xen\0"
        struct.pack_into("<I", raw, 100, 0x10000)
        for name, contents in [
            ("pvh.elf", raw),
            ("oslab.img", b"disk"),
            ("kernel.elf", b"symbols"),
        ]:
            (root / name).write_bytes(contents)
        self.record(root)
        return root / "pvh.elf", root / "oslab.img", root / "kernel.elf"

    def record(self, root):
        artifacts = {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["pvh.elf", "oslab.img", "kernel.elf"]
        }
        (root / "pvh-inputs.json").write_text(
            json.dumps({"generated_artifacts": artifacts})
        )

    def test_metadata_accepted_then_hash_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.inputs(root)
            self.assertEqual(validate_pvh(*args)[0], args[0].resolve())
            for name in ["pvh.elf", "oslab.img", "kernel.elf"]:
                prior = (root / name).read_bytes()
                (root / name).write_bytes(prior + b"x")
                with self.assertRaises(ValueError):
                    validate_pvh(*args)
                (root / name).write_bytes(prior)

    def test_bad_headers_notes_and_missing_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.inputs(root)
            good = args[0].read_bytes()
            for offset, replacement in [
                (4, b"\x02"),
                (42, b"\x00\x00"),
                (44, b"\xff\xff"),
                (92, b"\x00\x00\x00\x00"),
                (88, b"\xff\xff\xff\xff"),
            ]:
                bad = bytearray(good)
                bad[offset : offset + len(replacement)] = replacement
                args[0].write_bytes(bad)
                self.record(root)
                with self.assertRaises(ValueError):
                    validate_pvh(*args)
            args[0].write_bytes(good)
            (root / "pvh-inputs.json").unlink()
            with self.assertRaises(ValueError):
                validate_pvh(*args)

    def test_pvh_wrong_mode_rejected_before_run(self):
        with tempfile.TemporaryDirectory() as directory:
            disk = Path(directory) / "disk.img"
            disk.write_bytes(b"\0" * 510 + b"\x55\xaa")
            with self.assertRaisesRegex(ValueError, "PVH requires manual long64"):
                start(manual=True, image=disk, boot_kernel="/nonexistent/pvh")

    def test_preload_requires_boolean_and_actual_hashed_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.inputs(root)
            path = root / "pvh-inputs.json"
            record = json.loads(path.read_text())
            for flag in ["true", 1, 0, None, []]:
                record["preload"] = flag
                path.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, "must be a boolean"):
                    validate_pvh(*args)
            record["preload"] = True
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "kernel.bin"):
                validate_pvh(*args)
            payload = root / "kernel.bin"
            payload.write_bytes(b"payload metadata, never executed")
            record["generated_artifacts"]["kernel.bin"] = hashlib.sha256(payload.read_bytes()).hexdigest()
            path.write_text(json.dumps(record))
            validate_pvh(*args)
            payload.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "hash mismatch: kernel.bin"):
                validate_pvh(*args)

    def test_preload_payload_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.inputs(root)
            path = root / "pvh-inputs.json"
            record = json.loads(path.read_text())
            record["preload"] = True
            for size in [0, 1, 524288, 524289]:
                payload = b"x" * size
                (root / "kernel.bin").write_bytes(payload)
                record["generated_artifacts"]["kernel.bin"] = hashlib.sha256(payload).hexdigest()
                path.write_text(json.dumps(record))
                if size in [1, 524288]:
                    validate_pvh(*args)
                else:
                    with self.assertRaisesRegex(ValueError, "1..524288 bytes"):
                        validate_pvh(*args)
