"""Host profiling/parser and provenance policy regressions, never guest acceptance."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from osenv.host_perf import EVENTS, events_for_scope, parse_counters
from osenv.peer_bench import retain_build_provenance


class HostPerfTests(unittest.TestCase):
    def test_guest_scope_requires_kvm_and_preserves_host_software_events(self):
        self.assertEqual(events_for_scope("host", {"acceleration": "tcg"}), EVENTS)
        guest = events_for_scope("guest", {"acceleration": "kvm"}, True)
        self.assertIn("cycles:G", guest)
        self.assertIn("context-switches", guest)
        self.assertIn("cpu-migrations", guest)
        self.assertIn("kvm:kvm_exit", guest)
        for scope, exits in [("guest", False), ("host", True)]:
            with self.assertRaisesRegex(ValueError, "actual KVM"):
                events_for_scope(scope, {"acceleration": "tcg"}, exits)

    def test_multiplexed_counts_preserved_and_missing_or_invalid_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "stats.csv"
            valid = "\n".join(f"123;;{event};1000000;75.00;;" for event in EVENTS)
            path.write_text(valid)
            parsed = parse_counters(path)
            self.assertEqual(parsed["cycles:H"]["percent_running"], 75)
            self.assertTrue(parsed["cycles:H"]["scaled_by_perf"])
            for bad in [
                valid.split("\n", 1)[1],
                valid.replace("123;;cycles:H", "<not supported>;;cycles:H"),
                valid.replace("123;;cycles:H", "nan;;cycles:H"),
                valid + "\n" + valid.split("\n")[0],
            ]:
                path.write_text(bad)
                with self.assertRaises(ValueError):
                    parse_counters(path)


class RetainedProvenanceTests(unittest.TestCase):
    def test_raw_snapshot_rejects_changed_source_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            build.mkdir()
            image = build / "oslab.img"
            image.write_bytes(b"host policy fixture, never booted")
            symbols = build / "kernel.elf"
            symbols.write_bytes(b"host metadata fixture")
            source = build / "sources/src/raw/test.inc"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"authored host source-vector fixture")
            record = {
                "route": "hand-placed hexadecimal bytes; no compiler/assembler/linker",
                "image_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
                "sources": {
                    "src/raw/test.inc": hashlib.sha256(source.read_bytes()).hexdigest()
                },
            }
            (build / "manifest.json").write_text(json.dumps(record))
            good = retain_build_provenance(image, symbols, None, root / "good")
            self.assertEqual(good["verified_guest_sources"], record["sources"])
            original = source.read_bytes()
            source.write_bytes(original + b"x")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                retain_build_provenance(image, symbols, None, root / "changed")
            source.unlink()
            outside = root / "outside"
            outside.write_bytes(original)
            source.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "Symlink"):
                retain_build_provenance(image, symbols, None, root / "linked")

    def test_metadata_only_build_does_not_claim_verified_guest_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "oslab.img").write_bytes(b"image")
            (root / "kernel.elf").write_bytes(b"symbols")
            (root / "manifest.json").write_text(
                json.dumps({"tools": {"compiler": "recorded"}})
            )
            record = retain_build_provenance(
                root / "oslab.img", root / "kernel.elf", None, root / "retained"
            )
            self.assertFalse(record["verified_guest_sources"])
            self.assertIn("no verified guest-source snapshot claimed", record["scope"])
