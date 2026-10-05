"""Seeded malformed-input and host interface regression checks."""
import json
from pathlib import Path
import random
import tempfile
import unittest
from osenv.core import get_run, read_cursor, validate_image
from osenv.debug import operations
from osenv.protocol import verdict


class HostTests(unittest.TestCase):
    def test_integrity_rejects_deliberate_violations(self):
        from osenv.integrity import inspect_source
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'candidate.py'
            for source in ['import requests\n', 'def f():\n    pass\n',
                           'def f():\n    ...\n', 'def f():\n    raise NotImplementedError\n']:
                path.write_text(source)
                self.assertTrue(inspect_source(path, set()), source)
            path.write_text('import os\ndef f(value):\n    return value * 7\n')
            self.assertEqual(inspect_source(path, set()), [])

    def test_audit_rejects_dependencies_and_harness_in_os(self):
        import subprocess
        from osenv.integrity import audit
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', directory], check=True, timeout=5)
            (root / 'requirements.txt').write_text('requests\n')
            self.assertFalse(audit(root)['ok'])
            (root / 'requirements.txt').unlink()
            (root / 'fixture').mkdir()
            (root / 'fixture' / 'boot.asm').write_text('bits 16\nhlt\n')
            self.assertFalse(audit(root, os_only=True)['ok'])
            self.assertTrue(audit(root)['ok'])

    def test_protocol_rejects_false_success(self):
        good = b'OSE1 BOOT real16\nOSE1 READY\nOSE1 RESULT id=1 value=42\nOSE1 DONE\n'
        self.assertTrue(verdict(good, 33, [])['ok'])
        for candidate in [good[:-1][:-8], good+good, good.replace(b'42', b'41'), b'PASS\n']:
            self.assertFalse(verdict(candidate, 33, [])['ok'])
        for code in [0, 1, 35, None]:
            self.assertFalse(verdict(good, code, [])['ok'])
        self.assertFalse(verdict(good, 33, [{'event': 'RESET'}])['ok'])
        self.assertFalse(verdict(good, 33, [], True)['ok'])

    def test_seeded_protocol_fuzz(self):
        rng = random.Random(7)
        for _ in range(5000):
            raw = rng.randbytes(rng.randrange(1024))
            result = verdict(raw, rng.choice([None, 0, 33, 35]), [])
            self.assertFalse(result['ok'])

    def test_cursor_and_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'log'
            p.write_bytes(b'abc\n\xffdef')
            first = read_cursor(p, 0, 4)
            second = read_cursor(p, first['cursor'], 4)
            self.assertEqual(first, {'cursor': 4, 'text': 'abc\n'})
            self.assertEqual(second['cursor'], 8)
            for cursor, length in [(-1, 1), (0, 0), (0, 1048577)]:
                with self.assertRaises(ValueError):
                    read_cursor(p, cursor, length)

    def test_invalid_debug_input(self):
        for address in ['-1', str(2**64), '0;quit']:
            with self.assertRaises(ValueError):
                operations('memory', address)
        for length in [0, -1, 65537]:
            with self.assertRaises(ValueError):
                operations('memory', '0', length)
        for value in ['zz', '0', '00\n-gdb-exit']:
            with self.assertRaises(ValueError):
                operations('write-memory', '0', value=value)
        with self.assertRaises(ValueError):
            get_run('../../')


if __name__ == '__main__':
    unittest.main()
