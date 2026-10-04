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
