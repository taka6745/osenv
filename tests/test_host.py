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

    def test_fragmented_panic_waits_for_complete_record(self):
        from osenv.protocol import panic_record_ready
        for record in [b'OSE1 PANIC vector=6\n', b'OSL1 PANIC vector=6 error=0 rip=0x100042\n']:
            for end in range(len(record)):
                self.assertFalse(panic_record_ready(record[:end]))
            self.assertTrue(panic_record_ready(record))
        self.assertFalse(panic_record_ready(b'OSL1 LOG text=OSL1 PANIC vector=6\n'))

    def test_wire_reassembly_wrap_duplicates_and_corruption(self):
        import struct
        from osenv.project import wire_evidence
        content=b'HTTP/1.0 200 OK\r\n\r\nbody'
        def record(offset, data):
            ip=bytearray(20);ip[0]=0x45;ip[9]=6
            ip[2:4]=(40+len(data)).to_bytes(2,'big')
            ip[12:16]=bytes([192,0,2,1]);ip[16:20]=bytes([10,0,2,15])
            tcp=bytearray(20);tcp[0:2]=(80).to_bytes(2,'big');tcp[2:4]=(55000).to_bytes(2,'big')
            tcp[4:8]=((0xfffffff0+offset)&0xffffffff).to_bytes(4,'big');tcp[12]=0x50
            frame=bytes(12)+b'\x08\x00'+ip+tcp+data
            return struct.pack('<IIII',0,0,len(frame),len(frame))+frame
        header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65536,1)
        good=header+record(12,content[12:])+record(0,content[:12])+record(0,content[:12])
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'network.pcap';path.write_bytes(good)
            result=wire_evidence(path)
            self.assertEqual(result['responses'][0]['bytes'],len(content))
            self.assertTrue(result['responses'][0]['http_header'])
            self.assertEqual(len(result['responses']),1)
            path.write_bytes(good+record(0,b'X'))
            with self.assertRaises(ValueError):wire_evidence(path)
            path.write_bytes(good[:-1])
            with self.assertRaises(ValueError):wire_evidence(path)

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
