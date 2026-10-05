"""Raw capture conservation across sparse blocks, tails and actual file reads."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from .core import compact_memory

class CaptureStorageTests(unittest.TestCase):
    def test_zero_dense_boundary_and_tail_bytes_unchanged(self):
        for content in [b'',bytes(131073),bytes(65536)+b'fault'+bytes(65537),bytes(range(256))*513]:
            with self.subTest(length=len(content)), tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'memory.bin';path.write_bytes(content)
                stamp=path.stat().st_mtime_ns;record=compact_memory(path)
                self.assertEqual(path.read_bytes(),content)
                self.assertEqual(path.stat().st_mtime_ns,stamp)
                self.assertEqual(record['bytes'],len(content))
                self.assertEqual(record['sha256'],hashlib.sha256(content).hexdigest())
                self.assertFalse(list(Path(directory).glob('memory-sparse-*')))
    def test_missing_capture_remains_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):compact_memory(Path(directory)/'missing')

if __name__=='__main__':unittest.main()
