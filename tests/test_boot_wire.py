import struct
import tempfile
import unittest
from pathlib import Path
from osenv.boot_wire import analyze


class BootWireTests(unittest.TestCase):
    def test_truncated_records_cannot_claim_small_exchange(self):
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "capture.pcap"
            for payload in [b"\0", struct.pack("<IIII", 0, 0, 54, 54) + b"\0" * 53]:
                p.write_bytes(header + payload)
                with self.assertRaises(ValueError):
                    analyze(p)

    def test_invalid_tcp_header_cannot_claim_data(self):
        ethernet = b"\0" * 12 + b"\x08\0"
        ip = bytearray(20)
        ip[0] = 0x45
        ip[2:4] = struct.pack("!H", 40)
        ip[9] = 6
        tcp = bytearray(20)
        tcp[:4] = struct.pack("!HH", 50000, 80)
        tcp[12] = 0xF0
        frame = ethernet + ip + tcp
        raw = (
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 0, 0, len(frame), len(frame))
            + frame
        )
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "capture.pcap"
            p.write_bytes(raw)
            with self.assertRaises(ValueError):
                analyze(p)
