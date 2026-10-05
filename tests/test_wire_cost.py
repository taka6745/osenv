import struct
import tempfile
import unittest
from pathlib import Path
from osenv.wire_cost import wire_cost


class WireCostTests(unittest.TestCase):
    expected = b"HTTP/1.0 200 OK\r\n\r\nx"

    def packet(self, tx, seq, flags, data):
        tcp = (
            struct.pack(
                "!HHIIBBHHH",
                80 if tx else 1234,
                1234 if tx else 80,
                seq,
                0,
                5 << 4,
                flags,
                4096,
                0,
                0,
            )
            + data
        )
        ip = bytearray(20)
        ip[0] = 0x45
        ip[9] = 6
        ip[2:4] = struct.pack("!H", 20 + len(tcp))
        ip[12:20] = (
            b"\x0a\x00\x00\x01\x0a\x00\x00\x02"
            if tx
            else b"\x0a\x00\x00\x02\x0a\x00\x00\x01"
        )
        frame = bytes(12) + b"\x08\x00" + ip + tcp
        return struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame

    def check(self, records):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.pcap"
            path.write_bytes(
                struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + records
            )
            return wire_cost(path, self.expected)

    def test_wrap_reassembly_and_duplicate_fin(self):
        a = self.packet(True, 0xFFFFFFF0, 0x18, self.expected[:16])
        b = self.packet(True, 0, 0x19, self.expected[16:])
        result = self.check(self.packet(False, 5, 0x18, b"GET /\r\n") + a + b + b)
        self.assertEqual(result["matched_response_flows"], 1)
        self.assertEqual(result["per_flow"]["repeated_segments"]["median"], 1)
        self.assertEqual(result["per_flow"]["tx_frames"]["median"], 3)

    def test_conflicting_bytes_and_truncation_rejected(self):
        a = self.packet(True, 1, 0x19, self.expected)
        with self.assertRaises(ValueError):
            self.check(a + self.packet(True, 1, 0x19, self.expected[:-1] + b"z"))
        with self.assertRaises(ValueError):
            self.check(a[:-1])

    def test_reused_tuple_is_two_connections(self):
        records = b""
        for client, server in ((10, 100), (20, 200)):
            records += self.packet(False, client, 2, b"")
            records += self.packet(False, client + 1, 0x18, b"GET /\r\n")
            records += self.packet(True, server, 0x19, self.expected)
        self.assertEqual(self.check(records)["matched_response_flows"], 2)


if __name__ == "__main__":
    unittest.main()
