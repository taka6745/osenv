import struct
import tempfile
import unittest
from pathlib import Path
from osenv.web_stress import dhcp_ack_seen


class ReadinessTests(unittest.TestCase):
    def capture(self, options, ports=b"\x00\x43\x00\x44"):
        bootp = bytearray(240)
        bootp[0] = 2
        bootp[236:240] = b"\x63\x82\x53\x63"
        udp = ports + struct.pack("!HH", 248 + len(options), 0) + bootp + options
        ip = bytearray(20)
        ip[0] = 0x45
        ip[9] = 17
        ip[2:4] = struct.pack("!H", 20 + len(udp))
        frame = bytes(12) + b"\x08\x00" + ip + udp
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        return header + struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame

    def seen(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.pcap"
            path.write_bytes(raw)
            return dhcp_ack_seen(path)

    def test_ack_and_live_partial_record(self):
        raw = self.capture(b"\x35\x01\x05\xff")
        self.assertTrue(self.seen(raw))
        self.assertTrue(self.seen(raw + bytes(5)))
        self.assertFalse(self.seen(raw[:-1]))

    def test_offer_wrong_ports_and_truncated_option(self):
        self.assertFalse(self.seen(self.capture(b"\x35\x01\x02\xff")))
        self.assertFalse(
            self.seen(self.capture(b"\x35\x01\x05\xff", b"\x00\x44\x00\x43"))
        )
        self.assertFalse(self.seen(self.capture(b"\x35\x01")))


if __name__ == "__main__":
    unittest.main()
