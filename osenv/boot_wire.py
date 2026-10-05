"""Independent boot DHCP timeline and per-connection TCP counts from real pcaps."""

import argparse
import json
import struct
from pathlib import Path


def analyze(path):
    raw = Path(path).read_bytes()
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(raw[:4])
    if (
        len(raw) < 24
        or endian is None
        or struct.unpack_from(endian + "I", raw, 20)[0] != 1
    ):
        raise ValueError("Expected Ethernet pcap")
    cursor = 24
    dhcp, flows = [], []
    active = {}
    while cursor < len(raw):
        if cursor + 16 > len(raw):
            raise ValueError("Truncated pcap record")
        sec, us, size, original = struct.unpack_from(endian + "IIII", raw, cursor)
        cursor += 16
        if size != original or cursor + size > len(raw):
            raise ValueError("Truncated Ethernet frame")
        frame = raw[cursor : cursor + size]
        cursor += size
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        h, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
        if ip[0] >> 4 != 4 or h < 20 or total > len(ip) or total < h + 8:
            continue
        data = ip[h:total]
        timestamp = sec * 1000000 + us
        ports = struct.unpack_from("!HH", data)
        if ip[9] == 17 and ports in [(68, 67), (67, 68)] and len(data) >= 248:
            bootp = data[8:]
            if bootp[236:240] != b"\x63\x82\x53\x63":
                continue
            i = 240
            while i < len(bootp):
                tag = bootp[i]
                i += 1
                if tag == 255:
                    break
                if tag == 0:
                    continue
                if i == len(bootp) or i + 1 + bootp[i] > len(bootp):
                    raise ValueError("Truncated DHCP option")
                n = bootp[i]
                i += 1
                if tag == 53 and n == 1:
                    dhcp.append({"type": bootp[i], "capture_us": timestamp})
                i += n
        elif ip[9] == 6 and 80 in ports and len(data) >= 20:
            tcp_header = (data[12] >> 4) * 4
            if tcp_header < 20 or tcp_header > len(data):
                raise ValueError("Invalid TCP header length")
            tx = ports[0] == 80
            key = (ip[16:20], ports[1]) if tx else (ip[12:16], ports[0])
            seq, ack = struct.unpack_from("!II", data, 4)
            flags = data[13]
            if not tx and flags & 2:
                if key not in active or active[key]["client_isn"] != seq:
                    flow = {"client_isn": seq, "frames": []}
                    flows.append(flow)
                    active[key] = flow
            if key in active:
                active[key]["frames"].append(
                    {
                        "direction": "server" if tx else "client",
                        "flags": flags,
                        "sequence": seq,
                        "ack": ack,
                        "payload_bytes": len(data) - tcp_header,
                    }
                )
    return {
        "scope": "pcap clock, not physical boot time",
        "dhcp": dhcp,
        "dhcp_gaps_ms": [
            (b["capture_us"] - a["capture_us"]) / 1000 for a, b in zip(dhcp, dhcp[1:])
        ],
        "tcp_connections": flows,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap")
    args = parser.parse_args()
    print(json.dumps(analyze(args.pcap), indent=2))
