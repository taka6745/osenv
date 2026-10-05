"""Captured Ethernet costs of actual TCP80 flows; no assumed NIC line rate."""

import hashlib
import json
import statistics
import struct
from pathlib import Path


def wire_cost(path, expected):
    raw = Path(path).read_bytes()
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(raw[:4])
    if (
        endian is None
        or len(raw) < 24
        or struct.unpack_from(endian + "I", raw, 20)[0] != 1
    ):
        raise ValueError("Expected complete Ethernet pcap")
    flows = {}
    previous_connections = []
    cursor = 24
    while cursor < len(raw):
        if cursor + 16 > len(raw):
            raise ValueError("Truncated record header")
        sec, us, count, original = struct.unpack_from(endian + "IIII", raw, cursor)
        cursor += 16
        if count != original or cursor + count > len(raw):
            raise ValueError("Incomplete captured frame")
        frame = raw[cursor : cursor + count]
        cursor += count
        if len(frame) < 54 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        header = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], "big")
        if header < 20 or total > len(ip) or total < header + 20 or ip[9] != 6:
            continue
        tcp = ip[header:total]
        source, destination, seq, ack = struct.unpack_from("!HHII", tcp)
        if source != 80 and destination != 80:
            continue
        tx = source == 80
        key = (ip[16:20] if tx else ip[12:16], destination if tx else source)
        if (
            not tx
            and tcp[13] & 2
            and key in flows
            and flows[key].get("client_seq") != seq
        ):
            previous_connections.append(flows.pop(key))
        flow = flows.setdefault(
            key,
            {
                "tx_frames": 0,
                "rx_frames": 0,
                "tx_bytes": 0,
                "rx_bytes": 0,
                "tx_ack_only": 0,
                "data_fin": 0,
                "data": {},
                "repeated_segments": 0,
                "request_at": None,
                "response_at": None,
            },
        )
        if not tx and tcp[13] & 2:
            flow["client_seq"] = seq
        prefix = "tx" if tx else "rx"
        flow[prefix + "_frames"] += 1
        flow[prefix + "_bytes"] += count
        tcp_header = (tcp[12] >> 4) * 4
        if tcp_header < 20 or tcp_header > len(tcp):
            raise ValueError("Malformed TCP header")
        data = tcp[tcp_header:]
        flags = tcp[13]
        stamp = sec * 1000000 + us
        if tx:
            if not data and flags == 0x10:
                flow["tx_ack_only"] += 1
            if data:
                if flow["response_at"] is None:
                    flow["response_at"] = stamp
                    flow["base_seq"] = seq
                if seq in flow["data"]:
                    if flow["data"][seq] != data:
                        raise ValueError("Conflicting retransmitted bytes")
                    flow["repeated_segments"] += 1
                flow["data"][seq] = data
                flow["data_fin"] += bool(flags & 1)
        elif data and flow["request_at"] is None:
            flow["request_at"] = stamp
    complete = []
    for flow in [*previous_connections, *flows.values()]:
        if not flow["data"]:
            continue
        chunks = sorted(
            (
                ((seq - flow["base_seq"]) & 0xFFFFFFFF, data)
                for seq, data in flow["data"].items()
            )
        )
        response = bytearray()
        for offset, data in chunks:
            if offset != len(response):
                break
            response.extend(data)
        if bytes(response) != expected:
            continue
        flow["captured_service_seconds"] = (
            flow["response_at"] - flow["request_at"]
        ) / 1000000
        del flow["data"]
        complete.append(flow)
    if not complete:
        raise ValueError("No independently reconstructed expected responses")
    metrics = (
        "tx_frames",
        "rx_frames",
        "tx_bytes",
        "rx_bytes",
        "tx_ack_only",
        "data_fin",
        "repeated_segments",
        "captured_service_seconds",
    )
    return {
        "scope": "captured Ethernet frames, excluding physical preamble/IFG/FCS; TCP80 expected-response flows only",
        "matched_response_flows": len(complete),
        "response_sha256": hashlib.sha256(expected).hexdigest(),
        "pcap_sha256": hashlib.sha256(raw).hexdigest(),
        "per_flow": {
            name: {
                "median": statistics.median([x[name] for x in complete]),
                "p99": sorted(x[name] for x in complete)[
                    int(0.99 * (len(complete) - 1))
                ],
            }
            for name in metrics
        },
    }
