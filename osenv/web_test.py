"""Authored external peer acceptance for the actual OS web image, never a guest fixture."""

import socket, struct, time, json, traceback
from pathlib import Path
from osenv.worker import start
from osenv.core import get_run
from osenv.__main__ import call


def web_test(image, symbols, production=False):
    if not __debug__:
        raise RuntimeError("Acceptance checks require Python assertions enabled")
    r = start(
        timeout=60,
        manual=True,
        image=image,
        symbols=symbols,
        mode="long64",
        memory=64,
        network="peer",
    )
    rid = r["run_id"]
    try:
        return _exercise_peer(rid, production)
    except Exception as error:
        run = get_run(rid)
        (run / "web-failure.txt").write_text(traceback.format_exc())
        failure = {
            "ok": False,
            "run_id": rid,
            "verdict": "web-peer-rejected",
            "error": str(error) or type(error).__name__,
        }
        try:
            failure["capture"] = call(rid, {"operation": "capture", "mode": "long64"})
            call(rid, {"operation": "stop"})
        except Exception as recovery_error:
            failure["recovery_error"] = str(recovery_error)
        (run / "web-wire-verdict.json").write_text(json.dumps(failure, indent=2))
        return failure


def _exercise_peer(rid, production):
    run = get_run(rid)
    t = time.monotonic()
    while "peer_port" not in json.loads((run / "manifest.json").read_text()):
        assert time.monotonic() - t < 10
        time.sleep(0.01)
    port = json.loads((run / "manifest.json").read_text())["peer_port"]
    while True:
        try:
            peer = socket.create_connection(("127.0.0.1", port), timeout=1)
            break
        except ConnectionRefusedError:
            assert time.monotonic() - t < 10
            time.sleep(0.01)
    peer.settimeout(5)
    mac = b"\x02\x00\x00\x00\x00\x02"
    host = socket.inet_aton("10.0.2.2")
    guest = socket.inet_aton("10.0.2.15")
    guestmac = None
    ack_sent = False
    seed = 0x5EED

    (run / "web-inputs.json").write_text(
        json.dumps(
            {
                "seed": seed,
                "peer_mac": mac.hex(),
                "peer_ip": "10.0.2.2",
                "offered_ip": "10.0.2.15",
                "client_sequence": 0xFFFFFFF0,
                "mss": 128,
                "withhold_arp": True,
                "corrupt_prefix": True,
                "drop_first_ack": True,
                "zero_window": True,
                "out_of_order_prefix": 8,
            },
            indent=2,
        )
    )

    def checksum(b):
        if len(b) % 2:
            b += b"\0"
        n = sum(struct.unpack("!%dH" % (len(b) // 2), b))
        n = (n & 65535) + (n >> 16)
        n = (n & 65535) + (n >> 16)
        return (~n) & 65535

    def send(frame):
        peer.sendall(struct.pack("!I", len(frame)) + frame)

    incoming = bytearray()
    frame_size = None

    def exact(n):
        while len(incoming) < n:
            more = peer.recv(n - len(incoming))
            if not more:
                raise RuntimeError("Peer disconnected mid-frame")
            incoming.extend(more)
        value = bytes(incoming[:n])
        del incoming[:n]
        return value

    def frame_read():
        nonlocal frame_size
        if frame_size is None:
            frame_size = struct.unpack("!I", exact(4))[0]
            if not 14 <= frame_size <= 65536:
                raise RuntimeError("Invalid Ethernet framing length")
        value = exact(frame_size)
        frame_size = None
        return value

    def recv():
        while True:
            f = frame_read()
            kind = f[12:14]
            if kind == b"\x08\x06":
                # Withhold ARP replies: the passive connection must retain its
                # real next hop even after an unrelated neighbour lookup.
                continue
            if kind != b"\x08\0":
                continue
            p = f[14:]
            h = (p[0] & 15) * 4
            assert checksum(p[:h]) == 0
            p = p[: struct.unpack("!H", p[2:4])[0]]
            if p[9] == 17:
                b = p[h + 8 :]
                assert b[236:240] == b"\x63\x82\x53\x63"
                nonlocal guestmac, ack_sent
                guestmac = b[28:34]
                options = b[240:]
                msg = None
                i = 0
                while i < len(options) and options[i] != 255:
                    if options[i] == 0:
                        i += 1
                        continue
                    key, n = options[i : i + 2]
                    value = options[i + 2 : i + 2 + n]
                    i += n + 2
                    if key == 53:
                        msg = value[0]
                assert msg in (1, 3)
                reply = bytearray(240)
                reply[:4] = b"\2\1\6\0"
                reply[4:8] = b[4:8]
                reply[16:20] = guest
                reply[28:34] = guestmac
                reply[236:240] = b"\x63\x82\x53\x63"
                reply += (
                    bytes([53, 1, 2 if msg == 1 else 5, 54, 4])
                    + host
                    + bytes([1, 4])
                    + b"\xff\xff\xff\0"
                    + bytes([51, 4])
                    + struct.pack("!I", 3600)
                    + b"\xff"
                )
                udp = struct.pack("!HHHH", 67, 68, len(reply) + 8, 0) + reply
                ip_send(17, udp, destination=b"\xff" * 4, dstmac=b"\xff" * 6)
                ack_sent = msg == 3
                continue
            if production and p[9] == 1:
                raise AssertionError("Production unexpectedly exposes ICMP echo")
            if p[9] != 6:
                continue
            tcp = p[h:]
            assert checksum(p[12:20] + b"\0\6" + struct.pack("!H", len(tcp)) + tcp) == 0
            header = (tcp[12] >> 4) * 4
            return struct.unpack("!II", tcp[4:12]), tcp[13], tcp[header:]

    def ip_send(proto, data, destination=guest, dstmac=None, source=host):
        p = bytearray(
            struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                len(data) + 20,
                seed,
                0,
                64,
                proto,
                0,
                source,
                destination,
            )
        )
        p[10:12] = struct.pack("!H", checksum(p))
        send((dstmac or guestmac) + mac + b"\x08\0" + p + data)

    def tcp_send(
        seq,
        ack,
        flags,
        data=b"",
        window=128,
        options=b"",
        corrupt=False,
        destination_port=80,
    ):
        h = bytearray(
            struct.pack(
                "!HHIIBBHHH",
                50000,
                destination_port,
                seq & 0xFFFFFFFF,
                ack & 0xFFFFFFFF,
                ((20 + len(options)) // 4) << 4,
                flags,
                window,
                0,
                0,
            )
            + options
            + data
        )
        h[16:18] = struct.pack(
            "!H", checksum(host + guest + b"\0\6" + struct.pack("!H", len(h)) + h)
        )
        if corrupt:
            h[-1] ^= 1
        ip_send(6, h)

    # Let our DHCP peer configure the real guest, then establish TCP with a tiny MSS.
    while (
        not ack_sent
        if production
        else b"OSL1 SERVING" not in (run / "serial.log").read_bytes()
    ):
        peer.settimeout(0.1)
        try:
            recv()
        except TimeoutError:
            pass
        assert time.monotonic() - t < 10
    peer.settimeout(5)
    client_seq = 0xFFFFFFF0
    tcp_send(client_seq, 0, 2, options=b"\2\4\0\x80")
    (seq, ack), flags, data = recv()
    assert flags & 0x12 == 0x12 and ack == ((client_seq + 1) & 0xFFFFFFFF)
    server_seq = seq + 1
    client_seq += 1
    tcp_send(client_seq, server_seq, 0x10)
    echo = bytearray(b"\x08\x00\x00\x00\x00\x01\x00\x01neighbour")
    echo[2:4] = struct.pack("!H", checksum(echo))
    ip_send(1, echo, source=socket.inet_aton("10.0.2.99"))
    request = b"GET / HTTP/1.1\r\nHost: peer\r\n\r\n"
    tcp_send(client_seq, server_seq, 0x18, request[:8], corrupt=True)
    # Out-of-order tail must be ACKed at the missing prefix position, not consumed.
    tcp_send(client_seq + 8, server_seq, 0x18, request[8:])
    (seq, ack), flags, data = recv()
    assert ack == (client_seq & 0xFFFFFFFF) and not data
    tcp_send(client_seq, server_seq, 0x18, request[:8])
    recv()
    client_seq += 8
    tcp_send(client_seq, server_seq, 0x18, request[8:])
    client_seq += len(request) - 8
    body = b""
    dropped = False
    zero_test = False
    retransmits = 0
    withheld_fin = None
    fin_retransmits = 0
    while True:
        (seq, ack), flags, data = recv()
        if data:
            assert len(data) <= 128
            if not dropped:
                first = (seq, data)
                dropped = True
                continue  # Deliberately drop first data ACK.
            if not body:
                assert (seq, data) == first
                retransmits += 1
            if withheld_fin is not None:
                assert (seq, data) == withheld_fin and flags & 1
                fin_retransmits += 1
            else:
                assert seq == (server_seq & 0xFFFFFFFF)
                body += data
                server_seq += len(data)
            if not zero_test:
                tcp_send(client_seq, server_seq, 0x10, window=0)
                peer.settimeout(0.1)
                try:
                    _, _, extra = recv()
                    assert not extra, "data sent into zero receive window"
                except TimeoutError:
                    pass
                peer.settimeout(5)
                zero_test = True
            tcp_send(client_seq, server_seq, 0x10)
        if flags & 1:
            if withheld_fin is None:
                withheld_fin = (seq, data)
                tcp_send(client_seq, server_seq, 0x10)
                continue  # ACK every data byte, deliberately withhold FIN ACK.
            if not data:
                assert (seq, data) == withheld_fin
                fin_retransmits += 1
            assert (seq + len(data)) & 0xFFFFFFFF == (server_seq & 0xFFFFFFFF)
            server_seq += 1
            tcp_send(client_seq, server_seq, 0x11)
            client_seq += 1
            break
    while True:
        (_, ack), flags, data = recv()
        if ack == (client_seq & 0xFFFFFFFF):
            break
    assert body.startswith(b"HTTP/1.0 200") and body.endswith(b"</html>")
    assert retransmits and zero_test and fin_retransmits
    # Fill the advertised window exactly, then close it after all data. FIN
    # consumes sequence space and must wait for the window-update ACK.
    client_seq = 0x12345678
    tcp_send(client_seq, 0, 2, window=len(body), options=b"\x02\x04\x05\xb4")
    (seq, ack), flags, data = recv()
    assert flags & 0x12 == 0x12 and not data
    client_seq += 1
    server_seq = seq + 1
    tcp_send(client_seq, server_seq, 0x10, window=len(body))
    tcp_send(client_seq, server_seq, 0x18, request, window=len(body))
    client_seq += len(request)
    while True:
        (seq, ack), flags, data = recv()
        if data:
            break
    assert data == body and not flags & 1
    server_seq += len(data)
    tcp_send(client_seq, server_seq, 0x10, window=0)
    peer.settimeout(0.1)
    try:
        _, flags, extra = recv()
        assert not extra and not flags & 1, "FIN/data sent outside zero window"
    except TimeoutError:
        pass
    peer.settimeout(5)
    tcp_send(client_seq, server_seq, 0x10, window=1460)
    while True:
        (seq, ack), flags, data = recv()
        if flags & 1:
            break
    assert seq == server_seq and not data
    server_seq += 1
    tcp_send(client_seq, server_seq, 0x11)
    client_seq += 1
    while recv()[0][1] != client_seq:
        pass
    verdict = {
        "ok": True,
        "run_id": rid,
        "response_bytes": len(body),
        "mss": 128,
        "dropped_ack_retransmission": True,
        "zero_window_reopen": True,
        "fin_ack_loss_retransmission": bool(fin_retransmits),
        "fin_waits_for_window": True,
        "out_of_order_request": True,
        "client_sequence_wrap": True,
        "corrupt_tcp_rejected": True,
        "arp_neighbor_contention": not production,
        "icmp_echo_disabled": production,
    }
    if production:
        for port in (22, 23, 443, 2222, 8080, 12345, 65535):
            tcp_send(100, 0, 2, destination_port=port)
            peer.settimeout(0.1)
            try:
                recv()
                raise AssertionError(
                    "Unexpected TCP service response on port " + str(port)
                )
            except TimeoutError:
                pass
        verdict["silent_tcp_ports"] = [22, 23, 443, 2222, 8080, 12345, 65535]
        assert not (run / "serial.log").read_bytes()
        assert not (run / "early.log").read_bytes()
        assert json.loads((run / "status.json").read_text())["state"] == "running"
        call(rid, {"operation": "stop"})
    else:
        call(rid, {"operation": "serial", "text": "exit\n"})
    peer.close()
    deadline = time.monotonic() + 10
    while True:
        status = json.loads((run / "status.json").read_text())
        if status["state"] == "finished":
            break
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert status["ok"] and status["exit_code"] == (0 if production else 33)
    raw = (run / "serial.log").read_bytes()
    if not production:
        assert b"OSL1 DONE" in raw and b"PANIC" not in raw
    assert not any(
        json.loads(line).get("event") == "RESET"
        for line in (run / "events.jsonl").read_text().splitlines()
    )
    verdict["production"] = production
    verdict["termination"] = "external-stop" if production else "guest-debug-exit"
    verdict["image_sha256"] = json.loads((run / "manifest.json").read_text())[
        "image_sha256"
    ]
    verdict["exit_code"] = status["exit_code"]
    (run / "web-wire-verdict.json").write_text(json.dumps(verdict, indent=2))
    return verdict
