"""Execute bounded network paths in a real BIOS-booted raw image.

External GDB writes packet/test state and return addresses, never executable
instructions. Save complete input vectors, CPU trace and exact image provenance.
Setup IPs/sequence/window values are documented deterministic input vectors;
assertions inspect actual guest state and outgoing bytes against RFC invariants.
"""
import argparse
import hashlib
import json
import struct
import time
from pathlib import Path
from .worker import start
from .core import get_run
from .__main__ import call
from .raw_primitives_test import ActualGuest, elf_symbols, checksum, PRESERVED

def test(build, output, seed=17113126, extra=None):
    if not __debug__:
        raise RuntimeError('Network acceptance requires Python assertions enabled')
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError('Preserve prior evidence: choose a fresh output path')
    output.parent.mkdir(parents=True, exist_ok=True)
    vm = None
    out = Path(build).resolve()
    s = elf_symbols(out / 'kernel.elf')
    r = start(timeout=50, paused=True, manual=True, image=str(out / 'oslab.img'), symbols=str(out / 'kernel.elf'), mode='long64', memory=64, network='isolated', nic_model='e1000e', minimal_devices=True)
    rid = r['run_id']
    run = get_run(rid)
    try:
        while not (run / 'manifest.json').exists():
            time.sleep(0.01)
        m = json.loads((run / 'manifest.json').read_text())
        vm = ActualGuest(str(Path(m['socket_directory']) / 'gdb'), str(out / 'kernel.elf'))
        vm.command(f"-break-insert -h *{s['raw_loop']:#x}")
        vm.command('-exec-continue')
        saved = vm.registers()
        checks = []
        mac = vm.read(s['nic_mac'], 6)
        ack = bytearray(240)
        ack[:4] = bytes([2, 1, 6, 0])
        ack[4:8] = struct.pack('!I', seed)
        ack[16:20] = bytes([10, 0, 2, 15])
        ack[28:34] = mac
        ack[236:240] = bytes.fromhex('63825363')
        ack += bytes.fromhex('35010536040a0002020104ffffff00330400000e10ff')
        ip = bytearray(20)
        ip[0] = 69
        ip[2:4] = struct.pack('!H', 44)
        ip[6:8] = bytes.fromhex('4000')
        ip[8] = 64
        ip[9] = 6
        ip[12:16] = bytes([10, 0, 2, 2])
        ip[16:20] = bytes([10, 0, 2, 15])
        ip[10:12] = struct.pack('!H', checksum(ip))
        tcp = bytearray(24)
        tcp[:4] = struct.pack('!HH', 40000, 80)
        tcp[4:8] = struct.pack('!I', 4294967280)
        tcp[12:16] = bytes.fromhex('60020080')
        tcp[20:24] = bytes.fromhex('02040080')
        pseudo = ip[12:20] + bytes([0, 6]) + struct.pack('!H', 24)
        tcp[16:18] = struct.pack('!H', checksum(pseudo + tcp))
        syn = mac + bytes.fromhex('0200000000020800') + ip + tcp
        (run / 'raw-network-inputs.json').write_text(json.dumps({'seed': seed, 'description': 'authored RFC DHCP ACK and TCP SYN input vectors; no executable code written', 'ack_hex': ack.hex(), 'syn_hex': syn.hex()}, indent=2))
        sent = {k: 287440896 + j for (j, k) in enumerate(PRESERVED)}

        def invoke(name, data=b'', size=None, setup=None):
            state = bytearray(272)
            state[0:8] = struct.pack('<Q', 1000)
            state[8] = 1
            state[16:20] = b'\n\x00\x02\x0f'
            state[40:48] = struct.pack('<Q', 100000000)
            if setup:
                setup(state)
            vm.write(1638400, state)
            vm.write(1769472, data)
            vm.write(1900536, struct.pack('<Q', s['raw_loop']))
            vm.set({**sent, 'rdi': 1769472, 'rsi': len(data) if size is None else size, 'rsp': 1900536, 'rip': s[name], 'eflags': saved['eflags'] & ~1536})
            vm.command('-exec-continue')
            regs = vm.registers()
            assert regs['rip'] == s['raw_loop']
            assert regs['rsp'] == 0x1d0000
            assert not regs['eflags'] & 0x400
            assert all((regs[k] == v for (k, v) in sent.items()))
            return vm.read(1638400, 272)

        def record(label, test):
            assert test, label
            checks.append({'case': label, 'ok': True})

        def dhcpstate(st):
            st[8] = 0
            st[9] = 1
            st[12:16] = struct.pack('<I', int.from_bytes(ack[4:8], 'big'))
            st[20:24] = ack[16:20]
            st[24:28] = b'\n\x00\x02\x02'

        def dhcp(label, data, valid=False):
            st = invoke('net_dhcp_receive', data, setup=dhcpstate)
            record(label, bool(st[8]) == valid)
            return st
        st = dhcp('actual-ACK-optional-router', ack, True)
        record('actual-mask-lease-IP', st[16:20] == ack[16:20] and st[28:32] == b'\xff\xff\xff\x00' and (int.from_bytes(st[36:40], 'little') == 3600))
        for (off, label) in [(4, 'wrong-xid'), (28, 'wrong-client-MAC'), (236, 'wrong-cookie'), (16, 'wrong-offered-IP')]:
            q = bytearray(ack)
            q[off] ^= 1
            dhcp(label, q)
        for n in [0, 1, 239, len(ack) - 1]:
            dhcp('truncated-ACK-' + str(n), ack[:n])
        q = ack[:-1] + b'\x03\x04\n\x00\x02\x02\xff'
        dhcp('actual-router-option', q, True)
        dhcp('wrong-subnet-router', ack[:-1] + b'\x03\x04\n\x00\x03\x02\xff')
        dhcp('duplicate-message-option', ack[:-1] + b'5\x01\x05\xff')
        q = bytearray(ack)
        pos = q.index(b'\x01\x04\xff\xff\xff\x00')
        q[pos + 3] = 240
        dhcp('noncontiguous-subnet', q)
        q = bytearray(ack)
        pos = q.index(b'3\x04\x00\x00\x0e\x10')
        q[pos + 2:pos + 6] = bytes(4)
        dhcp('zero-lease', q)
        q = bytearray(ack[:240])
        q[16:20] = bytes(4)
        q += b'5\x01\x066\x04\n\x00\x02\x02\xff'
        st = invoke('net_dhcp_receive', q, setup=dhcpstate)
        record('matching-NAK-restarts-discovery', st[9] == 0 and st[48:56] == bytes(8))
        record('actual-SYN-opens-connection', invoke('net_frame', syn)[64] == 1)
        for n in [0, 13, 14, 33, len(syn) - 1]:
            record('short-frame-' + str(n), invoke('net_frame', syn[:n])[64] == 0)
        q = bytearray(syn)
        q[24] ^= 1
        record('bad-IPv4-checksum', invoke('net_frame', q)[64] == 0)
        q = bytearray(syn)
        q[50] ^= 1
        record('bad-TCP-checksum', invoke('net_frame', q)[64] == 0)

        def ipfix(q):
            q[24:26] = bytes(2)
            q[24:26] = struct.pack('!H', checksum(q[14:34]))
            return q
        q = bytearray(syn)
        q[20:22] = b' \x00'
        record('fragment-MF-rejected', invoke('net_frame', ipfix(q))[64] == 0)
        q = bytearray(syn)
        q[20:22] = b'\x00\x01'
        record('fragment-offset-rejected', invoke('net_frame', ipfix(q))[64] == 0)
        q = bytearray(syn)
        q[16:18] = b'\x00\x10'
        record('IPv4-total-shorter-than-header', invoke('net_frame', ipfix(q))[64] == 0)
        q = bytearray(syn)
        q[16:18] = b'\x05\xdc'
        record('IPv4-total-exceeds-frame', invoke('net_frame', ipfix(q))[64] == 0)
        q = bytearray(syn)
        q[22] = 0
        record('zero-TTL-rejected', invoke('net_frame', ipfix(q))[64] == 0)
        q = bytearray(syn)
        q[0] ^= 4
        record('wrong-Ethernet-destination', invoke('net_frame', q)[64] == 0)
        q = bytearray(syn)
        q[30] ^= 4
        record('wrong-IP-destination', invoke('net_frame', ipfix(q))[64] == 0)

        def timeout(st):
            st[64] = 1
            st[128:136] = struct.pack('<Q', 1000)
        record('actual-connection-deadline-clears', invoke('net_server_poll', setup=timeout)[64] == 0)

        def lease(st):
            st[64] = 1
            st[128:136] = struct.pack('<Q', 10000)
            st[40:48] = struct.pack('<Q', 1000)
        record('actual-lease-deadline-stops-serving', invoke('net_server_poll', setup=lease)[64] == 0)

        def retry(st):
            st[64] = 1
            st[84:88] = struct.pack('<I', 1)
            st[88:92] = struct.pack('<I', 2)
            st[97] = 5
            st[128:136] = struct.pack('<Q', 10000)
            st[136:144] = struct.pack('<Q', 1000)
        record('actual-retransmission-budget-clears', invoke('net_server_poll', setup=retry)[64] == 0)

        def tcpfix(q):
            q[50:52] = bytes(2)
            end = 14 + int.from_bytes(q[16:18], 'big')
            seg = q[34:end]
            pseudo = q[26:34] + bytes([0, 6]) + struct.pack('!H', len(seg))
            q[50:52] = struct.pack('!H', checksum(pseudo + seg))
            return ipfix(q)
        for (offset, value, label) in [(46, 64, 'TCP-header-below-minimum'), (46, 240, 'TCP-header-exceeds-packet'), (55, 1, 'TCP-malformed-option-length'), (56, 0, 'TCP-zero-MSS')]:
            q = bytearray(syn)
            q[offset] = value
            if label == 'TCP-zero-MSS':
                q[57] = 0
            record(label, invoke('net_frame', tcpfix(q))[64] == 0)
        q = bytearray(syn)
        q[56:58] = b'\x00\x01'
        record('TCP-one-byte-MSS-valid', invoke('net_frame', tcpfix(q))[64] == 1)
        q = bytearray(syn)
        q[36:38] = b'\x00Q'
        record('TCP-other-port-silent', invoke('net_frame', tcpfix(q))[64] == 0)
        q = bytearray(syn)
        q.extend(q[54:58])
        q[46] = 112
        q[16:18] = struct.pack('!H', len(q) - 14)
        record('TCP-duplicate-MSS-rejected', invoke('net_frame', tcpfix(q))[64] == 0)
        arp = b'\xff' * 6 + b'\x02\x00\x00\x00\x00\x02' + b'\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + b'\n\x00\x02\x02' + bytes(6) + b'\n\x00\x02\x0f'
        vm.write(1642496, b'\xaa' * 60)
        invoke('net_frame', arp)
        reply = vm.read(1642496, 42)
        record('actual-ARP-reply-fields', reply[:6] == arp[6:12] and reply[6:12] == mac and (reply[20:22] == b'\x00\x02') and (reply[28:32] == b'\n\x00\x02\x0f') and (reply[38:42] == b'\n\x00\x02\x02'))
        for (offset, label) in [(14, 'ARP-hardware-type'), (16, 'ARP-protocol'), (18, 'ARP-hardware-size'), (19, 'ARP-protocol-size'), (22, 'ARP-source-MAC-mismatch'), (38, 'ARP-wrong-target')]:
            q = bytearray(arp)
            q[offset] ^= 1
            vm.write(1642496, b'\xaa' * 60)
            invoke('net_frame', q)
            record(label, vm.read(1642496, 60) == b'\xaa' * 60)

        def responding(st, window=31, mss=64):
            st[64] = 1
            st[65] = 1
            st[68:72] = b'\n\x00\x02\x02'
            st[72:74] = b'\x9c@'
            st[74:76] = struct.pack('<H', window)
            st[76:78] = struct.pack('<H', mss)
            st[84:88] = struct.pack('<I', 512)
            st[88:92] = struct.pack('<I', 512)
            st[112:120] = struct.pack('<Q', s['http_response_3'])
            st[120:128] = struct.pack('<Q', 1460)
            st[128:136] = struct.pack('<Q', 10000)
            st[144:150] = b'\x02\x00\x00\x00\x00\x02'
        st = invoke('net_server_poll', setup=responding)
        record('actual-send-limited-by-window', int.from_bytes(st[100:104], 'little') == 31 and int.from_bytes(st[88:92], 'little') == 543)
        record('actual-send-limited-by-MSS', int.from_bytes(invoke('net_server_poll', setup=lambda st: responding(st, 4096, 64))[100:104], 'little') == 64)
        record('actual-zero-window-no-send', int.from_bytes(invoke('net_server_poll', setup=lambda st: responding(st, 0, 64))[88:92], 'little') == 512)

        def offerretry(st):
            st[8] = 0
            st[9] = 1
            st[10] = 4
            st[20:24] = b'\n\x00\x02\x0f'
            st[24:28] = b'\n\x00\x02\x02'
        st = invoke('net_dhcp_send', setup=offerretry)
        record('actual-request-retry-budget-rediscovers', st[9] == 0 and st[10] == 1)

        def expiredpoll(st):
            st[64] = 1
            st[40:48] = bytes(8)
        st = invoke('net_poll', setup=expiredpoll)
        record('actual-poll-lease-expiry-removes-config-and-connection', st[8] == 0 and st[64] == 0)

        def established(st):
            st[64] = 1
            st[65] = 1
            st[68:72] = syn[26:30]
            st[72:74] = syn[34:36]
            st[74:76] = struct.pack('<H', 123)
            st[76:78] = struct.pack('<H', 128)
            st[80:84] = struct.pack('<I', 256)
            st[84:88] = struct.pack('<I', 512)
            st[88:92] = struct.pack('<I', 513)
            st[128:136] = struct.pack('<Q', 10000)
            st[144:150] = syn[6:12]

        def ackframe(seq=256, acknowledge=512, flags=16, payload=b''):
            q = bytearray(syn[:54])
            q += payload
            q[46] = 80
            q[47] = flags
            q[38:46] = struct.pack('!II', seq, acknowledge)
            q[48:50] = struct.pack('!H', 17)
            q[16:18] = struct.pack('!H', len(q) - 14)
            return tcpfix(q)
        for (acknowledge, label) in [(511, 'ACK-before-unacknowledged'), (514, 'ACK-beyond-send-next')]:
            st = invoke('net_frame', ackframe(acknowledge=acknowledge), setup=established)
            record(label, int.from_bytes(st[84:88], 'little') == 512 and int.from_bytes(st[74:76], 'little') == 123)
        st = invoke('net_frame', ackframe(acknowledge=513), setup=established)
        record('actual-valid-ACK-updates-window', int.from_bytes(st[84:88], 'little') == 513 and int.from_bytes(st[74:76], 'little') == 17)
        st = invoke('net_frame', ackframe(seq=272, payload=b'X'), setup=established)
        record('actual-future-sequence-not-consumed', int.from_bytes(st[80:84], 'little') == 256 and int.from_bytes(st[104:108], 'little') == 0)
        record('actual-out-of-sequence-RST-ignored', invoke('net_frame', ackframe(seq=257, flags=4), setup=established)[64] == 1)
        record('actual-in-sequence-RST-closes', invoke('net_frame', ackframe(flags=4), setup=established)[64] == 0)
        st = invoke('net_frame', ackframe(flags=17), setup=established)
        record('actual-peer-FIN-consumes-one-sequence', st[67] == 1 and int.from_bytes(st[80:84], 'little') == 257)
        vm.write(1646592, b'\xcc' * 1024)
        st = invoke('net_frame', ackframe(payload=b'A' * 769), setup=established)
        record('actual-request-overflow-reset-before-copy', st[64] == 0 and vm.read(1646592, 1024) == b'\xcc' * 1024)
        if extra:
            extra(vm, s, saved, sent, record, ack, mac, out, run)
        result = {'ok': True, 'run_id': rid, 'actual_guest_image': str(out / 'oslab.img'), 'checks': checks, 'seed': seed, 'image_sha256': hashlib.sha256((out / 'oslab.img').read_bytes()).hexdigest(), 'build_manifest': json.loads((out / 'manifest.json').read_text()), 'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        (run / 'raw-network-boundaries.json').write_text(json.dumps(result, indent=2))
        (run / 'raw-network-boundaries.mi').write_bytes(vm.debugger.transcript)
        output.write_text(json.dumps(result, indent=2))
        return result
    except Exception as error:
        failure = {'ok': False, 'run_id': rid, 'error': str(error), 'seed': seed, 'image_sha256': hashlib.sha256((out / 'oslab.img').read_bytes()).hexdigest(), 'build_manifest': json.loads((out / 'manifest.json').read_text()), 'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        output.write_text(json.dumps(failure, indent=2))
        (run / 'raw-network-failure.json').write_text(json.dumps(failure, indent=2))
        if vm:
            (run / 'raw-network-boundaries.mi').write_bytes(vm.debugger.transcript)
        raise
    finally:
        if vm:
            vm.debugger.close()
        try:
            call(rid, {'operation': 'stop'})
        except Exception:
            pass
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, help='Exact raw_build output directory')
    parser.add_argument('--output', required=True, help='Fresh JSON evidence path')
    parser.add_argument('--seed', type=lambda value: int(value, 0), default=17113126)
    args = parser.parse_args()
    result = test(args.build, args.output, args.seed)
    print(json.dumps({'ok': result['ok'], 'run_id': result['run_id'], 'cases': len(result['checks']), 'image_sha256': result['image_sha256']}))
