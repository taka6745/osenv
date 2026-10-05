"""Execute raw image primitive symbols in the paused guest, with independent oracles.

This external harness writes inputs/registers only, never executable instructions.
The return breakpoint reuses raw_loop from the actual image. Save/restore all
scratch, page-table and CPU state; do not run alongside a second debugger.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import re
import struct
import time

from .debug import Debugger


def checksum(data):
    total = sum(int.from_bytes(data[i:i+2].ljust(2, b'\0'), 'big')
                for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def elf_symbols(path):
    data = Path(path).read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01'
    section_offset = struct.unpack_from('<Q', data, 40)[0]
    section_size, section_count = struct.unpack_from('<HH', data, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, section_offset+i*section_size)
                for i in range(section_count)]
    result = {}
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        names = data[strings[4]:strings[4]+strings[5]]
        for offset in range(section[4], section[4]+section[5], section[9]):
            name, _, _, _, address, _ = struct.unpack_from('<IBBHQQ', data, offset)
            if name:
                result[names[name:names.index(0, name)].decode()] = address
    return result


class ActualGuest:
    def __init__(self, socket, elf):
        self.debugger = Debugger(socket, elf)
        self.debugger.collect(0.1)
        self.names = json.loads(re.search(r'register-names=(\[[^\n]*\])',
                                         self.command('-data-list-register-names'))[1])

    def command(self, command, timeout=5):
        begin = len(self.debugger.transcript)
        token = self.debugger.send(command)
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            self.debugger.collect(0.01)
            output = self.debugger.transcript[begin:].decode(errors='replace')
            match = re.search(r'(?:^|\n)'+str(token)+r'\^(done|error|running)', output)
            if match and (match[1] != 'running' or '*stopped' in output):
                if match[1] == 'error':
                    raise RuntimeError(output)
                return output
        raise TimeoutError(command)

    def registers(self):
        output = self.command('-data-list-register-values x')
        values = re.findall(r'number="(\d+)",value="([^"]+)"', output)
        return {self.names[int(i)]: int(v, 16) for i, v in values
                if self.names[int(i)] in CPU}

    def set(self, registers):
        fields = ' '.join(f'{self.names.index(k)} 0x{v:x}' for k, v in registers.items())
        self.command('-data-write-register-values x '+fields)

    def read(self, address, size):
        if not size:
            return b''
        output = self.command(f'-data-read-memory-bytes {address:#x} {size}')
        return bytes.fromhex(''.join(re.findall(r'contents="([0-9a-f]+)"', output)))

    def write(self, address, data):
        for offset in range(0, len(data), 4096):
            self.command(f'-data-write-memory-bytes {address+offset:#x} '
                         +data[offset:offset+4096].hex())


CPU = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9',
       'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip', 'eflags', 'cr3']
PRESERVED = ['rbx', 'rbp', 'r12', 'r13', 'r14', 'r15']


def test(socket, elf, manifest, report, seed=0x1052026):
    if not __debug__:
        raise RuntimeError('Assertions required for raw acceptance')
    symbols = elf_symbols(elf)
    source = json.loads(Path(manifest).read_text())
    for name in ['checksum', 'transport_checksum', 'mem_copy', 'mem_zero',
                 'http_select', 'raw_loop', 'raw_fault']:
        assert symbols[name] == source['symbols'][name]
    vm = ActualGuest(socket, elf)
    vm.command(f'-break-insert -h *{symbols["raw_loop"]:#x}')
    vm.command('-exec-continue')
    saved = vm.registers()
    assert saved['rip'] == symbols['raw_loop'], 'Could not reach raw_loop before testing'
    assert saved.get('cr3') == 0x90000
    # Preserve both scratch region and last 8KiB before the unmapped guard.
    regions = [(0x1b0000, 0x21000), (0x1fe000, 0x2000)]
    originals = [(a, vm.read(a, n)) for a, n in regions]
    old_pde = vm.read(0x92008, 8)
    checks = []
    rng = random.Random(seed)
    sentinels = {name: 0xa5100000+i*0x101 for i, name in enumerate(PRESERVED)}

    def invoke(name, args):
        vm.write(0x1cfff8, struct.pack('<Q', symbols['raw_loop']))
        vm.set({**sentinels, **args, 'rsp': 0x1cfff8, 'rip': symbols[name],
                'eflags': saved['eflags'] & ~0x600})  # IF=DF=0
        vm.command('-exec-continue')
        registers = vm.registers()
        assert registers['rip'] == symbols['raw_loop'], (name, registers)
        assert registers['rsp'] == 0x1d0000
        assert all(registers[n] == v for n, v in sentinels.items()), name
        assert not registers['eflags'] & 0x400
        return registers['rax']

    def record(label, actual, expected):
        assert actual == expected, (label, actual, expected)
        checks.append({'case': label, 'ok': True})

    def request(data, expected_status, head=False, offset=0):
        p = 0x200000-len(data)-offset
        vm.write(p, data)
        descriptor = invoke('http_select', {'rdi': p, 'rsi': len(data)})
        if expected_status is None:
            record('http-incomplete-'+data.hex(), descriptor, 0)
            return
        pointer, size = struct.unpack('<QQ', vm.read(descriptor, 16))
        wire = vm.read(pointer, size)
        header, separator, body = wire.partition(b'\r\n\r\n')
        assert separator and header.startswith(b'HTTP/1.0 '+str(expected_status).encode()+b' ')
        length = int(header.split(b'Content-Length:')[1].split(b'\r\n')[0])
        assert (not body if head else len(body) == length)
        if expected_status == 200:
            assert length == 1366
            if not head:
                assert body.startswith(b'<!doctype html>') and body.endswith(b'</html>')
        checks.append({'case': 'http-'+data.hex(), 'status': expected_status,
                       'wire_size': size, 'ok': True})

    failure = None
    try:
        vm.command('-break-delete')
        vm.command(f'-break-insert -h *{symbols["raw_loop"]:#x}')
        vm.command(f'-break-insert -h *{symbols["raw_fault"]:#x}')
        vm.write(0x92008, bytes(8))
        vm.set({'cr3': saved['cr3']})
        try:
            vm.read(0x200000, 1)
        except RuntimeError:
            pass
        else:
            raise AssertionError('Guard boundary remains mapped')
        lengths = [0, 1, 2, 3, 7, 8, 9, 15, 16, 31, 32, 33, 63, 64, 65,
                   127, 255, 511, 768, 1460, 4096]
        for length in lengths:
            for offset in [0, 1, 3, 7]:
                data = bytes(rng.randrange(256) for _ in range(length))
                address = 0x200000-length-offset
                vm.write(address, data)
                actual = invoke('checksum', {'rdi': address, 'rsi': length})
                record(f'checksum-{length}-{offset}', actual, checksum(data))
        for length in [1, 7, 8, 9, 31, 32, 33, 4096, 8192]:
            data = b'\xff'*length
            address = 0x200000-length
            vm.write(address, data)
            record(f'checksum-carry-{length}', invoke('checksum', {'rdi': address, 'rsi': length}), checksum(data))
        for length in [0, 1, 2, 7, 8, 31, 32, 33, 768, 1460]:
            for offset in [0, 3]:
                data = bytes(rng.randrange(256) for _ in range(length))
                address = 0x200000-length-offset
                vm.write(address, data)
                src, dst, proto = rng.getrandbits(32), rng.getrandbits(32), rng.randrange(256)
                pseudo = struct.pack('>IIBBH', src, dst, 0, proto, length)
                record(f'transport-{length}-{offset}', invoke('transport_checksum',
                       {'rdi': src, 'rsi': dst, 'rdx': proto, 'rcx': address, 'r8': length}), checksum(pseudo+data))
        record('transport-overflow-no-read', invoke('transport_checksum',
               {'rdi': 0, 'rsi': 0, 'rdx': 6, 'rcx': 0x200000, 'r8': 65536}), 1)
        for length in [0, 1, 7, 8, 9, 31, 32, 255, 768, 4096]:
            address = 0x200000-length
            data = bytes(rng.randrange(256) for _ in range(length))
            vm.write(0x1b0000, data)
            vm.write(address-1, b'\xa5'+b'\xcc'*length)
            record(f'copy-return-{length}', invoke('mem_copy',
                   {'rdi': address, 'rsi': 0x1b0000, 'rdx': length}), address)
            record(f'copy-content-{length}', vm.read(address-1, length+1), b'\xa5'+data)
            invoke('mem_zero', {'rdi': address, 'rsi': length})
            record(f'zero-content-{length}', vm.read(address-1, length+1), b'\xa5'+bytes(length))
            # Reversed guard: source ends at unmapped page, destination is scratch.
            vm.write(address, data)
            invoke('mem_copy', {'rdi': 0x1b0000, 'rsi': address, 'rdx': length})
            record(f'copy-source-guard-{length}', vm.read(0x1b0000, length), data)
        for method in [b'GET', b'HEAD']:
            for version in [b'1.0', b'1.1']:
                for target in [b'/', b'/missing']:
                    request(method+b' '+target+b' HTTP/'+version+b'\r\nHost: example\r\n\r\n',
                            200 if target == b'/' else 404, head=method == b'HEAD')
        for data in [b'', b'G', b'GET / HTTP/1.1\r\nHost:x\r\n', b'\r\n\r']:
            request(data, None)
        for data in [b'\r\n\r\n', b'GET / HTTP/1.1\r\n\r\n',
                     b'GET / HTTP/1.1\r\nHost:x\r\nHost:y\r\n\r\n',
                     b'GET / HTTP/1.1\r\nHost:x y\r\n\r\n',
                     b'GET / HTTP/1.0\r\nContent-Length:1\r\n\r\n',
                     b'GET / HTTP/1.0\r\nContent-Length:0\r\nContent-Length:0\r\n\r\n',
                     b'GET / HTTP/1.0\r\nTransfer-Encoding:chunked\r\n\r\n',
                     b'GET / HTTP/1.0\r\nBad Name:x\r\n\r\n',
                     b'GET / HTTP/1.0\r\nX:\x01\r\n\r\n',
                     b'GET / HTTP/1.0\r\n folded:x\r\n\r\n',
                     b'GET / HTTP/1.0\r\n\r\nx', b'GET / HTTP/1.2\r\n\r\n',
                     b'GET /\x00 HTTP/1.0\r\n\r\n']:
            request(data, 400)
        request(b'POST / HTTP/1.0\r\n\r\n', 405)
        request(b'GET / HTTP/1.1\r\nhOsT:\tx\t\r\nContent-Length:000\r\n\r\n', 200)
        prefix = b'GET / HTTP/1.1\r\nHost:x\r\nX:'
        for length in [767, 768, 769]:
            data = prefix+b'a'*(length-len(prefix)-4)+b'\r\n\r\n'
            request(data, 200 if length <= 768 else 400)
        # Isolated deliberate defect in actual loaded code, restored before any continuation.
        # Our authored fold's NOT AX ends at offset30; changing D0 to D1 targets CX.
        mutant = symbols['fold']+30
        original = vm.read(mutant, 1)
        assert original == b'\xd0'
        try:
            vm.write(mutant, b'\xd1')
            vm.write(0x1b0000, b'\x12\x34')
            actual = invoke('checksum', {'rdi': 0x1b0000, 'rsi': 2})
            assert actual != checksum(b'\x12\x34'), 'Oracle accepted checksum mutant'
            checks.append({'case': 'checksum-mutant-rejected', 'ok': True})
        finally:
            vm.write(mutant, original)
        record('checksum-restored', invoke('checksum', {'rdi': 0x1b0000, 'rsi': 2}), checksum(b'\x12\x34'))
    except Exception as error:
        failure = repr(error)
        raise
    finally:
        try:
            vm.write(0x92008, old_pde)
            vm.set({'cr3': saved['cr3']})
            for address, data in originals:
                vm.write(address, data)
            vm.set(saved)
            vm.command('-break-delete')
        finally:
            Path(report).parent.mkdir(parents=True, exist_ok=True)
            Path(report).write_text(json.dumps({'ok': failure is None, 'failure': failure,
                'seed': seed, 'elf_sha256': hashlib.sha256(Path(elf).read_bytes()).hexdigest(),
                'image_sha256': source['image_sha256'], 'checks': checks,
                'guard': {'boundary': 0x200000, 'pde': 0x92008}}, indent=2)+'\n')
            vm.debugger.close()
    return {'ok': True, 'checks': len(checks), 'report': str(report)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gdb', required=True)
    parser.add_argument('--elf', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--seed', type=lambda x: int(x, 0), default=0x1052026)
    args = parser.parse_args()
    print(json.dumps(test(args.gdb, args.elf, args.manifest, args.report, args.seed)))


if __name__ == '__main__':
    main()
