"""Fault injection into the actual authored PVH adapter, with external PC verdicts."""
import argparse
import json
import struct
import subprocess
from pathlib import Path

from .core import get_run, digest, tool
from .debug import Debugger
from .worker import start
from .__main__ import call


def test(image, symbols, boot_kernel, report, cases=None):
    image, symbols, boot_kernel = map(lambda p: Path(p).resolve(), (image, symbols, boot_kernel))
    nm = subprocess.run([tool('llvm-nm'), str(boot_kernel)], check=True, capture_output=True, text=True).stdout
    addresses = {line.split()[-1]: int(line.split()[0], 16) for line in nm.splitlines() if len(line.split()) == 3}
    entry = struct.unpack_from('<I', boot_kernel.read_bytes(), 24)[0]
    assert entry == addresses['pvh_entry']
    selected = cases or ['magic', 'version', 'count-zero', 'count-overflow', 'pointer-overflow',
                         'map-wrap', 'destination-overlap', 'kernel-corrupt', 'stack-overlap']
    checks = []
    report = Path(report)
    report.parent.mkdir(parents=True, exist_ok=True)
    for label in selected:
        rid = start(timeout=30, manual=True, paused=True, image=image, symbols=symbols,
                    boot_kernel=boot_kernel, mode='long64', memory=64, network='none')['run_id']
        run = get_run(rid)
        debugger = None
        check = {'case': label, 'run_id': rid, 'writes': [], 'ok': False}
        try:
            debugger = Debugger(Path('/tmp') / ('ose-' + rid[:8]) / 'gdb', symbols)

            def execute(commands, mode='protected32'):
                result = debugger.run(commands, mode)
                assert result['ok'], result
                return result

            def number(expression):
                return int(execute(['-data-evaluate-expression ' + json.dumps(expression)])['values'][0].split()[0], 0)

            def memory(address, length):
                return bytes.fromhex(''.join(execute([f'-data-read-memory-bytes {address:#x} {length}'])['memory_hex']))

            def write(address, data):
                previous = memory(address, len(data))
                execute([f'-data-write-memory-bytes {address:#x} {data.hex()}'])
                actual = memory(address, len(data))
                assert actual == data
                check['writes'].append({'address': address, 'before': previous.hex(), 'after': actual.hex()})

            execute(['-interpreter-exec console ' + json.dumps(f'add-symbol-file {boot_kernel} {entry:#x}'),
                     f'-break-insert -h *{entry:#x}', '-exec-continue'])
            assert number('$pc') == entry
            info = number('$ebx')
            original = memory(info, 56)
            assert struct.unpack_from('<II', original) == (0x336ec578, 1)
            pointer = struct.unpack_from('<Q', original, 40)[0]
            count = struct.unpack_from('<I', original, 48)[0]
            assert 0 < count <= 64 and 0x1000 <= pointer <= 0x400000 - count * 24
            records = memory(pointer, count * 24)
            check['start_info'] = {'address': info, 'bytes': original.hex(), 'map_address': pointer,
                                   'map_count': count, 'map_bytes': records.hex()}
            if label == 'magic':
                write(info, struct.pack('<I', 0))
            elif label == 'version':
                write(info + 4, struct.pack('<I', 2))
            elif label in ('count-zero', 'count-overflow'):
                write(info + 48, struct.pack('<I', 0 if label == 'count-zero' else 65))
            elif label == 'pointer-overflow':
                write(info + 40, struct.pack('<Q', 0xfffffff0))
            elif label == 'map-wrap':
                write(pointer, struct.pack('<QQ', 0xfffffffffffffff0, 32))
            elif label == 'destination-overlap':
                write(info + 40, struct.pack('<Q', 0x5000))
            elif label == 'kernel-corrupt':
                provenance = json.loads((boot_kernel.parent / 'pvh-inputs.json').read_text())
                address = 0x100000 if provenance.get('preload') else addresses['kernel_payload']
                byte = memory(address, 1)
                write(address, bytes([byte[0] ^ 1]))
            elif label == 'stack-overlap':
                write(0x7bfc, records)
                write(info + 40, struct.pack('<Q', 0x7bfc))
            else:
                raise ValueError(label)
            target = 0x100000 if label == 'stack-overlap' else addresses['pvh_failed']
            execute(['-break-delete', f'-break-insert -h *{target:#x}', '-exec-continue'])
            pc = number('$pc')
            check['expected_pc'], check['actual_pc'] = target, pc
            assert pc == target, check
            if label == 'stack-overlap':
                expected_map = b''.join(records[i:i + 20] + struct.pack('<I', 1)
                                        for i in range(0, len(records), 24))
                assert memory(0x5010, len(records)) == expected_map
                kernel = (boot_kernel.parent / 'kernel.bin').read_bytes()
                assert memory(0x100000, len(kernel)) == kernel
                check['actual_map_copy_matches'] = True
                check['actual_kernel_copy_matches'] = True
            check['ok'] = True
        except Exception as error:
            check['error'] = repr(error)
        finally:
            if debugger:
                (run / 'pvh-test.mi').write_bytes(debugger.transcript)
                debugger.close()
            if not check['ok']:
                try:
                    check['failure_capture'] = call(rid, {'operation': 'capture', 'mode': 'protected32'})
                except Exception as error:
                    check['capture_error'] = repr(error)
            check['stop'] = call(rid, {'operation': 'stop'})
            checks.append(check)
            report.write_text(json.dumps({'ok': all(c['ok'] for c in checks), 'image_sha256': digest(image),
                                         'symbols_sha256': digest(symbols), 'boot_kernel_sha256': digest(boot_kernel),
                                         'checks': checks}, indent=2) + '\n')
        if not check['ok']:
            raise AssertionError(check)
    return checks


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--symbols', required=True)
    parser.add_argument('--boot-kernel', required=True)
    parser.add_argument('--report', default='local/pvh-boundaries.json')
    parser.add_argument('--case', action='append', dest='cases')
    args = parser.parse_args()
    test(args.image, args.symbols, args.boot_kernel, args.report, args.cases)
