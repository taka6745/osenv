"""Actual HPET reciprocal-clock execution and qword-zero guard gate.

Uses only the release ELF's guest functions. Counter injection is performed with
HPET disabled. This disposable VM is stopped afterward; clock continuity through
counter injection is deliberately not claimed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import time
import traceback

from .__main__ import call
from .core import get_run
from .raw_primitives_test import ActualGuest, PRESERVED, elf_symbols
from .raw_test import primitive_gate
from .worker import start


HPET = 0xfed00000


def test(build, output):
    if not __debug__:
        raise RuntimeError('Assertions required for raw acceptance')
    build, output = Path(build).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((build/'manifest.json').read_text())
    image_hash = hashlib.sha256((build/'oslab.img').read_bytes()).hexdigest()
    assert image_hash == manifest['image_sha256']
    symbols = elf_symbols(build/'kernel.elf')
    for name in ['raw_loop', 'raw_fault', 'clock_ms', 'mem_zero']:
        assert symbols[name] == manifest['symbols'][name]
    seed = 0x1052026
    rng = random.Random(seed)
    counters = {0, 1, 31, 32, 99999, 100000, 100001, (1 << 64)-1}
    for bits in range(64):
        for delta in [-1, 0, 1]:
            value = (1 << bits)+delta
            if 0 <= value < 1 << 64:
                counters.add(value)
    # Explicit quotient/remainder boundaries throughout the full count range.
    for quotient in [1, 2, 31, (1 << 32)-1, ((1 << 64)-1)//100000]:
        for remainder in [0, 1, 31, 32, 99998, 99999]:
            value = quotient*100000+remainder
            if value < 1 << 64:
                counters.add(value)
    counters.update(rng.getrandbits(64) for _ in range(32))
    rid = start(timeout=120, manual=True, image=build/'oslab.img',
                symbols=build/'kernel.elf', mode='long64', memory=64,
                network='isolated', nic_model='e1000e', minimal_devices=True,
                nic_rom=False, timing='realtime')['run_id']
    run = get_run(rid)
    result = {'ok': False, 'run_id': rid, 'image_sha256': image_hash,
              'elf_sha256': hashlib.sha256((build/'kernel.elf').read_bytes()).hexdigest(),
              'seed': seed, 'checks': [], 'clock_continuity': 'not claimed; VM stopped after test'}
    vm = None
    saved = None
    originals = []
    original_config = original_counter = original_pde = None
    mutant_original = None
    mutant_address = symbols['clock_ms']+25
    try:
        time.sleep(.3)
        assert call(rid, {'operation': 'debug', 'action': 'pause'})['ok']
        runtime = json.loads((run/'manifest.json').read_text())
        vm = ActualGuest(Path(runtime['socket_directory'])/'gdb', build/'kernel.elf')
        vm.command(f'-break-insert -h *{symbols["raw_loop"]:#x}')
        vm.command('-exec-continue')
        saved = vm.registers()
        assert saved['rip'] == symbols['raw_loop']
        originals = [(address, vm.read(address, size)) for address, size in
                     [(0x1b0000, 0x21000), (0x1fe000, 0x2000)]]
        original_pde = vm.read(0x92008, 8)
        original_config = vm.read(HPET+0x10, 8)
        original_counter = vm.read(HPET+0xf0, 8)
        caps = int.from_bytes(vm.read(HPET, 8), 'little')
        assert caps >> 32 == 10000000, hex(caps)
        assert caps & (1 << 13), 'HPET counter lacks advertised64-bit capability'
        result['capabilities'] = hex(caps)
        config = int.from_bytes(original_config, 'little')
        vm.write(HPET+0x10, struct.pack('<Q', config & ~1))
        assert not int.from_bytes(vm.read(HPET+0x10, 8), 'little') & 1
        frozen = vm.read(HPET+0xf0, 8)
        time.sleep(.002)
        assert vm.read(HPET+0xf0, 8) == frozen
        vm.command(f'-break-insert -h *{symbols["raw_fault"]:#x}')
        sentinels = {name: 0xabcd0000+i*0x101 for i, name in enumerate(PRESERVED)}

        def invoke(name, arguments=None):
            vm.write(0x1cfff8, struct.pack('<Q', symbols['raw_loop']))
            vm.set({**sentinels, **(arguments or {}), 'rsp': 0x1cfff8,
                    'rip': symbols[name], 'eflags': saved['eflags'] & ~0x600})
            vm.command('-exec-continue')
            registers = vm.registers()
            assert registers['rip'] == symbols['raw_loop'], (name, registers)
            assert registers['rsp'] == 0x1d0000
            assert all(registers[key] == value for key, value in sentinels.items())
            assert not registers['eflags'] & 0x400
            return registers['rax']

        def inject(counter):
            vm.write(HPET+0xf0, struct.pack('<Q', counter))
            assert int.from_bytes(vm.read(HPET+0xf0, 8), 'little') == counter

        for counter in sorted(counters):
            inject(counter)
            actual = invoke('clock_ms')
            expected = counter//100000
            assert actual == expected, (counter, actual, expected)
            result['checks'].append({'counter': counter, 'expected_ms': expected,
                                     'actual_ms': actual, 'ok': True})
        # Mutate only an immediate byte in the loaded image, never the file.
        mutant_original = vm.read(mutant_address, 1)
        assert mutant_original == b'\x0a'
        try:
            vm.write(mutant_address, b'\x09')
            inject((1 << 64)-1)
            actual = invoke('clock_ms')
            assert actual != ((1 << 64)-1)//100000, 'Clock mutant accepted'
            result['checks'].append({'case': 'reciprocal-magic-mutant-rejected',
                                     'actual_ms': actual, 'ok': True})
        finally:
            vm.write(mutant_address, mutant_original)
            mutant_original = None
        inject((1 << 64)-1)
        assert invoke('clock_ms') == ((1 << 64)-1)//100000
        result['checks'].append({'case': 'reciprocal-code-restored', 'ok': True})
        # Actual qword zero routine at the unmapped hugepage boundary, every tail.
        vm.write(0x92008, bytes(8))
        vm.set({'cr3': saved['cr3']})
        try:
            vm.read(0x200000, 1)
        except RuntimeError:
            pass
        else:
            raise AssertionError('Guard page remains mapped')
        for length in range(32):
            address = 0x200000-length
            vm.write(address-1, b'\xa5'+b'\xcc'*length)
            assert invoke('mem_zero', {'rdi': address, 'rsi': length}) == 0
            assert vm.read(address-1, length+1) == b'\xa5'+bytes(length)
            result['checks'].append({'case': 'zero-guard', 'length': length, 'ok': True})
        vm.write(0x92008, original_pde)
        vm.set({'cr3': saved['cr3']})
        # Resume real HPET and real guest execution, then observe real progression.
        inject(1000000)
        vm.write(HPET+0x10, struct.pack('<Q', config | 1))
        assert int.from_bytes(vm.read(HPET+0x10, 8), 'little') & 1
        vm.set(saved)
        vm.command('-break-delete')
        before = int.from_bytes(vm.read(HPET+0xf0, 8), 'little')
        vm.debugger.send('-exec-continue')
        time.sleep(.012)
        assert call(rid, {'operation': 'debug', 'action': 'pause'})['ok']
        after = int.from_bytes(vm.read(HPET+0xf0, 8), 'little')
        assert after >= before+100000, (before, after)
        result['checks'].append({'case': 'real-enabled-hpet-progress',
                                 'before': before, 'after': after, 'ok': True})
        result['ok'] = True
    except Exception as error:
        result['error'] = repr(error)
        result['traceback'] = traceback.format_exc()
    finally:
        if vm is not None:
            try:
                if original_config is not None:
                    vm.write(HPET+0x10, struct.pack('<Q', int.from_bytes(original_config, 'little') & ~1))
                if mutant_original is not None:
                    vm.write(mutant_address, mutant_original)
                if original_pde is not None:
                    vm.write(0x92008, original_pde)
                if saved is not None:
                    vm.set({'cr3': saved['cr3']})
                for address, data in originals:
                    vm.write(address, data)
                if original_counter is not None:
                    vm.write(HPET+0xf0, original_counter)
                if original_config is not None:
                    vm.write(HPET+0x10, original_config)
                if saved is not None:
                    vm.set(saved)
                vm.command('-break-delete')
                result['restored'] = True
            except Exception as error:
                result['ok'] = False
                result['restore_error'] = repr(error)
            finally:
                vm.debugger.close()
        result['capture'] = call(rid, {'operation': 'capture', 'mode': 'long64'})
        result['stop'] = call(rid, {'operation': 'stop'})
        result['ok'] = result['ok'] and result['capture']['complete'] and result['stop']['ok']
        assert hashlib.sha256((build/'oslab.img').read_bytes()).hexdigest() == image_hash
        (run/'raw-clock.json').write_text(json.dumps(result, indent=2)+'\n')
        (output/'clock.json').write_text(json.dumps(result, indent=2)+'\n')
    primitives = primitive_gate(build, output/'primitives.json')
    report = {'ok': result['ok'] and primitives['ok'], 'clock': result,
              'primitives': primitives, 'image_sha256': image_hash}
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    report = test(args.build, args.output)
    print(json.dumps({'ok': report['ok'], 'clock_checks': len(report['clock']['checks']),
                      'clock_run': report['clock']['run_id'],
                      'primitive_run': report['primitives']['run_id']}))
    raise SystemExit(0 if report['ok'] else 1)
