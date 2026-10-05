"""Actual BIOS packed-decoder bounds, hash, overlap and exact-output gates.

Custom disks contain only project-authored literal instruction bytes. The outer
stored-payload hash is recomputed so malformed streams reach the real decoder.
Guards and input streams are data; no executable test adapter is generated.
"""
import argparse
import hashlib
import json
from pathlib import Path
import traceback
import time

from .__main__ import call
from .core import get_run
from .raw_build import place, span
from .raw_primitives_test import ActualGuest
from .worker import start


BASE = 0x100000
RELOCATED = 0x80000
GUARD = bytes((i * 29 + 17) & 255 for i in range(32))
SENTINEL = 0xa5


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fnv_reference(data):
    result = 2166136261
    for byte in data:
        result = ((result ^ byte) * 16777619) & 0xffffffff
    return result


def custom_disk(boot_source, packed_source, stream, decoded_size, decoded_hash):
    """Independently set image fields and place literal source; no production codec."""
    if not 1 <= decoded_size < 0xfe00:
        raise ValueError('Test decoded size outside actual raw loading bound')
    initial = {'blob_source': BASE, 'relocated_bytes': 1,
               'input_start': RELOCATED, 'input_end': RELOCATED + 1,
               'decoded_kernel_end': BASE + decoded_size,
               'decoded_kernel_size': decoded_size,
               'decoded_kernel_hash': decoded_hash}
    _, symbols, _ = place([packed_source], initial)
    stub_size = symbols['packed_stub_end'][0] - BASE
    decoder_size = symbols['packed_decoder_end'][0] - RELOCATED
    blob_size = decoder_size + len(stream)
    assert blob_size > 0 and RELOCATED + blob_size <= 0x90000
    fields = {**initial, 'blob_source': BASE + stub_size,
              'relocated_bytes': blob_size,
              'input_start': RELOCATED + decoder_size,
              'input_end': RELOCATED + blob_size}
    cells, symbols, _ = place([packed_source], fields)
    payload = (span(cells, BASE, BASE + stub_size)
               + span(cells, RELOCATED, RELOCATED + decoder_size) + stream)
    assert len(payload) < 0xfe00
    boot_fields = {'kernel_size': len(payload),
                   'kernel_sectors': (len(payload) + 511) // 512,
                   'kernel_hash': fnv_reference(payload)}
    boot_cells, boot_symbols, _ = place([boot_source], boot_fields)
    boot = span(boot_cells, 0x7c00, 0x7e00)
    assert boot[-2:] == b'\x55\xaa'
    image = boot + payload + bytes((-len(payload)) % 512)
    metadata = {'fields': fields, 'boot_fields': boot_fields,
                'stub_bytes': stub_size, 'decoder_bytes': decoder_size,
                'stream_hex': stream.hex(), 'payload_sha256': digest(payload),
                'image_sha256': digest(image),
                'symbols': {k: address for k, (address, _) in symbols.items()},
                'boot_symbols': {k: address for k, (address, _) in boot_symbols.items()}}
    return image, metadata


def test(build, output):
    if not __debug__:
        raise RuntimeError('Assertions required for packed acceptance')
    build, output = Path(build).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((build / 'manifest.json').read_text())
    original = (build / 'kernel.bin').read_bytes()
    image = (build / 'oslab.img').read_bytes()
    assert digest(image) == manifest['image_sha256']
    boot_source = build / 'sources/src/raw/boot.inc'
    packed_source = build / 'sources/src/raw/packed.inc'
    source_hashes = {str(p.relative_to(build / 'sources')): digest(p.read_bytes())
                     for p in [boot_source, packed_source]}
    for name, expected in source_hashes.items():
        assert manifest['sources'][name] == expected, (name, 'source snapshot mismatch')
    _, template = custom_disk(boot_source, packed_source, b'', 4, 0)
    packed_symbols = template['symbols']
    cases = []

    def run_case(name, disk_bytes, expected_output=None, custom=None):
        # expected_output=None denotes the complete real-kernel positive boot.
        full_kernel = expected_output is None
        success = full_kernel or name == 'valid-overlap'
        disk = output / (name + '.img')
        disk.write_bytes(disk_bytes)
        metadata = custom or {'image_sha256': digest(disk_bytes),
                              'symbols': packed_symbols,
                              'decoded_kernel_bytes': len(original)}
        (output / (name + '-input.json')).write_text(json.dumps(metadata, indent=2) + '\n')
        result = {'case': name, 'ok': False, 'image_sha256': digest(disk_bytes),
                  'source_hashes': source_hashes, 'input': metadata,
                  'expected_outcome': 'decoded jump' if success else 'decoder halt'}
        rid = start(timeout=40, paused=True, manual=True, image=disk,
                    symbols=build / 'kernel.elf', mode='protected32', memory=64,
                    network='isolated', nic_model='e1000e', minimal_devices=True,
                    nic_rom=False)['run_id']
        run = get_run(rid)
        result['run_id'] = rid
        guest = None
        try:
            runtime = json.loads((run / 'manifest.json').read_text())
            guest = ActualGuest(Path(runtime['socket_directory']) / 'gdb', build / 'kernel.elf')
            decoder = metadata['symbols']['packed_decode']
            fail = metadata['symbols']['packed_fail']
            guest.command(f'-break-insert -h *{decoder:#x}')
            guest.command('-exec-continue', timeout=15)
            before = guest.registers()
            assert before['rip'] == decoder, ('outer boot did not reach real decoder', before)
            guest.command('-break-delete')
            result['decoder_entry_registers'] = before
            if not full_kernel:
                size = custom['fields']['decoded_kernel_size']
                guest.write(BASE, bytes([SENTINEL]) * size)
                guest.write(BASE + size, GUARD)
                guest.write(BASE - len(GUARD), GUARD)
            target = BASE if success else fail
            guest.command(f'-break-insert -h *{target:#x}')
            if success:
                guest.command(f'-break-insert -h *{fail:#x}')
            guest.command('-exec-continue', timeout=15)
            registers = guest.registers()
            result['observed_registers'] = registers
            assert registers['rip'] == target, ('unexpected decoder result', registers, target)
            assert registers['rsp'] == before['rsp'], 'decoder leaked overlap-copy stack slot'
            assert registers['eflags'] & 0x400 == 0, 'decoder direction flag set'
            if full_kernel:
                actual = guest.read(BASE, len(original))
                assert actual == original, 'expanded real kernel differs from release bytes'
                result['decoded_kernel_sha256'] = digest(actual)
                result['decoded_kernel_bytes'] = len(actual)
            else:
                size = custom['fields']['decoded_kernel_size']
                actual = guest.read(BASE, size)
                expected = expected_output + bytes([SENTINEL]) * (size - len(expected_output))
                assert actual == expected, (name, actual.hex(), expected.hex())
                assert guest.read(BASE + size, len(GUARD)) == GUARD, 'output overflow'
                assert guest.read(BASE - len(GUARD), len(GUARD)) == GUARD, 'output underflow'
                result['decoded_output_hex'] = actual.hex()
                result['both_output_guards_unchanged'] = True
                if success:
                    # The valid overlap fixture is data, never a guest program.
                    # We proved the decoder's actual successful jump, then route
                    # cleanup to its authored halt before detaching the debugger.
                    guest.set({'rip': fail})
                    result['cleanup_rip'] = fail
                # Actually execute CLI/HLT, rather than accepting a breakpoint
                # at the error label alone. With IF cleared, EIP must remain at
                # the instruction after HLT until external QMP stops the CPU.
                guest.command('-break-delete')
                guest.debugger.send('-exec-continue')
                time.sleep(.03)
                paused = call(rid, {'operation': 'debug', 'action': 'pause',
                                    'mode': 'protected32'})
                assert paused['ok'], paused
                guest.debugger.collect(.05)
                halted = guest.registers()
                assert halted['rip'] == fail + 2, ('failure did not halt', halted)
                assert halted['eflags'] & 0x200 == 0, 'failure halt left IF enabled'
                result['halt_registers'] = halted
            result['ok'] = True
        except Exception as error:
            result['error'] = str(error) or type(error).__name__
            result['traceback'] = traceback.format_exc()
            if guest:
                try:
                    result['failure_registers'] = guest.registers()
                except Exception as capture_error:
                    result['register_capture_error'] = str(capture_error)
        finally:
            if guest:
                (run / 'raw-packed.mi').write_bytes(guest.debugger.transcript)
                try:
                    guest.debugger.close()
                except Exception as error:
                    result['debugger_close_error'] = str(error)
                    result['ok'] = False
            result['capture'] = call(rid, {'operation': 'capture', 'mode': 'protected32'})
            events = [json.loads(line) for line in (run / 'events.jsonl').read_text().splitlines()
                      if line.strip()]
            result['unexpected_resets'] = [event for event in events if event.get('event') == 'RESET']
            result['stop'] = call(rid, {'operation': 'stop'})
            result['ok'] = (result['ok'] and result['capture']['complete']
                            and result['stop']['ok'] and not result['unexpected_resets'])
            (output / (name + '.json')).write_text(json.dumps(result, indent=2) + '\n')
            (run / 'raw-packed-verdict.json').write_text(json.dumps(result, indent=2) + '\n')
            cases.append(result)

    run_case('complete-kernel', image)
    inputs = [
        ('truncated-literal', b'\x03ab', 4, b'', 0),
        ('short-match', b'\x80\x01', 4, b'', 0),
        ('zero-distance', b'\x80\x00\x00', 4, b'', 0),
        ('distance-before-output', b'\x80\x01\x00', 4, b'', 0),
        ('distance-beyond-produced', b'\x00A\x80\x02\x00', 4, b'A', 0),
        ('literal-output-overflow', b'\x04abcde', 4, b'', 0),
        ('match-output-overflow', b'\x00A\x81\x01\x00', 4, b'A', 0),
        ('wrong-original-hash', b'\x03ABCD', 4, b'ABCD', fnv_reference(b'ABCD') ^ 1),
        ('early-end', b'\x00A', 4, b'A', fnv_reference(b'AAAA')),
        ('empty-stream', b'', 4, b'', 0),
        ('trailing-garbage', b'\x03ABCD\x00Z', 4, b'ABCD', fnv_reference(b'ABCD')),
        ('valid-overlap', b'\x00A\x80\x01\x00', 4, b'AAAA', fnv_reference(b'AAAA')),
    ]
    for name, stream, size, decoded_prefix, decoded_hash in inputs:
        custom_image, metadata = custom_disk(boot_source, packed_source, stream, size, decoded_hash)
        run_case(name, custom_image, decoded_prefix, metadata)
    report = {'ok': all(case['ok'] for case in cases),
              'source_image_sha256': digest(image), 'decoded_kernel_sha256': digest(original),
              'source_hashes': source_hashes, 'harness_sha256': digest(Path(__file__).read_bytes()),
              'scope': 'actual BIOS disk chain and authored protected32 decoder; external guards, hashes, register and reset outcomes',
              'cases': cases}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    report = test(args.build, args.output)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['ok'] else 1)
