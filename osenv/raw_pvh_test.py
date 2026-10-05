"""Actual literal PVH CPU/metadata/PCI failure gates; isolated mutations only."""
import argparse
import json
from pathlib import Path
import struct
from .worker import start
from .core import get_run, digest
from .__main__ import call
from .raw_primitives_test import ActualGuest

CASES = ('valid', 'magic', 'version', 'start-reserved', 'map-high', 'count-zero',
         'count-overflow', 'pointer-overflow', 'map-wrap', 'map-reserved',
         'low-ram-absent', 'high-ram-absent', 'aperture-occupied', 'kernel-corrupt',
         'stack-overlap', 'msr-missing', 'bar-probe-bad', 'bar-assignment-bad', 'pirq-bad')


def test(build, report, cases=None, mutant_magic=False, expected_bar=0xc0000000):
    if not __debug__:
        raise RuntimeError('Assertions are required for actual-image acceptance')
    if type(expected_bar) is not int or not 0xc0000000 <= expected_bar < 0xe0000000 or expected_bar & 0x1ffff:
        raise ValueError('Expected BAR must be aligned128KiB inside the validated aperture')
    build, report = Path(build).resolve(), Path(report).resolve()
    provenance = json.loads((build/'pvh-inputs.json').read_text())
    kernel_record = json.loads((build/'manifest.json').read_text())
    symbols = provenance['symbols'] | kernel_record['symbols']
    checks = []
    report.parent.mkdir(parents=True, exist_ok=True)
    selected = cases or (['magic'] if mutant_magic else CASES)
    for label in selected:
        if label not in CASES:
            raise ValueError(label)
        launch = start(timeout=30, manual=True, paused=True, image=build/'oslab.img',
                       symbols=build/'kernel.elf', boot_kernel=build/'pvh.elf',
                       mode='long64', memory=64, network='isolated', timing='realtime',
                       nic_model='e1000e', nic_rom=False, minimal_devices=True)
        rid, run = launch['run_id'], get_run(launch['run_id'])
        item = {'case':label, 'run_id':rid, 'ok':False, 'writes':[], 'registers':[],
                'deliberate_test_only_mutant':mutant_magic}
        guest = None
        try:
            manifest = json.loads((run/'manifest.json').read_text())
            guest = ActualGuest(Path(manifest['socket_directory'])/'gdb', build/'kernel.elf')
            guest.command('-interpreter-exec console '+json.dumps(
                f'add-symbol-file {build / "pvh-symbols.elf"} {symbols["raw_pvh_entry"]:#x}'))

            def until(addresses):
                guest.command('-break-delete')
                for address in addresses:
                    guest.command(f'-break-insert -h *{address:#x}')
                guest.command('-exec-continue', timeout=15)
                return guest.registers()['rip']

            def write(address, data):
                before = guest.read(address,len(data))
                guest.write(address,data)
                assert guest.read(address,len(data)) == data
                item['writes'].append({'address':address,'before':before.hex(),'after':data.hex()})

            def setreg(register, value):
                before = guest.registers()[register]
                guest.set({register:value})
                assert guest.registers()[register] == value
                item['registers'].append({'name':register,'before':before,'after':value})

            entry = symbols['raw_pvh_entry']
            assert until([entry]) == entry
            info = guest.registers()['rbx']
            original = guest.read(info,56)
            assert struct.unpack_from('<II',original) == (0x336ec578,1)
            pointer = struct.unpack_from('<Q',original,40)[0]
            count = struct.unpack_from('<I',original,48)[0]
            assert 0 < count <= 64 and 0x1000 <= pointer <= 0x400000-count*24
            records = guest.read(pointer,count*24)
            assert guest.read(0x100000,len((build/'kernel.bin').read_bytes())) == (build/'kernel.bin').read_bytes()
            item['metadata'] = {'address':info,'bytes':original.hex(),'map_address':pointer,
                                'map_count':count,'map_bytes':records.hex()}
            if mutant_magic:
                # Six-byte JNE after real magic comparison becomes six NOPs.
                # Only this isolated paused VM changes; build/source files do not.
                text = guest.read(entry,64)
                branch = entry+text.index(bytes.fromhex('813b78c56e330f85'))+6
                assert guest.read(branch,2) == b'\x0f\x85'
                write(branch,b'\x90'*6)
            if label == 'magic':
                write(info,struct.pack('<I',0))
            elif label == 'version':
                write(info+4,struct.pack('<I',2))
            elif label == 'start-reserved':
                write(info+52,struct.pack('<I',1))
            elif label == 'map-high':
                write(info+44,struct.pack('<I',1))
            elif label in ('count-zero','count-overflow'):
                write(info+48,struct.pack('<I',0 if label == 'count-zero' else 65))
            elif label == 'pointer-overflow':
                write(info+40,struct.pack('<Q',0xfffffff0))
            elif label == 'map-wrap':
                write(pointer,struct.pack('<QQ',0xfffffffffffffff0,32))
            elif label == 'map-reserved':
                write(pointer+20,struct.pack('<I',1))
            elif label in ('low-ram-absent','high-ram-absent'):
                minimum, maximum = (0x5000,0x96000) if label == 'low-ram-absent' else (0x100000,0x200000)
                matches = [i for i in range(count)
                           if (lambda b,n,t,r: t == 1 and b <= minimum and b+n >= maximum)(
                               *struct.unpack_from('<QQII',records,i*24))]
                assert matches
                for i in matches:
                    write(pointer+i*24+16,struct.pack('<I',2))
            elif label == 'aperture-occupied':
                available = [i for i in range(count) if struct.unpack_from('<I',records,i*24+16)[0] != 1]
                assert available, 'Need non-RAM record to isolate aperture exclusion'
                write(pointer+available[-1]*24,struct.pack('<QQII',0xc0000000,0x20000,2,0))
            elif label == 'kernel-corrupt':
                # Hash-only data mutation does not alter entry/interrupt control flow.
                address = symbols['http_response_0']
                byte = guest.read(address,1)
                write(address,bytes([byte[0]^1]))
            elif label == 'stack-overlap':
                write(0x7bf0,records)
                write(info+40,struct.pack('<Q',0x7bf0))
            elif label in ('msr-missing','bar-probe-bad','bar-assignment-bad','pirq-bad'):
                location, register, mask = {
                    'msr-missing':('raw_pvh_cpu_features','rdx',~0x20),
                    'bar-probe-bad':('raw_pvh_bar_probe_result','rax',0),
                    'bar-assignment-bad':('raw_pvh_bar_assignment_result','rax',0),
                    'pirq-bad':('raw_pvh_pirq_result','rax',~0xff),
                }[label]
                assert until([symbols[location],symbols['raw_pvh_fail']]) == symbols[location]
                setreg(register,guest.registers()[register]&mask)
            expected = symbols['raw_loop'] if label in ('valid','stack-overlap') else symbols['raw_pvh_fail']
            actual = until([symbols['raw_pvh_fail'],symbols['raw_loop'],symbols['raw_fault'],entry])
            item['expected_pc'], item['actual_pc'] = expected,actual
            assert actual == expected, item
            if expected == symbols['raw_pvh_fail']:
                assert guest.read(expected,2) == bytes.fromhex('faf4')
                # Execute CLI then HLT; a breakpoint at halt confirms terminal path.
                assert until([symbols['raw_pvh_halted'],entry,symbols['raw_loop']]) == symbols['raw_pvh_halted']
                item['terminal_cli_hlt_verified'] = True
            else:
                assert guest.registers()['cr3'] == 0x90000
                assert guest.read(0x180108,8) == struct.pack('<Q',expected_bar)
                assert guest.read(0x18011c,4) == struct.pack('<I',11)
                assert guest.read(0x100000,len((build/'kernel.bin').read_bytes())) == (build/'kernel.bin').read_bytes()
                item['actual_kernel_dma_irq_state_verified'] = True
            item['ok'] = True
        except Exception as error:
            item['error'] = repr(error)
        finally:
            if guest:
                (run/'raw-pvh-test.mi').write_bytes(guest.debugger.transcript)
                guest.debugger.close()
            if not item['ok']:
                try:
                    item['failure_capture'] = call(rid,{'operation':'capture','mode':'protected32'})
                except Exception as error:
                    item['capture_error'] = repr(error)
            item['stop'] = call(rid,{'operation':'stop'})
            if not item['stop'].get('ok'):
                item.update(ok=False,cleanup_error=item['stop'])
            checks.append(item)
            report.write_text(json.dumps({'ok':all(c['ok'] for c in checks),
                'image_sha256':digest(build/'oslab.img'),'loader_sha256':digest(build/'pvh.elf'),
                'kernel_sha256':digest(build/'kernel.bin'),'deliberate_test_only_mutant':mutant_magic,
                'expected_bar':expected_bar,
                'checks':checks},indent=2)+'\n')
        if not item['ok']:
            raise AssertionError(item)
    return json.loads(report.read_text())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',required=True)
    parser.add_argument('--report',required=True)
    parser.add_argument('--case',action='append',dest='cases')
    parser.add_argument('--mutant-magic',action='store_true')
    parser.add_argument('--expected-bar',type=lambda value:int(value,0),default=0xc0000000)
    args = parser.parse_args()
    test(args.build,args.report,args.cases,args.mutant_magic,args.expected_bar)
