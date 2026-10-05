"""Real raw-image IRQ register preservation, HPET and idle CPU measurements."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
import traceback
from .worker import start
from .core import get_run
from .__main__ import call
from .raw_primitives_test import ActualGuest, CPU

GPRS = [r for r in CPU if r not in ('rip', 'rsp', 'eflags', 'cr3')]


def cpu_seconds(pid):
    value = subprocess.check_output(['ps', '-p', str(pid), '-o', 'time='], text=True).strip()
    fields = value.split(':')
    return sum(float(v)*60**i for i, v in enumerate(reversed(fields)))


def measurement(build, seconds=2):
    build = Path(build).resolve()
    launch = start(timeout=30, manual=True, image=build/'oslab.img', symbols=build/'kernel.elf',
                   mode='long64', network='isolated', memory=64, timing='realtime', nic_model='e1000e')
    rid, pid = launch['run_id'], launch['qemu_pid']
    try:
        time.sleep(3)
        begin, cpu = time.monotonic(), cpu_seconds(pid)
        time.sleep(seconds)
        elapsed, consumed = time.monotonic()-begin, cpu_seconds(pid)-cpu
        return {'run_id':rid, 'elapsed_seconds':elapsed, 'qemu_cpu_seconds':consumed,
                'cpu_percent_one_core':100*consumed/elapsed,
                'image_sha256':json.loads((get_run(rid)/'manifest.json').read_text())['image_sha256']}
    finally:
        call(rid, {'operation':'stop'})


def test(build, poll_build=None, mutant=False):
    if not __debug__:
        raise RuntimeError('Assertions required')
    build = Path(build).resolve()
    symbols = json.loads((build/'manifest.json').read_text())['symbols']
    launch = start(timeout=90, manual=True, paused=True, image=build/'oslab.img',
                   symbols=build/'kernel.elf', mode='long64', network='isolated', memory=64,
                   timing='realtime', nic_model='e1000e')
    rid, run = launch['run_id'], get_run(launch['run_id'])
    result = {'ok':False, 'run_id':rid}
    guest = None
    saved = None
    snapshots = []
    try:
        call(rid, {'operation':'trace', 'events':'int,guest_errors,cpu_reset'})
        socket = Path(json.loads((run/'manifest.json').read_text())['socket_directory'])/'gdb'
        guest = ActualGuest(socket, build/'kernel.elf')
        cli = symbols['idle_return']-1
        sti = cli-2
        guest.command(f'-break-insert *{sti:#x}')
        guest.command('-exec-continue', timeout=15)
        assert guest.registers()['rip'] == sti
        assert guest.read(sti,3) == bytes.fromhex('fbf4fa')
        guest.command('-break-delete')
        saved = guest.registers()
        if mutant:
            # Deliberate test-only POP destination defect; never modifies release files.
            stub=guest.read(symbols['raw_irq'],96)
            tail=bytes.fromhex('5f5e5d5b5a595848cf')
            pop=symbols['raw_irq']+stub.index(tail)+6
            snapshots.append((pop,guest.read(pop,1)))
            guest.write(pop,b'\x59')
        for address,size in [(0x180000,0x21000),(saved['rsp']-4096,8192)]:
            snapshots.append((address,guest.read(address,size)))
        gates = guest.read(0x1a0000,4096)
        for vector in range(256):
            d=gates[vector*16:vector*16+16]
            address=int.from_bytes(d[:2],'little') | int.from_bytes(d[6:8],'little')<<16 | int.from_bytes(d[8:12],'little')<<32
            assert address == symbols['raw_irq' if 32 <= vector < 48 else 'raw_fault']
            assert d[2:6] == bytes.fromhex('1800008e') and d[12:] == bytes(4)
        mmio=int.from_bytes(guest.read(0x180108,8),'little')
        period=int.from_bytes(guest.read(0x180120,8),'little')
        injections=[]
        for nic in (False,True,True):
            # Reuse existing STI/HLT/CLI; no guest instruction bytes are injected.
            values={r:0x1234567800000000+i*0x10203 for i,r in enumerate(GPRS)}
            values.update({'rip':sti,'rsp':saved['rsp'],'eflags':saved['eflags']&~0x600})
            guest.set(values)
            if nic:
                guest.write(mmio+0xc8,bytes.fromhex('80000000'))
            guest.command(f'-break-insert *{symbols["raw_irq"]+36:#x}')
            guest.command(f'-break-insert *{cli:#x}')
            guest.command('-exec-continue')
            observed=guest.registers()
            assert observed['rip']==symbols['raw_irq']+36, observed
            cause=observed['rax'] & 0xffffffff
            if nic:
                assert cause & 0x80, hex(cause)
            guest.command('-break-delete')
            guest.command(f'-break-insert *{cli:#x}')
            guest.command('-exec-continue')
            returned=guest.registers()
            assert returned['rip']==cli, returned
            assert {r:returned[r] for r in GPRS} == {r:values[r] for r in GPRS}, 'IRQ GPR preservation mismatch'
            assert returned['rsp']==saved['rsp']
            assert int.from_bytes(guest.read(mmio+0xc0,4),'little') == 0
            injections.append({'nic_injected':nic,'actual_icr':cause,'all_15_gprs_preserved':True})
            guest.command('-break-delete')
        before=int.from_bytes(guest.read(0xfed000f0,8),'little')
        guest.set({'rip':symbols['raw_halted'],'eflags':saved['eflags']&~0x600})
        guest.debugger.send('-exec-continue')
        guest.debugger.collect(0.02)
        time.sleep(0.12) # Running halted guest defers IRQ delivery; real HPET advances.
        call(rid, {'operation':'debug','action':'pause'})
        guest.debugger.collect(0.05)
        after=int.from_bytes(guest.read(0xfed000f0,8),'little')
        assert after > before
        result['hpet_deferred_ms']=(after-before)*period/1e12
        # Invoke the real guest conversion after deferring interrupts. IF1 lets
        # an already halted QEMU CPU wake; its existing ISR preserves call inputs.
        return_sp=saved['rsp']-8
        original_return=guest.read(return_sp,8)
        guest.write(return_sp,symbols['raw_loop'].to_bytes(8,'little'))
        guest.command(f'-break-insert *{symbols["raw_loop"]:#x}')
        guest.set({'rip':symbols['clock_ms'],'rsp':return_sp,
                   'eflags':(saved['eflags']|0x200)&~0x400})
        lower=int.from_bytes(guest.read(0xfed000f0,8),'little')*period//10**12
        guest.command('-exec-continue')
        converted=guest.registers()
        upper=int.from_bytes(guest.read(0xfed000f0,8),'little')*period//10**12
        assert converted['rip']==symbols['raw_loop']
        assert lower <= converted['rax'] <= upper
        guest.write(return_sp,original_return)
        result['guest_clock_ms']=converted['rax']
        result['guest_clock_oracle_range_ms']=[lower,upper]
        trace=(run/'trace.log').read_text(errors='replace')
        assert re.search(r'Servicing hardware INT=0x20',trace), trace[-2000:]
        result.update({'ok':True,'gates_checked':256,'injections':injections,'pit_vector32_observed':True})
    except Exception as error:
        result['error']=str(error) or type(error).__name__
        result['mutant_rejected']=bool(mutant and str(error)=='IRQ GPR preservation mismatch')
        (run/'raw-irq-failure.txt').write_text(traceback.format_exc())
    finally:
        if guest:
            try:
                call(rid, {'operation':'debug','action':'pause'})
                guest.debugger.collect(0.05)
                guest.command('-break-delete')
                for address,data in snapshots:
                    guest.write(address,data)
                if saved:
                    guest.set(saved)
                (run/'raw-irq.mi').write_bytes(guest.debugger.transcript)
                guest.debugger.close()
            except Exception:
                (run/'raw-irq-restore-failure.txt').write_text(traceback.format_exc())
                result['ok']=False
        call(rid, {'operation':'stop'})
    if result['ok']:
        result['idle_measurement']=measurement(build)
        if poll_build:
            result['poll_measurement']=measurement(poll_build)
        result['measurement_scope']='2-second isolated NIC QEMU TCG process CPU; observed values, no universal threshold'
    (run/'raw-irq-verdict.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--build',required=True)
    parser.add_argument('--poll-build')
    parser.add_argument('--mutant',action='store_true')
    args=parser.parse_args()
    answer=test(args.build,args.poll_build,args.mutant)
    print(json.dumps(answer,indent=2))
    raise SystemExit(0 if answer['ok'] or (args.mutant and answer.get('mutant_rejected')) else 1)
