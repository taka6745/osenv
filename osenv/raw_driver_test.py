"""Direct real-image NIC calls with injected DMA descriptor faults and guards.

No guest instructions are generated. Devices remain real; RX/TX engines are
quiesced during descriptor fault injection. Wire delivery is a separate gate.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import struct
import traceback
from .worker import start
from .core import get_run
from .__main__ import call
from .raw_primitives_test import ActualGuest, PRESERVED


def test(build, output, mutant=False, extra=None):
    if not __debug__:
        raise RuntimeError('Assertions required')
    output=Path(output).resolve()
    if output.exists():
        raise FileExistsError('Preserve prior evidence: choose fresh output')
    output.parent.mkdir(parents=True,exist_ok=True)
    build=Path(build).resolve()
    provenance=json.loads((build/'manifest.json').read_text())
    symbols=provenance['symbols']
    launch=start(timeout=120,manual=True,paused=True,image=build/'oslab.img',
                 symbols=build/'kernel.elf',mode='long64',network='isolated',
                 memory=64,timing='realtime',nic_model='e1000e')
    rid=launch['run_id']; run=get_run(rid)
    result={'ok':False,'run_id':rid,'image_sha256':hashlib.sha256((build/'oslab.img').read_bytes()).hexdigest(),
            'source_hashes':provenance['sources'],
            'scope':'real guest functions and MMIO; DMA engines quiesced for descriptor fault inputs; no wire-delivery claim'}
    guest=None; saved=None; originals=[]; mmio=None; controls={}; checks=[]
    try:
        socket=Path(json.loads((run/'manifest.json').read_text())['socket_directory'])/'gdb'
        guest=ActualGuest(socket,build/'kernel.elf')
        guest.command(f'-break-insert -h *{symbols["raw_loop"]:#x}')
        guest.command('-exec-continue',timeout=15)
        saved=guest.registers()
        assert saved['rip']==symbols['raw_loop']
        guest.command(f'-break-insert -h *{symbols["raw_fault"]:#x}')
        mmio=int.from_bytes(guest.read(0x180108,8),'little')
        assert mmio >= 0xc0000000
        for offset in (0x100,0x400,0x2818,0x3818,0x3810):
            controls[offset]=guest.read(mmio+offset,4)
        for offset in (0x100,0x400):
            guest.write(mmio+offset,(int.from_bytes(controls[offset],'little')&~2).to_bytes(4,'little'))
        for address,size in ((0x180000,0xb000),(0x1b0000,0x21000),(0x1fe000,0x2000),(0x92008,8),(0x190000,0x3000)):
            originals.append((address,guest.read(address,size)))
        if mutant:
            if mutant=='rx-budget':
                code=guest.read(symbols['nic_rx_drop'],symbols['nic_rx_none']-symbols['nic_rx_drop'])
                address=symbols['nic_rx_drop']+code.index(bytes.fromhex('41ffc8'))+2
                originals.append((address,guest.read(address,1)))
                guest.write(address,b'\xc0') # Test-only increment instead of decrement budget.
            else:
                code=guest.read(symbols['nic_send'],symbols['nic_tx_bad']-symbols['nic_send'])
                address=symbols['nic_send']+code.index(bytes.fromhex('f3aa'))
                originals.append((address,guest.read(address,2)))
                guest.write(address,bytes.fromhex('9090')) # Test-only missing padding.
        guest.write(0x92008,bytes(8)); guest.set({'cr3':saved['cr3']})
        sentinels={r:0xa5100000+i*0x101 for i,r in enumerate(PRESERVED)}

        def invoke(name,args=None,max_rx_iterations=None):
            guest.write(0x1cfff8,struct.pack('<Q',symbols['raw_loop']))
            guest.set({**sentinels,**(args or {}),'rsp':0x1cfff8,'rip':symbols[name],
                       'eflags':saved['eflags']&~0x600})
            breakpoint=None
            if max_rx_iterations is not None:
                reply=guest.command(f'-break-insert -h *{symbols["nic_rx_next"]:#x}')
                breakpoint=re.search(r'number="(\d+)"',reply)[1]
            iterations=0
            while True:
                guest.command('-exec-continue')
                registers=guest.registers()
                if max_rx_iterations is None or registers['rip']!=symbols['nic_rx_next']:
                    break
                iterations+=1
                assert iterations<=max_rx_iterations,'RX work budget exceeded'
            if breakpoint:
                guest.command('-break-delete '+breakpoint)
                registers['driver_iterations']=iterations
            assert registers['rip']==symbols['raw_loop'],(name,'actual guest fault',registers)
            assert registers['rsp']==0x1d0000 and not registers['eflags']&0x400
            assert all(registers[r]==v for r,v in sentinels.items()),name
            return registers

        def u32(address):
            return int.from_bytes(guest.read(address,4),'little')

        def set32(address,value):
            guest.write(address,struct.pack('<I',value))

        def rx_reset(slot=0):
            for i in range(8):
                guest.write(0x181000+i*16,struct.pack('<QH HBBH',0x182000+i*2048,0,0,0,0,0))
            set32(0x180110,slot); set32(0x180118,0)
            set32(mmio+0x2818,(slot+7)%8)

        for status,error,length in [(0,0,14),(1,0,14),(3,1,14),(3,0,0),(3,0,13),
                                    (3,0,14),(3,0,1514),(3,0,1515),(3,0,2048)]:
            slot=3; rx_reset(slot)
            guest.write(0x181000+slot*16+8,struct.pack('<HHBBH',length,0,status,error,0))
            assert invoke('nic_pending')['rax']==(status&1)
            returned=invoke('nic_receive')
            valid=status==3 and not error and 14<=length<=1514
            if valid:
                assert returned['rax']==0x182000+slot*2048 and returned['rdx']==length
                assert u32(0x180110)==slot and u32(0x180118)==1
                assert invoke('nic_receive')['rax']==0
                invoke('nic_release')
                assert u32(0x180118)==0
            else:
                assert returned['rax']==0 and returned['rdx']==0
            advanced=bool(status&1)
            assert u32(0x180110)==(slot+advanced)%8
            assert guest.read(0x181000+slot*16+12,1)==bytes([0 if advanced else status])
            if advanced:
                assert u32(mmio+0x2818)==slot
            head=u32(0x180110); tail=u32(mmio+0x2818)
            invoke('nic_release')
            assert u32(0x180110)==head and u32(mmio+0x2818)==tail
            checks.append({'function':'nic_receive','status':status,'errors':error,'length':length,
                           'accepted':valid,'released':advanced,'head':head})
        rx_reset()
        for i in range(8):
            guest.write(0x181000+i*16+8,struct.pack('<HHBBH',2048,0,3,1,0))
        bounded=invoke('nic_receive',max_rx_iterations=8)
        assert bounded['rax']==0 and bounded['driver_iterations']==8
        assert u32(0x180110)==0 and u32(mmio+0x2818)==7
        assert all(guest.read(0x181000+i*16+12,1)==b'\0' for i in range(8))
        checks.append({'function':'nic_receive','case':'eight malformed descriptors bounded wrap','actual_descriptor_iterations':bounded['driver_iterations'],'ok':True})
        for status in (0,3,5,9):
            set32(0x180114,0)
            guest.write(0x181080,struct.pack('<QHBBBBH',0x186000,0,0,0,status,0,0))
            before=guest.read(0x181080,16); tail=u32(mmio+0x3818)
            assert invoke('nic_send',{'rdi':0x200000,'rsi':14})['rax']==0
            assert guest.read(0x181080,16)==before and u32(mmio+0x3818)==tail
            checks.append({'function':'nic_send','descriptor_status':status,'rejected':True})
        for length in (0,13,14,59,60,1514,1515):
            slot=7; buffer=0x186000+slot*2048
            set32(0x180114,slot)
            set32(mmio+0x3818,slot)
            guest.write(0x181080+slot*16,struct.pack('<QHBBBBH',buffer,0,0,0,1,0,0))
            guest.write(buffer-1,b'\xa5'+b'\xcc'*2048+b'\x5a')
            valid=14<=length<=1514
            payload=bytes((i*17+3)&255 for i in range(length))
            address=0x200000-length if valid else 0x200000
            if valid:
                guest.write(address,payload)
            before=guest.read(0x181080+slot*16,16); tail=u32(mmio+0x3818)
            returned=invoke('nic_send',{'rdi':address,'rsi':length})
            assert returned['rax']==int(valid)
            if valid:
                size=max(60,length)
                actual=guest.read(buffer,size)
                assert actual==payload+bytes(size-length),'TX padding/content mismatch'
                descriptor=guest.read(0x181080+slot*16,16)
                assert int.from_bytes(descriptor[8:10],'little')==size
                assert descriptor[10:]==bytes.fromhex('000b00000000')
                assert u32(0x180114)==0 and u32(mmio+0x3818)==0
                assert guest.read(buffer+size,1)==b'\xcc'
            else:
                assert guest.read(0x181080+slot*16,16)==before and u32(mmio+0x3818)==tail
            assert guest.read(buffer-1,1)==b'\xa5' and guest.read(buffer+2048,1)==b'\x5a'
            checks.append({'function':'nic_send','length':length,'queued':valid,'zero_padding_checked':valid and length<60})
        if extra:
            extra(guest, invoke, checks, symbols, mmio, run, set32, u32, originals)
        result.update({'ok':True,'checks':checks,'guard_boundary':0x200000})
    except Exception as error:
        result['error']=str(error) or type(error).__name__
        result['mutant_rejected']=bool(mutant and str(error) in ('TX padding/content mismatch','RX work budget exceeded'))
        result['mutant']=mutant
        result['checks']=checks
        (run/'raw-driver-failure.txt').write_text(traceback.format_exc())
    finally:
        if guest:
            try:
                call(rid,{'operation':'debug','action':'pause'}); guest.debugger.collect(0.05)
                guest.command('-break-delete')
                (run/'raw-driver-registers.json').write_text(json.dumps(guest.registers(),indent=2))
                (run/'raw-driver-observed-state.bin').write_bytes(guest.read(0x180000,0xb000))
                for address,data in originals:
                    guest.write(address,data)
                if saved:
                    guest.set(saved)
                if mmio:
                    for offset in (0x2818,0x3818,0x3810,0x100,0x400):
                        guest.write(mmio+offset,controls[offset])
                (run/'raw-driver.mi').write_bytes(guest.debugger.transcript)
                guest.debugger.close()
            except Exception:
                result['ok']=False
                (run/'raw-driver-restore-failure.txt').write_text(traceback.format_exc())
        events=[json.loads(line) for line in (run/'events.jsonl').read_text().splitlines() if line.strip()]
        result['unexpected_resets']=[event for event in events if event.get('event')=='RESET']
        if result['unexpected_resets']:
            result['ok']=False
        call(rid,{'operation':'stop'})
        output.write_text(json.dumps(result,indent=2)+'\n')
        (run/'raw-driver-verdict.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--build',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--mutant',action='store_true')
    parser.add_argument('--mutant-rx-budget',action='store_true')
    args=parser.parse_args()
    mutant='rx-budget' if args.mutant_rx_budget else args.mutant
    result=test(args.build,args.output,mutant)
    print(json.dumps(result,indent=2))
    raise SystemExit(0 if result['ok'] or (mutant and result.get('mutant_rejected')) else 1)
