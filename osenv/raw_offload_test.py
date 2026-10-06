"""Actual extended TX checksum seeds and two-descriptor ownership acceptance.

Uses the real driver's quiesced device context and its unchanged original
checks. Metadata/seed success does not prove final wire checksum insertion.
"""
import argparse
import json
import struct
from pathlib import Path
from .raw_driver_test import test as driver_test


MUTANT_ERROR = 'offload data TXSM metadata mismatch'


def _checks(guest, invoke, checks, symbols, mmio, run, set32, u32):
    # Actual extendedTX metadata oracle. DMA is quiesced: seed is not finalchecksum.
    from .raw_primitives_test import checksum as independent_checksum
    import random
    vectors=[]
    rng=random.Random(0x2407)
    def fold_seed(data):
        value=sum(int.from_bytes(data[i:i+2],'big') for i in range(0,len(data),2))
        while value>>16:value=(value&65535)+(value>>16)
        return value
    def prepare_slots(slot,head=None,status0=1,status1=1):
        following=(slot+1)&7
        set32(0x180114,slot);set32(mmio+0x3818,slot)
        set32(mmio+0x3810,slot if head is None else head)
        assert u32(mmio+0x3810)==(slot if head is None else head),'quiescedTDH setup failed'
        for index,status in ((slot,status0),(following,status1)):
            guest.write(0x181080+index*16,struct.pack('<QHBBBBH',0x186000+index*2048,0,0,0,status,0,0))
        return following
    def seeded_send(slot,length,flags=0x18):
        following=prepare_slots(slot)
        source=rng.getrandbits(32).to_bytes(4,'big');destination=rng.getrandbits(32).to_bytes(4,'big')
        port=rng.randrange(1,65536);sequence=rng.getrandbits(32);ack=rng.getrandbits(32)
        guest.write(0x190010,source);guest.write(0x190044,destination)
        guest.write(0x190048,port.to_bytes(2,'big'));guest.write(0x190050,struct.pack('<I',ack))
        guest.write(0x190090,bytes.fromhex('020000000002'))
        address=symbols['http_response_3']
        payload=guest.read(address,length)
        invoke('net_tcp_send',{'rdi':flags,'rsi':sequence,'rdx':address,'rcx':length})
        header_length=24 if flags&2 else 20
        tcp_length=header_length+length
        total=34+tcp_length
        offload=tcp_length>=26
        if offload:
            context=guest.read(0x181080+slot*16,16)
            descriptor=guest.read(0x181080+following*16,16)
            assert context[:8]==struct.pack('<IBBH',0,34,50,total-1),'actualcontext checksum offsets'
            assert context[8:]==struct.pack('<II',0x2b000000,0),'actualcontext RS/DEXT/type/state'
            assert descriptor[8:]==struct.pack('<II',total|0x2b100000,0x200), 'offload data TXSM metadata mismatch'
            assert int.from_bytes(descriptor[:8],'little')==0x186000+following*2048
            assert u32(0x180114)==(slot+2)&7 and u32(mmio+0x3818)==(slot+2)&7
            frame=guest.read(0x186000+following*2048,total)
        else:
            descriptor=guest.read(0x181080+slot*16,16)
            assert descriptor[10:]==bytes.fromhex('000b00000000'),'smallpacket ordinarymetadata'
            assert int.from_bytes(descriptor[8:10],'little')==max(60,total)
            assert u32(0x180114)==(slot+1)&7
            frame=guest.read(0x186000+slot*2048,max(60,total))
            assert frame[total:]==bytes(max(60,total)-total),'smallpacket zero padding'
        ip=frame[14:34];tcp=frame[34:total]
        assert independent_checksum(ip)==0 and int.from_bytes(ip[2:4],'big')==20+tcp_length
        assert ip[12:20]==source+destination and ip[9]==6
        assert tcp[:4]==struct.pack('!HH',80,port)
        assert tcp[4:12]==struct.pack('!II',sequence,ack)
        assert tcp[12]>>4==header_length//4 and tcp[13]==flags
        assert tcp[header_length:]==payload
        pseudo=source+destination+b'\x00\x06'+tcp_length.to_bytes(2,'big')
        if offload:
            assert int.from_bytes(tcp[16:18],'big')==fold_seed(pseudo),'actualuncomplemented pseudoheader seed'
        else:
            assert independent_checksum(pseudo+tcp)==0,'actualsmallpacket finalCPUchecksum'
        vectors.append({'slot':slot,'flags':flags,'length':length,'offload':offload,'frame_hex':frame.hex(),'source_hex':source.hex(),'destination_hex':destination.hex(),'sequence':sequence,'ack':ack})
        return frame[:total]
    for slot,length,flags in ((0,6,0x18),(2,7,0x19),(4,100,0x18),(7,1460,0x18),(3,6,0x12),(5,0,0x10),(6,0,0x12),(1,5,0x18)):
        good_frame=seeded_send(slot,length,flags)
    # Use a complete valid offload frame as directNIC API input.
    good_frame=seeded_send(7,100)
    guest.write(0x1b0000,good_frame)
    for slot,head,status0,status1 in ((0,0,0,1),(1,1,1,0),(2,2,3,1),(3,3,1,3),(6,0,1,1)):
        following=prepare_slots(slot,head,status0,status1)
        before0=guest.read(0x181080+slot*16,16);before1=guest.read(0x181080+following*16,16)
        buffer=0x186000+following*2048;guest.write(buffer,b'\xcc'*len(good_frame))
        tail=u32(mmio+0x3818)
        assert invoke('nic_send_tcp',{'rdi':0x1b0000,'rsi':len(good_frame)})['rax']==0,'ownership/fullring refusal'
        assert guest.read(0x181080+slot*16,16)==before0 and guest.read(0x181080+following*16,16)==before1
        assert guest.read(buffer,len(good_frame))==b'\xcc'*len(good_frame) and u32(mmio+0x3818)==tail
    for mutate in ('ethertype','IPheader','protocol','shortIP','excessIP','TCPheader'):
        frame=bytearray(good_frame)
        if mutate=='ethertype':frame[12]^=1
        elif mutate=='IPheader':frame[14]=0x46
        elif mutate=='protocol':frame[23]=17
        elif mutate=='shortIP':frame[16:18]=struct.pack('!H',40)
        elif mutate=='excessIP':frame[16:18]=struct.pack('!H',len(frame)+1)
        else:frame[46]=0x40
        prepare_slots(0);guest.write(0x1b0000,frame)
        assert invoke('nic_send_tcp',{'rdi':0x1b0000,'rsi':len(frame)})['rax']==0,mutate
    # Simulate realhardware completedcontext reuse, then call ordinaryAPI.
    seeded_send(7,100)
    context=bytearray(guest.read(0x181080+7*16,16));context[12]=1
    guest.write(0x181080+7*16,context);set32(0x180114,7);set32(mmio+0x3818,7)
    ordinary=bytes(range(60));guest.write(0x1b0000,ordinary)
    assert invoke('nic_send',{'rdi':0x1b0000,'rsi':len(ordinary)})['rax']==1
    descriptor=guest.read(0x181080+7*16,16)
    assert int.from_bytes(descriptor[:8],'little')==0x186000+7*2048,'completedcontext buffer restoration'
    assert guest.read(0x186000+7*2048,60)==ordinary and descriptor[10:]==bytes.fromhex('000b00000000')
    (run/'t024-offload-seeds-and-metadata.json').write_text(json.dumps({'seed':0x2407,'vectors':vectors,'scope':'Actual guest seeds, descriptors and DMA; engine quiesced. Final wire checksums require separate e1000/e1000e gates.'},indent=2)+'\n')
    checks.append({'case':'extendedTXseed-context-data-ownership-wrap-fallback','vectors':len(vectors),'ok':True})


def test(build, output, mutant=False):
    if not __debug__:
        raise RuntimeError('Offload acceptance requires Python assertions enabled')
    mutation = {'requested':bool(mutant), 'applied':False, 'restored':False}

    def extra(guest, invoke, checks, symbols, mmio, run, set32, u32, originals):
        address = None
        saved = None
        try:
            if mutant:
                # Isolated GDB mutation of the existing authored TXSM immediate.
                # No generated instructions or alternative guest implementation.
                start = symbols['nic_send_tcp']
                end = symbols['transport_seed']
                code = guest.read(start, end-start)
                token = bytes.fromhex('41c7420c00020000')
                if code.count(token) != 1:
                    raise ValueError('Expected unique authored TXSM publication')
                address = start+code.index(token)+5
                saved = guest.read(address,1)
                if saved != b'\x02':
                    raise ValueError('Unexpected original TXSM byte')
                originals.append((address,saved))
                guest.write(address,b'\x00')
                mutation.update({'applied':True,'address':address,
                                 'original_hex':saved.hex(),'mutant_hex':'00'})
            _checks(guest, invoke, checks, symbols, mmio, run, set32, u32)
        finally:
            if address is not None and saved is not None:
                guest.write(address,saved)
                mutation['restored'] = guest.read(address,1) == saved
                if not mutation['restored']:
                    raise RuntimeError('TXSM mutant opcode restoration failed')
            (run/'raw-offload-mutation.json').write_text(json.dumps(mutation,indent=2)+'\n')

    result = driver_test(build,output,extra=extra)
    result['offload_scope'] = ('Actual guest pseudoheader seeds, context/data metadata, '
                              'copied DMA bytes, ownership and fallback; device quiesced. '
                              'Final wire insertion is a separate gate.')
    result['mutation'] = mutation
    result['mutant'] = bool(mutant)
    from .core import get_run
    run = get_run(result['run_id'])
    cleanup_failed = (run/'raw-driver-restore-failure.txt').exists()
    result['mutant_rejected'] = bool(mutant and mutation['applied'] and
                                     mutation['restored'] and not result['ok'] and
                                     result.get('error') == MUTANT_ERROR and
                                     not result.get('unexpected_resets') and not cleanup_failed)
    # Preserve the driver evidence and add this gate's explicit scoped verdict.
    Path(output).write_text(json.dumps(result,indent=2)+'\n')
    (run/'raw-offload-verdict.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--mutant',action='store_true')
    args = parser.parse_args()
    result = test(args.build,args.output,args.mutant)
    print(json.dumps(result,indent=2))
    return 0 if result['ok'] or (args.mutant and result['mutant_rejected']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
