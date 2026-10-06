"""Actual static-response SG descriptors, final ownership and cached checksums.

The real driver context retains its original checks. Concatenating actual DMA
segments is an independent checksum/data oracle, not a final wire delivery gate.
"""
import argparse
import json
import struct
from pathlib import Path
from .raw_driver_test import test as driver_test


MUTANT_ERROR = 'second slot final owner must gate SG reuse'


def _checks(guest, invoke, checks, symbols, mmio, run, set32, u32):
    # Real two-descriptor SG reconstruction/lifetime oracle, DMA quiesced.
    from .raw_primitives_test import checksum as independent_checksum
    invoke('net_init')
    page=symbols['http_response_3'];size=u32(symbols['http_response3_length'])
    immutable=guest.read(page,size)
    assert u32(0x190110)==(~independent_checksum(immutable)&65535)
    assert guest.read(0x190114,1)==b'\x01'
    vectors=[]
    def slots(slot,head=None,status0=1,status1=1):
        following=(slot+1)&7
        set32(0x180114,slot);set32(mmio+0x3818,slot);set32(mmio+0x3810,slot if head is None else head)
        assert u32(mmio+0x3810)==(slot if head is None else head)
        for index,status in ((slot,status0),(following,status1)):
            guest.write(0x181080+index*16,struct.pack('<QHBBBBH',0x186000+index*2048,0,0,0,status,0,0))
            guest.write(0x190188+index,b'\x00')
        return following
    def tcp_case(slot,pointer,length,flags=0x18,ready=True,source=b'\x0a\x00\x02\x0f',dest=b'\x0a\x00\x02\x02',port=40000,sequence=0xfffffff0,ack=0xffffffff):
        following=slots(slot)
        guest.write(0x190010,source);guest.write(0x190044,dest);guest.write(0x190048,struct.pack('!H',port))
        set32(0x190050,ack);guest.write(0x190090,bytes.fromhex('020000000002'))
        guest.write(0x190114,bytes([int(ready)]))
        headerbuffer=0x186000+slot*2048
        guest.write(headerbuffer,b'\xcc'*2048)
        vector={'slot':slot,'pointer':pointer,'length':length,'flags':flags,'ready':ready,
                'source_hex':source.hex(),'destination_hex':dest.hex(),'port':port,
                'sequence':sequence,'ack':ack,'cache_sum':u32(0x190110)}
        vectors.append(vector)
        (run/'raw-sg-inputs-and-frames.json').write_text(json.dumps({'vectors':vectors},indent=2)+'\n')
        invoke('net_tcp_send',{'rdi':flags,'rsi':sequence,'rdx':pointer,'rcx':length})
        sg=ready and flags&2==0 and pointer==page and length==size
        if sg:
            first=guest.read(0x181080+slot*16,16);last=guest.read(0x181080+following*16,16)
            assert first==struct.pack('<QHBBBBH',headerbuffer,54,0,8,0,0,0),'actual SG first descriptor'
            assert last==struct.pack('<QHBBBBH',page,size,0,11,0,0,0),'actual SG final descriptor'
            assert u32(0x180114)==(slot+2)&7 and u32(mmio+0x3818)==(slot+2)&7
            assert guest.read(0x190188+slot,1)==bytes([following+1]),'final owner recorded'
            assert guest.read(headerbuffer+60,size)==b'\xcc'*size,'payload memcpy must be absent'
            frame=guest.read(headerbuffer,54)+guest.read(page,size)
        else:
            first=guest.read(0x181080+slot*16,16)
            expected=max(60,34+(24 if flags&2 else 20)+length)
            assert int.from_bytes(first[8:10],'little')==expected and first[10:]==bytes.fromhex('000b00000000')
            assert u32(0x180114)==(slot+1)&7
            frame=guest.read(headerbuffer,expected)
        actual_ip_length=int.from_bytes(frame[16:18],'big')
        tcp=frame[34:14+actual_ip_length]
        vector.update({'SG':sg,'frame_hex':frame.hex()})
        (run/'raw-sg-inputs-and-frames.json').write_text(json.dumps({'vectors':vectors},indent=2)+'\n')
        assert frame[26:34]==source+dest and tcp[:4]==struct.pack('!HH',80,port)
        assert tcp[4:12]==struct.pack('!II',sequence,ack)
        assert independent_checksum(frame[14:34])==0
        assert independent_checksum(source+dest+b'\x00\x06'+len(tcp).to_bytes(2,'big')+tcp)==0,'actual SG combined checksum'
        h=(tcp[12]>>4)*4
        assert tcp[h:]==guest.read(pointer,length),'reconstructed SG data'
        assert guest.read(page,size)==immutable,'immutable response must never be overwritten'
        return frame[:14+actual_ip_length]
    good=tcp_case(7,page,size)
    # Header DD alone cannot authorize reuse until the final payload DD.
    header=bytearray(guest.read(0x181080+7*16,16));header[12]=1;guest.write(0x181080+7*16,header)
    set32(0x180114,7);set32(mmio+0x3818,7)
    assert invoke('nic_tx_buffer')['rax']==0,'final descriptor ownership must gate header getter'
    guest.write(0x1b0000,bytes(range(60)))
    before=guest.read(0x186000+7*2048,60)
    assert invoke('nic_send',{'rdi':0x1b0000,'rsi':60})['rax']==0,'final descriptor must gate ordinary reuse'
    assert guest.read(0x186000+7*2048,60)==before
    final=bytearray(guest.read(0x181080,16));final[12]=1;guest.write(0x181080,final)
    assert invoke('nic_tx_buffer')['rax']==0x186000+7*2048
    assert invoke('nic_send',{'rdi':0x1b0000,'rsi':60})['rax']==1
    assert guest.read(0x186000+7*2048,60)==bytes(range(60))
    assert guest.read(0x190188+7,1)==b'\x00'
    # A completed payload slot's literal page pointer must become its owned buffer.
    set32(0x180114,0);set32(mmio+0x3818,0)
    assert invoke('nic_tx_buffer')['rax']==0x186000
    assert invoke('nic_send',{'rdi':0x1b0000,'rsi':60})['rax']==1
    assert int.from_bytes(guest.read(0x181080,8),'little')==0x186000
    assert guest.read(page,size)==immutable
    for slot,pointer,length,flags,ready in ((2,page,size,0x18,True),(4,page,100,0x18,True),(6,page,94,0x18,True),(1,symbols['http_response_0'],79,0x18,True),(3,page,0,0x10,True),(5,page,6,0x12,True),(0,page,size,0x18,False)):
        good=tcp_case(slot,pointer,length,flags,ready)
    # Live pseudoheader/header carry cases and seeded randomized endpoints.
    import random
    rng=random.Random(0x2408)
    for index in range(12):
        source=rng.getrandbits(32).to_bytes(4,'big')
        destination=rng.getrandbits(32).to_bytes(4,'big')
        good=tcp_case(index%8,page,size,0x18|(index&1),True,source,destination,
                      rng.randrange(1,65536),rng.getrandbits(32),rng.getrandbits(32))
    source=b'\xff'*4;destination=b'\xff'*4;port=65535;ack=0xffffffff
    header=struct.pack('!HHIIBBHHH',80,port,0,ack,0x50,0x18,768,0,0)
    pseudo=source+destination+b'\x00\x06'+(20+size).to_bytes(2,'big')
    sequence=independent_checksum(pseudo+header+immutable)
    zero=tcp_case(4,page,size,0x18,True,source,destination,port,sequence,ack)
    assert zero[50:52]==b'\x00\x00','actual cached checksum negative-zero encoding'
    # Poison must fail this independent real-frame checksum oracle, then restore.
    saved_cache=guest.read(0x190110,4)
    poison_rejected=False
    try:
        set32(0x190110,int.from_bytes(saved_cache,'little')^1)
        try:
            tcp_case(6,page,size)
        except AssertionError as error:
            if str(error)!='actual SG combined checksum':
                raise
            poison_rejected=True
    finally:
        guest.write(0x190110,saved_cache)
    assert poison_rejected,'actual cached-sum poison escaped checksum oracle'
    checks.append({'case':'actual-static-SG-live-checksum-carry-zero-and-cache-poison',
                   'random_cases':12,'negative_zero':True,'poison_rejected':True,'ok':True})
    # Restore a full ordinary response header as direct SG API input.
    good=tcp_case(0,page,size,ready=False)
    guest.write(0x1b0000,good[:54])
    # Direct SG needs exactly the header and immutable fullresponse inputs.
    for slot,head,status0,status1 in ((0,0,0,1),(1,1,1,0),(2,2,3,1),(3,3,1,3),(6,0,1,1)):
        following=slots(slot,head,status0,status1)
        before=guest.read(0x181080+slot*16,16)+guest.read(0x181080+following*16,16)
        tail=u32(mmio+0x3818)
        assert invoke('nic_send_static',{'rdi':0x1b0000,'rsi':54,'rdx':page,'rcx':size})['rax']==0
        assert guest.read(0x181080+slot*16,16)+guest.read(0x181080+following*16,16)==before
        assert u32(mmio+0x3818)==tail
    # Second slot can be an earlier header with an outstanding final owner.
    following=slots(2);owner=5
    guest.write(0x190188+following,bytes([owner+1]))
    guest.write(0x181080+owner*16+12,b'\x00')
    before=guest.read(0x181080+2*16,16)+guest.read(0x181080+following*16,16)
    tail=u32(mmio+0x3818)
    assert invoke('nic_send_static',{'rdi':0x1b0000,'rsi':54,'rdx':page,'rcx':size})['rax']==0,'second slot final owner must gate SG reuse'
    assert guest.read(0x181080+2*16,16)+guest.read(0x181080+following*16,16)==before and u32(mmio+0x3818)==tail
    assert guest.read(0x190188+following,1)==bytes([owner+1])
    guest.write(0x181080+owner*16+12,b'\x01')
    assert invoke('nic_send_static',{'rdi':0x1b0000,'rsi':54,'rdx':page,'rcx':size})['rax']==1
    assert guest.read(0x190188+following,1)==b'\x00','completed stale payload owner must clear'
    assert guest.read(0x190188+2,1)==bytes([following+1]),'new header final owner recorded'
    (run/'t024-static-sg-inputs.json').write_text(json.dumps({'vectors':vectors,'scope':'actual header plus immutable DMA descriptor reconstruction; quiesced device, separate wire gate required'},indent=2)+'\n')
    checks.append({'case':'static-SG-cache-wire-reconstruction-final-owner-wrap-reuse','vectors':len(vectors),'ok':True})

def test(build, output, mutant=False):
    if not __debug__:
        raise RuntimeError('SG acceptance requires Python assertions enabled')
    mutation = {'requested':bool(mutant), 'applied':False, 'restored':False}

    def extra(guest, invoke, checks, symbols, mmio, run, set32, u32, originals):
        address = None
        saved = None
        try:
            if mutant:
                # Isolated GDB mutation of the existing authored second-owner rejection branch.
                # No generated instructions or alternative guest implementation.
                start = symbols['nic_send_static']
                end = symbols['static_checksum']
                code = guest.read(start, end-start)
                token = bytes.fromhex('0fb6480c83e10f83f9010f85')
                if code.count(token) != 1:
                    raise ValueError('Expected unique second-owner rejection branch')
                address = start+code.index(token)+11
                saved = guest.read(address,1)
                if saved != b'\x85':
                    raise ValueError('Unexpected original second-owner condition byte')
                originals.append((address,saved))
                guest.write(address,b'\x84')
                mutation.update({'applied':True,'address':address,
                                 'original_hex':saved.hex(),'mutant_hex':'84'})
            _checks(guest, invoke, checks, symbols, mmio, run, set32, u32)
        finally:
            if address is not None and saved is not None:
                guest.write(address,saved)
                mutation['restored'] = guest.read(address,1) == saved
                if not mutation['restored']:
                    raise RuntimeError('SG owner mutant opcode restoration failed')
            (run/'raw-sg-mutation.json').write_text(json.dumps(mutation,indent=2)+'\n')

    result = driver_test(build,output,extra=extra)
    result['sg_scope'] = 'Actual descriptor-segment reconstruction, immutable data, cached checksums and final ownership; DMA quiesced. Final wire delivery remains a separate gate.'
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
    (run/'raw-sg-verdict.json').write_text(json.dumps(result,indent=2)+'\n')
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
