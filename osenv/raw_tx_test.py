"""Actual literal TX ownership and static checksum reuse; no guest bytes generated."""
import argparse
import json
import struct
from pathlib import Path
from .raw_driver_test import test as driver_test


def test(build, output, checksum_cache=False, ownership_mutant=False):
    manifest=json.loads((Path(build)/'manifest.json').read_text())
    required=['nic_tx_buffer','nic_tx_buffer_bad']
    if checksum_cache:required+=['http_response3_length','net_tcp_checksum_cached']
    if any(name not in manifest['symbols'] for name in required):
        raise ValueError('Image does not implement requested literal TX interface')

    def exercise(guest, invoke, checks, symbols, mmio, run, set32, u32, originals):
        mutant='ownership' if ownership_mutant else False
        if mutant=='ownership':
            code=guest.read(symbols['nic_tx_buffer'],symbols['nic_tx_buffer_bad']-symbols['nic_tx_buffer'])
            branch=code.index(bytes.fromhex('f6400c0174'))+4
            address=symbols['nic_tx_buffer']+branch
            originals.append((address,guest.read(address,2)))
            guest.write(address,b'\x90\x90') # Isolated GDB-only DD rejection removal.
        # Candidate-specific real guest DMA ownership and in-place guards.
        for slot in range(8):
            buffer=0x186000+slot*2048; descriptor_address=0x181080+slot*16
            for status in (0,1,3,5,9):
                set32(0x180114,slot)
                guest.write(descriptor_address,struct.pack('<QHBBBBH',buffer,0,0,0,status,0,0))
                guest.write(buffer,b'\xcc'*2048)
                before=guest.read(descriptor_address,16); poison=guest.read(buffer,2048)
                assert invoke('nic_tx_buffer')['rax']==(buffer if status==1 else 0),'DMA ownership mismatch'
                assert guest.read(descriptor_address,16)==before and guest.read(buffer,2048)==poison
                checks.append({'function':'nic_tx_buffer','slot':slot,'status':status,'ownership_checked':True})
            for length in (0,13,14,15,59,60,61,1513,1514,1515):
                valid=14<=length<=1514; payload=bytes((i*17+3)&255 for i in range(length))
                set32(0x180114,slot);set32(mmio+0x3818,slot)
                guest.write(descriptor_address,struct.pack('<QHBBBBH',buffer,0,0,0,1,0,0))
                guest.write(buffer-1,b'\xa5'+b'\xcc'*2048+b'\x5a');guest.write(buffer,payload)
                before=guest.read(descriptor_address,16);old=guest.read(buffer,2048)
                assert invoke('nic_send',{'rdi':buffer,'rsi':length})['rax']==int(valid)
                if valid:
                    size=max(60,length)
                    assert guest.read(buffer,size)==payload+bytes(size-length)
                    assert guest.read(buffer+size,2048-size)==old[size:]
                    assert guest.read(descriptor_address+8,8)==struct.pack('<H',size)+bytes.fromhex('000b00000000')
                    assert u32(0x180114)==(slot+1)%8 and u32(mmio+0x3818)==(slot+1)%8
                else:
                    assert guest.read(descriptor_address,16)==before and guest.read(buffer,2048)==old
                    assert u32(0x180114)==slot and u32(mmio+0x3818)==slot
                assert guest.read(buffer-1,1)==b'\xa5' and guest.read(buffer+2048,1)==b'\x5a'
                checks.append({'function':'nic_send','in_place':True,'slot':slot,'length':length,'checked':True})
        # Actual builder into poisoned DMA, independently checked packet content/checksums.
        def independent_sum(data):
            if len(data)%2:data+=b'\x00'
            total=sum(int.from_bytes(data[i:i+2],'big') for i in range(0,len(data),2))
            while total>>16:total=(total&65535)+(total>>16)
            return total
        for status in (0,1,3,5,9):
            for length in (0,1,2,7,8,9,1406,1460):
                slot=7;buffer=0x186000+slot*2048;descriptor_address=0x181080+slot*16
                set32(0x180114,slot);set32(mmio+0x3818,slot)
                guest.write(descriptor_address,struct.pack('<QHBBBBH',buffer,0,0,0,status,0,0))
                guest.write(buffer-1,b'\xa5'+b'\xcc'*2048+b'\x5a')
                before=guest.read(descriptor_address,16);poison=guest.read(buffer,2048)
                guest.write(0x190010,bytes([10,0,2,15]));guest.write(0x190044,bytes([10,0,2,2]))
                guest.write(0x190048,struct.pack('>H',12345));guest.write(0x190050,struct.pack('<I',0xabcdef00))
                guest.write(0x190090,bytes.fromhex('525400123456'))
                payload=bytes((i*11+5)&255 for i in range(length));guest.write(0x1b1000,payload)
                invoke('net_tcp_send',{'rdi':0x18,'rsi':0x12345678,'rdx':0x1b1000,'rcx':length})
                if status!=1:
                    assert guest.read(descriptor_address,16)==before and guest.read(buffer,2048)==poison
                    assert u32(0x180114)==slot and u32(mmio+0x3818)==slot
                else:
                    size=max(60,54+length);frame=guest.read(buffer,size);ip=frame[14:34];tcp=frame[34:54+length]
                    assert frame[:6]==bytes.fromhex('525400123456') and frame[6:12]==guest.read(0x180100,6)
                    assert frame[12:14]==b'\x08\x00' and ip[0]==0x45 and ip[9]==6
                    assert int.from_bytes(ip[2:4],'big')==40+length and independent_sum(ip)==65535
                    assert ip[12:20]==bytes([10,0,2,15,10,0,2,2])
                    pseudo=ip[12:20]+bytes([0,6])+struct.pack('>H',len(tcp))
                    assert independent_sum(pseudo+tcp)==65535
                    assert tcp[:4]==struct.pack('>HH',80,12345) and tcp[4:12]==struct.pack('>II',0x12345678,0xabcdef00)
                    assert tcp[12:14]==b'\x50\x18' and tcp[20:]==payload
                    assert frame[54+length:]==bytes(size-(54+length))
                    assert guest.read(buffer+size,2048-size)==poison[size:]
                    assert guest.read(descriptor_address+8,8)==struct.pack('<H',size)+bytes.fromhex('000b00000000')
                    assert u32(0x180114)==0 and u32(mmio+0x3818)==0
                assert guest.read(buffer-1,1)==b'\xa5' and guest.read(buffer+2048,1)==b'\x5a'
                checks.append({'function':'net_tcp_send','slot':7,'status':status,'payload_bytes':length,'packet_and_ownership_checked':True})
        if checksum_cache:
            # T024 actual net_init/net_tcp_send cache oracle in quiesced real NIC context.
            # No executable bytes are generated; returned frames are actual guest DMA.
            from .raw_primitives_test import checksum as independent_checksum
            import random
            cache_address=0x190110
            ready_address=0x190114
            invoke('net_init')
            response_address=symbols['http_response_3']
            response_length=u32(symbols['http_response3_length'])
            response=guest.read(response_address,response_length)
            cache_expected=(~independent_checksum(response))&65535
            assert u32(cache_address)==cache_expected and guest.read(ready_address,1)==b'\x01','cache must derive from actual response'
            checks.append({'case':'actual-net-init-response-cache','bytes':response_length,'sum':cache_expected,'ok':True})
            rng=random.Random(0x2406)
            vectors=[]

            def cached_frame(source,destination,port,sequence,ack,flags,pointer,length,ready=True,poison=False):
                guest.write(0x190010,source)
                guest.write(0x190044,destination)
                guest.write(0x190048,port.to_bytes(2,'big'))
                guest.write(0x190050,struct.pack('<I',ack))
                guest.write(0x190090,bytes.fromhex('020000000002'))
                set32(cache_address,cache_expected^(1 if poison else 0))
                guest.write(ready_address,bytes([int(ready)]))
                slot=7; buffer=0x186000+slot*2048
                set32(0x180114,slot);set32(mmio+0x3818,slot)
                guest.write(0x181080+slot*16,struct.pack('<QHBBBBH',buffer,0,0,0,1,0,0))
                guest.write(buffer-1,b'\xa5'+b'\xcc'*2048+b'\x5a')
                invoke('net_tcp_send',{'rdi':flags,'rsi':sequence,'rdx':pointer,'rcx':length})
                descriptor=guest.read(0x181080+slot*16,16)
                expected_tcp_header=24 if flags&2 else 20
                expected_size=max(60,14+20+expected_tcp_header+length)
                assert int.from_bytes(descriptor[8:10],'little')==expected_size,'actual DMA wire length'
                frame=guest.read(buffer,expected_size)
                assert guest.read(buffer-1,1)==b'\xa5' and guest.read(buffer+expected_size,1)==b'\xcc','DMA guard'
                assert frame[12:14]==b'\x08\x00'
                ip=frame[14:34];tcp=frame[34:34+expected_tcp_header+length]
                assert independent_checksum(ip)==0,'actual IPv4 checksum'
                assert int.from_bytes(ip[2:4],'big')==20+len(tcp),'actual IPv4 framing'
                assert ip[12:16]==source and ip[16:20]==destination and ip[9]==6
                assert tcp[:4]==struct.pack('!HH',80,port)
                assert tcp[4:12]==struct.pack('!II',sequence,ack)
                assert tcp[12]>>4==expected_tcp_header//4 and tcp[13]==flags
                assert tcp[14:16]==b'\x03\x00','actual server receive window'
                assert tcp[expected_tcp_header:]==guest.read(pointer,length),'actual TCP data'
                pseudo=source+destination+b'\x00\x06'+len(tcp).to_bytes(2,'big')
                valid=independent_checksum(pseudo+tcp)==0
                if not poison or not ready:
                    assert valid,'actual TCP checksum mismatch'
                vector={'source_hex':source.hex(),'destination_hex':destination.hex(),'port':port,'sequence':sequence,'ack':ack,'flags':flags,'payload_bytes':length,'ready':ready,'poison':poison,'frame_hex':frame.hex(),'checksum_valid':valid}
                vectors.append(vector)
                return tcp,valid

            for index in range(12):
                source=rng.getrandbits(32).to_bytes(4,'big')
                destination=rng.getrandbits(32).to_bytes(4,'big')
                sequence=rng.getrandbits(32);ack=rng.getrandbits(32);port=rng.randrange(1,65536)
                flags=0x18|(index&1)
                cached_frame(source,destination,port,sequence,ack,flags,response_address,response_length)
            source=b'\x0a\x00\x02\x0f';destination=b'\x0a\x00\x02\x02'
            # Force raw one's-complement sumffff by choosing the live SEQ low word.
            header=struct.pack('!HHIIBBHHH',80,40000,0,0xffffffff,0x50,0x18,768,0,0)
            pseudo=source+destination+b'\x00\x06'+(20+response_length).to_bytes(2,'big')
            residual=independent_checksum(pseudo+header+response)
            tcp,valid=cached_frame(source,destination,40000,residual,0xffffffff,0x18,response_address,response_length)
            assert tcp[16:18]==b'\x00\x00','negative-zero checksum encoding'
            for ready,flags,pointer,length in ((False,0x18,response_address,response_length),
                                              (True,0x12,response_address,100),
                                              (True,0x18,response_address+7,99),
                                              (True,0x18,symbols['http_response_0'],79),
                                              (True,0x18,response_address,94),
                                              (True,0x10,response_address,0)):
                cached_frame(source,destination,40000,0xfffffff0,0xffffffff,flags,pointer,length,ready)
            _,valid=cached_frame(source,destination,40000,17,19,0x18,response_address,response_length,True,True)
            assert not valid,'deliberate cached-sum poison escaped independent checksum oracle'
            _,valid=cached_frame(source,destination,40000,17,19,0x18,response_address,response_length,False,True)
            assert valid,'uninitialized cache fallback must ignore poisoned sum'
            set32(cache_address,cache_expected);guest.write(ready_address,b'\x01')
            (run/'t024-cache-inputs-and-frames.json').write_text(json.dumps({'seed':0x2406,'vectors':vectors,'scope':'actual guest net_init/net_tcp_send and NIC DMA bytes; TX engine quiesced, not delivery/throughput'},indent=2)+'\n')
            checks.append({'case':'actual-cached-response-checksums','vectors':len(vectors),'cache-poison-rejected':True,'ok':True})

    result=driver_test(build,output,extra=exercise)
    if ownership_mutant:
        rejected=not result['ok'] and result.get('error')=='DMA ownership mismatch'
        verdict={'ok':rejected,'mutant_rejected':rejected,'actual_result':result,
                 'scope':'Isolated GDB removal of descriptor ownership branch, restored afterward'}
        Path(output).write_text(json.dumps(verdict,indent=2)+'\n')
        return verdict
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--checksum-cache',action='store_true')
    parser.add_argument('--ownership-mutant',action='store_true')
    args=parser.parse_args()
    result=test(args.build,args.output,args.checksum_cache,args.ownership_mutant)
    print(json.dumps({'ok':result['ok'],'run_id':result.get('run_id'),
                      'checks':len(result.get('checks',[])),
                      'mutant_rejected':result.get('mutant_rejected')}))
    raise SystemExit(0 if result['ok'] else 1)
