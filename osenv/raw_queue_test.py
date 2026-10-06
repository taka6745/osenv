"""Actual guest one-slot deferred-SYN, packet framing and bounds oracle.

The ordinary network gate remains unchanged; its extra callback invokes these
checks on the same real guest and retains every existing assertion.
"""
import argparse
import json
import struct
from functools import partial
from pathlib import Path
from .raw_network_test import test as network_test
from .raw_primitives_test import checksum


def assert_http_response(wire, expected_status):
    header, separator, body = wire.partition(b'\r\n\r\n')
    assert separator, 'HTTP header boundary absent'
    lines = header.split(b'\r\n')
    status = lines[0].split(b' ', 2)
    assert len(status) == 3 and status[0] == b'HTTP/1.0', 'HTTP status line version/fields'
    assert len(status[1]) == 3 and status[1].isdigit(), 'HTTP numeric status malformed'
    assert int(status[1]) == expected_status, 'HTTP status mismatch'
    assert all(32 <= byte <= 126 for byte in status[2]), 'HTTP reason phrase malformed'
    lengths = []
    for line in lines[1:]:
        name, colon, value = line.partition(b':')
        assert colon and name, 'HTTP response header malformed'
        if name.lower() == b'content-length':
            value = value.strip(b' \t')
            assert value and value.isdigit(), 'HTTP Content-Length malformed'
            lengths.append(int(value))
    assert len(lengths) == 1, 'HTTP Content-Length absent/duplicate'
    assert lengths[0] == len(body), 'HTTP Content-Length/body mismatch'
    return body


def queue_checks(vm, s, saved, sent, record, ack, mac, out, run, queue_mutant=False):
    # Actual two-peer interleaving; quiesced DMA permits independent packet reconstruction.
    hpet_config=vm.read(0xfed00010,8);hpet_counter=vm.read(0xfed000f0,8)
    mmio=int.from_bytes(vm.read(0x180108,8),'little')
    controls={o:vm.read(mmio+o,4) for o in (0x100,0x400)}
    scratch_before=vm.read(0x180000,0xb000);net_before=vm.read(0x190000,0x3000)
    changed_guest=None
    try:
        vm.write(0xfed00010,(int.from_bytes(hpet_config,'little')&~1).to_bytes(8,'little'))
        vm.write(0xfed000f0,struct.pack('<Q',100000000))
        for o,d in controls.items():vm.write(mmio+o,(int.from_bytes(d,'little')&~2).to_bytes(4,'little'))
        def reset_old(closing=1,fin_acked=True):
            st=bytearray(0x178);st[:8]=struct.pack('<Q',1000);st[8]=1
            st[16:20]=bytes([10,0,2,15]);st[40:48]=struct.pack('<Q',100000)
            st[64]=1;st[65]=1;st[66]=closing
            st[68:72]=bytes([10,0,2,2]);st[72:74]=struct.pack('>H',39999)
            st[74:76]=struct.pack('<H',17);st[76:78]=struct.pack('<H',77)
            st[80:84]=struct.pack('<I',256);st[84:88]=struct.pack('<I',513 if fin_acked else 512)
            st[88:92]=struct.pack('<I',513);st[128:136]=struct.pack('<Q',100000)
            st[136:144]=struct.pack('<Q',50000);st[144:150]=bytes.fromhex('020000000003')
            vm.write(0x190000,st);vm.write(0x190117,b'\xa5');vm.write(0x190178,b'\x5a'*8)
            vm.write(0x181000,bytes(128));vm.write(0x180110,bytes(4));vm.write(0x180118,bytes(4));vm.write(0x180114,bytes(4))
            for slot in range(8):
                vm.write(0x181080+16*slot,struct.pack('<QHBBBBH',0x186000+2048*slot,0,0,0,1,0,0))
                vm.write(0x186000+2048*slot,b'\xcc'*2048)
            return st
        def packet(port=40000,seq=0xfffffff0,ackno=0,flags=2,options=bytes.fromhex('02040080'),payload=b'',source=bytes([10,0,2,2]),srcmac=bytes.fromhex('020000000002'),bad_checksum=False):
            assert len(options)%4==0 and len(options)<=40
            tcp=bytearray(20+len(options));tcp[:4]=struct.pack('>HH',port,80)
            tcp[4:12]=struct.pack('>II',seq&0xffffffff,ackno&0xffffffff)
            tcp[12]=((len(tcp)//4)<<4);tcp[13]=flags;tcp[14:16]=struct.pack('>H',1536)
            tcp[20:]=options;tcp+=payload
            dest=bytes([10,0,2,15]);pseudo=source+dest+bytes([0,6])+struct.pack('>H',len(tcp))
            tcp[16:18]=struct.pack('>H',checksum(pseudo+tcp))
            if bad_checksum:tcp[16]^=1
            ip=bytearray(20);ip[0]=0x45;ip[2:4]=struct.pack('>H',20+len(tcp));ip[8]=64;ip[9]=6
            ip[12:16]=source;ip[16:20]=dest;ip[10:12]=struct.pack('>H',checksum(ip))
            return mac+srcmac+b'\x08\x00'+ip+tcp
        def keep(name,data=b''):
            vm.write(0x1b0000,data);vm.write(0x1cfff8,struct.pack('<Q',s['raw_loop']))
            vm.set({**sent,'rdi':0x1b0000,'rsi':len(data),'rsp':0x1cfff8,'rip':s[name],'eflags':saved['eflags']&~1536})
            vm.command('-exec-continue');regs=vm.registers()
            assert regs['rip']==s['raw_loop'] and regs['rsp']==0x1d0000 and all(regs[k]==v for k,v in sent.items())
            assert vm.read(0x190117,1)==b'\xa5' and vm.read(0x190178,8)==b'\x5a'*8,'queued SYN bounds'
            return vm.read(0x190000,0x178)
        def tail():return int.from_bytes(vm.read(0x180114,4),'little')
        def transmitted(slot):
            d=vm.read(0x181080+16*slot,16);n=int.from_bytes(d[8:10],'little')
            f=vm.read(int.from_bytes(d[:8],'little'),n);ip=f[14:34]
            assert f[12:14]==b'\x08\x00' and ip[0]==0x45 and ip[9]==6
            assert checksum(ip)==0
            total=int.from_bytes(ip[2:4],'big');tcp=f[34:14+total]
            assert checksum(ip[12:20]+bytes([0,6])+struct.pack('>H',len(tcp))+tcp)==0
            h=(tcp[12]>>4)*4;assert 20<=h<=60 and h<=len(tcp)
            assert d[10:]==bytes.fromhex('000b00000000')
            vm.write(0x181080+16*slot+12,b'\x01') # External device-completion input for next finite segment.
            return f,tcp,tcp[h:]
        def old_fin():return packet(port=39999,seq=256,ackno=513,flags=17,options=b'')
        def stage(q):
            st=reset_old();before=bytes(vm.read(0x190040,96));descriptor=vm.read(0x181080,128)
            result=keep('net_frame',q)
            assert result[64:160]==before,'queue changed active connection'
            assert tail()==0 and vm.read(0x181080,128)==descriptor,'queue sent early packet'
            return result
        if queue_mutant:
            code=vm.read(s['net_tcp_queue_syn'],s['net_server_poll']-s['net_tcp_queue_syn'])
            off=code.index(bytes.fromhex('c6831801000001'));address=s['net_tcp_queue_syn']+off
            changed_guest=(address,vm.read(address,7));vm.write(address,b'\x90'*7)
        q=packet();st=stage(q)
        assert st[0x118]==1,'queued SYN staging mutant rejected'
        assert int.from_bytes(st[0x11c:0x120],'little')==24
        assert st[0x120:0x128]==q[26:34] and st[0x128:0x12e]==q[6:12] and st[0x130:0x148]==q[34:]
        record('different-peer-SYN-before-old-FIN-staged-actual-bytes',True)
        before=bytes(st[0x118:]);keep('net_frame',packet(port=40001,seq=123))
        record('one-queued-SYN-slot-never-overwritten',vm.read(0x190118,0x60)==before)
        st=keep('net_frame',old_fin());assert st[64]==0 and st[0x118]==1
        f,t,p=transmitted(0);assert int.from_bytes(t[2:4],'big')==39999 and t[13]==16
        slot=tail();st=keep('net_poll');assert st[64]==1 and st[0x118]==0
        f,t,p=transmitted(slot);server_isn=int.from_bytes(t[4:8],'big')
        assert f[:6]==q[6:12] and f[26:34]==bytes([10,0,2,15,10,0,2,2])
        assert t[:4]==struct.pack('>HH',80,40000) and t[13]==18 and not p and int.from_bytes(t[8:12],'big')==0xfffffff1
        record('old-close-then-queued-SYN-replay-emits-real-SYNACK',True)
        request=b'GET / HTTP/1.1\r\nHost: local\r\n\r\n';client_seq=0xfffffff1
        keep('net_frame',packet(seq=client_seq,ackno=server_isn+1,flags=25,options=b'',payload=request))
        client_seq=(client_seq+len(request)+1)&0xffffffff;wire=bytearray();seq=(server_isn+1)&0xffffffff
        for _ in range(32):
            slot=tail();keep('net_poll');assert tail()!=(slot),'queued GET stalled'
            f,t,p=transmitted(slot);assert t[:4]==struct.pack('>HH',80,40000)
            assert int.from_bytes(t[4:8],'big')==seq and int.from_bytes(t[8:12],'big')==client_seq
            wire+=p;seq=(seq+len(p)+bool(t[13]&1))&0xffffffff
            keep('net_frame',packet(seq=client_seq,ackno=seq,flags=16,options=b''))
            if t[13]&1:break
        else:raise AssertionError('queued GET response did not FIN')
        host_kernel=(out/'kernel.bin').read_bytes();pos=s['http_response_3']-0x100000
        assert bytes(wire)==host_kernel[pos:pos+1460]
        assert_http_response(bytes(wire),200)
        assert wire.endswith(b'</html>')
        record('queued-handshake-full-GET-reconstructed-with-sequences-and-checksums',True)
        # Same peer retransmission and non-eligible connection phases remain unchanged.
        for closing,acked in [(0,True),(1,False)]:
            reset_old(closing,acked);st=keep('net_frame',packet())
            record('queued-SYN-requires-closing-and-own-FIN-ACK-'+str((closing,acked)),st[0x118]==0)
        reset_old();st=keep('net_frame',packet(port=39999))
        record('same-peer-SYN-existing-path-no-queue',st[0x118]==0)
        invalid=[('bad-checksum',packet(bad_checksum=True)),('payload',packet(payload=b'X')),('ACK-SYN',packet(flags=18)),('FIN-SYN',packet(flags=3)),('RST-SYN',packet(flags=6)),('multicast-IP',packet(source=bytes([224,0,0,1]))),('zero-IP',packet(source=bytes(4))),('multicast-MAC',packet(srcmac=bytes.fromhex('030000000002'))),('truncated',packet()[:-1])]
        for header_byte in (0x40,0xf0):
            q=bytearray(packet());tcp=bytearray(q[34:]);tcp[12]=header_byte;tcp[16:18]=bytes(2)
            tcp[16:18]=struct.pack('>H',checksum(q[26:34]+bytes([0,6])+struct.pack('>H',len(tcp))+tcp));q[34:]=tcp
            invalid.append(('header-bounds-'+hex(header_byte),bytes(q)))
        for label,q in invalid:
            st=stage(q);record('queued-SYN-reject-'+label,st[0x118]==0)
        for options in [bytes.fromhex('02030000'),bytes.fromhex('02040000'),bytes.fromhex('0204008002040080'),bytes.fromhex('02010000'),bytes.fromhex('02ff0000')]:
            st=stage(packet(options=options));assert st[0x118]==1
            keep('net_frame',old_fin());transmitted(0);slot=tail();st=keep('net_poll')
            record('queued-SYN-invalid-options-never-SYNACK-'+options.hex(),st[64]==0 and st[0x118]==0 and tail()==slot)
        q=packet(options=bytes([1])*40);st=stage(q)
        assert st[0x118]==1 and int.from_bytes(st[0x11c:0x120],'little')==60 and st[0x130:0x16c]==q[34:]
        record('queued-SYN-sixty-byte-header-bounded',True)
        stage(packet());vm.write(0xfed000f0,struct.pack('<Q',1100000000));st=keep('net_poll')
        record('queued-SYN-ten-second-expiry',st[0x118]==0 and st[64]==1)
        vm.write(0xfed000f0,struct.pack('<Q',100000000));stage(packet());vm.write(0x190028,struct.pack('<Q',1000));st=keep('net_poll')
        record('queued-SYN-lease-expiry-clears-slot',st[0x118]==0 and st[8]==0 and st[64]==0)
        reset_old();vm.write(0x190118,b'\x01');vm.write(0x190009,b'\x01');vm.write(0x190018,bytes([10,0,2,2]));vm.write(0x19000c,struct.pack('<I',int.from_bytes(ack[4:8],'big')))
        nak=bytes(ack).replace(bytes.fromhex('350105'),bytes.fromhex('350106'),1)
        st=keep('net_dhcp_receive',nak)
        record('queued-SYN-matching-NAK-clears-slot',st[0x118]==0)
    finally:
        if changed_guest:vm.write(*changed_guest)
        vm.write(0x180000,scratch_before);vm.write(0x190000,net_before)
        for o,d in controls.items():vm.write(mmio+o,d)
        vm.write(0xfed000f0,hpet_counter);vm.write(0xfed00010,hpet_config)


def test(build, output, queue_mutant=False):
    manifest = json.loads((Path(build)/'manifest.json').read_text())
    if 'net_tcp_queue_syn' not in manifest['symbols']:
        raise ValueError('Unsupported image: deferred-SYN interface absent')
    try:
        result = network_test(build, output, extra=partial(queue_checks, queue_mutant=queue_mutant))
    except AssertionError:
        if not queue_mutant:
            raise
        report = Path(output)
        result = json.loads(report.read_text())
        assert result['error'] == 'queued SYN staging mutant rejected', result
        result.update(mutant_rejected=True,
                      deliberate_gdb_only_mutant='queue flag store replaced with NOPs')
        report.write_text(json.dumps(result, indent=2)+'\n')
        return result
    assert not queue_mutant, 'queued SYN mutant escaped oracle'
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--queue-mutant', action='store_true')
    args = parser.parse_args()
    result = test(args.build, args.output, args.queue_mutant)
    print(json.dumps({'ok': result['ok'], 'checks': len(result.get('checks', [])),
                      'mutant_rejected': result.get('mutant_rejected', False)}))
