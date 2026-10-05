"""Build and externally verify the actual oslab disk image, never a fixture."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid
from .core import ROOT, command, digest, doctor, get_run, load, save, tool
from .integrity import audit
from .worker import start


def project_build(project, machine_code=False, machine_http=False):
    if type(machine_code) is not bool or type(machine_http) is not bool:
        raise ValueError('Machine-code build options must be booleans')
    project = Path(project).resolve()
    if re.search(r'[^A-Za-z0-9_./-]', str(project)):
        raise ValueError('Project Makefile currently requires a path without whitespace or shell metacharacters')
    policy = audit(project, os_only=True)
    if not policy['ok']:
        raise ValueError(json.dumps(policy))
    versions = doctor()
    sources = {str(p.relative_to(project)): digest(p) for p in sorted(project.rglob('*'))
               if p.is_file() and '.git' not in p.parts and (p.suffix in ['.c', '.h', '.asm', '.inc', '.ld', '.S', '.s'] or p.name == 'Makefile')}
    if not sources or 'Makefile' not in sources:
        raise ValueError('No project build definitions')
    configuration = {'debug': True, 'machine_code': machine_code, 'machine_http': machine_http}
    inputs = {'schema': 1, 'fixture': False, 'source_hashes': sources, 'tools': versions,
              'configuration': configuration}
    identity = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()[:16]
    output = ROOT / 'build' / ('os-' + identity)
    output.mkdir(parents=True, exist_ok=True)
    args = ['make', '-C', project, f'OUT={output}', 'DEBUG=1', f'CC={tool("clang")}', f'LD={tool("ld.lld")}',
            f'OBJCOPY={tool("llvm-objcopy")}', f'NASM={tool("nasm")}', f'PYTHON={os.sys.executable}',
            f'MACHINE={int(machine_code)}', f'MACHINE_HTTP={int(machine_http)}',
            f'MACHINE_HEADERS={int(machine_http)}']
    targets = ['all', 'host-test'] + (['machine-host-test'] if machine_code or machine_http else [])
    built = subprocess.run([str(x) for x in args+targets], capture_output=True, text=True, timeout=120)
    (output/'build.log').write_text(built.stdout+'\n'+built.stderr)
    if built.returncode:
        raise RuntimeError(f'OS build or host tests failed; see {output}/build.log')
    packet_source=(project/'kernel/packets.c').read_text()
    defect='checksum(p, h) ||'
    if packet_source.count(defect)!=1:
        raise RuntimeError('Update the explicit checksum mutation test for the parser implementation')
    with tempfile.TemporaryDirectory(dir=output) as mutant:
        mutant=Path(mutant)
        (mutant/'packets.c').write_text(packet_source.replace(defect,''))
        compiled=subprocess.run([tool('clang'),'-std=c11','-O1','-g','-fsanitize=address,undefined',
                                  '-I'+str(project/'include'),str(mutant/'packets.c'),str(project/'tests/packets.c'),
                                  '-o',str(mutant/'mutant')],capture_output=True,text=True,timeout=30)
        if compiled.returncode:
            raise RuntimeError('Deliberate-defect test did not compile')
        rejected=subprocess.run([str(mutant/'mutant')],capture_output=True,text=True,timeout=30)
        (output/'mutation-test.log').write_text(rejected.stdout+'\n'+rejected.stderr)
        if rejected.returncode==0:
            raise RuntimeError('Host tests accepted a deliberately disabled IPv4 checksum validation')
    files = ['oslab.img', 'kernel.elf', 'stage1.elf', 'stage2.elf', 'kernel.bin', 'stage1.bin', 'stage2.bin', 'kernel.payload']
    manifest = {**inputs, 'build_id': identity, 'files': {f: digest(output/f) for f in files},
                'symbols': {'kernel': {'file': 'kernel.elf', 'address': 0x100000, 'mode': 'long64'},
                            'stage1': {'file': 'stage1.elf', 'address': 0x7c00, 'mode': 'real16'},
                            'stage2': {'file': 'stage2.elf', 'address': 0x8000, 'mode': 'real16'}},
                'configuration': configuration,
                'disk': {'interface': 'ide', 'stage2_lba': 1, 'kernel_lba': 1+(output/'stage2.bin').stat().st_size//512}}
    save(output/'manifest.json', manifest)
    return {'ok': True, 'build_id': identity, 'directory': str(output), **manifest}


def observe(identity, marker, seconds=15):
    run = get_run(identity)
    deadline = time.monotonic()+seconds
    while time.monotonic()<deadline:
        raw = (run/'serial.log').read_bytes()
        if marker in raw:
            return raw
        status = load(run/'status.json')
        if status['state'] in ['finished', 'error']:
            raise RuntimeError(f'VM ended before {marker!r}: {status}; run={identity}')
        time.sleep(0.02)
    raise TimeoutError(f'Missing {marker!r}; run={identity}')


def image_gate(directory, internet_host=None):
    from .__main__ import call, wait
    directory = Path(directory)
    manifest = load(directory/'manifest.json')
    for f, expected in manifest['files'].items():
        if digest(directory/f) != expected:
            raise ValueError('Saved build hash mismatch: '+f)
    checks = []
    live = []
    def launch(network='none', timeout=30, image=None):
        started = time.monotonic()
        result = start(manual=True, image=image or directory/'oslab.img', symbols=directory/'kernel.elf',
                       mode='long64', memory=64, network=network, timeout=timeout)
        identity = result['run_id']
        live.append(identity)
        save(get_run(identity)/'project-build.json', manifest)
        return identity, started
    original = (directory/'oslab.img').read_bytes()
    boot_times = []
    try:
        for repeat in range(3):
            identity, started = launch()
            raw = observe(identity, b'OSL1 READY\n')
            boot_times.append(time.monotonic()-started)
            call(identity, {'operation': 'serial', 'text': 'selftest\nstats\nexit\n'})
            raw = observe(identity, b'OSL1 DONE\n', 20)
            state = wait(identity, 10)
            ok = all(x in raw for x in [b'OSL1 BOOT stage1\n', b'OSL1 BOOT stage2\n', b'OSL1 BOOT kernel long64\n', b'OSL1 BUILD debug=1\n', b'command=selftest ok=1', b'network=absent-or-failed'])
            ok = ok and state.get('exit_code')==33 and not state.get('captures') and b'PANIC' not in raw
            checks.append({'case': 'disk-boot-memory-exhaustion-'+str(repeat), 'ok': ok, 'run_id': identity})
        for label, cmd, expected in [('fault', 'fault\n', 'panic'), ('pagefault', 'pagefault\n', 'panic'), ('hang', 'hang\n', 'timeout')]:
            identity, _ = launch(timeout=3 if label=='hang' else 12)
            observe(identity, b'OSL1 READY\n')
            call(identity, {'operation': 'serial', 'text': cmd})
            state = wait(identity, 20)
            capture = get_run(identity)/'capture-001'
            snap = load(capture/'capture.json')
            raw = (get_run(identity)/'serial.log').read_bytes()
            ok = state.get('verdict')==expected and snap['complete'] and (capture/'memory.bin').stat().st_size==64*1024*1024
            if label=='fault':
                match = re.search(rb'OSL1 PANIC vector=6 error=0 rip=0x([0-9a-f]+)',raw)
                ok = ok and bool(match) and 'register-values=' in (capture/'gdb.mi').read_text()
                if match:
                    with (capture/'memory.bin').open('rb') as memory:
                        memory.seek(int(match[1],16))
                        ok = ok and memory.read(2)==b'\x0f\x0b'
            if label=='pagefault':
                ok = ok and bool(re.search(rb'OSL1 PANIC vector=14 error=2 rip=0x[0-9a-f]+ rsp=0x[0-9a-f]+ cr2=0x100000000\n',raw))
            checks.append({'case': label+'-capture', 'ok': ok, 'run_id': identity})
            recovered = call_recover(identity)
            live.append(recovered)
            observe(recovered,b'OSL1 READY\n')
            call(recovered, {'operation': 'serial', 'text': 'selftest\nexit\n'})
            raw = observe(recovered,b'OSL1 DONE\n',20)
            restored = wait(recovered,10)
            checks.append({'case': label+'-recovery', 'ok': restored.get('exit_code')==33 and b'command=selftest ok=1' in raw, 'run_id': recovered})
        original = (directory/'oslab.img').read_bytes()
        ROOT.joinpath('build').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            for label, offset in [('stage2-corrupt', 600), ('kernel-corrupt', manifest['disk']['kernel_lba']*512+16), ('truncated', None)]:
                bad = bytearray(original)
                if offset is None:
                    bad = bad[:manifest['disk']['kernel_lba']*512]
                else:
                    bad[offset] ^= 1
                path = Path(tmp)/(label+'.img');path.write_bytes(bad)
                identity, _ = launch(image=path)
                state = wait(identity,15)
                raw = (get_run(identity)/'serial.log').read_bytes()
                checks.append({'case': label, 'ok': state.get('exit_code')==35 and b'OSL1 BOOT_ERROR' in raw and b'OSL1 READY' not in raw, 'run_id': identity})
        identity, _ = launch(network='isolated',timeout=30)
        observe(identity,b'OSL1 READY\n')
        call(identity, {'operation': 'serial', 'text': 'dhcp\nstats\nexit\n'})
        raw=observe(identity,b'OSL1 DONE\n',20);state=wait(identity,10)
        checks.append({'case': 'isolated-DHCP', 'ok': state.get('exit_code')==33 and b'command=dhcp ok=1' in raw and b'OSL1 DHCP address=' in raw, 'run_id': identity})
        identity, _ = launch(network='isolated',timeout=30)
        observe(identity,b'OSL1 READY\n')
        call(identity, {'operation':'network-link','up':False})
        call(identity, {'operation':'serial','text':'dhcp\nstats\nexit\n'})
        raw=observe(identity,b'OSL1 DONE\n',10);state=wait(identity,10)
        checks.append({'case':'link-down-rejected','ok':state.get('exit_code')==35 and b'command=dhcp ok=0' in raw,'run_id':identity})
        identity, _ = launch(network='isolated',timeout=30)
        observe(identity,b'OSL1 READY\n')
        call(identity, {'operation':'serial','text':'dhcp\nresolve example.com\nexit\n'})
        raw=observe(identity,b'OSL1 DONE\n',15);state=wait(identity,10)
        checks.append({'case':'missing-DNS-rejected','ok':state.get('exit_code')==35 and b'command=resolve ok=0' in raw,'run_id':identity})
        identity, _ = launch(network='isolated',timeout=45)
        observe(identity,b'OSL1 READY\n')
        snapshot=call(identity, {'operation':'debug','action':'registers'})
        location=call(identity, {'operation':'debug','action':'evaluate','value':'(unsigned long)&rx[rx_head]'})
        address=int(location['values'][0],0)
        # Explicit corruption injection into a paused DMA descriptor; not a mocked driver.
        call(identity, {'operation':'debug','action':'write-memory','address':hex(address+8),'value':'0e0000000301'})
        call(identity, {'operation':'debug','action':'resume'})
        call(identity, {'operation':'serial','text':'stats\nexit\n'})
        raw=observe(identity,b'OSL1 DONE\n',10);state=wait(identity,10)
        checks.append({'case':'live-GDB-injected-RX-error','ok':state.get('exit_code')==33
                       and b'rx_errors=1' in raw and bool(snapshot['registers']), 'run_id':identity})
        if internet_host:
            if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',internet_host):
                raise ValueError('Invalid Internet acceptance hostname')
            identity, _ = launch(network='internet',timeout=90)
            observe(identity,b'OSL1 READY\n')
            call(identity, {'operation': 'serial', 'text': 'selftest\ndhcp\n'+('http '+internet_host+' /\n')*5+'stats\nexit\n'})
            raw = observe(identity,b'OSL1 DONE\n',60);state=wait(identity,10)
            evidence = wire_evidence(get_run(identity)/'network.pcap')
            elapsed=[int(v) for v in re.findall(rb'OSL1 HTTP [^\n]+ elapsed_ms=(\d+)',raw)]
            evidence['HTTP_elapsed_ms']=elapsed
            matches=re.findall(rb'OSL1 HTTP host=[^ \n]+ status=([0-9]{3}) bytes=(\d+) fnv1a=(\d+)',raw)
            recorded={(int(size),int(value)) for _,size,value in matches}
            observed={(r['bytes'],r['fnv1a']) for r in evidence['responses'] if r['http_header'] and r['global_peer']}
            ok = len(matches)==5 and len(evidence['responses'])==5 and recorded==observed and state.get('exit_code')==33 and b'command=http ok=1' in raw and b'OSL1 DNS host=' in raw and b'OSL1 HTTP host=' in raw and evidence['http_response_bytes']>0 and evidence['dns_responses']>0
            save(get_run(identity)/'wire-verdict.json',evidence)
            checks.append({'case': 'live-Internet-DNS-TCP-HTTP', 'ok': ok, 'run_id': identity, 'wire': evidence})
    except Exception as error:
        checks.append({'case':'execution','ok':False,'error':str(error)})
    finally:
        for identity in live:
            try:
                if load(get_run(identity)/'status.json')['state'] not in ['finished','error']:
                    call(identity, {'operation': 'stop'})
            except (RuntimeError, OSError) as error:
                checks.append({'case':'cleanup','ok':False,'run_id':identity,'error':str(error)})
    return {'ok': all(c['ok'] for c in checks), 'checks': checks, 'image_sha256': manifest['files']['oslab.img'],
            'build_id': manifest['build_id'], 'boot_launch_to_ready_seconds': boot_times,
            'image_bytes': len(original), 'kernel_bytes': (directory/'kernel.bin').stat().st_size,
            'network': 'live opt-in' if internet_host else 'isolated deterministic'}


def call_recover(identity):
    import argparse
    from .__main__ import dispatch
    return dispatch(argparse.Namespace(operation='recover',run_id=identity))['run_id']


def wire_evidence(path):
    import struct
    import ipaddress
    raw=Path(path).read_bytes()
    if raw[:4]==b'\xd4\xc3\xb2\xa1':
        endian='<'
    elif raw[:4]==b'\xa1\xb2\xc3\xd4':
        endian='>'
    else:
        raise ValueError('Unsupported pcap encoding')
    if len(raw)<24 or struct.unpack(endian+'I',raw[20:24])[0]!=1:
        raise ValueError('Expected Ethernet pcap')
    pos=24;http_bytes=0;dns=0;packets=0;streams={}
    while pos<len(raw):
        if len(raw)-pos<16:raise ValueError('Truncated pcap record')
        _,_,cap,size=struct.unpack(endian+'IIII',raw[pos:pos+16]);pos+=16
        if cap>size or cap>65536 or cap>len(raw)-pos:raise ValueError('Invalid pcap length')
        frame=raw[pos:pos+cap];pos+=cap;packets+=1
        if len(frame)<34 or frame[12:14]!=b'\x08\x00':continue
        ip=frame[14:];h=(ip[0]&15)*4;total=int.from_bytes(ip[2:4],'big')
        if h<20 or total>len(ip) or total<h:continue
        payload=ip[h:total]
        if ip[9]==17 and len(payload)>=20 and payload[:2]==b'\x00\x35' and payload[10]&0x80:dns+=1
        if ip[9]==6 and len(payload)>=20 and payload[:2]==b'\x00\x50':
            header=(payload[12]>>4)*4
            if header>=20 and header<=len(payload):
                content=payload[header:]
                if content:
                    key=(str(ipaddress.IPv4Address(ip[12:16])),str(ipaddress.IPv4Address(ip[16:20])),int.from_bytes(payload[2:4],'big'))
                    seq=int.from_bytes(payload[4:8],'big')
                    stream=streams.setdefault(key,{})
                    for index,byte in enumerate(content):
                        position=(seq+index)&0xffffffff
                        if position in stream and stream[position]!=byte:
                            raise ValueError('Conflicting TCP retransmission bytes')
                        stream[position]=byte
                    http_bytes+=len(content)
    responses=[]
    for key,stream in streams.items():
        if not stream:continue
        # Order across sequence wrap by locating the first byte after the largest gap.
        positions=sorted(stream)
        first=max(enumerate(positions),key=lambda item:(item[1]-positions[item[0]-1])&0xffffffff)[1]
        ordered=sorted(positions,key=lambda x:(x-first)&0xffffffff)
        if any(((position-first)&0xffffffff)!=index for index,position in enumerate(ordered)):
            raise ValueError('Incomplete captured HTTP TCP stream')
        content=bytes(stream[x] for x in ordered)
        value=2166136261
        for byte in content:value=((value^byte)*16777619)&0xffffffff
        responses.append({'remote_ip':key[0],'local_port':key[2],'bytes':len(content),'fnv1a':value,
                          'http_header':content.startswith((b'HTTP/1.0 ',b'HTTP/1.1 ')), 'global_peer':ipaddress.IPv4Address(key[0]).is_global})
    return {'packets':packets,'dns_responses':dns,'http_response_bytes':http_bytes,
            'responses':responses,'pcap_sha256':digest(path)}


def project_test(project, internet_host=None, machine_code=False, machine_http=False):
    built = project_build(project, machine_code, machine_http)
    result = image_gate(built['directory'], internet_host)
    ROOT.joinpath('artifacts').mkdir(exist_ok=True)
    save(ROOT/'artifacts/os-latest-test.json',result)
    return result


def project_deploy(project, config_path, internet_host=None, machine_code=False, machine_http=False):
    built=project_build(project, machine_code, machine_http)
    config=load(config_path)
    host=config['ssh_host']
    if not re.fullmatch(r'[A-Za-z0-9_.@-]+',host) or host.startswith('-'):
        raise ValueError('Invalid SSH host alias')
    if internet_host and not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',internet_host):
        raise ValueError('Invalid acceptance host')
    identity=str(uuid.uuid4());run=ROOT/'runs'/identity;run.mkdir(parents=True,mode=0o700)
    save(run/'manifest.json',{'kind':'OS-deployment','schema':1,'build':built,'private_config':config,'internet_host':internet_host})
    save(run/'status.json',{'state':'running','ok':True,'run_id':identity})
    with (run/'owner.log').open('ab') as output:
        process=subprocess.Popen([os.sys.executable,'-m','osenv','_project_deploy_worker',identity],cwd=ROOT,
                                 stdin=subprocess.DEVNULL,stdout=output,stderr=output,start_new_session=True)
    save(run/'launch.json',{'owner_pid':process.pid})
    return {'ok':True,'run_id':identity,'build_id':built['build_id'],'state':'running'}


def project_deploy_worker(identity):
    import shlex
    run=get_run(identity);manifest=load(run/'manifest.json');built=manifest['build'];host=manifest['private_config']['ssh_host']
    remote='/var/lib/vz/osenv-harness/os-'+built['build_id']+'/'+identity
    ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',host]
    try:
        archive=run/'source.tar.gz'
        with tarfile.open(archive,'w:gz') as stream:
            for p in sorted(Path(__file__).parent.glob('*.py')):stream.add(p,arcname='osenv/'+p.name)
            directory=Path(built['directory'])
            for f in [*built['files'],'manifest.json']:stream.add(directory/f,arcname='image/'+f)
        command(ssh+['mkdir -p '+shlex.quote(remote)+' && chmod 700 '+shlex.quote(remote)],timeout=15)
        with archive.open('rb') as source:
            sent=subprocess.run(ssh+['tar -xzf - -C '+shlex.quote(remote)],stdin=source,capture_output=True,timeout=30)
        if sent.returncode:raise RuntimeError('SSH image upload failed: '+sent.stderr.decode(errors='replace')[-1000:])
        script='from osenv.project import image_gate; import json; from pathlib import Path; r=image_gate("image",'+repr(manifest['internet_host'])+'); Path("verdict.json").write_text(json.dumps(r)); print(json.dumps(r)); raise SystemExit(0 if r["ok"] else 1)'
        executed=subprocess.run(ssh+['cd '+shlex.quote(remote)+' && python3 -c '+shlex.quote(script)],capture_output=True,text=True,timeout=240)
        (run/'remote.stdout').write_text(executed.stdout);(run/'remote.stderr').write_text(executed.stderr)
        # Fetch raw evidence even when a guest check fails. Private deployment files remain ignored.
        evidence=run/'remote-evidence.tar.gz'
        with evidence.open('wb') as output:
            fetched=subprocess.run(ssh+['tar -czf - -C '+shlex.quote(remote)+' runs verdict.json'],stdout=output,stderr=subprocess.PIPE,timeout=60)
        if fetched.returncode:raise RuntimeError('Remote evidence retrieval failed; local stdout/stderr preserved')
        target=run/'remote';target.mkdir()
        with tarfile.open(evidence) as stream:stream.extractall(target,filter='data')
        result=load(target/'verdict.json')
        if executed.returncode or not result['ok']:raise RuntimeError('Remote OS gate failed; see retained verdict and runs')
        if result['image_sha256']!=built['files']['oslab.img']:raise RuntimeError('Remote image hash mismatch')
        save(run/'result.json',result)
        save(run/'status.json',{'state':'finished','ok':True,'verdict':'OS-homelab-verified','image_sha256':result['image_sha256'],
                               'build_id':built['build_id'],'checks':len(result['checks']),'internet_verified':bool(manifest['internet_host'])})
    except Exception as error:
        save(run/'status.json',{'state':'error','ok':False,'error':str(error),'evidence_preserved':True})
