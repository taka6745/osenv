"""One owner per isolated QEMU, with independent deadlines and evidence capture."""
import json
import fcntl
import os
import re
from pathlib import Path
import selectors
import shutil
import socket
import struct
import subprocess
import time
import uuid
from .core import ROOT, MACHINE, build, command, digest, get_run, load, save, tool, validate_image
from .debug import Debugger, operations
from .protocol import verdict, panic_record_ready
from .transport import QMP

SCENARIOS = {'pass': 'P', 'fault': 'F', 'hang': 'H', 'bad-result': 'B',
             'wrong-exit': 'W', 'reset': 'R'}


class EventLog(list):
    def __init__(self, path):
        super().__init__()
        self.path = path

    def append(self, event):
        super().append(event)
        with self.path.open('a') as stream:
            stream.write(json.dumps(event) + '\n')


def validate_pvh(kernel, image, symbols):
    kernel = Path(kernel).resolve()
    provenance = kernel.parent / 'pvh-inputs.json'
    if not kernel.is_file() or not 52 <= kernel.stat().st_size <= 1024*1024:
        raise ValueError('PVH kernel must be an ELF32 file bounded to 1 MiB')
    raw = kernel.read_bytes()
    if raw[:7] != b'\x7fELF\x01\x01\x01' or struct.unpack_from('<HHI', raw, 16) != (2, 3, 1):
        raise ValueError('PVH requires a little-endian i386 executable ELF32')
    offset = struct.unpack_from('<I', raw, 28)[0]
    size, count = struct.unpack_from('<HH', raw, 42)
    if size != 32 or not 1 <= count <= 64 or offset+size*count > len(raw):
        raise ValueError('Invalid bounded PVH program header table')
    found = False
    for index in range(count):
        kind, start, _, _, length = struct.unpack_from('<IIIII', raw, offset+index*size)
        if start+length > len(raw):
            raise ValueError('Truncated PVH segment')
        if kind != 4:
            continue
        end = start+length
        while start < end:
            if start+12 > end:
                raise ValueError('Truncated PVH note')
            names, values, note_type = struct.unpack_from('<III', raw, start)
            name_at = start+12
            value_at = name_at+((names+3)&~3)
            next_at = value_at+((values+3)&~3)
            if next_at > end:
                raise ValueError('PVH note exceeds segment')
            if note_type == 18 and names == 4 and values == 4 and raw[name_at:name_at+4] == b'Xen\0':
                found = True
            start = next_at
    if not found:
        raise ValueError('Missing Xen PHYS32_ENTRY note')
    if not provenance.is_file() or provenance.stat().st_size > 1024*1024:
        raise ValueError('Missing or excessive PVH provenance')
    record = load(provenance)
    preload = record.get('preload', False)
    if type(preload) is not bool:
        raise ValueError('PVH preload metadata must be a boolean')
    expected = record.get('generated_artifacts', {})
    for name, path in [('pvh.elf', kernel), ('oslab.img', image), ('kernel.elf', symbols)]:
        if not path or expected.get(name) != digest(path):
            raise ValueError('PVH artifact hash mismatch: ' + name)
    if preload:
        payload = kernel.parent / 'kernel.bin'
        if not payload.is_file() or not 0 < payload.stat().st_size <= 524288:
            raise ValueError('PVH preload kernel.bin must be 1..524288 bytes')
        if expected.get('kernel.bin') != digest(payload):
            raise ValueError('PVH artifact hash mismatch: kernel.bin')
    return kernel, provenance


def pvh_firmware():
    prefix = Path(tool('qemu-system-x86_64')).resolve().parent.parent
    for candidate in [prefix / 'share/qemu/qboot.rom', Path('/usr/share/qemu/qboot.rom')]:
        if candidate.is_file():
            return candidate
    raise ValueError('PVH requires the installed QEMU qboot.rom firmware')


def start(scenario='pass', timeout=8, paused=False, image=None, existing_build=None,
          manual=False, symbols=None, mode='real16', memory=32, network='none', disk_interface=None, timing='virtual', nic_rom=True, nic_model='e1000', minimal_devices=False, boot_kernel=None):
    if type(minimal_devices) is not bool or (minimal_devices and not manual):
        raise ValueError('Minimal devices require a manual OS image and a boolean flag')
    if nic_model not in ['e1000', 'e1000e']:
        raise ValueError('Unsupported NIC model')
    if scenario not in SCENARIOS or not 0.2 <= timeout <= 600:
        raise ValueError('Invalid scenario or timeout (0.2..600 seconds)')
    if timing not in ['virtual', 'realtime']:
        raise ValueError('Timing must be virtual or realtime')
    external = manual and image is not None and existing_build is None
    result = existing_build or (None if external else build())
    directory = Path(result['directory']) if result else None
    image = Path(image).resolve() if image else directory / 'fixture.img'
    if mode not in ['real16', 'protected32', 'long64'] or not 16 <= memory <= 4096:
        raise ValueError('Invalid CPU mode or RAM size (16..4096 MiB)')
    if network not in ['none', 'isolated', 'internet', 'peer']:
        raise ValueError('Network must be none, isolated or internet')
    disk_interface = disk_interface or ('ide' if external else 'floppy')
    if minimal_devices and disk_interface != 'ide':
        raise ValueError('Minimal devices require the complete IDE disk boot path')
    if disk_interface not in ['ide', 'floppy']:
        raise ValueError('Disk interface must be ide or floppy')
    validate_image(image, fixture=not manual)
    preload = False
    if boot_kernel:
        if not manual or mode != 'long64' or disk_interface != 'ide':
            raise ValueError('PVH requires manual long64 mode and the retained IDE image')
        boot_kernel, provenance = validate_pvh(boot_kernel, image,
            symbols or (directory / 'boot.elf' if directory else None))
        preload = load(provenance).get('preload', False)
        if directory:
            saved = load(directory / 'manifest.json')
            if (saved.get('boot_kernel_sha256') != digest(boot_kernel) or
                    saved.get('boot_provenance_sha256') != digest(provenance)):
                raise ValueError('Saved PVH loader/provenance hash mismatch')
            if preload and saved.get('preload_kernel_sha256') != digest(boot_kernel.parent / 'kernel.bin'):
                raise ValueError('Saved PVH preload payload hash mismatch')
        pvh_firmware()
    identity = str(uuid.uuid4())
    run = ROOT / 'runs' / identity
    run.mkdir(parents=True, mode=0o700)
    if directory:
        for name in ['boot.elf', 'boot.bin']:
            if (directory / name).exists():
                shutil.copyfile(directory / name, run / name)
    else:
        (run / 'boot.bin').write_bytes(image.read_bytes()[:512])
    if symbols:
        shutil.copyfile(symbols, run / 'boot.elf')
    shutil.copyfile(image, run / 'disk.img')
    if boot_kernel:
        shutil.copyfile(boot_kernel, run / 'pvh.elf')
        shutil.copyfile(provenance, run / 'pvh-inputs.json')
        if preload:
            shutil.copyfile(boot_kernel.parent / 'kernel.bin', run / 'kernel.bin')
    # Short random /tmp sockets avoid macOS's 104-byte UNIX path limit.
    sockets = Path('/tmp') / ('ose-' + identity[:8])
    sockets.mkdir(mode=0o700)
    save(run / 'manifest.json', {'schema': 1, 'run_id': identity,
         'build': load(directory / 'manifest.json') if directory else {
             'fixture': False, 'files': {'image': digest(image)},
             'symbols': {'mode': mode, 'elf_sha256': digest(symbols) if symbols else None}},
         'image_sha256': digest(run / 'disk.img'),
         'boot_kernel_sha256': digest(run / 'pvh.elf') if boot_kernel else None,
         'boot_provenance_sha256': digest(run / 'pvh-inputs.json') if boot_kernel else None,
         'preload_kernel_sha256': digest(run / 'kernel.bin') if preload else None,
         'input': {'scenario': scenario, 'command': '1' + SCENARIOS[scenario] + '\n',
                   'seed': 7, 'expected_value': 42, 'timeout': timeout, 'paused': paused,
                   'manual': manual, 'mode': mode, 'memory_mib': memory, 'network': network,
                   'disk_interface': disk_interface, 'timing': timing, 'nic_rom': nic_rom, 'nic_model': nic_model, 'minimal_devices': minimal_devices,
                   'boot_route': 'pvh' if boot_kernel else 'bios', 'preload': preload},
         'socket_directory': str(sockets), 'source_hashes':
         {'osenv/' + p.name: digest(p) for p in sorted(Path(__file__).parent.glob('*.py'))}})
    for name in ['serial.log', 'early.log', 'qemu.log', 'trace.log', 'events.jsonl', 'annotations.jsonl', 'actions.jsonl']:
        (run / name).touch()
    output = (run / 'owner.log').open('ab')
    process = subprocess.Popen([os.sys.executable, '-m', 'osenv', '_worker', identity],
                               cwd=ROOT, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                               start_new_session=True)
    output.close()
    save(run / 'launch.json', {'owner_pid': process.pid})
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if (run / 'status.json').exists():
            status = load(run / 'status.json')
            return {'ok': status.get('state') != 'error', 'run_id': identity, **status}
        if process.poll() is not None:
            raise RuntimeError(f'Owner exited during startup: {(run / "owner.log").read_text()}')
        time.sleep(0.05)
    raise TimeoutError(f'Owner startup timeout; evidence at {run}')


class Owner:
    def __init__(self, identity):
        self.run = get_run(identity)
        self.lock = (self.run / 'owner.lock').open('a')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.manifest = load(self.run / 'manifest.json')
        self.sockets = Path(self.manifest['socket_directory'])
        self.events = EventLog(self.run / 'events.jsonl')
        self.breakpoints = None
        self.qmp = None
        self.process = None
        self.started = time.monotonic()
        self.command_sent = False
        self.finished = False
        self.ready_seconds = None
        self.reason = None
        self.capture_count = 0
        self.raw = bytearray()
        self.selector = selectors.DefaultSelector()
        self.state = 'starting'

    def status(self, **extra):
        result = {'state': self.state, 'owner_pid': os.getpid(),
                  'qemu_pid': self.process.pid if self.process else None,
                  'ready_seconds': self.ready_seconds, **extra}
        save(self.run / 'status.json', result)
        return result

    def capture(self, reason='manual', mode=None):
        mode = mode or self.manifest.get('debug_mode', self.manifest['input']['mode'])
        self.capture_count += 1
        target = self.run / f'capture-{self.capture_count:03d}'
        target.mkdir()
        errors = []
        # Existing logs are copied before attempting any connection or debugger.
        for name in ['serial.log', 'early.log', 'qemu.log', 'trace.log', 'annotations.jsonl', 'actions.jsonl']:
            shutil.copyfile(self.run / name, target / name)
        try:
            self.qmp.call('stop')
            save(target / 'qmp-status.json', self.qmp.call('query-status'))
            save(target / 'hardware.json', {
                'pci': self.qmp.call('query-pci'),
                **{name: self.qmp.call('human-monitor-command', {'command-line': 'info ' + name})
                   for name in ['pic', 'irq']}})
        except Exception as error:
            errors.append(f'QMP stop/status: {error}')
        if self.breakpoints:
            (target / 'breakpoints.mi').write_text(self.breakpoints.collect())
        try:
            if not self.breakpoints:
                self.breakpoints = Debugger(self.sockets / 'gdb', self.run / 'boot.elf')
            pc = '"($cs*16)+$rip"' if mode == 'real16' else '$pc'
            stack = {'real16': 'x/16hx $sp', 'protected32': 'x/16wx $esp', 'long64': 'x/16gx $rsp'}[mode]
            result = self.breakpoints.run(['-data-list-register-names', '-data-list-register-values x',
                                           f'-data-read-memory-bytes {pc} 128',
                                           '-data-read-memory-bytes 0x7c00 512',
                                           '-interpreter-exec console ' + json.dumps(stack)], mode)
            self.qmp.call('stop')
            save(target / 'gdb.json', result)
            (target / 'gdb.mi').write_text(result['stdout'])
            if result.get('disassembly'):
                (target / 'disassembly.txt').write_text(result['disassembly'])
            if not result['ok']:
                errors.append('GDB snapshot contains errors; see gdb.mi')
        except Exception as error:
            errors.append(f'GDB: {error}')
        try:
            self.qmp.call('pmemsave', {'val': 0, 'size': self.manifest['input']['memory_mib'] * 1024 * 1024,
                                      'filename': str(target / 'memory.bin')})
        except Exception as error:
            errors.append(f'Physical memory dump: {error}')
        if reason == 'panic' and mode == 'real16' and (target / 'gdb.json').exists() and (target / 'memory.bin').exists():
            import struct
            registers = load(target / 'gdb.json').get('registers', {})
            stack = int(registers.get('rsp', '0'), 0)
            with (target / 'memory.bin').open('rb') as stream:
                stream.seek(stack)
                frame = stream.read(6)
                if len(frame) == 6:
                    ip, cs, flags = struct.unpack('<HHH', frame)
                    stream.seek(cs*16 + ip)
                    opcode = stream.read(2).hex()
                    save(target / 'panic.json', {'version': 1, 'vector': 6, 'ip': ip,
                         'cs': cs, 'flags': flags, 'fault_opcode': opcode,
                         'expected_ud2': opcode == '0f0b', 'stack_address': stack})
        save(target / 'capture.json', {'reason': reason, 'errors': errors,
             'files': {p.name: digest(p) for p in target.iterdir() if p.is_file()},
             'complete': not errors})
        return {'ok': True, 'capture': target.name, 'complete': not errors, 'errors': errors}

    def request(self, request):
        with (self.run / 'actions.jsonl').open('a') as stream:
            stream.write(json.dumps({'elapsed': time.monotonic()-self.started, 'request': request}) + '\n')
        operation = request['operation']
        if operation == 'status':
            if self.breakpoints:
                return {'ok': True, **self.status(), 'breakpoints': self.breakpoints.collect()}
            return {'ok': True, **self.status()}
        if operation == 'capture':
            return self.capture(mode=request.get('mode'))
        if operation in ['stop', 'recover']:
            self.capture(operation)
            self.reason = 'stopped'
            self.finished = True
            return {'ok': True, 'state': 'stopping'}
        if operation == 'debug':
            action = request['action']
            mode = request.get('mode') or self.manifest.get('debug_mode', self.manifest['input']['mode'])
            self.manifest['debug_mode'] = mode
            save(self.run / 'manifest.json', self.manifest)
            if action == 'resume':
                if self.breakpoints:
                    self.breakpoints.send('-exec-continue')
                else:
                    self.qmp.call('cont')
                self.state = 'running'
                return {'ok': True, **self.status()}
            self.qmp.call('stop')
            self.state = 'paused'
            if action == 'pause':
                return {'ok': True, **self.status()}
            if action == 'add-symbols':
                source = Path(request['symbols']).resolve()
                if not source.is_file() or source.stat().st_size > 100*1024*1024:
                    raise ValueError('Missing ELF or ELF exceeds 100 MiB')
                if source.read_bytes()[:4] != b'\x7fELF':
                    raise ValueError('Symbols must be ELF')
                address = int(request['address'], 0)
                if not 0 <= address < 2**64:
                    raise ValueError('Symbol load address out of range')
                checksum = digest(source)
                directory = self.run / 'symbols'
                directory.mkdir(exist_ok=True)
                destination = directory / (checksum[:16] + '.elf')
                shutil.copyfile(source, destination)
                if not self.breakpoints:
                    self.breakpoints = Debugger(self.sockets / 'gdb', self.run / 'boot.elf')
                console = f'add-symbol-file {json.dumps(str(destination))} {address:#x}'
                result = self.breakpoints.run(['-interpreter-exec console ' + json.dumps(console)])
                if result['ok']:
                    self.manifest.setdefault('symbol_files', []).append({'elf': str(destination.relative_to(self.run)),
                            'sha256': checksum, 'text_address': address, 'mode': mode})
                    save(self.run / 'manifest.json', self.manifest)
                return result
            if action == 'breakpoint':
                if not self.breakpoints:
                    self.breakpoints = Debugger(self.sockets / 'gdb', self.run / 'boot.elf')
                address = request['address']
                try:
                    address = f'*{int(str(address), 0):#x}'
                except ValueError:
                    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_:]*', address or ''):
                        raise ValueError('Breakpoint needs an address or symbol name')
                begin = len(self.breakpoints.transcript)
                inserted = self.breakpoints.run(['-break-insert ' + json.dumps(address)])
                if not inserted['ok']:
                    (self.run / 'breakpoints.mi').write_text(inserted['stdout'])
                    raise RuntimeError(inserted['error'])
                self.breakpoints.send('-exec-continue')
                self.breakpoints.collect(1)
                transcript = self.breakpoints.transcript[begin:].decode(errors='replace')
                (self.run / 'breakpoints.mi').write_text(transcript)
                if '^error' in transcript:
                    raise RuntimeError(transcript)
                return {'ok': True, 'mi': transcript, 'breakpoint_active': True}
            commands = operations(action, request.get('address'), request.get('length', 64),
                                  request.get('value'))
            if not self.breakpoints:
                self.breakpoints = Debugger(self.sockets / 'gdb', self.run / 'boot.elf')
            result = self.breakpoints.run(commands, mode)
            self.qmp.call('stop')
            save(self.run / 'last-debug.json', result)
            self.status()
            return result
        if operation == 'serial':
            data = request['text'].encode('ascii')
            if len(data) > 4096:
                raise ValueError('Serial input too large')
            self.serial.sendall(data)
            return {'ok': True, 'bytes': len(data)}
        if operation == 'connections':
            return {'ok': True, 'network': self.manifest['input']['network'],
                    'qmp': self.qmp.call('query-status'), 'pci': self.qmp.call('query-pci'),
                    'chardev': self.qmp.call('query-chardev')}
        if operation == 'network-link':
            if self.manifest['input']['network'] == 'none':
                raise ValueError('Run has no NIC; launch with --network isolated')
            self.qmp.call('set_link', {'name': 'nic0', 'up': request['up']})
            return {'ok': True, 'up': request['up']}
        if operation == 'inspect':
            results = {}
            for name in ['pic', 'irq']:
                try:
                    results['info-' + name] = self.qmp.call('human-monitor-command',
                        {'command-line': 'info ' + name})
                except RuntimeError as error:
                    results['info-' + name] = {'unsupported': str(error)}
            for name in ['query-status', 'query-cpus-fast', 'query-pci', 'query-block',
                         'query-blockstats', 'query-chardev', 'query-memory-size-summary', 'query-iothreads']:
                try:
                    results[name] = self.qmp.call(name)
                except RuntimeError as error:
                    results[name] = {'unsupported': str(error)}
            return {'ok': True, 'machine': self.manifest['machine'], 'results': results}
        if operation == 'annotate':
            text = request['text']
            if len(text.encode()) > 4096:
                raise ValueError('Log annotation too large')
            entry = {'source': request.get('source', 'host'), 'level': request.get('level', 'info'),
                     'elapsed': time.monotonic()-self.started, 'text': text}
            with (self.run / 'annotations.jsonl').open('a') as stream:
                stream.write(json.dumps(entry) + '\n')
            return {'ok': True, 'entry': entry}
        if operation == 'network-forward':
            host_port, guest_port = request['host_port'], request.get('guest_port', 80)
            if (type(host_port) is not int or type(guest_port) is not int or
                    not 1024 <= host_port <= 65535 or not 1 <= guest_port <= 65535):
                raise ValueError('Invalid TCP forwarding ports')
            if self.manifest['input']['network'] == 'none':
                raise ValueError('No guest network')
            result = self.qmp.call('human-monitor-command', {'command-line':
                f'hostfwd_add net0 tcp:127.0.0.1:{host_port}-:{guest_port}'})
            if result:
                raise RuntimeError(result)
            save(self.run / 'forward.json', {'host': '127.0.0.1', 'host_port': host_port,
                                           'guest_port': guest_port})
            return {'ok': True, 'host': '127.0.0.1', 'host_port': host_port, 'guest_port': guest_port}
        if operation == 'snapshot':
            action, tag = request.get('action'), request.get('tag', '')
            if action not in ['save', 'load'] or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,47}', tag):
                raise ValueError('Snapshot requires save/load and a bounded alphanumeric tag')
            if self.qmp.call('query-status')['running']:
                raise ValueError('Pause the VM before saving or loading a snapshot')
            begun = time.monotonic()
            try:
                raw = self.qmp.call('human-monitor-command', {'command-line': f'{action}vm {tag}'})
            finally:
                self.qmp.call('stop')
                self.state = 'paused'
            snapshot_result = {
                'action': action, 'tag': tag, 'raw_result': raw,
                'seconds': time.monotonic()-begun,
                'image_sha256': digest(self.run / 'disk.img'),
                'symbols_sha256': digest(self.run / 'boot.elf')}
            with (self.run / 'snapshot-results.jsonl').open('a') as stream:
                stream.write(json.dumps(snapshot_result) + '\n')
            if raw:
                raise RuntimeError('Snapshot failed: ' + raw)
            return {'ok': True, 'state': 'paused', 'raw_result': raw,
                    'seconds': time.monotonic()-begun}
        if operation == 'qmp':
            name = request['command']
            if not name.startswith('query-') and name not in ['trace-event-get-state', 'trace-event-set-state']:
                raise ValueError('Use lifecycle/debug commands to mutate VM state; QMP exposes query-* and tracing')
            return {'ok': True, 'result': self.qmp.call(name, request.get('arguments', {}))}
        if operation == 'trace':
            options = request['events'].split(',')
            allowed = {'none', 'guest_errors', 'int', 'cpu_reset', 'in_asm', 'exec'}
            if not options or any(option not in allowed for option in options):
                raise ValueError('Trace events: none,guest_errors,int,cpu_reset,in_asm,exec')
            return {'ok': True, 'result': self.qmp.call('human-monitor-command',
                     {'command-line': 'log ' + ','.join(options)}), 'stream': 'trace'}
        if operation == 'physical-memory':
            address = int(request['address'], 0)
            length = request.get('length', 256)
            if address < 0 or not 1 <= length <= 65536 or address+length > self.manifest['input']['memory_mib']*1024*1024:
                raise ValueError('Physical memory range is outside RAM or too large')
            path = self.run / 'physical-memory.bin'
            self.qmp.call('pmemsave', {'val': address, 'size': length, 'filename': str(path)})
            return {'ok': True, 'address': address, 'hex': path.read_bytes().hex()}
        raise ValueError('Unknown owner operation')

    def serve(self, connection):
        with connection:
            connection.settimeout(1)
            try:
                with connection.makefile('rb') as stream:
                    line = stream.readline(16385)
                if len(line) > 16384:
                    raise ValueError('RPC request too large')
                result = self.request(json.loads(line))
            except Exception as error:
                result = {'ok': False, 'error': str(error)}
            connection.sendall(json.dumps(result).encode() + b'\n')

    def boot(self):
        command([tool('qemu-img'), 'create', '-f', 'qcow2', '-F', 'raw',
                 '-b', self.run / 'disk.img', self.run / 'overlay.qcow2'])
        config = ['-machine', MACHINE, '-accel', 'tcg,thread=single', '-cpu', 'qemu64',
                  '-smp', '1', '-m', f'{self.manifest["input"]["memory_mib"]}M', '-display', 'none', '-nic', 'none',
                  '-monitor', 'none', '-no-reboot', '-no-shutdown',
                  '-d', 'guest_errors', '-D', str(self.run / 'trace.log'),
                  '-rtc', 'base=2000-01-01T00:00:00,clock=vm',
                  '-icount', 'shift=3,align=off,sleep=off', '-S',
                  '-drive', f'file={self.run / "overlay.qcow2"},format=qcow2,if={self.manifest["input"]["disk_interface"]}',
                  '-boot', 'a' if self.manifest['input']['disk_interface'] == 'floppy' else 'c',
                  '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
                  '-chardev', f'socket,id=serial,path={self.sockets / "serial"},server=on,wait=off',
                  '-serial', 'chardev:serial', '-debugcon', f'file:{self.run / "early.log"}',
                  '-qmp', f'unix:{self.sockets / "qmp"},server=on,wait=off',
                  '-gdb', f'unix:{self.sockets / "gdb"},server=on,wait=off']
        if self.manifest['input'].get('minimal_devices', False):
            config += ['-nodefaults', '-vga', 'none']
        nic_device = self.manifest['input'].get('nic_model', 'e1000') + ',id=nic0,netdev=net0'
        if not self.manifest['input'].get('nic_rom', True):
            nic_device += ',romfile='
        if self.manifest['input']['network'] in ['isolated', 'internet']:
            restriction = 'on' if self.manifest['input']['network'] == 'isolated' else 'off'
            config += ['-netdev', 'user,id=net0,restrict=' + restriction, '-device', nic_device,
                       '-object', f'filter-dump,id=pcap0,netdev=net0,file={self.run / "network.pcap"}']
        if self.manifest['input']['network'] == 'peer':
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            self.manifest['peer_port'] = port
            save(self.run / 'manifest.json', self.manifest)
            config += ['-netdev', f'socket,id=net0,listen=127.0.0.1:{port}',
                       '-device', nic_device,
                       '-object', f'filter-dump,id=pcap0,netdev=net0,file={self.run / "network.pcap"}']
        if (self.manifest['input']['network'] == 'internet' or
                self.manifest['input'].get('timing') == 'realtime'):
            at = config.index('-icount')
            del config[at:at+2]
        pvh = self.manifest['input'].get('boot_route', 'bios') == 'pvh'
        preload = False
        if pvh:
            if (digest(self.run / 'pvh.elf') != self.manifest['boot_kernel_sha256'] or
                    digest(self.run / 'pvh-inputs.json') != self.manifest['boot_provenance_sha256']):
                raise ValueError('Saved PVH loader/provenance hash mismatch')
            validate_pvh(self.run / 'pvh.elf', self.run / 'disk.img', self.run / 'boot.elf')
            preload = load(self.run / 'pvh-inputs.json').get('preload', False)
            if preload != self.manifest['input'].get('preload', False):
                raise ValueError('Saved PVH preload flag changed')
            config += ['-kernel', str(self.run / 'pvh.elf')]
            if preload:
                if digest(self.run / 'kernel.bin') != self.manifest['preload_kernel_sha256']:
                    raise ValueError('Saved PVH preload payload hash mismatch')
                config += ['-device', f'loader,file={self.run / "kernel.bin"},addr=0x100000,force-raw=on']
        firmware = pvh_firmware() if pvh else Path(tool('qemu-system-x86_64')).resolve().parent.parent / 'share/qemu/bios-256k.bin'
        if not firmware.exists():
            for candidate in [Path('/usr/share/qemu/bios-256k.bin'), Path('/usr/share/seabios/bios-256k.bin')]:
                if candidate.exists():
                    firmware = candidate
                    break
        if firmware.exists():
            config += ['-bios', str(firmware)]
            self.manifest['firmware_sha256'] = digest(firmware)
        self.manifest['runtime_tools'] = {name: command(
            [tool(name), '--version']).splitlines()[0] for name in ['qemu-system-x86_64', 'gdb', 'nasm']}
        self.manifest['machine'] = {'type': MACHINE, 'cpu': 'qemu64', 'ram_mib': self.manifest['input']['memory_mib'],
                                    'acceleration': 'tcg', 'cpus': 1, 'network': self.manifest['input']['network'],
                                    'rtc': '2000-01-01T00:00:00', 'record_replay': False,
                                    'boot_route': ('pvh-qboot-preload' if preload else 'pvh-qboot') if pvh else 'bios-disk',
                                    'timing': self.manifest['input'].get('timing', 'virtual')}
        self.manifest['qemu_argv'] = [tool('qemu-system-x86_64')] + config
        save(self.run / 'manifest.json', self.manifest)
        output = (self.run / 'qemu.log').open('ab', buffering=0)
        self.process = subprocess.Popen(self.manifest['qemu_argv'], stdin=subprocess.DEVNULL,
                                        stdout=output, stderr=output)
        output.close()
        deadline = time.monotonic() + 5
        while not (self.sockets / 'qmp').exists():
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('QEMU startup failed: ' + (self.run / 'qemu.log').read_text())
            time.sleep(0.02)
        self.qmp = QMP(self.sockets / 'qmp', self.events)
        self.serial = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.serial.settimeout(3)
        self.serial.connect(str(self.sockets / 'serial'))
        self.serial.setblocking(False)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.sockets / 'owner'))
        self.server.listen(4)
        self.selector.register(self.serial, selectors.EVENT_READ, 'serial')
        self.selector.register(self.server, selectors.EVENT_READ, 'owner')
        self.state = 'paused' if self.manifest['input']['paused'] else 'running'
        # Initial RESET events were generated before guest boot; retain but exclude from verdict.
        self.qmp.call('query-status')
        self.events.clear()
        self.status()
        if self.state == 'running':
            self.qmp.call('cont')

    def serial_read(self):
        data = self.serial.recv(65536)
        if not data:
            self.selector.unregister(self.serial)
            return
        self.raw.extend(data)
        with (self.run / 'serial.log').open('ab') as stream:
            stream.write(data)
        if b'OSE1 READY\n' in self.raw and not self.command_sent and not self.manifest['input']['manual']:
            self.ready_seconds = time.monotonic() - self.started
            self.serial.sendall(self.manifest['input']['command'].encode())
            self.command_sent = True
            self.status()

    def loop(self):
        self.boot()
        deadline = self.started + self.manifest['input']['timeout']
        while not self.finished:
            for key, _ in self.selector.select(0.05):
                if key.data == 'serial':
                    self.serial_read()
                else:
                    connection, _ = self.server.accept()
                    self.serve(connection)
            if self.process.poll() is not None:
                # Drain bytes queued before QEMU's exit.
                try:
                    while self.serial in [key.fileobj for key in self.selector.get_map().values()]:
                        self.serial_read()
                except BlockingIOError:
                    pass
                self.reason = 'exit'
                break
            try:
                self.qmp.call('query-status')
            except (OSError, RuntimeError):
                try:
                    self.process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    raise
                continue
            if any(e.get('data', {}).get('reason') == 'guest-reset' for e in self.events):
                self.reason = 'reset'
                self.capture('reset')
                break
            if any(e.get('data', {}).get('reason') == 'guest-shutdown' for e in self.events):
                # -no-shutdown preserves a reset/crash CPU for capture. It also
                # pauses debug-exit; QMP quit releases the saved debug-exit code.
                self.reason = 'exit'
                self.qmp.call('quit')
                self.process.wait(timeout=3)
                try:
                    while self.serial in [key.fileobj for key in self.selector.get_map().values()]:
                        self.serial_read()
                except BlockingIOError:
                    pass
                break
            if panic_record_ready(self.raw):
                self.reason = 'panic'
                self.capture('panic')
                break
            if time.monotonic() >= deadline:
                self.reason = 'timeout'
                self.capture('timeout')
                break
        result = verdict(bytes(self.raw), self.process.poll(), self.events, self.reason == 'timeout')
        if self.reason == 'panic' and self.manifest['input']['manual']:
            import re
            match = re.search(rb'OSL1 PANIC vector=(\d+)', self.raw)
            result = {'ok': False, 'verdict': 'panic', 'panic': {'vector': int(match[1]) if match else None}}
        if self.reason == 'stopped':
            result = {'ok': False, 'verdict': 'stopped'}
        if self.manifest['input']['manual'] and self.reason == 'stopped':
            result = {'ok': True, 'verdict': 'manual_stopped', 'verified': False}
        if self.manifest['input']['manual'] and self.reason == 'exit':
            result = {'ok': True, 'verdict': 'manual_exited', 'verified': False}
        self.cleanup()
        self.state = 'finished'
        self.status(**result, elapsed_seconds=time.monotonic()-self.started,
                    exit_code=self.process.returncode, captures=self.capture_count)

    def cleanup(self):
        if self.breakpoints:
            try:
                self.breakpoints.close()
            except Exception:
                pass
        if self.process and self.process.poll() is None:
            try:
                self.qmp.call('quit')
                self.process.wait(timeout=3)
            except Exception:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
        if self.qmp:
            self.qmp.close()
        for name in ['serial', 'server']:
            item = getattr(self, name, None)
            if item:
                item.close()
        self.selector.close()
        shutil.rmtree(self.sockets, ignore_errors=True)
        self.lock.close()


def worker(identity):
    owner = Owner(identity)
    try:
        owner.loop()
    except Exception as error:
        # Always retain logs, even when startup or capture itself fails.
        save(owner.run / 'failure.json', {'error': str(error)})
        owner.cleanup()
        owner.state = 'error'
        owner.status(ok=False, error=str(error))
        raise
