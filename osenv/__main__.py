"""One JSON CLI for the VM lifecycle, evidence and debugger."""
import argparse
import json
from pathlib import Path
import sys
import time
from .core import ROOT, build, doctor, get_run, load, read_cursor
from .transport import rpc
from .worker import SCENARIOS, start, worker


def call(identity, request):
    run = get_run(identity)
    status = load(run / 'status.json')
    if status['state'] in ['finished', 'error']:
        raise ValueError('Run is no longer live; use logs/artifacts or reproduce')
    socket = Path(load(run / 'manifest.json')['socket_directory']) / 'owner'
    return rpc(socket, request)


def wait(identity, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        status = load(get_run(identity) / 'status.json')
        if status['state'] in ['finished', 'error']:
            return {'run_id': identity, **status}
        time.sleep(0.05)
    raise TimeoutError(f'Wait expired; run {identity} continues within its own deadline')


def test_suite():
    from .tests import integration
    return integration()


class JSONParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def parser():
    p = JSONParser(description='OS development harness; every result is JSON')
    sub = p.add_subparsers(dest='operation', required=True)
    sub.add_parser('setup')
    sub.add_parser('doctor')
    item = sub.add_parser('audit')
    item.add_argument('--repo', default=str(ROOT))
    item.add_argument('--os-only', action='store_true')
    item = sub.add_parser('build')
    item.add_argument('--fixture-mode', choices=['real16', 'protected32', 'long64'], default='real16')
    item = sub.add_parser('project-build')
    item.add_argument('--project', required=True)
    item = sub.add_parser('project-test')
    item.add_argument('--project', required=True)
    item.add_argument('--internet-host', help='Opt-in live HTTP/DNS acceptance host')
    item = sub.add_parser('project-deploy')
    item.add_argument('--project', required=True)
    item.add_argument('--config', required=True)
    item.add_argument('--internet-host')
    item = sub.add_parser('test')
    item.add_argument('--background', action='store_true')
    sub.add_parser('capabilities')
    item = sub.add_parser('benchmark')
    item.add_argument('--repeat', type=int, default=5)
    item = sub.add_parser('pi4-test')
    item.add_argument('--project', required=True)
    item = sub.add_parser('web-test')
    item.add_argument('--image', required=True)
    item.add_argument('--symbols', required=True)
    item.add_argument('--production', action='store_true')
    item.add_argument('--nic-model', choices=['e1000', 'e1000e'], default='e1000')
    item.add_argument('--minimal-devices', action='store_true')
    item.add_argument('--boot-kernel', help='Optional authored PVH ELF32 plus matching provenance')
    run = sub.add_parser('run')
    run.add_argument('--scenario', choices=SCENARIOS, default='pass')
    run.add_argument('--timeout', type=float, default=8)
    run.add_argument('--paused', action='store_true')
    run.add_argument('--image')
    run.add_argument('--manual', action='store_true', help='Observe a custom BIOS image without fixture assertions')
    run.add_argument('--symbols', help='ELF at its linked load address')
    run.add_argument('--mode', choices=['real16', 'protected32', 'long64'], default='real16')
    run.add_argument('--memory', type=int, default=32)
    run.add_argument('--network', choices=['none', 'isolated', 'internet', 'peer'], default='none')
    run.add_argument('--disk-interface', choices=['ide', 'floppy'])
    run.add_argument('--nic-model', choices=['e1000', 'e1000e'], default='e1000')
    run.add_argument('--minimal-devices', action='store_true')
    run.add_argument('--boot-kernel', help='Optional authored PVH ELF32 plus matching provenance')
    for operation in ['status', 'stop', 'recover', 'connections', 'inspect', '_worker', '_deploy_worker', '_job_worker', '_project_deploy_worker']:
        item = sub.add_parser(operation)
        item.add_argument('run_id')
    item = sub.add_parser('wait')
    item.add_argument('run_id')
    item.add_argument('--timeout', type=float, default=30)
    item = sub.add_parser('reproduce')
    item.add_argument('run_id')
    item = sub.add_parser('logs')
    item.add_argument('run_id')
    item.add_argument('--stream', choices=['serial', 'early', 'qemu', 'owner', 'trace', 'events', 'annotations', 'actions'], default='serial')
    item.add_argument('--cursor', type=int, default=0)
    item.add_argument('--limit', type=int, default=65536)
    item = sub.add_parser('annotate')
    item.add_argument('run_id')
    item.add_argument('text')
    item.add_argument('--source', default='host')
    item.add_argument('--level', choices=['debug', 'info', 'warn', 'error'], default='info')
    item = sub.add_parser('qmp')
    item.add_argument('run_id')
    item.add_argument('command')
    item.add_argument('--arguments', type=json.loads, default={})
    item = sub.add_parser('physical-memory')
    item.add_argument('run_id')
    item.add_argument('--address', required=True)
    item.add_argument('--length', type=int, default=256)
    item = sub.add_parser('trace')
    item.add_argument('run_id')
    item.add_argument('--events', default='guest_errors,int,cpu_reset')
    item = sub.add_parser('network-forward')
    item.add_argument('run_id')
    item.add_argument('--host-port', type=int, required=True)
    item.add_argument('--guest-port', type=int, default=80)
    item = sub.add_parser('network-link')
    item.add_argument('run_id')
    item.add_argument('state', choices=['up', 'down'])
    item = sub.add_parser('artifacts')
    item.add_argument('run_id')
    item.add_argument('--file')
    item.add_argument('--cursor', type=int, default=0)
    item.add_argument('--limit', type=int, default=4096)
    item.add_argument('--hex', action='store_true')
    item = sub.add_parser('capture')
    item.add_argument('run_id')
    item.add_argument('--mode', choices=['real16', 'protected32', 'long64'])
    item = sub.add_parser('serial')
    item.add_argument('run_id')
    item.add_argument('text')
    item = sub.add_parser('debug')
    item.add_argument('run_id')
    item.add_argument('action', choices=['pause', 'resume', 'registers', 'step', 'memory',
                                       'write-memory', 'disassemble', 'breakpoint', 'evaluate',
                                       'write-register', 'backtrace', 'symbols', 'control-registers',
                                       'breakpoints', 'delete-breakpoints', 'watchpoint', 'add-symbols'])
    item.add_argument('--address')
    item.add_argument('--length', type=int, default=64)
    item.add_argument('--value')
    item.add_argument('--symbols')
    item.add_argument('--mode', choices=['real16', 'protected32', 'long64'])
    item = sub.add_parser('deploy')
    item.add_argument('--config', default='local/deploy.json')
    item.add_argument('--build-id')
    return p


def dispatch(a):
    operation = a.operation
    if operation == '_worker':
        worker(a.run_id)
        return {'ok': True}
    if operation == '_project_deploy_worker':
        from .project import project_deploy_worker
        project_deploy_worker(a.run_id)
        return {'ok': True}
    if operation == '_deploy_worker':
        from .deploy import deploy_worker
        deploy_worker(a.run_id)
        return {'ok': True}
    if operation == '_job_worker':
        from .jobs import worker as job_worker
        job_worker(a.run_id)
        return {'ok': True}
    if operation == 'setup':
        from .jobs import launch
        return launch('setup')
    if operation == 'audit':
        from .integrity import audit
        return audit(a.repo, a.os_only)
    if operation == 'doctor':
        return doctor()
    if operation in ['project-build', 'project-test', 'project-deploy']:
        from .project import project_build, project_test, project_deploy
        if operation == 'project-build':
            return project_build(a.project)
        if operation == 'project-test':
            return project_test(a.project, a.internet_host)
        return project_deploy(a.project, a.config, a.internet_host)
    if operation == 'pi4-test':
        from .pi4_test import pi4_test
        return pi4_test(a.project)
    if operation == 'web-test':
        from .web_test import web_test
        return web_test(a.image, a.symbols, production=a.production, nic_model=a.nic_model, minimal_devices=a.minimal_devices, boot_kernel=a.boot_kernel)
    if operation == 'build':
        return build(a.fixture_mode)
    if operation == 'run':
        return start(a.scenario, a.timeout, a.paused, a.image, manual=a.manual,
                     symbols=a.symbols, mode=a.mode, memory=a.memory, network=a.network,
                     disk_interface=a.disk_interface, nic_model=a.nic_model, minimal_devices=a.minimal_devices, boot_kernel=a.boot_kernel)
    if operation == 'test':
        if a.background:
            from .jobs import launch
            return launch('test')
        return test_suite()
    if operation == 'benchmark':
        if not 1 <= a.repeat <= 100:
            raise ValueError('Repeat must be 1..100')
        import statistics
        built = build()
        samples = []
        identities = []
        for _ in range(a.repeat):
            launched = start(existing_build=built)
            finished = wait(launched['run_id'])
            if finished.get('verdict') != 'pass':
                raise RuntimeError(f'Benchmark boot failed: {finished}')
            samples.append(finished['ready_seconds'])
            identities.append(launched['run_id'])
        return {'ok': True, 'scope': 'local TCG fixture process launch to serial READY; not OS performance',
                'samples_seconds': samples, 'median_seconds': statistics.median(samples),
                'image_bytes': 1474560, 'boot_sector_bytes': 512, 'ram_mib': 32,
                'run_ids': identities, 'build_id': built['build_id']}
    if operation == 'capabilities':
        return {'ok': True, 'protocol': 1, 'host': ['qmp', 'gdb-mi', 'serial', 'cursor-logs',
                'physical-memory-dump', 'registers', 'memory-read-write', 'disassembly',
                'breakpoints', 'watchpoints', 'step', 'expressions', 'symbols', 'backtrace',
                'control-registers', 'register-writes', 'device-inspection', 'trace',
                'isolated-network', 'link-failure-injection', 'pcap', 'qcow2-overlays',
                'fault-capture', 'hang-capture', 'reset-capture', 'reproduce', 'writable-logs',
                'benchmark', 'homelab-deploy', 'project-build', 'project-test', 'project-deploy', 'opt-in-Internet'],
                'guest': {'fixture': True, 'cpu_modes_tested': ['real16','protected32','long64'],
                          'network_stack': False, 'threads': False, 'drivers': False},
                'record_replay': False}
    if operation == 'wait':
        if not 0 < a.timeout <= 660:
            raise ValueError('Wait timeout must be 0..660 seconds')
        return wait(a.run_id, a.timeout)
    if operation == 'status':
        return {'ok': True, 'run_id': a.run_id, **load(get_run(a.run_id) / 'status.json')}
    if operation == 'logs':
        filename = a.stream + ('.jsonl' if a.stream in ['events', 'annotations', 'actions'] else '.log')
        return {'ok': True, **read_cursor(get_run(a.run_id) / filename, a.cursor, a.limit)}
    if operation == 'artifacts':
        run = get_run(a.run_id)
        if not a.file:
            return {'ok': True, 'files': [{'path': str(p.relative_to(run)), 'bytes': p.stat().st_size}
                     for p in sorted(run.rglob('*')) if p.is_file()]}
        path = (run / a.file).resolve()
        if not path.is_relative_to(run.resolve()):
            raise ValueError('Artifact path escapes run')
        if a.hex:
            if a.cursor < 0 or not 1 <= a.limit <= 1048576:
                raise ValueError('Invalid cursor/limit')
            with path.open('rb') as stream:
                stream.seek(a.cursor)
                value = stream.read(a.limit)
                return {'ok': True, 'cursor': stream.tell(), 'hex': value.hex()}
        return {'ok': True, **read_cursor(path, a.cursor, a.limit)}
    if operation == 'reproduce':
        old = get_run(a.run_id)
        manifest = load(old / 'manifest.json')
        from .core import digest
        if digest(old / 'disk.img') != manifest['image_sha256']:
            raise ValueError('Saved image hash mismatch')
        # Replay the exact saved image and symbols, never rebuild changed source.
        inputs = manifest['input']
        return start(inputs['scenario'], inputs['timeout'], inputs['paused'], old / 'disk.img',
                     {'directory': str(old)}, manual=inputs['manual'], mode=inputs['mode'], memory=inputs['memory_mib'],
                     network=inputs['network'], disk_interface=inputs['disk_interface'],
                     timing=inputs.get('timing', 'virtual'), nic_rom=inputs.get('nic_rom', True),
                     nic_model=inputs.get('nic_model', 'e1000'), minimal_devices=inputs.get('minimal_devices', False),
                     boot_kernel=old / 'pvh.elf' if inputs.get('boot_route') == 'pvh' else None)
    if operation == 'recover':
        old = get_run(a.run_id)
        manifest = load(old / 'manifest.json')
        if load(old / 'status.json')['state'] not in ['finished', 'error']:
            try:
                call(a.run_id, {'operation': 'recover'})
                wait(a.run_id, 20)
            except (OSError, RuntimeError):
                from .recovery import rescue
                rescue(a.run_id)
        inputs = manifest['input']
        return start('pass', inputs['timeout'], image=old / 'disk.img', existing_build={'directory': str(old)},
                     manual=inputs['manual'], mode=inputs['mode'], memory=inputs['memory_mib'],
                     network=inputs['network'], disk_interface=inputs['disk_interface'],
                     timing=inputs.get('timing', 'virtual'), nic_rom=inputs.get('nic_rom', True),
                     nic_model=inputs.get('nic_model', 'e1000'), minimal_devices=inputs.get('minimal_devices', False),
                     boot_kernel=old / 'pvh.elf' if inputs.get('boot_route') == 'pvh' else None)
    if operation == 'deploy':
        from .deploy import deploy
        return deploy(a.config, a.build_id)
    if operation == 'network-link':
        return call(a.run_id, {'operation': operation, 'up': a.state == 'up'})
    if operation in ['stop', 'connections', 'capture', 'serial', 'debug', 'inspect', 'qmp',
                     'physical-memory', 'annotate', 'trace', 'network-forward']:
        request = vars(a).copy()
        request.pop('run_id')
        return call(a.run_id, request)
    raise ValueError('Unsupported command')


def main():
    try:
        a = parser().parse_args()
        result = dispatch(a)
        print(json.dumps(result))
        return 0 if result.get('ok', True) else 1
    except Exception as error:
        print(json.dumps({'ok': False, 'error': str(error)}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
