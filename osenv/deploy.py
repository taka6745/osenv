"""Run the exact saved build in dedicated, owned homelab QEMU VMs over SSH.

No guest network, no changes to existing Proxmox VMs. Host names stay in ignored
configuration and run artifacts, never in source. Deployment returns a job ID.
"""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import uuid
from .core import ROOT, build, command, digest, get_run, load, save


def deploy(config_path, build_id=None):
    config = load(config_path)
    host = config['ssh_host']
    if not re.fullmatch(r'[A-Za-z0-9_.@-]+', host) or host.startswith('-'):
        raise ValueError('Invalid SSH host alias')
    if build_id:
        if not re.fullmatch('[0-9a-f]{16}', build_id):
            raise ValueError('Invalid build ID')
        built = {'build_id': build_id, 'directory': str(ROOT / 'build' / build_id)}
    else:
        built = build()
    directory = Path(built['directory'])
    manifest = load(directory / 'manifest.json')
    for name, expected in manifest['files'].items():
        if digest(directory / name) != expected:
            raise ValueError(f'Build hash mismatch: {name}')
    identity = str(uuid.uuid4())
    run = ROOT / 'runs' / identity
    run.mkdir(parents=True)
    modes = {mode: build(mode) for mode in ['protected32', 'long64']}
    save(run / 'manifest.json', {'schema': 1, 'kind': 'deployment', 'run_id': identity,
                                'private_config': config, 'build': built, 'modes': modes})
    save(run / 'status.json', {'state': 'running', 'ok': True, 'run_id': identity})
    output = (run / 'owner.log').open('ab')
    process = subprocess.Popen([os.sys.executable, '-m', 'osenv', '_deploy_worker', identity],
                               stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                               cwd=ROOT, start_new_session=True)
    output.close()
    save(run / 'launch.json', {'owner_pid': process.pid})
    return {'ok': True, 'run_id': identity, 'state': 'running', 'build_id': built['build_id']}


def deploy_worker(identity):
    run = get_run(identity)
    manifest = load(run / 'manifest.json')
    built = manifest['build']
    build_id = built['build_id']
    host = manifest['private_config']['ssh_host']
    remote = '/var/lib/vz/osenv-harness/' + build_id
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5',
           '-o', 'ServerAliveCountMax=2', host]
    try:
        archive_path = run / 'source.tar.gz'
        with tarfile.open(archive_path, 'w:gz') as archive:
            for path in sorted((ROOT / 'osenv').glob('*.py')):
                archive.add(path, arcname=str(path.relative_to(ROOT)))
            for item in [built, *manifest['modes'].values()]:
                for path in Path(item['directory']).iterdir():
                    if path.is_file():
                        archive.add(path, arcname='build/' + item['build_id'] + '/' + path.name)
        # This is host tooling only; no guest package or external guest agent.
        preparation = command(ssh + ['command -v python3; command -v qemu-system-x86_64; '
                                      'command -v gdb; command -v nasm'], timeout=15)
        (run / 'remote-tools.txt').write_text(preparation)
        with archive_path.open('rb') as stream:
            result = subprocess.run(ssh + ['mkdir -p ' + shlex.quote(remote) + ' && tar -xz -C ' + shlex.quote(remote)],
                                    stdin=stream, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
        expected = load(Path(built['directory']) / 'manifest.json')['files']['fixture.img']
        modes = {mode: {'build_id': value['build_id'], 'image_sha256':
                       load(Path(value['directory']) / 'manifest.json')['files']['fixture.img']}
                 for mode, value in manifest['modes'].items()}
        script = f'''
import json, os, pathlib, time
os.chdir({remote!r})
from osenv.core import digest, get_run, load, save
from osenv.worker import start
from osenv.__main__ import wait, call
directory = pathlib.Path('build/{build_id}').resolve()
assert digest(directory / 'fixture.img') == {expected!r}, 'Uploaded image hash mismatch'
checks = []
for scenario, expected in [('pass','pass'), ('fault','panic'), ('hang','timeout'), ('reset','reset'), ('pass','pass')]:
    launched = start(scenario, timeout=3 if scenario == 'hang' else 10,
                     existing_build={{'directory': str(directory)}})
    result = wait(launched['run_id'], 30)
    path = get_run(launched['run_id'])
    complete = True
    if scenario in ['fault','hang','reset']:
        complete = load(path / 'capture-001/capture.json')['complete']
    checks.append({{'scenario':scenario,'ok':result.get('verdict') == expected and complete,
                    'run_id':launched['run_id'],'status':result,
                    'runtime_tools':load(path / 'manifest.json')['runtime_tools']}})
for mode, item in {modes!r}.items():
    directory = pathlib.Path('build') / item['build_id']
    assert digest(directory / 'fixture.img') == item['image_sha256']
    launched = start(timeout=30, manual=True, mode=mode, existing_build={{'directory':str(directory.resolve())}})
    path = get_run(launched['run_id'])
    deadline = time.monotonic()+8
    marker = ('OSE1 MODE '+mode).encode()
    while time.monotonic()<deadline and marker not in (path/'serial.log').read_bytes():
        time.sleep(0.05)
    registers = call(launched['run_id'], {{'operation':'debug','action':'registers','mode':mode}})
    capture = call(launched['run_id'], {{'operation':'capture','mode':mode}})
    call(launched['run_id'], {{'operation':'stop'}})
    stopped = wait(launched['run_id'])
    checks.append({{'scenario':mode, 'ok': marker in (path/'serial.log').read_bytes() and registers['ok']
                   and capture['complete'] and stopped.get('verdict')=='manual_stopped',
                   'run_id':launched['run_id'],'image_sha256':item['image_sha256']}})
result = {{'ok':all(c['ok'] for c in checks), 'checks':checks, 'image_sha256':{expected!r},
          'remote_directory':str(pathlib.Path.cwd()), 'dedicated_vm':'owned QEMU TCG process per run',
          'network':False, 'build_id':{build_id!r}}}
save(pathlib.Path('verification.json'), result)
print(json.dumps(result))
'''
        result = command(ssh + ['cd ' + shlex.quote(remote) + ' && python3 -'],
                         timeout=180, input=script)
        verification = json.loads(result)
        save(run / 'verification.json', verification)
        # Retrieve raw failure evidence as well as verdicts; keep it ignored.
        package = run / 'remote-evidence.tar.gz'
        with package.open('wb') as output:
            fetched = subprocess.run(ssh + ['tar -cz -C ' + shlex.quote(remote) + ' runs verification.json'],
                                     stdout=output, stderr=subprocess.PIPE, timeout=60)
        if fetched.returncode:
            raise RuntimeError('Verification finished but evidence retrieval failed: ' + fetched.stderr.decode(errors='replace'))
        with tarfile.open(package, 'r:gz') as archive:
            archive.extractall(run / 'remote', filter='data')
        save(run / 'status.json', {'state': 'finished', 'ok': verification['ok'],
             'verdict': 'homelab_verified' if verification['ok'] else 'homelab_failed',
             'image_sha256': expected, 'build_id': build_id,
             'checks': len(verification['checks']), 'evidence': 'remote-evidence.tar.gz'})
    except Exception as error:
        save(run / 'status.json', {'state': 'error', 'ok': False, 'error': str(error)})
