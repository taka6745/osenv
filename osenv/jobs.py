"""Bounded background host jobs share the run-ID/status/log interface."""
import os
import subprocess
import uuid
from .core import ROOT, command, doctor, get_run, load, save


def launch(operation):
    identity = str(uuid.uuid4())
    run = ROOT / 'runs' / identity
    run.mkdir(parents=True, mode=0o700)
    save(run / 'manifest.json', {'schema': 1, 'kind': 'host-job', 'operation': operation})
    save(run / 'status.json', {'state': 'running', 'ok': True})
    output = (run / 'owner.log').open('ab')
    process = subprocess.Popen([os.sys.executable, '-m', 'osenv', '_job_worker', identity],
                               cwd=ROOT, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                               start_new_session=True)
    output.close()
    save(run / 'launch.json', {'owner_pid': process.pid})
    return {'ok': True, 'run_id': identity, 'state': 'running'}


def worker(identity):
    run = get_run(identity)
    operation = load(run / 'manifest.json')['operation']
    try:
        if operation == 'setup':
            if os.sys.platform != 'darwin':
                raise RuntimeError('See TOOLING.md for pinned Linux tools; automatic setup currently supports Homebrew')
            output = command(['brew', 'install', 'llvm', 'lld', 'nasm', 'qemu', 'gdb'], timeout=600)
            (run / 'setup.log').write_text(output)
            result = doctor()
        elif operation == 'test':
            # Overall deadline protects the gate in addition to each VM's deadline.
            output = command([os.sys.executable, '-m', 'osenv', 'test'], timeout=180)
            import json
            result = json.loads(output)
        else:
            raise ValueError('Unknown background operation')
        save(run / 'result.json', result)
        save(run / 'status.json', {'state': 'finished', 'ok': result['ok'], 'result': result})
    except Exception as error:
        save(run / 'status.json', {'state': 'error', 'ok': False, 'error': str(error)})
