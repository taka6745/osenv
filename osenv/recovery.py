"""Recover a dead controller without risking a reused PID or another VM."""
import os
import signal
import time
from .core import command, get_run, load, save
from .transport import QMP
from .worker import Owner


def owned_process(pid, image):
    if not pid:
        return False
    try:
        arguments = command(['ps', '-p', str(pid), '-o', 'command='], timeout=3)
    except RuntimeError:
        return False
    return 'qemu-system-x86_64' in arguments and str(image) in arguments


def rescue(identity):
    run = get_run(identity)
    status = load(run / 'status.json')
    pid = status.get('qemu_pid')
    owner = Owner(identity)  # Exclusive flock refuses adoption of a live owner.
    try:
        image = run / 'overlay.qcow2'
        if not owned_process(pid, image):
            save(run / 'status.json', {'state': 'finished', 'ok': False,
                                      'verdict': 'owner_lost', 'reason': 'No matching owned QEMU remains'})
            return {'ok': True, 'qemu_found': False}
        try:
            owner.qmp = QMP(owner.sockets / 'qmp', owner.events)
        except Exception:
            pass
        evidence = owner.capture('owner-lost')
        try:
            owner.qmp.call('quit')
        except Exception:
            pass
        deadline = time.monotonic() + 3
        while owned_process(pid, image) and time.monotonic() < deadline:
            time.sleep(0.05)
        for sig in [signal.SIGTERM, signal.SIGKILL]:
            if owned_process(pid, image):
                os.kill(pid, sig)
                time.sleep(0.1)
        if owned_process(pid, image):
            raise RuntimeError('Owned QEMU did not stop; preserved capture and refused another controller')
        save(run / 'status.json', {'state': 'finished', 'ok': False, 'verdict': 'owner_lost',
                                  'capture': evidence, 'old_qemu_pid': pid})
        return {'ok': True, 'qemu_found': True, 'evidence': evidence}
    finally:
        owner.cleanup()
