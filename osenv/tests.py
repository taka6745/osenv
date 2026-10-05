"""External integration gate, including deliberate-defect rejection."""
from pathlib import Path
import tempfile
import time
from .core import ROOT, build, get_run, load, save, validate_image
from .protocol import verdict
from .worker import start


def integration():
    from .__main__ import call, wait
    from .integrity import audit
    integrity = audit(Path(__file__).resolve().parent.parent)
    if not integrity['ok']:
        return integrity
    built = build()
    import io
    import unittest
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).resolve().parent.parent / 'tests'))
    host = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    checks = [{'case': 'host-regressions-and-seeded-fuzz', 'ok': host.wasSuccessful(),
               'tests': host.testsRun}]
    for scenario, expected in [('pass', 'pass'), ('fault', 'panic'), ('hang', 'timeout'),
                               ('bad-result', 'assertion_failed'), ('wrong-exit', 'exit_failed'),
                               ('reset', 'reset')]:
        result = start(scenario, timeout=3 if scenario == 'hang' else 8, existing_build=built)
        identity = result['run_id']
        completed = wait(identity, 25)
        run = get_run(identity)
        errors = []
        if completed.get('verdict') != expected:
            errors.append(f'Expected {expected}; got {completed}')
        if expected in ['panic', 'timeout', 'reset']:
            capture = run / 'capture-001'
            if not (capture / 'capture.json').exists() or not load(capture / 'capture.json')['complete']:
                errors.append('Incomplete failure capture')
            else:
                if (capture / 'memory.bin').stat().st_size != 32*1024*1024:
                    errors.append('Incorrect memory dump length')
                if 'register-values=' not in (capture / 'gdb.mi').read_text():
                    errors.append('Missing register evidence')
            if expected == 'panic' and completed.get('panic', {}).get('vector') != 6:
                errors.append('Incorrect exception decoder')
            if expected == 'panic' and not load(capture / 'panic.json')['expected_ud2']:
                errors.append('Fault frame does not point to UD2')
            recovered = start('pass', existing_build=built)
            recovery = wait(recovered['run_id'])
            if recovery.get('verdict') != 'pass':
                errors.append('Recovery boot failed')
        checks.append({'case': scenario, 'ok': not errors, 'run_id': identity, 'errors': errors})
    # Prove saved-input reproduction works without recompiling.
    from .__main__ import dispatch
    import argparse
    fault_id = next(c['run_id'] for c in checks if c['case'] == 'fault')
    reproduced = dispatch(argparse.Namespace(operation='reproduce', run_id=fault_id))
    repeated = wait(reproduced['run_id'])
    checks.append({'case': 'reproduce-fault', 'ok': repeated.get('verdict') == 'panic',
                   'run_id': reproduced['run_id']})
    with tempfile.TemporaryDirectory() as directory:
        bad = Path(directory) / 'bad.img'
        for value in [b'', bytes(512), bytes(1474560), b'\x55\xaa']:
            bad.write_bytes(value)
            try:
                validate_image(bad)
                raise AssertionError('Malformed image accepted')
            except ValueError:
                pass
    checks.append({'case': 'malformed-truncated-images', 'ok': True})
    # Exercise live debugger/control rather than only the snapshot path.
    paused = start('hang', timeout=60, paused=True, existing_build=built)
    identity = paused['run_id']
    errors = []
    try:
        for action, arguments in [('registers', {}), ('memory', {'address': '0xffff0', 'length': 16}),
                                  ('disassemble', {'address': '0xffff0', 'length': 32}),
                                  ('write-memory', {'address': '0x500', 'value': 'cafebabe'}),
                                  ('memory', {'address': '0x500', 'length': 4}),
                                  ('write-register', {'value': '$rax=0x1234'}),
                                  ('evaluate', {'value': '$rax'}),
                                  ('control-registers', {}), ('backtrace', {}),
                                  ('symbols', {'value': '_start'}), ('step', {})]:
            result = call(identity, {'operation': 'debug', 'action': action, **arguments})
            if not result.get('ok'):
                errors.append(action)
            if action == 'memory' and arguments['address'] == '0x500' and 'cafebabe' not in result['memory_hex']:
                errors.append('Memory write/read mismatch')
        connection = call(identity, {'operation': 'connections'})
        if connection['network'] != 'none':
            errors.append('Unexpected guest networking')
        physical = call(identity, {'operation': 'physical-memory', 'address': '0x500', 'length': 4})
        if physical['hex'] != 'cafebabe':
            errors.append('Physical read mismatch')
        inspected = call(identity, {'operation': 'inspect'})
        if not inspected['results']['query-cpus-fast']:
            errors.append('Missing CPU inspection')
        call(identity, {'operation': 'annotate', 'text': 'test log marker'})
        if 'test log marker' not in (get_run(identity) / 'annotations.jsonl').read_text():
            errors.append('Writable log marker missing')
        call(identity, {'operation': 'trace', 'events': 'guest_errors,int,cpu_reset'})
        call(identity, {'operation': 'debug', 'action': 'add-symbols', 'address': '0x7c00',
                        'symbols': str(get_run(identity) / 'boot.elf')})
        try:
            call(identity, {'operation': 'debug', 'action': 'breakpoint', 'address': 'definitely_absent_fixture_symbol'})
            errors.append('Undefined breakpoint accepted')
        except RuntimeError as error:
            if 'not defined' not in str(error):
                raise
        cpu = call(identity, {'operation': 'qmp', 'command': 'query-status'})
        if cpu['result']['running']:
            errors.append('Failed breakpoint resumed CPU')
        result = call(identity, {'operation': 'debug', 'action': 'breakpoint', 'address': '0x7c00'})
        deadline = time.monotonic() + 8
        hit = False
        while time.monotonic() < deadline:
            status = call(identity, {'operation': 'status'})
            if 'breakpoint-hit' in status.get('breakpoints', ''):
                hit = True
                break
            time.sleep(0.05)
        if not hit:
            errors.append('Boot breakpoint did not hit')
        listed = call(identity, {'operation': 'debug', 'action': 'breakpoints'})
        if 'BreakpointTable' not in listed['stdout']:
            errors.append('Persistent breakpoint missing after register inspection')
        watched = call(identity, {'operation': 'debug', 'action': 'watchpoint', 'address': '0x18'})
        call(identity, {'operation': 'debug', 'action': 'resume'})
        deadline = time.monotonic() + 8
        watch_hit = False
        while time.monotonic() < deadline:
            state = call(identity, {'operation': 'status'})
            if 'access-watchpoint-trigger' in state.get('breakpoints', '') or 'watchpoint-trigger' in state.get('breakpoints', ''):
                watch_hit = True
                break
            time.sleep(0.05)
        if not watch_hit:
            errors.append('Hardware watchpoint did not trigger')
        result = call(identity, {'operation': 'capture'})
        if not result['complete']:
            errors.append('Live capture failed')
        call(identity, {'operation': 'stop'})
        finished = wait(identity)
        if finished.get('verdict') != 'stopped':
            errors.append('Stop did not finish')
    except Exception as error:
        errors.append(str(error))
        try:
            call(identity, {'operation': 'stop'})
        except Exception:
            pass
    checks.append({'case': 'live-debug-breakpoint-stop', 'ok': not errors,
                   'run_id': identity, 'errors': errors})
    a = start('hang', timeout=20, existing_build=built)
    b = start('pass', existing_build=built)
    isolated = wait(b['run_id'])
    call(a['run_id'], {'operation': 'stop'})
    stopped = wait(a['run_id'])
    checks.append({'case': 'concurrent-run-isolation', 'ok': isolated.get('verdict') == 'pass'
                   and stopped.get('verdict') == 'stopped', 'run_ids': [a['run_id'], b['run_id']]})
    isolated_net = start('hang', timeout=30, paused=True, existing_build=built, network='isolated')
    nid = isolated_net['run_id']
    connection = call(nid, {'operation': 'connections'})
    call(nid, {'operation': 'network-link', 'up': False})
    call(nid, {'operation': 'network-link', 'up': True})
    call(nid, {'operation': 'stop'})
    wait(nid)
    pcap = get_run(nid) / 'network.pcap'
    checks.append({'case': 'isolated-network-link-and-pcap', 'ok': connection['network'] == 'isolated'
                   and pcap.exists() and pcap.stat().st_size >= 24, 'run_id': nid})
    # Make the external debugger fail; raw logs and RAM must still survive.
    import os
    with tempfile.TemporaryDirectory() as directory:
        fake = Path(directory) / 'gdb'
        fake.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo "test GDB 17.2"; else exit 1; fi\n')
        fake.chmod(0o755)
        previous = os.environ.get('OSENV_GDB')
        os.environ['OSENV_GDB'] = str(fake)
        try:
            failed = start('fault', existing_build=built)
            retained = wait(failed['run_id'])
        finally:
            if previous is None:
                del os.environ['OSENV_GDB']
            else:
                os.environ['OSENV_GDB'] = previous
        evidence = get_run(failed['run_id']) / 'capture-001'
        valid = (retained.get('verdict') == 'panic' and not load(evidence / 'capture.json')['complete']
                 and (evidence / 'memory.bin').stat().st_size == 32*1024*1024
                 and b'OSE1 PANIC' in (evidence / 'serial.log').read_bytes())
    checks.append({'case': 'capture-failure-retains-evidence', 'ok': valid, 'run_id': failed['run_id']})
    for mode in ['protected32', 'long64']:
        mode_build = build(mode)
        launched = start(timeout=30, manual=True, mode=mode, existing_build=mode_build)
        identity = launched['run_id']
        deadline = time.monotonic() + 8
        expected = ('OSE1 MODE ' + mode).encode()
        while time.monotonic() < deadline and expected not in (get_run(identity) / 'serial.log').read_bytes():
            time.sleep(0.05)
        errors = []
        try:
            if expected not in (get_run(identity) / 'serial.log').read_bytes():
                errors.append('Mode boot marker missing')
            registers = call(identity, {'operation': 'debug', 'action': 'registers', 'mode': mode})
            from .core import command, tool
            symbols = command([tool('llvm-nm'), '-n', get_run(identity) / 'boot.elf'])
            hold = next(line.split()[0] for line in symbols.splitlines() if line.endswith(' hold'))
            decoded = call(identity, {'operation': 'debug', 'action': 'disassemble',
                                       'address': '0x'+hold, 'length': 32})
            if not decoded.get('disassembly') or 'pause' not in decoded['disassembly']:
                errors.append('Actual mode instructions not decoded correctly')
            call(identity, {'operation': 'debug', 'action': 'breakpoint', 'address': '0x'+hold})
            status = call(identity, {'operation': 'status'})
            if 'breakpoint-hit' not in status.get('breakpoints', ''):
                errors.append('Mode breakpoint did not hit')
            capture = call(identity, {'operation': 'capture', 'mode': mode})
            if not capture['complete']:
                errors.append('Mode capture incomplete')
            call(identity, {'operation': 'stop'})
            wait(identity)
        except Exception as error:
            errors.append(str(error))
            try:
                call(identity, {'operation': 'stop'})
            except Exception:
                pass
        checks.append({'case': 'cpu-mode-'+mode, 'ok': not errors, 'run_id': identity, 'errors': errors})
    abandoned = start('hang', timeout=30, paused=True, existing_build=built)
    import signal
    os.kill(abandoned['owner_pid'], signal.SIGKILL)
    time.sleep(0.1)
    rescued = dispatch(argparse.Namespace(operation='recover', run_id=abandoned['run_id']))
    fresh = wait(rescued['run_id'])
    stale = load(get_run(abandoned['run_id']) / 'status.json')
    checks.append({'case': 'dead-controller-recovery', 'ok': fresh.get('verdict') == 'pass'
                   and stale.get('verdict') == 'owner_lost',
                   'run_ids': [abandoned['run_id'], rescued['run_id']]})
    # The generic path must work without a project fixture build or floppy disk.
    custom = start(timeout=30, manual=True, paused=True,
                   image=Path(built['directory']) / 'fixture.img',
                   symbols=Path(built['directory']) / 'boot.elf')
    identity = custom['run_id']
    call(identity, {'operation': 'debug', 'action': 'breakpoint', 'address': '_start'})
    at_boot = call(identity, {'operation': 'status'})
    call(identity, {'operation': 'debug', 'action': 'delete-breakpoints'})
    call(identity, {'operation': 'debug', 'action': 'resume'})
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and b'OSE1 READY' not in (get_run(identity)/'serial.log').read_bytes():
        time.sleep(0.05)
    call(identity, {'operation': 'serial', 'text': '1P\n'})
    exited = wait(identity)
    custom_manifest = load(get_run(identity)/'manifest.json')
    checks.append({'case': 'custom-IDE-image-symbols-and-serial', 'ok':
                   'breakpoint-hit' in at_boot.get('breakpoints', '')
                   and exited.get('verdict') == 'manual_exited' and exited.get('exit_code') == 33
                   and custom_manifest['input']['disk_interface'] == 'ide'
                   and b'OSE1 DONE' in (get_run(identity)/'serial.log').read_bytes(), 'run_id': identity})
    # Unknown guest commands must fail on the real serial execution path.
    rejected = start('pass', manual=True, image=str(Path(built['directory']) / 'fixture.img'), timeout=8)
    identity = rejected['run_id']
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and b'OSE1 READY' not in (get_run(identity)/'serial.log').read_bytes():
        time.sleep(0.05)
    call(identity, {'operation': 'serial', 'text': '1X\n'})
    completed = wait(identity)
    raw = (get_run(identity)/'serial.log').read_bytes()
    checks.append({'case': 'unknown-command-rejected', 'ok': completed.get('exit_code') == 35
                   and b'OSE1 ERROR unsupported-command' in raw and b'OSE1 DONE' not in raw,
                   'run_id': identity})
    result = {'ok': all(c['ok'] for c in checks), 'checks': checks,
              'build_id': built['build_id']}
    ROOT.joinpath('artifacts').mkdir(exist_ok=True)
    save(ROOT / 'artifacts/latest-test.json', result)
    return result
