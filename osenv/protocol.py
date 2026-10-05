"""Strict OSE1 fixture result parser: PASS requires host checks and exit state."""
import re


def verdict(raw, code, events, timed_out=False):
    lines = raw.decode('ascii', errors='replace').splitlines()
    lines = [line for line in lines if not line.startswith('OSE1 LOG ')]
    if any(e.get('event') == 'RESET' or e.get('data', {}).get('reason') == 'guest-reset' for e in events):
        return {'verdict': 'reset', 'ok': False, 'reason': 'unexpected QMP reset'}
    panic = [x for x in lines if x.startswith('OSE1 PANIC ')]
    if panic:
        match = re.fullmatch(r'OSE1 PANIC vector=(\d+)', panic[0])
        return {'verdict': 'panic', 'ok': False,
                'panic': {'version': 1, 'vector': int(match[1]) if match else None}}
    if timed_out:
        return {'verdict': 'timeout', 'ok': False, 'reason': 'external deadline expired'}
    expected = ['OSE1 BOOT real16', 'OSE1 READY', 'OSE1 RESULT id=1 value=42', 'OSE1 DONE']
    if lines != expected:
        return {'verdict': 'assertion_failed', 'ok': False, 'reason': 'missing, extra or incorrect protocol records'}
    if code != 33:
        return {'verdict': 'exit_failed', 'ok': False, 'reason': f'expected debug-exit 33, got {code}'}
    return {'verdict': 'pass', 'ok': True}


def panic_record_ready(raw):
    """Act only on a complete protocol record, never a UART prefix."""
    return any(line.startswith((b'OSE1 PANIC ', b'OSL1 PANIC '))
               for line in raw.split(b'\n')[:-1])
