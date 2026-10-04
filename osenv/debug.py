"""GDB/MI snapshots and CPU controls, including 16-bit disassembly."""
import json
from pathlib import Path
import re
import subprocess
from .core import tool


def operations(action, address=None, length=64, value=None):
    if address is not None:
        address = int(str(address), 0)
        if address < 0 or address >= 2**64:
            raise ValueError('Address out of range')
    if not 1 <= length <= 65536:
        raise ValueError('Length must be 1..65536')
    if action == 'evaluate':
        if not value or len(value) > 1024 or '\n' in value:
            raise ValueError('Invalid expression')
        return ['-data-evaluate-expression ' + json.dumps(value)]
    if action == 'write-register':
        if not value or not re.fullmatch(r'\$[a-zA-Z][a-zA-Z0-9]*=0x[0-9a-fA-F]{1,16}', value):
            raise ValueError('Use --value "$rax=0x1234" (quoted to protect shell variables)')
        return ['-data-evaluate-expression ' + json.dumps(value)]
    if action == 'backtrace':
        return ['-stack-list-frames 0 63']
    if action == 'symbols':
        return ['-symbol-info-functions --name ' + json.dumps(value or '.*')]
    if action == 'breakpoints':
        return ['-break-list']
    if action == 'delete-breakpoints':
        return ['-break-delete']
    if action == 'watchpoint':
        return [f'-break-watch -a "*(unsigned int*){address:#x}"']
    if action == 'control-registers':
        return ['-data-evaluate-expression ' + register for register in ['$cr0', '$cr2', '$cr3', '$cr4', '$efer']]
    if action == 'registers':
        return ['-data-list-register-names', '-data-list-register-values x']
    if action == 'step':
        return ['-exec-step-instruction', '-data-list-register-values x']
    if action == 'memory':
        return [f'-data-read-memory-bytes {address:#x} {length}']
    if action == 'write-memory':
        if not value or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,65536}', value):
            raise ValueError('Value must be bounded hexadecimal bytes')
        return [f'-data-write-memory-bytes {address:#x} {value}']
    if action == 'disassemble':
        return [f'-data-read-memory-bytes {address:#x} {length}']
    raise ValueError('Unknown debug action')


class Debugger:
    """One persistent GDB/MI connection keeps the CPU paused and breakpoints alive."""
    def __init__(self, path, elf, address=None):
        import selectors
        self.process = subprocess.Popen([tool('gdb'), '--quiet', '--nx', '--interpreter=mi2'],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, bufsize=0)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.transcript = b''
        self.sequence = 0
        if elf and Path(elf).exists():
            self.send(f'-file-exec-and-symbols {json.dumps(str(elf))}')
        self.send('-gdb-set architecture i386:x86-64')
        self.send(f'-target-select remote {path}')
        if address is not None:
            self.send(f'-break-insert *{int(str(address), 0):#x}')
            self.send('-exec-continue')

    def send(self, line):
        self.sequence += 1
        self.process.stdin.write(f'{self.sequence}{line}\n'.encode())
        self.process.stdin.flush()
        return self.sequence

    def run(self, commands, mode='real16'):
        import time
        begin = len(self.transcript)
        for operation in commands:
            command_begin = len(self.transcript)
            token = self.send(operation)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                self.collect(0.05)
                current = self.transcript[command_begin:]
                completed = re.search(rb'(?:^|\n)' + str(token).encode() + rb'\^(done|error|running)', current)
                if completed and (completed[1] != b'running' or b'*stopped' in current):
                    break
            else:
                raise TimeoutError('Persistent GDB command timed out')
        text = self.transcript[begin:].decode(errors='replace')
        names_match = re.search(r'register-names=(\[[^\n]*\])', text)
        values = dict(re.findall(r'number="(\d+)",value="([^"]+)"', text))
        registers = values
        if names_match:
            names = json.loads(names_match[1])
            registers = {names[int(index)]: value for index, value in values.items()
                         if int(index) < len(names) and names[int(index)]}
        memory = re.findall(r'contents="([0-9a-f]+)"', text)
        decoded = None
        if memory:
            import tempfile
            from .core import command
            with tempfile.TemporaryDirectory() as directory:
                binary = Path(directory) / 'memory.bin'
                binary.write_bytes(bytes.fromhex(memory[0]))
                address = re.search(r'begin="(0x[0-9a-f]+)"', text)
                decoded = command([str(Path(tool('nasm')).parent / 'ndisasm'),
                                   '-b', {'real16':'16','protected32':'32','long64':'64'}[mode],
                                   '-o', address[1] if address else '0', binary])
        return {'ok': '^error' not in text, 'stdout': text, 'commands': commands,
                'error': text if '^error' in text else None,
                'registers': registers, 'disassembly': decoded, 'memory_hex': memory,
                'values': [json.loads('"' + value + '"') for value in
                           re.findall(r'\^done,value="((?:[^"\\]|\\.)*)"', text)]}

    def collect(self, timeout=0.1):
        import os
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready = self.selector.select(max(0, deadline-time.monotonic()))
            if not ready:
                break
            data = os.read(self.process.stdout.fileno(), 65536)
            if not data:
                break
            self.transcript += data
        return self.transcript[-65536:].decode(errors='replace')

    def close(self):
        self.send('-target-detach')
        self.send('-gdb-exit')
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
        self.collect()
        self.selector.close()
        self.process.stdin.close()
        self.process.stdout.close()
