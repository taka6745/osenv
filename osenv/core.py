"""Bounded host helpers and immutable build inputs."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(os.environ.get('OSENV_ROOT', Path.cwd())).resolve()
MACHINE = 'pc-i440fx-9.2'
TOOLS = {'nasm': '3.02', 'ld.lld': '23.1.2', 'llvm-objcopy': '23.1.2',
         'qemu-system-x86_64': '11.1.2', 'qemu-img': '11.1.2', 'gdb': '17.2'}


def command(args, timeout=30, **kwargs):
    result = subprocess.run([str(a) for a in args], capture_output=True,
                            text=True, timeout=timeout, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args[0]} exited {result.returncode}: {result.stderr[-2000:]}')
    return result.stdout


def tool(name):
    env = os.environ.get('OSENV_' + name.upper().replace('-', '_').replace('.', '_'))
    if env:
        return env
    formula = ('llvm' if name.startswith('llvm-') else 'qemu' if name.startswith('qemu-')
               else {'ld.lld': 'lld'}.get(name, name))
    homebrew = Path('/opt/homebrew/opt') / formula / 'bin' / name
    if homebrew.is_file():
        return str(homebrew)
    path = shutil.which(name)
    if path:
        return path
    raise RuntimeError(f'Missing {name}; run osenv setup')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(data, indent=2) + '\n')
    os.replace(temporary, path)


def load(path):
    return json.loads(Path(path).read_text())


def doctor(strict=True):
    tools = {}
    for name, expected in TOOLS.items():
        path = tool(name)
        version = command([path, '--version']).strip()
        if strict and expected not in version:
            raise RuntimeError(f'{name}: expected {expected}, got {version}')
        tools[name] = {'path': path, 'version': version, 'expected': expected}
    machines = command([tool('qemu-system-x86_64'), '-machine', 'help'])
    if MACHINE not in machines:
        raise RuntimeError(f'QEMU lacks pinned machine {MACHINE}')
    return {'ok': True, 'tools': tools, 'python': sys.version.split()[0],
            'machine': MACHINE, 'record_replay': 'disabled: not validated'}


def validate_image(path, fixture=True):
    data = Path(path).read_bytes()
    if (fixture and len(data) != 1474560) or not 512 <= len(data) <= 512*1024*1024 or len(data) % 512 or data[510:512] != b'\x55\xaa':
        raise ValueError('Invalid raw BIOS disk size or boot signature')


def build(mode='real16'):
    if mode not in ['real16', 'protected32', 'long64']:
        raise ValueError('Unknown fixture mode')
    versions = doctor()
    destination = ROOT / 'build'
    destination.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination) as directory:
        work = Path(directory)
        assembly = 'fixture/boot.asm' if mode == 'real16' else 'fixture/modes.asm'
        linker = 'fixture/link.ld' if mode == 'real16' else 'fixture/modes.ld'
        options = ['-DTARGET32'] if mode == 'protected32' else []
        command([tool('nasm'), '-f', 'elf32' if mode == 'real16' else 'elf64', '-g', '-F', 'dwarf',
                 *options, ROOT / assembly, '-o', work / 'boot.o'])
        command([tool('ld.lld'), '-m', 'elf_i386' if mode == 'real16' else 'elf_x86_64', '-T', ROOT / linker,
                 work / 'boot.o', '-o', work / 'boot.elf'])
        command([tool('llvm-objcopy'), '-O', 'binary', work / 'boot.elf', work / 'boot.bin'])
        sector = (work / 'boot.bin').read_bytes()
        if len(sector) != 512 or sector[-2:] != b'\x55\xaa':
            raise RuntimeError('Invalid generated boot sector')
        (work / 'fixture.img').write_bytes(sector + bytes(1474560 - 512))
        files = ['boot.elf', 'boot.bin', 'fixture.img']
        manifest = {'schema': 1, 'fixture': True, 'tools': versions,
                    'sources': {p: digest(ROOT / p) for p in [assembly, linker]},
                    'files': {p: digest(work / p) for p in files},
                    'symbols': {'mode': mode, 'elf': 'boot.elf', 'load_address': 0x7c00}}
        identity = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()[:16]
        target = destination / identity
        if not target.exists():
            target.mkdir()
            for name in files:
                shutil.copyfile(work / name, target / name)
            save(target / 'manifest.json', manifest)
        return {'ok': True, 'build_id': identity, 'directory': str(target), **manifest}


def get_run(identity):
    if not identity or any(c not in '0123456789abcdef-' for c in identity):
        raise ValueError('Invalid run ID')
    path = ROOT / 'runs' / identity
    if not path.is_dir():
        raise ValueError('Unknown run ID')
    return path


def read_cursor(path, cursor=0, limit=65536):
    if cursor < 0 or limit < 1 or limit > 1048576:
        raise ValueError('Invalid cursor/limit')
    with Path(path).open('rb') as stream:
        stream.seek(cursor)
        data = stream.read(limit)
        return {'cursor': stream.tell(), 'text': data.decode('utf-8', errors='replace')}
