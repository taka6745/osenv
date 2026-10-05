#!/usr/bin/env python3
"""Bounded host toolchain smoke check; not the OS controller or boot test."""
import json
import pathlib
import socket as sockets
import subprocess
import tempfile


def run(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True,
                            timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args[0]} exited {result.returncode}: {result.stderr.strip()}')
    return result.stdout.strip()


def main():
    versions = {}
    paths = {}
    for name, formula in [('clang', 'llvm'), ('ld.lld', 'lld'),
                          ('llvm-objcopy', 'llvm'), ('nasm', 'nasm'),
                          ('qemu-system-x86_64', 'qemu'), ('gdb', 'gdb')]:
        prefix = run(['brew', '--prefix', formula])
        path = pathlib.Path(prefix) / 'bin' / name
        if not path.is_file():
            raise RuntimeError(f'Missing tool: {path}')
        paths[name] = str(path)
        versions[name] = run([str(path), '--version']).splitlines()[0]
    with tempfile.TemporaryDirectory(prefix='oslab-tools-') as directory:
        root = pathlib.Path(directory)
        source = root / 'probe.c'
        source.write_text('void _start(void) { for (;;) __asm__("hlt"); }\n')
        host = root / 'host.c'
        host.write_text('int main(void) { return 0; }\n')
        run([paths['clang'], '-fsanitize=address,undefined', str(host),
             '-o', str(root / 'host')])
        run([str(root / 'host')])
        run([paths['clang'], '--target=x86_64-unknown-none-elf', '-ffreestanding',
             '-fno-stack-protector', '-mno-red-zone', '-c', str(source),
             '-o', str(root / 'probe.o')])
        run([paths['ld.lld'], '-m', 'elf_x86_64', '--image-base=0x100000',
             '-Ttext=0x100000', '-e', '_start',
             str(root / 'probe.o'), '-o', str(root / 'probe.elf')])
        run([paths['llvm-objcopy'], '-O', 'binary', str(root / 'probe.elf'),
             str(root / 'probe.bin')])
        asm = root / 'probe.asm'
        asm.write_text('bits 16\norg 0x7c00\nhlt\ntimes 510-($-$$) db 0\ndw 0xaa55\n')
        run([paths['nasm'], '-f', 'bin', str(asm), '-o', str(root / 'boot.bin')])
        assert (root / 'boot.bin').stat().st_size == 512
        socket = root / 'gdb.sock'
        qmp = root / 'qmp.sock'
        command = [paths['qemu-system-x86_64'], '-machine', 'pc', '-accel', 'tcg',
                   '-smp', '1', '-m', '32M', '-display', 'none', '-nic', 'none',
                   '-serial', 'none', '-monitor', 'none', '-S',
                   '-gdb', f'unix:{socket},server=on,wait=off',
                   '-qmp', f'unix:{qmp},server=on,wait=off']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            import time
            deadline = time.monotonic() + 10
            while not socket.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('QEMU GDB socket did not start')
                time.sleep(0.05)
            with sockets.socket(sockets.AF_UNIX, sockets.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(str(qmp))
                with client.makefile('rwb') as stream:
                    assert 'QMP' in json.loads(stream.readline())
                    for operation in ['qmp_capabilities', 'query-status']:
                        stream.write(json.dumps({'execute': operation}).encode() + b'\n')
                        stream.flush()
                        response = json.loads(stream.readline())
                        while 'event' in response:
                            response = json.loads(stream.readline())
                        assert 'return' in response, response
            output = run([paths['gdb'], '--quiet', '--nx', '--interpreter=mi2'],
                         input=f'-target-select remote {socket}\n-data-list-register-values x\n-gdb-exit\n')
            if '^connected' not in output or 'register-values=' not in output or '^error' in output:
                raise RuntimeError(f'GDB/MI probe failed: {output}')
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
    print(json.dumps({'ok': True, 'versions': versions,
                      'checks': ['host ASan/UBSan', 'x86_64 ELF compile/link/objcopy',
                                 'NASM BIOS sector', 'QEMU TCG start/stop',
                                 'QMP handshake/status', 'GDB/MI remote registers']}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'ok': False, 'error': str(error)}))
        raise SystemExit(1)
