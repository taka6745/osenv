"""Bounded JSON QMP and local owner RPC transports."""
import json
import socket
import time


class QMP:
    def __init__(self, path, events):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(3)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile('rwb')
        self.events = events
        self.sequence = 0
        if 'QMP' not in self.read():
            raise RuntimeError('Invalid QMP greeting')
        self.call('qmp_capabilities')

    def read(self):
        line = self.stream.readline(1048577)
        if not line or len(line) > 1048576:
            raise RuntimeError('QMP closed or record too large')
        return json.loads(line)

    def call(self, operation, arguments=None):
        self.sequence += 1
        token = self.sequence
        self.stream.write(json.dumps({'execute': operation, 'arguments': arguments or {},
                                      'id': token}).encode() + b'\n')
        self.stream.flush()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            value = self.read()
            if 'event' in value:
                self.events.append(value)
            elif value.get('id') == token:
                if 'error' in value:
                    raise RuntimeError(str(value['error']))
                return value.get('return')
        raise TimeoutError('QMP request deadline')

    def close(self):
        try:
            self.stream.close()
        except OSError:
            pass
        self.socket.close()


def rpc(path, request, timeout=20):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(str(path))
        client.sendall(json.dumps(request).encode() + b'\n')
        with client.makefile('rb') as stream:
            line = stream.readline(1048577)
            if not line or len(line) > 1048576:
                raise RuntimeError('Owner closed or reply too large')
            response = json.loads(line)
    if not response.get('ok'):
        raise RuntimeError(response.get('error') or 'Owner request failed')
    return response
