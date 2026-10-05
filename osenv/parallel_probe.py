"""Real server contention and isolated-replica capacity, never guest SMP claims."""
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import http.client
import json
from pathlib import Path
import socket
import statistics
import threading
import time
from .core import ROOT, get_run
from .worker import start
from .__main__ import call
from .raw_size import account
from .web_stress import dhcp_ack_seen


def probe(build, output, replicas=1, clients=1, requests=512):
    if any(type(x) is not int for x in (replicas,clients,requests)) or not (1 <= replicas <= 4 and 1 <= clients <= 4 and 1 <= requests <= 512):
        raise ValueError('Require replicas/clients1..4, requests1..512 per client')
    build, output = Path(build).resolve(), Path(output).resolve()
    expected = account(build)
    output.mkdir(parents=True, exist_ok=False)
    lock_path = ROOT/'local/experiment.lock';lock_path.parent.mkdir(exist_ok=True)
    report = {'ok':False, 'image_sha256':expected['image_sha256'], 'replicas':replicas,
              'clients_per_replica':clients,'requests_per_client':requests,
              'scope':'Parallel host clients against separate one-CPU QEMU processes; no AP startup, guest SMP, CPU pinning or physical network claim'}
    runs = []; lock = lock_path.open('a+')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ports = []
        for _ in range(replicas):
            rid = start(timeout=240,manual=True,image=build/'oslab.img',symbols=build/'kernel.elf',
                        mode='long64',memory=64,network='isolated',timing='realtime',
                        nic_model='e1000e',nic_rom=False,minimal_devices=True)['run_id']
            runs.append(rid)
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
            if not call(rid,{'operation':'network-forward','host_port':port})['ok']:
                raise RuntimeError('Could not establish owned forwarding')
            deadline = time.monotonic()+15
            while not dhcp_ack_seen(get_run(rid)/'network.pcap'):
                if time.monotonic() >= deadline: raise TimeoutError('No real DHCP ACK')
                time.sleep(.002)
            ports.append(port)

        def fetch(port, timeout=.3):
            client = http.client.HTTPConnection('127.0.0.1',port,timeout=timeout)
            try:
                client.request('GET','/',headers={'Host':'oslab','Connection':'close'})
                response = client.getresponse();body = response.read(65537)
                if (response.status != 200 or int(response.getheader('Content-Length','-1')) != len(body)
                        or len(body) != expected['literal_page']['bytes']
                        or hashlib.sha256(body).hexdigest() != expected['literal_page']['sha256']):
                    raise ValueError('Actual response bytes/framing differ')
            finally:
                client.close()

        for port in ports: fetch(port,5)
        begun = []
        barrier = threading.Barrier(replicas*clients+1, action=lambda:begun.append(time.monotonic()))
        def load(replica, worker):
            samples = [];errors = []
            barrier.wait(timeout=10)
            for index in range(requests):
                begun = time.monotonic()
                try: fetch(ports[replica])
                except Exception as error:
                    errors.append({'request':index,'error':str(error) or type(error).__name__,
                                   'invalid_response':isinstance(error,ValueError)})
                else: samples.append(time.monotonic()-begun)
            return {'replica':replica,'worker':worker,'completed':len(samples),'errors':errors,'samples_seconds':samples}

        with ThreadPoolExecutor(max_workers=replicas*clients) as pool:
            futures = [pool.submit(load,r,c) for r in range(replicas) for c in range(clients)]
            barrier.wait(timeout=10)
            rows = [f.result(timeout=180) for f in futures]
            elapsed = time.monotonic()-begun[0]
        recovery = []
        for rid,port in zip(runs,ports):
            deadline = time.monotonic()+12
            while True:
                try: fetch(port,.5);break
                except Exception:
                    if time.monotonic()>=deadline:raise RuntimeError('Server did not recover from valid contention')
                    time.sleep(.01)
            events = [json.loads(line) for line in (get_run(rid)/'events.jsonl').read_text().splitlines()]
            if any(e.get('event') in ('RESET','SHUTDOWN') for e in events):
                raise RuntimeError('Unexpected reset/shutdown during capacity trial')
            recovery.append({'run_id':rid,'verified_response_after_load':True})
        completed = sum(row['completed'] for row in rows)
        samples = sorted(x for row in rows for x in row['samples_seconds'])
        report.update(ok=not any(e['invalid_response'] for row in rows for e in row['errors']),
                      all_requests_completed=completed==replicas*clients*requests,
                      completed_requests=completed,failed_requests=replicas*clients*requests-completed,
                      wall_load_seconds=elapsed,verified_requests_per_second=completed/elapsed,
                      latency_median_seconds=statistics.median(samples) if samples else None,
                      latency_p99_seconds=samples[min(len(samples)-1,int(.99*len(samples)))] if samples else None,
                      workers=rows,recovery=recovery)
    except Exception as error:
        report['error'] = str(error) or type(error).__name__
        report['failure_captures'] = [call(rid,{'operation':'capture','mode':'long64'}) for rid in runs]
    finally:
        report['runs'] = runs
        report['cleanup'] = [call(rid,{'operation':'stop'}) for rid in runs]
        if not all(r.get('ok') for r in report['cleanup']):report['ok']=False
        (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
    return report
