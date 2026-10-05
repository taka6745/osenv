"""Serialized, bounded real-OS candidate trials with retained negative results."""
import fcntl
import hashlib
import json
import math
from pathlib import Path
import random
import re
import shutil
import statistics
import subprocess
import sys
import time
from .core import ROOT
from .raw_size import account


def load_plan(path):
    plan = json.loads(Path(path).read_text())
    if set(plan) != {'hypothesis', 'baseline', 'candidates', 'repeat', 'requests', 'seed'}:
        raise ValueError('Plan requires hypothesis, baseline, candidates, repeat, requests, seed')
    if not isinstance(plan['hypothesis'], str) or not plan['hypothesis'].strip():
        raise ValueError('State a falsifiable hypothesis')
    for key, low, high in [('repeat', 3, 9), ('requests', 100, 30000), ('seed', 0, 0xffffffff)]:
        if type(plan[key]) is not int or not low <= plan[key] <= high:
            raise ValueError(f'{key} must be {low}..{high}')
    if not isinstance(plan['candidates'], list) or not 1 <= len(plan['candidates']) <= 8:
        raise ValueError('Require 1..8 candidate builds')
    names = set()
    for variant in [plan['baseline']] + plan['candidates']:
        if not isinstance(variant, dict) or set(variant) not in ({'name', 'build'}, {'name', 'build', 'boot_kernel'}, {'name', 'build', 'boot_kernel', 'expected_bar'}):
            raise ValueError('Variant requires name/build and optional boot_kernel/expected_bar')
        if 'expected_bar' in variant:
            bar=variant['expected_bar']
            if type(bar) is not int or not 0xc0000000 <= bar < 0xe0000000 or bar & 0x1ffff:
                raise ValueError('Expected BAR must be aligned128KiB inside the validated aperture')
        name = variant['name']
        if not isinstance(name, str) or not re.fullmatch('[a-z][a-z0-9-]{0,47}', name) or name in names:
            raise ValueError('Unique bounded variant names required')
        names.add(name)
        variant['build'] = str(Path(variant['build']).resolve())
        checked = account(variant['build'])
        variant['image_sha256'] = checked['image_sha256']
        variant['image_bytes'] = checked['image_bytes']
        variant['response_body'] = checked['literal_page']
        variant['symbols_sha256'] = hashlib.sha256((Path(variant['build'])/'kernel.elf').read_bytes()).hexdigest()
        if variant.get('boot_kernel'):
            from .worker import validate_pvh
            kernel, _ = validate_pvh(variant['boot_kernel'], Path(variant['build'])/'oslab.img', Path(variant['build'])/'kernel.elf')
            variant['boot_kernel'] = str(kernel)
    reference = plan['baseline']['response_body']
    for variant in plan['candidates']:
        if any(variant['response_body'][key] != reference[key] for key in ('bytes','sha256')):
            raise ValueError('Candidate changes the website payload; not a matched experiment')
    return plan


def paired_ratio(candidate, baseline, seed):
    if len(candidate) != len(baseline) or len(candidate) < 3:
        raise ValueError('At least three matched observations required')
    if any(type(x) not in (float, int) or not math.isfinite(x) or x <= 0 for x in candidate+baseline):
        raise ValueError('Observations must be positive finite numbers')
    logs = [math.log(a/b) for a,b in zip(candidate, baseline)]
    rng = random.Random(seed)
    draws = sorted(math.exp(statistics.mean(rng.choices(logs, k=len(logs)))) for _ in range(4096))
    return {'geometric_ratio':math.exp(statistics.mean(logs)),
            'paired_bootstrap_95_interval':[draws[102], draws[3993]],
            'pairs':len(logs), 'seed':seed,
            'scope':'Exploratory paired bootstrap; few trials and host noise limit generalization'}


def compare(directory, repeat, seed):
    rows = {name:[json.loads((directory/f'{name}-{i}.json').read_text()) for i in range(repeat)]
            for name in ('candidate', 'baseline')}
    if not all(r.get('ok') for values in rows.values() for r in values):
        raise ValueError('Failed run cannot contribute to a performance claim')
    selectors = {'throughput':lambda r:r['requests']/r['load_seconds'],
                 'client_median':lambda r:r['latency_seconds']['median'],
                 'client_p99':lambda r:r['latency_seconds']['p99'],
                 'cpu_release_to_reply':lambda r:r['cpu_release_to_returned_request']['cpu_release_to_returned_request_seconds']}
    result = {key:paired_ratio([fn(r) for r in rows['candidate']], [fn(r) for r in rows['baseline']], seed)
              for key,fn in selectors.items()}
    lower, upper = result['throughput']['paired_bootstrap_95_interval']
    result['throughput_evidence'] = 'improved' if lower > 1 else 'regressed' if upper < 1 else 'inconclusive'
    result['scope'] = 'Local evidence only; acceptance also requires safety, other metrics and exact-image homelab verification'
    return result


def run(plan_path, output):
    if not __debug__:
        raise RuntimeError('Acceptance requires assertions enabled')
    plan = load_plan(plan_path)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output/'plan.json').write_text(json.dumps(plan, indent=2)+'\n')
    sources = {path.name:hashlib.sha256(path.read_bytes()).hexdigest()
               for path in Path(__file__).parent.glob('*.py')}
    snapshot = output/'harness-source';snapshot.mkdir()
    for name in sources:shutil.copyfile(Path(__file__).parent/name,snapshot/name)
    (output/'harness-hashes.json').write_text(json.dumps(sources,indent=2)+'\n')
    lock_path = ROOT/'local/experiment.lock'
    lock_path.parent.mkdir(exist_ok=True)
    report = {'ok':False, 'hypothesis':plan['hypothesis'], 'results':[],
              'scope':'Authored real OS; one-CPU TCG; serial trials, no physical cache/cycle claim'}
    with lock_path.open('a+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another experiment owns the measurement lock')
        lock.seek(0);lock.truncate();lock.write(str(output));lock.flush()
        try:
            from .raw_test import test as gate
            from .raw_packed_test import test as decoder
            for variant in [plan['baseline']] + plan['candidates']:
                name, build = variant['name'], Path(variant['build'])
                actual = account(build)
                if actual['image_sha256'] != variant['image_sha256']:
                    raise ValueError('Candidate changed after plan validation')
                verdict = gate(build, output/(name+'-acceptance'))
                if not verdict['ok']:
                    raise RuntimeError(name+' failed actual OS acceptance')
                if actual.get('packing'):
                    if not decoder(build, output/(name+'-decoder'))['ok']:
                        raise RuntimeError(name+' failed actual decoder acceptance')
                if variant.get('boot_kernel'):
                    from .raw_pvh_test import test as direct_gate
                    if not direct_gate(build, output/(name+'-direct-entry'), expected_bar=variant.get('expected_bar',0xc0000000))['ok']:
                        raise RuntimeError(name+' failed actual direct entry acceptance')
            base = plan['baseline']
            for variant in plan['candidates']:
                for item in (base,variant):
                    checked=account(item['build'])
                    if (checked['image_sha256'] != item['image_sha256'] or
                        hashlib.sha256((Path(item['build'])/'kernel.elf').read_bytes()).hexdigest() != item['symbols_sha256']):
                        raise ValueError('Experiment artifacts changed before benchmarking')
                target = output/(variant['name']+'-paired')
                args = [sys.executable, '-m', 'osenv.perf_bench', '--image', str(Path(variant['build'])/'oslab.img'),
                        '--symbols', str(Path(variant['build'])/'kernel.elf'), '--compare-image', str(Path(base['build'])/'oslab.img'),
                        '--compare-symbols', str(Path(base['build'])/'kernel.elf'), '--output', str(target),
                        '--repeat', str(plan['repeat']), '--requests', str(plan['requests']), '--seed', str(plan['seed']),
                        '--nic-model', 'e1000e', '--no-nic-rom', '--minimal-devices']
                for key, option in [('boot_kernel','--boot-kernel')]:
                    if variant.get(key): args += [option, variant[key]]
                    if base.get(key): args += ['--compare-boot-kernel', base[key]]
                with (output/(variant['name']+'-benchmark.log')).open('w') as log:
                    measured = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
                if measured.returncode:
                    raise RuntimeError(variant['name']+' failed real benchmark; retained log')
                summary=json.loads((target/'summary.json').read_text())
                for name,item in [('candidate',variant),('baseline',base)]:
                    if summary[name]['image_sha256'] != item['image_sha256']:
                        raise ValueError('Measured image differs from the frozen plan')
                comparison = compare(target, plan['repeat'], plan['seed'])
                report['results'].append({'candidate':variant, 'comparison':comparison})
                (output/'progress.json').write_text(json.dumps(report, indent=2)+'\n')
            report['ok'] = True
        except Exception as error:
            report['error'] = str(error) or type(error).__name__
        finally:
            current = {path.name:hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in Path(__file__).parent.glob('*.py')}
            if current != sources:
                report.update(ok=False,error='Harness source changed during experiment; measurements retained, not accepted')
            (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
            fcntl.flock(lock, fcntl.LOCK_UN)
    return report
