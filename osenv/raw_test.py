"""Integrated acceptance of the complete hand-encoded OS, never fixture substitution."""
import argparse
import hashlib
import json
import time
import traceback
from pathlib import Path
from .worker import start
from .core import get_run
from .__main__ import call


def primitive_gate(build, output):
    from .raw_primitives_test import test as exercise
    build=Path(build).resolve()
    rid=start(timeout=60,manual=True,image=str(build/'oslab.img'),symbols=str(build/'kernel.elf'),mode='long64',memory=64,network='isolated',nic_model='e1000e',minimal_devices=True,nic_rom=False)['run_id']
    report={'ok':False,'run_id':rid}
    try:
        time.sleep(.3)
        assert call(rid,{'operation':'debug','action':'pause'})['ok']
        manifest=json.loads((get_run(rid)/'manifest.json').read_text())
        report.update(exercise(str(Path(manifest['socket_directory'])/'gdb'),str(build/'kernel.elf'),str(build/'manifest.json'),str(get_run(rid)/'raw-primitives.json')))
    except Exception as error:
        report['error']=str(error) or type(error).__name__
        (get_run(rid)/'raw-primitives-failure.txt').write_text(traceback.format_exc())
    finally:
        report['capture']=call(rid,{'operation':'capture','mode':'long64'})
        report['stop']=call(rid,{'operation':'stop'})
        report['ok']=report['ok'] and report['capture']['complete'] and report['stop']['ok']
        Path(output).write_text(json.dumps(report,indent=2))
    return report


def test(build, output):
    if not __debug__:
        raise RuntimeError('Acceptance checks require Python assertions enabled')
    from .raw_boot_test import test as boot
    from .raw_clock_test import test as clock
    from .raw_network_test import test as network
    from .raw_irq_test import test as irq
    from .raw_driver_test import test as driver
    from .web_test import web_test
    build,output=Path(build).resolve(),Path(output).resolve()
    output.mkdir(parents=True,exist_ok=False)
    expected=json.loads((build/'manifest.json').read_text())['image_sha256']
    assert hashlib.sha256((build/'oslab.img').read_bytes()).hexdigest()==expected
    results={}
    jobs=[
        ('boot',lambda:boot(build,output/'boot')),
        ('clock-primitives',lambda:clock(build,output/'clock-primitives')),
        ('driver',lambda:driver(build,output/'driver')),
        ('network',lambda:network(build,output/'network')),
        ('irq',lambda:irq(build)),
        ('wire-e1000e',lambda:web_test(str(build/'oslab.img'),str(build/'kernel.elf'),production=True,nic_model='e1000e',minimal_devices=True)),
        ('wire-e1000',lambda:web_test(str(build/'oslab.img'),str(build/'kernel.elf'),production=True,nic_model='e1000',minimal_devices=True)),
    ]
    symbols=json.loads((build/'manifest.json').read_text())['symbols']
    if 'nic_tx_buffer' in symbols:
        from .raw_tx_test import test as tx
        jobs.insert(3,('tx-extended',lambda:tx(build,output/'tx-extended.json',
                                             checksum_cache='net_tcp_checksum_cached' in symbols)))
    if 'net_tcp_queue_syn' in symbols:
        from .raw_queue_test import test as queue
        jobs.insert(4,('queued-handshake',lambda:queue(build,output/'queued-handshake.json')))
    if 'nic_send_static' in symbols:
        from .raw_sg_test import test as sg
        jobs.insert(4,('static-scatter-gather',lambda:sg(build,output/'static-scatter-gather.json')))
    for name, function in jobs:
        try:
            result=function()
        except Exception as error:
            result={'ok':False,'error':str(error) or type(error).__name__,'traceback':traceback.format_exc()}
        results[name]=result
        (output/(name+'.json')).write_text(json.dumps(result,indent=2))
        (output/'progress.json').write_text(json.dumps(results,indent=2))
    report={'ok':all(r.get('ok',False) for r in results.values()),'image_sha256':expected,'gates':results,'scope':'actual BIOS OS image and CPU/device/network outcomes; source audit and performance remain separate'}
    (output/'report.json').write_text(json.dumps(report,indent=2))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    result=test(args.build,args.output)
    print(json.dumps(result,indent=2))
    raise SystemExit(0 if result['ok'] else 1)
