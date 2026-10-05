"""Real raw-disk rejection, CPU fault, hang and reset recovery checks."""
import argparse
import hashlib
import json
import time
import traceback
from pathlib import Path
from .worker import start
from .core import get_run
from .__main__ import call, dispatch, parser as harness_parser


def test(build, output):
    if not __debug__:
        raise RuntimeError('Assertions required for raw acceptance')
    build, output = Path(build).resolve(), Path(output).resolve()
    output.mkdir(parents=True,exist_ok=False)
    manifest=json.loads((build/'manifest.json').read_text())
    source=(build/'oslab.img').read_bytes()
    cases=[]

    def run_case(name, image, expected, network='isolated', mutate=None, reset=False):
        disk=output/(name+'.img'); disk.write_bytes(image)
        result={'case':name,'image_sha256':hashlib.sha256(image).hexdigest(),'ok':False}
        rid=start(timeout=15,paused=True,manual=True,image=str(disk),symbols=str(build/'kernel.elf'),mode='long64',memory=64,network=network,nic_model='e1000e',minimal_devices=True,nic_rom=False)['run_id']
        result['run_id']=rid
        def debug(action,**kwargs):
            response=call(rid,{'operation':'debug','action':action,**kwargs})
            assert response['ok'],response
            return response
        try:
            if mutate:
                reached=debug('breakpoint',address=hex(manifest['symbols']['raw_loop']))
                assert 'breakpoint-hit' in reached['mi'],reached
                debug('delete-breakpoints')
                address=manifest['symbols']['net_poll']
                debug('write-memory',address=hex(address),value=mutate.hex())
                result['isolated_mutation']={'address':address,'bytes':mutate.hex()}
                if name=='hang-reset':
                    debug('resume');time.sleep(.1)
                    snapshots=[]
                    for _ in range(2):
                        value=debug('evaluate',value='$rip')
                        snapshots.append(int(value['values'][0].split()[0],0))
                        debug('resume');time.sleep(.1)
                    assert snapshots==[address,address],snapshots
                    result['observed_hang_rip']=snapshots
                    # Reset executes the original disk, removing the RAM-only defect.
                    old_rid=rid
                    restored=dispatch(harness_parser().parse_args(['recover',rid]))
                    assert 'run_id' in restored,restored
                    rid=restored['run_id']
                    result['recovered_run_id']=rid
                    result['failed_run_id']=old_rid
                    debug('pause')
                    reached=debug('breakpoint',address=hex(manifest['symbols']['raw_loop']))
                else:
                    reached=debug('breakpoint',address=hex(expected))
            else:
                reached=debug('breakpoint',address=hex(expected))
            assert 'breakpoint-hit' in reached['mi'],reached
            actual=int(debug('evaluate',value='$rip')['values'][0].split()[0],0)
            assert actual==expected,(actual,expected)
            result['observed_rip']=actual
            if reset:
                result['original_opcode_restored']=debug('memory',address=hex(manifest['symbols']['net_poll']),length=2)['memory_hex'][0]
                assert result['original_opcode_restored']!='ebfe'
            result['ok']=True
        except Exception as error:
            result['error']=str(error) or type(error).__name__
            (get_run(rid)/'raw-boot-failure.txt').write_text(traceback.format_exc())
        finally:
            result['capture']=call(rid,{'operation':'capture','mode':'long64'})
            result['stop']=call(rid,{'operation':'stop'})
            (get_run(rid)/'raw-boot-verdict.json').write_text(json.dumps(result,indent=2))
            cases.append(result)

    corrupt=bytearray(source);corrupt[512]^=1
    run_case('kernel-integrity',bytes(corrupt),manifest['boot_symbols']['boot_fail32'])
    run_case('truncated-disk',source[:512],manifest['boot_symbols']['boot_fail'])
    run_case('absent-nic',source,manifest['symbols']['raw_fault'],network='none')
    run_case('cpu-invalid-opcode',source,manifest['symbols']['raw_fault'],mutate=b'\x0f\x0b')
    run_case('hang-reset',source,manifest['symbols']['raw_loop'],mutate=b'\xeb\xfe',reset=True)
    report={'ok':all(c['ok'] and c['capture']['ok'] and c['stop']['ok'] for c in cases),'recovery_mode':'preserved failure then cold restart of exact disk; pinned no-reboot policy retained','source_image_sha256':hashlib.sha256(source).hexdigest(),'cases':cases}
    (output/'report.json').write_text(json.dumps(report,indent=2))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    print(json.dumps(test(args.build,args.output),indent=2))
