"""Accounting conservation and deliberate corruption rejection on real OS builds."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from .raw_size import account, provenance, report


class RawSizeTests(unittest.TestCase):
    def test_directive_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'source.inc'
            path.write_text('.org 1000\n@begin\n90 abs32:begin\n.align 8\n.zero 2\n.section bss\n.org 180000\n.zero 16\n')
            cells, bss = provenance([path])
            self.assertEqual(sum(x['kind']=='literal' for x in cells.values()), 1)
            self.assertEqual(sum(x['kind']=='fixup' for x in cells.values()), 4)
            self.assertEqual(sum(x['kind']=='alignment' for x in cells.values()), 3)
            self.assertEqual(sum(x['kind']=='explicit_zero' for x in cells.values()), 2)
            self.assertEqual(bss[0]['bytes'], 16)
            self.assertEqual(len(cells), 10)

    def test_unattained_lower_bound_is_not_claimed_minimum(self):
        result = {'image_bytes':1024, 'image_bits':8192, 'image_sha256':'x',
                  'categories':{}, 'bss_reserved_bytes':0,
                  'bounds':{'relocation_only_disk_lower_bound_bytes':512,
                            'minimum_proved_in_constrained_family':False, 'scope':'fixed family'}}
        text = report(result)
        self.assertIn('not attained', text)
        self.assertNotIn('proving a minimum', text)

    def test_real_build_conservation_and_mutants(self):
        base = Path(__file__).resolve().parents[1]/'build'
        build = next((base/name for name in ('raw','t021-raw-release') if (base/name).exists()), base/'raw')
        if not build.exists():
            self.skipTest('saved actual OS build unavailable')
        result = account(build)
        self.assertEqual(sum(x['bytes'] for x in result['categories'].values()), result['image_bytes'])
        intervals = result['provenance_runs']
        self.assertEqual(intervals[0]['start'], 0)
        self.assertEqual(intervals[-1]['end'], result['image_bytes'])
        self.assertTrue(all(a['end']==b['start'] for a,b in zip(intervals, intervals[1:])))
        self.assertEqual(result['literal_page']['bytes'], 1366)
        self.assertEqual(result['bss_disk_bits'], 0)
        for mutant in ('image', 'source', 'symbol', 'bss', 'size'):
            with self.subTest(mutant=mutant), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)/'build'
                shutil.copytree(build, target)
                if mutant == 'image':
                    path = target/'oslab.img'
                    data = bytearray(path.read_bytes()); data[-1] ^= 1; path.write_bytes(data)
                elif mutant == 'source':
                    path = target/'sources/src/raw/entry.inc'
                    path.write_bytes(path.read_bytes()+b'\n;mutation\n')
                else:
                    path = target/'manifest.json'
                    manifest = json.loads(path.read_text())
                    if mutant == 'symbol':
                        manifest['symbols']['raw_entry'] += 1
                    elif mutant == 'bss':
                        manifest['bss']['bss'][0][1] += 1
                    else:
                        manifest['image_bytes'] += 1
                    path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    account(target)

    def test_packed_real_build_and_certificate_mutants(self):
        base = Path(__file__).resolve().parents[1]/'build'
        build = next((base/name for name in ('raw-packed','t022-original-hot-packed','t022-packed') if (base/name).exists()), base/'raw-packed')
        if not build.exists():
            self.skipTest('saved actual packed OS build unavailable')
        result = account(build)
        self.assertEqual(result['image_bytes'],8192)
        optimal = json.loads((build/'packing-proof.json').read_text())['optimal_bytes']
        self.assertEqual(result['bounds']['codec_stream_minimum_bytes'],optimal)
        self.assertEqual(result['bounds']['packed_disk_minimum_bits'],65536)
        self.assertTrue(result['bounds']['minimum_proved_in_constrained_family'])
        self.assertEqual(sum(x['bytes'] for x in result['categories'].values()),8192)
        self.assertEqual(result['decoded_kernel_disk_bits'],0)
        self.assertEqual(result['categories']['compressed_tag']['bytes']+
                         result['categories']['compressed_distance']['bytes']+
                         result['categories']['compressed_literal']['bytes'],optimal)
        for mutant in ('manifest','proof_cost','proof_path','stream','adapter'):
            with self.subTest(mutant=mutant), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)/'build'
                shutil.copytree(build,target)
                if mutant == 'manifest':
                    path = target/'manifest.json'
                    value = json.loads(path.read_text()); value['packing']['values']['input_end'] += 1
                    path.write_text(json.dumps(value))
                elif mutant.startswith('proof'):
                    path = target/'packing-proof.json'
                    value = json.loads(path.read_text())
                    if mutant == 'proof_cost':
                        value['suffix_cost_bytes'][1] += 1
                    else:
                        value['path'][0]['source_end'] += 1
                    path.write_text(json.dumps(value))
                else:
                    path = target/'packed.bin'
                    value = bytearray(path.read_bytes())
                    value[187 if mutant == 'stream' else 0] ^= 1
                    path.write_bytes(value)
                with self.assertRaises(ValueError):
                    account(target)


if __name__ == '__main__':
    unittest.main()
