"""Reject invalid measurements instead of promoting them as faster candidates."""
import unittest
import tempfile
import json
from pathlib import Path
from .experiment import paired_ratio, load_plan


class ExperimentTests(unittest.TestCase):
    def test_invalid_plan_bounds_and_schema(self):
        original={'hypothesis':'measure real throughput','baseline':{'name':'base','build':'absent'},
                  'candidates':[{'name':'candidate','build':'absent'}],'repeat':3,'requests':100,'seed':7}
        for key,value in [('repeat',True),('repeat',2),('requests',30001),('seed',-1),
                          ('hypothesis',''),('candidates',[]),('candidates',[{}]*9)]:
            with self.subTest(key=key,value=value),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'plan.json';path.write_text(json.dumps(original|{key:value}))
                with self.assertRaises(ValueError):load_plan(path)

    def test_real_direct_plan_and_bar_bounds(self):
        build=Path(__file__).resolve().parents[1]/'build/raw-pvh'
        if not build.exists():build=Path(__file__).resolve().parents[1]/'build/t023-boot-pvh-bar-ba'
        if not build.exists():self.skipTest('Actual authored direct-entry build unavailable')
        plan={'hypothesis':'Compare actual direct entry against the same BIOS kernel',
              'baseline':{'name':'bios','build':str(build)},
              'candidates':[{'name':'direct','build':str(build),'boot_kernel':str(build/'pvh.elf'),'expected_bar':0xc0ba0000}],
              'repeat':3,'requests':100,'seed':7}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'plan.json';path.write_text(json.dumps(plan))
            result=load_plan(path)
            self.assertEqual(result['baseline']['image_sha256'],result['candidates'][0]['image_sha256'])
            self.assertEqual(result['candidates'][0]['expected_bar'],0xc0ba0000)
            for bar in [True,0xbffe0000,0xe0000000,0xc0ba0001]:
                plan['candidates'][0]['expected_bar']=bar;path.write_text(json.dumps(plan))
                with self.assertRaises(ValueError):load_plan(path)

    def test_pairing_and_reproducibility(self):
        a = paired_ratio([200,400,600], [100,200,300], 7)
        self.assertAlmostEqual(a['geometric_ratio'], 2)
        self.assertEqual(a, paired_ratio([200,400,600], [100,200,300], 7))
        self.assertEqual(a['paired_bootstrap_95_interval'], [2,2])

    def test_regression_and_noise(self):
        self.assertLess(paired_ratio([50,50,50], [100,100,100], 9)['paired_bootstrap_95_interval'][1], 1)
        bounds = paired_ratio([90,100,110], [100,100,100], 9)['paired_bootstrap_95_interval']
        self.assertLess(bounds[0], 1)
        self.assertGreater(bounds[1], 1)

    def test_invalid_observations(self):
        for a,b in [([], []), ([1,2,3],[1,2]), ([1,0,3],[1,2,3]), ([True,2,3],[1,2,3]),
                    ([1,float('nan'),3],[1,2,3]), ([1,float('inf'),3],[1,2,3])]:
            with self.subTest(a=a,b=b), self.assertRaises(ValueError):
                paired_ratio(a,b,0)


if __name__ == '__main__':
    unittest.main()
