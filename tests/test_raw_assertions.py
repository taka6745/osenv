"""Optimized Python must reject acceptance before starting or touching a VM."""
import subprocess
import sys
import unittest


class RawAssertionsTests(unittest.TestCase):
    def test_optimized_entry_rejected_before_inputs_or_vm(self):
        script = '''import importlib, sys
try:
    importlib.import_module(sys.argv[1]).test(*sys.argv[2:])
except RuntimeError as error:
    if str(error) != 'Assertions required for raw acceptance':
        raise
else:
    raise SystemExit('optimized acceptance was not rejected')
'''
        for module, count in [('raw_boot_test', 2), ('raw_clock_test', 2),
                              ('raw_primitives_test', 4)]:
            with self.subTest(module=module):
                # Paths do not exist: passing requires rejection before input I/O.
                result = subprocess.run([sys.executable, '-O', '-c', script,
                                         'osenv.'+module]+['/nonexistent/raw-assertion-input']*count,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
