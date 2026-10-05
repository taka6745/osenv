"""Acceleration configuration must reject unsupported use without fallback."""
import unittest
from .worker import start
from .perf_bench import summarize


class AccelerationTests(unittest.TestCase):
    def test_explicit_invalid_and_deterministic_kvm_rejected(self):
        with self.assertRaisesRegex(ValueError,'Acceleration'):
            start(acceleration='automatic')
        with self.assertRaisesRegex(ValueError,'KVM requires'):
            start(acceleration='kvm')
        with self.assertRaisesRegex(ValueError,'KVM requires'):
            start(manual=True,timing='virtual',acceleration='kvm')

    def test_mixed_acceleration_is_not_a_matched_series(self):
        rows=[{'ok':True,'image_sha256':'same','boot_route':'bios-disk','acceleration':value}
              for value in ('tcg','kvm')]
        with self.assertRaisesRegex(ValueError,'Acceleration changed'):
            summarize(rows)


if __name__=='__main__':unittest.main()
