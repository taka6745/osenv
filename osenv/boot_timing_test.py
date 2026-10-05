"""Integer epoch precision, clock bounds and execution interruption regressions."""
import unittest
from .boot_timing import event_wall_ns, returned_request_timing

EPOCH = 1_800_000_000_000_000_000


def event(name, offset):
    seconds, remainder = divmod(EPOCH+offset, 1_000_000_000)
    return {'event':name,'timestamp':{'seconds':seconds,'microseconds':remainder//1000}}


def sample(offset, skew=10):
    return {'wall_ns':EPOCH+offset, 'monotonic_before_ns':100_000_000+offset,
            'monotonic_after_ns':100_000_000+offset+skew}


class BootTimingTests(unittest.TestCase):
    def measure(self, events=None, before=None, done=None, **kwargs):
        return returned_request_timing(events if events is not None else [event('RESET',-1000),event('RESUME',1000)],
                                       before or sample(0), done or sample(10_000_000), **kwargs)

    def test_exact_large_epoch_integer_subtraction(self):
        result = self.measure()
        self.assertEqual(result['cpu_release_to_returned_request_ns'], 9_999_000)
        self.assertEqual(result['clock_shift_interval_ns'], [-10,10])
        self.assertEqual(event_wall_ns(event('RESUME',1000)), EPOCH+1000)

    def test_cleanup_stop_after_completion_allowed(self):
        result = self.measure(events=[event('RESUME',1000),event('STOP',11_000_000)])
        self.assertEqual(result['cpu_release_to_returned_request_ns'],9_999_000)

    def test_interrupted_execution_rejected(self):
        for name in ('STOP','RESET','RESUME'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError,'unexpected'):
                self.measure(events=[event('RESUME',1000),event(name,5000)])

    def test_event_order_and_missing_start_rejected(self):
        for events in ([], [event('RESUME',-1000)], [event('RESUME',11_000_000)],
                       [event('RESUME',1000),event('RESET',0)]):
            with self.subTest(events=events), self.assertRaises(ValueError):
                self.measure(events=events)

    def test_wall_clock_jump_and_wide_sample_rejected(self):
        done = sample(10_000_000); done['wall_ns'] += 2_000_000
        with self.assertRaisesRegex(ValueError,'drift'):
            self.measure(done=done)
        with self.assertRaisesRegex(ValueError,'drift'):
            self.measure(done=sample(10_000_000,2_000_000))

    def test_malformed_clock_fields_and_order(self):
        for value in (True,1.0,-1):
            bad = sample(10_000_000); bad['wall_ns']=value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.measure(done=bad)
        with self.assertRaises(ValueError):
            self.measure(done=sample(-1000))
        bad = event('RESUME',1000); bad['timestamp']['microseconds']=1_000_000
        with self.assertRaises(ValueError):
            self.measure(events=[bad])


if __name__ == '__main__':
    unittest.main()
