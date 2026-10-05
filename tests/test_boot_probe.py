import unittest
from osenv.boot_probe import interval, probe


class BootProbeTests(unittest.TestCase):
    def event(self, name, us):
        return {"event": name, "timestamp": {"seconds": 10, "microseconds": us}}

    def test_event_interval(self):
        e = [self.event("STOP", 0), self.event("RESUME", 100), self.event("STOP", 200)]
        self.assertAlmostEqual(interval(e), 0.0001)

    def test_reset_or_missing_stop_rejected(self):
        with self.assertRaises(ValueError):
            interval(
                [self.event("RESUME", 0), self.event("RESET", 1), self.event("STOP", 2)]
            )
        with self.assertRaises(StopIteration):
            interval([self.event("RESUME", 0)])

    def test_invalid_target_rejected_before_launch(self):
        with self.assertRaises(ValueError):
            probe("unused", "unused", "bad target")
