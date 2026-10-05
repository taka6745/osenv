import unittest
from osenv.perf_bench import summarize
from osenv.web_stress import stress


class PerformanceReportTests(unittest.TestCase):
    def sample(self):
        return dict(
            ok=True,
            image_sha256="synthetic-input",
            run_id="aggregation-fixture",
            requests=10,
            load_seconds=2,
            latency_seconds={"median": 0.01, "p99": 0.02},
            controller_ready_seconds=0.5,
            boot_seconds=1,
            resume_call_to_first_response_seconds=0.1,
        )

    def test_aggregation(self):
        r = summarize([self.sample(), self.sample()])
        self.assertEqual(r["requests_per_second"], 5)
        self.assertEqual(r["requests"], 20)
        self.assertEqual(r["median_resume_call_to_response_seconds"], 0.1)

    def test_failed_or_changed_image_rejected(self):
        for field, value in [("ok", False), ("image_sha256", "changed")]:
            b = self.sample()
            b[field] = value
            with self.assertRaises(ValueError):
                summarize([self.sample(), b])
        with self.assertRaises(ValueError):
            summarize([])

    def test_controlled_debug_rejected_before_launch(self):
        with self.assertRaises(ValueError):
            stress("unused", "unused", controlled_boot=True)
