"""Result integrity checks: incomplete runs must never become valid evidence."""
import copy
from types import SimpleNamespace
import unittest

from connectivity_bench import distribution, summarize, validate


class ResultIntegrity(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(count=2, cold=2, warmup=0, concurrency=1)
        self.raw = dict(backend='peerspan-go', count=2, cold=2, warmup=0, concurrency=1,
                        cold_first_echo_seconds=[0.001, 0.002], workloads=[
                            dict(content_bytes=size, sequential_seconds=[0.001, 0.002],
                                 concurrent_seconds=[0.001, 0.002], concurrent_wall_seconds=0.01)
                            for size in (16, 65536)])

    def test_incomplete_and_invalid_results_are_rejected(self):
        validate(self.raw, self.args)
        for bad in ([], [0.001], [0.0, 0.002], [float('nan'), 0.002], [float('inf'), 0.002]):
            with self.subTest(samples=bad):
                raw = copy.deepcopy(self.raw)
                raw['workloads'][1]['concurrent_seconds'] = bad
                with self.assertRaises(ValueError):
                    validate(raw, self.args)
        raw = copy.deepcopy(self.raw)
        raw['count'] = 3
        with self.assertRaises(ValueError):
            validate(raw, self.args)

    def test_small_samples_use_nearest_rank_without_interpolation(self):
        result = distribution([0.001, 0.002])
        self.assertEqual(result['p50_ms'], 1.0)
        self.assertEqual(result['p99_ms'], 2.0)

    def test_partial_report_does_not_invent_unrun_backends(self):
        report = summarize([self.raw])
        self.assertEqual(list(report), ['peerspan-go'])
        self.assertEqual(report['peerspan-go']['workloads']['16']['median_requests_per_second'], 200)


if __name__ == '__main__':
    unittest.main()
