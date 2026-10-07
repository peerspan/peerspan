"""Do not erase unsuccessful or censored exchanges from comparison evidence."""
import unittest
from unittest.mock import Mock, patch
from connectivity_suite import reusable_rows, summarize, verified_exchange_seconds


class NetworkEvidence(unittest.TestCase):
    def test_failed_attempts_and_failed_cases_remain_visible(self):
        rows = [dict(pair='iroh', scenario='cone', status='failed', workloads=[dict(
            content_bytes=16, concurrency=1, succeeded=1, failed=1, wall_seconds=8.001,
            attempts=[dict(seconds=0.001, verified=True), dict(seconds=8.0, verified=False)])]),
            dict(pair='iroh', scenario='cone', status='passed')]
        group = summarize(rows)['cone/iroh']
        self.assertEqual((group['passed'], group['failed']), (1, 1))
        workload = group['workloads']['16B/c1']
        self.assertEqual((workload['verified'], workload['failed']), (1, 1))
        self.assertEqual(workload['successful_latency']['samples'], 1)
        self.assertLess(workload['median_verified_requests_per_second'], 1)

    def test_zero_successes_does_not_create_latency_percentiles(self):
        rows = [dict(pair='go-rust', scenario='cone', status='failed', workloads=[dict(
            content_bytes=16, concurrency=1, succeeded=0, failed=1, wall_seconds=8,
            attempts=[dict(seconds=8, verified=False)])])]
        result = summarize(rows)['cone/go-rust']['workloads']['16B/c1']
        self.assertIsNone(result['successful_latency'])
        self.assertEqual(result['median_verified_requests_per_second'], 0)


class RecoveryAndResume(unittest.TestCase):
    def test_late_success_is_a_failed_bound(self):
        with patch('connectivity_suite.time.monotonic', side_effect=[0, 46]):
            with self.assertRaisesRegex(AssertionError, 'late recovery'):
                verified_exchange_seconds(lambda: {'succeeded': 1}, 45, 'late recovery')

    def test_failure_then_checked_success_within_bound(self):
        exchange = Mock(side_effect=[{'succeeded': 0}, {'succeeded': 1}])
        with patch('connectivity_suite.time.monotonic', side_effect=[0, 8, 9]), patch('connectivity_suite.time.sleep'):
            self.assertEqual(verified_exchange_seconds(exchange, 45, 'late recovery'), 9)

    def test_resume_rejects_changed_evidence_and_filters_matrix(self):
        current = dict(binary_sha256={'go': 'binary'}, harness_sha256={'suite': 'source'},
                       parameters=dict(count=100, nat_repeats=3, no_capture=False))
        previous = dict(current, cases=[
            dict(scenario='cone', pair='go-go', repeat=1, status='passed'),
            dict(scenario='cone', pair='go-go', repeat=1, status='passed'),
            dict(scenario='cone', pair='go-go', repeat=2, status='failed'),
            dict(scenario='cone', pair='iroh', repeat=1, status='passed'),
            dict(scenario='udp-blocked', pair='go-go', repeat=1, status='passed')])
        self.assertEqual(list(reusable_rows(previous, current, ['cone'], ['go-go'])), [previous['cases'][0]])
        for changed in (dict(current, harness_sha256={'suite': 'other'}),
                        dict(current, binary_sha256={'go': 'other'}),
                        dict(current, parameters=dict(current['parameters'], no_capture=True))):
            with self.assertRaises(AssertionError):
                list(reusable_rows(previous, changed, ['cone'], ['go-go']))


if __name__ == '__main__':
    unittest.main()
