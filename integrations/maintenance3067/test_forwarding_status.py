import unittest
from forwarding_status import agent_running, mirai_routes, usage_for


class ForwardingStatusTests(unittest.TestCase):
    def test_requests_are_deduplicated_and_retry_backoff_is_excluded(self):
        rows = [{'id': '1', 'accountId': 'a', 'phase': 'streaming'},
                {'id': '2', 'accountId': 'a', 'phase': 'waiting'},
                {'id': '3', 'accountId': 'b', 'phase': 'retrying'},
                {'id': '4', 'accountId': '', 'phase': 'connecting'}]
        self.assertEqual(agent_running(lambda _: {'matched': 4, 'entries': rows}), {'a': 2})

    def test_truncated_native_pages_are_not_treated_as_all_requests(self):
        with self.assertRaises(ValueError):
            agent_running(lambda _: {'matched': 5, 'entries': [{'id': '1'}]})

    def test_busy_with_capacity_is_available_but_full_is_blocked(self):
        data = {'ok': True, 'complete': True, 'inflight': {'a': 1, 'b': 2},
                'accounts': [{'id': i, 'uid': uid, 'state': 'usable', 'limit': 2}
                             for i, uid in enumerate(['a', 'b', 'c'])]}
        routes = mirai_routes(data, 100)
        self.assertEqual(routes['mirai:0']['state'], 'usable')
        self.assertEqual(routes['mirai:1']['state'], 'concurrency')
        self.assertEqual(routes['mirai:2']['inFlight'], 0)

    def test_truncated_pressure_never_turns_missing_id_into_idle(self):
        data = {'ok': True, 'complete': False, 'inflight': {'other-platform': 2},
                'accounts': [{'id': 1, 'uid': 'wps', 'state': 'usable', 'limit': 2}]}
        row = mirai_routes(data, 100)['mirai:1']
        self.assertEqual(row['state'], 'unknown')
        self.assertIsNone(row['inFlight'])

    def test_disabled_stays_disabled_even_with_no_traffic(self):
        data = {'ok': True, 'complete': True, 'inflight': {},
                'accounts': [{'id': 1, 'uid': 'wps', 'state': 'disabled', 'limit': 2}]}
        self.assertEqual(mirai_routes(data, 100)['mirai:1']['state'], 'disabled')

    def test_stale_or_missing_usage_is_not_zero(self):
        self.assertIsNone(usage_for({}, {}, 'agent', 50000))
        self.assertIsNone(usage_for({}, {'at': 1, 'counts': {}}, 'agent', 50000))
        self.assertEqual(usage_for({}, {'at': 49999, 'counts': {}}, 'agent', 50000), 0)
        self.assertIsNone(usage_for({'usageAt': 1, 'inFlight': 3}, {}, 'mirai:1', 50000))


if __name__ == '__main__':
    unittest.main()

