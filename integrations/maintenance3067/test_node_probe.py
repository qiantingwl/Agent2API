"""Real worker lifecycle with SQLite; no business accounts or external requests."""
import contextlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from node_probe import NodeProbe, TARGETS, outcome


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'probe.db'
        with self.db() as c:
            c.execute('create table settings(key text primary key,value text)')
        self.clock = 1000000
        self.stop = threading.Event()
        self.calls = []
        self.gate = None
        self.active = self.peak = 0
        self.guard = threading.Lock()
        self.gateway = type('Gateway', (), {'call': lambda _, p, b=None: self.call(p, b)})()
        self.probe = NodeProbe(self.db, lambda: self.gateway, lambda: self.clock)
        self.addCleanup(self.probe.pool.shutdown, wait=True, cancel_futures=True)

    @contextlib.contextmanager
    def db(self):
        with contextlib.closing(sqlite3.connect(self.path, timeout=5)) as c:
            with c:
                yield c

    def call(self, path, body):
        with self.guard:
            self.calls.append((path, body))
        if path == '/api/proxies/pool':
            return {'items': [{'id': str(i), 'source': 'manual', 'enabled': i < 4,
                               'password': 'must-not-persist'} for i in range(5)]}
        with self.guard:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            if self.gate:
                self.gate.wait(2)
            return {'success': True, 'status': 200, 'durationMs': 12, 'ip': 'not-retained'}
        finally:
            with self.guard:
                self.active -= 1

    def finish_workers(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with self.probe.lock:
                futures = list(self.probe.active.values())
            if all(f.done() for f in futures):
                for f in futures:
                    f.result()
                return
            time.sleep(.01)
        self.fail('worker did not finish')

    def test_auth_rejection_is_reached_but_not_success(self):
        self.assertFalse(outcome({'success': True, 'data': {'success': False, 'status': 403}})['httpOk'])
        self.assertTrue(outcome({'success': True, 'data': {'success': True, 'status': 200}})['httpOk'])
        for status in (401, 403):
            result = outcome({'success': True, 'status': status, 'error': 'secret'})
            self.assertTrue(result['transportReached'])
            self.assertFalse(result['httpOk'])
            self.assertEqual(result['category'], 'rejected')
            self.assertNotIn('secret', json.dumps(result))
        self.assertEqual(outcome({'error': 'probe_timeout'})['category'], 'timeout')
        self.assertFalse(outcome({'success': True})['httpOk'])

    def test_default_disabled_and_explicit_configuration_bounds(self):
        self.assertEqual(self.probe.tick(self.stop), 0)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.probe.config()['interval'], 900)
        for bad in ({'interval': 1}, {'concurrency': 3}, {'concurrency': True}, {'enabled': 1}):
            with self.assertRaises(ValueError):
                self.probe.configure(bad)

    def test_bounded_workers_skip_disabled_nodes_and_retain_only_results(self):
        self.probe.configure({'enabled': True})
        self.gate = threading.Event()
        self.assertEqual(self.probe.tick(self.stop), 2)
        self.assertEqual(self.probe.tick(self.stop), 0)
        self.gate.set()
        self.finish_workers()
        self.assertEqual(self.probe.tick(self.stop), 2)
        self.finish_workers()
        self.assertEqual(self.probe.tick(self.stop), 0)
        self.assertLessEqual(self.peak, 2)
        results = self.probe.status()['results']
        self.assertEqual(len(results), 4 * len(TARGETS))
        self.assertNotIn('must-not-persist', json.dumps(results))
        self.assertNotIn('not-retained', json.dumps(results))
        requests = [body for path, body in self.calls if body]
        self.assertEqual({body['id'] for body in requests}, {'0', '1', '2', '3'})
        self.assertTrue(all(set(body) == {'id', 'testUrl'} for body in requests))
        self.assertEqual({body['testUrl'] for body in requests}, set(TARGETS.values()))
        # The next interval admits the nodes again, without changing pool state.
        self.clock += 900000
        self.assertEqual(self.probe.tick(self.stop), 2)
        self.finish_workers()

    def test_stop_prevents_requests_and_gateway_failure_is_recorded(self):
        self.probe.configure({'enabled': True})
        self.stop.set()
        self.assertEqual(self.probe.tick(self.stop), 0)
        self.stop.clear()
        self.gateway.call = lambda *args: (_ for _ in ()).throw(RuntimeError('do-not-save-credentials'))
        self.probe._probe('existing-proxy-reference', self.stop)
        results = self.probe.status()['results']
        self.assertEqual(len(results), 3)
        self.assertTrue(all(r['category'] == 'connection_error' for r in results))
        self.assertNotIn('do-not-save-credentials', json.dumps(results))
        self.stop.set()
        self.probe._probe('should-not-run', self.stop)
        self.assertEqual(len(self.probe.status()['results']), 3)


if __name__ == '__main__':
    unittest.main()
