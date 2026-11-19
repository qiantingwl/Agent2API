"""Unified routing contracts; SQLite memory fixtures and no network calls."""
import contextlib
import json
import sqlite3
import unittest
from unittest.mock import Mock

from routing_guard import PREFIX, reconcile


class UnifiedRoutingTests(unittest.TestCase):
    def setUp(self):
        self.main = sqlite3.connect(':memory:')
        self.state = sqlite3.connect(':memory:')
        for connection in (self.main, self.state):
            connection.row_factory = sqlite3.Row
            self.addCleanup(connection.close)
        self.main.execute('create table requests(account_id,ts,duration_ms,error,provider,status,phase)')
        self.state.execute('create table jobs(account,ended,message,credential_version,provider,status)')
        self.state.execute('create table ledger(key primary key,value)')
        self.row = dict(id='fixture', name='fixture', provider='loomy',
                        enabled=False, balance=0, lastSuccess=50)
        self.official = Mock()
        self.official.call.return_value = {'failed': []}
        self.event = Mock()

    @contextlib.contextmanager
    def db(self, main=False, ro=False):
        connection = self.main if main else self.state
        with connection:
            yield connection

    def marker(self, kind='balance', owned=True):
        self.state.execute('insert or replace into ledger values (?,?)',
                           (PREFIX + 'fixture', json.dumps(dict(
                               at=100, kind=kind, owned=owned, version='v1'))))

    def saved_marker(self):
        row = self.state.execute('select value from ledger where key=?',
                                 (PREFIX + 'fixture',)).fetchone()
        return json.loads(row[0]) if row else None

    def failure(self, message, source='request'):
        if source == 'request':
            self.main.execute('insert into requests values (?,200,10,?,?,401,?)',
                              ('fixture', message, self.row['provider'], ''))
        else:
            self.state.execute('insert into jobs values (?,210,?,?,?,?)',
                               ('fixture', message, 'v1', self.row['provider'], 'needs_login'))

    def run_guard(self):
        return reconcile(self.db, {'accounts': [self.row]}, lambda aid: ({}, {}),
                         lambda data: {}, lambda secret: 'v1', self.official,
                         self.event, 1000)

    def test_zero_credit_error_does_not_disable_routing(self):
        self.row['enabled'] = True
        self.failure('积分余额不足')
        self.assertEqual(self.run_guard(), 0)
        self.official.call.assert_not_called()
        self.assertIsNone(self.saved_marker())

    def test_owned_legacy_balance_disable_is_retired_even_at_zero(self):
        self.marker()
        self.failure('积分余额不足')
        self.assertEqual(self.run_guard(), 1)
        self.official.call.assert_called_once_with('/api/accounts/batch',
                                                  {'action': 'enable', 'ids': ['fixture']})
        self.assertFalse(self.saved_marker()['owned'])
        self.assertEqual(self.run_guard(), 0)
        self.assertEqual(self.official.call.call_count, 1)

    def test_already_enabled_legacy_marker_needs_no_gateway_write(self):
        self.row['enabled'] = True
        self.marker()
        self.assertEqual(self.run_guard(), 0)
        self.assertFalse(self.saved_marker()['owned'])
        self.official.call.assert_not_called()

    def test_manual_disable_is_not_reenabled(self):
        self.assertEqual(self.run_guard(), 0)
        self.marker(owned=False)
        self.assertEqual(self.run_guard(), 0)
        self.official.call.assert_not_called()

    def test_new_login_failure_supersedes_legacy_balance_marker(self):
        self.marker()
        self.failure('请重新登录', source='job')
        self.assertEqual(self.run_guard(), 1)
        self.official.call.assert_called_once_with('/api/accounts/batch',
                                                  {'action': 'disable', 'ids': ['fixture']})
        self.assertEqual(self.saved_marker()['kind'], 'login')

    def test_explicit_ban_is_not_lifted_by_positive_balance(self):
        self.marker(kind='disabled')
        self.row.update(balance=100, lastSuccess=500)
        self.assertEqual(self.run_guard(), 0)
        self.assertTrue(self.saved_marker()['owned'])
        self.official.call.assert_not_called()

    def test_verified_balance_restores_owned_login_disable_without_token_change(self):
        self.marker(kind='login')
        self.row.update(balance=100,lastSuccess=500)
        self.assertEqual(self.run_guard(),1)
        self.official.call.assert_called_once_with('/api/accounts/batch',{'action':'enable','ids':['fixture']})
        self.assertFalse(self.saved_marker()['owned'])

    def test_checkin_alone_does_not_restore_owned_login_disable(self):
        self.marker(kind='login')
        self.state.execute('insert into jobs values (?,500,?,?,?,?)',('fixture','signed','v1','loomy','ok'))
        self.assertEqual(self.run_guard(),0)
        self.official.call.assert_not_called()

    def test_failed_native_enable_preserves_marker_for_retry(self):
        self.marker()
        self.official.call.return_value = {'failed': [{'id': 'fixture'}]}
        self.assertEqual(self.run_guard(), 0)
        self.assertTrue(self.saved_marker()['owned'])
        self.official.call.return_value = {'failed': []}
        self.assertEqual(self.run_guard(), 1)
        self.assertFalse(self.saved_marker()['owned'])

    def test_codearts_auth_failure_is_consumed_from_both_evidence_sources(self):
        self.row.update(provider='codearts', enabled=True)
        for source in ('request', 'job'):
            with self.subTest(source=source):
                self.main.execute('delete from requests')
                self.state.execute('delete from jobs')
                self.state.execute('delete from ledger')
                self.official.reset_mock()
                self.failure('请重新登录', source=source)
                self.assertEqual(self.run_guard(), 1)
                self.official.call.assert_called_once_with('/api/accounts/batch',
                                                          {'action': 'disable', 'ids': ['fixture']})

    def test_unrelated_provider_marker_is_untouched(self):
        self.row['provider'] = 'zcode-intl'
        self.marker()
        self.assertEqual(self.run_guard(), 0)
        self.assertTrue(self.saved_marker()['owned'])
        self.official.call.assert_not_called()


if __name__ == '__main__':
    unittest.main()

