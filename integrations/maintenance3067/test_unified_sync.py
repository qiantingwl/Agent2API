import contextlib
import json
import sqlite3
import unittest
from unittest.mock import patch
import unified_sync as u


class SyncTests(unittest.TestCase):
    def test_older_inventory_does_not_erase_task_balance_or_restore_deleted_identity(self):
        incoming={'1':{'uid':'same','balance':0,'balance_at':1800000000000},'2':{'uid':'new','balance':5,'balance_at':1800000000000}}
        live={'1':{'uid':'same','balance':100,'balance_at':1800000010000},'2':{'uid':'old','balance':999,'balance_at':1800000010000},'3':{'uid':'deleted','balance':100,'balance_at':1800000010000}}
        u.preserve_balance_observations(incoming,live)
        self.assertEqual(incoming['1']['balance'],100)
        self.assertEqual(incoming['2']['balance'],5)
        self.assertNotIn('3',incoming)

    def test_native_balance_updates_cache_immediately(self):
        import threading
        obj=object.__new__(u.UnifiedMaintenance);obj.lock=threading.RLock();obj.wake=threading.Event()
        obj.external={'12':{'uid':'u','balance':0,'balance_at':1800000000000}}
        c=sqlite3.connect(':memory:');self.addCleanup(c.close);c.execute('create table ledger(key primary key,value)')
        @contextlib.contextmanager
        def db():yield c
        obj.db=db
        with patch.object(u,'bridge_call',return_value={'status':'ok','ok':True,'balance':12,'balanceAt':1800000010000}):
            obj.execute_task({'account':'mirai:12','action':'balance'})
        self.assertEqual(obj.external['12']['balance'],12)
        self.assertEqual(obj.external['12']['balance_at'],1800000010000)
    def test_timezone_and_units(self):
        self.assertEqual(u.millis('2026-11-09T12:00:00+08:00'),u.millis('2026-11-09T04:00:00Z'))
        self.assertEqual(u.millis(1800000000),1800000000000)
        self.assertEqual(u.millis(float('nan')),0)

    def test_conflicting_first_tokens_are_not_guessed(self):
        self.assertEqual(u.choose_credentials({'auth':{'token':'a'}},{'auth':{'token':'b'}}),'conflict')

    def test_changed_provenance_and_expiry(self):
        a={'auth':{'token':'a','expires_at':1800000000}}
        b={'auth':{'token':'b','expires_at':1800000100}}
        self.assertEqual(u.choose_credentials(a,b),'target')
        prev={'source_token':u.token_digest(a['auth']),'target_token':u.token_digest(b['auth'])}
        a['auth']['token']='new'
        self.assertEqual(u.choose_credentials(a,b,prev),'source')

    def test_balance_change_is_not_credential_change(self):
        self.assertEqual(u.choose_credentials({'auth':{'token':'same'},'balance':1},{'auth':{'token':'same'},'balance':0}),'same')

    def test_source_aliases_keep_refresh_bundle(self):
        row={'provider':'codearts','id':'c','enabled':1,'remaining':4,'last_success_at':1800000000000}
        r=u.source_record(row,{'pluginSecret':{'user_id':'u','accessToken':'t','access_key_id':'ak','secret_access_key':'sk','security_token':'st','refreshToken':'rt'}})
        self.assertEqual(r['auth']['refresh_token'],'rt')
        self.assertEqual(r['auth']['access_key'],'ak')
        self.assertEqual(r['source_id'],'c')

    def test_task_translation_preserves_confirmed_sign(self):
        obj=object.__new__(u.UnifiedMaintenance)
        import threading
        obj.wake=threading.Event();obj.lock=threading.RLock();obj.external={}
        c=sqlite3.connect(':memory:');self.addCleanup(c.close)
        c.execute('create table ledger(key primary key,value)')
        @contextlib.contextmanager
        def db():yield c
        obj.db=db
        for original,expected in [('signed','ok'),('already_signed','ok'),('failed','error'),('cooldown','cooling')]:
            with patch.object(u,'bridge_call',return_value={'status':original}) as call:
                r=obj.execute_task({'account':'mirai:12','action':'checkin'})
                self.assertEqual(r['status'],expected)
                self.assertEqual(call.call_args[0][0]['account_id'],'12')

    def test_central_wps_sign_is_counted_today(self):
        c=sqlite3.connect(':memory:')
        c.execute('create table jobs(account,provider,action,status,ended)')
        c.execute('create table ledger(key primary key,value)')
        at=u.millis('2026-11-09T04:00:00Z')
        c.execute("insert into jobs values('mirai:1','wps-lingxi','checkin','ok',?)",(at,))
        @contextlib.contextmanager
        def db():yield c
        obj=object.__new__(u.UnifiedMaintenance)
        import threading
        obj.lock=threading.RLock();obj.db=db;obj.external={'1':{'id':1,'platform':'wps-lingxi','auth':{},'status':'active'}}
        obj.health={'lastRun':at,'error':''};obj.today=lambda:'2026-11-09';obj.now=lambda:at
        rows=obj.external_rows({}, {}, {}, {})
        self.assertTrue(rows[0]['signed'])
        self.assertEqual(rows[0]['signedAt'],at)
        self.assertFalse(rows[0]['maintenancePaused'])


if __name__=='__main__':unittest.main()

