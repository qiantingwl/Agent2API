"""Isolated ownership and receipt contracts; no server import or account insertion."""
import ast
import contextlib
import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from direct_maintenance import DirectMaintenance, DeliveryPending
from direct_clients import Unsupported
from job_lifecycle import reconcile_completed_balances
from maintenance_state import resolve_auth, credential_version, cooldown_map
from maintenance_policy import credential_meta
from ui_support import account_pause_details
from relogin_recovery import ReloginRecovery
from ag_wps_client import pending_wps_models


class WpsReceiptTests(unittest.TestCase):
    def setUp(self):
        self.conn=sqlite3.connect(':memory:')
        self.conn.row_factory=sqlite3.Row
        self.addCleanup(self.conn.close)
        self.conn.executescript('''create table ledger(key text primary key,value text);
            create table jobs(id,account,action,status,started,ended,message);''')
        self.gateway=Mock()
        self.gateway.call.return_value={'applied':True}
        self.engine=DirectMaintenance(self.db,json.dumps,json.loads,Mock(),lambda:self.gateway,
            lambda:200000,Mock(),Mock())
        # Stub only the already-resolved inventory boundary; no business accounts.
        self.engine.prepare=Mock(return_value=({}, {}, {'expect':{},'secret':{},'target':None}))
        self.job={'id':'receipt','account':'reference','provider':'wps-lingxi','action':'balance'}

    @contextlib.contextmanager
    def db(self,*args):
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def test_ag_wps_receipt_never_discovers_or_writes_mirai(self):
        with patch('direct_maintenance.Client') as client, patch('unified_sync.bridge_call') as bridge:
            client.return_value.balance.return_value={'available':0}
            result=self.engine.execute(self.job)
            self.assertEqual(result['status'],'ok')
            self.assertIn('AG 已确认接收',result['message'])
            self.engine.deliver('receipt')
            self.assertEqual(dict(self.conn.execute('select target,status from direct_outbox')),
                {'gateway':'done','mirai':'not_required'})
            bridge.assert_not_called()
            client.return_value.balance.assert_called_once()
            self.gateway.call.assert_called_once()

    def test_delivery_retry_does_not_repeat_wps_upstream(self):
        with patch('direct_maintenance.Client') as client, patch('unified_sync.bridge_call') as bridge:
            client.return_value.balance.return_value={'available':12}
            self.gateway.call.side_effect=TimeoutError('isolated transport failure')
            with self.assertRaises(DeliveryPending):self.engine.execute(self.job)
            self.gateway.call.side_effect=None
            self.conn.execute("update direct_outbox set next_at=0")
            result=self.engine.execute(self.job)
            self.assertEqual(result['status'],'ok')
            client.return_value.balance.assert_called_once()
            self.assertEqual(self.gateway.call.call_count,2)
            bridge.assert_not_called()

    def test_all_providers_only_acknowledge_ag(self):
        with patch('direct_maintenance.Client') as client, patch('unified_sync.bridge_call') as bridge:
            client.return_value.balance.return_value={'available':1}
            for provider in ('loomy','raccoon','wps-lingxi'):
                self.engine.execute(dict(self.job,id=provider,provider=provider))
            self.assertEqual(self.conn.execute("select count(*) from direct_outbox where target='mirai' and status='not_required'").fetchone()[0],3)
            bridge.assert_not_called()

    def test_old_pending_mirror_is_never_delivered(self):
        with patch('direct_maintenance.Client') as client, patch('unified_sync.bridge_call') as bridge:
            client.return_value.balance.return_value={'available':1}
            self.engine.execute(self.job)
            self.conn.execute("update direct_outbox set status='pending' where target='mirai'")
            self.conn.commit()
            self.engine.deliver('receipt')
            bridge.assert_not_called()
            self.gateway.call.assert_called_once()

    def test_missing_balance_is_not_acknowledged(self):
        with patch('direct_maintenance.Client') as client:
            client.return_value.balance.return_value={'available':None}
            with self.assertRaises(ValueError):self.engine.execute(self.job)
            self.assertEqual(self.conn.execute('select count(*) from direct_results').fetchone()[0],0)
            self.gateway.call.assert_not_called()

    def test_not_required_allows_completed_balance_recovery(self):
        with patch('direct_maintenance.Client') as client:
            client.return_value.balance.return_value={'available':1}
            self.engine.execute(self.job)
        self.conn.execute('insert into jobs values(?,?,?,?,?,?,?)',
            ('receipt','reference','balance','running',1,None,''))
        self.conn.commit()
        self.assertEqual(reconcile_completed_balances(self.db,{},400000),1)
        self.assertEqual(self.conn.execute('select status from jobs').fetchone()[0],'ok')

    def test_unacknowledged_gateway_cannot_complete_job(self):
        with patch('direct_maintenance.Client') as client:
            client.return_value.balance.return_value={'available':1}
            self.gateway.call.return_value={'applied':False}
            with self.assertRaises(DeliveryPending):self.engine.execute(self.job)
        self.conn.execute('insert into jobs values(?,?,?,?,?,?,?)',
            ('receipt','reference','balance','running',1,None,''))
        self.conn.commit()
        self.assertEqual(reconcile_completed_balances(self.db,{},400000),0)

    def wps_claim_setup(self):
        from wps_maintenance import TZ
        day=datetime.datetime.now(TZ).date().isoformat()
        secret={'cookie':'wps_sid=in-memory-credential','base':'https://lingxi.wps.cn','label':'内存协议验证'}
        auth_hash=hashlib.sha256(json.dumps(secret,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
        self.engine.prepare.return_value=({}, {}, {'expect':secret,'secret':secret,'target':None})
        job=dict(self.job,account='mirai:reference',action='checkin')
        return day,auth_hash,job

    def test_legacy_wps_same_day_same_credential_intent_never_repeats_claim(self):
        day,auth_hash,job=self.wps_claim_setup()
        key='wps-claim:reference:'+day+':'+auth_hash
        self.conn.execute('insert into ledger values(?,?)',(key,'123'))
        self.conn.commit()
        with patch('wps_maintenance.WpsClient') as protocol:
            protocol.return_value.daily.return_value={'status':'unclaimed'}
            self.assertEqual(self.engine.execute(job)['status'],'unconfirmed')
            protocol.return_value.call.assert_not_called()
            self.gateway.call.assert_not_called()
            self.assertEqual(self.conn.execute('select value from ledger where key=?',(key,)).fetchone()[0],'123')

    def test_other_legacy_wps_day_credential_or_source_does_not_suppress_new_claim(self):
        day,auth_hash,job=self.wps_claim_setup()
        old_day=(datetime.date.fromisoformat(day)-datetime.timedelta(days=1)).isoformat()
        for source,claim_day,version in [('reference',old_day,auth_hash),('reference',day,'different'),('other',day,auth_hash)]:
            self.conn.execute('insert into ledger values(?,?)',('wps-claim:'+source+':'+claim_day+':'+version,'123'))
        self.conn.commit()
        with patch('wps_maintenance.WpsClient') as protocol:
            protocol.return_value.daily.side_effect=[{'status':'unclaimed'},{'status':'claimed'}]
            self.assertEqual(self.engine.execute(job)['status'],'ok')
            protocol.return_value.call.assert_called_once_with('tasks/daily_check_in/claim?date='+day,post=True)
            self.gateway.call.assert_called_once()

    def test_legacy_wps_intent_still_accepts_actual_daily_confirmation(self):
        day,auth_hash,job=self.wps_claim_setup()
        self.conn.execute('insert into ledger values(?,?)',('wps-claim:reference:'+day+':'+auth_hash,'123'))
        self.conn.commit()
        with patch('wps_maintenance.WpsClient') as protocol:
            protocol.return_value.daily.return_value={'status':'claimed'}
            self.assertEqual(self.engine.execute(job)['status'],'ok')
            protocol.return_value.call.assert_not_called()
            self.gateway.call.assert_called_once()

    def test_new_wps_lost_acknowledgement_keeps_durable_intent_and_never_reposts(self):
        day,auth_hash,job=self.wps_claim_setup()
        with patch('wps_maintenance.WpsClient') as protocol:
            protocol.return_value.daily.return_value={'status':'unclaimed'}
            protocol.return_value.call.side_effect=TimeoutError('lost acknowledgement')
            with self.assertRaises(TimeoutError):self.engine.execute(job)
            self.assertEqual(self.engine.execute(job)['status'],'unconfirmed')
            protocol.return_value.call.assert_called_once()
            self.gateway.call.assert_not_called()


class WpsModelGateTests(unittest.TestCase):
    def gate(self,reason,**values):
        return {'blocked':True,'reason':reason,'model':'model-a','at':1,**values}

    def test_identity_or_verification_gate_never_schedules_model_probe(self):
        for reason in ('identity','verification'):
            self.assertEqual(pending_wps_models({'pluginLedger.wpsRecovery.identity':self.gate(reason),
                'pluginLedger.wpsRecovery.model':self.gate('permission')}),[])

    def test_same_credential_authentication_gate_waits_for_new_login(self):
        secret={'cookie':'in-memory-credential'}
        stamp=hashlib.sha256(json.dumps([None,secret['cookie'],None,None,None],ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
        account={'pluginLedger.wpsRecovery.identity':self.gate('authentication',credential=stamp),
                 'pluginLedger.wpsRecovery.model':self.gate('permission')}
        self.assertEqual(pending_wps_models(account,secret),[])
        self.assertEqual(pending_wps_models(account,{'cookie':'changed-in-memory-credential'}),['model-a'])

    def test_only_explicit_pending_permission_or_rate_models_are_probed(self):
        account={'pluginLedger.wpsRecovery.a':self.gate('permission'),
                 'pluginLedger.wpsRecovery.b':self.gate('rate',model='model-b',at=2),
                 'pluginLedger.wpsRecovery.c':self.gate('rate'),
                 'pluginLedger.wpsRecovery.d':self.gate('quota',model='model-c'),
                 'pluginLedger.wpsRecovery.e':self.gate('permission',model='model-d',blocked=False)}
        self.assertEqual(pending_wps_models(account),['model-a','model-b'])


class OwnershipDispatchTests(unittest.TestCase):
    def test_relogin_recovery_finishes_with_ag_only_receipt(self):
        query=Mock()
        query.execute.return_value.fetchone.return_value=None
        @contextlib.contextmanager
        def db():yield query
        recovery=ReloginRecovery(db,lambda:200000,Mock(),Mock(),Mock(),
            lambda:{'paused':False,'providers':{'loomy':{'checkin':{'enabled':False}}}},Mock(),Mock())
        recovery.save=Mock()
        state={'account':'reference','required_after':100,'report_at':100,
               'phase':'pending','version':'current','target':'','job':''}
        snapshot={'reference':{'provider':'loomy','authStatus':'verified','lastSuccess':150}}
        inventory={'reference':{'version':'current'}}
        for gateway,mirror,phase in [('done','not_required','verified'),('done','done','verified'),
                                     ('pending','not_required','delivery_wait'),('done','pending','verified')]:
            with self.subTest(gateway=gateway,mirror=mirror):
                recovery.proof=Mock(return_value={'id':'receipt','gateway':gateway,'mirror':mirror})
                recovery.reconcile(state,snapshot,inventory)
                self.assertEqual(recovery.save.call_args.kwargs['phase'],phase)

    def test_wps_snapshot_uses_current_row_and_receipt(self):
        tree=ast.parse(Path(__file__).with_name('server.py').read_text(encoding='utf-8'))
        node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='build_snapshot')
        data={'pluginSecret':{},'usageQuery':{'enabled':False},
              'pluginLedger.wpsRecovery.test':{'blocked':True,'reason':'permission','model':'selected-model','at':1}}
        rows=[dict(id=aid,provider='wps-lingxi',enabled=enabled,data=json.dumps(data),
                   remaining=1,unlimited=0,last_success_at=20,last_attempt_at=20,error='')
              for aid,enabled in [('first',1),('second',0)]]
        query=Mock()
        query.execute.side_effect=lambda sql,*args:SimpleNamespace(fetchall=lambda:rows) if 'from accounts a' in sql else []
        @contextlib.contextmanager
        def db(*args):yield query
        receipts=[{'account':'first','ended':15,'status':'ok','credential_version':credential_version({})}]
        unified=SimpleNamespace(account_sync_state=lambda _: {},loomy_credential_state=lambda _: {},
            external_rows=lambda *a:[],status=lambda:{'mode':'agent2api-only'})
        env=dict(LOCK=threading.RLock(),SNAP={},time=time,db=db,today=lambda:'2026-11-20',
            now=lambda:30,latest_jobs=lambda _:[],latest_verifications=lambda _:receipts,
            json=json,decode=json.loads,SUPPORTED={'wps-lingxi'},secret_of=lambda d:d['pluginSecret'],
            resolve_auth=resolve_auth,credential_version=credential_version,cooldown_map=cooldown_map,
            credential_meta=credential_meta,account_pause_details=account_pause_details,scrub=str,UNIFIED=unified)
        exec(compile(ast.Module(body=[node],type_ignores=[]),'isolated-wps-snapshot','exec'),env)
        result=env['build_snapshot']()['accounts']
        self.assertTrue(result[0]['recheckAllowed'])
        self.assertEqual(result[0]['verifiedBalanceAt'],15)
        self.assertEqual(result[0]['verificationState'],'ok')
        self.assertFalse(result[1]['recheckAllowed'])
        self.assertEqual(result[1]['verifiedBalanceAt'],0)
        self.assertEqual(result[1]['verificationAt'],0)

    def test_only_ag_members_dispatch_regardless_of_id_prefix(self):
        tree=ast.parse(Path(__file__).with_name('server.py').read_text(encoding='utf-8'))
        node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='execute_reserved')
        for owned,aid in ((True,'mirai:historical-reference'),(False,'plain-reference')):
            with self.subTest(owned=owned):
                direct,legacy,invitation=Mock(),Mock(),Mock()
                for target in (direct,legacy):target.execute.return_value={'status':'ok','message':'complete'}
                @contextlib.contextmanager
                def db():yield Mock()
                config={'timeout':30,'providers':{'wps-lingxi':{
                    'jitterMin':0,'jitterMax':0,'balance':{'route':'direct'}}}}
                persist=Mock()
                env=dict(settings=lambda:config,PROGRESS={},random=SimpleNamespace(uniform=lambda *a:0),
                    STOP=threading.Event(),SUPPORTED={'wps-lingxi'},HEALTH=Mock(),select_proxy=lambda _:None,
                    is_agent_account=lambda _:owned,account=Mock(return_value=({},{})),db=db,
                    credential_version=lambda _:'version',secret_of=lambda _: {},DIRECT=direct,
                    WPS_DIRECT=legacy,INVITATIONS=invitation,DeliveryPending=DeliveryPending,
                    Unsupported=Unsupported,scrub=str,WriteConflict=type('WriteConflict',(Exception,),{}),
                    persist_job_outcome=persist,now=lambda:200000,UNIFIED=SimpleNamespace(wake=threading.Event()),
                    UI_WAKE=threading.Event(),ROUTING_WAKE=threading.Event(),ROUTING_REFRESH=threading.Event())
                exec(compile(ast.Module(body=[node],type_ignores=[]),'isolated-wps-dispatch','exec'),env)
                job={'id':'job','account':aid,'provider':'wps-lingxi','action':'balance'}
                env['execute_reserved'](job)
                if owned:direct.execute.assert_called_once_with(job,None,30)
                else:direct.execute.assert_not_called()
                legacy.execute.assert_not_called()
                invitation.execute.assert_not_called()
                self.assertEqual(persist.call_args.args[2],'ok' if owned else 'unsupported')
                self.assertEqual(env['account'].call_count,int(owned))


class ReloginReceiptTests(unittest.TestCase):
    def setUp(self):
        self.conn=sqlite3.connect(':memory:')
        self.conn.row_factory=sqlite3.Row
        self.addCleanup(self.conn.close)
        self.conn.executescript('''create table jobs(id text,account text,action text,status text,
            ended integer,credential_version text);
            create table direct_outbox(result text,target text,status text);''')
        self.recovery=ReloginRecovery(self.db,lambda:200000,Mock(),Mock(),Mock(),
            lambda:{'paused':False,'providers':{'loomy':{'checkin':{'enabled':False}}}},Mock(),Mock())
        self.conn.execute("insert into relogin_recoveries(account,report_at,provider,version,required_after,updated) values('reference',100,'loomy','current',100,100)")
        self.conn.execute("insert into jobs values('receipt','reference','balance','ok',150,'current')")
        self.conn.commit()

    @contextlib.contextmanager
    def db(self):
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def reconcile(self):
        state=dict(self.conn.execute('select * from relogin_recoveries').fetchone())
        self.recovery.reconcile(state,
            {'reference':{'provider':'loomy','authStatus':'verified','lastSuccess':150}},
            {'reference':{'version':'current'}})
        return self.conn.execute('select phase from relogin_recoveries').fetchone()[0]

    def test_gateway_done_recovers_with_pending_or_absent_legacy_receipt(self):
        for mirror in ('pending','conflict','not_required',None):
            with self.subTest(mirror=mirror):
                self.conn.execute('delete from direct_outbox')
                self.conn.execute("insert into direct_outbox values('receipt','gateway','done')")
                if mirror:self.conn.execute("insert into direct_outbox values('receipt','mirai',?)",(mirror,))
                self.conn.commit()
                self.assertEqual(self.reconcile(),'verified')
                saved=self.conn.execute("select status from direct_outbox where target='mirai'").fetchone()
                self.assertEqual(saved[0] if saved else None,mirror)

    def test_unconfirmed_gateway_never_recovers_despite_completed_legacy_receipt(self):
        for gateway in ('pending','conflict'):
            with self.subTest(gateway=gateway):
                self.conn.execute('delete from direct_outbox')
                self.conn.execute("insert into direct_outbox values('receipt','gateway',?)",(gateway,))
                self.conn.execute("insert into direct_outbox values('receipt','mirai','done')")
                self.conn.commit()
                self.assertEqual(self.reconcile(),'delivery_wait')

    def test_receipt_proof_remains_bound_to_credential_and_time(self):
        self.conn.execute("insert into direct_outbox values('receipt','gateway','done')")
        self.conn.commit()
        self.assertIsNone(self.recovery.proof('reference','other',100))
        self.assertIsNone(self.recovery.proof('reference','current',151))


if __name__=='__main__':unittest.main()
