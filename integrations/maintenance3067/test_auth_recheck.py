from task_backlog import checkin_phase, ordinary_during_sign, checkin_providers, sign_hold, capacity_hold
"""Auth recovery regression tests; isolated functions, no live server imports."""
import ast, contextlib, pathlib, sqlite3, threading, secrets, unittest, random, collections, datetime, sys, time
from types import SimpleNamespace
from unittest.mock import Mock
from auth_recheck import resolve_loomy_auth, recheck_allowed, recheck_due, is_capacity_error
from maintenance_state import cooldown_scopes, operation_cooldown
from maintenance_policy import balance_waits_for_checkin, balance_satisfied
from dashboard import dispatch_order
from routing_guard import can_restore
from direct_maintenance import DeliveryPending
from direct_clients import Unsupported
from job_lifecycle import persist_job_outcome

TREE=ast.parse(pathlib.Path(__file__).with_name('server.py').read_text(encoding='utf-8'))
def functions(env,*names):
    for node in TREE.body:
        if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in names:
            exec(compile(ast.Module(body=[node],type_ignores=[]),'isolated-server','exec'),env)
    return env

class AuthPolicyTests(unittest.TestCase):
    def state(self,**kw):
        values=dict(persisted=True,failure={},success_at=0,version='v2',timestamp=100000000)
        values.update(kw);return resolve_loomy_auth(**values)
    def test_legacy_flag_without_time_gets_verification_not_enable(self):
        s=self.state();self.assertTrue(s['needsLogin']);self.assertTrue(s['authRecheck']);self.assertEqual(s['authStatus'],'pending_verify')
        self.assertTrue(recheck_allowed(dict(s,provider='loomy')))
    def test_old_success_without_failure_time_does_not_verify_flag(self):
        self.assertEqual(self.state(success_at=500)['authStatus'],'pending_verify')
    def test_current_failure_observation_and_expiry(self):
        f=dict(ended=99900000,credential_version='v2',action='balance')
        s=self.state(failure=f);self.assertEqual(s['authStatus'],'observing');self.assertFalse(s['authRecheck'])
        self.assertEqual(self.state(failure=f,timestamp=200000000)['authStatus'],'pending_verify')
    def test_failed_explicit_recheck_shows_login_and_observation(self):
        s=self.state(failure=dict(ended=99900000,credential_version='v2',action='recheck'))
        self.assertEqual(s['authStatus'],'credential_failed');self.assertGreater(s['authRecheckAt'],100000000)
    def test_changed_credential_requires_new_verification(self):
        s=self.state(failure=dict(ended=100,credential_version='v1'),success_at=200)
        self.assertTrue(s['authCredentialChanged']);self.assertEqual(s['authStatus'],'pending_verify')
        self.assertFalse(can_restore(dict(kind='login',at=300),dict(lastSuccess=200),'v2',0,200))
    def test_matching_new_verification_recovers_and_old_does_not(self):
        for version,expected in [('v2','verified'),('v1','pending_verify')]:
            s=self.state(marker=dict(kind='login',at=100,version='v1',owned=True),verification=dict(status='ok',ended=200,credential_version=version))
            self.assertEqual(s['authStatus'],expected)
    def test_newer_failure_overrides_success(self):
        s=self.state(failure=dict(ended=99900000,credential_version='v2',action='recheck'),verification=dict(status='ok',ended=200,credential_version='v2'))
        self.assertEqual(s['authStatus'],'credential_failed')
    def test_manual_pause_and_backoff(self):
        row=dict(self.state(),provider='loomy')
        self.assertTrue(recheck_due(row,0,100000000,{}))
        self.assertFalse(recheck_due(row,99999000,100000000,{}))
        self.assertFalse(recheck_allowed(dict(row,maintenancePaused=True)))
    def test_local_capacity_is_not_auth_evidence(self):
        self.assertTrue(is_capacity_error('余额桥并发已满，请排队重试'))
        self.assertFalse(is_capacity_error('登录已失效'))

class RecheckExecutionTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(':memory:');self.c.row_factory=sqlite3.Row;self.addCleanup(self.c.close)
        self.c.execute('create table jobs(id,account,provider,action,status,created,started,ended,message,proxy,credential_version,not_before default 0,origin,priority default 0,attempt default 0)')
        self.c.execute('create table cooldowns(scope,until,reason)')
        self.c.execute("insert into jobs(id,account,provider,action,status,created,origin) values('j','a','loomy','recheck','running',1,'auto')")
        @contextlib.contextmanager
        def db(*args):
            yield self.c;self.c.commit()
        self.cfg=dict(paused=False,timeout=45,globalConcurrency=4,globalBalanceConcurrency=2,providers={'loomy':dict(concurrency=4,jitterMin=0,jitterMax=0,balance=dict(concurrency=2,route='direct'),recheck=dict(concurrency=1,route='direct'))})
        self.official=Mock();self.official.call.return_value={'results':[{'id':'a','usage':{'available':100}}]}
        self.env=dict(checkin_phase=checkin_phase,ordinary_during_sign=ordinary_during_sign,db=db,random=random,settings=lambda:self.cfg,STOP=threading.Event(),LOCK=threading.RLock(),PROGRESS={},ACTIVE={'a':('loomy','recheck')},SNAP={},UI_WAKE=threading.Event(),ROUTING_WAKE=threading.Event(),ROUTING_REFRESH=threading.Event(),UNIFIED=SimpleNamespace(wake=threading.Event()),now=lambda:100000000,account=lambda _:({},{}),credential_version=lambda _:'v2',secret_of=lambda _: {},get_snapshot=lambda *args:{'accounts':[dict(id='a',recheckAllowed=True)]},HEALTH=Mock(),balance_gate_account=lambda _:dict(balance=0,lastSuccess=1),balance_waits_for_checkin=balance_waits_for_checkin,ROOT=SimpleNamespace(__truediv__=None),official_client=lambda:self.official,scrub=str,is_capacity_error=is_capacity_error,cooldown=Mock(),urllib=__import__('urllib'),json=__import__('json'),dumps=lambda x:__import__('json').dumps(x,ensure_ascii=False))
        self.direct=Mock();self.direct.execute.return_value={'status':'ok','message':'verified'}
        self.env.update(SUPPORTED={'loomy','raccoon','codearts'},DeliveryPending=DeliveryPending,Unsupported=Unsupported,DIRECT=self.direct,select_proxy=lambda route:None)
        self.env['ROOT']=pathlib.Path('.')
        self.env['WriteConflict']=type('WriteConflict',(Exception,),{})
        self.env['ProxyUnavailable']=type('ProxyUnavailable',(Exception,),{})
        self.env.update(sys=sys,time=time,event=lambda *args:None,persist_job_outcome=persist_job_outcome)
        self.env.update(SCHEDULER_WAKE=threading.Event(),is_agent_account=lambda aid:aid in ('a','b'),
                        checkin_providers=checkin_providers,sign_hold=sign_hold,capacity_hold=capacity_hold)
        functions(self.env,'RpcError','classify','execute','execute_reserved')
        # Patch filesystem readiness only; no provider worker is permitted.
        self.env['ROOT']=type('Root',(),{'__truediv__':lambda s,k:SimpleNamespace(exists=lambda:True)})()
        self.env['Worker']=Mock(side_effect=AssertionError('recheck must use native usage API'))
    def run_job(self):
        self.c.commit()
        self.env['execute'](dict(self.c.execute("select * from jobs where id='j'").fetchone()))
        return dict(self.c.execute("select * from jobs where id='j'").fetchone())
    def test_verification_uses_independent_balance_even_if_zero(self):
        row=self.run_job();self.assertEqual(row['status'],'ok');self.assertEqual(row['credential_version'],'v2')
        self.direct.execute.assert_called_once();self.official.call.assert_not_called()
        self.assertTrue(self.env['ROUTING_WAKE'].is_set());self.env['Worker'].assert_not_called()
    def test_capacity_defers_same_job_without_auth_failure_or_cooldown(self):
        self.direct.execute.side_effect=DeliveryPending('结果等待重投')
        row=self.run_job();self.assertEqual(row['status'],'queued');self.assertEqual(row['not_before'],100030000);self.assertIsNone(row['ended']);self.env['cooldown'].assert_not_called()
    def test_upstream_login_error_is_classified(self):
        self.direct.execute.side_effect=RuntimeError('登录已失效，请重新登录')
        self.assertEqual(self.run_job()['status'],'needs_login')
    def test_pause_or_changed_account_stops_before_api(self):
        self.cfg['providers']['loomy']['balance']['paused']=True
        self.assertEqual(self.run_job()['status'],'skipped');self.official.call.assert_not_called()
    def test_dispatch_shares_balance_capacity_and_honors_one_worker(self):
        self.c.execute("update jobs set status='queued'")
        self.c.execute("insert into jobs(id,account,provider,action,status,created,origin) values('j2','b','loomy','recheck','queued',2,'auto')")
        self.env.update(collections=collections,datetime=datetime,TZ=datetime.timezone.utc,cooldown_scopes=cooldown_scopes,dispatch_order=dispatch_order,balance_satisfied=balance_satisfied)
        self.env['HEALTH'].available_routes.return_value={'direct'}
        self.env['get_snapshot']=lambda **kwargs:{'accounts':[dict(id=x,provider='loomy',recheckAllowed=True,needsLogin=True) for x in ('a','b')]}
        functions(self.env,'dispatch_jobs');pool=Mock()
        self.env['ACTIVE']={'other':('loomy','balance'),'other2':('loomy','balance')}
        self.env['dispatch_jobs'](self.cfg,pool);pool.submit.assert_not_called()
        self.env['ACTIVE'].clear();self.env['dispatch_jobs'](self.cfg,pool)
        self.assertEqual(pool.submit.call_count,1)

    def test_temporary_cooldown_resumes_at_expiry_for_every_scope(self):
        clock=[100000000]
        self.env.update(collections=collections,datetime=datetime,TZ=datetime.timezone.utc,
            cooldown_scopes=cooldown_scopes,dispatch_order=dispatch_order,balance_satisfied=balance_satisfied,
            now=lambda:clock[0])
        self.env['HEALTH'].available_routes.return_value={'direct'}
        self.env['get_snapshot']=lambda **kwargs:{'accounts':[dict(id='a',provider='loomy',recheckAllowed=True,needsLogin=True)]}
        functions(self.env,'dispatch_jobs')
        for scope in cooldown_scopes('a','loomy','recheck'):
            with self.subTest(scope=scope):
                clock[0]=100000000
                self.c.execute("update jobs set status='queued'")
                self.c.execute('delete from cooldowns')
                self.c.execute('insert into cooldowns values(?,?,?)',(scope,clock[0]+1000,'temporary failure'))
                self.c.commit();self.env['ACTIVE'].clear();pool=Mock()
                self.env['dispatch_jobs'](self.cfg,pool)
                pool.submit.assert_not_called()
                clock[0]+=1000
                self.env['dispatch_jobs'](self.cfg,pool)
                self.assertEqual(pool.submit.call_count,1)

    def test_changed_credential_only_bypasses_old_auth_cooldown_not_rate_limit(self):
        self.c.execute("update jobs set status='queued'")
        self.c.execute('insert into cooldowns values(?,?,?)',('operation:recheck:a',100001000,'鉴权失败，凭证需要检查或重新登录'))
        self.c.execute('insert into cooldowns values(?,?,?)',('provider:loomy',100001000,'429'))
        self.c.commit();self.env['ACTIVE'].clear()
        self.env.update(collections=collections,datetime=datetime,TZ=datetime.timezone.utc,
            cooldown_scopes=cooldown_scopes,dispatch_order=dispatch_order,balance_satisfied=balance_satisfied)
        self.env['HEALTH'].available_routes.return_value={'direct'}
        self.env['get_snapshot']=lambda **kwargs:{'accounts':[dict(id='a',provider='loomy',recheckAllowed=True,needsLogin=True,authCredentialChanged=True)]}
        functions(self.env,'dispatch_jobs');pool=Mock()
        self.env['dispatch_jobs'](self.cfg,pool)
        pool.submit.assert_not_called()
        self.c.execute("delete from cooldowns where scope='provider:loomy'");self.c.commit()
        self.env['dispatch_jobs'](self.cfg,pool)
        self.assertEqual(pool.submit.call_count,1)

class BridgeAdmissionTests(unittest.TestCase):
    def test_busy_slot_waits_then_admits_without_exceeding_limit(self):
        busy={'old':'loomy'};clock=[0.0];stop=Mock()
        def wait(seconds):
            clock[0]+=seconds;busy.clear();return False
        stop.wait.side_effect=wait
        env=functions(dict(LOCK=threading.RLock(),BRIDGE_BUSY=busy,STOP=stop,time=SimpleNamespace(monotonic=lambda:clock[0])),'reserve_bridge_slot')
        cfg={'timeout':45,'globalConcurrency':1,'providers':{'loomy':{'concurrency':1,'balance':{'concurrency':1}}}}
        env['reserve_bridge_slot']('new','loomy',cfg)
        self.assertEqual(busy,{'new':'loomy'});self.assertEqual(stop.wait.call_count,1)
    def test_sustained_capacity_has_bounded_wait_and_preserves_owner(self):
        busy={'old':'loomy'};clock=[0.0];stop=Mock()
        def wait(seconds):clock[0]+=5;return False
        stop.wait.side_effect=wait
        env=functions(dict(LOCK=threading.RLock(),BRIDGE_BUSY=busy,STOP=stop,time=SimpleNamespace(monotonic=lambda:clock[0])),'reserve_bridge_slot')
        cfg={'timeout':45,'globalConcurrency':1,'providers':{'loomy':{'concurrency':1,'balance':{'concurrency':1}}}}
        with self.assertRaisesRegex(RuntimeError,'余额桥并发已满'):env['reserve_bridge_slot']('new','loomy',cfg)
        self.assertEqual(busy,{'old':'loomy'});self.assertEqual(clock[0],10)

if __name__=='__main__':unittest.main()

