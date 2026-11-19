import ast,sys,time,contextlib,pathlib,random,secrets,sqlite3,threading,unittest,collections,datetime
from types import SimpleNamespace
from maintenance_state import cooldown_scopes,operation_cooldown
from maintenance_policy import balance_next_at,balance_waits_for_checkin
from job_queries import latest_jobs
from direct_maintenance import DeliveryPending
from direct_clients import Unsupported
from job_lifecycle import persist_job_outcome
from dashboard import dispatch_order
from task_backlog import checkin_phase, ordinary_during_sign, checkin_providers, sign_hold, capacity_hold

class SignChainTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(':memory:');self.c.row_factory=sqlite3.Row;self.addCleanup(self.c.close)
        self.c.execute('''create table jobs(id text,account text,provider text,action text,status text,created integer,started integer,ended integer,message text,proxy text,credential_version text,attempt integer default 0,origin text,priority integer default 0,required_after integer default 0,not_before integer default 0)''')
        self.c.execute('create table cooldowns(scope text primary key,until integer,reason text)')
        @contextlib.contextmanager
        def db(*args):
            yield self.c
            self.c.commit()
        self.c.execute('create table accounts(id text,enabled integer)');self.c.execute("insert into accounts values('a',1),('b',1),('c',1)")
        self.cfg={'timeout':30,'paused':False,'globalBalanceConcurrency':2,'providers':{'loomy':{'jitterMin':0,'jitterMax':0,'checkin':{'route':'direct'},'balance':{'route':'direct',**{'concurrency':2,'enabled':True,'interval':3600,'positiveInterval':3600}}}}}
        self.active={'a':('loomy','checkin')};self.calls=[];self.balance_status='ok';self.now=10000000
        def native(job,*args):
            self.calls.append(job['action'])
            self.assertIn('a',self.active)
            if job['action']=='balance':
                self.assertEqual(self.active['a'],('loomy','balance'))
                self.assertEqual(self.c.execute('select status from jobs where id=?',(job['id'],)).fetchone()[0],'running')
                return {'status':self.balance_status,'message':'balance result'}
            self.env['queue_post_checkin_balance'](job['account'],'loomy',self.now)
            return {'status':'ok','message':'signed'}
        self.env=dict(checkin_phase=checkin_phase,ordinary_during_sign=ordinary_during_sign,sys=sys,time=time,event=lambda *args:None,persist_job_outcome=persist_job_outcome,db=db,LOCK=threading.RLock(),PROGRESS={},ACTIVE=self.active,STOP=threading.Event(),SNAP={},UNIFIED=SimpleNamespace(execute_task=native,wake=threading.Event()),UI_WAKE=threading.Event(),ROUTING_WAKE=threading.Event(),ROUTING_REFRESH=threading.Event(),settings=lambda:self.cfg,random=random,now=lambda:self.now,secrets=secrets,scrub=str,cooldown=lambda *args:None,cooldown_scopes=cooldown_scopes,operation_cooldown=operation_cooldown,balance_next_at=balance_next_at,balance_waits_for_checkin=balance_waits_for_checkin)
        self.env.update(SUPPORTED={'loomy','raccoon','codearts'},DeliveryPending=DeliveryPending,Unsupported=Unsupported,DIRECT=SimpleNamespace(execute=native),select_proxy=lambda route:None,HEALTH=SimpleNamespace(require_available=lambda route:None),account=lambda aid:({},{}),secret_of=lambda d:{},credential_version=lambda s:'fixture')
        self.env.update(SCHEDULER_WAKE=threading.Event(),is_agent_account=lambda aid:bool(self.c.execute('select 1 from accounts where id=?',(aid,)).fetchone()),
                        checkin_providers=checkin_providers,sign_hold=sign_hold,capacity_hold=capacity_hold)
        self.env['WriteConflict']=type('WriteConflict',(Exception,),{})
        self.env['ProxyUnavailable']=type('ProxyUnavailable',(Exception,),{})
        self.env['RpcError']=type('RpcError',(Exception,),{})
        self.env['classify']=lambda e:('error',type(e).__name__,300)
        tree=ast.parse(pathlib.Path('server.py').read_text(encoding='utf-8'))
        for node in tree.body:
            if isinstance(node,ast.FunctionDef) and node.name in ('execute','execute_reserved','queue_post_checkin_balance','claim_checkin_balance','schedule_balances','dispatch_jobs'):
                exec(compile(ast.Module(body=[node],type_ignores=[]),'isolated-server-functions','exec'),self.env)
        self.c.execute("insert into jobs(id,account,provider,action,status,created,origin) values('sign','a','loomy','checkin','running',1,'auto')")

    def run_sign(self):
        self.c.commit()
        self.env['execute'](dict(self.c.execute("select * from jobs where id='sign'").fetchone()))

    def test_sign_phase_reserves_spare_slots_and_admits_three_checkins(self):
        self.c.execute('delete from jobs');self.active.clear()
        self.cfg.update(globalConcurrency=8,globalBalanceConcurrency=6)
        self.cfg['providers']['loomy'].update(concurrency=4,checkin={'enabled':True,'concurrency':3,'route':'direct'})
        self.cfg['providers']['loomy']['balance']['concurrency']=3
        self.now=int(datetime.datetime(2026,11,12,2,tzinfo=datetime.timezone.utc).timestamp()*1000)
        rows=[dict(id=x,provider='loomy',balance=1,lastSuccess=0,signed=False) for x in ('a','b','c','d','e')]
        for aid,action in [('a','checkin'),('d','balance')]:
            self.c.execute("insert into jobs(id,account,provider,action,status,created,origin) values(?,?,?,?,'queued',?,'auto')",(aid,aid,'loomy',action,self.now))
        self.env.update(collections=collections,datetime=datetime,TZ=datetime.timezone.utc,dispatch_order=dispatch_order,balance_satisfied=lambda *args:False,HEALTH=SimpleNamespace(available_routes=lambda:{'direct'}),get_snapshot=lambda **kwargs:{'accounts':rows})
        submitted=[];pool=SimpleNamespace(submit=lambda fn,j:submitted.append(j))
        self.env['dispatch_jobs'](self.cfg,pool)
        self.assertEqual([j['action'] for j in submitted],['checkin'])
        # Unqueued b/c/e hold the sign phase: ordinary d cannot use spare slots.
        for aid in ('b','c','e'):
            self.c.execute("insert into jobs(id,account,provider,action,status,created,origin) values(?,?,?,'checkin','queued',?,'auto')",(aid,aid,'loomy',self.now))
        self.env['dispatch_jobs'](self.cfg,pool)
        self.assertEqual(len(self.active),3)
        self.assertEqual([j['action'] for j in submitted],['checkin']*3)

    def test_sign_immediately_queries_without_releasing_account(self):
        self.run_sign()
        self.assertEqual(self.calls,['checkin','balance'])
        self.assertNotIn('a',self.active)
        self.assertEqual([r[0] for r in self.c.execute('select status from jobs')],['ok','ok'])
        self.assertTrue(self.env['ROUTING_WAKE'].is_set())

    def test_existing_future_query_is_reused(self):
        self.c.execute("insert into jobs(id,account,provider,action,status,created,origin,not_before) values('balance','a','loomy','balance','queued',1,'auto',999999999)")
        self.run_sign()
        self.assertEqual(self.c.execute('select count(*) from jobs').fetchone()[0],2)
        self.assertEqual(self.c.execute("select status from jobs where id='balance'").fetchone()[0],'ok')

    def test_full_capacity_preserves_priority_followup(self):
        self.active.update(b=('loomy','balance'),c=('loomy','balance'))
        self.run_sign()
        self.assertEqual(self.calls,['checkin'])
        r=self.c.execute("select * from jobs where action='balance'").fetchone()
        self.assertEqual((r['status'],r['origin'],r['not_before']),('queued','post_checkin',0))
        self.assertEqual(len(self.active),2)

    def test_global_and_operation_pause_prevent_inline_query(self):
        for mode in ('global','balance'):
            if mode=='global':self.cfg['paused']=True
            else:self.cfg['paused']=False;self.cfg['providers']['loomy']['balance']['paused']=True
            self.active['a']=('loomy','checkin');self.calls.clear();self.run_sign()
            self.assertEqual(self.calls,['checkin'])

    def test_failed_balance_does_not_reclassify_successful_checkin_and_retries_before_hour(self):
        self.balance_status='error';self.run_sign()
        self.assertEqual(self.c.execute("select status from jobs where id='sign'").fetchone()[0],'ok')
        row=dict(id='a',provider='loomy',supported=True,balance=0,lastSuccess=self.now-1000,signedAt=self.now,operationCooldowns={})
        self.env['schedule_balances'](self.cfg,{'accounts':[row]},self.now)
        q=self.c.execute("select * from jobs where status='queued'").fetchone()
        self.assertEqual(q['origin'],'post_checkin')
        self.assertEqual(q['not_before'],self.now+300000)

    def test_dispatch_reserves_followup_slots_before_starting_checkins(self):
        self.c.execute('delete from jobs');self.active.clear()
        self.cfg.update(globalConcurrency=64)
        pc=self.cfg['providers']['loomy'];pc.update(concurrency=18,checkin={'concurrency':16,'route':'direct','start':'00:00','end':'23:59'})
        pc['balance']['route']='direct'
        rows=[dict(id=x,provider='loomy',signed=False) for x in ('a','b','c')]
        for x in rows:self.c.execute("insert into jobs(id,account,provider,action,status,created,origin) values(?,?,'loomy','checkin','queued',1,'auto')",(x['id'],x['id']))
        self.c.commit()
        self.env.update(collections=collections,datetime=datetime,TZ=datetime.timezone.utc,dispatch_order=dispatch_order,HEALTH=SimpleNamespace(available_routes=lambda:{'direct'}),get_snapshot=lambda **kwargs:{'accounts':rows})
        submitted=[]
        self.env['dispatch_jobs'](self.cfg,SimpleNamespace(submit=lambda fn,j:submitted.append(j)))
        self.assertEqual(len(submitted),2)
        self.assertTrue(all(j['action']=='checkin' for j in submitted))
        # Both checkins can now take their pre-reserved balance slot, serially.
        self.env['queue_post_checkin_balance']('a','loomy',self.now)
        self.env['queue_post_checkin_balance']('b','loomy',self.now)
        self.assertIsNotNone(self.env['claim_checkin_balance']('a','loomy',self.cfg))
        self.assertIsNotNone(self.env['claim_checkin_balance']('b','loomy',self.cfg))

    def test_busy_large_providers_cannot_starve_due_single_slot_provider(self):
        self.exercise_single_slot_provider(busy=True)

    def test_empty_batch_does_not_starve_due_single_slot_provider(self):
        self.exercise_single_slot_provider(busy=False)

    def exercise_single_slot_provider(self,busy):
        self.c.execute('delete from jobs');self.active.clear()
        self.cfg.update(globalConcurrency=8,globalBalanceConcurrency=6)
        rows=[]
        for provider,limit,total in [('loomy',3,40),('raccoon',3,40),('codearts',1,3)]:
            self.cfg['providers'][provider]={'concurrency':limit+1,'balance':{'concurrency':limit,'route':'direct'}}
            for i in range(total):
                aid=f'{provider}-{i}'
                rows.append(dict(id=aid,provider=provider,balance=1,lastSuccess=0))
                created=100 if provider=='codearts' else 1
                self.c.execute("insert into jobs(id,account,provider,action,status,created,origin) values(?,?,?,'balance','queued',?,'auto')",(aid,aid,provider,created))
        # Five long-running requests leave one slot; old large queues always
        # refill it unless an idle provider gets a turn before weighted rank.
        if busy:
            self.active.update({f'busy-l-{i}':('loomy','balance') for i in range(2)})
            self.active.update({f'busy-r-{i}':('raccoon','balance') for i in range(3)})
        self.env.update(collections=collections,datetime=datetime,TZ=datetime.timezone.utc,dispatch_order=dispatch_order,balance_satisfied=lambda *args:False,HEALTH=SimpleNamespace(available_routes=lambda:{'direct'}),get_snapshot=lambda **kwargs:{'accounts':rows})
        for _ in range(3):
            submitted=[]
            self.env['dispatch_jobs'](self.cfg,SimpleNamespace(submit=lambda fn,j:submitted.append(j)))
            self.assertEqual(sum(j['provider']=='codearts' for j in submitted),1)
            self.assertEqual(len(self.active),6)
            for provider in self.cfg['providers']:
                self.assertLessEqual(sum(p==provider for p,a in self.active.values()),self.cfg['providers'][provider]['balance']['concurrency'])
            for job in submitted:
                self.c.execute("update jobs set status='ok' where id=?",(job['id'],))
                del self.active[job['account']]

class LatestJobsTests(unittest.TestCase):
    def test_platform_fairness_prevents_old_backlog_from_hiding_other_providers(self):
        cfg={'providers':{p:{'balance':{'concurrency':16}} for p in ('loomy','raccoon')}}
        first=dict(id='l',account='l',provider='loomy',action='balance',origin='post_checkin',created=1000,dispatch_rank=1)
        old=dict(first,id='r',provider='raccoon',created=1,dispatch_rank=20)
        self.assertLess(dispatch_order(first,{}, {},cfg),dispatch_order(old,{}, {},cfg))
    def test_indexed_latest_matches_window_with_timestamp_ties_and_out_of_order_inserts(self):
        c=sqlite3.connect(':memory:');self.addCleanup(c.close);c.row_factory=sqlite3.Row
        c.execute('create table jobs(account,action,created,status)')
        c.executemany('insert into jobs values(?,?,?,?)',[('a','balance',3,'ok'),('a','balance',1,'old'),('a','balance',3,'new'),('a','checkin',2,'sign'),('b','checkin',0,'ok')])
        for per_action in (False,True):
            keys='account,action' if per_action else 'account'
            expected=[tuple(r)[:4] for r in c.execute(f'select *,row_number() over(partition by {keys} order by created desc,rowid desc) rn from jobs') if r['rn']==1]
            self.assertEqual(sorted(tuple(r) for r in latest_jobs(c,per_action)),sorted(expected))

if __name__=='__main__':unittest.main()

