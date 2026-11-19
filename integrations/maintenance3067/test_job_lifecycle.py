import ast
import contextlib
import pathlib
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from job_lifecycle import persist_job_outcome, reconcile_completed_balances


SCHEMA = """create table jobs(id text primary key,account text,action text,status text,
 started integer,ended integer,not_before integer,message text);
 create table cooldowns(scope text,reason text);
 create table direct_results(id text,account text,action text,created integer);
 create table direct_outbox(result text,target text,status text);"""


class JobLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.c = sqlite3.connect(':memory:')
        self.addCleanup(self.c.close)
        self.c.executescript(SCHEMA)

    @contextlib.contextmanager
    def db(self):
        try:
            yield self.c
            self.c.commit()
        except Exception:
            self.c.rollback()
            raise

    def add(self, aid='a', status='running', action='balance', targets=('gateway','mirai'), message='', account=None):
        self.c.execute('insert into jobs values(?,?,?,?,?,?,?,?)', (aid,aid,action,status,100, None,0,message))
        self.c.execute('insert into direct_results values(?,?,?,?)', (aid,account or aid,action,200))
        for target in targets:
            self.c.execute('insert into direct_outbox values(?,?,?)', (aid,target,'done'))
        self.c.commit()

    def wrapper(self, reserved, log=lambda *args:None):
        node=next(n for n in ast.parse(pathlib.Path('server.py').read_text(encoding='utf-8')).body if isinstance(n,ast.FunctionDef) and n.name=='execute')
        env={'execute_reserved':reserved,'event':log,'scrub':str,'sys':sys,'time':time,
             'PROGRESS':{},'LOCK':threading.RLock(),'ACTIVE':{'a':('loomy','balance')},'SNAP':{'expires':time.time()+60}}
        env['SCHEDULER_WAKE']=threading.Event()
        exec(compile(ast.Module(body=[node],type_ignores=[]),'isolated-execute','exec'),env)
        return env

    def test_setup_failure_releases_reservation(self):
        def fail(job):raise sqlite3.OperationalError('database is locked')
        env=self.wrapper(fail)
        with self.assertRaises(sqlite3.OperationalError):env['execute']({'account':'a'})
        self.assertNotIn('a',env['ACTIVE'])

    def test_result_persistence_failure_releases_reservation(self):
        self.add()
        def fail(job):
            self.assertEqual(self.c.execute('select count(*) from direct_outbox where status="done"').fetchone()[0],2)
            raise sqlite3.OperationalError('database is locked')
        env=self.wrapper(fail)
        with self.assertRaises(sqlite3.OperationalError):env['execute']({'account':'a'})
        self.assertFalse(env['ACTIVE'])

    def test_nested_followup_keeps_outer_reservation(self):
        env=self.wrapper(lambda job:None)
        env['execute']({'account':'a'},release=False)
        self.assertIn('a',env['ACTIVE'])
        env['execute']({'account':'a'})
        self.assertFalse(env['ACTIVE'])

    def test_sqlite_busy_retries_same_result_without_upstream(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'state.db'
            with sqlite3.connect(path) as c:
                c.executescript(SCHEMA)
                c.execute("insert into jobs values('a','a','balance','running',100,null,0,'')")
            c.close()
            blocker=sqlite3.connect(path)
            blocker.execute('begin immediate')
            @contextlib.contextmanager
            def db():
                conn=sqlite3.connect(path,timeout=0)
                try:
                    yield conn
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                finally:conn.close()
            delays=[]
            def unlock(delay):delays.append(delay);blocker.rollback()
            try:persist_job_outcome(db,{'id':'a','account':'a','action':'balance'},'ok','complete',300,unlock)
            finally:blocker.close()
            self.assertEqual(len(delays),1)
            with db() as c:self.assertEqual(c.execute('select status,ended from jobs').fetchone(),('ok',300))

    def test_other_sql_errors_are_not_retried(self):
        self.c.execute('drop table cooldowns');self.c.commit();delays=[]
        with self.assertRaises(sqlite3.OperationalError):persist_job_outcome(self.db,{'id':'a','account':'a','action':'balance'},'ok','',300,delays.append)
        self.assertEqual(delays,[])

    def test_reconcile_requires_complete_matching_balance_and_no_owner(self):
        self.add('complete');self.add('active');self.add('partial',targets=('mirai',))
        self.add('credential',action='credential');self.add('mismatch',account='other')
        self.assertEqual(reconcile_completed_balances(self.db,{'active':('loomy','balance')},200000),1)
        self.assertEqual(self.c.execute("select status,ended from jobs where id='complete'").fetchone(),('ok',200))
        self.assertEqual(self.c.execute("select count(*) from jobs where status='running'").fetchone()[0],4)
        self.assertEqual(reconcile_completed_balances(self.db,{'active':('loomy','balance')},200000),0)

    def test_reconcile_ignores_legacy_mirror_receipt(self):
        for status in ('pending','conflict','not_required'):
            self.add(status)
            self.c.execute("update direct_outbox set status=? where result=? and target='mirai'",(status,status))
        self.add('absent',targets=('gateway',))
        self.c.commit()
        before=list(self.c.execute("select * from direct_outbox where target='mirai' order by result"))
        self.assertEqual(reconcile_completed_balances(self.db,{},200000),4)
        self.assertEqual(self.c.execute("select count(*) from jobs where status='ok'").fetchone()[0],4)
        self.assertEqual(list(self.c.execute("select * from direct_outbox where target='mirai' order by result")),before)

    def test_reconcile_requires_gateway_done_even_when_mirror_done(self):
        self.add('pending');self.add('conflict');self.add('absent',targets=('mirai',))
        for status in ('pending','conflict'):
            self.c.execute("update direct_outbox set status=? where result=? and target='gateway'",(status,status))
        self.c.commit()
        self.assertEqual(reconcile_completed_balances(self.db,{},200000),0)

    def test_recent_completed_job_is_not_touched(self):
        self.add();self.assertEqual(reconcile_completed_balances(self.db,{},1000),0)

    def test_restart_recovery_does_not_override_operator_cancellation(self):
        self.add('restart',status='interrupted',message='服务重启；未自动重试，请人工核对签到结果')
        self.add('cancelled',status='cancelled');self.add('other',status='interrupted',message='manual')
        self.assertEqual(reconcile_completed_balances(self.db,{},200000),1)
        self.assertEqual(self.c.execute("select status from jobs where id='cancelled'").fetchone()[0],'cancelled')

    def test_deferred_delivery_remains_queued(self):
        self.add();persist_job_outcome(self.db,{'id':'a','account':'a','action':'balance'},'queued','delivery pending',300)
        self.assertEqual(self.c.execute('select status,started,ended,not_before from jobs').fetchone(),('queued',None,None,30300))


if __name__=='__main__':unittest.main()
