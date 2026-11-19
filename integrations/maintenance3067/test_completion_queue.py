import ast
import contextlib
import pathlib
import secrets
import sqlite3
import threading
import unittest
from maintenance_policy import balance_next_at,balance_waits_for_checkin,credential_meta
from maintenance_state import operation_cooldown
from dashboard import queue_order


class CompletionQueueTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(':memory:');self.c.row_factory=sqlite3.Row
        self.c.execute('''create table jobs(id text,account text,provider text,action text,status text,created integer,message text,attempt integer,origin text,not_before integer default 0,ended integer,started integer,priority integer default 0,required_after integer default 0)''')
        @contextlib.contextmanager
        def db():
            yield self.c
            self.c.commit()
        self.env={'db':db,'secrets':secrets,'balance_next_at':balance_next_at,'balance_waits_for_checkin':balance_waits_for_checkin,'operation_cooldown':operation_cooldown,'LOCK':threading.RLock()}
        module=ast.parse(pathlib.Path('server.py').read_text(encoding='utf-8'))
        names={'schedule_balances','queue_post_checkin_balance','enqueue'}
        for node in module.body:
            if isinstance(node,ast.FunctionDef) and node.name in names:
                exec(compile(ast.Module(body=[node],type_ignores=[]),'server-functions','exec'),self.env)
        self.now=1800000000000
        self.cfg={'providers':{'loomy':{'balance':{'enabled':True,'interval':3600,'positiveInterval':3600}}}}
        self.row={'id':'a','provider':'loomy','supported':True,'balance':10,'lastSuccess':self.now-1000,'lastAttempt':self.now-2000,'cooldownUntil':0,'signed':False,'needsLogin':False}
    def tearDown(self):self.c.close()
    def schedule(self,row=None):self.env['schedule_balances'](self.cfg,{'accounts':[row or self.row]},self.now)
    def test_future_job_exists_before_due_and_is_not_duplicated(self):
        self.schedule();self.schedule()
        rows=self.c.execute('select * from jobs').fetchall()
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['not_before'],self.now+3599000)
        self.assertEqual(self.c.execute("select count(*) from jobs where status='queued' and not_before<=?",(self.now,)).fetchone()[0],0)
    def test_completion_time_not_creation_time_starts_hour(self):
        self.c.execute("insert into jobs(id,account,provider,action,status,created,ended,origin) values('old','a','loomy','balance','ok',?,?, 'auto')",(self.now-500000,self.now-100))
        self.schedule();r=self.c.execute("select * from jobs where status='queued'").fetchone()
        self.assertEqual(r['not_before'],self.now+3599900)
    def test_zero_leaves_periodic_queue_but_sign_success_bypasses_delay(self):
        self.schedule();self.row['balance']=0;self.schedule()
        self.assertEqual(self.c.execute("select count(*) from jobs where status='queued'").fetchone()[0],0)
        self.env['queue_post_checkin_balance']('a','loomy',self.now)
        r=self.c.execute("select * from jobs where status='queued'").fetchone();self.assertEqual(r['not_before'],0);self.assertEqual(r['origin'],'post_checkin')
    def test_sign_promotes_existing_future_row_without_duplicate(self):
        self.schedule();self.env['queue_post_checkin_balance']('a','loomy',self.now)
        r=self.c.execute('select * from jobs').fetchall();self.assertEqual(len(r),1);self.assertEqual(r[0]['not_before'],0)
    def test_manual_refresh_promotes_future_job(self):
        self.schedule();self.env.update(get_snapshot=lambda:{'accounts':[self.row]},now=lambda:self.now)
        result=self.env['enqueue'](['a'],'balance')
        self.assertEqual(result['added'],1);r=self.c.execute('select * from jobs').fetchone();self.assertEqual(r['not_before'],0);self.assertEqual(r['origin'],'manual')
    def test_earliest_due_wins_over_balance_size(self):
        a={'id':'a','account':'a','action':'balance','origin':'auto','created':1,'not_before':10}
        b={**a,'id':'b','account':'b','not_before':20}
        self.assertLess(queue_order(a,{'a':{'balance':0}}),queue_order(b,{'b':{'balance':100}}))
    def test_loomy_requires_saved_password_not_session_only(self):
        self.assertFalse(credential_meta('loomy',{'session':'x'})['credentialRenewable'])
        self.assertTrue(credential_meta('loomy',{'loginid':'p','password':'x'})['credentialRenewable'])

if __name__=='__main__':unittest.main()

