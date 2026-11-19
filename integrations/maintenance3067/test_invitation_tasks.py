import contextlib,json,sqlite3,unittest
from types import SimpleNamespace
from invitation_tasks import InvitationTasks

class InvitationTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(':memory:');self.addCleanup(self.c.close)
        @contextlib.contextmanager
        def db():
            try:yield self.c;self.c.commit()
            except:self.c.rollback();raise
        self.calls=[];self.states=[];self.followups=[];self.post_error=False
        outer=self
        class Client:
            def __init__(self,*args):pass
            def close(self):pass
            def loomy(self,path,body=None):
                outer.calls.append(body)
                if body:
                    assert outer.m.read('a')[0]=='submitted'
                    if outer.post_error:raise TimeoutError('reply lost')
                    return {}
                v=outer.states.pop(0)
                if isinstance(v,Exception):raise v
                return v
        self.m=InvitationTasks(db,json.dumps,json.loads,SimpleNamespace(prepare=lambda aid:({}, {}, {'uid':aid,'secret':{}})),lambda:{'accounts':[]},lambda:1000,lambda *a:self.followups.append(a),Client)
        self.m.donor=lambda *a:'synthetic-code'
        self.job={'account':'a'}
    def test_known_binding_never_queries_even_on_repeat(self):
        self.m.save('a','bound',{})
        self.assertEqual(self.m.execute(self.job)['status'],'skipped');self.assertEqual(self.calls,[])
        self.m.save('a','retry',{});self.assertEqual(self.m.read('a')[0],'bound')
    def test_existing_other_binding_is_permanent(self):
        self.states=[{'activated':True,'appliedInvitationCode':'other'}]
        self.m.execute(self.job);self.m.execute(self.job)
        self.assertEqual(self.calls,[None]);self.assertEqual(self.followups,[])
    def test_success_is_durable_and_queries_balance(self):
        self.states=[{'activated':False},{'activated':False},{'activated':True}]
        self.m.execute(self.job);self.m.execute(self.job)
        self.assertEqual(sum(x is not None for x in self.calls),1)
        self.assertEqual(len(self.followups),1);self.assertEqual(self.m.read('a')[0],'bound')
    def test_ambiguous_submit_never_reposts_after_restart(self):
        self.post_error=True;self.states=[{'activated':False},{'activated':False},TimeoutError('read failed')]
        with self.assertRaises(TimeoutError):self.m.execute(self.job)
        self.assertEqual(self.m.read('a')[0],'verifying')
        self.states=[{'activated':False}];self.m.execute(self.job)
        self.assertEqual(sum(x is not None for x in self.calls),1)
        self.states=[{'activated':True}];self.m.execute(self.job)
        self.assertEqual(self.m.read('a')[0],'bound')
    def test_unknown_activation_never_submits(self):
        self.states=[{}]
        with self.assertRaises(Exception):self.m.execute(self.job)
        self.assertEqual(self.calls,[None])
    def test_binding_that_races_our_precheck_is_preserved(self):
        self.states=[{'activated':False},{'activated':True}]
        self.m.execute(self.job);self.assertEqual(self.calls,[None,None]);self.assertEqual(self.m.read('a')[0],'bound')
    def test_no_donor_defers_without_submission(self):
        self.m.donor=lambda *a:None;self.states=[{'activated':False}]
        self.m.execute(self.job);self.assertEqual(self.m.read('a')[0],'waiting_donor');self.assertEqual(self.calls,[None])
    def test_balance_queue_failure_does_not_lose_pending_submission(self):
        self.states=[{'activated':False},{'activated':False},{'activated':True}]
        self.m.queue_balance=lambda *a:(_ for _ in ()).throw(sqlite3.OperationalError('busy'))
        with self.assertRaises(sqlite3.OperationalError):self.m.execute(self.job)
        self.assertEqual(self.m.read('a')[0],'verifying')
    def test_failed_submission_receipt_prevents_post(self):
        self.states=[{'activated':False},{'activated':False}]
        original=self.m.save
        def save(a,s,d,delay=0):
            if s=='submitted':raise sqlite3.OperationalError('busy')
            return original(a,s,d,delay)
        self.m.save=save
        with self.assertRaises(sqlite3.OperationalError):self.m.execute(self.job)
        self.assertEqual(self.calls,[None,None])

if __name__=='__main__':unittest.main()
