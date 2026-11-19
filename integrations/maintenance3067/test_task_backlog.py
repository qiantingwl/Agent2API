import datetime, sqlite3, unittest
from task_backlog import checkin_phase, ordinary_during_sign, task_backlogs

TZ=datetime.timezone(datetime.timedelta(hours=8))
NOW=int(datetime.datetime(2026,11,12,2,tzinfo=TZ).timestamp()*1000)


class TaskBacklogTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(':memory:');self.addCleanup(self.c.close)
        self.c.execute('create table jobs(account,action,created,attempt,status)')
        self.cfg={'providers':{'loomy':{'checkin':{'enabled':True,'concurrency':3,'route':'direct','maxAttempts':3,'retryInterval':1800},'balance':{'enabled':True},'invitation':{'enabled':True}}}}
        self.row=dict(id='a',provider='loomy',supported=True,enabled=True,balanceDetail={'waitingForCheckin':False,'nextEligibleAt':NOW},checkinDetail={'state':'eligible'})

    def phase(self,rows=None,jobs=None,active=None):
        return checkin_phase(rows if rows is not None else [self.row],self.cfg,self.c,NOW,TZ,{'direct'},active or {},jobs or [])

    def test_unqueued_eligible_accounts_keep_sign_phase_active(self):
        self.assertTrue(self.phase())
        self.assertTrue(ordinary_during_sign({'action':'balance','origin':'auto'}))
        self.assertTrue(ordinary_during_sign({'action':'invitation'}))
        self.assertFalse(ordinary_during_sign({'action':'balance','origin':'post_checkin'}))
        self.assertFalse(ordinary_during_sign({'action':'credential'}))

    def test_third_queued_attempt_runs_without_retry_delay(self):
        self.c.executemany('insert into jobs values(?,?,?,?,?)',[('a','checkin',NOW-100,0,'error')]*2+[('a','checkin',NOW,0,'queued')])
        self.assertFalse(self.phase())
        self.assertTrue(self.phase(jobs=[dict(account='a',provider='loomy',action='checkin')]))

    def test_login_cooling_exhaustion_and_unavailable_route_do_not_block_background(self):
        for patch in [dict(needsLogin=True),dict(signed=True),dict(maintenancePaused=True),dict(operationCooldowns={'checkin':NOW+10000})]:
            self.assertFalse(self.phase(rows=[dict(self.row,**patch)]),patch)
        self.cfg['providers']['loomy']['checkin']['route']='offline'
        self.assertFalse(self.phase())
        self.cfg['providers']['loomy']['checkin']['route']='direct'
        self.c.execute("insert into jobs values('a','checkin',?,0,'error')",(NOW-1000,))
        self.assertFalse(self.phase())
        self.assertTrue(self.phase(active={'a':('loomy','checkin')}))

    def test_remaining_counts_whole_backlog_not_only_prefetched_jobs(self):
        rows=[dict(self.row,id=str(i)) for i in range(100)]
        rows.extend([dict(self.row,id='login',needsLogin=True),dict(self.row,id='paused',maintenancePaused=True),dict(self.row,id='running')])
        latest={('0','checkin'):{'status':'queued'},('running','checkin'):{'status':'running'}}
        result=task_backlogs(rows,self.cfg,latest,{},NOW,TZ)['loomy']['checkin']
        self.assertEqual(result['remaining'],100)
        self.assertEqual(result['ready'],100)
        self.assertEqual((result['running'],result['needsLogin'],result['paused']),(1,1,1))

    def test_bound_invitation_excluded_and_future_balance_separate(self):
        rows=[dict(self.row,id='bound',balanceDetail={'waitingForCheckin':False,'nextEligibleAt':NOW+60000}),dict(self.row,id='login',needsLogin=True)]
        b=task_backlogs(rows,self.cfg,{}, {'bound':{'status':'bound'}},NOW,TZ)['loomy']
        self.assertEqual(b['invitation']['remaining'],0)
        self.assertEqual(b['invitation']['needsLogin'],1)
        self.assertEqual((b['balance']['remaining'],b['balance']['scheduled']),(1,1))


if __name__=='__main__':unittest.main()
