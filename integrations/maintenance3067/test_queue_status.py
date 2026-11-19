import contextlib,sqlite3,unittest
from unittest.mock import patch
from queue_status import QueueStatus,read_queue_status

class QueueStatusTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(':memory:');self.addCleanup(self.c.close)
        self.c.execute('create table jobs(provider,action,status,not_before)')

    @contextlib.contextmanager
    def db(self):yield self.c

    def test_one_snapshot_counts_due_future_and_running(self):
        self.c.executemany('insert into jobs values(?,?,?,?)',[
            ('loomy','balance','queued',99),('loomy','balance','queued',101),
            ('raccoon','checkin','running',0),('raccoon','balance','ok',0),
            ('other','balance','queued',0)])
        result=read_queue_status(self.db,100)
        self.assertEqual(sum(r['attempts'] for r in result['pending'] if r['status']=='queued'),2)
        self.assertEqual({r['state']:r['total'] for r in result['queueTiming']},{'ready':1,'scheduled':1,'running':1})

    def test_actual_zero_is_valid_but_failed_read_never_becomes_zero(self):
        cached=QueueStatus(self.db,lambda:100)
        self.c.execute("insert into jobs values('loomy','balance','running',0)")
        first=cached.read();self.assertEqual(first['pending'][0]['attempts'],1)
        cached.until=0
        with patch('queue_status.read_queue_status',side_effect=sqlite3.OperationalError('busy')):
            with self.assertRaises(sqlite3.OperationalError):cached.read()
        self.assertEqual(cached.cached,first)
        self.c.execute('delete from jobs');cached.until=0
        self.assertEqual(cached.read()['pending'],[])

    def test_read_cache_expires_without_waiting_for_account_snapshot(self):
        q=QueueStatus(self.db,lambda:100);q.read()
        self.c.execute("insert into jobs values('loomy','balance','running',0)")
        self.assertEqual(q.read()['pending'],[])
        q.until=0
        self.assertEqual(q.read()['pending'][0]['attempts'],1)

if __name__=='__main__':unittest.main()

