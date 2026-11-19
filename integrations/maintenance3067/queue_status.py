"""Small consistent queue counters, independent of account/history projections."""
import threading
import time
from collections import Counter


def read_queue_status(db, timestamp):
    with db() as c:
        rows=c.execute("""select provider,action,status,
            case when status='running' then 'running'
                 when not_before>? then 'scheduled' else 'ready' end timing,
            count(*) total from jobs
            where status in ('queued','running')
              and provider in ('loomy','raccoon','codearts','wps-lingxi')
            group by provider,action,status,timing""",(timestamp,)).fetchall()
    grouped={};timing=[]
    for provider,action,status,phase,total in rows:
        key=(provider,action,status);grouped[key]=grouped.get(key,0)+total
        timing.append({'provider':provider,'action':action,'state':phase,'total':total})
    pending=[{'provider':p,'action':a,'status':s,'attempts':n} for (p,a,s),n in grouped.items()]
    return {'at':timestamp,'pending':pending,'queueTiming':timing}


class QueueStatus:
    def __init__(self, db, now):
        self.db=db;self.now=now;self.lock=threading.Lock();self.cached=None;self.until=0

    def read(self):
        with self.lock:
            if self.cached is not None and time.monotonic()<self.until:return self.cached
            # Failed reads propagate; they must never publish fabricated zeroes.
            result=read_queue_status(self.db,self.now())
            self.cached=result;self.until=time.monotonic()+1
            return result



def project_queue_status(jobs, timestamp):
    counts = Counter((j['provider'], j['action'], j['status']) for j in jobs)
    timing = Counter((j['provider'], j['action'], 'running' if j['status']=='running'
                     else 'scheduled' if (j.get('not_before') or 0)>timestamp else 'ready') for j in jobs)
    return {'at':timestamp,
            'pending':[{'provider':p,'action':a,'status':s,'attempts':n} for (p,a,s),n in counts.items()],
            'queueTiming':[{'provider':p,'action':a,'state':s,'total':n} for (p,a,s),n in timing.items()]}
