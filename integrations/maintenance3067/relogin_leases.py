"""Durable account claims. Expired work is uncertain, never silently retried."""
import collections
import hashlib
import hmac
import json
import re
from relogin_records import read_book, eligible, save_reports, day_start

TTL = 300000
# Both 5-minute and 10-minute cron workers get scheduling grace.
WORKER_FRESH_MS = 15 * 60 * 1000

def init(c):
    c.execute('create table if not exists relogin_leases(account text primary key,provider text,claim text unique,worker text,state text,created integer,updated integer,expires integer,result_hash text)')
    from relogin_history import init as init_history
    init_history(c)
    if 'identity' not in {r[1] for r in c.execute('pragma table_info(relogin_leases)')}:c.execute("alter table relogin_leases add column identity text not null default ''")
    c.execute('create table if not exists relogin_workers(worker text primary key,provider text,seen integer)')
    if 'detail' not in {r[1] for r in c.execute('pragma table_info(relogin_workers)')}:c.execute("alter table relogin_workers add column detail text not null default '{}'")

def clean(v):
    if not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',v):raise ValueError('invalid_claim')
    return v

def blocked(c):
    return {r[0] for r in c.execute("select account from relogin_leases where state in ('running','uncertain')")}

def claim(c,snap,d,now):
    worker,token=clean(d.get('worker')),clean(d.get('claim'))
    aid=d.get('account');provider=d.get('provider');identity=d.get('identity','')
    if identity and not re.fullmatch(r'[a-f0-9]{64}',identity):raise ValueError('invalid_identity')
    if not isinstance(aid,str) or not aid or len(aid)>256 or provider not in ('loomy','raccoon'):raise ValueError('invalid_claim')
    c.execute('begin immediate')
    c.execute("update relogin_leases set state='uncertain',updated=? where state='running' and expires<=?",(now,now))
    c.execute('insert into relogin_workers(worker,provider,seen) values(?,?,?) on conflict(worker) do update set provider=excluded.provider,seen=excluded.seen',(worker,provider,now))
    row=c.execute('select * from relogin_leases where account=?',(aid,)).fetchone()
    if row and row['claim']==token and row['worker']==worker and row['provider']==provider:
        return {'ok':True,'claimed':row['state']=='running','state':row['state'],'expires':row['expires']}
    if row and row['state'] in ('running','uncertain'):return {'ok':True,'claimed':False,'state':row['state']}
    if row and row['created']>=day_start(now):return {'ok':True,'claimed':False,'state':'daily_account_limit'}
    events,_,given,_=read_book(c)
    if identity:
        from relogin_history import identities
        known=identities(c)
        if aid in known and known[aid]!=identity:raise ValueError('identity_mismatch')
        c.execute('insert into relogin_identity_links values(?,?,?,?,?) on conflict(account) do nothing',(aid,provider,identity,'executor_full_phone',now))
        related=c.execute('select account,state,created from relogin_leases where identity=? and provider=?',(identity,provider)).fetchall()
        if any(r['state'] in ('running','uncertain') or r['created']>=day_start(now) for r in related):return {'ok':True,'claimed':False,'state':'identity_busy_or_daily_limit'}
        aliases={r['account'] for r in related}|{a for a,i in known.items() if i==identity}|{aid};attempts=0
        if any(event['account_id'] in aliases and event['at']>=day_start(now) for event in events):return {'ok':True,'claimed':False,'state':'identity_busy_or_daily_limit'}
        for event in events:
            if event['account_id'] not in aliases:continue
            if event['outcome']=='ok' and not event.get('recovery_failed'):attempts=0
            else:attempts+=1
        if attempts>=3:return {'ok':True,'claimed':False,'state':'identity_attempt_limit'}
    matches=[r for r in eligible(snap,events,given,now) if r['id']==aid and r['provider']==provider]
    if not matches:return {'ok':True,'claimed':False,'state':'not_eligible'}
    c.execute('insert into relogin_leases(account,provider,claim,worker,state,created,updated,expires,result_hash,identity) values(?,?,?,?,?,?,?,?,?,?) on conflict(account) do update set provider=excluded.provider,claim=excluded.claim,worker=excluded.worker,state=excluded.state,created=excluded.created,updated=excluded.updated,expires=excluded.expires,result_hash=excluded.result_hash,identity=excluded.identity',(aid,provider,token,worker,'running',now,now,now+TTL,'',identity))
    return {'ok':True,'claimed':True,'state':'running','expires':now+TTL}

def heartbeat(c,d,now):
    token,worker=clean(d.get('claim')),clean(d.get('worker'))
    n=c.execute("update relogin_leases set updated=?,expires=? where claim=? and worker=? and state='running' and expires>?",(now,now+TTL,token,worker,now)).rowcount
    if n:c.execute('update relogin_workers set seen=? where worker=?',(now,worker))
    return {'ok':True,'alive':bool(n),'expires':now+TTL if n else None}

def finish(c,d,now,scrub):
    token,worker=clean(d.get('claim')),clean(d.get('worker'))
    result=d.get('result')
    if not isinstance(result,dict) or len(result.get('items',[]))!=1:raise ValueError('one_claim_one_result')
    # Result and lease completion commit together in the caller transaction.
    import json
    digest=hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    c.execute('begin immediate')
    row=c.execute('select * from relogin_leases where claim=? and worker=?',(token,worker)).fetchone()
    if not row or result['items'][0].get('id')!=row['account']:raise ValueError('claim_mismatch')
    if row['state']=='finished':
        if not hmac.compare_digest(row['result_hash'],digest):raise ValueError('conflicting_result')
        return save_reports(c,result,now,scrub,transaction=False)
    if row['state'] not in ('running','uncertain'):raise ValueError('claim_not_active')
    reply=save_reports(c,result,now,scrub,transaction=False)
    c.execute("update relogin_leases set state='finished',updated=?,expires=0,result_hash=? where claim=?",(now,digest,token))
    return reply

def summary(c,now):
    states=collections.Counter()
    for state,expires in c.execute('select state,expires from relogin_leases'):
        states['uncertain' if state=='running' and expires<=now else state]+=1
    active = collections.Counter(r[0] for r in c.execute("select worker from relogin_leases where state='running' and expires>?", (now,)))
    workers = []
    for worker, provider, seen, raw in c.execute('select worker,provider,seen,detail from relogin_workers order by provider'):
        detail = json.loads(raw or '{}')
        age = max(0, now - seen)
        stale = age > WORKER_FRESH_MS
        state = ('running' if active[worker] else 'stale' if stale else
                 'cooldown' if detail.get('coolUntil', 0) > now else 'ready')
        workers.append(dict(detail, provider=provider, lastSeen=seen, ageMs=age,
                            stale=stale, state=state, activeClaims=active[worker]))
    return {'running':states['running'],'uncertain':states['uncertain'],'workers':workers,'protocol':'lease-v1'}


def worker_status(c,d,now):
    worker=clean(d.get('worker'));provider=d.get('provider')
    if provider not in ('loomy','raccoon'):raise ValueError('invalid_provider')
    count,cool=(int(d.get(k,0)) for k in ('count','coolUntil'))
    if min(count,cool)<0 or count>100000:raise ValueError('invalid_worker_status')
    detail={'count':count,'coolUntil':cool,'policy':'per_account_daily_3','state':'cooldown' if cool>now else 'ready'}
    c.execute('insert into relogin_workers(worker,provider,seen,detail) values(?,?,?,?) on conflict(worker) do update set provider=excluded.provider,seen=excluded.seen,detail=excluded.detail',(worker,provider,now,json.dumps(detail)))
    return {'ok':True}


def receipts(c,d):
    worker=clean(d.get('worker'));items=d.get('items')
    if not isinstance(items,list) or len(items)>100:raise ValueError('invalid_receipt_batch')
    out=[]
    for item in items:
        token=clean(item.get('claim'));digest=item.get('digest','')
        if not isinstance(digest,str) or not re.fullmatch(r'[a-f0-9]{64}',digest):raise ValueError('invalid_receipt_digest')
        row=c.execute('select account,state,result_hash from relogin_leases where claim=? and worker=?',(token,worker)).fetchone()
        # A later claim replaces the lease row; its durable result still exists.
        event=c.execute('select 1 from relogin_events where run_id=? limit 1',(token,)).fetchone()
        if row and row['state']=='finished' and row['result_hash']!=digest:state='conflict'
        elif event:state='received'
        elif row and row['state'] in ('running','uncertain','finished'):state='replay'
        else:state='missing_claim'
        out.append({'claim':token,'state':state})
    return {'ok':True,'items':out}
