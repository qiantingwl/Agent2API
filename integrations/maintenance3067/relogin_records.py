"""Result ledger projections; no SMS, account switches or credential writes."""
import collections
import datetime
import re
import sqlite3
import time

MAX_ATTEMPTS = 3
EXECUTORS = ('loomy', 'raccoon')
OUTCOMES = {'ok', 'fail', 'banned', 'other', 'superseded'}


def stamp_ms(value):
    value = int(value or 0)
    return value * 1000 if 0 < value < 100000000000 else value


def read_book(conn):
    try:
        rows = [dict(r) for r in conn.execute('select id,account_id,name,phone_tail,outcome,note,at,run_id from relogin_events order by id')]
    except sqlite3.OperationalError as exc:
        if 'no such table' in str(exc): rows=[]
        else: raise
    from relogin_history import historical_rows, identities
    identity_map=identities(conn)
    rows.extend(historical_rows(conn))
    groups={}
    for aid,identity in identity_map.items():groups.setdefault(identity,set()).add(aid)
    unique = {}
    for row in rows:
        row['at'] = stamp_ms(row['at'])
        key = (row['account_id'], row['run_id'], row['outcome'], row['at'])
        unique.setdefault(key, row)
    rows = sorted(unique.values(), key=lambda r: (r['at'], r['id']))
    recoveries={}
    if conn.execute("select 1 from sqlite_master where name='relogin_recoveries'").fetchone():
        recoveries={r['account']:dict(r) for r in conn.execute('select * from relogin_recoveries')}
    recovery_outcomes={}
    if conn.execute("select 1 from sqlite_master where name='relogin_recovery_outcomes'").fetchone():
        recovery_outcomes={(r[0],r[1]):r[2] for r in conn.execute('select account,report_at,outcome from relogin_recovery_outcomes')}
    tries, given, merged = {}, set(), set()
    for row in rows:
        aid, outcome = row['account_id'], row['outcome']
        key=identity_map.get(aid,'account:'+aid)
        row['countKey']=key
        row['relatedAccounts']=sorted(groups.get(key,{aid}))
        count = tries.get(key, 0)
        row['attempt'] = count + 1 if outcome in ('ok', 'fail', 'banned', 'other') else None
        recovery=recoveries.get(aid,{})
        row['recovery_failed']=outcome=='ok' and (recovery_outcomes.get((aid,row['at']))=='verification_failed' or recovery.get('report_at')==row['at'] and recovery.get('phase')=='verification_failed')
        if outcome=='ok' and row['recovery_failed']:
            tries[key]=count+1
            if tries[key]>=MAX_ATTEMPTS:given.add(key)
        elif outcome == 'ok':
            tries[key] = 0; given.discard(key); merged.discard(key)
        elif outcome in ('fail', 'banned', 'other'):
            tries[key] = count + 1
            if tries[key] >= MAX_ATTEMPTS or outcome == 'banned': given.add(key)
        elif outcome == 'superseded':
            given.add(key); merged.add(key)
    accounts={r['account_id'] for r in rows}|set(identity_map)
    return rows, {a:tries.get(identity_map.get(a,'account:'+a),0) for a in accounts}, {a for a in accounts if identity_map.get(a,'account:'+a) in given}, {a for a in accounts if identity_map.get(a,'account:'+a) in merged}


def candidates(snap):
    result = []
    for row in snap.get('accounts', []):
        if row.get('maintenancePaused') or not row.get('needsLogin') or row.get('authCredentialChanged'): continue
        if row.get('provider') not in EXECUTORS: continue
        if row['provider'] == 'loomy' and not row.get('authConfirmedFailed'): continue
        result.append(row)
    return sorted(result, key=lambda r: r.get('authFailureAt') or 0)


def day_start(timestamp):
    tz=datetime.timezone(datetime.timedelta(hours=8))
    return int(datetime.datetime.fromtimestamp(timestamp/1000,tz).replace(hour=0,minute=0,second=0,microsecond=0).timestamp()*1000)


def eligible(snap, events, given, timestamp=None):
    start=day_start(timestamp if timestamp is not None else int(time.time()*1000))
    last = {aid:r for r in events for aid in r.get('relatedAccounts',[r['account_id']])}
    successes = {aid:r['at'] for r in events if r['outcome']=='ok' and not r.get('historical') for aid in r.get('relatedAccounts',[r['account_id']])}
    failed_recoveries={r['account_id'] for r in events if r.get('recovery_failed') and r['at']==successes.get(r['account_id'])}
    out = []
    for row in candidates(snap):
        event = last.get(row['id'], {})
        if row['id'] in given or event.get('at',0)>=start: continue
        # A successful executor report awaits independent current-credential
        # verification; stale failure evidence must not buy another SMS.
        success_at = successes.get(row['id'],0)
        if row['id'] not in failed_recoveries and success_at and (success_at >= (row.get('authFailureAt') or 0) or row.get('lastSuccess',0)<success_at): continue
        out.append(row)
    return sorted(out, key=lambda r: (last.get(r['id'], {}).get('at', 0), r.get('authFailureAt') or 0))


def history(snap, book, timestamp, limit, recoveries=None):
    events, tries, given, merged = book
    tz = datetime.timezone(datetime.timedelta(hours=8))
    start = int(datetime.datetime.fromtimestamp(timestamp/1000, tz).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()*1000)
    today = [r for r in events if start <= r['at'] <= timestamp]
    counts = collections.Counter(r['outcome'] for r in today)
    accounts = {r['id']: r for r in snap.get('accounts', [])}
    cand = candidates(snap); ready = eligible(snap, events, given,timestamp)
    latest = {aid:r for r in events for aid in r.get('relatedAccounts',[r['account_id']])}
    success = list({r['account_id']:r for r in events if r['outcome']=='ok' and not r.get('historical')}.values())
    verified = sum(bool((a:=accounts.get(r['account_id'],{})).get('authStatus')=='verified' and not a.get('needsLogin') and not a.get('authCredentialChanged') and a.get('lastSuccess',0)>=r['at']) for r in success)
    items = [dict(r, name=accounts.get(r['account_id'],{}).get('name') or r.get('name') or ('历史账号' if r.get('historical') else ''), provider=accounts.get(r['account_id'],{}).get('provider',r.get('provider',''))) for r in reversed(events[-limit:])]
    summary = {'today':len(today),'todayOk':counts['ok'],'todayOkAccounts':len({r['account_id'] for r in today if r['outcome']=='ok'}),'todayFail':counts['fail'],'todayFailAccounts':len({r['account_id'] for r in today if r['outcome']=='fail'}),'todayBanned':counts['banned'],'todayOther':counts['other'],'todayMerged':counts['superseded'],
        'all':len(events),'allOk':sum(r['outcome']=='ok' for r in events),'pending':len(ready),
        'givenUp':sum(r['id'] in given and r['id'] not in merged for r in cand),'merged':sum(r['id'] in merged for r in cand),
        'unsupported':sum(r.get('needsLogin',False) and r.get('provider') not in EXECUTORS for r in accounts.values()),
        'verifiedRecovered':verified,'reportedSuccessAwaitingVerification':sum(accounts.get(r['account_id'],{}).get('lastSuccess',0)<r['at'] for r in success),
        'maxAttempts':MAX_ATTEMPTS,'retryPolicy':'per-account-once-per-Beijing-day','waitingNextDay':sum(r['id'] not in given and latest.get(r['id'],{}).get('at',0)>=start and latest.get(r['id'],{}).get('outcome')!='ok' for r in cand),'byProvider':dict(collections.Counter(r['provider'] for r in ready)),
        'historicalEvents':sum(bool(r.get('historical')) for r in events),'identityCounting':True,
        'at':timestamp,'windowStart':start,'window':'Asia/Shanghai calendar day','dispatchObserved':False}
    summary['unconnectedProviders'] = [
        {'provider':p,'accounts':sum(bool(r.get('needsLogin')) and r.get('provider')==p for r in accounts.values()),
         'reason':'缺少账号与完整手机号的可靠对应，自动重登未接通' if p=='wps-lingxi' else '尚无该平台的自动重登执行器'}
        for p in sorted({r.get('provider') for r in accounts.values() if r.get('needsLogin') and r.get('provider') not in EXECUTORS})]
    if recoveries is not None:
        from relogin_recovery import ACTIVE_PHASES, LABELS
        phases=collections.Counter(r.get('phase') for r in recoveries.values())
        summary['recoveryPhases']=dict(phases)
        summary['recoveryVerified']=phases['verified']
        summary['recoveryFailed']=phases['verification_failed']+phases['failed_again']
        summary['reportedSuccessAwaitingVerification']=sum(phases[p] for p in ACTIVE_PHASES)+phases['paused']
        for item in items:
            r=recoveries.get(item['account_id'],{})
            if r and not item.get('historical') and r['report_at']>=item['at']:
                item.update(recoveryState=r['phase'],recoveryMessage=LABELS.get(r['phase'],r['phase']),recoveryAt=r['updated'])
    return {'summary':summary,'items':items}


def save_reports(conn, data, timestamp, scrub, transaction=True):
    rows = data.get('items'); run = str(data.get('run') or '')
    if not isinstance(rows,list) or len(rows)>500 or not 1<=len(run)<=128: raise ValueError('invalid_relogin_report')
    normalized=[]
    for row in rows:
        if not isinstance(row,dict): raise ValueError('invalid_relogin_report')
        aid=str(row.get('id') or ''); outcome=row.get('outcome'); at=stamp_ms(row.get('at'))
        if not 1<=len(aid)<=256 or outcome not in OUTCOMES or not 0<at<=timestamp+60000: raise ValueError('invalid_relogin_report')
        tail=re.sub(r'\D','',str(row.get('phone') or ''))[-4:]
        normalized.append((aid,scrub(str(row.get('name') or ''))[:60],tail,outcome,scrub(str(row.get('note') or ''))[:240],at,run))
    if transaction:conn.execute('begin immediate')
    conn.execute('create table if not exists relogin_events(id integer primary key autoincrement,account_id text,name text,phone_tail text,outcome text,note text,at integer,run_id text)')
    saved=0
    for row in normalized:
        aid,_,_,outcome,_,at,run=row
        if conn.execute('select 1 from relogin_events where account_id=? and run_id=? and outcome=? and (at=? or at=?) limit 1',(aid,run,outcome,at,at//1000)).fetchone():continue
        conn.execute('insert into relogin_events(account_id,name,phone_tail,outcome,note,at,run_id) values(?,?,?,?,?,?,?)',row);saved+=1
    return {'ok':True,'saved':saved,'duplicates':len(rows)-saved}
