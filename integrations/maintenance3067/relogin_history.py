"""Historical execution evidence, kept separate from current recovery reports."""
import hashlib
import json

def init(c):
    c.execute('''create table if not exists relogin_identity_links(
        account text primary key,provider text not null,identity text not null,
        source text not null,updated integer not null)''')
    c.execute('''create table if not exists relogin_historical_events(
        evidence text primary key,account text not null,provider text not null,
        identity text not null,outcome text not null,at integer not null,
        source text not null,source_digest text not null,note text not null,
        counted integer not null,imported integer not null)''')
    c.execute('create index if not exists relogin_history_identity on relogin_historical_events(identity,at)')
    c.execute('''create table if not exists relogin_history_imports(
        source text primary key,digest text not null,records integer not null,
        imported integer not null)''')
    c.execute('''create table if not exists relogin_history_unlinked(
        evidence text primary key,provider text,identity text,outcome text,at integer,
        source text,source_digest text,reason text,imported integer)''')

def tables(c):
    return {r[0] for r in c.execute("select name from sqlite_master where type='table'")}

def identities(c):
    names=tables(c);result={}
    if 'relogin_identity_links' in names:
        result={r[0]:r[1] for r in c.execute('select account,identity from relogin_identity_links')}
    if 'relogin_leases' in names:
        columns={r[1] for r in c.execute('pragma table_info(relogin_leases)')}
        if 'identity' in columns:
            for aid,identity in c.execute("select account,identity from relogin_leases where identity<>''"):
                # Persisted verified mapping wins; mismatches are rejected on claim.
                result.setdefault(aid,identity)
    return result

def historical_rows(c):
    if 'relogin_historical_events' not in tables(c):return []
    result=[]
    for i,r in enumerate(c.execute('select * from relogin_historical_events where counted=1 order by at,evidence'),1):
        r=dict(r)
        result.append(dict(id=-i,account_id=r['account'],name='',phone_tail='',outcome=r['outcome'],
            note=r['note'],at=r['at'],run_id='history:'+r['evidence'],historical=True,
            provider=r['provider'],historySource=r['source']))
    return result

def import_evidence(c,bundle,now):
    """Caller owns transaction. Never seed credential recovery from old success."""
    init(c);added=duplicates=0
    for link in bundle['links']:
        aid,provider,identity=link['account'],link['provider'],link['identity']
        old=c.execute('select identity from relogin_identity_links where account=?',(aid,)).fetchone()
        if old and old[0]!=identity:raise ValueError('historical_identity_conflict')
        lease=c.execute('select identity from relogin_leases where account=?',(aid,)).fetchone() if 'relogin_leases' in tables(c) else None
        if lease and lease[0] and lease[0]!=identity:raise ValueError('lease_identity_conflict')
        c.execute('insert into relogin_identity_links values(?,?,?,?,?) on conflict(account) do update set updated=excluded.updated',
                  (aid,provider,identity,'verified_full_phone_target',now))
    known=identities(c)
    live={}
    if 'relogin_events' in tables(c):
        for aid,outcome,at in c.execute('select account_id,outcome,at from relogin_events'):
            if at<100000000000:at*=1000
            live.setdefault((known.get(aid,'account:'+aid),outcome),[]).append(at)
    for r in bundle['events']:
        aid,identity,outcome,at=r['account'],r['identity'],r['outcome'],r['at']
        if known.get(aid,'account:'+aid)!=identity or outcome not in ('ok','fail','other','banned') or not 0<at<=now:
            raise ValueError('invalid_historical_evidence')
        key=hashlib.sha256(json.dumps([r['provider'],identity,outcome,at],separators=(',',':')).encode()).hexdigest()
        # Legacy bridge writes seconds, then the same result is reported in ms.
        # A bounded match is only applied to bridge results, never unrelated logs.
        tolerance=120000 if r['source']=='bridge_results.jsonl' else 1000
        duplicate=any(abs(t-at)<=tolerance for t in live.get((identity,outcome),[]))
        n=c.execute('insert or ignore into relogin_historical_events values(?,?,?,?,?,?,?,?,?,?,?)',
            (key,aid,r['provider'],identity,outcome,at,r['source'],r['source_digest'],
             '历史批次：'+r['label']+'；仅作次数依据，不代表当前凭证已恢复',int(not duplicate),now)).rowcount
        added+=n;duplicates+=not n
    for s in bundle['sources']:
        c.execute('insert into relogin_history_imports values(?,?,?,?) on conflict(source) do update set digest=excluded.digest,records=excluded.records,imported=excluded.imported',
                  (s['source'],s['digest'],s['records'],now))
    for r in bundle.get('unlinked',[]):
        key=hashlib.sha256(json.dumps([r['provider'],r['identity'],r['outcome'],r['at']],separators=(',',':')).encode()).hexdigest()
        c.execute('insert or ignore into relogin_history_unlinked values(?,?,?,?,?,?,?,?,?)',
                  (key,r['provider'],r['identity'],r['outcome'],r['at'],r['source'],r['source_digest'],'未找到可靠账号关联；不猜测计入',now))
    return {'added':added,'duplicates':duplicates,
            'counted':c.execute('select count(*) from relogin_historical_events where counted=1').fetchone()[0],
            'duplicateLiveEvidence':c.execute('select count(*) from relogin_historical_events where counted=0').fetchone()[0],
            'unlinked':c.execute('select count(*) from relogin_history_unlinked').fetchone()[0]}
