"""Durable recovery of the reported account; no SMS or account-switch writes."""
import collections
import datetime
import secrets
from direct_maintenance import confirmed_day_key
from relogin_records import day_start

ACTIVE_PHASES = {'pending', 'identity_wait', 'checkin_queued', 'balance_queued', 'delivery_wait', 'retry_wait'}
LABELS = {'pending':'等待核对账户', 'identity_wait':'账户关联待核对',
          'checkin_queued':'重登后待签到', 'balance_queued':'重登后待查余额',
          'delivery_wait':'余额已查询，等待 AG 回写', 'retry_wait':'核验暂时失败，等待重试',
          'verified':'原账户已核验恢复', 'verification_failed':'新凭证核验失败',
          'failed_again':'恢复后再次失效', 'paused':'等待维护恢复'}


def init(c):
    c.execute('create table if not exists relogin_recovery_outcomes(account text,report_at integer,outcome text,updated integer,primary key(account,report_at))')
    c.execute('''create table if not exists relogin_recoveries(
        account text primary key, report_at integer not null, provider text not null,
        target text not null default '', phase text not null default 'pending',
        version text not null default '', required_after integer not null,
        job text not null default '', updated integer not null, next_at integer not null default 0,
        error text not null default '')''')


def records(c):
    return {r['account']:dict(r) for r in c.execute('select * from relogin_recoveries')}


def verified(row, required):
    return bool(row and row.get('authStatus') == 'verified' and not row.get('needsLogin')
                and not row.get('authCredentialChanged') and not row.get('balanceCredentialChanged') and row.get('lastSuccess', 0) >= required)


def select_target(original, inventory, snapshot, required):
    """Only exact provider + official UID, never name/phone suffix or guessed IDs."""
    key = (original['provider'], original['uid'])
    choices = [x for x in inventory.values() if x['id'] != original['id']
               and (x['provider'], x['uid']) == key
               and verified(snapshot.get(x['id']), required-120000)]
    return max(choices, key=lambda x: snapshot[x['id']]['lastSuccess']) if choices else None


class ReloginRecovery:
    def __init__(self, db, now, snapshot, inventory, copy_identity, config, wake, event):
        self.db, self.now, self.snapshot, self.inventory = db, now, snapshot, inventory
        self.copy_identity, self.config, self.wake, self.event = copy_identity, config, wake, event
        with db() as c:init(c)

    def save(self, account, **values):
        values['updated'] = self.now()
        with self.db() as c:
            c.execute('begin immediate')
            c.execute('update relogin_recoveries set '+','.join(k+'=?' for k in values)+' where account=?',
                      (*values.values(), account))
            if values.get('phase') in ('verified','verification_failed'):
                row=c.execute('select report_at from relogin_recoveries where account=?',(account,)).fetchone()
                if row:c.execute('insert into relogin_recovery_outcomes values(?,?,?,?) on conflict(account,report_at) do update set outcome=excluded.outcome,updated=excluded.updated',(account,row[0],values['phase'],self.now()))

    def authorized(self, job, version):
        if job.get('origin') != 'post_relogin':return False
        with self.db() as c:r=c.execute('select * from relogin_recoveries where account=?', (job['account'],)).fetchone()
        return bool(r and r['phase'] in ACTIVE_PHASES and r['version'] == version
                    and job.get('credential_version') == version
                    and job.get('required_after', 0) >= r['required_after'])

    def ensure_job(self, account, provider, action, version, required):
        timestamp=self.now()
        with self.db() as c:
            c.execute('begin immediate')
            old=c.execute("select * from jobs where account=? and action=? and status in ('queued','running') order by created limit 1", (account,action)).fetchone()
            if old and old['status']=='running':return old['id']
            jid=old['id'] if old else secrets.token_hex(12)
            if old:
                c.execute("update jobs set origin='post_relogin',priority=110,required_after=?,credential_version=?,not_before=0,message='重登完成，核验当前凭证与余额' where id=?",(required,version,jid))
            else:
                c.execute("""insert into jobs(id,account,provider,action,status,created,message,attempt,origin,priority,required_after,credential_version,not_before)
                    values(?,?,?,?,'queued',?,'重登完成，核验当前凭证与余额',0,'post_relogin',110,?,?,0)""",(jid,account,provider,action,timestamp,required,version))
            c.execute('update relogin_recoveries set phase=?,version=?,required_after=?,job=?,updated=?,next_at=0,error=? where account=?',
                      (action+'_queued',version,required,jid,timestamp,'',account))
        self.wake()
        return jid

    def after_checkin(self, job):
        with self.db() as c:r=c.execute('select * from relogin_recoveries where account=?', (job['account'],)).fetchone()
        if r and r['version']==job.get('credential_version'):
            self.ensure_job(job['account'],job['provider'],'balance',r['version'],max(r['required_after'],self.now()))

    def seed(self, snapshot):
        with self.db() as c:
            if not c.execute("select 1 from sqlite_master where name='relogin_events'").fetchone():return
            rows=c.execute("select account_id,max(case when at<100000000000 then at*1000 else at end) at from relogin_events where outcome='ok' group by account_id").fetchall()
            for aid,at in rows:
                row=snapshot.get(aid)
                if not row or row.get('provider') not in ('loomy','raccoon'):continue
                c.execute('''insert into relogin_recoveries(account,report_at,provider,required_after,updated) values(?,?,?,?,?)
                    on conflict(account) do update set report_at=excluded.report_at,required_after=excluded.required_after,
                    phase='pending',version='',job='',target='',next_at=0,error='',updated=excluded.updated
                    where excluded.report_at>relogin_recoveries.report_at''', (aid,at,row['provider'],at,self.now()))

    def proof(self, account, version, required):
        with self.db() as c:
            row=c.execute("""select j.id,j.ended,g.status gateway from jobs j
                join direct_outbox g on g.result=j.id and g.target='gateway'
                where j.account=? and j.action in ('balance','recheck') and j.status='ok'
                  and j.credential_version=? and j.ended>=? order by j.ended desc limit 1""",
                (account,version,required)).fetchone()
        return dict(row) if row else None

    def reconcile(self, recovery, snapshot, inventory):
        aid=recovery['account'];at=self.now();row=snapshot.get(aid);original=inventory.get(aid)
        if not row or not original:
            self.save(aid,phase='identity_wait',error='原账户或官方身份缺失',next_at=at+300000);return
        cfg=self.config();pc=cfg['providers'].get(row['provider'],{})
        if cfg.get('paused') or row.get('maintenancePaused'):
            self.save(aid,phase='paused',next_at=at+60000);return
        version=original['version'];required=recovery['required_after'];report=recovery['report_at']
        if recovery['phase'] in ('verification_failed','failed_again') and recovery['version']==version:
            self.save(aid,next_at=at+300000);return
        # Never refresh a credential from an older success when its own newer
        # balance was followed by a real authentication failure.
        if row.get('authFailureAt',0)>max(report,row.get('lastSuccess',0)) and row.get('lastSuccess',0)>=report:
            self.save(aid,phase='failed_again',version=version,error='恢复后有较新的登录失败证据',next_at=at+60000);return
        if row.get('lastSuccess',0)<report and not recovery['target']:
            donor=select_target(original,inventory,snapshot,report)
            if donor and donor['version']!=version:
                version=self.copy_identity(original,donor,snapshot[donor['id']])
                # Copy callback confirms same official UID, CAS and readback.
                self.save(aid,target=donor['id'],version=version,required_after=at,phase='pending',next_at=0,error='')
                self.wake();return
        if recovery['version'] and recovery['version']!=version:
            required=at
            self.save(aid,version=version,required_after=required,phase='pending',job='',error='')
        elif not recovery['version']:self.save(aid,version=version)
        # Terminal current-version auth failure is visible, not an endless
        # "success awaiting verification" or an immediate new SMS attempt.
        with self.db() as c:
            failure=c.execute("select ended from jobs where account=? and status='needs_login' and credential_version=? and ended>? order by ended desc limit 1",(aid,version,required)).fetchone()
            job=c.execute('select * from jobs where id=?',(recovery['job'],)).fetchone() if recovery['job'] else None
        if failure:
            self.save(aid,phase='verification_failed',version=version,error='当前凭证的后续核验仍返回登录失效',next_at=at+60000);return
        proof=self.proof(aid,version,required)
        signed=row.get('signed') or not pc.get('checkin',{}).get('enabled')
        if verified(row,required) and proof and signed:
            # Historical mirror rows remain audit data; AG is the only receiver.
            done=proof['gateway']=='done'
            self.save(aid,phase='verified' if done else 'delivery_wait',version=version,job=proof['id'],
                      error='' if done else '等待 AG 余额回写确认',next_at=at+(60000 if done else 10000));return
        if job and job['status'] in ('running','queued'):
            if job['origin']=='post_relogin' and job['credential_version']==version:
                self.save(aid,next_at=at+10000);return
            if job['status']=='running':
                self.save(aid,next_at=at+10000);return
        if job and job['status'] in ('error','cooling','unconfirmed','interrupted') and (job['ended'] or 0)+300000>at:
            self.save(aid,phase='retry_wait',error='维护核验暂时失败，等待退避重试',next_at=job['ended']+300000);return
        action='balance' if signed else 'checkin'
        if not pc.get(action,{}).get('enabled') or pc.get(action,{}).get('paused'):
            self.save(aid,phase='paused',error='等待对应维护项目开启',next_at=at+60000);return
        if action=='checkin':
            with self.db() as c:attempts=c.execute("select count(*) from jobs where account=? and action='checkin' and created>=? and credential_version=? and status not in ('cancelled','skipped')",(aid,day_start(at),version)).fetchone()[0]
            if attempts>=pc.get('checkin',{}).get('maxAttempts',3):
                self.save(aid,phase='retry_wait',error='当前凭证今日签到尝试已达上限，等待次日',next_at=day_start(at)+86400000);return
        self.ensure_job(aid,row['provider'],action,version,required)

    def tick(self):
        snapshot={r['id']:r for r in self.snapshot()['accounts']};self.seed(snapshot)
        with self.db() as c:rows=[dict(r) for r in c.execute('select * from relogin_recoveries where next_at<=? order by updated limit 12',(self.now(),))]
        if not rows:return
        inventory=self.inventory()
        for row in rows:
            try:self.reconcile(row,snapshot,inventory)
            except Exception as e:
                self.save(row['account'],phase='retry_wait',error='恢复核对暂未完成：'+type(e).__name__,next_at=self.now()+60000)
                self.event('relogin_recovery','恢复核对暂未完成：'+type(e).__name__)

    def run(self, stop):
        while not stop.is_set():
            try:self.tick()
            except Exception as e:self.event('relogin_recovery','恢复任务核对失败：'+type(e).__name__)
            if stop.wait(10):break
