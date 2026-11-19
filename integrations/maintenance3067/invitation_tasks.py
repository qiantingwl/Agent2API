"""Durable one-time invitation binding. Unknown submissions are read back only."""
import json
from direct_clients import Client, UpstreamError

DEFAULT_INVITATION={'enabled':False,'paused':False,'concurrency':1,'interval':3600,'route':'direct'}

class InvitationTasks:
    def __init__(self,db,encode,decode,direct,snapshot,now,queue_balance,client=Client):
        self.db,self.encode,self.decode,self.direct,self.snapshot,self.now,self.queue_balance,self.client=db,encode,decode,direct,snapshot,now,queue_balance,client
        self.donor_cursor=0
        with db() as c:
            c.execute('create table if not exists invitation_state(account text primary key,status text not null,data text not null,updated integer not null,next_at integer not null default 0)')
            c.execute('create table if not exists ledger(key text primary key,value text not null)')
            c.execute('create table if not exists invitation_followups(account text primary key,required_after integer not null,status text not null)')

    def states(self):
        with self.db() as c:return {r[0]:{'status':r[1],'nextAt':r[2],'updatedAt':r[3]} for r in c.execute('select account,status,next_at,updated from invitation_state')}

    def read(self,aid):
        with self.db() as c:r=c.execute('select status,data from invitation_state where account=?',(aid,)).fetchone()
        return (r[0],self.decode(r[1])) if r else ('unknown',{})

    def save(self,aid,status,data,delay=0):
        with self.db() as c:
            # A confirmed binding is permanent; neither failures nor later polls erase it.
            c.execute('insert into invitation_state values(?,?,?,?,?) on conflict(account) do update set status=excluded.status,data=excluded.data,updated=excluded.updated,next_at=excluded.next_at where invitation_state.status != \'bound\'',(aid,status,self.encode(data),self.now(),self.now()+delay))

    def confirm(self,aid,uid,followup=False):
        """Commit official proof before any fallible downstream queue operation."""
        at=self.now();data={'uid':uid,'confirmedAt':at,'source':'official_readback'}
        with self.db() as c:
            c.execute('insert into invitation_state values(?,?,?,?,0) on conflict(account) do update set status=excluded.status,data=excluded.data,updated=excluded.updated,next_at=0 where invitation_state.status != \'bound\'',(aid,'bound',self.encode(data),at))
            key='direct:'+aid+':invitation';old=c.execute('select value from ledger where key=?',(key,)).fetchone()
            if not old or self.decode(old[0]).get('activated') is not True:
                c.execute('insert or replace into ledger values(?,?)',(key,self.encode({'activated':True,'confirmed':True,'at':at})))
            if followup:c.execute("insert or ignore into invitation_followups values(?,?,'pending')",(aid,at))
        self.flush_followups()

    def flush_followups(self):
        with self.db() as c:rows=c.execute("select account,required_after from invitation_followups where status='pending'").fetchall()
        for aid,at in rows:
            try:self.queue_balance(aid,'loomy',at)
            except Exception:continue  # Durable receipt survives; planner retries locally.
            with self.db() as c:c.execute("update invitation_followups set status='done' where account=? and required_after=?",(aid,at))

    def summary(self):
        with self.db() as c:
            return {'counts':dict(c.execute('select status,count(*) from invitation_state group by status')),'updatedAt':c.execute('select max(updated) from invitation_state').fetchone()[0] or 0}

    def donor(self,aid,uid,proxy,timeout):
        # Bounded read-only search; one invitation job shares the existing global cap.
        rows=[r for r in self.snapshot()['accounts'] if r['provider']=='loomy' and r['id']!=aid and r.get('enabled') and not r.get('needsLogin') and not r.get('maintenancePaused') and (r.get('balance') or 0)>0]
        rows.sort(key=lambda r:(-r.get('lastSuccess',0),r['id']))
        if rows:
            offset=self.donor_cursor%len(rows);rows=rows[offset:]+rows[:offset];self.donor_cursor+=3
        for row in rows[:3]:
            client=None
            try:
                _,_,inv=self.direct.prepare(row['id'])
                if not inv['uid'] or inv['uid']==uid:continue
                client=self.client('loomy',inv['secret'],proxy,min(timeout,10))
                if (client.balance().get('available') or 0)<=0:continue
                data=client.loomy('/api/v1/invitation-codes')
                for code in data.get('list',[]):
                    if not isinstance(code,dict):continue
                    left=int(code.get('maxUses') or 0)-int(code.get('usedCount') or 0)
                    value=str(code.get('inviteCode') or '').strip()
                    if value and len(value)<=128 and not any(ch.isspace() for ch in value) and left>0 and str(code.get('status','')).lower() not in ('expired','exhausted','disabled'):
                        return value
            except Exception:continue
            finally:
                if client:client.close()
        return None

    def execute(self,job,proxy=None,timeout=30):
        aid=job['account'];status,saved=self.read(aid)
        if status=='bound':return {'status':'skipped','message':'已有绑定证据，跳过查询与绑定'}
        client=None;submitted=status in ('submitted','verifying')
        try:
            _,_,inv=self.direct.prepare(aid)
            if not inv.get('uid'):raise ValueError('Missing account identity')
            client=self.client('loomy',inv['secret'],proxy,timeout)
            state=client.loomy('/api/v1/points/activation')
            if state.get('activated') is True:
                self.confirm(aid,inv['uid'],submitted)
                return {'status':'ok','message':'已确认绑定，今后不再查询；新绑定余额补查已安排' if submitted else '已确认绑定，今后不再查询'}
            if state.get('activated') is not False:raise UpstreamError('Activation state unknown')
            if submitted:
                self.save(aid,'verifying',saved,3600000)
                return {'status':'unconfirmed','message':'历史提交尚未确认，仅回查，不重复绑定'}
            code=self.donor(aid,inv['uid'],proxy,timeout)
            if not code:
                self.save(aid,'waiting_donor',{'uid':inv['uid']},3600000)
                return {'status':'unconfirmed','message':'暂未找到有余额且邀请码可用的其他账户，稍后重查'}
            # Recheck immediately before submission; unknown values never authorize a POST.
            state=client.loomy('/api/v1/points/activation')
            if state.get('activated') is True:
                self.confirm(aid,inv['uid'])
                return {'status':'ok','message':'账号已绑定，保留现状并永久跳过'}
            if state.get('activated') is not False:raise UpstreamError('Activation state unknown')
            saved={'uid':inv['uid'],'code':code,'submittedAt':self.now()}
            self.save(aid,'submitted',saved,3600000) # Must commit BEFORE the irreversible request.
            submitted=True
            body={'inviteCode':code}
            if inv['secret'].get('devid'):body['deviceId']=inv['secret']['devid']
            try:client.loomy('/api/v1/points/activation',body)
            except Exception:pass # Response loss is ambiguous; read back, never blindly replay.
            state=client.loomy('/api/v1/points/activation')
            if state.get('activated') is True:
                self.confirm(aid,inv['uid'],True)
                return {'status':'ok','message':'绑定已回查确认，后续永久跳过；余额补查已安排'}
            self.save(aid,'verifying',saved,3600000)
            return {'status':'unconfirmed','message':'绑定尚未确认，后续仅回查，不重复提交'}
        except Exception as exc:
            self.save(aid,'verifying' if submitted else 'retry',saved,86400000 if '401' in str(exc) else 3600000)
            raise
        finally:
            if client:client.close()
