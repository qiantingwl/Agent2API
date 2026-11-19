"""Durable maintenance receipts and independently retried deliveries to Agent2API."""
import datetime, hashlib, json, math, threading, time, urllib.error
from direct_clients import Unsupported
from ag_wps_client import Client, pending_wps_models
from maintenance_state import credential_version
from unified_sync import source_record, auth_token, millis

SKELETON={'id','provider','name','source','priority','enabled','addedAt','updatedAt','rateLimits',
    'upstreamCooldownUntil','upstreamBlockedReason','limiterGroups','limiters','lowBalance','checkinAt',
    'streakDays','claimAt','claimPlanId','claimPlans','needsRelogin','needsReloginReason','nameCustom',
    'pluginIdentity','pluginIdentityContract','pluginState','usageQuery','userAgent'}

def secret_of(data):
    if isinstance(data.get('pluginSecret'),dict):return data['pluginSecret']
    return {k:v for k,v in data.items() if k not in SKELETON and not k.startswith('pluginLedger.')}

def fingerprint(secret):
    return hashlib.sha256(json.dumps(secret,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

class DeliveryPending(RuntimeError):pass

def confirmed_day_key(account, timestamp):
    day=datetime.datetime.fromtimestamp(timestamp/1000,datetime.timezone(datetime.timedelta(hours=8))).date().isoformat()
    return 'daily-confirmed:'+day+':'+account

class DirectMaintenance:
    def __init__(self,db,encode,decode,account,official,now,event,queue_balance):
        self.db,self.encode,self.decode,self.account,self.official=db,encode,decode,account,official
        self.now,self.event,self.queue_balance=now,event,queue_balance
        self.delivery_lock=threading.Lock()
        self.mirror_lock=threading.Lock()
        with db() as c:
            c.executescript('''
              CREATE TABLE IF NOT EXISTS direct_inventory(account TEXT PRIMARY KEY,version TEXT NOT NULL,data TEXT NOT NULL,updated INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS direct_targets(identity TEXT PRIMARY KEY,data TEXT NOT NULL,updated INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS direct_results(id TEXT PRIMARY KEY,account TEXT NOT NULL,action TEXT NOT NULL,payload TEXT NOT NULL,created INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS direct_outbox(result TEXT,target TEXT,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_at INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',PRIMARY KEY(result,target));
              CREATE TABLE IF NOT EXISTS direct_renewals(account TEXT,version TEXT,status TEXT NOT NULL,updated INTEGER NOT NULL,PRIMARY KEY(account,version));
            ''')

    def target(self,p,uid):
        return None  # AG is the sole inventory and receipt target.

    def credential_block_reason(self,row,data):
        """Read-only eligibility; re-evaluated when credentials or inventory change."""
        secret=secret_of(data);p=row['provider']
        with self.db() as c:
            attempted=c.execute('select 1 from direct_renewals where account=? and version=?',(row['id'],fingerprint(secret))).fetchone()
        if attempted:return '该版本凭证已尝试续期，等待已保存结果同步或新凭证'
        return ''


    def ledger(self,aid,key,value=None):
        key='direct:'+aid+':'+key
        with self.db() as c:
            if value is not None:c.execute('insert or replace into ledger values(?,?)',(key,self.encode(value)));return value
            row=c.execute('select value from ledger where key=?',(key,)).fetchone()
        return self.decode(row[0]) if row else None

    def client_ledger(self,aid,provider,secret,key,value=None):
        saved=self.ledger(aid,key,value)
        if value is not None or saved is not None:return saved
        # Imported WPS accounts retain their source ID and original auth object.
        # A legacy intent proves only that a claim was attempted, never success.
        prefix='wps-claim-intent:'
        if provider=='wps-lingxi' and aid.startswith('mirai:') and key.startswith(prefix):
            day=key[len(prefix):]
            try:valid_day=datetime.date.fromisoformat(day).isoformat()==day
            except ValueError:valid_day=False
            if valid_day:
                legacy='wps-claim:'+aid[len('mirai:'):]+':'+day+':'+fingerprint(secret)
                with self.db() as c:
                    row=c.execute('select 1 from ledger where key=?',(legacy,)).fetchone()
                if row:return {'started':True,'legacy':True}
        return None

    def prepare(self,aid):
        row,data=self.account(aid);expect=secret_of(data);secret=dict(expect)
        src=source_record(row,data);target=self.target(row['provider'],src['uid'])
        value={'provider':row['provider'],'uid':src['uid'],'expect':expect,'secret':secret,'target':target}
        with self.db() as c:c.execute('insert or replace into direct_inventory values(?,?,?,?)',(aid,fingerprint(expect),self.encode(value),self.now()))
        return row,data,value

    def execute(self,job,proxy=None,timeout=30):
        if job['action']!='credential':return self._execute(job,proxy,timeout)
        lease={'account':job['account'],'provider':job['provider'],'owner':job['id']}
        try:
            reply=self.official().call('/api/external-maintenance/lease',lease)
            if reply.get('acquired') is not True:raise DeliveryPending('等待原程序释放账户后再续期')
        except urllib.error.HTTPError as e:
            if e.code==423:raise DeliveryPending('账户有原程序操作，稍后续期') from None
            raise
        try:return self._execute(job,proxy,min(timeout,60),lease)
        finally:
            # Persisted results retain the lease until the gateway acknowledges;
            # the durable delivery worker retries without consuming another token.
            with self.db() as c:
                row=c.execute("select status from direct_outbox where result=? and target='gateway'",(job['id'],)).fetchone()
            if not row or row[0] in ('done','conflict'):
                try:self.official().call('/api/external-maintenance/lease',{**lease,'release':True})
                except Exception:pass # Server expiry releases abandoned reservations.

    def _execute(self,job,proxy=None,timeout=30,lease=None):
        jid,aid,p,a=job['id'],job['account'],job['provider'],job['action']
        with self.db() as c:existing=c.execute('select payload from direct_results where id=?',(jid,)).fetchone()
        if existing:
            self.deliver(jid,include_mirror=False)
            return {'status':'ok','message':'已完成结果重新投递，没有重复访问上游','credentialVersion':credential_version(self.decode(existing[0])['gateway']['expect'])}
        if a=='checkin':
            with self.db() as c:confirmed=c.execute('select 1 from ledger where key=?',(confirmed_day_key(aid,self.now()),)).fetchone()
            if confirmed:return {'status':'skipped','message':'今日签到已有官方确认，不再重复签到；余额独立补查'}
        row,data,inventory=self.prepare(aid);expect=inventory['expect'];s=inventory['secret']
        if p=='wps-lingxi' and a=='recheck':
            models=pending_wps_models(data,s)
            if not models:return {'status':'skipped','message':'没有待验证的 WPS 模型；未发起请求'}
            reply=self.official().call('/api/external-maintenance/wps-recheck',{'account':aid,'model':models[0],'expect':expect})
            if reply.get('recovered') is not True:return {'status':'unconfirmed','message':'AG 未确认模型回答，保留恢复门控'}
            return {'status':'ok','message':'AG 已确认该模型返回完整回答','credentialVersion':credential_version(expect)}
        action='balance' if a=='recheck' else a
        if action=='credential':
            counts=self.official().call('/api/external-maintenance/inflight').get('counts',{})
            if isinstance(counts,list):counts=dict(counts)
            if counts.get(aid,0):raise DeliveryPending('账户有转发请求，稍后续期')
            version=fingerprint(expect)
            with self.db() as c:
                c.execute('begin immediate')
                prior=c.execute('select status from direct_renewals where account=? and version=?',(aid,version)).fetchone()
                if prior:raise Unsupported('该版本凭证已尝试续期；等待已保存结果同步或重新导入，避免重复使用刷新令牌')
                c.execute('insert into direct_renewals values(?,?,?,?)',(aid,version,'started',self.now()))
        client=Client(p,s,proxy,timeout,lambda key,value=None:self.client_ledger(aid,p,s,key,value))
        observed=self.now()
        payload={'account':aid,'provider':p,'action':action,'requestId':jid,'observedAt':observed,'expect':expect}
        try:
            if action=='balance':
                usage=client.balance()
                amount=usage.get('available') if isinstance(usage,dict) else None
                valid=isinstance(amount,(int,float)) and not isinstance(amount,bool) and math.isfinite(amount)
                if not isinstance(usage,dict) or not (valid or usage.get('unlimited') is True):
                    raise ValueError('上游未返回有效余额，保留原观测')
                payload['usage']=usage
            elif action=='checkin':
                claim=client.checkin(verify_only=job.get('attempt',0)<0)
                if not claim.get('confirmed'):return {'status':'unconfirmed','message':'上游尚未确认今日签到到账，保留旧状态'}
                payload['confirmed']=True
                # Retain the original observation day across retries and midnight.
                payload['observedAt']=observed
            elif action=='credential':payload['secret']=client.renew()
            else:raise Unsupported('当前操作未接管')
        finally:client.close()
        result={'gateway':payload,'lease':lease,'completedAt':self.now()}
        with self.db() as c:
            c.execute('begin immediate')
            c.execute('insert into direct_results values(?,?,?,?,?)',(jid,aid,action,self.encode(result),self.now()))
            if action=='checkin' and payload.get('confirmed'):
                c.execute('insert or replace into ledger values(?,?)',(confirmed_day_key(aid,payload['observedAt']),str(payload['observedAt'])))
            for target in ('gateway','mirai'):
                c.execute('insert into direct_outbox(result,target,status) values(?,?,?)',(jid,target,'pending' if target=='gateway' else 'not_required'))
            if action=='credential':c.execute("update direct_renewals set status='saved',updated=? where account=? and version=?",(self.now(),aid,version))
        self.deliver(jid,include_mirror=False)
        return {'status':'ok','message':'独立请求完成，AG 已确认接收','credentialVersion':credential_version(expect)}

    def deliver(self,jid,include_mirror=True):
        with self.delivery_lock:
            with self.db() as c:
                row=c.execute('select payload from direct_results where id=?',(jid,)).fetchone()
                out={r['target']:dict(r) for r in c.execute('select * from direct_outbox where result=?',(jid,))}
            if not row:return
            result=self.decode(row[0]);payload=result['gateway']
            for target in ('gateway',):
                item=out.get(target,{})
                if item.get('status') in ('done','conflict','discovery') or item.get('next_at',0)>self.now():continue
                try:
                    if target=='gateway':
                        reply=self.official().call('/api/external-maintenance/apply',payload)
                        if reply.get('applied') is not True:raise RuntimeError('unconfirmed')
                    with self.db() as c:c.execute("update direct_outbox set status='done',error='' where result=? and target=?",(jid,target))
                    out[target]['status']='done'
                    if target=='gateway' and payload['action']=='checkin':self.queue_balance(payload['account'],payload['provider'],max(payload['observedAt'],result.get('completedAt',0)))
                except Exception as e:
                    conflict=target=='gateway' and isinstance(e,urllib.error.HTTPError) and e.code==409
                    with self.db() as c:c.execute('update direct_outbox set status=?,attempts=attempts+1,next_at=?,error=? where result=? and target=?',('conflict' if conflict else 'pending',self.now()+min(300000,5000*2**min(item.get('attempts',0),6)), '凭证或结果已更新，未覆盖' if conflict else '接收端未确认，等待重投',jid,target))
                    if target=='gateway':raise DeliveryPending('结果已安全保存，等待同步；未重复执行上游操作') from None
            if out['gateway'].get('status')=='conflict':raise Unsupported('结果对应的凭证或时间已过期，未覆盖新状态')
            if out['gateway'].get('status')!='done':raise DeliveryPending('结果等待同步')
            if result.get('lease'):
                try:self.official().call('/api/external-maintenance/lease',{**result['lease'],'release':True})
                except Exception:pass



    def run(self,stop):
        while not stop.wait(5):
            try:
                with self.db() as c:ids=[r[0] for r in c.execute("select distinct result from direct_outbox where target='gateway' and status='pending' and next_at<=? limit 16",(self.now(),))]
                for jid in ids:
                    if stop.is_set():return
                    try:self.deliver(jid,include_mirror=False)
                    except DeliveryPending:pass
            except Exception:self.event('result_sync','结果重投暂未完成，将重试')
