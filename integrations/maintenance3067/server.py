from relogin_recovery import ReloginRecovery, records as recovery_records, LABELS as RECOVERY_LABELS
from relogin_leases import receipts as relogin_receipts, worker_status, init as init_relogin_leases, claim as claim_relogin, heartbeat as heartbeat_relogin, finish as finish_relogin, summary as lease_summary, blocked as leased_accounts
from direct_maintenance import DirectMaintenance, DeliveryPending, secret_of as direct_secret
from direct_clients import Unsupported
from handoff_crypto import seal as seal_handoff, open_envelope as open_handoff
from proxy_health import AutoProxyHealth, ProxyUnavailable
from node_probe import NodeProbe
import gzip
from ui_support import scope_snapshot, account_page, ProxyHealth, account_pause_details
"""Independent Agent2API maintenance controller. Official provider binary is never patched."""
import sys
import base64, collections, concurrent.futures, contextlib, datetime, hashlib, hmac, http.cookies, http.cookiejar, json, math, os, pathlib, queue, random, re, secrets, signal, sqlite3, subprocess, threading, time, urllib.request, urllib.error, urllib.parse
from dashboard import enrich, queue_order, queue_view, history_view, dispatch_order
from task_backlog import checkin_phase, ordinary_during_sign, checkin_providers, sign_hold, capacity_hold
from maintenance_policy import credential_meta, credential_due, balance_interval, balance_satisfied, balance_waits_for_checkin, balance_next_at
from auth_recheck import resolve_loomy_auth, recheck_allowed, is_capacity_error
from maintenance_state import resolve_auth, credential_version, cooldown_map, cooldown_scopes, operation_cooldown, migrate_cooldowns
from routing_guard import reconcile as reconcile_routing
from unified_sync import UnifiedMaintenance
from forwarding_status import agent_running
from auxiliary_policy import AUX_ACTIONS, DEFAULT_AUX, auxiliary_due
from job_queries import latest_jobs, latest_verifications, VERIFICATION_INDEX

from relogin_records import (MAX_ATTEMPTS as RELOGIN_MAX_ATTEMPTS, EXECUTORS as RELOGIN_EXECUTORS,
    read_book as relogin_book, candidates as relogin_candidates, eligible as relogin_eligible,
    history as relogin_history, save_reports as save_relogin_reports)
from queue_status import QueueStatus
from invitation_tasks import InvitationTasks, DEFAULT_INVITATION
from job_lifecycle import persist_job_outcome, reconcile_completed_balances
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT=pathlib.Path('/state'); ROOT.mkdir(exist_ok=True)
MAIN=pathlib.Path('/gateway/agent2api.db'); KEY=pathlib.Path('/key/account.key').read_bytes(); AES=AESGCM(KEY)
AUTH=json.loads(pathlib.Path('/secrets/auth.json').read_text()); PLUGIN='/official/agent2api-providers'
GATEWAY_URL=os.environ.get('AG_GATEWAY_URL','http://gateway:3065').rstrip('/')
TZ=datetime.timezone(datetime.timedelta(hours=8)); STOP=threading.Event(); LOCK=threading.RLock(); SNAP={}; ACTIVE={}; SESSIONS={}; LOGIN_ATTEMPTS={}
SUPPORTED={'loomy','raccoon','codearts','wps-lingxi'}
BRIDGE_BUSY={}
SCHEDULER_WAKE=threading.Event()
HANDOFF_SLOT=threading.BoundedSemaphore(1)
ROUTING={'at':0,'entries':{},'error':'官方调度快照尚未加载','scope':'未指定模型的官方调度队列'}
ROUTING_LOCK=threading.RLock()
FORWARDING={'at':0,'counts':{}}; MIRAI_ROUTING={}
ROUTING_WAKE=threading.Event();ROUTING_REFRESH=threading.Event()
BRIDGE_KEY=pathlib.Path('/secrets/bridge.key').read_text().strip()
def now(): return int(time.time()*1000)
def today(): return datetime.datetime.now(TZ).strftime('%Y-%m-%d')
def dumps(v): return json.dumps(v,ensure_ascii=False,separators=(',',':'))
@contextlib.contextmanager
def db(main=False,ro=False):
 p=MAIN if main else ROOT/'maintenance.db'; c=sqlite3.connect('file:'+str(p)+('?mode=ro' if ro else '?mode=rw') if main else str(p),uri=main,timeout=8);c.row_factory=sqlite3.Row;c.execute('pragma busy_timeout=8000')
 if ro:c.execute('pragma query_only=on')
 try:yield c;c.commit()
 except: c.rollback();raise
 finally:c.close()
with db() as c:init_relogin_leases(c)

def decode(v):
 if not v.startswith('enc1:'):return json.loads(v)
 b=base64.b64decode(v[5:]);return json.loads(AES.decrypt(b[:12],b[12:],None))
def encode(v):
 n=os.urandom(12);return 'enc1:'+base64.b64encode(n+AES.encrypt(n,dumps(v).encode(),None)).decode()
def account(aid):
 with db(True,True) as c:r=c.execute('select * from accounts where id=?',(aid,)).fetchone()
 if not r:raise RuntimeError('账户已不存在')
 return dict(r),decode(r['data'])
def is_agent_account(aid):
 with db(True,True) as c:return c.execute('select 1 from accounts where id=?',(aid,)).fetchone() is not None

def secret_of(d):return direct_secret(d)
def scrub(s):
 s=str(s);s=re.sub(r'https?://\S+','[上游地址]',s);s=re.sub(r'(?i)(bearer\s+|token[=: ]+|auth[=: ]+|session[=: ]+)[^\s,;]+',r'\1[隐藏]',s);s=re.sub(r'[A-Za-z0-9_+/=.-]{40,}','[隐藏]',s)
 return s[:220]
with db() as c:
 c.executescript('''PRAGMA journal_mode=WAL;
 CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,account TEXT,provider TEXT,action TEXT,status TEXT,created INTEGER,started INTEGER,ended INTEGER,message TEXT,proxy TEXT,attempt INTEGER DEFAULT 0);
 CREATE INDEX IF NOT EXISTS jobs_lookup ON jobs(account,action,created);
 CREATE TABLE IF NOT EXISTS cooldowns(scope TEXT PRIMARY KEY,until INTEGER,failures INTEGER,reason TEXT);
 CREATE TABLE IF NOT EXISTS proxies(id TEXT PRIMARY KEY,label TEXT,secret TEXT,enabled INTEGER);
 CREATE TABLE IF NOT EXISTS ledger(key TEXT PRIMARY KEY,value TEXT);
 CREATE TABLE IF NOT EXISTS events(ts INTEGER,kind TEXT,message TEXT);
 CREATE TABLE IF NOT EXISTS bridge_audit(ts INTEGER,account TEXT,provider TEXT,proxy TEXT,status TEXT,duration_ms INTEGER);
 ''')
 columns={row[1] for row in c.execute('pragma table_info(jobs)')}
 for name,decl in [('origin',"TEXT NOT NULL DEFAULT 'manual'"),('priority','INTEGER NOT NULL DEFAULT 0'),('required_after','INTEGER NOT NULL DEFAULT 0'),('credential_version','TEXT'),('not_before','INTEGER NOT NULL DEFAULT 0')]:
  if name not in columns:c.execute('alter table jobs add column '+name+' '+decl)
 c.execute(VERIFICATION_INDEX)
 migrate_cooldowns(c)
 c.execute("update jobs set status='interrupted',ended=?,message='服务重启；未自动重试，请人工核对签到结果' where status='running'",(now(),))
 c.execute('create index if not exists jobs_account_created on jobs(account,created)')
 c.execute('create index if not exists jobs_status_account_ended on jobs(status,account,ended)')
# Preserve the operator's pause setting across restarts.
DEFAULT={'paused':True,'globalConcurrency':2,'timeout':45,'providers':{p:{'concurrency':1,'jitterMin':1,'jitterMax':3,'balance':{'concurrency':1,'enabled':False,'interval':3600,'positiveInterval':21600,'route':'direct'},'checkin':{'concurrency':1,'enabled':False,'interval':86400,'route':'direct'},'credential':{'concurrency':1,'enabled':False,'interval':3600,'route':'direct'}} for p in sorted(SUPPORTED|{'wps-lingxi'})}}
def settings():
 with db() as c:r=c.execute("select value from settings where key='config'").fetchone()
 value=json.loads(r[0]) if r else json.loads(dumps(DEFAULT))
 for p in SUPPORTED:
  if p not in value['providers']:value['providers'][p]=json.loads(dumps(DEFAULT['providers'][p]))
 for a,default in DEFAULT_AUX.items():value['providers']['wps-lingxi'].setdefault(a,dict(default))
 value['providers']['loomy'].setdefault('invitation',dict(DEFAULT_INVITATION))
 value['providers']['loomy']['invitation']['concurrency']=1
 value['providers']['loomy'].setdefault('recheck',dict(DEFAULT_AUX['recheck'],enabled=True,concurrency=1))
 value['providers']['loomy']['recheck']['route']=value['providers']['loomy']['balance']['route']
 value['sharedMaintenanceSlots']=True
 return value
def save_settings(v):
 old=settings();out=json.loads(dumps(old))
 if 'paused' in v:out['paused']=bool(v['paused'])
 for k,lo,hi in [('globalConcurrency',1,64),('globalBalanceConcurrency',1,32),('timeout',10,120),('queueBufferMultiplier',1,5)]:
  if k in v:out[k]=max(lo,min(hi,int(v[k])))
 for p,d in v.get('providers',{}).items():
  if p not in SUPPORTED:continue
  t=out['providers'][p]
  for k,lo,hi in [('concurrency',1,32),('jitterMin',0,60),('jitterMax',0,120)]:
   if k in d:t[k]=max(lo,min(hi,int(d[k])))
  t['jitterMax']=max(t['jitterMax'],t['jitterMin'])
  for a in ['balance','checkin','credential','invitation',*AUX_ACTIONS]:
   if a not in d:continue
   if a=='invitation' and p!='loomy':continue
   if a in AUX_ACTIONS and not (p=='wps-lingxi' or (p=='loomy' and a=='recheck')):continue
   x=d[a];r=t[a]
   if 'enabled' in x:r['enabled']=bool(x['enabled'])
   if 'paused' in x:r['paused']=bool(x['paused'])
   if 'concurrency' in x:r['concurrency']=max(1,min({'balance':16,'checkin':16,'credential':2,'activity':2,'recheck':2,'invitation':1}[a],int(x['concurrency'])))
   if 'interval' in x:r['interval']=max(300,min(604800,int(x['interval'])))
   if 'positiveInterval' in x:r['positiveInterval']=max(300,min(604800,int(x['positiveInterval'])))
   if 'route' in x:
    route=str(x['route'])[:80]
    if (p=='wps-lingxi' or (p=='codearts' and a!='balance') or (p=='loomy' and a=='credential')) and route!='direct':raise ValueError('该操作仅支持直连出口')
    if route not in ('auto','direct') and route!=r.get('route'):
     with db() as c:found=c.execute('select 1 from proxies where id=? and enabled=1',(route,)).fetchone()
     if not found:raise ValueError('固定节点不存在或已停用')
    r['route']=route
   if a=='checkin':
    for k,default in [('start','00:10'),('end','23:00')]:
     if k in x:
      value=str(x[k])
      if not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d',value):raise ValueError('签到时间格式应为 HH:MM')
      r[k]=value
    if r.get('start','00:10')>=r.get('end','23:00'):raise ValueError('签到结束时间必须晚于开始时间')
    if 'maxAttempts' in x:r['maxAttempts']=max(1,min(6,int(x['maxAttempts'])))
    if 'retryInterval' in x:r['retryInterval']=max(300,min(21600,int(x['retryInterval'])))
 with db() as c:c.execute('insert or replace into settings values(?,?)',('config',dumps(out)))
 return out
def event(k,msg):
 with db() as c:c.execute('insert into events values(?,?,?)',(now(),k,scrub(msg)))
class Official:
 def __init__(self):self.lock=threading.Lock();self.op=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.logged=False
 def raw(self,path,body=None):
  req=urllib.request.Request(GATEWAY_URL+path,data=dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json'})
  with self.op.open(req,timeout=75) as r:v=json.load(r)
  if isinstance(v,dict) and v.get('success') is False:raise RuntimeError('官方管理接口拒绝请求')
  return v.get('data',v) if isinstance(v,dict) else v
 def call(self,path,body=None):
  with self.lock:
   if not self.logged:self.raw('/api/panel/login',{'username':AUTH['username'],'password':AUTH['password']});self.logged=True
   try:return self.raw(path,body)
   except urllib.error.HTTPError as e:
    if e.code not in (401,403):raise
    self.logged=False;raise RuntimeError('官方管理登录失效，需要重试登录')
OFFICIAL=Official()
OFFICIAL_THREADS=threading.local()
def official_client():
 if not hasattr(OFFICIAL_THREADS,'client'):OFFICIAL_THREADS.client=Official()
 return OFFICIAL_THREADS.client

UNIFIED=UnifiedMaintenance(db,decode,encode,official_client,event,now,today)

SNAP_BUILD_LOCK=threading.Lock()
def get_snapshot(force=False,allow_stale=False):
 with LOCK:
  data=SNAP.get('data')
  # Dispatch may reuse the existing bounded snapshot while observers rebuild.
  # Execution still reads current credentials and enforces persisted sign receipts.
  if not force and data and (SNAP.get('expires',0)>time.time() or (allow_stale and 0<=now()-data['at']<=30000)):return data
 with SNAP_BUILD_LOCK:return build_snapshot(force)

def build_snapshot(force=False):
 with LOCK:
  if not force and SNAP.get('expires',0)>time.time():return SNAP['data']
 with db(True,True) as c:
  raw=c.execute('select a.id,a.provider,a.enabled,a.data,u.remaining,u.unlimited,u.last_success_at,u.last_attempt_at,u.error from accounts a left join account_usage_records u on a.id=u.account_id').fetchall()
  signed={r[0]:r[1] for r in c.execute('select account_id,max(ts) from checkin_records where date=? and ok=1 group by account_id',(today(),))}
 with db() as c:
  cool={r['scope']:dict(r) for r in c.execute('select * from cooldowns where until>?',(now(),))}
  latest={r['account']:dict(r) for r in latest_jobs(c)}
  auth_failures={r['account']:dict(r) for r in c.execute("select * from (select *,row_number() over(partition by account order by coalesce(ended,created) desc,rowid desc) rn from jobs where status='needs_login') where rn=1")}
  successes={r[0]:r[1] for r in c.execute("select account,max(ended) from jobs where status='ok' group by account")}
  verifications={r['account']:dict(r) for r in latest_verifications(c)}
  guards={r[0].split(':',1)[1]:json.loads(r[1]) for r in c.execute("select key,value from ledger where key like 'routing-guard-v1:%'")}
 rows=[];needs=[]
 for r in raw:
  try:d=decode(r['data'])
  except:continue
  u=d.get('usageQuery');
  if r['provider'] in SUPPORTED and (not isinstance(u,dict) or u.get('enabled') is not False):needs.append(r['id'])
  j=latest.get(r['id'],{})
  success=max(r['last_success_at'] or 0,d.get('checkinAt') or 0,signed.get(r['id'],0),successes.get(r['id']) or 0)
  current_receipt=dict(verifications.get(r['id'],{}),ended=min(verifications.get(r['id'],{}).get('ended') or 0,r['last_success_at'] or 0))
  auth=resolve_auth(bool(d.get('needsRelogin')),auth_failures.get(r['id']),success,credential_version(secret_of(d)),now(),verification=current_receipt)
  if r['provider']=='loomy':
   auth=resolve_loomy_auth(bool(d.get('needsRelogin')),auth_failures.get(r['id']),r['last_success_at'] or 0,credential_version(secret_of(d)),now(),guards.get(r['id']),dict(verifications.get(r['id'],{}),ended=min(verifications.get(r['id'],{}).get('ended') or 0,r['last_success_at'] or 0)))
  receipt=verifications.get(r['id'],{});version=credential_version(secret_of(d))
  changed=bool((receipt.get('credential_version') and receipt['credential_version']!=version) or (not receipt.get('credential_version') and r['last_success_at']))
  auth['balanceCredentialChanged']=changed
  auth['balanceRefreshRequestedAt']=(d.get('updatedAt') or 0) if d.get('upstreamBlockedReason')=='余额待核验：上游返回402' else 0
  operation_cds=cooldown_map(cool,r['id'],r['provider'],auth['authRecovered'] or auth.get('authCredentialChanged',False));cd=max(operation_cds.values())
  rows.append({'id':r['id'],'name':str(d.get('name') or r['id'])[:100],'provider':r['provider'],'enabled':bool(r['enabled']),'balance':r['remaining'],'unlimited':bool(r['unlimited']),'lastSuccess':r['last_success_at'] or 0,'lastAttempt':r['last_attempt_at'] or 0,'error':scrub(r['error'] or ''),'signed':r['id'] in signed,'signedAt':signed.get(r['id'],0),'cooldownUntil':cd,**auth,'operationCooldowns':operation_cds,'supported':r['provider'] in SUPPORTED,'jobStatus':j.get('status',''),'jobMessage':j.get('message',''),'autoBalanceEnabled':r['id'] in needs,**credential_meta(r['provider'],secret_of(d))})
  marker=guards.get(r['id'],{});kind=marker.get('kind') if marker.get('owned') else ''
  manual_pause=not bool(r['enabled'])
  rows[-1].update(home='agent2api',maintenancePaused=manual_pause,pauseReason='3065账户开关已关闭' if manual_pause else '',routingDisabledReason='原程序账户开关已关闭' if manual_pause else '')
  rows[-1].update(account_pause_details(bool(r['enabled']),marker))
  if r['provider']=='wps-lingxi':
   from ag_wps_client import pending_wps_models
   rows[-1]['recheckAllowed']=not manual_pause and bool(pending_wps_models(d,secret_of(d)))
   proof_at=min(receipt.get('ended') or 0,r['last_success_at'] or 0)
   verified=receipt.get('status')=='ok' and receipt.get('credential_version')==version and proof_at>0
   rows[-1].update(verifiedBalanceAt=proof_at if verified else 0,verificationAt=receipt.get('ended') or 0,
       verificationState='ok' if verified else 'needs_login' if auth['needsLogin'] else 'pending')
  if r['provider']=='loomy':
   rows[-1]['recheckAllowed']=recheck_allowed(rows[-1])
   if kind=='login':rows[-1]['routingDisabledReason']='鉴权待复核，验证成功后恢复'
  rows[-1].update(UNIFIED.account_sync_state(r['id']))
  if r['provider']=='loomy':rows[-1].update(UNIFIED.loomy_credential_state(r['id']))
  if rows[-1].get('credentialRenewable'):
   blocked=DIRECT.credential_block_reason(dict(r),d)
   if blocked:rows[-1].update(credentialRenewable=False,credentialReason=blocked)
 native_ids={r['id'] for r in rows}
 rows.extend(dict(r,supported=True) for r in UNIFIED.external_rows(cool,latest,auth_failures,successes) if r['id'] not in native_ids)
 result={'at':now(),'accounts':rows,'summary':{'total':len(rows),'positive':sum((r['balance'] or 0)>0 for r in rows),'knownBalance':sum(r['lastSuccess']>0 for r in rows),'signedToday':sum(r['signed'] for r in rows),'cooling':sum(r['cooldownUntil']>now() for r in rows),'needsLogin':sum(r['enabled'] and r['needsLogin'] for r in rows)},'autoBalanceIds':needs,'sync':UNIFIED.status()}
 with LOCK:SNAP.update(data=result,expires=time.time()+30)
 return result

def select_proxy(route):
 if route=='direct':return None
 rows=HEALTH.candidates(route)
 if not rows:raise ProxyUnavailable('MAINTENANCE_PROXY_WAIT: 无可用维护节点，保留排队；不会回退直连')
 return random.choice(rows)

class WriteConflict(Exception):pass
class RpcError(Exception):
 def __init__(self,obj):self.obj=obj;super().__init__(dumps(obj))
class Worker:
 def __init__(self,aid,proxy,timeout):
  self.aid=aid;self.row,self.initial=account(aid);self.timeout=timeout;self.q=queue.Queue();self.n=0;self.changed=0;self.temp=ROOT/'workers'/secrets.token_hex(10);self.temp.mkdir(parents=True,mode=0o700)
  env=os.environ.copy()
  for k in list(env):
   if 'proxy' in k.lower():env.pop(k,None)
  if proxy:
   val=decode(proxy['secret']);u=urllib.parse.urlsplit(val['url']);host=u.hostname
   if not re.fullmatch(r'[0-9.]+',host or ''):raise RuntimeError('第一版代理地址请填写 IPv4，避免解析歧义')
   user=urllib.parse.unquote(u.username or '');pw=urllib.parse.unquote(u.password or '')
   if any(ch.isspace() for ch in user+pw) or '\n' in user+pw:raise RuntimeError('代理凭证不能含空白字符')
   typ={'http':'http','socks5':'socks5','socks4':'socks4'}.get(u.scheme)
   if not typ or not u.port:raise RuntimeError('仅支持带端口的 HTTP/SOCKS5/SOCKS4 代理')
   config='strict_chain\nquiet_mode\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\n'+f'{typ} {host} {u.port}'+(f' {user} {pw}' if user else '')+'\n'
   cf=self.temp/'proxychains.conf';cf.write_text(config);cf.chmod(0o600);env['LD_PRELOAD']='/usr/lib/x86_64-linux-gnu/libproxychains.so.4';env['PROXYCHAINS_CONF_FILE']=str(cf)
  self.proc=subprocess.Popen([PLUGIN],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1,env=env,cwd=self.temp,start_new_session=True)
  def read():
   try:
    for line in self.proc.stdout:
     try:self.q.put(json.loads(line))
     except:pass
   finally:self.q.put({'_eof':True})
  threading.Thread(target=read,daemon=True).start()
  try:self.rpc('init',{'env':{'data_dir':str(self.temp),'host_version':'3.4.2','target':'x86_64-unknown-linux-gnu','proxy':'','debug_traffic':False}},min(8,timeout))
  except:self.close();raise
 def callback(self,m,p):
  aid=p.get('account',self.aid)
  if m.startswith('store.') and aid and aid!=self.aid:raise RuntimeError('插件越过当前账户范围')
  if m=='store.get':
   r,d=account(self.aid);return {'id':self.aid,'provider':r['provider'],'secret':secret_of(d),'public':d.get('pluginPublic',{})}
  if m=='store.list':return [self.callback('store.get',{'account':self.aid})]
  if m=='store.update':
   with db(True) as c:
    c.execute('begin immediate');r=c.execute('select data from accounts where id=?',(aid,)).fetchone()
    if not r:return {'updated':False}
    d=decode(r[0]);cur=secret_of(d)
    if cur!=p.get('expect'):return {'updated':False}
    if 'pluginSecret' in d:d['pluginSecret']=p['secret']
    else:
     for k in cur:d.pop(k,None)
     d.update(p['secret'])
    if isinstance(p.get('public'),dict):d['pluginPublic']=p['public']
    d['updatedAt']=now();n=c.execute('update accounts set data=? where id=? and data=?',(encode(d),aid,r[0])).rowcount;self.changed+=n;return {'updated':bool(n)}
  if m in ['store.ledger_get','store.ledger_put','settings.get','settings.set']:
   k=dumps([self.row['provider'],aid,p.get('kind'),p.get('key')])
   with db() as c:
    if m.endswith(('get','.get')):
     r=c.execute('select value from ledger where key=?',(k,)).fetchone();return decode(r[0]).get('value') if r else None
    c.execute('insert or replace into ledger values(?,?)',(k,encode({'value':p.get('value')})));return None
  if m in ['log','notify']:return None
  raise RuntimeError('第一版未支持此官方回调：'+m)
 def rpc(self,m,p,timeout=None):
  self.n+=1;n=self.n;self.proc.stdin.write(dumps({'id':n,'method':m,'params':p})+'\n');self.proc.stdin.flush();end=time.monotonic()+(timeout or self.timeout)
  while time.monotonic()<end:
   try:f=self.q.get(timeout=max(.01,end-time.monotonic()))
   except queue.Empty:raise TimeoutError('官方插件调用超时')
   if f.get('_eof'):raise RuntimeError('官方插件进程提前退出')
   if f.get('method'):
    try:r={'id':f.get('id'),'result':self.callback(f['method'],f.get('params') or {})}
    except Exception as e:r={'id':f.get('id'),'error':{'code':-32603,'message':scrub(e)}}
    self.proc.stdin.write(dumps(r)+'\n');self.proc.stdin.flush()
   elif f.get('id')==n:
    if 'error' in f:raise RpcError(f['error'])
    return f.get('result')
  raise TimeoutError('官方插件调用超时')
 def close(self):
  if hasattr(self,'proc'):
   if self.proc.poll() is None:
    try:os.killpg(self.proc.pid,signal.SIGTERM);self.proc.wait(timeout=2)
    except:os.killpg(self.proc.pid,signal.SIGKILL);self.proc.wait()
   for s in [self.proc.stdin,self.proc.stdout]:
    if s:s.close()
  import shutil
  shutil.rmtree(self.temp,ignore_errors=True)

def write_balance(aid,u,attempt_at):
 if not isinstance(u,dict):raise RuntimeError('官方余额响应格式不正确')
 n=u.get('totalLeft',u.get('available'));un=bool(u.get('unlimited'));n=None if un or not isinstance(n,(int,float)) or not math.isfinite(n) else n;t=attempt_at
 with db(True) as c:
  written=c.execute('''INSERT INTO account_usage_records(account_id,usage,error,code,remaining,unlimited,last_success_at,last_attempt_at,updated_at) VALUES(?,?,NULL,NULL,?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET usage=excluded.usage,error=NULL,code=NULL,remaining=excluded.remaining,unlimited=excluded.unlimited,last_success_at=excluded.last_success_at,last_attempt_at=excluded.last_attempt_at,updated_at=excluded.updated_at WHERE account_usage_records.last_attempt_at<=excluded.last_attempt_at''',(aid,dumps(u),n,int(un),t,t,t)).rowcount
  if not written:raise WriteConflict('发现更新的官方余额记录，本次未覆盖')
 return n

def verify_raccoon_daily(w,aid,proxy,day):
 r,d=account(aid);secret=secret_of(d)
 token=secret.get('accessToken') or d.get('accessToken') or ''
 identity=secret.get('officeIdentity') or secret.get('office_identity') or d.get('officeIdentity') or ''
 env=os.environ.copy()
 for k in list(env):
  if 'proxy' in k.lower():env.pop(k,None)
 if proxy:
  cf=w.temp/'proxychains.conf'
  if not cf.exists():raise RuntimeError('账单核对代理配置缺失；禁止回退直连')
  env['LD_PRELOAD']='/usr/lib/x86_64-linux-gnu/libproxychains.so.4';env['PROXYCHAINS_CONF_FILE']=str(cf)
 try:
  process=subprocess.run([sys.executable,'/app/raccoon_ledger.py'],input=dumps({'token':token,'identity':identity,'date':day,'timeout':120}),text=True,capture_output=True,env=env,timeout=130)
 except subprocess.TimeoutExpired:raise TimeoutError('账单核对超时，未确认成功')
 if process.returncode:raise RuntimeError('账单核对进程失败，未确认成功')
 result=json.loads(process.stdout)
 if result.get('error'):raise RuntimeError(result['error'])
 claim=result['claim'];proof=claim.get('evidence',{})
 if claim.get('verifiedDate')!=day or proof.get('date')!=day:raise RuntimeError('账单核对日期不一致，拒绝回写')
 if claim.get('outcome')=='done':
  from raccoon_ledger import daily_grant
  if not any(daily_grant(item,day) for item in proof.get('grants',[])):raise RuntimeError('缺少有效入账证据，拒绝回写')
 with db() as c:c.execute('insert or replace into ledger values(?,?)',('daily-grant-proof:'+day+':'+aid,encode({'value':proof})))
 return claim

def write_checkin(aid,claim):
 if claim.get('verifiedDate') and claim['verifiedDate']!=today():raise WriteConflict('账单核对跨日，未回写到新的一天')
 ok=not claim.get('error') and (claim.get('outcome') in ['claimed','done'] or claim.get('success') is True or claim.get('alreadyCompleted') is True)
 t=now();r,d=account(aid)
 with db(True) as c:
  c.execute('begin immediate')
  if ok:
   row=c.execute('select data from accounts where id=?',(aid,)).fetchone();d=decode(row[0]);d['checkinAt']=t;c.execute('update accounts set data=? where id=? and data=?',(encode(d),aid,row[0]))
  c.execute('insert into checkin_records(ts,date,source,reason,account_id,account_name,provider,outcome,ok,message,error,kept_active) values(?,?,?,?,?,?,?,?,?,?,?,0)',(t,today(),'maintenance-v1','账单核对（未重复领取）' if claim.get('evidence') else '独立容器／官方插件',aid,str(d.get('name',aid))[:100],r['provider'],str(claim.get('outcome','unknown')),int(bool(ok)),scrub(claim.get('message') or claim.get('msg') or ''),None if ok else scrub(claim.get('error') or '官方接口未确认签到完成')))
 return bool(ok)

def cooldown(scope,seconds,reason):
 with db() as c:
  old=c.execute('select failures,until from cooldowns where scope=?',(scope,)).fetchone()
  failures=old[0] if old and old[1]>now() else 0
  seconds=min(86400,seconds*(2**min(failures,5)))
  c.execute('insert into cooldowns values(?,?,1,?) on conflict(scope) do update set until=max(until,excluded.until),failures=case when until>? then failures+1 else 1 end,reason=excluded.reason',(scope,now()+int(seconds*1000),reason,now()))
def classify(e):
 if getattr(e,'status',None)=='needs_login':return 'needs_login','鉴权失败，凭证需要检查或重新登录',3600
 text=str(e).lower()
 if '429' in text or 'rate limit' in text:return 'cooling','上游 429 限流；账户与平台已冷却',900
 if isinstance(e,TimeoutError) or 'timeout' in text or 'timed out' in text or '超时' in text:return 'cooling','请求超时；保留旧余额并冷却',300
 if '401' in text or 'authorization_verify_error' in text or any(s in text for s in ('请重新登录','登录已失效','登录态已过期')):return 'needs_login','鉴权失败，凭证需要检查或重新登录',3600
 if '403' in text:return 'cooling','上游 403；未判定账号失效，已冷却',1800
 return 'error',scrub(e),300

def balance_gate_account(aid):
 # Balance workers need one current row, not a serialized rebuild of every account.
 with db(True,True) as c:
  row=c.execute("select remaining,unlimited,last_success_at from account_usage_records where account_id=?",(aid,)).fetchone()
  if row is None:return {}
  signed=c.execute("select max(ts) from checkin_records where account_id=? and date=? and ok=1",(aid,today())).fetchone()[0]
 return {'balance':row['remaining'],'unlimited':bool(row['unlimited']),'lastSuccess':row['last_success_at'] or 0,'signedAt':signed or 0}

def execute(job,release=True):
 try:
  return execute_reserved(job)
 except Exception as e:
  try:event('worker_failure',type(e).__name__+': '+scrub(e))
  except Exception:print('maintenance worker failure: '+type(e).__name__,file=sys.stderr,flush=True)
  raise
 finally:
  PROGRESS.pop(job.get('id'),None)
  if release:
   with LOCK:
    ACTIVE.pop(job.get('account'),None)
    if SNAP:SNAP['expires']=min(SNAP.get('expires',0),time.time()+5)
   SCHEDULER_WAKE.set()

def execute_reserved(job):
 w=None;aid=job['account'];p=job['provider'];a=job['action'];conf=settings();pc=conf['providers'][p];status='error';msg='';px=None
 try:
  if job.get('origin')=='post_relogin':
   _,current_data=account(aid)
   if not RECOVERY.authorized(job,credential_version(secret_of(current_data))):raise WriteConflict('重登后的凭证已变化，重新核对后再安排')
  PROGRESS[job['id']]='等待错峰执行'
  delay=random.uniform(pc['jitterMin'],pc['jitterMax']);STOP.wait(delay)
  if STOP.is_set():raise RuntimeError('服务正在停止')
  if p not in SUPPORTED:raise Unsupported('该平台暂不接管')
  if a=='recheck' and (pc['balance'].get('paused') or not next((r for r in get_snapshot()['accounts'] if r['id']==aid),{}).get('recheckAllowed')):
   raise WriteConflict('复核条件已变化，未发起请求')
  route=pc['balance' if a=='recheck' else a]['route']
  HEALTH.require_available(route)
  px=select_proxy(route)
  proxy=decode(px['secret'])['url'] if px else None
  if is_agent_account(aid):
   _,data=account(aid)
   with db() as c:c.execute('update jobs set credential_version=?,proxy=? where id=?',(credential_version(secret_of(data)),px['label'] if px else '直连',job['id']))
  PROGRESS[job['id']]='查询绑定状态、选择邀请码并核验' if a=='invitation' else '请求官方并保存、同步结果'
  if not is_agent_account(aid):raise Unsupported('账户不在 AG 中，请先通过 AG 官方入口导入')
  result=(INVITATIONS if a=='invitation' else DIRECT).execute(job,proxy,conf['timeout'])
  status=result['status'];msg=result['message']
  if result.get('credentialVersion'):
   with db() as c:c.execute('update jobs set credential_version=? where id=?',(result['credentialVersion'],job['id']))
 except DeliveryPending as e:
  status='queued';msg=str(e)
 except Unsupported as e:
  status='unsupported';msg=scrub(e)
 except WriteConflict as e:
  status='skipped';msg=str(e)
 except Exception as e:
  if is_capacity_error(e):
   status='queued';msg='本地余额容量不足，稍后重试；未判定凭证失效'
  elif isinstance(e,ProxyUnavailable) or 'MAINTENANCE_PROXY_WAIT' in str(e):
   status='queued';msg='等待可用维护节点；本次未发起上游维护请求'
  else:
   status,msg,sec=classify(e)
   if isinstance(e,RpcError):
    detail=e.obj.get('data') or {}
    if isinstance(detail,dict):
     retry=detail.get('retry_after',detail.get('retryAfter'))
     if isinstance(retry,(int,float)) and retry>0:sec=max(sec,retry)
   cooldown('operation:'+a+':'+aid,sec,msg)
   if '429' in str(e):cooldown('provider:'+p,sec,msg)
 finally:
  if w:w.close()
  persist_job_outcome(db,job,status,msg,now())
  if status=='ok':
   UNIFIED.wake.set();UI_WAKE.set()
   if a in ('balance','recheck'):ROUTING_WAKE.set();ROUTING_REFRESH.set()
  if status=='ok' and a=='checkin' and not STOP.is_set():
   if job.get('origin')=='post_relogin':RECOVERY.after_checkin(job)
   followup=claim_checkin_balance(aid,p,settings())
   if followup:execute(followup,release=False)

def claim_checkin_balance(aid,provider,cfg):
 # Keep this account's existing worker reservation across the sign -> balance
 # transition. No new worker, no duplicate query, and both caps still apply.
 pc=cfg['providers'][provider]['balance']
 if cfg.get('paused') or pc.get('paused'):return None
 with LOCK,db() as c:
  if aid not in ACTIVE or not is_agent_account(aid):return None
  if is_agent_account(aid):
   with db(True,True) as source:row=source.execute('select enabled from accounts where id=?',(aid,)).fetchone()
   if not row:return None
   if not row['enabled']:
    marker=c.execute('select value from ledger where key=?',('routing-guard-v1:'+aid,)).fetchone()
    marker=json.loads(marker[0]) if marker else {}
    if not marker.get('owned') or marker.get('kind') not in ('login','balance'):return None
  balances=[p for p,a in ACTIVE.values() if a in ('balance','recheck')]
  if len(balances)>=cfg.get('globalBalanceConcurrency',16) or (not cfg.get('sharedMaintenanceSlots') and balances.count(provider)>=pc.get('concurrency',1)):return None
  if c.execute('select 1 from cooldowns where scope in (?,?,?,?) and until>?',(*cooldown_scopes(aid,provider,'balance'),now())).fetchone():return None
  row=c.execute("select * from jobs where account=? and action='balance' and origin in ('post_checkin','post_relogin') and status='queued' order by created,id limit 1",(aid,)).fetchone()
  if not row:return None
  c.execute("update jobs set status='running',started=?,message='签到已完成，立即刷新余额' where id=? and status='queued'",(now(),row['id']))
  c.commit();ACTIVE[aid]=(provider,'balance')
  return dict(row)

def queue_post_checkin_balance(aid,provider,required_after):
 # The account is still reserved in ACTIVE until this transaction finishes.
 with LOCK,db() as c:
  c.execute('begin immediate')
  existing=c.execute("select id,status from jobs where account=? and action='balance' and status in ('queued','running') order by created,id",(aid,)).fetchone()
  if existing:
   c.execute("update jobs set origin='post_checkin',priority=100,required_after=max(required_after,?),not_before=0,message='签到成功，优先刷新余额' where id=?",(required_after,existing['id']))
   return existing['id']
  jid=secrets.token_hex(12)
  c.execute("insert into jobs(id,account,provider,action,status,created,message,attempt,origin,priority,required_after) values(?,?,?,'balance','queued',?,'签到成功，优先刷新余额',0,'post_checkin',100,?)",(jid,aid,provider,required_after,required_after))
  return jid

def enqueue(ids,action,skip_positive=False,verify_only=False,origin='manual',snapshot=None):
 from direct_maintenance import confirmed_day_key
 if action not in ['balance','checkin','credential','activity','recheck','invitation']:raise ValueError('未知任务')
 if verify_only and action!='checkin':raise ValueError('只读账单核对仅用于签到')
 rows={r['id']:r for r in (snapshot if snapshot is not None else get_snapshot())['accounts']};added=0;skipped=0
 with LOCK,db() as c:
  c.execute('begin immediate')
  for aid in dict.fromkeys(ids):
   if action=='checkin' and c.execute('select 1 from ledger where key=?',(confirmed_day_key(aid,now()),)).fetchone():skipped+=1;continue
   r=rows.get(aid)
   if not r or r.get('maintenancePaused') or (verify_only and r['provider']!='raccoon') or not r['supported'] or (r['needsLogin'] and action not in ('credential','recheck')) or operation_cooldown(r,action)>now() or (skip_positive and (r['balance'] or 0)>0) or (action=='checkin' and r['signed']) or (action=='credential' and not r.get('credentialRenewable')):skipped+=1;continue
   if action in ('activity','recheck') and (not (r['provider']=='wps-lingxi' or (r['provider']=='loomy' and action=='recheck')) or (action=='recheck' and not r.get('recheckAllowed'))):skipped+=1;continue
   if action=='invitation' and (r['provider']!='loomy' or not r.get('enabled')):skipped+=1;continue
   existing=c.execute("select id,status,origin from jobs where account=? and action=? and status in ('queued','running')",(aid,action)).fetchone()
   if existing:
    if action=='balance' and origin=='manual' and existing['status']=='queued' and existing['origin']=='auto':
     c.execute("update jobs set not_before=0,origin='manual',priority=100,message='手动刷新，立即等待执行' where id=?",(existing['id'],));added+=1
    else:skipped+=1
    continue
   c.execute('insert into jobs(id,account,provider,action,status,created,message,attempt,origin) values(?,?,?,?,?,?,?,?,?)',(secrets.token_hex(12),aid,r['provider'],action,'queued',now(),'账单核对（不重复领取）' if verify_only else '等待执行',-1 if verify_only else 0,origin));added+=1
 return {'added':added,'skipped':skipped}

def schedule_balances(cfg,snapshot,timestamp):
 # Serialize admission mutations with dispatch and manual enqueue.
 with LOCK,db() as c:
  pending={r['account']:dict(r) for r in c.execute("select * from jobs where action='balance' and status in ('queued','running')")}
  completed=dict(c.execute("select account,max(ended) from jobs where action='balance' and status in ('ok','error','cooling','needs_login','unconfirmed') group by account"))
  for row in snapshot['accounts']:
   if not row['supported']:continue
   pc=cfg['providers'][row['provider']]['balance'];job=pending.get(row['id'])
   if job and job['status']=='queued' and job.get('origin')=='post_checkin' and row.get('lastSuccess',0)>=job.get('required_after',0)>0:
    c.execute("update jobs set status='skipped',ended=?,message='已有签到后的新余额，补查已完成' where id=?",(timestamp,job['id']));job=None
   if job and (job['status']=='running' or job.get('origin')!='auto'):continue
   eligible=pc.get('enabled') and not row.get('maintenancePaused') and not row.get('needsLogin') and not balance_waits_for_checkin(row)
   if not eligible:
    if job:c.execute("update jobs set status='skipped',ended=?,message='已退出周期查询，等待签到、重登或恢复维护' where id=?",(timestamp,job['id']))
    continue
   due=max(balance_next_at(row,completed.get(row['id'],0),timestamp,pc),operation_cooldown(row,'balance'))
   if row.get('signedAt',0)>row.get('lastSuccess',0):
    # Recover missing/failed post-checkin queries without waiting the ordinary
    # hourly interval. Failed attempts retain at least a five-minute backoff.
    last=completed.get(row['id'],0)
    due=max(timestamp,operation_cooldown(row,'balance'),last+300000 if last>=row['signedAt'] else 0)
    if job:
     c.execute("update jobs set origin='post_checkin',priority=100,required_after=?,not_before=?,message='签到已完成，优先确认入账' where id=?",(row['signedAt'],due,job['id']))
    else:
     c.execute("insert into jobs(id,account,provider,action,status,created,message,attempt,origin,priority,required_after,not_before) values(?,?,?,'balance','queued',?,'签到已完成，优先确认入账',0,'post_checkin',100,?,?)",(secrets.token_hex(12),row['id'],row['provider'],timestamp,row['signedAt'],due))
    continue
   if job:
    # Unknown balances stay due from first admission, not pushed forward forever.
    if not completed.get(row['id']) and not row.get('lastSuccess') and not row.get('lastAttempt'):due=min(due,job.get('not_before') or job['created']) if operation_cooldown(row,'balance')<=timestamp else due
    if due!=job.get('not_before'):c.execute('update jobs set not_before=? where id=?',(due,job['id']))
   else:
    c.execute("insert into jobs(id,account,provider,action,status,created,message,attempt,origin,not_before) values(?,?,?,'balance','queued',?,'已安排下一轮余额查询',0,'auto',?)",(secrets.token_hex(12),row['id'],row['provider'],timestamp,due))


def auto_enqueue():
 cfg=settings()
 if cfg['paused']:return
 snap=get_snapshot();t=now()
 INVITATIONS.flush_followups()
 schedule_balances(cfg,snap,t)
 with db() as c:
  pending_rows=c.execute("select account,action,provider,origin from jobs where status in ('queued','running')").fetchall()
  pending={(r[0],r[1]) for r in pending_rows}
  pending_load=collections.Counter((r[2],r[1]) for r in pending_rows if r[3]=='auto')
  last={(r[0],r[1]):r[2] for r in c.execute('select account,action,max(created) from jobs group by account,action')}
  day_start=int(datetime.datetime.now(TZ).replace(hour=0,minute=0,second=0,microsecond=0).timestamp()*1000)
  attempts={r[0]:r[1] for r in c.execute("select account,count(*) from jobs where action='checkin' and attempt>=0 and created>=? and status not in ('cancelled','skipped') group by account",(day_start,))}
 invitation_states=INVITATIONS.states() if cfg['providers']['loomy']['invitation']['enabled'] else {}
 for a in ['credential','checkin','invitation',*AUX_ACTIONS]:
  candidates=collections.defaultdict(list)
  for r in snap['accounts']:
   if a=='invitation' and (r['provider']!='loomy' or not r.get('enabled')):continue
   if a in AUX_ACTIONS and not (r['provider']=='wps-lingxi' or (r['provider']=='loomy' and a=='recheck')):continue
   if not r['supported'] or r.get('maintenancePaused') or (r['needsLogin'] and a not in ('credential','recheck')) or operation_cooldown(r,a)>t or (r['id'],a) in pending:continue
   cfgp=cfg['providers'][r['provider']][a]
   if not cfgp['enabled'] or cfgp.get('paused',False):continue
   prev=last.get((r['id'],a),0)
   if a=='invitation':
    record=invitation_states.get(r['id'],{})
    if record.get('status')!='bound' and record.get('nextAt',0)<=t and t-prev>=cfgp.get('interval',3600)*1000:candidates['loomy'].append((1,prev,r['id']))
    continue
   if a in AUX_ACTIONS:
    if auxiliary_due(r,a,prev,t,cfgp,TZ):candidates[r['provider']].append((0 if a=='recheck' and r.get('authCredentialChanged') else 1,prev,r['id']))
    continue
   if a=='credential':
    if credential_due(r,prev,t,cfgp):candidates[r['provider']].append((r.get('credentialExpiresAt') or 2**62,prev,r['id']))
    continue
   interval=cfgp['interval']
   if a=='balance':
    if balance_waits_for_checkin(r):continue
    interval=balance_interval(r,cfgp);prev=max(prev,r['lastAttempt'],r['lastSuccess'])
   if a=='checkin':
    clock=datetime.datetime.now(TZ).strftime('%H:%M')
    if r['signed'] or not cfgp.get('start','00:00')<=clock<cfgp.get('end','23:00'):continue
    if attempts.get(r['id'],0)>=cfgp.get('maxAttempts',3):continue
    interval=cfgp.get('retryInterval',1800)
    if prev<day_start:prev=0
   if (a=='balance' and r.get('signedAt',0)>r['lastSuccess']) or t-prev>=interval*1000:candidates[r['provider']].append((0 if a=='balance' and (r.get('balance') or 0)>0 else 1,prev,r['id']))
  # Separate queue budgets prevent balance backlog from blocking daily/renewal work.
  for provider,items in candidates.items():
   cap=cfg.get('globalBalanceConcurrency',16) if cfg.get('sharedMaintenanceSlots') and a in ('checkin','balance','recheck') else cfg['providers'][provider][a].get('concurrency',1)
   count=max(0,cap*cfg.get('queueBufferMultiplier',3)-pending_load[(provider,a)])
   changed=[item for item in items if a=='recheck' and item[0]==0]
   ordinary=[item for item in items if not (a=='recheck' and item[0]==0)]
   selected=sorted(changed)+sorted(ordinary)[:max(0,count-len(changed))]
   if selected:enqueue([item[2] for item in selected],a,origin='auto',snapshot=snap)

def dispatch_jobs(cfg,pool):
 with LOCK:
  if len(ACTIVE)>=cfg['globalConcurrency']:return
 routes=HEALTH.available_routes()
 snap={r['id']:r for r in get_snapshot(allow_stale=True)['accounts']};timestamp=now()
 with LOCK,db() as c:
  active=collections.Counter(v[0] for v in ACTIVE.values());active_action=collections.Counter(ACTIVE.values());balance_reserved=sum(v[1] in ('balance','checkin','recheck') for v in ACTIVE.values());cap=cfg['globalConcurrency']-len(ACTIVE)
  if cap<=0:return
  # Rank separately per platform AND operation; a balance backlog cannot hide other work.
  jobs=[dict(j) for j in c.execute("select * from (select j.*,row_number() over(partition by provider,action order by priority desc,not_before,created,id) as dispatch_rank from jobs j where status='queued' and not_before<=?)",(timestamp,))]
  sign_first=checkin_providers(list(snap.values()),cfg,c,timestamp,TZ,routes,ACTIVE,jobs)
  # Earliest due time is stable throughout a dispatch pass. Sort once so a full
  # future queue does not turn admission into a quadratic scan under the lock.
  for j in sorted(jobs,key=lambda j:dispatch_order(j,snap,active_action,cfg,timestamp)):
   if sign_hold(j,sign_first,timestamp,snap.get(j['account'])):continue
   aid=j['account'];p=j['provider'];a=j['action'];r=snap.get(aid)
   j['credential_refresh']=bool(r and r.get('authCredentialChanged'))
   if not r:
    c.execute("update jobs set status='skipped',ended=?,message='账户已不存在' where id=?",(timestamp,j['id']));continue
   if r.get('maintenancePaused'):
    c.execute("update jobs set status='skipped',ended=?,message='账户维护已暂停' where id=?",(timestamp,j['id']));continue
   if p not in SUPPORTED:
    c.execute("update jobs set status='skipped',ended=?,message='平台暂不接管' where id=?",(timestamp,j['id']));continue
   if aid in ACTIVE or cfg['providers'][p][a].get('paused',False):continue
   if a=='recheck' and not r.get('recheckAllowed'):
    c.execute("update jobs set status='skipped',ended=?,message='账号状态已变化，停止自动核验' where id=?",(timestamp,j['id']));continue
   recovery_job=False
   if j.get('origin')=='post_relogin':
    _,current_data=account(aid)
    recovery_job=RECOVERY.authorized(j,credential_version(secret_of(current_data)))
    if not recovery_job:
     c.execute("update jobs set status='skipped',ended=?,message='恢复任务的凭证已变化，等待重新核对' where id=?",(timestamp,j['id']));continue
   if r.get('needsLogin') and a not in ('credential','recheck') and not recovery_job:
    c.execute("update jobs set status='skipped',ended=?,message='鉴权异常，等待凭证更新或到期核验' where id=?",(timestamp,j['id']));continue
   if a=='balance' and j.get('origin')=='auto' and balance_waits_for_checkin(r):
    c.execute("update jobs set status='skipped',ended=?,message='已确认零积分，等待下次签到成功后查询' where id=?",(timestamp,j['id']));continue
   if a=='balance' and not recovery_job and balance_satisfied(j,r,timestamp,cfg['providers'][p]['balance']):
    c.execute("update jobs set status='skipped',ended=?,message='已有更新的成功余额，本轮跳过' where id=?",(timestamp,j['id']));continue
   if a=='checkin' and j['attempt']>=0:
    clock=datetime.datetime.fromtimestamp(timestamp/1000,TZ).strftime('%H:%M');cp=cfg['providers'][p][a]
    if not cp.get('start','00:00')<=clock<cp.get('end','23:00'):continue
    if r['signed']:
     c.execute("update jobs set status='skipped',ended=?,message='今日已签到，本轮跳过' where id=?",(timestamp,j['id']));continue
   if a=='credential' and not r.get('credentialRenewable'):
    c.execute("update jobs set status='unsupported',ended=?,message='当前凭证不支持官方续期' where id=?",(timestamp,j['id']));continue
   if a=='invitation' and (p!='loomy' or not r.get('enabled') or not cfg['providers'][p][a].get('enabled')):continue
   if cfg['providers'][p][a]['route'] not in routes:continue
   cd=c.execute('select 1 from cooldowns where scope in (?,?,?,?) and until>? and not (? and scope=? and reason=?)',(*cooldown_scopes(aid,p,a),timestamp,int(recovery_job or r.get('authRecovered',False) or r.get('authCredentialChanged',False)),'operation:'+a+':'+aid,'鉴权失败，凭证需要检查或重新登录')).fetchone()
   # A checkin reserves its follow-up balance slot before starting. Ordinary
   # queries cannot steal it while the checkin is in flight.
   if a in ('balance','checkin','recheck'):
    if balance_reserved>=cfg.get('globalBalanceConcurrency',16):continue
    if not cfg.get('sharedMaintenanceSlots') and active_action[(p,'balance')]+active_action[(p,'checkin')]+active_action[(p,'recheck')]>=cfg['providers'][p]['balance'].get('concurrency',1):continue
   if p=='loomy' and a=='recheck' and cfg['providers'][p]['balance'].get('paused'):continue
   if cd or capacity_hold(j,ACTIVE,cfg):continue
   c.execute("update jobs set status='running',started=? where id=? and status='queued'",(timestamp,j['id']));c.commit();ACTIVE[aid]=(p,a);active[p]+=1;active_action[(p,a)]+=1;pool.submit(execute,j);cap-=1
   if a in ('balance','checkin','recheck'):balance_reserved+=1
   if cap<=0:break

def prune_superseded(c, timestamp):
  # Only a successful checkin on the same Beijing calendar day is a duplicate.
  # Periodic balance tasks belong to their next due time; a prior success does
  # not make the next scheduled refresh obsolete.
  start=int(datetime.datetime.fromtimestamp(timestamp/1000,TZ).replace(hour=0,minute=0,second=0,microsecond=0).timestamp()*1000)
  return c.execute("update jobs set status='skipped',ended=?,message='今日已签到，排队作废' "
      "where status='queued' and action='checkin' and exists (select 1 from jobs j2 "
      "where j2.account=jobs.account and j2.action='checkin' and j2.status='ok' "
      "and j2.ended>=? and j2.ended<?)",(timestamp,start,start+86400000)).rowcount


def queue_planner():
 while not STOP.is_set():
  try:
   if not settings()['paused']:
    with LOCK:
     recovered=reconcile_completed_balances(db,ACTIVE,now())
     with db() as c:dropped=prune_superseded(c,now())
    if recovered:event('job_recovered',str(recovered)+' 个 AG 已确认余额任务恢复状态')
    if dropped:event('queue_pruned',str(dropped)+' 条排队任务已有更新结果，已作废')
    auto_enqueue();SCHEDULER_WAKE.set()
  except Exception as e:event('queue_planner',type(e).__name__+': '+scrub(e))
  if STOP.wait(10):break


def scheduler():
 pool=concurrent.futures.ThreadPoolExecutor(max_workers=64)
 while not STOP.is_set():
  SCHEDULER_WAKE.wait(1);SCHEDULER_WAKE.clear()
  if STOP.is_set():break
  try:
   cfg=settings()
   if cfg['paused']:continue
   dispatch_jobs(cfg,pool)
  except Exception as e:event('scheduler',type(e).__name__+': '+scrub(e))
 pool.shutdown(wait=True)


def forwarding_observer():
 while not STOP.is_set():
  try:
   counts=official_client().call('/api/external-maintenance/inflight').get('counts',{})
   if isinstance(counts,list):counts=dict(counts)
   with ROUTING_LOCK:FORWARDING.update(at=now(),counts=counts)
   UI_WAKE.set()
  except Exception:pass
  if STOP.wait(5):break


def routing_observer():
 while not STOP.is_set():
  ROUTING_REFRESH.clear()
  try:
   response=official_client().call('/api/routing/queue');entries={}
   for bucket in ['ordered','blocked']:
    for row in response.get(bucket,[]):
     aid=row.get('id')
     if aid:entries[aid]={'state':str(row.get('state','unknown')),'reason':scrub(row.get('reason','')),'bucket':bucket,'resetAt':row.get('resetAt')}
   with ROUTING_LOCK:ROUTING.update(at=now(),entries=entries,error='',strategy=response.get('strategy'),scope='未指定模型的官方调度队列')
  except Exception as e:
   with ROUTING_LOCK:ROUTING['error']='官方调度快照读取失败：'+scrub(type(e).__name__)
  # UI-only observation: completed maintenance must never trigger a full rescan.
  if STOP.wait(60):break

def routing_snapshot():
 with ROUTING_LOCK:
  return dict(ROUTING,entries=dict(ROUTING['entries']),usage=dict(FORWARDING))


def ownership_guard():
 # Only official settings APIs are used; credentials and proxy bindings are not changed.
 while not STOP.wait(300):
  try:
   snap=get_snapshot(True);ids=snap['autoBalanceIds']
   if ids:OFFICIAL.call('/api/accounts/batch',{'action':'usageQuery','ids':ids,'usageQuery':{'enabled':False,'interval':0}});event('ownership',f'关闭 {len(ids)} 个新增/变更账户的官方自动余额查询')
  except Exception as e:event('ownership','自动余额接管检查失败：'+type(e).__name__)

def routing_guard():
 # Read existing local evidence only; no extra upstream balance/login probes.
 while not STOP.is_set():
  ROUTING_WAKE.clear()
  try:
   if reconcile_routing(db,get_snapshot(True),account,secret_of,credential_version,official_client(),event,now()):
    with LOCK:SNAP.clear()
    ROUTING_REFRESH.set();UI_WAKE.set()
  except Exception as e:event('routing_guard','调度联动失败，将重试：'+type(e).__name__)
  ROUTING_WAKE.wait(15)
  if STOP.wait(1):break

def reserve_bridge_slot(aid,provider,cfg):
 # Absorb brief collisions with native/manual refreshes before replying to the
 # gateway. Never exceed the existing caps or hold LOCK while waiting.
 pc=cfg['providers'][provider];deadline=time.monotonic()+min(10,cfg['timeout']/4)
 while True:
  with LOCK:
   if aid not in BRIDGE_BUSY and len(BRIDGE_BUSY)<cfg['globalConcurrency'] and sum(p==provider for p in BRIDGE_BUSY.values())<min(pc['concurrency'],pc['balance'].get('concurrency',1)):
    BRIDGE_BUSY[aid]=provider
    return
  if time.monotonic()>=deadline:raise RuntimeError('余额桥并发已满，请排队重试')
  if STOP.wait(0.1):raise RuntimeError('维护服务正在停止')

def bridge_usage(params):
 raise RuntimeError('维护查询已迁至独立调度，请使用结果同步入口')

with db() as c:
 c.execute('create index if not exists jobs_status_queue on jobs(status,provider,action,created)')
 c.execute('create index if not exists jobs_due_queue on jobs(status,not_before,provider,action)')
 c.execute('create index if not exists jobs_created on jobs(created desc)')
HEALTH=AutoProxyHealth(db,decode,settings)
QUEUE_STATUS=QueueStatus(db,now)
UI_LOCK=threading.Lock();UI_WAKE=threading.Event();UI_STATE={'data':None,'error':''}
def build_ui_state():
 snap=enrich(scope_snapshot(get_snapshot()),settings(),db,now(),TZ,routing_snapshot())
 with db() as c:
  queued=[dict(r) for r in c.execute("select * from jobs where status='queued' and action='checkin'")]
  snap['dashboard']['signFirst']=checkin_phase(snap['accounts'],settings(),c,now(),TZ,HEALTH.available_routes(),dict(ACTIVE),queued)
 return {**snap,'config':settings(),'cacheSync':'余额返回官方主程序落库并更新调度缓存','supported':sorted(SUPPORTED),'builtAt':now()}
def ui_observer():
 while not STOP.is_set():
  started=time.monotonic()
  try:
   data=build_ui_state()
   with UI_LOCK:UI_STATE.update(data=data,error='')
  except Exception as e:
   with UI_LOCK:UI_STATE['error']='维护视图更新失败：'+type(e).__name__
  # Completion bursts must not rebuild thousands of account projections per job.
  if STOP.wait(max(.1,5-(time.monotonic()-started))):break
  UI_WAKE.clear()
def ui_state():
 with UI_LOCK:
  data=UI_STATE['data'];error=UI_STATE['error']
 if data is None:return None
 return {**data,'viewError':error,'viewAgeSeconds':max(0,(now()-data['builtAt'])//1000)}

class Handler(BaseHTTPRequestHandler):
 server_version='Maintenance/1.0'
 def log_message(self,*args):pass
 def send(self,status,data,html=False,cookie=None,content_type=None):
  body=data.encode() if html else dumps(data).encode();compressed='gzip' in self.headers.get('Accept-Encoding','') and len(body)>1024
  if compressed:body=gzip.compress(body,compresslevel=3)
  self.send_response(status)
  if compressed:self.send_header('Content-Encoding','gzip');self.send_header('Vary','Accept-Encoding')
  self.send_header('Content-Type',content_type or ('text/html; charset=utf-8' if html else 'application/json; charset=utf-8'));self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY');self.send_header('Referrer-Policy','no-referrer');self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
  if cookie:self.send_header('Set-Cookie',cookie)
  self.end_headers();self.wfile.write(body)
 def authed(self):
  try:c=http.cookies.SimpleCookie(self.headers.get('Cookie',''));token=c['maintenance_session'].value;return SESSIONS.get(token,0)>time.time()
  except:return False
 def do_GET(self):
  try:
   path=urllib.parse.urlsplit(self.path).path
   if path=='/health':return self.send(200,{'ok':True,'version':'1.0','engine':'official-plugin-3.4.2'})
   if path=='/':return self.send(200,pathlib.Path('/app/index.html').read_text(),True)
   if path=='/invitation':return self.send(200,pathlib.Path('/app/invitation.html').read_text(),True)
   if path=='/ui.js':return self.send(200,pathlib.Path('/app/ui.js').read_text(),html=True,content_type='application/javascript; charset=utf-8')
   static={'/ux.js':('ux.js','application/javascript'),'/ui.css':('ui.css','text/css'),'/vendor/tom-select.min.js':('vendor/tom-select.min.js','application/javascript'),'/vendor/tom-select.css':('vendor/tom-select.css','text/css')}
   if path in static:
    f,mime=static[path];return self.send(200,(pathlib.Path('/app')/f).read_text(),html=True,content_type=mime+'; charset=utf-8')
   if not self.authed():return self.send(401,{'error':'请登录'})
   if path=='/api/node-probes':return self.send(200,NODE_PROBE.status())
   if path=='/api/invitation/config':
    with db() as c:r=c.execute("select value from settings where key='loomyInvitation'").fetchone()
    return self.send(200,json.loads(r[0]) if r else {'code':''})
   if path=='/api/queue/status':
    value=QUEUE_STATUS.read();snap=ui_state() or {};names={r['id']:r.get('name',r['id']) for r in snap.get('accounts',[])}
    with db() as c:running=[dict(r) for r in c.execute("select id,account,provider,action,started,origin from jobs where status='running' order by started limit 64")]
    for r in running:r.update(name=names.get(r['account'],r['account']),elapsedSeconds=max(0,(now()-(r['started'] or now()))//1000),phase=PROGRESS.get(r['id'],'执行中，等待任务回执'))
    return self.send(200,{**value,'runningItems':running,'runningAt':now()})
   if path=='/api/invitation/summary':return self.send(200,{**INVITATIONS.summary(),'config':settings()['providers']['loomy']['invitation']})
   if path=='/api/account/tasks':
    from account_task_records import account_task_records
    query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query);aid=query.get('account',[''])[0]
    snap=ui_state()
    if snap is None:return self.send(503,{'error':'账户快照尚未就绪'})
    row=next((r for r in snap['accounts'] if r['id']==aid),None)
    if row is None:return self.send(404,{'error':'账户不存在'})
    with db() as c:result=account_task_records(c,row,settings(),now(),decode)
    return self.send(200,{**result,'snapshotAt':snap.get('at'),'name':row.get('name','')})
   if path in ['/api/state','/api/accounts','/api/queue','/api/history','/api/proxies','/api/relogin/queue','/api/relogin/history']:
    query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
    if path=='/api/proxies':return self.send(200,{'items':HEALTH.rows(),'health':HEALTH.status()})
    snap=ui_state()
    if snap is None:return self.send(503,{'error':'首次维护快照正在加载，请稍候'})
    if path=='/api/state':
     live=QUEUE_STATUS.read()
     snap['dashboard']={**snap['dashboard'],'pending':live['pending'],'queueTiming':live['queueTiming'],'queueAt':live['at']}
     snap['config']=settings()
     if query.get('compact')==['1']:snap={k:v for k,v in snap.items() if k!='accounts'}
     return self.send(200,{**snap,'proxies':HEALTH.rows(),'proxyHealth':HEALTH.status()})
    if path=='/api/relogin/history':
     limit=max(1,min(500,int(query.get('limit',['120'])[0])))
     with db(ro=True) as c:
      book=relogin_book(c);lease=lease_summary(c,now());busy=leased_accounts(c);recoveries=recovery_records(c);unlinked=c.execute('select count(*) from relogin_history_unlinked').fetchone()[0]
     result=relogin_history(snap,book,now(),limit,recoveries)
     ready=[r for r in relogin_eligible(snap,book[0],book[2],now()) if r['id'] not in busy]
     result['summary'].update(historicalUnlinked=unlinked,dispatchObserved=True,leases=lease,pending=len(ready),byProvider={p:sum(r['provider']==p for r in ready) for p in ('loomy','raccoon')})
     names={r['id']:r.get('name','') for r in snap['accounts']}
     with db(ro=True) as c:
      result['activeItems']=[{'name':names.get(r['account'],''),'provider':r['provider'],'state':'uncertain' if r['expires']<=now() else r['state'],'created':r['created'],'updated':r['updated']} for r in c.execute("select * from relogin_leases where state in ('running','uncertain') order by created limit 200")]
     return self.send(200,result)
    if path=='/api/relogin/queue':
     provider=(query.get('provider',[''])[0] or '').strip()
     with db(ro=True) as c:
      events,tries,given,merged=relogin_book(c);busy=leased_accounts(c)
     cand=[r for r in relogin_eligible(snap,events,given,now()) if r['id'] not in busy]
     if provider:cand=[r for r in cand if r['provider']==provider]
     limit=max(1,min(500,int(query.get('limit',['200'])[0])))
     return self.send(200,{'count':len(cand),'limit':limit,'maxAttempts':RELOGIN_MAX_ATTEMPTS,'items':[{'id':r['id'],'name':r.get('name',''),'provider':r.get('provider'),'attempts':tries.get(r['id'],0),'failureAt':r.get('authFailureAt') or 0,'failureAction':r.get('authFailureAction') or '', 'recheckAt':r.get('authRecheckAt') or 0,'status':r.get('authStatus') or ''} for r in cand[:limit]]})
    if path=='/api/accounts':return self.send(200,account_page(snap,query))
    if path=='/api/queue':return self.send(200,queue_view(snap,settings(),db,now(),query,HEALTH.available_routes()))
    result=history_view(db,query);names={r['id']:r['name'] for r in snap['accounts']}
    for item in result['items']:item['name']=names.get(item['account'],item['account'])
    return self.send(200,result)
   return self.send(404,{'error':'不存在'})
  except (ValueError,KeyError) as e:self.send(400,{'error':scrub(e)})
  except (BrokenPipeError,ConnectionResetError):pass
  except Exception as e:
   event('http_error',self.command+' '+urllib.parse.urlsplit(self.path).path+' 500 '+type(e).__name__)
   self.send(500,{'error':'服务处理异常，请稍后重试','kind':type(e).__name__})
 def do_POST(self):
  try:
   origin=self.headers.get('Origin');host=self.headers.get('Host')
   if origin and urllib.parse.urlsplit(origin).netloc!=host:return self.send(403,{'error':'来源不匹配'})
   if self.headers.get('Content-Type','').split(';')[0]!='application/json':return self.send(415,{'error':'需要 JSON'})
   n=int(self.headers.get('Content-Length','0'))
   if n>1000000:return self.send(413,{'error':'请求过大'})
   d=json.loads(self.rfile.read(n) or b'{}');path=urllib.parse.urlsplit(self.path).path
   if path=='/api/registration/loomy-handoff':
    if n>24000:return self.send(413,{'error':'request_too_large'})
    try:
     key=pathlib.Path('/secrets/registration-handoff.key').read_bytes()
     request=open_handoff(key,d,'request')
    except Exception:return self.send(401,{'error':'invalid_handoff'})
    result={'ok':False,'error':'handoff_busy'}
    if HANDOFF_SLOT.acquire(blocking=False):
     try:
      result=UNIFIED.registration_handoff(request.get('account'))
      if result.get('ok'):
       with LOCK:SNAP['expires']=0
       UNIFIED.wake.set();UI_WAKE.set();ROUTING_REFRESH.set()
     except ValueError as exc:result={'ok':False,'error':str(exc)[:80]}
     except Exception:result={'ok':False,'error':'handoff_unconfirmed_retry'}
     finally:HANDOFF_SLOT.release()
    return self.send(200,seal_handoff(key,{'requestId':request['requestId'],'ts':int(time.time()),'result':result},'response'))
   if path=='/internal/usage':
    token=self.headers.get('Authorization','')
    if not hmac.compare_digest(token.encode(),('Bearer '+BRIDGE_KEY).encode()):return self.send(401,{'error':{'message':'未授权','code':'unauthorized'}})
    try:return self.send(200,{'result':bridge_usage(d)})
    except RpcError as e:return self.send(200,{'error':{'message':scrub(e.obj.get('message',str(e))),'code':e.obj.get('code','upstream')}})
    except Exception as e:return self.send(200,{'error':{'message':scrub(e),'code':'maintenance_bridge'}})
   if path=='/api/login':
    ip=self.client_address[0];attempts=[x for x in LOGIN_ATTEMPTS.get(ip,[]) if x>time.time()-300]
    if len(attempts)>=10:return self.send(429,{'error':'登录尝试过多，等待5分钟'})
    if not (hmac.compare_digest(str(d.get('username','')).encode(),AUTH['username'].encode()) and hmac.compare_digest(str(d.get('password','')).encode(),AUTH['password'].encode())):
     LOGIN_ATTEMPTS[ip]=attempts+[time.time()];return self.send(401,{'error':'用户名或密码错误'})
    token=secrets.token_urlsafe(32);SESSIONS[token]=time.time()+28800;return self.send(200,{'ok':True},cookie='maintenance_session='+token+'; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800')
   if not self.authed():return self.send(401,{'error':'请登录'})
   if path=='/api/logout':
    cookies=http.cookies.SimpleCookie(self.headers.get('Cookie',''));SESSIONS.pop(cookies['maintenance_session'].value,None)
    return self.send(200,{'ok':True},cookie='maintenance_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
   if path=='/api/relogin/receipts':
    with db() as c:result=relogin_receipts(c,d)
    return self.send(200,result)
   if path=='/api/settings':
    result=save_settings(d);UI_WAKE.set();return self.send(200,result)
   if path=='/api/node-probes/settings':return self.send(200,NODE_PROBE.configure(d))
   if path=='/api/invitation/config':
    code=str(d.get('code') or '').strip()
    if len(code)>128 or any(ch.isspace() for ch in code):raise ValueError('邀请码格式不正确')
    with db() as c:c.execute('insert or replace into settings values(?,?)',('loomyInvitation',dumps({'code':code})))
    return self.send(200,{'ok':True,'code':code})
   if path in ('/api/invitation/status','/api/invitation/bind'):
    aid=str(d.get('account') or '')
    with LOCK:
     if aid in ACTIVE:return self.send(409,{'error':'该账号正在维护，请稍后重试'})
     row,_=account(aid)
     if row['provider']!='loomy':raise ValueError('仅支持 Loomy 邀请码')
     ACTIVE[aid]=('loomy','invitation')
    client=None
    try:
     cached,_=INVITATIONS.read(aid)
     if cached=='bound':return self.send(200,{'activated':True,'confirmed':True,'cached':True,'code':''})
     if cached in ('submitted','verifying') and path.endswith('/bind'):return self.send(409,{'error':'已有待核验提交，禁止重复绑定，请查询状态'})
     from direct_clients import Client
     _,_,inventory=DIRECT.prepare(aid)
     code=None
     if path.endswith('/bind'):
      with db() as c:r=c.execute("select value from settings where key='loomyInvitation'").fetchone()
      code=str(d.get('code') or (json.loads(r[0]).get('code') if r else '') or '').strip()
      if not code or len(code)>128:raise ValueError('请先填写邀请码')
     route=settings()['providers']['loomy']['balance']['route'];px=select_proxy(route)
     client=Client('loomy',inventory['secret'],decode(px['secret'])['url'] if px else None,30)
     result=client.invitation(code)
     DIRECT.ledger(aid,'invitation',{**result,'at':now()})
     if result.get('activated') is True:INVITATIONS.save(aid,'bound',{'confirmedAt':now(),'source':'manual_readback'})
     if code and result['confirmed']:queue_post_checkin_balance(aid,'loomy',now())
     return self.send(200,result)
    finally:
     if client:client.close()
     with LOCK:ACTIVE.pop(aid,None)
   if path=='/api/proxies/health-settings':return self.send(200,HEALTH.save_policy(d))
   if path=='/api/proxies/test':return self.send(202,HEALTH.start(d.get('ids')))
   if path=='/api/proxies/toggle':return self.send(200,HEALTH.toggle(str(d.get('id','')),d.get('enabled')))
   if path=='/api/relogin/worker':
    with db() as c:result=worker_status(c,d,now())
    return self.send(200,result)
   if path=='/api/relogin/claim':
    snap=scope_snapshot(get_snapshot(force=True))
    with db() as c:result=claim_relogin(c,snap,d,now())
    return self.send(200,result)
   if path=='/api/relogin/heartbeat':
    with db() as c:result=heartbeat_relogin(c,d,now())
    return self.send(200,result)
   if path=='/api/relogin/finish':
    with db() as c:result=finish_relogin(c,d,now(),scrub)
    UI_WAKE.set();SCHEDULER_WAKE.set()
    return self.send(200,result)
   if path=='/api/relogin/report':
    with db() as c:result=save_relogin_reports(c,d,now(),scrub)
    UI_WAKE.set()
    return self.send(200,result)
   if path=='/api/jobs':
    ids=d.get('ids',[])
    if not isinstance(ids,list) or len(ids)>100:return self.send(400,{'error':'第一版每次最多选择100个，避免误点全量'})
    return self.send(200,enqueue(ids,d.get('action'),bool(d.get('skipPositive')),bool(d.get('verifyOnly'))))
   if path=='/api/jobs/cancel':
    ids=d.get('jobIds')
    if not isinstance(ids,list) or not ids or len(ids)>100 or any(not isinstance(x,str) for x in ids):raise ValueError('请选择1—100条待执行任务；不取消执行中的请求')
    with LOCK,db() as c:
     n=c.execute("update jobs set status='cancelled',ended=?,message='用户取消待执行任务' where status='queued' and id in ("+','.join('?' for _ in ids)+')',(now(),*ids)).rowcount
    return self.send(200,{'cancelled':n})
   if path=='/api/proxies':
    url=str(d.get('url',''));u=urllib.parse.urlsplit(url)
    if u.scheme not in ['http','socks5','socks4'] or not re.fullmatch(r'[0-9.]+',u.hostname or '') or not u.port:raise ValueError('请输入 http://IPv4:端口 或 socks5://IPv4:端口，可含用户名密码')
    if any(x.isspace() for x in urllib.parse.unquote(u.username or '')+urllib.parse.unquote(u.password or '')):raise ValueError('代理凭证不支持空白字符')
    pid=secrets.token_hex(8)
    with db() as c:c.execute('insert into proxies values(?,?,?,1)',(pid,str(d.get('label') or '节点 '+pid[:4])[:60],encode({'url':url})))
    return self.send(200,{'id':pid,'ok':True})
   if path=='/api/proxies/delete':
    return self.send(200,HEALTH.delete(str(d.get('id',''))))
   return self.send(404,{'error':'不存在'})
  except (ValueError,KeyError) as e:self.send(400,{'error':scrub(e)})
  except Exception as e:
   event('http_error',self.command+' '+urllib.parse.urlsplit(self.path).path+' 500 '+type(e).__name__)
   self.send(500,{'error':'服务处理异常，请稍后重试','kind':type(e).__name__})

RECOVERY_INVENTORY={'at':0,'data':{}}

def recovery_inventory():
 if now()-RECOVERY_INVENTORY['at']<60000:return RECOVERY_INVENTORY['data']
 from unified_sync import source_record
 with db(True,True) as c:raw=c.execute("select id,provider,enabled,data from accounts where provider in ('loomy','raccoon')").fetchall()
 result={}
 for r in raw:
  try:
   d=decode(r['data']);identity=source_record(dict(r),d)
   result[r['id']]={'id':r['id'],'provider':r['provider'],'uid':identity['uid'],'version':credential_version(secret_of(d))}
  except (ValueError,KeyError):continue
 RECOVERY_INVENTORY.update(at=now(),data=result)
 return result

def recovery_wake():
 with LOCK:
  SNAP['expires']=0
 UI_WAKE.set();SCHEDULER_WAKE.set();UNIFIED.wake.set()

def copy_relogin_identity(original,donor,donor_view):
 from unified_sync import source_record,auth_token
 aid=original['id'];p=original['provider'];cfg=settings()
 with LOCK:
  if aid in ACTIVE or len(ACTIVE)>=cfg['globalConcurrency'] or sum(v[0]==p for v in ACTIVE.values())>=cfg['providers'][p]['concurrency'] or sum(v==(p,'credential') for v in ACTIVE.values())>=1:raise DeliveryPending('等待维护槽位')
  ACTIVE[aid]=(p,'credential')
 try:
  with UNIFIED.sync_lock:
   row,data=account(aid);other,other_data=account(donor['id'])
   old=source_record(row,data);new=source_record(other,other_data)
   if (old['platform'],old['uid'])!=(new['platform'],new['uid']):raise WriteConflict('官方身份不匹配')
   if credential_version(secret_of(data))!=original['version'] or credential_version(secret_of(other_data))!=donor['version']:raise WriteConflict('凭证已更新，等待重新核对')
   old['_data']=data
   UNIFIED._write_primary(new,old)
   row,updated=account(aid);current=source_record(row,updated)
   if current['uid']!=old['uid'] or auth_token(current['auth'])!=auth_token(new['auth']):raise WriteConflict('原账户凭证回读未确认')
   # Carry only a genuine same-day receipt for the exact same official UID.
   with db(True,True) as c:receipt=c.execute('select max(ts) from checkin_records where account_id=? and date=? and ok=1',(donor['id'],today())).fetchone()[0]
   if receipt:
    reply=official_client().call('/api/external-maintenance/apply',{'account':aid,'provider':p,'action':'checkin','requestId':'relogin-sign-'+secrets.token_hex(12),'observedAt':receipt,'expect':secret_of(updated),'confirmed':True})
    if reply.get('applied') is not True:raise DeliveryPending('原账户签到凭证等待回读')
    from direct_maintenance import confirmed_day_key
    with db() as c:c.execute('insert or replace into ledger values(?,?)',(confirmed_day_key(aid,receipt),str(receipt)))
   return credential_version(secret_of(updated))
 finally:
  RECOVERY_INVENTORY['at']=0
  with LOCK:ACTIVE.pop(aid,None)
  recovery_wake()

PROGRESS={}
DIRECT=DirectMaintenance(db,encode,decode,account,official_client,now,event,queue_post_checkin_balance)
NODE_PROBE=NodeProbe(db,official_client,now)

INVITATIONS=InvitationTasks(db,encode,decode,DIRECT,get_snapshot,now,queue_post_checkin_balance)

RECOVERY=ReloginRecovery(db,now,get_snapshot,recovery_inventory,copy_relogin_identity,settings,recovery_wake,event)

if __name__=='__main__':
 signal.signal(signal.SIGTERM,lambda *_:STOP.set())
 threading.Thread(target=DIRECT.run,args=(STOP,),daemon=True).start()
 threading.Thread(target=NODE_PROBE.run,args=(STOP,),daemon=True).start()
 threading.Thread(target=RECOVERY.run,args=(STOP,),daemon=True).start()
 threading.Thread(target=forwarding_observer,daemon=True).start()
 threading.Thread(target=HEALTH.run,args=(STOP,),daemon=True).start();threading.Thread(target=ui_observer,daemon=True).start();threading.Thread(target=scheduler,daemon=True).start();threading.Thread(target=queue_planner,daemon=True).start();threading.Thread(target=ownership_guard,daemon=True).start()
 threading.Thread(target=routing_observer,daemon=True).start()
 server=ThreadingHTTPServer(('0.0.0.0',8080),Handler);server.timeout=1
 print('Independent upstream maintenance ready; persisted scheduler settings retained',flush=True)
 while not STOP.is_set():server.handle_request()
 server.server_close()

