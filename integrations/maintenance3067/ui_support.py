"""Read-only UI projections and bounded, explicit proxy health checks."""
import datetime,json,os,pathlib,subprocess,tempfile,threading,time,urllib.parse,re,ipaddress,concurrent.futures
from functools import lru_cache
SUPPORTED={'loomy','raccoon','codearts','wps-lingxi'}
# UI snapshots must never carry credential payloads, even from a new provider.
_SECRET_KEYS={'secret','credentials','password','token','accesstoken','refreshtoken','apikey','authorization','cookie','setcookie','credentialversion'}
_KEY_NORMALIZER=re.compile(r'[^a-z]')
_BEARER=re.compile(r'(?i)bearer\s+[A-Za-z0-9._~+/=-]+')
_URL_AUTH=re.compile(r'(?i)(https?://)[^\s/@]+:[^\s/@]+@')
_ASSIGNMENT=re.compile(r'(?i)((?:access[_-]?token|refresh[_-]?token|api[_-]?key|password|secret|token|cookie|authorization)[\"\']?\s*[:=]\s*)[^\s&,;]+')
_JWT=re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

@lru_cache(maxsize=512)
def _public_key(key):
    # Cache schema-key decisions only, never values, credentials or payloads.
    return _KEY_NORMALIZER.sub('',key.lower()) not in _SECRET_KEYS
def public_value(value):
    if isinstance(value,dict):
        return {k:public_value(v) for k,v in value.items() if _public_key(k)}
    if isinstance(value,list):return [public_value(v) for v in value]
    if isinstance(value,str):
        value=_BEARER.sub('Bearer [已隐藏]',value)
        # These literal characters are required by the original expressions.
        # Clean names/statuses therefore avoid unnecessary regex scans without
        # weakening case-insensitive or Unicode whitespace handling.
        if '://' in value:value=_URL_AUTH.sub(r'\1[已隐藏]@',value)
        if ':' in value or '=' in value:value=_ASSIGNMENT.sub(r'\1[已隐藏]',value)
        if 'eyJ' in value:value=_JWT.sub('[已隐藏]',value)
    return value

# Keep only public account metadata as providers are added to the snapshot.
_ACCOUNT_FIELDS=set("id name provider enabled balance unlimited lastSuccess lastAttempt error signed signedAt cooldownUntil supported jobStatus jobMessage autoBalanceEnabled needsLogin authStatus authRecovered authRecheck authFailureAt authRecheckAt authFailureMessage authCredentialChanged authConfirmedFailed authFailureAction capacityRetry maintenanceMessage recheckAllowed operationCooldowns credentialRenewable credentialExpiresAt credentialLeadMs credentialReason maintenancePaused pauseReason routingDisabledReason home syncStatus syncAt syncError checkinDetail balanceDetail credentialDetail routing balanceKind verificationState verificationAt verifiedBalanceAt".split())
_ACCOUNT_FIELDS.update(('pauseOrigin','pauseAt','balanceCredentialChanged','balanceRefreshRequestedAt','verificationDetail','unavailableReason'))

def account_pause_details(enabled, marker=None, source='3065'):
    """Explain existing switches; a historical marker never changes a switch."""
    if enabled:return {}
    marker=marker or {}
    kind=marker.get('kind') if marker.get('owned') else None
    reasons={'login':'旧版3067曾因登录失效关闭调度；刷新凭证不会自动开启账户',
             'disabled':'历史记录：上游明确停用，旧版3067关闭调度',
             'balance':'历史记录：旧版3067曾因余额不足关闭调度'}
    known=kind in reasons
    return {'pauseOrigin':'legacy_'+kind if known else 'source_disabled_unknown',
            'pauseAt':(marker.get('appliedAt') or marker.get('at') or 0) if known else 0,
            'pauseReason':reasons[kind] if known else source+'账户开关已关闭；暂无可核实的停用来源'}

def public_account(row):
    return public_value({k:v for k,v in row.items() if k in _ACCOUNT_FIELDS})

def unavailable_reason(row):
    state=row.get('routing',{}).get('state','unknown')
    # Display only: native selection and account switches are never changed.
    if state in ('usable','concurrency','unknown','candidate'):return None
    native_key=row.get('routing',{}).get('reasonKey')
    if native_key in ('model_permission','identity_required','network_cooling','response_cooling','native_cooling','rate_limited'):return native_key
    reason=str(row.get('routing',{}).get('reason') or '')
    if state in ('banned','upstream-banned') or any(s in reason for s in ('upstream_ban','账号已被停用','账号已停用','账号被封禁','账号已封禁')):return 'banned'
    if state=='no-credentials':return 'missing_credentials'
    auth=row.get('authStatus','')
    if row.get('authCredentialChanged'):return 'credential_pending'
    if state in ('auth_failed','needs-relogin') or row.get('needsLogin'):
        if row.get('authRecovered') and auth=='verified':return 'native_auth_stale'
        # 核验判过失败的账号，即使已经到点重排复核，仍然是「需重登」。
        # 复核只是待办动作，不构成恢复证据；只有复核成功才会离开这个分类。
        if row.get('authConfirmedFailed'):return 'needs_login'
        if auth in ('pending_verify','observing','recheck_due'):return 'login_check'
        if row.get('authFailureAt') and auth in ('credential_failed','needs_login'):return 'needs_login'
        return 'login_check'
    if state=='disabled':return 'native_disabled'
    if state=='absent':return 'not_in_queue'
    if state in ('cooldown','rate-limited') or '429' in reason or '限流' in reason:return 'rate_limited'
    if row.get('balanceCredentialChanged'):return 'credential_pending'
    if row.get('signed') and row.get('signedAt',0)>row.get('lastSuccess',0):return 'signed_balance_pending'
    if row.get('balanceKind') in ('zero','negative') and state=='limiter':
        if not row.get('signed'):return 'unsigned_zero'
        signed_at=row.get('signedAt',0) or 0;observed=row.get('lastSuccess',0) or 0
        if signed_at<=0 or observed<signed_at:return 'balance_pending'
        if row.get('balanceRefreshRequestedAt',0)>observed:return 'balance_pending'
        return 'zero_balance'
    if state=='limiter' and any(s in reason for s in ('额度耗尽','额度用完','次数用完','Token 限额','token 限额','token_limit','quota_exhausted')):return 'exhausted'
    if row.get('verificationDetail')=='expired_verified':return 'balance_expired'
    if row.get('verificationDetail')=='credential_changed':return 'credential_pending'
    if row.get('error') or any(s in reason for s in ('超时','查询失败','连接失败')):return 'query_failed'
    if state=='unverified':return 'balance_pending'
    return 'native_limit'

def awaiting_signed_balance(row):
    return (row.get('routing',{}).get('state')=='limiter' and row.get('balanceKind') in ('zero','negative')
            and not row.get('needsLogin') and bool(row.get('signed') and row.get('signedAt',0)>row.get('lastSuccess',0)))

def scope_snapshot(snapshot):
    rows=[public_account(x) for x in snapshot.get('accounts',[]) if x.get('provider') in SUPPORTED]
    s=public_value(snapshot);s['accounts']=rows;s.pop('autoBalanceIds',None)
    s['summary']={'total':len(rows),'positive':sum((r.get('balance') or 0)>0 for r in rows),'knownBalance':sum(r.get('lastSuccess',0)>0 for r in rows),'signedToday':sum(bool(r.get('signed')) for r in rows),'cooling':sum(r.get('cooldownUntil',0)>s['at'] for r in rows),'needsLogin':sum(bool(r.get('enabled') and r.get('needsLogin')) for r in rows),'maintenancePaused':sum(r.get('maintenancePaused') is True for r in rows)}
    return s

def account_page(state,query):
    value=lambda k:query.get(k,[''])[0]
    page=max(0,min(100000,int(value('page') or 0)));size=max(1,min(100,int(value('size') or 50)))
    provider=value('provider');term=value('search').strip().casefold();f=value('filter');now=state['at']
    def match(r):
        if provider and r['provider']!=provider:return False
        if term and term not in (r['name']+' '+r['id']).casefold():return False
        if f=='in_use':return r['routing'].get('inUse') is True
        if f=='unavailable':return unavailable_reason(r) is not None
        if f=='ready':return r['routing'].get('ready') is True
        if f=='available_in_use':return r['routing'].get('availableInUse') is True
        if f=='unavailable_in_use':return r['routing'].get('inUse') is True and unavailable_reason(r) is not None
        if f=='route_disabled':return r.get('enabled') is False
        if f=='checkin_balance_pending':return bool(r.get('signed') and r.get('signedAt',0)>r.get('lastSuccess',0))
        if f=='route_concurrency':return r['routing'].get('availableInUse') is True
        if f=='sign_needs_login':return r['checkinDetail'].get('todayCategory')=='needs_login'
        if f=='signed_balance_blocked':return awaiting_signed_balance(r)
        if f=='sync_conflict':return r.get('syncError')=='两端凭证不同且新旧不明，保留原值待核对'
        if f=='route_limits':return unavailable_reason(r)=='exhausted'
        if f=='route_blocked':return unavailable_reason(r) not in (None,'unsigned_zero','zero_balance','exhausted')
        if f.startswith('route_'):return unavailable_reason(r)==f.removeprefix('route_')
        if f in ('observing','pending_verify','credential_failed'):return r.get('enabled') and r.get('authStatus')==f
        if f=='capacity_retry':return r.get('capacityRetry',False)
        flags={'paused':r.get('maintenancePaused',False),'signed':r['signed'],'failed':r['checkinDetail'].get('todayCategory')=='failed','waiting':r['checkinDetail'].get('todayCategory')=='waiting','zero_skipped':r['balanceDetail'].get('waitingForCheckin',False),'sync_error':r.get('syncStatus')=='error','usable':r['routing']['state'] in ('usable','concurrency'),'candidate':r['routing']['state']=='candidate','positive':r['balanceKind']=='positive','zero':r['balanceKind']=='zero','unknown':r['balanceKind']=='unknown','due':r['balanceDetail']['due'],'queued':r['balanceDetail']['state']=='queued','stale':r['lastSuccess']>0 and not r['balanceDetail']['fresh'],'needs_login':r['enabled'] and r['needsLogin'],'auth_recheck':r.get('authRecheck',False),'cooling':r['cooldownUntil']>now,'unsigned':not r['signed'],'renewable':r.get('credentialRenewable',False)}
        return not f or flags.get(f,False)
    rows=[r for r in state['accounts'] if match(r)];total=len(rows);page=min(page,max(0,(total-1)//size))
    return {'at':now,'total':total,'page':page,'size':size,'items':rows[page*size:(page+1)*size], 'view':{k:state[k] for k in ('at','builtAt','summary','dashboard','config') if k in state}}

class ProxyHealth:
    def __init__(self,db,decode,settings):
        self.db=db;self.decode=decode;self.settings=settings;self.lock=threading.Lock();self.active=set();self.pool=concurrent.futures.ThreadPoolExecutor(max_workers=3,thread_name_prefix='proxy-health')
        with db() as c:c.execute('create table if not exists proxy_health(id text primary key,checked_at integer,status text,latency_ms integer,http_status integer,message text)')
    def rows(self):
        with self.db() as c:rows=[dict(r) for r in c.execute('select p.id,p.label,p.enabled,h.checked_at,h.status,h.latency_ms,h.http_status,h.message from proxies p left join proxy_health h on p.id=h.id order by p.enabled desc,p.label,p.id')]
        with self.lock:active=set(self.active)
        for r in rows:
            r['testing']=r['id'] in active;r['status']=r['status'] or 'untested'
        return rows
    def refs(self,pid):
        return [p+'/'+a for p,pc in self.settings()['providers'].items() for a in ['balance','checkin','credential'] if pc.get(a,{}).get('route')==pid]
    def toggle(self,pid,enabled):
        if not isinstance(enabled,bool):raise ValueError('enabled 必须为布尔值')
        if not enabled and self.refs(pid):raise ValueError('节点被固定出口设置引用，请先更换对应出口')
        with self.db() as c:
            if not c.execute('update proxies set enabled=? where id=?',(int(enabled),pid)).rowcount:raise ValueError('节点不存在')
        return {'ok':True,'enabled':enabled}
    def delete(self,pid):
        if self.refs(pid):raise ValueError('节点被固定出口设置引用，请先更换对应出口')
        with self.lock:
            if pid in self.active:raise ValueError('节点正在检测，请等待检测结束')
        with self.db() as c:
            c.execute('delete from proxies where id=?',(pid,));c.execute('delete from proxy_health where id=?',(pid,))
        return {'ok':True}
    def start(self,ids):
        if not isinstance(ids,list) or not 1<=len(ids)<=100 or any(not isinstance(i,str) for i in ids):raise ValueError('请选择1—100个节点')
        with self.db() as c:known={r['id']:dict(r) for r in c.execute('select * from proxies')}
        if any(i not in known for i in ids):raise ValueError('包含不存在的节点')
        added=[]
        with self.lock:
            if len(self.active)+len(set(ids)-self.active)>105:raise ValueError('检测队列已满')
            for i in dict.fromkeys(ids):
                if i in self.active:continue
                self.active.add(i);added.append(i)
        for i in added:self.pool.submit(self._run,known[i])
        return {'queued':len(added),'skipped':len(set(ids))-len(added),'concurrency':3,'timeoutSeconds':12}
    def _run(self,row):
        start=time.monotonic();status='failed';code=0;ms=None;message='代理连通检测失败'
        try:
            u=urllib.parse.urlsplit(self.decode(row['secret'])['url']);ipaddress.IPv4Address(u.hostname)
            typ={'http':'http','socks5':'socks5','socks4':'socks4'}[u.scheme];user=urllib.parse.unquote(u.username or '');pw=urllib.parse.unquote(u.password or '')
            if not u.port or any(ch.isspace() for ch in user+pw):raise ValueError('invalid proxy')
            env={k:v for k,v in os.environ.items() if 'proxy' not in k.lower()}
            with tempfile.TemporaryDirectory(prefix='node-health-') as tmp:
                cfg=pathlib.Path(tmp)/'proxychains.conf';cfg.write_text('strict_chain\nquiet_mode\nproxy_dns\ntcp_read_time_out 7000\ntcp_connect_time_out 5000\n[ProxyList]\n'+f'{typ} {u.hostname} {u.port}'+(f' {user} {pw}' if user else '')+'\n');cfg.chmod(0o600)
                env.update(LD_PRELOAD='/usr/lib/x86_64-linux-gnu/libproxychains.so.4',PROXYCHAINS_CONF_FILE=str(cfg))
                script="import urllib.request,json,time; t=time.monotonic(); o=urllib.request.build_opener(urllib.request.ProxyHandler({})); r=o.open('https://www.gstatic.com/generate_204',timeout=9); r.read(32); print(json.dumps({'code':r.status,'ms':round((time.monotonic()-t)*1000)}))"
                p=subprocess.run(['/usr/local/bin/python3','-c',script],env=env,capture_output=True,text=True,timeout=12)
                if p.returncode==0:
                    v=json.loads(p.stdout);code=int(v['code']);ms=int(v['ms']);status='ok' if code==204 else 'failed';message='HTTPS 204 连通成功' if status=='ok' else '检测端点未返回预期状态'
                else:message='代理连接、认证、DNS 或 TLS 失败（不代表账户失效）'
        except subprocess.TimeoutExpired:status='timeout';message='检测超过12秒'
        except Exception:message='节点配置或连通检测失败'
        finally:
            try:
                with self.db() as c:c.execute('insert or replace into proxy_health values(?,?,?,?,?,?)',(row['id'],int(time.time()*1000),status,ms,code,message))
                if hasattr(self,'on_result'):self.on_result(row['id'],status)
            finally:
                with self.lock:self.active.discard(row['id'])

