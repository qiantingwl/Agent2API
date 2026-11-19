"""WPS maintenance through the same durable AG receipt/outbox as other providers."""
import datetime, hashlib, json
from direct_clients import Client as NativeClient, Unsupported

def pending_wps_models(account, secret=None):
    """Only probe explicit, current AG model gates; never guess a model."""
    gates=[v for k,v in account.items() if k.startswith('pluginLedger.wpsRecovery.') and isinstance(v,dict) and v.get('blocked') is True]
    if any(v.get('reason') in ('verification','identity') for v in gates):return []
    secret=secret if isinstance(secret,dict) else account.get('pluginSecret')
    stamp=None
    if isinstance(secret,dict):
        metadata=secret.get('metadata') or {}
        values=[metadata.get('cookie'),secret.get('cookie'),secret.get('key'),secret.get('access'),metadata.get('sid')]
        stamp=hashlib.sha256(json.dumps(values,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    if any(v.get('reason')=='authentication' and (stamp is None or v.get('credential')==stamp) for v in gates):return []
    gates.sort(key=lambda v:int(v.get('at') or 0))
    return list(dict.fromkeys(v['model'] for v in gates if v.get('reason') in ('permission','rate') and isinstance(v.get('model'),str) and 0<len(v['model'].strip())<=160))

def wps_auth(secret):
    metadata=secret.get('metadata') or {}
    raw=metadata.get('cookie') or secret.get('cookie') or secret.get('key') or secret.get('access') or metadata.get('sid') or ''
    if not isinstance(raw,str) or not raw.strip():raise Unsupported('缺少 WPS Cookie')
    raw=raw.strip()
    if '=' not in raw:raw='wps_sid='+raw
    cookies={}
    for item in raw.split(';'):
        name,sep,value=item.strip().partition('=')
        if sep and name in ('wps_sid','uid','copilot_server_branch'):cookies[name]=value
    if not cookies.get('wps_sid') or any(c in raw for c in '\r\n'):raise Unsupported('WPS Cookie 无效')
    base=metadata.get('host') or metadata.get('base') or secret.get('base') or 'https://lingxi.wps.cn'
    if not isinstance(base,str):raise Unsupported('WPS 登录域名无效')
    base=base.rstrip('/')
    if base not in ('https://lingxi.wps.cn','https://lingxi.kdocs.cn'):
        raise Unsupported('WPS 登录域名不受支持')
    return {'cookie':'; '.join(k+'='+v for k,v in cookies.items()),'uid':cookies.get('uid',''),'base':base}

class WpsClient:
    def __init__(self,secret,proxy,timeout,ledger):
        from wps_maintenance import WpsClient as Protocol
        if proxy:raise Unsupported('WPS 维护保留已配置的官方直连策略')
        self.protocol=Protocol(wps_auth(secret),timeout);self.ledger=ledger
    def close(self):pass
    def balance(self):return {'available':self.protocol.balance(),'unit':'智点'}
    def renew(self):raise Unsupported('WPS Cookie 不支持自动续期，请重新登录')
    def checkin(self,verify_only=False):
        from wps_maintenance import TZ
        day=datetime.datetime.now(TZ).date().isoformat();daily=self.protocol.daily()
        if not daily:return {'confirmed':False}
        if daily.get('status')=='claimed':return {'confirmed':True}
        key='wps-claim-intent:'+day
        if verify_only or not self.ledger or self.ledger(key):return {'confirmed':False}
        # Persist before POST. Lost acknowledgement never causes a repeated claim.
        self.ledger(key,{'started':True})
        self.protocol.call('tasks/daily_check_in/claim?date='+day,post=True)
        return {'confirmed':(self.protocol.daily() or {}).get('status')=='claimed'}

def Client(provider,secret,proxy=None,timeout=30,ledger=None):
    if provider=='wps-lingxi':return WpsClient(secret,proxy,timeout,ledger)
    return NativeClient(provider,secret,proxy,timeout,ledger)
