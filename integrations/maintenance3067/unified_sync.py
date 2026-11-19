"""Central maintenance inventory and versioned, non-destructive account mirroring.

Credentials remain on the private bridge and encrypted source database. Public
status contains counts, account IDs and fixed explanations only.
"""
import base64
import collections
import datetime
import hashlib
import hmac
import json
import math
import pathlib
import secrets
import threading
import time
import urllib.request

from maintenance_policy import credential_meta
from maintenance_state import credential_version, resolve_auth, cooldown_map

PRIMARY = {'loomy', 'raccoon', 'codearts'}
TZ = datetime.timezone(datetime.timedelta(hours=8))
BRIDGE_INVENTORY_LOCK = threading.Lock()
BRIDGE_RUNTIME_LOCK = threading.Lock()
BRIDGE_WPS_LOCK = threading.Lock()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def millis(value):
    try:
        n = float(value)
        if not math.isfinite(n): return 0
        return int(n * 1000 if 0 < n < 100000000000 else n)
    except (TypeError, ValueError, OverflowError):
        try:
            dt = datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
            if dt.tzinfo is None: dt = dt.replace(tzinfo=datetime.timezone.utc)
            return int(dt.timestamp() * 1000)
        except (ValueError, TypeError): return 0


def preserve_balance_observations(inventory, observed):
    for key,record in inventory.items():
        live=observed.get(key,{})
        same_identity=live.get('uid')==record.get('uid')
        same_version=bool(record.get('auth_hash') and record.get('auth_hash')==live.get('auth_hash'))
        if same_identity and (record.get('platform')!='wps-lingxi' or same_version) and millis(live.get('balance_at'))>millis(record.get('balance_at')):
            record.update(balance=live.get('balance'),balance_at=live['balance_at'])
        if same_identity and same_version and millis(live.get('verification_at'))>millis(record.get('verification_at')):
            for field in ('verification_status','verification_at','verified_balance_at','needs_login','signed_at'):
                if field in live:record[field]=live[field]


def jwt_claims(token):
    try:
        part = str(token).removeprefix('Bearer ').split('.')[1]
        data = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
        return data if isinstance(data, dict) else {}
    except Exception: return {}


def auth_token(auth):
    return str(auth.get('token') or auth.get('session') or auth.get('accessToken') or auth.get('security_token') or auth.get('cookie') or auth.get('key') or '')


def token_digest(auth):
    return hashlib.sha256(auth_token(auth).encode()).hexdigest()


def overlay_source_auth(source, target):
    merged={**target['auth'],**{k:v for k,v in source['auth'].items() if v not in ('',None)}}
    # Loomy's native account creation drops expiresAt. A missing source field
    # must not erase a registration receipt belonging to this identical session.
    if source['platform']=='loomy' and auth_token(source['auth'])==auth_token(target['auth']) and not millis(source['auth'].get('expires_at')):
        merged['expires_at']=target['auth'].get('expires_at',0)
    return merged


def source_record(row, data):
    p = row['provider']; s = data.get('pluginSecret') or data
    if p == 'loomy':
        token = s.get('session') or s.get('token') or data.get('accessToken')
        uid = str(s.get('userId') or s.get('uid') or data.get('uid') or '')
        auth = {'realm': 'cn', 'token': token, 'uid': uid, 'phone': s.get('phone') or '',
                'updatedAt': s.get('updatedAt') or s.get('addedAt'), 'expires_at': s.get('expiresAt') or 0}
        for k in ('devid', 'loginid', 'password'):
            if s.get(k): auth[k] = s[k]
    elif p == 'raccoon':
        token = s.get('accessToken') or data.get('accessToken') or s.get('token')
        cl = jwt_claims(token)
        uid = str(cl.get('sub') or s.get('userId') or data.get('uid') or '')
        auth = {'realm': 'cn', 'token': token, 'uid': uid,
                'expires_at': s.get('expiresAt') or millis(cl.get('exp')),
                'agent2api': dict(s)}
        refresh = s.get('refreshToken') or data.get('refreshToken') or s.get('refresh_token')
        if refresh: auth['refresh_token'] = refresh
    elif p == 'codearts':
        uid = str(s.get('user_id') or s.get('userId') or data.get('uid') or '')
        auth = dict(s)
        auth.update(realm='cn', uid=uid, access_key=s.get('access_key_id') or s.get('access_key'),
                    secret_key=s.get('secret_access_key') or s.get('secret_key'),
                    refresh_token=s.get('refresh_token') or s.get('refreshToken'),
                    expires_at=s.get('expires_at') or s.get('expiresAt'))
    elif p == 'wps-lingxi':
        from ag_wps_client import wps_auth
        auth=wps_auth(s);uid=str(auth.get('uid') or hashlib.sha256(auth['cookie'].encode()).hexdigest())
    else: raise ValueError('unsupported_provider')
    if not uid or not auth_token(auth): raise ValueError('missing_identity_or_credential')
    return {'platform': p, 'uid': uid, 'name': str(data.get('name') or uid), 'auth': auth,
            'status': 'active' if row['enabled'] else 'disabled', 'source_id': row['id'],
            'balance': row.get('remaining'), 'balance_at': row.get('last_success_at') or 0,
            'credential_at': millis(data.get('updatedAt')),
            'expiry': millis(auth.get('expires_at')), 'last_success': row.get('last_success_at') or 0}


def choose_credentials(source, target, previous=None):
    """Choose by change provenance, then expiry. Unknown first-import conflicts stay visible."""
    sh, th = token_digest(source['auth']), token_digest(target['auth'])
    if sh == th: return 'same'
    previous = previous or {}
    old_s, old_t = previous.get('source_token'), previous.get('target_token')
    if old_s and old_t:
        if sh != old_s and th == old_t: return 'source'
        if th != old_t and sh == old_s: return 'target'
    se = millis(source['auth'].get('expires_at'))
    te = millis(target['auth'].get('expires_at'))
    if se and te and se != te: return 'source' if se > te else 'target'
    # JWT issued-at can order credentials even when the expiry fields are absent.
    si = millis(jwt_claims(auth_token(source['auth'])).get('iat'))
    ti = millis(jwt_claims(auth_token(target['auth'])).get('iat'))
    if si and ti and si != ti: return 'source' if si > ti else 'target'
    return 'conflict'


def bridge_call(payload):
    raise RuntimeError('This maintenance candidate supports Agent2API only')

class UnifiedMaintenance:
    def __init__(self,db,decode,encode,official,event,now,today):
        self.db,self.decode,self.encode,self.official,self.event,self.now,self.today=db,decode,encode,official,event,now,today
        self.sync_lock=threading.Lock();self.wake=threading.Event()
    def status(self):return {'mode':'agent2api-only','enabled':False,'message':'账户和回执统一由 AG 管理'}
    def account_sync_state(self,aid):return {'syncState':'single_gateway'}
    def loomy_credential_state(self,aid):return {}
    def external_rows(self,*args):return []
    def routing_entries(self):return {}
    def registration_handoff(self,data):
        # Registration belongs to AG's existing authenticated import flow.
        raise ValueError('请通过 AG 导入账户；已移除双端注册同步')
    def _write_primary(self, record, current=None):
        p=record['platform'];auth=record['auth']
        old=current.get('_data',{}) if current else {}
        if current:
            with self.db(True,True) as c:
                live=c.execute('select data from accounts where id=?',(current['source_id'],)).fetchone()
            if not live or credential_version(self.decode(live[0]).get('pluginSecret') or {})!=credential_version(old.get('pluginSecret') or {}):
                raise RuntimeError('3065凭证已变化，等待下一轮核对')
        from direct_maintenance import secret_of
        secret=dict(secret_of(old))
        if p=='loomy':
            secret.update(session=auth_token(auth), userId=record['uid'])
            for k in ('phone','devid','loginid','password'):
                if auth.get(k):secret[k]=auth[k]
            if auth.get('expires_at'):secret['expiresAt']=millis(auth['expires_at'])
        elif p=='raccoon':
            secret.update(auth.get('agent2api') or {})
            secret.update(accessToken=auth_token(auth),userId=record['uid'])
            if auth.get('refresh_token'):secret['refreshToken']=auth['refresh_token']
            if auth.get('expires_at'):secret['expiresAt']=millis(auth['expires_at'])
        elif p=='codearts':
            secret.update(auth)
            secret.update(access_key_id=auth.get('access_key') or auth.get('access_key_id'),
                secret_access_key=auth.get('secret_key') or auth.get('secret_access_key'),
                security_token=auth.get('security_token'),user_id=record['uid'],userId=record['uid'])
            if auth.get('refresh_token'):secret.update(refresh_token=auth['refresh_token'],refreshToken=auth['refresh_token'])
        else:raise ValueError('unsupported_primary')
        if current:
            from direct_maintenance import secret_of
            result=self.official().call('/api/external-maintenance/apply',{
                'account':current['source_id'],'provider':p,'action':'credential',
                'requestId':'inventory-'+secrets.token_hex(12),'observedAt':self.now(),
                'expect':secret_of(old),'secret':secret})
            if result.get('applied') is not True:raise RuntimeError('凭证条件同步未确认')
            return result
        payload={'provider':p,'uid':record['uid'],'name':record.get('name') or record['uid'],
                 'pluginSecret':secret,'usageQuery':{'enabled':False,'interval':0}}
        if current:payload['id']=current['source_id']
        else:payload['enabled']=record.get('status')=='active'
        result=self.official().call('/api/accounts/import',{'accounts':[payload]}) or {}
        if result.get('failed') or result.get('errors') or not result.get('importedIds'):raise RuntimeError('3065未确认凭证同步')
        return result
