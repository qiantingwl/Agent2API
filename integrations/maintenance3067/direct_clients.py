"""Standalone upstream maintenance protocols; no gateway/plugin execution.

Protocol references: Agent2Providers v3.4.2 (AGPL-3.0), MiraiHub v1.1.1
signing implementations. direct_signer/direct_xfyun retain their source comments.
"""
import base64, datetime, json, math, secrets, time
from urllib.parse import urlencode
import requests
from direct_signer import sign
from raccoon_ledger import scan

TZ=datetime.timezone(datetime.timedelta(hours=8))
LOOMY='https://loomyad.xunfei.cn'
RACCOON='https://xiaohuanxiong.com'
CODEARTS='https://snap-access.cn-north-4.myhuaweicloud.com'
STS='https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens'

class UpstreamError(RuntimeError): pass
class Unsupported(RuntimeError): pass

def number(value):
    if value is None or isinstance(value,bool):return None
    try:
        n=float(value)
        return n if math.isfinite(n) else None
    except (ValueError,TypeError):return None

def jwt(token):
    try:
        part=token.removeprefix('Bearer ').split('.')[1]
        return json.loads(base64.urlsafe_b64decode(part+'='*(-len(part)%4)))
    except (ValueError,IndexError,TypeError):return {}

def codearts_usage(payload):
    if not isinstance(payload.get('metrics'),list):raise UpstreamError('CodeArts statistics missing metrics')
    rows=[r for r in payload['metrics'] if r.get('show') is True and r.get('name')]
    parts=[number(r.get('package_credit_remain')) for r in rows if r['name']!='usageTotalPackageCredit']
    parts=[n for n in parts if n is not None]
    values=[];wallets=[]
    for r in rows:
        n=number(r.get('package_credit_remain'))
        if n is None:continue
        wallets.append({'type':r['name'],'displayName':r['name'],'balance':n})
        if r['name']=='usageTotalPackageCredit' and parts and math.isclose(n,sum(parts),rel_tol=1e-6,abs_tol=2.22e-16):continue
        values.append(n)
    return {'available':sum(values) if values else None,'unit':'积分','wallets':wallets}

def dpop(context,method,url):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives import hashes
    private=context['dpop_key_pair']['private_key_jwk']
    public=context['dpop_key_pair']['public_key_jwk']
    if isinstance(private,str):private=json.loads(private)
    if isinstance(public,str):public=json.loads(public)
    if private.get('crv')!='P-256' or private.get('kty')!='EC':raise Unsupported('Invalid DPoP key type')
    b64=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=')
    pack=lambda o:b64(json.dumps(o,separators=(',',':')).encode())
    head={'alg':'ES256','typ':'dpop+jwt','jwk':{k:public[k] for k in ('kty','crv','x','y')}}
    body={'htm':method,'htu':url,'iat':int(time.time()),'jti':secrets.token_hex(16)}
    content=pack(head)+b'.'+pack(body)
    scalar=int.from_bytes(base64.urlsafe_b64decode(private['d']+'=='),'big')
    key=ec.derive_private_key(scalar,ec.SECP256R1())
    r,s=decode_dss_signature(key.sign(content,ec.ECDSA(hashes.SHA256())))
    return (content+b'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))).decode()

class Client:
    def __init__(self,provider,secret,proxy=None,timeout=30,ledger=None):
        self.provider=provider;self.secret=secret;self.timeout=min(timeout,45)
        self.deadline=time.monotonic()+self.timeout
        self.session=requests.Session();self.session.trust_env=False
        if proxy:
            if proxy.startswith('socks5://'):proxy='socks5h://'+proxy[9:]
            self.session.proxies={'http':proxy,'https':proxy}
        self.ledger=ledger

    def close(self):self.session.close()

    def request(self,method,url,headers=None,body=None):
        # Never forward credentials to a redirect target; never expose error bodies.
        try:
            remaining=self.deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('维护操作达到总时限')
            with self.session.request(method,url,headers=headers,data=body,timeout=(min(8,remaining),remaining),allow_redirects=False,stream=True) as r:
                chunks=[];size=0
                for chunk in r.iter_content(8192):
                    size+=len(chunk)
                    if size>4*1024*1024:raise UpstreamError('Upstream response too large')
                    if time.monotonic()>self.deadline:raise TimeoutError('维护操作达到总时限')
                    chunks.append(chunk)
                raw=b''.join(chunks)
                if not 200<=r.status_code<300:
                    try:error=json.loads(raw)
                    except (ValueError,TypeError):error={}
                    if isinstance(error,dict) and error.get('error_code')=='APIG.0602':
                        raise UpstreamError('HTTP 401 credential expired (APIG.0602)')
                    raise UpstreamError('HTTP '+str(r.status_code))
                result=json.loads(raw)
        except requests.Timeout:raise TimeoutError('上游请求超时') from None
        except requests.RequestException:raise UpstreamError('上游连接失败') from None
        except ValueError:raise UpstreamError('Upstream returned invalid JSON') from None
        if not isinstance(result,dict):raise UpstreamError('Upstream response is not an object')
        return result

    def loomy(self,path,body=None):
        token=self.secret.get('session') or self.secret.get('token') or self.secret.get('accessToken')
        if not token:raise UpstreamError('HTTP 401 missing session')
        headers={'token':token,'Authorization':'Bearer '+token,'Content-Type':'application/json'}
        result=self.request('POST' if body is not None else 'GET',LOOMY+path,headers,json.dumps(body,separators=(',',':')).encode() if body is not None else None)
        code=str(result.get('code',''))
        if code in ('020002','100002'):raise UpstreamError('HTTP 401 session expired')
        if code!='000000':raise UpstreamError('Loomy business response rejected')
        data=result.get('data')
        if not isinstance(data,dict):raise UpstreamError('Loomy missing data')
        return data.get('data',data)

    def raccoon(self,path,body=None):
        token=self.secret.get('accessToken') or self.secret.get('token') or ''
        if not token:raise UpstreamError('HTTP 401 missing token')
        headers={'Authorization':'Bearer '+token.removeprefix('Bearer ').strip(),'Accept':'application/json',
            'X-Client-Name':'raccoon-work','X-Client-Platform':'desktop-linux','X-Client-Version':'v1.1.5',
            'X-Request-Id':f'relay_js_{int(time.time()*1000)}_{secrets.token_hex(4)}'}
        identity=self.secret.get('officeIdentity') or self.secret.get('office_identity')
        if identity and identity!='personal':headers['X-Org-Code']=identity
        if body is not None:headers['Content-Type']='application/json'
        result=self.request('POST' if body is not None else 'GET',RACCOON+path,headers,json.dumps(body,separators=(',',':')).encode() if body is not None else None)
        if result.get('code') not in (0,'0'):raise UpstreamError('Raccoon business response rejected')
        if not isinstance(result.get('data'),dict):raise UpstreamError('Raccoon missing data')
        return result['data']

    def codearts(self,path,body=None):
        s=self.secret;method='POST' if body is not None else 'GET'
        payload=json.dumps(body,separators=(',',':')).encode() if body is not None else b''
        headers=({'Content-Type':'application/json','Agent-Type':'PromptCenter','X-Language':'en-us'} if path.startswith('/v1/ops/') else
                 {'Accept':'application/json','X-Language':'en-us','plugin-name':'snap_vscode','plugin-version':'26.9.101'})
        headers['X-Security-Token']=s.get('security_token') or s.get('securityToken') or ''
        if s.get('domain_id'):headers['X-Domain-Id']=s['domain_id']
        ak=s.get('access_key_id') or s.get('access_key');sk=s.get('secret_access_key') or s.get('secret_key')
        if not ak or not sk or not headers['X-Security-Token']:raise Unsupported('Missing CodeArts AK/SK/STS')
        url=CODEARTS+path
        headers=sign(method,url,headers,payload,ak,sk)
        result=self.request(method,url,headers,payload if body is not None else None)
        if path.startswith('/v1/ops/'):
            if type(result.get('code')) is not int or result['code']!=0:raise UpstreamError('CodeArts welfare not accepted')
            return result.get('data') or {}
        return result

    def balance(self):
        if self.provider=='loomy':
            data=self.loomy('/api/v2/points/records?pageNo=1&pageSize=1&direction=debit&granularity=chat')
            permanent=number(data.get('balance'));daily=number(data.get('dailyBalance'))
            return {'available':permanent+daily if permanent is not None and daily is not None else None,'unit':'积分',
                'wallets':[{'type':'permanent_points','displayName':'永久积分','balance':permanent},{'type':'daily_points','displayName':'每日赠送积分','balance':daily}]}
        if self.provider=='raccoon':
            data=self.raccoon('/api/web/points/v1/balance')
            total=number(data.get('total_chargeable_points'))
            if total is None:total=number(data.get('available_points'))
            return {'available':total,'unit':'积分','wallets':[{'type':k,'displayName':k,'balance':number(data[k])} for k in ('daily_points','monthly_points','reward_points','topup_points','enterprise_topup_points') if k in data]}
        if self.provider=='codearts':return codearts_usage(self.codearts('/snap-manager/v1/statistics/plugin'))
        raise Unsupported('Provider deferred')

    def checkin(self,verify_only=False):
        day=datetime.datetime.now(TZ).date().isoformat()
        if self.provider=='loomy':
            self.loomy('/api/v1/points/first-login',{})
            return {'confirmed':True,'day':day}
        if self.provider=='raccoon':
            def page(cursor,limit):
                return self.raccoon('/api/web/points/v2/bills?'+urlencode({'limit':limit,**({'cursor':cursor} if cursor else {})}))
            before=scan(page,day,max_pages=5)
            if before['outcome']=='done':return {'confirmed':True,'day':day,'evidence':before['evidence']}
            if not verify_only:
                org=self.secret.get('officeIdentity') or self.secret.get('office_identity')
                self.raccoon('/api/web/org/user/office/v1/setting_info' if org and org!='personal' else '/api/web/office/v3/setting_info')
            after=scan(page,day,max_pages=5)
            return {'confirmed':after['outcome']=='done','day':day,'evidence':after['evidence']}
        if self.provider=='codearts':return self.codearts_checkin(day)
        raise Unsupported('Provider deferred')

    def codearts_checkin(self,day):
        def delivery():
            data=self.codearts('/v1/ops/delivery?channel=IDE')
            if not isinstance(data.get('items'),list):raise UpstreamError('Missing campaign list')
            return [r for r in data['items'] if r.get('type')=='USER_LOGIN' and r.get('benefitUnit')=='CREDIT']
        def confirmed(r):return r.get('claimable') is False and r.get('status') in ('CONFIRMED','CONSUMED')
        items=delivery()
        if not items:return {'confirmed':False,'day':day}
        # A pre-existing CONFIRMED lacks a date; only today's local receipt proves today's completion.
        proof=self.ledger('checkin:'+day) or {}
        if all(confirmed(r) for r in items):return {'confirmed':proof.get('confirmed') is True,'day':day}
        for r in items:
            if confirmed(r):continue
            cid=r.get('campaignId')
            if type(cid) not in (str,int) or cid=='':raise UpstreamError('Invalid campaign id')
            key='campaign:'+day+':'+json.dumps(cid)
            progress=self.ledger(key) or {'idempotentKey':'claim_'+secrets.token_hex(16)}
            if r.get('status')=='CLAIMED':progress['claimed']=True
            if r.get('claimable') and not progress.get('claimed'):
                self.ledger(key,progress) # durable before issuing the non-read request
                result=self.codearts('/v1/ops/claim',{'campaignId':cid,'idempotentKey':progress['idempotentKey'],'channel':'IDE'})
                if result.get('campaignId')!=cid:raise UpstreamError('Claim campaign mismatch')
                progress['claimed']=True;self.ledger(key,progress)
            if progress.get('claimed'):self.codearts('/v1/ops/confirm',{'campaignId':cid})
        after=delivery()
        ok=all(any(a.get('campaignId')==r.get('campaignId') and confirmed(a) for a in after) for r in items)
        if ok:self.ledger('checkin:'+day,{'confirmed':True})
        return {'confirmed':ok,'day':day}

    def invitation(self,code=None):
        if self.provider!='loomy':raise Unsupported('仅 Loomy 支持此邀请绑定协议')
        state=self.loomy('/api/v1/points/activation')
        if code and state.get('activated') is not True:
            body={'inviteCode':code}
            if self.secret.get('devid'):body['deviceId']=self.secret['devid']
            self.loomy('/api/v1/points/activation',body)
            state=self.loomy('/api/v1/points/activation')
        return {'activated':state.get('activated') is True,'code':str(state.get('appliedInvitationCode') or ''),
                'confirmed':state.get('activated') is True and (not code or state.get('appliedInvitationCode')==code)}

    def renew(self):
        s=self.secret
        if self.provider=='loomy':
            import direct_xfyun as x
            loginid=s.get('loginid') or s.get('phone');password=s.get('password')
            if not loginid or not password:raise Unsupported('缺少手机号或密码，不能自动重登')
            def call(path,param):
                body=json.dumps({'base':x._base(s.get('devid') or 'web'),'param':param},ensure_ascii=False,separators=(',',':'))
                result=self.request('POST','https://account.xfinfr.com'+path,x.sign_headers('POST',path,body),body.encode())
                if str(result.get('code'))!='000000':raise UpstreamError('Loomy password login rejected')
                return result.get('data') or {}
            pub=call('/login/account/getPuKey',{})
            result=call('/login/account/byPwd',{'loginid':loginid,'password':x.rsa_encrypt(pub['pukey'],password),'rcode':pub.get('rcode',''),'type':1,'expire':x.SESSION_EXPIRE_SECONDS})
            uid=str(result.get('userid') or result.get('uid') or '')
            if not result.get('session') or uid!=str(s.get('userId') or s.get('uid')):raise UpstreamError('Loomy login identity mismatch')
            t=int(time.time()*1000)
            return {**s,'session':result['session'],'expiresAt':t+x.SESSION_EXPIRE_SECONDS*1000,'issuedAt':t,'updatedAt':t,'expirySource':'requested'}
        if self.provider=='raccoon':
            token=s.get('accessToken') or s.get('token') or ''
            if str(jwt(token).get('iss','')).endswith('/iam'):raise Unsupported('IAM 凭证不能使用旧刷新接口')
            refresh=s.get('refreshToken') or s.get('refresh_token')
            if not refresh:raise Unsupported('Missing refresh token')
            data=self.raccoon('/api/web/auth/v1/refresh',{'refresh_token':refresh})
            new=data.get('access_token');claims=jwt(new or '')
            if not new or not claims.get('exp'):raise UpstreamError('Refresh missing access credential')
            oldclaims=jwt(token)
            if oldclaims.get('sub') and claims.get('sub') and oldclaims['sub']!=claims['sub']:raise UpstreamError('Refresh identity mismatch')
            return {**s,'accessToken':new,'refreshToken':'' if str(claims.get('iss','')).endswith('/iam') else data.get('refresh_token') or refresh,'expiresAt':int(claims['exp']*1000)}
        if self.provider=='codearts':
            context=s.get('oauth_context') or {}
            verifier=context.get('pkce_pair',{}).get('code_verifier');refresh=s.get('refresh_token') or s.get('refreshToken')
            if not verifier or not refresh:raise Unsupported('缺少 CodeArts PKCE/刷新凭证')
            body=urlencode({'client_id':'vscode-codebot','code_verifier':verifier,'grant_type':'refresh_token','refresh_token':refresh}).encode()
            data=self.request('POST',STS,{'Content-Type':'application/x-www-form-urlencoded','DPoP':dpop(context,'POST',STS)},body)
            credentials=data.get('credentials') or {}
            keys=('access_key_id','secret_access_key','security_token','expiration')
            if not all(credentials.get(k) for k in keys):raise UpstreamError('STS response incomplete')
            expiry=credentials['expiration'];expiry_ms=int(datetime.datetime.fromisoformat(expiry.replace('Z','+00:00')).timestamp()*1000)
            new_refresh=data.get('refresh_token') or refresh
            return {**s,**{k:credentials[k] for k in keys[:3]},'expires_at':expiry,'expiresAt':expiry_ms,
                    'refresh_token':new_refresh,'refreshToken':new_refresh,'accessToken':credentials['security_token']}
        raise Unsupported('Provider deferred')
