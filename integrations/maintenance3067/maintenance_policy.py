"""Scheduling metadata for the independent upstream maintenance controller."""
import base64, json, datetime

def credential_meta(provider, secret):
    if provider == 'loomy':
        renewable=bool(secret.get('loginid') and secret.get('password'))
        try:
            expiry=float(secret.get('expiresAt') or secret.get('expires_at') or 0)
            expiry=int(expiry*1000 if 0<expiry<100000000000 else expiry)
        except (ValueError,TypeError,OverflowError):expiry=0
        return {'credentialRenewable':renewable,'credentialExpiresAt':expiry,
                'credentialLeadMs':86400000,
                'credentialReason':'3067使用已保存的手机号和密码独立续期' if renewable else '未保存手机号和密码，需要手动重登'}
    if provider == 'codearts':
        from unified_sync import millis
        expiry=millis(secret.get('expiresAt') or secret.get('expires_at'))
        context=secret.get('oauth_context') or {}
        renewable=bool((secret.get('refreshToken') or secret.get('refresh_token')) and context.get('pkce_pair',{}).get('code_verifier') and context.get('dpop_key_pair',{}).get('private_key_jwk'))
        return {'credentialRenewable':renewable,'credentialExpiresAt':expiry,'credentialLeadMs':3600000,
                'credentialReason':'提前一小时独立续期' if renewable else '缺少刷新凭证或 PKCE/DPoP 材料'}
    if provider == 'wps-lingxi':
        return {'credentialRenewable': False, 'credentialExpiresAt': 0,
                'credentialReason': '保活为余额探测，不保证延长登录态'}
    if provider != 'raccoon':
        return {'credentialRenewable': False, 'credentialExpiresAt': 0, 'credentialReason': '官方插件不支持续期'}
    token = next((secret.get(k) for k in ('accessToken','token','access_token') if isinstance(secret.get(k),str) and secret[k]), '')
    if token.lower().startswith('bearer '): token = token[7:].strip()
    claims = {}
    try:
        part=token.split('.')[1]; claims=json.loads(base64.urlsafe_b64decode(part+'='*(-len(part)%4)))
        if not isinstance(claims,dict): claims={}
    except (ValueError,IndexError,TypeError): pass
    refresh=next((secret.get(k) for k in ('refreshToken','refresh_token') if isinstance(secret.get(k),str) and secret[k].strip()), '')
    iam=str(claims.get('iss','')).endswith('/iam')
    expiry=0
    for value,seconds in [(secret.get('expiresAt'),False),(claims.get('exp'),True),(secret.get('tokenExpiresAt'),False)]:
        try:
            value=float(value)
            if value>0: expiry=int(value*1000 if seconds or value<100000000000 else value);break
        except (ValueError,TypeError,OverflowError): pass
    renewable=bool(token and refresh and not iam)
    return {'credentialRenewable':renewable,'credentialExpiresAt':expiry,'credentialReason': '支持官方续期' if renewable else 'IAM凭证不支持刷新令牌续期' if iam else '缺少可续期凭证'}

def balance_interval(row, config):
    return config.get('positiveInterval',config['interval']) if (row.get('balance') or 0)>0 else config['interval']


def balance_next_at(row, completed_at, timestamp, config):
    """The next cycle starts when the previous query completed, never enqueue time."""
    completed=max(row.get('lastSuccess',0) or 0,row.get('lastAttempt',0) or 0,completed_at or 0)
    if row.get('balanceCredentialChanged') or row.get('balanceRefreshRequestedAt',0)>row.get('lastSuccess',0) or row.get('signedAt',0)>completed:return timestamp
    return completed+balance_interval(row,config)*1000 if completed else timestamp

def credential_due(row, previous, timestamp, config):
    if not row.get('credentialRenewable'):return False
    expires=row.get('credentialExpiresAt',0)
    if expires and expires>timestamp+row.get('credentialLeadMs',300000):return False
    interval=config.get('interval',300) if expires else max(3600,config.get('interval',300))
    return timestamp-previous>=interval*1000

def balance_satisfied(job,row,timestamp,config):
    if row.get('balanceCredentialChanged') or row.get('balanceRefreshRequestedAt',0)>row.get('lastSuccess',0):return False
    success=row.get('lastSuccess',0)
    if not success:return False
    required=job.get('required_after',0)
    if required:return success>=required
    if row.get('signedAt',0)>success:return False
    return job.get('origin')=='auto' and timestamp-success<balance_interval(row,config)*1000


def balance_waits_for_checkin(row):
    """A confirmed zero leaves periodic polling until a newer successful checkin."""
    return (row.get('balanceRefreshRequestedAt',0)<=row.get('lastSuccess',0) and not row.get('balanceCredentialChanged') and not row.get('authCredentialChanged')
            and not row.get('unlimited') and row.get('balance') == 0
            and row.get('lastSuccess', 0) > 0
            and row.get('signedAt', 0) <= row.get('lastSuccess', 0))

