"""Narrow registration handoff into the existing CAS-protected backup bridge."""
import re
from unified_sync import source_record,auth_token,millis

class HandoffRejected(ValueError):pass


def deliver(data, db, decode, bridge, timestamp):
    if not isinstance(data,dict):raise HandoffRejected('invalid_handoff')
    for key in ('accountId','uid','phone','password','devid','session'):
        if not isinstance(data.get(key),str) or not 1<=len(data[key])<=4096:raise HandoffRejected('invalid_handoff')
    if not re.fullmatch(r'1[3-9][0-9]{9}',data['phone']) or not 8<=len(data['password'])<=128:raise HandoffRejected('invalid_handoff')
    expiry,issued=data.get('expiresAt'),data.get('issuedAt')
    if isinstance(expiry,bool) or isinstance(issued,bool) or not isinstance(expiry,int) or not isinstance(issued,int):raise HandoffRejected('invalid_expiry')
    if not 0<issued<=timestamp+30000 or not timestamp<expiry<=issued+14*86400000:raise HandoffRejected('invalid_expiry')
    if data.get('expiresAtSource') not in ('upstream','requested'):raise HandoffRejected('invalid_expiry_source')
    def source():
        with db(True,True) as c:row=c.execute('select * from accounts where id=?',(data['accountId'],)).fetchone()
        if not row or row['provider']!='loomy':raise HandoffRejected('source_account_missing')
        current=source_record(dict(row),decode(row['data']))
        if current['uid']!=data['uid'] or auth_token(current['auth'])!=data['session']:raise HandoffRejected('source_identity_or_session_changed')
        if current['auth'].get('phone') and current['auth']['phone']!=data['phone']:raise HandoffRejected('source_phone_mismatch')
        # Native POST /api/accounts omits expiry in current Loomy plugin storage.
        # Bind the receipt to its exact session; compare expiry when primary has it.
        known_expiry=millis(current['auth'].get('expires_at'))
        if known_expiry and known_expiry!=expiry:raise HandoffRejected('source_expiry_mismatch')
        return current
    current=source()
    with db() as c:
        row=c.execute('select metadata from unified_links where identity=?',('loomy|'+data['uid'],)).fetchone()
        if row:
            import json
            if json.loads(row[0]).get('tombstone'):raise HandoffRejected('identity_deleted')
    inventory=bridge({'command':'inventory'})
    if inventory.get('ok') is not True:raise HandoffRejected('inventory_unavailable')
    matches=[r for r in inventory.get('accounts',[]) if r.get('platform')=='loomy' and str(r.get('uid'))==data['uid']]
    if len(matches)>1:raise HandoffRejected('ambiguous_identity')
    target=matches[0] if matches else None
    if target and auth_token(target['auth'])!=data['session']:raise HandoffRejected('backup_session_not_synced')
    previous=target.get('auth',{}) if target else {}
    # The same session may have a later native import timestamp. Adding password
    # metadata must not roll that clock backwards or invent a newer session.
    updated=max(issued,millis(current['auth'].get('updatedAt')),millis(previous.get('updatedAt')))
    auth={**previous,**current['auth'],
          'loginid':data['phone'],'password':data['password'],'devid':data['devid'],
          'updatedAt':updated,'issuedAt':issued,'expires_at':expiry,'expiry_source':data['expiresAtSource']}
    source()  # Reject a concurrent primary rotation before touching its backup.
    result=bridge({'command':'upsert','accounts':[{'platform':'loomy','uid':data['uid'],
          'source_id':data['accountId'],'name':current['name'],'auth':auth,'status':target['status'] if target else 'active',
          'expected_auth_hash':target.get('auth_hash') if target else None,'primary':'agent2api'}]})
    rows=result.get('results',[])
    if len(rows)!=1 or rows[0].get('ok') is not True or rows[0].get('platform')!='loomy' or rows[0].get('uid')!=data['uid']:
        raise HandoffRejected('backup_write_unconfirmed')
    inventory=bridge({'command':'inventory'})
    matches=[r for r in inventory.get('accounts',[]) if r.get('platform')=='loomy' and str(r.get('uid'))==data['uid']]
    if inventory.get('ok') is not True or len(matches)!=1:raise HandoffRejected('backup_readback_failed')
    saved=matches[0];actual=saved.get('auth',{})
    if saved.get('status')!=(target['status'] if target else 'active') or any(actual.get(k)!=auth[k] for k in ('token','password','loginid','devid')) or millis(actual.get('expires_at'))!=expiry or millis(actual.get('issuedAt'))!=issued:
        raise HandoffRejected('backup_readback_mismatch')
    source()
    return {'ok':True,'accountId':data['accountId'],'uid':data['uid'],'targetId':saved['id'],
            'backupEnabled':saved['status']=='active','credentialRenewable':True,'expiresAt':expiry}

