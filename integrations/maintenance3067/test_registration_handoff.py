import contextlib,copy,json,sqlite3,time,unittest
from unittest.mock import patch
import registration_handoff as h
import mirai_bridge as m
import handoff_crypto as crypto

class EnvelopeTests(unittest.TestCase):
    def test_roundtrip_tampering_and_direction(self):
        key=b'k'*32;p={'requestId':'a'*32,'ts':int(time.time()),'account':{'password':'private-fixture'}}
        envelope=crypto.seal(key,p,'request')
        self.assertNotIn('private-fixture',json.dumps(envelope))
        self.assertEqual(crypto.open_envelope(key,envelope,'request'),p)
        for k,e,d in [(b'z'*32,envelope,'request'),(key,envelope,'response'),
                      (key,{**envelope,'body':envelope['body'][:-4]+'AAAA'},'request')]:
            with self.assertRaises(Exception):crypto.open_envelope(k,e,d)

    def test_stale_request_rejected(self):
        key=b'k'*32
        for ts in (time.time()-121,time.time()+121):
            with self.assertRaises(ValueError):crypto.open_envelope(key,crypto.seal(key,{'requestId':'a'*32,'ts':ts},'request'),'request')

class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.now=int(time.time()*1000)
        self.data=dict(accountId='loomy-account-fixture',uid='fixture',phone='13800000000',password='example-only-password',
                       devid='web-fixture',session='fixture-session',issuedAt=self.now-5000,expiresAt=self.now+3600000,expiresAtSource='upstream')
        self.conn=sqlite3.connect(':memory:');self.conn.row_factory=sqlite3.Row;self.addCleanup(self.conn.close)
        self.conn.execute('create table accounts(id,provider,enabled,data,remaining,last_success_at)')
        self.conn.execute('create table unified_links(identity,metadata)')
        secret=dict(userId='fixture',session='fixture-session',phone='13800000000',expiresAt=self.data['expiresAt'],updatedAt=self.now-1000)
        self.conn.execute('insert into accounts values(?,?,?,?,?,?)',(self.data['accountId'],'loomy',1,json.dumps({'pluginSecret':secret}),10,self.now))
        self.rows=[];self.writes=[];self.reject=False;self.active=False

    @contextlib.contextmanager
    def db(self,*args):yield self.conn

    def bridge(self,request):
        if request['command']=='inventory':return {'ok':True,'accounts':copy.deepcopy(self.rows)}
        self.writes.append(copy.deepcopy(request))
        if self.reject:return {'ok':False,'results':[{'ok':False,'error':'conflict'}]}
        item=request['accounts'][0];old=self.rows[0] if self.rows else None
        plan=m.merge_plan(item,old['auth'] if old else None,old['status'] if old else None)
        self.rows=[dict(id='17',platform='loomy',uid='fixture',auth=plan['auth'],auth_hash=m.auth_hash(plan['auth']),status='active' if self.active else plan['status'])]
        return {'ok':True,'results':[{'ok':True,'platform':'loomy','uid':'fixture','id':'17'}]}

    def run_delivery(self):return h.deliver(self.data,self.db,json.loads,self.bridge,self.now)

    def test_delivery_is_disabled_and_idempotent_preserves_balance(self):
        result=self.run_delivery();self.assertFalse(result['backupEnabled'])
        self.assertEqual(self.rows[0]['auth']['password'],self.data['password'])
        self.assertEqual(self.run_delivery()['targetId'],result['targetId'])
        self.assertEqual(self.rows[0]['auth']['updatedAt'],self.now-1000)
        self.assertEqual(self.conn.execute('select enabled,remaining from accounts').fetchone()[:],(1,10))

    def test_enrich_existing_session_with_later_import_clock(self):
        self.run_delivery()
        self.rows[0]['auth']['updatedAt']=self.now
        self.rows[0]['auth_hash']=m.auth_hash(self.rows[0]['auth'])
        self.assertTrue(self.run_delivery()['ok'])
        self.assertEqual(self.rows[0]['auth']['issuedAt'],self.data['issuedAt'])
        self.assertEqual(self.rows[0]['auth']['updatedAt'],self.now)

    def test_native_missing_expiry_preserves_registration_receipt_after_sync(self):
        import unified_sync as u
        payload=json.loads(self.conn.execute('select data from accounts').fetchone()[0])
        payload['pluginSecret'].pop('expiresAt')
        self.conn.execute('update accounts set data=?',(json.dumps(payload),))
        self.assertTrue(self.run_delivery()['ok'])
        row=dict(self.conn.execute('select * from accounts').fetchone())
        source=u.source_record(row,json.loads(row['data']))
        auth=u.overlay_source_auth(source,self.rows[0])
        self.assertEqual(auth['expires_at'],self.data['expiresAt'])
        self.assertEqual(auth['password'],self.data['password'])
        source['auth']['token']='different-session'
        self.assertEqual(u.overlay_source_auth(source,self.rows[0])['expires_at'],0)

    def test_reject_mismatched_identity_session_phone_expiry(self):
        for key,value in [('uid','wrong'),('session','old'),('phone','13900000000'),('expiresAt',self.now+7200000),('accountId','absent')]:
            saved=self.data[key];self.data[key]=value
            with self.assertRaises(h.HandoffRejected):self.run_delivery()
            self.data[key]=saved
        self.assertFalse(self.writes)

    def test_reject_expired_or_fabricated_long_lifetime(self):
        for value in (self.now-1,self.now+365*86400000,True,'later'):
            self.data['expiresAt']=value
            with self.assertRaises(h.HandoffRejected):self.run_delivery()
        self.assertFalse(self.writes)

    def test_deleted_identity_never_recreated(self):
        self.conn.execute('insert into unified_links values(?,?)',('loomy|fixture','{"tombstone":true}'))
        with self.assertRaisesRegex(h.HandoffRejected,'identity_deleted'):self.run_delivery()
        self.assertFalse(self.writes)

    def test_stale_backup_or_duplicate_rejected(self):
        self.run_delivery();self.writes=[]
        self.rows[0]['auth']['token']='newer'
        with self.assertRaisesRegex(h.HandoffRejected,'backup_session_not_synced'):self.run_delivery()
        self.rows.append(copy.deepcopy(self.rows[0]))
        with self.assertRaisesRegex(h.HandoffRejected,'ambiguous_identity'):self.run_delivery()
        self.assertFalse(self.writes)

    def test_cas_and_readback_failure_never_acknowledged(self):
        self.reject=True
        with self.assertRaisesRegex(h.HandoffRejected,'backup_write_unconfirmed'):self.run_delivery()
        self.reject=False;self.active=True
        with self.assertRaisesRegex(h.HandoffRejected,'backup_readback_mismatch'):self.run_delivery()

    def test_rotation_during_bridge_write_not_acknowledged(self):
        original=self.bridge
        def bridge(req):
            result=original(req)
            if req['command']=='upsert':
                row=json.loads(self.conn.execute('select data from accounts').fetchone()[0]);row['pluginSecret']['session']='rotated'
                self.conn.execute('update accounts set data=?',(json.dumps(row),))
            return result
        self.bridge=bridge
        with self.assertRaisesRegex(h.HandoffRejected,'source_identity_or_session_changed'):self.run_delivery()

if __name__=='__main__':unittest.main()

