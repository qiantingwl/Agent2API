import contextlib,json,sqlite3,tempfile,unittest,urllib.error
from pathlib import Path
from unittest.mock import patch,Mock
from direct_clients import Client,codearts_usage,Unsupported,UpstreamError,AuthenticationError
from direct_maintenance import DirectMaintenance,DeliveryPending
from mirai_bridge import target_status

class ProtocolTests(unittest.TestCase):
    def response(self,status,body):
        response=Mock(status_code=status)
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        response.iter_content.return_value=[json.dumps(body).encode()]
        return response

    def test_only_confirmed_upstream_authentication_is_typed(self):
        for provider in ('loomy','raccoon','codearts','wps-lingxi'):
            for status in (401,403,429,500):
                with self.subTest(provider=provider,status=status):
                    c=Client(provider,{})
                    with patch.object(c.session,'request',return_value=self.response(status,{'message':'private upstream detail'})):
                        with self.assertRaises(UpstreamError) as raised:c.request('GET','https://upstream.invalid')
                    self.assertEqual(isinstance(raised.exception,AuthenticationError),status==401 and provider in ('loomy','raccoon'))
                    self.assertNotIn('private upstream detail',str(raised.exception))
                    c.close()

    def test_loomy_explicit_business_auth_codes(self):
        for code in ('020002','100002'):
            c=Client('loomy',{'session':'test'})
            with patch.object(c,'request',return_value={'code':code}):
                with self.assertRaises(AuthenticationError):c.loomy('/balance')
            c.close()

    def test_missing_local_credentials_are_not_upstream_auth_evidence(self):
        for provider in ('loomy','raccoon'):
            c=Client(provider,{})
            with patch.object(c.session,'request') as request:
                with self.assertRaises(UpstreamError) as raised:getattr(c,provider)('/balance')
                self.assertNotIsInstance(raised.exception,AuthenticationError)
                request.assert_not_called()
            c.close()

    def test_codearts_apig_auth_error_keeps_existing_classification(self):
        c=Client('codearts',{})
        with patch.object(c.session,'request',return_value=self.response(401,{'error_code':'APIG.0602'})):
            with self.assertRaises(UpstreamError) as raised:c.request('GET','https://upstream.invalid')
            self.assertNotIsInstance(raised.exception,AuthenticationError)
            self.assertIn('APIG.0602',str(raised.exception))
        c.close()

    def test_missing_balance_stays_unknown(self):
        c=Client('loomy',{'session':'synthetic'})
        c.loomy=lambda *args:{'dailyBalance':'50'}
        self.assertIsNone(c.balance()['available']);c.close()

    def test_zero_and_total_balance(self):
        c=Client('raccoon',{'accessToken':'synthetic'})
        c.raccoon=lambda *args:{'total_chargeable_points':0,'available_points':500}
        self.assertEqual(c.balance()['available'],0);c.close()

    def test_codearts_summary_not_double_counted(self):
        metrics=[{'name':name,'show':True,'package_credit_remain':n} for name,n in [('usageTotalPackageCredit',120),('base',20),('bonus',100)]]
        self.assertEqual(codearts_usage({'metrics':metrics})['available'],120)
        self.assertIsNone(codearts_usage({'metrics':[{'name':'tokens','show':True,'usage_token_num':50}]})['available'])

    def test_campaign_id_and_key_survive_failed_claim(self):
        ledger={};calls=[]
        def store(k,v=None):
            if v is not None:ledger[k]=dict(v)
            return ledger.get(k)
        c=Client('codearts',{},ledger=store)
        def call(path,body=None):
            if 'delivery' in path:return {'items':[{'campaignId':42,'type':'USER_LOGIN','benefitUnit':'CREDIT','claimable':True}]}
            calls.append(body)
            raise TimeoutError('synthetic lost reply')
        c.codearts=call
        for _ in range(2):
            with self.assertRaises(TimeoutError):c.codearts_checkin('2026-11-11')
        self.assertEqual(calls[0]['campaignId'],42)
        self.assertEqual(calls[0]['idempotentKey'],calls[1]['idempotentKey']);c.close()

    def test_old_confirmed_does_not_prove_today(self):
        c=Client('codearts',{},ledger=lambda *a:None)
        c.codearts=lambda *a:{'items':[{'campaignId':1,'type':'USER_LOGIN','benefitUnit':'CREDIT','claimable':False,'status':'CONFIRMED'}]}
        self.assertFalse(c.codearts_checkin('2026-11-11')['confirmed']);c.close()

    def test_never_changes_existing_account_switch(self):
        for platform in ('loomy','raccoon','codearts','wps-lingxi'):
            self.assertEqual(target_status(platform,'disabled','active'),'active')
            self.assertEqual(target_status(platform,'active','disabled'),'disabled')

    def test_invitation_must_be_confirmed_by_readback(self):
        c=Client('loomy',{'session':'synthetic'});calls=[]
        responses=iter([{'activated':False},{},{'activated':True,'appliedInvitationCode':'different'}])
        def call(path,body=None):calls.append((path,body));return next(responses)
        c.loomy=call
        self.assertFalse(c.invitation('requested')['confirmed'])
        self.assertEqual([body is None for _,body in calls],[True,False,True]);c.close()

    def test_bound_invitation_is_never_rebound(self):
        c=Client('loomy',{'session':'synthetic'});calls=[]
        def call(path,body=None):calls.append(body);return {'activated':True,'appliedInvitationCode':'existing'}
        c.loomy=call
        self.assertFalse(c.invitation('requested')['confirmed']);self.assertEqual(calls,[None]);c.close()

    def test_codearts_refresh_replaces_all_credential_aliases(self):
        secret={'refresh_token':'old','refreshToken':'old','expiresAt':1,'accessToken':'old',
                'oauth_context':{'pkce_pair':{'code_verifier':'synthetic'}}}
        c=Client('codearts',secret)
        c.request=lambda *a:{'credentials':{'access_key_id':'ak','secret_access_key':'sk','security_token':'new','expiration':'2026-11-12T00:00:00Z'},'refresh_token':'next'}
        with patch('direct_clients.dpop',return_value='synthetic'):
            fresh=c.renew()
        self.assertEqual(fresh['refresh_token'],fresh['refreshToken']);self.assertEqual(fresh['accessToken'],fresh['security_token'])
        self.assertGreater(fresh['expiresAt'],1);c.close()

class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'db';self.calls=[];self.follow=[];self.fail=True
        @contextlib.contextmanager
        def db(*args):
            c=sqlite3.connect(self.path);c.row_factory=sqlite3.Row
            try:yield c;c.commit()
            except:c.rollback();raise
            finally:c.close()
        self.db=db
        with db() as c:c.execute('create table ledger(key text primary key,value text)')
        self.secret={'userId':'u','session':'synthetic'}
        def official(path,payload=None):
            self.calls.append(path)
            if self.fail:raise urllib.error.HTTPError('http://synthetic',503,'unavailable',{},None)
            if path.endswith('/lease'):return {'acquired':True,'released':True}
            return {'applied':True}
        self.engine=DirectMaintenance(db,json.dumps,json.loads,lambda aid:({'id':aid,'provider':'loomy','enabled':1},{'pluginSecret':self.secret}),lambda:type('Official',(),{'call':staticmethod(official)})(),lambda:1794360000000,lambda *a:None,lambda *a:self.follow.append(a))

    def tearDown(self):self.temp.cleanup()

    def test_login_invalid_is_durable_and_retry_keeps_failed_outcome(self):
        job={'id':'auth-receipt','account':'a','provider':'loomy','action':'balance'}
        with patch('direct_maintenance.Client') as client:
            client.return_value.balance.side_effect=AuthenticationError('private upstream detail')
            with self.assertRaises(DeliveryPending):self.engine.execute(job)
            client.return_value.close.assert_called_once()
            with self.db() as c:
                record=c.execute('select action,payload from direct_results').fetchone()
                result=json.loads(record['payload'])
                self.assertEqual(record['action'],'login_invalid')
                self.assertEqual(result['outcome']['status'],'needs_login')
                self.assertEqual(set(result['gateway']),{'account','provider','action','requestId','observedAt','expect'})
                self.assertEqual(result['gateway']['expect'],self.secret)
                self.assertNotIn('private upstream detail',record['payload'])
                self.assertEqual(c.execute('select count(*) from ledger').fetchone()[0],0)
                c.execute('update direct_outbox set next_at=0')
            self.fail=False
            repeated=self.engine.execute(job)
            self.assertEqual(repeated['status'],'needs_login')
            self.assertEqual(client.return_value.balance.call_count,1)
            self.assertEqual(client.call_count,1)
            self.assertFalse(self.follow)

    def test_each_maintenance_action_preserves_auth_failure_and_lease(self):
        self.fail=False
        for provider,action in (('raccoon','balance'),('loomy','checkin'),('loomy','credential')):
            with self.subTest(provider=provider,action=action),patch('direct_maintenance.Client') as client:
                method={'balance':'balance','checkin':'checkin','credential':'renew'}[action]
                getattr(client.return_value,method).side_effect=AuthenticationError('private')
                result=self.engine.execute({'id':provider+'-'+action,'account':'a','provider':provider,'action':action})
                self.assertEqual(result['status'],'needs_login')
                client.return_value.close.assert_called_once()
                if action=='credential':
                    self.assertEqual(self.calls[-1],'/api/external-maintenance/lease')
                    with self.db() as c:self.assertEqual(c.execute('select status from direct_renewals').fetchone()[0],'failed')
        self.assertFalse(self.follow)
        with self.db() as c:self.assertEqual(c.execute('select count(*) from ledger').fetchone()[0],0)

    def test_other_errors_do_not_emit_login_invalid(self):
        for index,error in enumerate((UpstreamError('HTTP 403'),UpstreamError('HTTP 429'),TimeoutError('timeout'))):
            with self.subTest(error=error),patch('direct_maintenance.Client') as client:
                client.return_value.balance.side_effect=error
                with self.assertRaises(type(error)):self.engine.execute({'id':str(index),'account':'a','provider':'loomy','action':'balance'})
                client.return_value.close.assert_called_once()
        with patch('direct_maintenance.Client') as client:
            client.return_value.balance.side_effect=AuthenticationError('invalid')
            with self.assertRaises(AuthenticationError):self.engine.execute({'id':'wps','account':'a','provider':'wps-lingxi','action':'balance'})
        with self.db() as c:self.assertEqual(c.execute('select count(*) from direct_results').fetchone()[0],0)

    def test_gateway_management_401_is_only_a_delivery_failure(self):
        official=Mock(side_effect=urllib.error.HTTPError('http://management',401,'invalid key',{},None))
        self.engine.official=lambda:type('Official',(),{'call':staticmethod(official)})()
        with patch('direct_maintenance.Client') as client:
            client.return_value.balance.return_value={'available':12}
            with self.assertRaises(DeliveryPending):self.engine.execute({'id':'management','account':'a','provider':'loomy','action':'balance'})
        with self.db() as c:
            row=c.execute('select action,payload from direct_results').fetchone()
            self.assertEqual(row['action'],'balance')
            self.assertNotIn('needs_login',row['payload'])

    def test_stale_auth_receipt_conflict_never_repeats_upstream(self):
        official=Mock(side_effect=urllib.error.HTTPError('http://management',409,'old credential',{},None))
        self.engine.official=lambda:type('Official',(),{'call':staticmethod(official)})()
        with patch('direct_maintenance.Client') as client:
            client.return_value.balance.side_effect=AuthenticationError('invalid')
            job={'id':'stale','account':'a','provider':'loomy','action':'balance'}
            with self.assertRaisesRegex(Unsupported,'未覆盖新状态'):self.engine.execute(job)
            with self.assertRaises(Unsupported):self.engine.execute(job)
            client.return_value.balance.assert_called_once()
        with self.db() as c:
            self.assertEqual(c.execute("select status from direct_outbox where target='gateway'").fetchone()[0],'conflict')

    def test_delivery_failure_does_not_repeat_upstream(self):
        job={'id':'j','account':'a','provider':'loomy','action':'balance'}
        with patch('direct_maintenance.Client') as client:
            client.return_value.balance.return_value={'available':12}
            with self.assertRaises(DeliveryPending):self.engine.execute(job)
            self.fail=False
            with self.db() as c:c.execute('update direct_outbox set next_at=0')
            self.engine.execute(job)
            self.assertEqual(client.return_value.balance.call_count,1)
        with self.db() as c:self.assertEqual(c.execute("select status from direct_outbox where target='gateway'").fetchone()[0],'done')

    def test_checkin_followup_waits_for_receipt(self):
        job={'id':'j','account':'a','provider':'loomy','action':'checkin'}
        with patch('direct_maintenance.Client') as client:
            client.return_value.checkin.return_value={'confirmed':True}
            with self.assertRaises(DeliveryPending):self.engine.execute(job)
            self.assertFalse(self.follow)
            self.fail=False
            with self.db() as c:c.execute('update direct_outbox set next_at=0')
            self.engine.execute(job)
            self.assertEqual(len(self.follow),1)

    def test_credential_rotation_has_lease_and_is_not_repeated(self):
        self.fail=False
        job={'id':'credential-test-0001','account':'a','provider':'loomy','action':'credential'}
        with patch('direct_maintenance.Client') as client:
            client.return_value.renew.return_value={'userId':'u','session':'fresh'}
            self.engine.execute(job);self.engine.execute(job)
            self.assertEqual(client.return_value.renew.call_count,1)
        self.assertEqual(self.calls[0],'/api/external-maintenance/lease')
        self.assertEqual(self.calls[-1],'/api/external-maintenance/lease')

    def test_stale_mirror_cache_cannot_create_ag_delivery_conflict(self):
        self.fail=False
        stale={'platform':'loomy','uid':'u','auth':{'token':'old'},'auth_hash':'oldhash','status':'disabled'}
        with self.db() as c:c.execute('insert into direct_targets values(?,?,?)',('loomy|u',json.dumps(stale),1))
        with patch('direct_maintenance.Client') as client,patch('unified_sync.bridge_call') as bridge:
            client.return_value.balance.return_value={'available':12}
            self.engine.execute({'id':'j','account':'a','provider':'loomy','action':'balance'})
            self.engine.deliver('j')
            bridge.assert_not_called()
        with self.db() as c:
            self.assertEqual(json.loads(c.execute('select data from direct_targets').fetchone()[0]),stale)
            self.assertEqual(dict(c.execute('select target,status from direct_outbox')),{'gateway':'done','mirai':'not_required'})

    def test_old_busy_mirror_receipt_does_not_hold_ag_result(self):
        self.fail=False
        target={'platform':'loomy','uid':'u','auth':{'token':'synthetic'},'auth_hash':'h','status':'disabled'}
        with self.db() as c:c.execute('insert into direct_targets values(?,?,?)',('loomy|u',json.dumps(target),1))
        with patch('direct_maintenance.Client') as client,patch('unified_sync.bridge_call') as bridge:
            client.return_value.balance.return_value={'available':12}
            self.engine.execute({'id':'j','account':'a','provider':'loomy','action':'balance'})
            with self.db() as c:c.execute("update direct_outbox set status='pending',error='legacy busy' where target='mirai'")
            self.engine.deliver('j')
            bridge.assert_not_called()
        self.assertEqual(self.calls,['/api/external-maintenance/apply'])
        with self.db() as c:self.assertEqual(dict(c.execute('select target,status from direct_outbox')),{'gateway':'done','mirai':'pending'})

    def test_multiple_ag_receipts_need_no_mirror_batch(self):
        self.fail=False
        for aid in ('a','b'):
            target={'platform':'loomy','uid':aid,'auth':{'token':'synthetic'},'auth_hash':'h','status':'disabled'}
            with self.db() as c:c.execute('insert into direct_targets values(?,?,?)',('loomy|'+aid,json.dumps(target),1))
        self.engine.account=lambda aid:({'id':aid,'provider':'loomy','enabled':1},{'pluginSecret':{'userId':aid,'session':'synthetic'}})
        with patch('direct_maintenance.Client') as client,patch('unified_sync.bridge_call') as bridge:
            client.return_value.balance.return_value={'available':12}
            for aid in ('a','b'):
                self.engine.execute({'id':aid,'account':aid,'provider':'loomy','action':'balance'})
                self.engine.deliver(aid)
            bridge.assert_not_called()
        self.assertEqual(self.calls,['/api/external-maintenance/apply']*2)
        with self.db() as c:
            self.assertEqual(c.execute("select count(*) from direct_outbox where target='gateway' and status='done'").fetchone()[0],2)
            self.assertEqual(c.execute("select count(*) from direct_outbox where target='mirai' and status='not_required'").fetchone()[0],2)

    def test_balance_of_same_identity_never_overwrites_other_valid_session(self):
        self.fail=False
        target={'platform':'loomy','uid':'u','auth':{'token':'other-valid-session'},'auth_hash':'otherhash','status':'disabled'}
        with self.db() as c:c.execute('insert into direct_targets values(?,?,?)',('loomy|u',json.dumps(target),1))
        with patch('direct_maintenance.Client') as client,patch('unified_sync.bridge_call') as bridge:
            client.return_value.balance.return_value={'available':12}
            self.engine.execute({'id':'j','account':'a','provider':'loomy','action':'balance'})
            self.engine.deliver('j')
            bridge.assert_not_called()
        with self.db() as c:
            self.assertEqual(json.loads(c.execute('select data from direct_targets').fetchone()[0]),target)
            result=json.loads(c.execute('select payload from direct_results').fetchone()[0])
            self.assertEqual(result['gateway']['expect'],self.secret)
            self.assertEqual(result['gateway']['usage']['available'],12)

if __name__=='__main__':unittest.main()
