import datetime
import unittest
from unittest.mock import patch
from auxiliary_policy import auxiliary_due
import mirai_bridge as bridge
from test_mirai_bridge import account, Store, backend
from dashboard import dispatch_order

class AuxiliaryTests(unittest.TestCase):
    def test_auxiliary_work_does_not_starve_behind_balance_backlog(self):
        def rank(action,created=1,origin='auto'):
            return dispatch_order(dict(id='j',account='a',provider='wps-lingxi',action=action,created=created,origin=origin),{}, {})
        self.assertLess(rank('recheck',1000),rank('balance'))
        self.assertLess(rank('checkin'),rank('activity'))
        self.assertLess(rank('balance',1000,'post_checkin'),rank('activity'))
        self.assertLess(rank('checkin'),rank('credential'))
        self.assertLess(rank('checkin'),rank('recheck'))
        self.assertLess(rank('checkin'),rank('balance',1000,'post_checkin'))
    def test_daily_activity_uses_beijing_day_and_respects_pauses(self):
        tz=datetime.timezone(datetime.timedelta(hours=8))
        now=int(datetime.datetime(2026,11,10,0,1,tzinfo=tz).timestamp()*1000)
        row={'provider':'wps-lingxi','enabled':True}
        self.assertTrue(auxiliary_due(row,'activity',now-120000,now,{},tz))
        self.assertFalse(auxiliary_due(row,'activity',now-1000,now,{},tz))
        self.assertFalse(auxiliary_due({**row,'maintenancePaused':True},'activity',0,now,{},tz))
        self.assertFalse(auxiliary_due({**row,'needsLogin':True},'activity',0,now,{},tz))

    def test_recheck_requires_provenance_and_interval(self):
        tz=datetime.timezone.utc
        row={'provider':'wps-lingxi','needsLogin':True,'recheckAllowed':True}
        self.assertTrue(auxiliary_due(row,'recheck',0,3600000,{},tz))
        self.assertFalse(auxiliary_due(row,'recheck',1,3600000,{},tz))
        self.assertFalse(auxiliary_due({**row,'recheckAllowed':False},'recheck',0,3600000,{},tz))
        self.assertFalse(auxiliary_due({**row,'maintenancePaused':True},'recheck',0,3600000,{},tz))

    def test_disabled_without_exact_marker_never_calls_native(self):
        row=account(platform=bridge.WPS,status='disabled')
        native=lambda *args:self.fail('manual disabled account was called')
        api=backend(Store([row]),native)
        for token in ('','wrong'):
            result=api.task({'account_id':'1','action':'recheck','auto_disable_token':token})
            self.assertEqual(result['status'],'disabled')

    def test_only_observed_auth_disable_produces_recovery_marker(self):
        row=account(platform=bridge.WPS)
        def native(action,db,row):
            row.status='disabled';db.commit()
            return {'ok':False,'error':{'kind':'auth'}}
        result=backend(Store([row]),native).task({'account_id':'1','action':'balance'})
        self.assertEqual(result['status'],'needs_login')
        self.assertEqual(len(result['auto_disable_token']),64)

    def test_fingerprint_invalidates_changed_credentials_or_operator_edit(self):
        row=account(platform=bridge.WPS,status='disabled')
        token=bridge.disabled_fingerprint(row)
        row.updated_at=datetime.datetime.now(datetime.timezone.utc)
        self.assertNotEqual(token,bridge.disabled_fingerprint(row))
        token=bridge.disabled_fingerprint(row)
        row.auth_json='{"cookie":"new"}'
        self.assertNotEqual(token,bridge.disabled_fingerprint(row))

if __name__=='__main__':unittest.main()

