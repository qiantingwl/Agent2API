"""Read-only projection tests; no server import or upstream requests."""
import datetime
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import unittest

from dashboard import enrich, history_view, queue_view
from ui_support import SUPPORTED, account_page, scope_snapshot

TZ = datetime.timezone(datetime.timedelta(hours=8))
NOW = int(datetime.datetime(2026, 11, 9, 12, tzinfo=TZ).timestamp() * 1000)
START = NOW - 12 * 3600000


class UnifiedDashboardTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(':memory:')
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('''create table jobs (
            id text, account text, provider text, action text, status text,
            created integer, started integer, ended integer, attempt integer,
            message text, priority integer, origin text, required_after integer, not_before integer default 0)''')
        self.config = {'paused': False, 'providers': {
            p: {'balance': {'enabled': True, 'interval': 3600},
                'checkin': {'enabled': True, 'maxAttempts': 3},
                'credential': {'enabled': False}} for p in SUPPORTED}}

    def tearDown(self):
        self.connection.close()

    def row(self, aid='account', provider='raccoon', **fields):
        return {'id': aid, 'name': aid, 'provider': provider, 'enabled': True,
                'balance': 0, 'lastSuccess': NOW - 10000, **fields}

    def job(self, aid, status, created=NOW - 1000, provider='raccoon', **fields):
        job = dict(id=aid + str(created), account=aid, provider=provider,
                   action='checkin', status=status, created=created,
                   started=created, ended=created + 500, attempt=0,
                   message='test record', priority=0, origin='auto', required_after=0,not_before=0)
        job.update(fields)
        self.connection.execute('insert into jobs values (' + ','.join('?' * len(job)) + ')', tuple(job.values()))

    def view(self, rows, config=None, routing=None, **snapshot):
        return enrich({'at': NOW, 'accounts': rows, **snapshot},
                      self.config if config is None else config,
                      lambda: self.connection, NOW, TZ, routing)

    def test_auth_states_capacity_and_manual_pause_are_separate(self):
        rows=[self.row('observed',provider='loomy',enabled=False,needsLogin=True,
                       authStatus='observing',error='余额桥并发已满，请排队重试',
                       authFailureMessage='历史鉴权失败'),
              self.row('pending',provider='loomy',enabled=False,needsLogin=True,authStatus='pending_verify'),
              self.row('manual',provider='loomy',enabled=False,needsLogin=True,authStatus='pending_verify',maintenancePaused=True)]
        route={'at':NOW,'entries':{r['id']:{'state':'disabled'} for r in rows}}
        v=self.view(rows,routing=route);p=v['dashboard']['platforms']['loomy']
        self.assertEqual(p['unavailableBreakdown'],dict(observing=1,pending_verify=1,disabled=1))
        self.assertEqual(p['capacityRetry'],1)
        self.assertEqual(p['authRecoveredScope'],'current_state')
        r=v['accounts'][0];self.assertEqual(r['error'],'');self.assertTrue(r['maintenanceMessage'])
        self.assertEqual(r['authFailureMessage'],'历史鉴权失败')
        self.assertEqual(account_page(v,{'filter':['capacity_retry']})['total'],1)
        self.assertEqual(account_page(v,{'filter':['route_pending_verify']})['total'],1)

    def test_zero_and_disabled_backup_are_not_maintenance_paused(self):
        result = self.view([self.row(), self.row('backup', enabled=False),
                            self.row('paused', maintenancePaused=True, pauseReason='manual')])
        self.assertEqual(result['summary']['maintenancePaused'], 1)
        self.assertEqual(result['summary']['routingDisabled'], 1)
        for r in result['accounts'][:2]:
            self.assertFalse(r['maintenancePaused'])
            self.assertEqual(r['balanceDetail']['state'], 'awaiting_checkin')
        self.assertEqual(len(account_page(result, {'filter': ['paused']})['items']), 1)
        self.assertEqual(result['summary']['zeroBalanceSkipped'], 3)

    def test_global_pause_does_not_reclassify_accounts(self):
        self.config['paused'] = True
        result = self.view([self.row(enabled=False)])
        self.assertEqual(result['summary']['maintenancePaused'], 0)
        self.assertEqual(result['accounts'][0]['checkinDetail']['state'], 'paused')

    def test_yesterday_signature_and_message_are_not_today(self):
        self.job('account', 'error', START - 5000)
        r = self.view([self.row(signed=True, signedAt=START - 10000)])['accounts'][0]
        self.assertFalse(r['signed'])
        self.assertFalse(r['checkinDetail']['lastMessageIsToday'])
        self.assertFalse(r['checkinDetail']['failedToday'])
        self.assertEqual(r['checkinDetail']['todayCategory'], 'waiting')

    def test_daily_categories_are_exclusive_and_completion_is_not_a_grant(self):
        self.job('failed', 'error')
        self.job('login', 'needs_login')
        self.job('unconfirmed', 'unconfirmed')
        rows = [self.row('done', signed=True, signedAt=NOW - 20000),
                self.row('failed'), self.row('login', needsLogin=True),
                self.row('unconfirmed'), self.row('waiting')]
        result = self.view(rows)
        counts = result['dashboard']['platforms']['raccoon']['today']
        self.assertEqual(counts, dict(completed=1, failed=2, needs_login=1, waiting=1, unsupported=0))
        self.assertEqual(sum(counts.values()), len(rows))
        done = result['accounts'][0]
        self.assertEqual(done['balanceKind'], 'zero')
        self.assertEqual(done['checkinDetail']['state'], 'signed')
        self.assertEqual(result['summary']['signedToday'], 1)

    def test_login_is_visible_while_a_job_is_queued_or_globally_paused(self):
        self.config['paused'] = True
        self.job('account', 'queued', ended=None)
        r = self.view([self.row(needsLogin=True)])['accounts'][0]
        self.assertEqual(r['checkinDetail']['state'], 'needs_login')
        self.assertEqual(r['checkinDetail']['todayCategory'], 'needs_login')

    def test_failure_finished_today_has_today_label(self):
        self.job('account', 'error', START - 1000, ended=START + 1000)
        detail = self.view([self.row()])['accounts'][0]['checkinDetail']
        self.assertTrue(detail['lastMessageIsToday'])
        self.assertTrue(detail['failedToday'])

    def test_four_platforms_and_missing_configs(self):
        rows = [self.row(p, p, balance=None) for p in sorted(SUPPORTED)]
        result = self.view(rows, config={})
        self.assertEqual(list(result['dashboard']['platforms']), sorted(SUPPORTED))
        for p in result['dashboard']['platforms'].values():
            self.assertFalse(p['configured'])
            self.assertEqual(p['balance']['unknown'], 1)
            self.assertIsNone(p['routable'])
        self.assertTrue(all(r['checkinDetail']['state'] == 'not_configured' for r in result['accounts']))

    def test_unknown_provider_is_safe_and_scoped_out(self):
        unknown = self.row('future', 'future', balance=None)
        self.assertEqual(scope_snapshot({'at': NOW, 'accounts': [unknown]})['accounts'], [])
        detail = self.view([unknown], config={})['accounts'][0]['checkinDetail']
        self.assertEqual(detail['todayCategory'], 'unsupported')

    def test_mirai_identity_and_injected_routing_are_preserved(self):
        row = self.row('mirai:42', 'wps-lingxi', home='miraihub', syncStatus='synced', syncAt=NOW)
        result = self.view([row], routing={'at': NOW, 'entries': {'mirai:42': {'state': 'usable', 'reason': 'ready'}}})
        r = result['accounts'][0]
        self.assertEqual((r['id'], r['home'], r['syncStatus']), ('mirai:42', 'miraihub', 'synced'))
        self.assertEqual(result['dashboard']['platforms']['wps-lingxi']['routable'], 1)
        absent = self.view([row], routing={'at': NOW, 'entries': {}})
        self.assertIsNone(absent['dashboard']['platforms']['wps-lingxi']['routable'])

    def test_wps_candidates_use_own_fresh_snapshot_not_agent_availability(self):
        rows=[self.row('mirai:1','wps-lingxi'),self.row('mirai:2','wps-lingxi',enabled=False)]
        routing={'at':0,'entries':{'mirai:1':{'state':'candidate','at':NOW,'reason':'native eligibility'},'mirai:2':{'state':'disabled','at':NOW}}}
        result=self.view(rows,routing=routing)
        self.assertEqual(result['dashboard']['platforms']['wps-lingxi']['candidates'],1)
        self.assertEqual(account_page(result,{'filter':['candidate']})['total'],1)
        self.assertEqual(account_page(result,{'filter':['usable']})['total'],0)
        routing['entries']['mirai:1']['at']=NOW-121000
        self.assertIsNone(self.view(rows,routing=routing)['dashboard']['platforms']['wps-lingxi']['candidates'])

    def test_queue_and_history_include_all_four_and_exclude_unknown(self):
        rows = []
        for p in sorted(SUPPORTED | {'future'}):
            self.job(p, 'queued', provider=p, ended=None)
            rows.append(self.row(p, p))
        queue = queue_view({'accounts': rows}, self.config, lambda: self.connection, NOW, {})
        self.assertEqual({j['provider'] for j in queue['items']}, SUPPORTED)
        self.assertEqual(history_view(lambda: self.connection, {})['total'], 4)

    def test_current_usage_counts_accounts_and_excludes_maintenance(self):
        self.job('maintenance-only', 'running')
        rows=[self.row('partial'),self.row('full'),self.row('maintenance-only')]
        routing={'at':NOW,'entries':{
            'partial':{'state':'usable'},'full':{'state':'concurrency'},
            'maintenance-only':{'state':'usable'}},
            'usage':{'at':NOW,'counts':{'partial':1,'full':2}}}
        view=self.view(rows,routing=routing)
        counts=view['dashboard']['platforms']['raccoon']
        self.assertEqual((counts['routable'],counts['unavailable'],counts['inUse']),(3,0,2))
        self.assertEqual(account_page(view,{'filter':['in_use']})['total'],2)
        self.assertEqual(account_page(view,{'filter':['unavailable']})['total'],0)
        self.assertEqual((counts['ready'],counts['occupied']),(2,1))
        self.assertEqual(account_page(view,{'filter':['usable']})['total'],3)
        self.assertEqual(account_page(view,{'filter':['ready']})['total'],2)
        self.assertEqual(account_page(view,{'filter':['route_concurrency']})['total'],1)

    def test_wps_runtime_is_independent_of_agent_observation(self):
        routing={'at':0,'entries':{'mirai:1':{'state':'usable','at':NOW,'usageAt':NOW,'inFlight':1}}}
        view=self.view([self.row('mirai:1','wps-lingxi')],routing=routing)
        counts=view['dashboard']['platforms']['wps-lingxi']
        self.assertEqual((counts['routable'],counts['unavailable'],counts['inUse']),(1,0,1))

    def test_busy_balance_and_filters_share_the_same_pool_without_double_counting(self):
        rows=[self.row('ready',balance=10),self.row('partial',balance=20),
              self.row('busy',balance=30),self.row('blocked',balance=40)]
        routing={'at':NOW,'entries':{
            'ready':{'state':'usable'},'partial':{'state':'usable'},
            'busy':{'state':'concurrency'},'blocked':{'state':'limiter'}},
            'usage':{'at':NOW,'counts':{'partial':1,'busy':1,'blocked':1}}}
        view=self.view(rows,routing=routing);p=view['dashboard']['platforms']['raccoon']
        self.assertEqual((p['routable'],p['ready'],p['occupied'],p['inUse']),(3,2,1,3))
        self.assertEqual(p['routablePoints'],60)
        self.assertEqual(p['routable']+p['unavailable'],p['total'])
        self.assertEqual(p['ready']+p['occupied'],p['routable'])
        for field,filter_name in [('routable','usable'),('ready','ready'),
                                  ('occupied','route_concurrency'),('unavailable','unavailable')]:
            self.assertEqual(p[field],account_page(view,{'filter':[filter_name]})['total'])
        routing['at']=NOW-121000
        stale=self.view(rows,routing=routing)['dashboard']['platforms']['raccoon']
        for field in ('routable','ready','occupied','unavailable','routablePoints'):
            self.assertIsNone(stale[field])

    def test_unavailable_causes_partition_total_and_signed_balance_is_subset(self):
        rows=[self.row('login',needsLogin=True),self.row('disabled'),
              self.row('signed-zero',signed=True,signedAt=NOW-1),
              self.row('token-cap',balance=5),self.row('busy'),self.row('cool'),self.row('other')]
        states=['disabled','disabled','limiter','limiter','concurrency','cooldown','blocked']
        routing={'at':NOW,'entries':{r['id']:{'state':st} for r,st in zip(rows,states)}}
        view=self.view(rows,routing=routing);p=view['dashboard']['platforms']['raccoon']
        self.assertEqual(p['unavailable'],6)
        self.assertEqual(p['routable'],1)
        self.assertNotIn('concurrency',p['unavailableBreakdown'])
        self.assertEqual(sum(p['unavailableBreakdown'].values()),6)
        for key,n in p['unavailableBreakdown'].items():
            self.assertEqual(account_page(view,{'filter':['route_'+key]})['total'],n)
        self.assertEqual(p['signedBalanceBlocked'],1)
        self.assertEqual(account_page(view,{'filter':['signed_balance_blocked']})['items'][0]['id'],'signed-zero')
        routing['at']=NOW-121000
        stale=self.view(rows,routing=routing)['dashboard']['platforms']['raccoon']
        self.assertIsNone(stale['unavailableBreakdown'])
        self.assertIsNone(stale['signedBalanceBlocked'])

    def test_sync_and_job_errors_do_not_expose_credentials(self):
        secret = 'not-a-real-test-secret'
        self.job('account', 'error', message='Bearer ' + secret)
        result = self.view([self.row(credential={'token': secret}, accessToken=secret,
                                    syncError='password=' + secret)],
                           sync={'lastRun': NOW, 'error': 'token=' + secret, 'counts': {'error': 1}})
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn('credential', result['accounts'][0])
        self.assertEqual(result['sync']['counts']['error'], 1)
        self.assertIn('credential', result['dashboard']['platforms']['raccoon']['operationCooling'])
        self.assertNotIn(secret, json.dumps(history_view(lambda: self.connection, {})))

    def test_html_ids_and_provider_options_are_unambiguous(self):
        class Elements(HTMLParser):
            def __init__(self):
                super().__init__()
                self.ids = []
                self.options = []

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if 'id' in attrs:
                    self.ids.append(attrs['id'])
                if tag == 'option' and attrs.get('value') in SUPPORTED:
                    self.options.append(attrs['value'])

        html = Elements()
        html.feed(Path(__file__).with_name('index.html').read_text(encoding='utf-8'))
        self.assertEqual(len(html.ids), len(set(html.ids)))
        self.assertEqual(html.options, sorted(SUPPORTED) * 3)

    @unittest.skipUnless(shutil.which('node'), 'Node.js unavailable')
    def test_frontend_renders_four_missing_configs_and_today_semantics(self):
        """Run real rendering functions without network or a browser dependency."""
        state = self.view([self.row('zero', enabled=False),
                           self.row('old', signed=True, signedAt=START - 1000)], config={})
        state.update(config={'providers': {}}, proxies=[])
        self.job('old', 'error', START - 3000)
        state = self.view(state['accounts'], config={}, sync={'lastRun': NOW, 'counts': {'synced': 1}})
        state.update(config={'providers': {}}, proxies=[])
        script = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const nodes=new Map(),document={getElementById(id){if(!nodes.has(id))nodes.set(id,{innerHTML:'',textContent:'',classList:{add(){},remove(){}}});return nodes.get(id)},querySelectorAll(){return []}};
const context=vm.createContext({document,console,Map,Set,URLSearchParams});
vm.runInContext(fs.readFileSync('ui.js','utf8'),context);
vm.runInContext(fs.readFileSync('ux.js','utf8').split("document.addEventListener('click'")[0],context);
// This test checks generated semantic content; DOM card reconciliation is tested in a browser.
vm.runInContext('paintCards=(id,html)=>{$(id).innerHTML=html}',context);
context.fixture=JSON.parse(fs.readFileSync(0,'utf8'));
vm.runInContext('state=fixture;renderOverview();renderQueueSummary();renderAccountSummary();renderDailySummary();renderCredentialSummary();paintSettings();drawAccounts({page:0,total:2,at:state.at,items:state.accounts})',context);
const settings=nodes.get('provider-settings').innerHTML;
for(const p of ['codearts','loomy','raccoon','wps-lingxi'])assert(settings.includes(`data-provider="${p}"`));
assert(settings.includes('尚未配置'));assert(!settings.includes('NaN'));
const rows=nodes.get('account-rows').innerHTML;
assert(rows.includes('零余额跳过'));assert(rows.includes('上次记录（非今日）'));assert(!rows.includes('零余额暂停'));
assert(nodes.get('overview-kpis').innerHTML.includes('正在使用账户'));assert(!nodes.get('platform-summary').innerHTML.includes('候选'));
assert(nodes.get('overview-kpis').innerHTML.includes('可用账户'));
assert(nodes.get('platform-summary').innerHTML.includes('data-route-filter="route_limits"'));
assert(fs.readFileSync('index.html','utf8').includes('<th>余额不足</th>'));
assert(!nodes.get('overview-kpis').innerHTML.includes('停用、限制或并发占满'));
assert(nodes.get('checkin-summary').innerHTML.includes('<table>'));assert(fs.readFileSync('index.html','utf8').includes('完成不等于积分到账'));
vm.runInContext(`state.config.providers=Object.fromEntries(providers.map(p=>[p,{concurrency:1,balance:{enabled:true,interval:3600},checkin:{enabled:true,concurrency:4},credential:{enabled:true}}]));state.dashboard.platforms.raccoon.renewable=1;renderOverview();renderQueueSummary();renderAccountSummary();renderDailySummary();renderCredentialSummary();paintSettings()`,context);
const configured=nodes.get('provider-settings').innerHTML;
assert.equal((configured.match(/data-setting-action="checkin"/g)||[]).length,4);
assert.equal((configured.match(/max="16"/g)||[]).length,8);
assert(configured.includes('当前没有支持续期的账户'));
assert(!configured.includes('NaN'));
assert.equal((nodes.get('operation-rows').innerHTML.match(/<tr>/g)||[]).length,16);
vm.runInContext(`state.dashboard.taskBacklog={loomy:{checkin:{remaining:2170,ready:2160,scheduled:0,cooling:10}}};state.config.providers.loomy.invitation={enabled:true,concurrency:1};state.config.providers.loomy.balance.concurrency=3;state.dashboard.pending=[{provider:'loomy',action:'balance',status:'running',attempts:2}];renderRunningTasks()`,context);
const concurrency=nodes.get('running-tasks').innerHTML;
assert(concurrency.includes('剩余待执行'));assert(concurrency.includes('现在可执行'));assert(concurrency.includes('2,170'));assert(concurrency.includes('邀请码绑定'));assert(concurrency.includes('2 <span class="concurrency-limit">/ 3'));
assert(concurrency.includes('0 <span class="concurrency-limit">/ 1'));assert(!concurrency.includes('WPS'));
assert(!concurrency.includes('running-task'));assert(!concurrency.includes('已运行'));
vm.runInContext(`for(const p of providers)Object.assign(state.dashboard.platforms[p],{routable:null,inUse:null,unavailable:null,unavailableBreakdown:null});Object.assign(state.dashboard.platforms.loomy,{routable:623,inUse:120,unavailable:2867});Object.assign(state.dashboard.platforms.raccoon,{routable:1579,inUse:30,unavailable:225});Object.assign(state.dashboard.platforms.codearts,{routable:3,inUse:0,unavailable:0});renderOverview()`,context);
let cards=nodes.get('overview-kpis').innerHTML;
assert(cards.includes('2,205'));assert(cards.includes('150'));assert(cards.includes('3,092'));assert(cards.includes('已统计 3/4 个平台'));
assert(nodes.get('platform-summary').innerHTML.includes('尚未接入实时调度状态'));
vm.runInContext(`for(const p of providers)Object.assign(state.dashboard.platforms[p],{routable:null,inUse:null,unavailable:null,unavailableBreakdown:null});renderOverview()`,context);
assert(nodes.get('overview-kpis').innerHTML.includes('已统计 0/4 个平台'));
vm.runInContext(`paintInvitationSummary({counts:{bound:2563,retry:2,submitted:1},config:{enabled:true,paused:false}})`,context);
assert(nodes.get('invite-kpis').innerHTML.includes('2,563'));assert(nodes.get('invite-auto-state').textContent.includes('自动入队已开启'));
assert(fs.readFileSync('index.html','utf8').includes('data-tab="invitation"'));
assert(!fs.readFileSync('index.html','utf8').includes('<a href="/invitation"'));
console.log('frontend semantic render passed');
'''
        result = subprocess.run(['node', '-e', script], input=json.dumps(state), text=True,
                                encoding='utf-8', cwd=Path(__file__).parent, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()

