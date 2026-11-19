"""Direct WPS daily maintenance; no native task calls or credential renewal."""
import datetime
import hashlib
import json
import math
import urllib.error
import urllib.request

from direct_maintenance import DeliveryPending, confirmed_day_key
from maintenance_state import credential_version

BASES = ('https://lingxi.wps.cn', 'https://lingxi.kdocs.cn')
TZ = datetime.timezone(datetime.timedelta(hours=8))


class WpsError(RuntimeError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class WpsClient:
    def __init__(self, auth, timeout):
        self.base = str(auth.get('base') or BASES[0]).rstrip('/')
        if self.base not in BASES:
            raise WpsError('error', 'WPS 账号域名不在官方白名单')
        cookie = str(auth.get('cookie') or '').strip()
        if not cookie and auth.get('sid'):
            cookie = 'wps_sid=' + str(auth['sid'])
            if auth.get('uid'): cookie += '; uid=' + str(auth['uid'])
        if not cookie:
            raise WpsError('needs_login', '缺少 WPS Cookie，需要重新登录')
        stamp = 'x-kso-app-name=win-lingxi-desktop; x-kso-app-version=1.3.31; x-kso-device-id=' + hashlib.sha256(b'magpie-lingxi-device').hexdigest()
        self.headers = {'Cookie': cookie.rstrip(';') + '; ' + stamp,
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                        'Referer': self.base + '/', 'Accept': 'application/json', 'Content-Type': 'application/json'}
        self.timeout = min(30, max(5, timeout))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, path, post=False):
        req = urllib.request.Request(self.base + '/api/public/v1/' + path,
                                     data=b'{}' if post else None, headers=self.headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                value = json.loads(r.read(1048576))
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise WpsError('needs_login', 'WPS 官方确认登录态失效，需要重新登录') from None
            # Generic 403 can be a WAF/permission error; do not mark cookies dead.
            raise WpsError('cooling' if e.code == 429 else 'error', 'WPS 官方接口返回 HTTP ' + str(e.code)) from None
        except TimeoutError:
            raise TimeoutError('WPS 官方接口请求超时，保留原观测') from None
        except urllib.error.URLError as e:
            if isinstance(e.reason, TimeoutError):
                raise TimeoutError('WPS 官方接口请求超时，保留原观测') from None
            raise WpsError('error', 'WPS 官方接口连接异常，未判定登录失效') from None
        except Exception:
            raise WpsError('error', 'WPS 官方接口网络或响应异常，未判定登录失效') from None
        if not isinstance(value, dict): raise WpsError('error', 'WPS 官方响应格式异常')
        result = str(value.get('result') or value.get('code') or '').lower()
        if result in ('userunauthorized', 'unauthorized'):
            raise WpsError('needs_login', 'WPS 官方确认登录态失效，需要重新登录')
        if result not in ('', 'ok', 'success', '0', '200') or value.get('success') is False or value.get('error'):
            raise WpsError('error', 'WPS 官方业务请求未成功')
        return value.get('data') if isinstance(value.get('data'), dict) else {}

    def balance(self):
        data = self.call('credits/balance')
        value = data.get('total_balance', data.get('balance'))
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise WpsError('error', 'WPS 未返回有效余额，保留原观测')
        return value

    def daily(self):
        data = self.call('tasks')
        return next((x for x in data.get('tasks', []) if isinstance(x, dict) and x.get('task_key') == 'daily_check_in'), None)


class WpsMaintenance:
    def __init__(self, unified, db, encode, decode, now, bridge, after_sign, client=WpsClient):
        self.unified, self.db, self.encode, self.decode = unified, db, encode, decode
        self.now, self.bridge, self.after_sign, self.client = now, bridge, after_sign, client
        with db() as c:
            c.execute('CREATE TABLE IF NOT EXISTS wps_results(id TEXT PRIMARY KEY,payload TEXT NOT NULL,delivered INTEGER NOT NULL DEFAULT 0)')
            c.execute("update jobs set status='queued',started=null,ended=null,message='已保存 WPS 结果，恢复回写' where provider='wps-lingxi' and status='interrupted' and id in (select id from wps_results)")

    def execute(self, job, proxy, timeout):
        if proxy: raise WpsError('error', 'WPS 维护仅使用官方直连')
        if job['action'] not in ('balance', 'checkin', 'recheck'):
            return {'status': 'unsupported', 'message': 'WPS 仅接管每日签到、余额和登录态复核'}
        key = job['account'].split(':', 1)[1]
        with self.db() as c:
            saved = c.execute('select payload from wps_results where id=?', (job['id'],)).fetchone()
        if saved:
            payload = self.decode(saved[0])
        else:
            if job['action']=='checkin':
                with self.db() as c:confirmed=c.execute('select 1 from ledger where key=?',(confirmed_day_key(job['account'],self.now()),)).fetchone()
                if confirmed:return {'status':'skipped','message':'今日签到已有官方确认，不再重复签到；余额独立补查'}
            with self.unified.lock: record = dict(self.unified.external.get(key, {}))
            if record.get('status') != 'active' or not record.get('auth_hash'):
                return {'status': 'skipped', 'message': '账户不可维护，保留现有开关'}
            auth = record.get('auth') or {}
            with self.db() as c:
                c.execute('update jobs set credential_version=? where id=?', (credential_version(auth), job['id']))
            payload = {'command': 'task', 'action': 'maintenance_result', 'account_id': key,
                       'expected_auth_hash': record['auth_hash'], 'result_id': job['id'],
                       'status': 'ok', 'operation': job['action'], 'signed': False,
                       'message': '官方余额与登录态已核验，结果已回写'}
            try:
                client = self.client(auth, timeout)
                if job['action'] == 'checkin':
                    day = datetime.datetime.fromtimestamp(self.now()/1000, TZ).strftime('%Y-%m-%d')
                    intent_key = 'wps-claim:' + key + ':' + day + ':' + record['auth_hash']
                    daily = client.daily()
                    if daily is None: raise WpsError('error', '官方任务中心没有每日签到')
                    if daily.get('status') != 'claimed':
                        # Persist BEFORE POST. An ambiguous submission is only verified,
                        # even across restarts or a new retry job on the same day.
                        with self.db() as c:
                            c.execute('begin immediate')
                            claimed = c.execute('select 1 from ledger where key=?', (intent_key,)).fetchone()
                            if not claimed: c.execute('insert into ledger values(?,?)', (intent_key, str(self.now())))
                        if not claimed:
                            client.call('tasks/daily_check_in/claim?date=' + day, post=True)
                        daily = client.daily()
                        if not daily or daily.get('status') != 'claimed':
                            raise WpsError('unconfirmed', '签到提交尚未确认；后续仅查询，不重复领取')
                    payload.update(signed=True, signed_at=self.now(), signed_date=day,
                                   message='今日签到已由官方确认；已安排签到后余额查询')
                else:
                    payload['balance'] = client.balance()
            except WpsError as e:
                payload.update(status=e.status, message=str(e))
            payload['observed_at'] = self.now()
            with self.db() as c:
                c.execute('insert into wps_results(id,payload) values(?,?)', (job['id'], self.encode(payload)))
                if payload.get('signed'):
                    c.execute('insert or replace into ledger values(?,?)',(confirmed_day_key(job['account'],payload['signed_at']),str(payload['signed_at'])))
        try:
            reply = self.bridge(payload)
        except Exception:
            raise DeliveryPending('WPS 结果已保存，等待回写；不重复执行官方操作') from None
        if not reply.get('ok'):
            if reply.get('status') in ('conflict', 'disabled', 'not_found', 'stale'):
                return {'status': 'skipped', 'message': '账户、凭证或观测已变化，旧结果未覆盖'}
            raise DeliveryPending('WPS 结果等待回写确认')
        # Acknowledged delivery updates the UI immediately, independently of a
        # slow full-inventory cycle. Old credential receipts cannot recover a new one.
        self.unified.apply_wps_receipt(payload)
        with self.db() as c:
            c.execute('update wps_results set delivered=1 where id=?', (job['id'],))
        if payload.get('signed'):
            self.after_sign(job['account'], 'wps-lingxi', payload['signed_at'])
        self.unified.wake.set()
        return {'status': payload['status'], 'message': payload['message']}
