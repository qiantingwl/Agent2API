"""Bounded site reachability probes through AG's existing proxy pool.

No account credentials or model requests are used. Probe results never change
an account, a proxy's enable switch, or the maintenance quarantine policy.
"""
import concurrent.futures
import json
import threading
import time

TARGETS = {
    'loomy': 'https://loomyad.xunfei.cn/',
    'raccoon': 'https://xiaohuanxiong.com/',
    'wps-lingxi': 'https://lingxi.wps.cn/',
}
DEFAULT = {'enabled': False, 'interval': 900, 'concurrency': 2}


def outcome(value):
    status = value.get('status')
    if type(status) is not int or not 100 <= status <= 599:
        status = None
    ok = status is not None and 200 <= status < 300 and value.get('success') is True
    duration = value.get('durationMs')
    if type(duration) not in (int, float) or not 0 <= duration <= 60000:
        duration = None
    return {'status': status, 'httpOk': ok, 'transportReached': status is not None,
            'durationMs': duration, 'category': 'ok' if ok else
            'rejected' if status in (401, 403) else 'http_error' if status else
            'timeout' if value.get('error') == 'probe_timeout' else 'connection_error'}


class NodeProbe:
    def __init__(self, db, official, now=None):
        self.db, self.official = db, official
        self.now = now or (lambda: int(time.time() * 1000))
        self.lock = threading.Lock()
        self.active = {}
        self.inventory = []
        self.inventory_at = None
        self.last_error = ''
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix='ag-node-probe')
        with self.db() as c:
            c.execute('create table if not exists node_probe_results(proxy text,provider text,checked_at integer,result text,primary key(proxy,provider))')
            c.execute('create table if not exists node_probe_schedule(proxy text primary key,next_at integer not null)')

    def config(self):
        with self.db() as c:
            row = c.execute("select value from settings where key='nodeProbe'").fetchone()
        return {**DEFAULT, **(json.loads(row[0]) if row else {})}

    def configure(self, value):
        cfg = self.config()
        if 'enabled' in value:
            if type(value['enabled']) is not bool:
                raise ValueError('enabled must be boolean')
            cfg['enabled'] = value['enabled']
        for key, low, high in [('interval', 300, 86400), ('concurrency', 1, 2)]:
            if key in value:
                number = value[key]
                if type(number) is not int or not low <= number <= high:
                    raise ValueError(key + ' out of range')
                cfg[key] = number
        with self.db() as c:
            c.execute('insert or replace into settings(key,value) values(?,?)', ('nodeProbe', json.dumps(cfg)))
        return cfg

    def status(self):
        with self.db() as c:
            results = [{'proxy': p, 'provider': s, 'checkedAt': at, **json.loads(v)}
                       for p, s, at, v in c.execute('select proxy,provider,checked_at,result from node_probe_results order by proxy,provider')]
        with self.lock:
            active = len(self.active)
        return {'config': self.config(), 'targets': dict(TARGETS), 'active': active,
                'error': self.last_error, 'results': results}

    def _probe(self, proxy_id, stop):
        try:
            for provider, url in TARGETS.items():
                if stop.is_set():
                    break
                try:
                    reply = self.official().call('/api/proxies/pool/test', {'id': proxy_id, 'testUrl': url})
                    result = outcome(reply)
                except Exception:
                    result = outcome({})
                with self.db() as c:
                    c.execute('insert or replace into node_probe_results values(?,?,?,?)',
                              (proxy_id, provider, self.now(), json.dumps(result)))
        finally:
            with self.db() as c:
                c.execute('insert or replace into node_probe_schedule values(?,?)',
                          (proxy_id, self.now() + self.config()['interval'] * 1000))

    def tick(self, stop):
        with self.lock:
            for key, future in list(self.active.items()):
                if future.done():
                    try:
                        future.result()
                    except Exception:
                        self.last_error = 'probe_storage_error'
                    del self.active[key]
        cfg = self.config()
        if stop.is_set() or not cfg['enabled']:
            return 0
        now = self.now()
        if self.inventory_at is None or now - self.inventory_at >= 60000:
            data = self.official().call('/api/proxies/pool')
            # Retain identifiers only; pool responses can include proxy passwords.
            self.inventory = list(dict.fromkeys(item['id'] for item in data.get('items', [])
                if isinstance(item, dict) and isinstance(item.get('id'), str)
                and item.get('enabled') is True and item.get('source') in ('manual', 'clash', 'subscription')))
            self.inventory_at = now
        with self.db() as c:
            due = dict(c.execute('select proxy,next_at from node_probe_schedule'))
        admitted = 0
        with self.lock:
            for proxy_id in sorted(self.inventory, key=lambda key: (due.get(key, 0), key)):
                if len(self.active) >= cfg['concurrency']:
                    break
                if proxy_id in self.active or due.get(proxy_id, 0) > now:
                    continue
                self.active[proxy_id] = self.pool.submit(self._probe, proxy_id, stop)
                admitted += 1
        return admitted

    def run(self, stop):
        try:
            while not stop.is_set():
                try:
                    self.tick(stop)
                except Exception:
                    self.last_error = 'probe_inventory_unavailable'
                if stop.wait(2):
                    break
        finally:
            self.pool.shutdown(wait=True, cancel_futures=True)
