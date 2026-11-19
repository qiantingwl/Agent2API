"""Persist worker outcomes without leaking the in-process account reservation."""
import sqlite3
import time


def persist_job_outcome(db, job, status, message, timestamp, sleep=time.sleep):
    for attempt in range(3):
        try:
            with db() as c:
                c.execute('begin immediate')
                if status == 'ok':
                    c.execute('delete from cooldowns where scope=?',
                              ('operation:' + job['action'] + ':' + job['account'],))
                    c.execute('delete from cooldowns where scope in (?,?,?) and reason=?',
                              (*('operation:' + action + ':' + job['account']
                                 for action in ('balance', 'checkin', 'credential')),
                               '鉴权失败，凭证需要检查或重新登录'))
                if status == 'queued':
                    c.execute("update jobs set status='queued',started=null,ended=null,not_before=?,message=? where id=?",
                              (timestamp + 30000, message, job['id']))
                else:
                    c.execute('update jobs set status=?,ended=?,message=? where id=?',
                              (status, timestamp, message, job['id']))
            return
        except sqlite3.OperationalError as exc:
            code = getattr(exc, 'sqlite_errorcode', 0) & 255
            busy = code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
            if not busy or attempt == 2:
                raise
            sleep(0.1 * (attempt + 1))


def reconcile_completed_balances(db, active, timestamp):
    """Require AG's receipt; historical mirror rows do not gate recovery."""
    changed = 0
    with db() as c:
        c.execute('begin immediate')
        rows = c.execute("""select j.id,j.account,r.created from jobs j
            join direct_results r on r.id=j.id and r.account=j.account and r.action='balance'
            join direct_outbox g on g.result=j.id and g.target='gateway' and g.status='done'
            where j.action='balance' and j.started<? and r.created>=j.started
              and (j.status='running' or (j.status='interrupted' and
                   j.message='服务重启；未自动重试，请人工核对签到结果'))""",
                         (timestamp - 120000,)).fetchall()
        for jid, account, completed in rows:
            if account in active:
                continue
            changed += c.execute("update jobs set status='ok',ended=?,message=? where id=? and status in ('running','interrupted')",
                                 (completed, '已依据 AG 成功回执恢复任务状态；未重复请求上游', jid)).rowcount
    return changed
