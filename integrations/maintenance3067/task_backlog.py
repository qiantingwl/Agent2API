"""Read-only backlog projections and the sign-first admission rule."""
import datetime
from collections import Counter
from maintenance_state import operation_cooldown
from maintenance_policy import credential_due
from auxiliary_policy import auxiliary_due

SUPPORTED = {'loomy', 'raccoon', 'codearts', 'wps-lingxi'}


def sign_context(connection, timestamp, tz):
    start = int(datetime.datetime.fromtimestamp(timestamp/1000, tz).replace(
        hour=0, minute=0, second=0, microsecond=0).timestamp()*1000)
    last = dict(connection.execute("select account,max(created) from jobs where action='checkin' group by account"))
    attempts = dict(connection.execute("select account,count(*) from jobs where action='checkin' and attempt>=0 and created>=? and status not in ('cancelled','skipped') group by account", (start,)))
    return start, last, attempts


def sign_ready(row, config, timestamp, tz, context, routes=None):
    """Only accounts runnable now hold ordinary work behind the sign phase."""
    p = row['provider']; cp = config.get('providers', {}).get(p, {}).get('checkin', {})
    if p not in SUPPORTED or not row.get('supported', True) or row.get('signed'):
        return False
    if config.get('paused') or row.get('maintenancePaused') or row.get('needsLogin') or not cp.get('enabled') or cp.get('paused'):
        return False
    if routes is not None and cp.get('route', 'direct') not in routes:
        return False
    clock = datetime.datetime.fromtimestamp(timestamp/1000, tz).strftime('%H:%M')
    if not cp.get('start', '00:00') <= clock < cp.get('end', '23:00'):
        return False
    start, last, attempts = context
    if attempts.get(row['id'], 0) >= cp.get('maxAttempts', 3) or operation_cooldown(row, 'checkin') > timestamp:
        return False
    previous = last.get(row['id'], 0)
    return previous < start or timestamp-previous >= cp.get('retryInterval', 1800)*1000


def checkin_phase(rows, config, connection, timestamp, tz, routes, active, jobs):
    return bool(checkin_providers(rows, config, connection, timestamp, tz, routes, active, jobs))


def checkin_providers(rows, config, connection, timestamp, tz, routes, active, jobs):
    providers = {p for p, action in active.values() if action == 'checkin'}
    context = sign_context(connection, timestamp, tz)
    by_id = {r['id']: r for r in rows}
    # Queued attempts already count toward maxAttempts and retryInterval; they
    # must still run now. Do not mistake enqueue time for a failed attempt.
    for job in jobs:
        if job['action'] != 'checkin' or job.get('not_before', 0) > timestamp:
            continue
        row = by_id.get(job['account'])
        if not row:
            continue
        cp = config.get('providers', {}).get(job['provider'], {}).get('checkin', {})
        relaxed = dict(config, providers={**config.get('providers', {}), job['provider']: {
            **config.get('providers', {}).get(job['provider'], {}), 'checkin': {**cp, 'enabled': True}}})
        if sign_ready(row, relaxed, timestamp, tz, (context[0], {}, {}), routes):
            providers.add(job['provider'])
    providers.update(r['provider'] for r in rows if sign_ready(r, config, timestamp, tz, context, routes))
    return providers


def ordinary_during_sign(job):
    # Explicit WPS refresh is an operator-requested verification, not periodic work.
    if job.get('provider')=='wps-lingxi' and job['action']=='balance' and job.get('origin')=='manual':return False
    # Credential renewal is a prerequisite, not ordinary background work.
    return job['action'] not in ('checkin', 'credential', 'recheck') and not (
        job['action'] == 'balance' and job.get('origin') in ('post_checkin','post_relogin'))


def task_backlogs(rows, config, latest, invitation_states, timestamp, tz):
    result = {}
    for p in SUPPORTED:
        pc = config.get('providers', {}).get(p, {})
        result[p] = {}
        for action in ('balance', 'checkin', 'credential', 'recheck', 'invitation'):
            if action not in pc or (action == 'invitation' and p != 'loomy') or (action == 'recheck' and p not in ('loomy','wps-lingxi')):
                continue
            cfg = pc[action]; counts = Counter()
            balance_display = Counter()
            for r in rows:
                if r['provider'] != p or not r.get('supported', True):
                    continue
                j = latest.get((r['id'], action), {}); status = j.get('status')
                inv = invitation_states.get(r['id'], {})
                signed_pending = False
                if action == 'balance':
                    signed_pending = bool(r.get('signed') and r.get('signedAt', 0) and (
                        r.get('lastSuccess', 0) < r['signedAt'] or r.get('balanceCredentialChanged')))
                    if signed_pending:
                        balance_display['postCheckinPending'] += 1
                        if status == 'running': balance_display['postCheckinRunning'] += 1
                        elif r.get('needsLogin'): balance_display['postCheckinNeedsLogin'] += 1
                        elif r.get('maintenancePaused') or config.get('paused') or cfg.get('paused'): balance_display['postCheckinPaused'] += 1
                        elif operation_cooldown(r, action) > timestamp: balance_display['postCheckinCooling'] += 1
                    elif r.get('signed') and r.get('signedAt', 0):
                        balance_display['postCheckinCompleted'] += 1
                if action == 'checkin' and r.get('signed'):
                    continue
                if action == 'balance' and r['balanceDetail']['waitingForCheckin']:
                    continue
                if action == 'credential' and not r.get('credentialRenewable'):
                    continue
                if action == 'invitation' and inv.get('status') == 'bound':
                    continue
                if action == 'recheck' and not r.get('recheckAllowed'):
                    continue
                if status == 'running':
                    counts['running'] += 1; continue
                if r.get('maintenancePaused') or (action == 'invitation' and not r.get('enabled')) or config.get('paused') or cfg.get('paused'):
                    counts['paused'] += 1; continue
                if r.get('needsLogin') and action not in ('credential', 'recheck'):
                    counts['needsLogin'] += 1; continue
                if not cfg.get('enabled') and status != 'queued':
                    counts['disabled'] += 1; continue
                if action == 'checkin':
                    kind = r['checkinDetail']['state']
                    bucket = {'eligible':'ready','queued':'ready','retry_wait':'cooling','outside_window':'scheduled','exhausted':'exhausted'}.get(kind)
                    if status == 'queued':
                        bucket = 'cooling' if operation_cooldown(r, action)>timestamp else 'scheduled' if j.get('not_before',0)>timestamp else 'ready'
                elif action == 'balance':
                    detail = r['balanceDetail']; due = detail.get('nextEligibleAt') or timestamp
                    bucket = 'cooling' if operation_cooldown(r, action)>timestamp else 'scheduled' if due>timestamp else 'ready'
                elif action == 'credential':
                    if status != 'queued' and not credential_due(r, j.get('created',0), timestamp, cfg):
                        continue
                    bucket = 'cooling' if operation_cooldown(r, action)>timestamp else 'ready'
                elif action == 'recheck':
                    bucket = 'ready' if auxiliary_due(r, action, j.get('created',0), timestamp, cfg, tz) else 'scheduled'
                    if operation_cooldown(r, action)>timestamp: bucket='cooling'
                else:
                    due=max(inv.get('nextAt',0),j.get('created',0)+cfg.get('interval',3600)*1000,operation_cooldown(r, action))
                    bucket='cooling' if due>timestamp else 'ready'
                if bucket:
                    counts[bucket] += 1
                    if action == 'balance' and not signed_pending:
                        balance_display[{'ready':'dueQueries','scheduled':'nextQueries','cooling':'retryCooling'}[bucket]] += 1
            counts['remaining'] = sum(counts[k] for k in ('ready','scheduled','cooling'))
            result[p][action] = {k:counts[k] for k in ('remaining','ready','scheduled','cooling','running','needsLogin','paused','disabled','exhausted')}
            if action == 'balance':
                result[p][action]['display'] = {k:balance_display[k] for k in (
                    'postCheckinPending','postCheckinCompleted','postCheckinRunning',
                    'postCheckinNeedsLogin','postCheckinPaused','postCheckinCooling',
                    'dueQueries','nextQueries','retryCooling')}
    return result


MAX_SIGN_HOLD_MS = 15 * 60 * 1000


def sign_hold(job, providers, timestamp, row=None):
    """Priority is enforced by dispatch order, never by leaving slots empty.

    Running checkins already reserve their follow-up balance slot. Queued
    runnable checkins are admitted first; their unused capacity is borrowable.
    """
    return False


def capacity_hold(job, active, config):
    p, a, aid = job['provider'], job['action'], job['account']
    pc = config['providers'][p]
    if aid in active:return '同一账户已有维护任务'
    if len(active) >= config.get('globalConcurrency',64):return '总维护并发已满'
    values = list(active.values())
    shared_mode = config.get('sharedMaintenanceSlots') and a in ('checkin','balance','recheck')
    if not shared_mode and sum(x[0] == p for x in values) >= pc.get('concurrency',64):return '本平台维护并发已满'
    if not shared_mode and not (a=='recheck' and job.get('credential_refresh')) and values.count((p, a)) >= pc[a].get('concurrency', 1):return '此类任务并发已满'
    if a in ('balance', 'checkin', 'recheck'):
        shared = [x for x in values if x[1] in ('balance', 'checkin', 'recheck')]
        if len(shared) >= config.get('globalBalanceConcurrency',16):return '签到与余额共用的总槽位已满'
        if not shared_mode and sum(x[0] == p for x in shared) >= pc['balance'].get('concurrency',1):return '本平台签到与余额共用槽位已满'
    return ''
