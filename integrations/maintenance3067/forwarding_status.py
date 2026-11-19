"""Read-only forwarding observations; maintenance jobs are never traffic."""
from collections import Counter


def agent_running(call):
    # Native endpoint reads live requests, not the completed request ledger.
    rows = []
    seen = set()
    for page in range(20):
        data = call('/api/stats/requests?status=running&limit=1000&offset=' + str(len(rows)))
        batch = data.get('entries')
        if not isinstance(batch, list):
            raise ValueError('invalid_running_snapshot')
        rows.extend(batch)
        if len(rows) >= data.get('matched', 0):
            break
        ids = {r.get('id') for r in batch}
        if not batch or ids <= seen:
            raise ValueError('truncated_running_snapshot')
        seen.update(ids)
    else:
        raise ValueError('truncated_running_snapshot')
    unique = {r['id']: r for r in rows}
    # Retry backoff can still name the previous account after releasing it.
    counts = Counter(r['accountId'] for r in unique.values()
                     if r.get('accountId') and r.get('phase') in ('waiting', 'streaming'))
    return dict(counts)


def mirai_routes(data, observed):
    if not data.get('ok'):
        raise ValueError('mirai_runtime_unavailable')
    # Never mistake the native top-ten list for the whole pool.
    complete = data.get('complete') is True
    counts = data.get('inflight', {})
    result = {}
    for row in data['accounts']:
        uid = row.get('uid', '')
        using = int(counts.get(uid, 0)) if complete or uid in counts else None
        state = row['state']
        reason = row.get('reason', '')
        if state == 'usable':
            if using is None:
                state, reason = 'unknown', '3066在途明细被原生接口截断，等待完整观测'
            elif row['limit'] > 0 and using >= row['limit']:
                state, reason = 'concurrency', '账户并发已占满'
        result['mirai:' + str(row['id'])] = {
            'state': state, 'reason': reason, 'at': observed,
            'inFlight': using, 'usageAt': observed, 'reasonKey':row.get('reasonKey',''), 'recovery':row.get('recovery',[]),
        }
    return result


def usage_for(route, observation, account_id, timestamp, maximum_age=30000, home=None):
    if home == 'miraihub' or (home is None and account_id.startswith('mirai:')):
        at, count = route.get('usageAt', 0), route.get('inFlight')
    else:
        at = observation.get('at', 0)
        count = observation.get('counts', {}).get(account_id, 0)
    return count if at and 0 <= timestamp - at <= maximum_age else None

