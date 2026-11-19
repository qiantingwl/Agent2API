"""Bounded Loomy verification policy. Never clears native flags or enables accounts."""
from maintenance_state import resolve_auth

# Loomy 核验失败后的重试退避。原为全局 24 小时，导致一次网络抖动造成的
# 误判会被冻结一整天，v7 已恢复的账号在面板上仍显示昨天的失败。
# 缩短到 1 小时，与 loomy.recheck.interval 对齐：失败一小时后真实复核一次。
LOOMY_RECHECK_MS = 3600000


def is_capacity_error(message):
    return any(text in str(message or '') for text in
               ('余额桥并发已满', '维护余额并发已满', '该账户余额查询正在执行'))


def resolve_loomy_auth(persisted, failure, success_at, version, timestamp,
                       marker=None, verification=None):
    failure, marker, verification = failure or {}, marker or {}, verification or {}
    state = resolve_auth(persisted, failure, success_at, version, timestamp, LOOMY_RECHECK_MS)
    failed_at = state['authFailureAt']
    marker_at = marker.get('at', 0) if marker.get('kind') == 'login' else 0
    verified = (verification.get('status') == 'ok'
                and verification.get('credential_version') == version
                and (verification.get('ended') or 0) > max(failed_at, marker_at))
    changed = bool((failure.get('credential_version') and failure['credential_version'] != version)
                   or (not failed_at and marker.get('version') and marker['version'] != version))
    # A newer authenticated balance supersedes an owned login marker. A sign
    # alone is never passed as success_at for this policy.
    recovered = verified
    if recovered:
        state.update(needsLogin=False, authStatus='verified', authRecovered=True,
                     authRecheck=False, authRecheckAt=0)
    elif persisted or failed_at or (marker.get('owned') and marker_at):
        due = changed or not failed_at or timestamp >= state['authRecheckAt']
        state.update(needsLogin=True, authRecovered=False, authRecheck=due,
                     authStatus='pending_verify' if due else
                     'credential_failed' if failure.get('action') == 'recheck' else 'observing')
        if due:
            # Missing timestamps remain zero; eligibility, rather than a fake
            # failure date, makes them verifiable.
            state['authRecheckAt'] = 0 if changed or not failed_at else state['authRecheckAt']
    state['authFailureMessage'] = failure.get('message') or ''
    state['authCredentialChanged'] = changed and not recovered
    # 「核验动作本身判了失败」是已确认失效的强证据。到点重验只是把它重新排进
    # 复核队列，不能让这条事实消失 —— 否则面板上「需重登」会随着时间凭空减少，
    # 看起来像账号被修好了，实际只是还没轮到第二次复核。
    state['authConfirmedFailed'] = bool(failure.get('action') == 'recheck' and not recovered and not changed)
    state['authFailureAction'] = failure.get('action') or ''
    return state


def recheck_allowed(row):
    return bool(row.get('provider') == 'loomy' and not row.get('maintenancePaused')
                and row.get('authRecheck'))


def recheck_due(row, previous, timestamp, config):
    return (recheck_allowed(row) and
            (row.get('authCredentialChanged') or not previous or timestamp - previous >= config.get('interval', 3600) * 1000))

