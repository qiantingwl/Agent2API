"""Evidence-based auth state and operation-scoped cooldowns; no upstream calls."""
import hashlib
import json

ACTIONS = ('balance', 'checkin', 'credential', 'activity', 'recheck', 'invitation')
AUTH_RECHECK_MS = 86400000


def credential_version(secret):
    return hashlib.sha256(json.dumps(secret, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def resolve_auth(persisted_flag, failure, success_at, version, timestamp, recheck_ms=None, verification=None):
    failure = failure or {}
    failed_at = failure.get('ended') or failure.get('created') or 0
    # A current successful authenticated operation supersedes an older error.
    changed = bool(failure.get('credential_version') and failure['credential_version'] != version)
    receipt=verification or {}
    proven=receipt.get('status')=='ok' and receipt.get('credential_version')==version and (receipt.get('ended') or 0)>failed_at
    recovered = bool(proven or (not changed and failed_at and success_at > failed_at))
    recheck_at = failed_at + (AUTH_RECHECK_MS if recheck_ms is None else recheck_ms) if failed_at else 0
    recheck = bool(not recovered and failed_at and (changed or timestamp >= recheck_at))
    blocked = bool(not recovered and not recheck and (persisted_flag or failed_at))
    return {'needsLogin': blocked, 'authStatus': 'recheck_due' if recheck else 'needs_login' if blocked else 'verified' if recovered or success_at else 'unknown',
            'authCredentialChanged': changed and not recovered, 'authRecovered': recovered, 'authRecheck': recheck, 'authFailureAt': failed_at,
            'authRecheckAt': recheck_at if failed_at and not recovered else 0}


def cooldown_scopes(account, provider, action):
    # Provider/account rate limits remain shared; ordinary failures do not.
    return (f'operation:{action}:{account}', f'provider:{provider}',
            f'account_rate:{account}', f'legacy_unknown:{account}')


def cooldown_map(cooldowns, account, provider, recovered_auth=False):
    def until(scope):
        record = cooldowns.get(scope, {})
        # Only an auth-specific ordinary cooldown is superseded by newer success.
        if recovered_auth and scope.startswith('operation:') and record.get('reason') == '鉴权失败，凭证需要检查或重新登录':
            return 0
        return record.get('until', 0)
    return {a: max((until(scope) for scope in cooldown_scopes(account, provider, a)), default=0) for a in ACTIONS}


def operation_cooldown(row, action):
    return row.get('operationCooldowns', {}).get(action, row.get('cooldownUntil', 0))


def migrate_cooldowns(connection):
    """Reattribute legacy rows using their matching failure; preserve ambiguity."""
    if connection.execute("select 1 from ledger where key='operation-cooldowns-v1'").fetchone():
        return 0
    migrated = 0
    for row in connection.execute("select * from cooldowns where scope like 'account:%'").fetchall():
        row = dict(row)
        account = row['scope'][len('account:'):]
        matched = connection.execute("select action from jobs where account=? and message=? and status in ('error','cooling','needs_login','unconfirmed') order by coalesce(ended,created) desc,rowid desc limit 1", (account, row['reason'])).fetchone()
        scope = f'account_rate:{account}' if '429' in (row['reason'] or '') else f'operation:{matched[0]}:{account}' if matched else f'legacy_unknown:{account}'
        connection.execute('insert into cooldowns values(?,?,?,?) on conflict(scope) do update set until=max(until,excluded.until),failures=max(failures,excluded.failures)', (scope, row['until'], row['failures'], row['reason']))
        connection.execute('delete from cooldowns where scope=?', (row['scope'],))
        migrated += 1
    connection.execute("insert into ledger values('operation-cooldowns-v1',?)", (str(migrated),))
    return migrated

