"""Display projection only. Never writes native account or routing state."""


def project_availability(row):
    route = row['routing']
    route['nativeState'] = route['state']
    route['nativeReason'] = route.get('reason', '')
    if route['state'] in ('usable', 'concurrency'):
        recovered = row.get('authRecovered') and row.get('authStatus') == 'verified'
        if not row.get('enabled'):
            route.update(state='disabled', reason='原程序账户开关关闭')
        elif row.get('authCredentialChanged') or row.get('balanceCredentialChanged'):
            route.update(state='unverified', reason='当前凭证已更新，等待匹配的余额核验')
        elif not recovered and (row.get('needsLogin') or row.get('authConfirmedFailed')
                or row.get('authStatus') in ('needs_login', 'credential_failed', 'recheck_due', 'pending_verify', 'observing')):
            route.update(state='auth_failed', reason='存在尚未恢复的登录异常，具体核验状态见账户明细')
        elif route.get('inUse') is not None:
            route.update(state='concurrency' if route['inUse'] else 'usable',
                         reason='可用账户正在使用' if route['inUse'] else '原生队列允许且当前空闲；以实际模型选号为准')
    available = route['state'] in ('usable', 'concurrency')
    route['ready'] = (available and not route['inUse']) if route.get('inUse') is not None else None
    route['availableInUse'] = (available and route['inUse']) if route.get('inUse') is not None else None
