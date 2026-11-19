"""Mirror explicit account failures into the gateway's native scheduling switch."""
import json

PREFIX = 'routing-guard-v1:'


def failure_kind(message):
    message = str(message or '')
    if '官方管理' in message:
        return None
    if '账号已被停用' in message or '账号已停用' in message:
        return 'disabled'
    # Zero credit is a limiter condition, not a durable account disable.
    if any(s in message for s in ('登录已失效', '登录态已过期', '请重新登录', '鉴权失败，凭证需要检查或重新登录')):
        return 'login'
    return None


def should_block(evidence, chat_success, maintenance_success, current_version):
    if evidence.get('version') and evidence['version'] != current_version:
        return False
    if chat_success > evidence['at']:
        return False
    if evidence['kind'] != 'disabled' and maintenance_success > evidence['at']:
        return False
    return True


def can_restore(marker, row, version, chat_success, maintenance_success):
    if marker['kind'] == 'disabled':
        return False
    if marker['kind'] == 'balance':
        return bool(row.get('lastSuccess', 0) > marker['at'] and
                    (row.get('unlimited') or (row.get('balance') or 0) >= 1))
    # Successful authenticated quota/chat after the failure also proves that the
    # same credential recovered. A checkin alone is not quota confirmation.
    return max(chat_success, row.get('lastSuccess',0)) > marker['at']


def reconcile(db, snapshot, account, secret_of, version_of, official, event, timestamp):
    """Retired: maintenance never changes model-routing account switches."""
    return 0
