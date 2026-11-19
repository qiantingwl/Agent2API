"""Project acknowledged, version-matched WPS receipts into the local inventory."""
import math


def apply_receipt(record, receipt):
    if (not record or record.get('platform') != 'wps-lingxi'
            or str(record.get('id')) != str(receipt.get('account_id'))
            or not record.get('auth_hash')
            or record['auth_hash'] != receipt.get('expected_auth_hash')):
        return False
    at = receipt.get('observed_at')
    if type(at) is not int or at <= 0 or at < (record.get('verification_at') or 0):
        return False
    status = receipt.get('status')
    if status not in ('ok', 'needs_login'):
        return False
    record.update(verification_status=status, verification_at=at,
                  needs_login=status == 'needs_login')
    if status == 'ok' and 'balance' in receipt:
        balance = receipt['balance']
        if isinstance(balance, bool) or not isinstance(balance, (int, float)) or not math.isfinite(balance) or balance < 0:
            raise ValueError('invalid_acknowledged_balance')
        record['verified_balance_at'] = max(at, record.get('verified_balance_at') or 0)
        if at >= (record.get('balance_at') or 0):
            record.update(balance=balance, balance_at=at)
    if status == 'ok' and receipt.get('signed'):
        record['signed_at'] = max(receipt.get('signed_at') or 0, record.get('signed_at') or 0)
    return True
