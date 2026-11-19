"""WPS auxiliary maintenance, owned by the central queue."""
import datetime
from auth_recheck import recheck_due

AUX_ACTIONS = ('activity', 'recheck')
DEFAULT_AUX = {
    'activity': {'enabled': False, 'paused': False, 'concurrency': 2,
                 'interval': 86400, 'route': 'direct'},
    'recheck': {'enabled': False, 'paused': False, 'concurrency': 1,
                'interval': 3600, 'route': 'direct'},
}

def auxiliary_due(row, action, previous, timestamp, config, timezone):
    if row.get('provider') == 'loomy' and action == 'recheck':
        return recheck_due(row, previous, timestamp, config)
    if row.get('provider') != 'wps-lingxi' or row.get('maintenancePaused'):
        return False
    if action == 'recheck':
        return bool(row.get('recheckAllowed')) and (row.get('authCredentialChanged') or timestamp-previous >= config.get('interval',3600)*1000)
    if action != 'activity' or row.get('needsLogin') or not row.get('enabled'):
        return False
    start=int(datetime.datetime.fromtimestamp(timestamp/1000, timezone).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()*1000)
    return previous < start

