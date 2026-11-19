"""Indexed latest-row lookups; preserve created/rowid tie-breaking."""
def latest_jobs(connection, per_action=False):
    keys='account,action' if per_action else 'account'
    match='j2.account=k.account'+(' and j2.action=k.action' if per_action else '')
    return connection.execute(f'''select j.* from (select distinct {keys} from jobs) k
        join jobs j on j.rowid=(select j2.rowid from jobs j2 where {match}
        order by j2.created desc,j2.rowid desc limit 1)''').fetchall()



VERIFICATION_INDEX = """create index if not exists jobs_verification_latest
    on jobs(account,coalesce(ended,created) desc)
    where status='ok' and action in ('balance','recheck')"""


def latest_verifications(connection):
    """One authenticated receipt per account, without sorting all receipt payloads."""
    return connection.execute("""select j.* from
        (select distinct account from jobs indexed by jobs_verification_latest where status='ok' and action in ('balance','recheck')) k
        join jobs j on j.rowid=(select j2.rowid from jobs j2 indexed by jobs_verification_latest where j2.account is k.account
            and j2.status='ok' and j2.action in ('balance','recheck')
            order by coalesce(j2.ended,j2.created) desc,j2.rowid desc limit 1)""").fetchall()
