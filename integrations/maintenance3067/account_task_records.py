"""Read one account's durable records, without re-running maintenance requests."""
from maintenance_state import operation_cooldown
from ui_support import public_value

def account_task_records(connection, row, config, timestamp, decode):
    aid=row['id'];pc=config.get('providers',{}).get(row['provider'],{})
    records=[]
    for action,cfg in pc.items():
        if not isinstance(cfg,dict):continue
        history=[dict(r) for r in connection.execute("""select action,status,created,started,ended,message,not_before,origin
            from jobs where account=? and action=? and status not in ('queued','running')
            order by created desc,rowid desc limit 2""",(aid,action))]
        current=connection.execute("""select action,status,created,started,ended,message,not_before,origin
            from jobs where account=? and action=? and status in ('queued','running')
            order by case when status='running' then 0 else 1 end,created limit 1""",(aid,action)).fetchone()
        current=dict(current) if current else None
        due=(current.get('not_before') or current['created']) if current else 0
        reason='等待下个维护周期'
        invitation=None
        if action=='invitation':
            r=connection.execute('select status,data,updated,next_at from invitation_state where account=?',(aid,)).fetchone()
            if r:
                data=decode(r['data'])
                invitation={'status':r['status'],'updatedAt':r['updated'],'confirmedAt':data.get('confirmedAt',0),'source':data.get('source',''),'nextAt':r['next_at']}
                due=0 if r['status']=='bound' else r['next_at']
        if invitation and invitation['status']=='bound':reason='已确认绑定，永久跳过查询与绑定'
        elif current and current['status']=='running':reason='正在执行'
        elif config.get('paused') or cfg.get('paused'):reason='维护任务已暂停'
        elif row.get('maintenancePaused'):reason=row.get('pauseReason') or '原程序账户开关已关闭'
        elif not cfg.get('enabled') and not current:reason='此项自动维护未开启'
        elif action=='checkin' and row.get('signed'):reason='今日已确认签到，不再安排签到'
        elif action=='credential' and not row.get('credentialRenewable'):reason=row.get('credentialReason') or '未保存可续期材料'
        elif row.get('authCredentialChanged') and action in ('recheck','balance'):reason='新凭证已检测到，优先核验；可借用空闲共享槽位'
        elif row.get('needsLogin') and action not in ('credential','recheck'):reason='等待登录凭证核验恢复'
        elif operation_cooldown(row,action)>timestamp:
            due=max(due,operation_cooldown(row,action));reason='失败退避，等待本项冷却结束'
        elif action=='balance' and row.get('balanceDetail',{}).get('waitingForCheckin'):reason='已确认余额用完，等待下次签到成功后补查'
        elif due>timestamp:reason='尚未到计划执行时间'
        elif current:reason='已到期，等待调度名额；签到优先，空闲槽位共享'
        elif action=='recheck':
            due=row.get('authRecheckAt',0)
            reason='已满足核验条件，等待入队' if row.get('recheckAllowed') else '当前无需核验或未到复查时间'
        records.append({'action':action,'previous':history[1] if len(history)>1 else None,'last':history[0] if history else None,
                        'current':current,'nextAt':due,'reason':reason,'invitation':invitation})
    return public_value({'at':timestamp,'account':aid,'items':records})
