"""Read-only operational metrics. Official routing state is not inferred from balance."""
import datetime,math
from collections import Counter
from ui_support import SUPPORTED, public_value, public_account, unavailable_reason, awaiting_signed_balance
from maintenance_policy import balance_interval, credential_due, balance_satisfied, balance_waits_for_checkin, balance_next_at
from maintenance_state import operation_cooldown
from auth_recheck import is_capacity_error
from job_queries import latest_jobs
from forwarding_status import usage_for
from availability_view import project_availability
from task_backlog import task_backlogs, checkin_providers, sign_hold, capacity_hold, MAX_SIGN_HOLD_MS, ordinary_during_sign
FAILED={'error','cooling','needs_login','interrupted','unconfirmed'}

def queue_order(job,accounts):
    row=accounts.get(job['account'],{});action=job['action']
    return (0 if action=='checkin' else 1 if job.get('origin') in ('post_checkin','post_relogin') else 2 if action=='credential' else 3 if action=='recheck' else 4 if action=='balance' else 5,
            (row.get('credentialExpiresAt') or 2**62) if action=='credential' else 0,
            job.get('not_before') or job['created'],job['created'],job['id'])

def dispatch_order(job, accounts, active_action, config=None, timestamp=None):
    action=job['action']
    # Credential/checkin capacity stays separate; balance providers share slots fairly.
    # Low-cap auxiliary work must not starve behind thousands of balance jobs.
    operation=queue_order(job,accounts)[0]
    busy=0;share=0
    if config and action in ('checkin','balance','recheck'):
        p=job['provider'];limit=config.get('globalBalanceConcurrency',16) if config.get('sharedMaintenanceSlots') else config['providers'][p]['balance'].get('concurrency',1)
        occupied=sum(active_action.get((p,a),0) for a in ('balance','checkin','recheck'))
        # Give an idle provider a turn before refilling busy providers. Weighted
        # rank alone ties at 1 for a single-slot provider and a nearly full large
        # provider, letting the latter's older backlog win indefinitely.
        # Sorting is once per batch: only the first candidate of each idle
        # provider gets this turn, before any provider receives a second slot.
        busy=int(occupied>0 or job.get('dispatch_rank',1)>1)
        share=(occupied+job.get('dispatch_rank',1))/max(1,limit)
    if timestamp is None:return (1,busy,share,operation,queue_order(job,accounts))
    p=job['provider'];first=job.get('dispatch_rank',1)==1
    tier=2
    if action=='credential':tier=-3
    elif action=='checkin':tier=-2
    elif job.get('origin') in ('post_checkin','post_relogin'):tier=-1
    elif accounts.get(job['account'],{}).get('authCredentialChanged') and action in ('balance','recheck'):tier=0
    elif action=='recheck':tier=1
    return (tier,busy,share,operation,queue_order(job,accounts))


def filters(query):
    value=lambda k:query.get(k,[''])[0]
    page=max(0,min(100000,int(value('page') or 0)));size=max(1,min(100,int(value('size') or 50)))
    return value,page,size

def queue_view(snapshot,config,db,timestamp,query,available_routes=None):
    value,page,size=filters(query);accounts={r['id']:r for r in snapshot['accounts']}
    with db() as c:
        jobs=[dict(x) for x in c.execute("select j.*,row_number() over(partition by provider,action,status order by priority desc,created,id) dispatch_rank from jobs j where provider in ('raccoon','loomy','codearts','wps-lingxi') and status in ('queued','running')")]
    # Counters and rows originate from the same query, before pagination/filtering.
    from queue_status import project_queue_status
    live = project_queue_status(jobs, timestamp)
    live['runningItems'] = [dict(id=j['id'], provider=j['provider'], action=j['action'],
        name=accounts.get(j['account'],{}).get('name',''), started=j.get('started'),
        elapsedSeconds=max(0,(timestamp-(j.get('started') or timestamp))//1000),
        phase='执行中，等待任务回执') for j in jobs if j['status']=='running']
    live['runningAt'] = timestamp
    active={j['account']:(j['provider'],j['action']) for j in jobs if j['status']=='running'}
    with db() as c:signing=checkin_providers(snapshot['accounts'],config,c,timestamp,datetime.timezone(datetime.timedelta(hours=8)),available_routes,active,jobs)
    jobs.sort(key=lambda j:(0 if j['status']=='running' else 1,queue_order(j,accounts)))
    counts=dict(Counter(j['status'] for j in jobs));rank=0;selected=[]
    for job in jobs:
        row=accounts.get(job['account'],{});cfg=config.get('providers',{}).get(job['provider'],{}).get(job['action'],{})
        job['credential_refresh']=bool(row.get('authCredentialChanged'))
        if job['status']=='queued':rank+=1
        job['position']=rank if job['status']=='queued' else None;job['name']=row.get('name',job['account']);job['waitSeconds']=max(0,(timestamp-job['created'])//1000)
        job['cooldownUntil']=operation_cooldown(row,job['action'])
        job['scheduledAt']=job.get('not_before') or job['created']
        job['remainingSeconds']=max(0,(job['scheduledAt']-timestamp+999)//1000)
        job['queueState']='running' if job['status']=='running' else 'scheduled' if job['remainingSeconds']>0 else 'ready'
        job['holdReason']=''
        if job['status']=='running':job['holdReason']='执行中（暂停不会中断已发出的请求）'
        elif config.get('paused',False):job['holdReason']='全局暂停'
        elif row.get('maintenancePaused'):job['holdReason']=row.get('pauseReason') or '账户维护暂停'
        elif cfg.get('paused'):job['holdReason']='此平台操作队列暂停'
        elif not cfg:job['holdReason']='尚未配置此平台操作'
        elif row.get('needsLogin') and job['action'] not in ('credential','recheck'):job['holdReason']='鉴权异常，等待凭证更新或核验'
        elif job['remainingSeconds']>0:job['holdReason']='等待计划时间；到点后按最早时间执行'
        elif job['cooldownUntil']>timestamp:job['holdReason']='当前操作冷却中'
        elif available_routes is not None and cfg.get('route','auto') not in available_routes:job['holdReason']='等待可用维护节点（不回退直连）'
        elif job['action']=='balance' and job.get('origin')=='auto' and balance_waits_for_checkin(row):job['holdReason']='已确认零积分，等待下次签到成功后查询'
        elif job['action']=='balance' and balance_satisfied(job,row,timestamp,cfg):job['holdReason']='已有新余额，执行前自动跳过'
        elif job['action']=='checkin' and job.get('attempt',0)>=0:
            clock=datetime.datetime.fromtimestamp(timestamp/1000,datetime.timezone(datetime.timedelta(hours=8))).strftime('%H:%M')
            if not cfg.get('start','00:00')<=clock<cfg.get('end','23:00'):job['holdReason']='签到窗口外'
        if job['status']=='queued' and not job['holdReason']:
            job['holdReason']='共享并发优先各平台签到；签后立即查余额，普通查询等待可执行签到完成' if sign_hold(job,signing,timestamp,row) else capacity_hold(job,active,config)
        if job['status']=='queued' and job['queueState']=='ready' and job['holdReason']:job['queueState']='blocked'
        if value('provider') and job['provider']!=value('provider'):continue
        if value('action') and job['action']!=value('action'):continue
        if value('status') and job['status']!=value('status') and job['queueState']!=value('status'):continue
        if value('search').lower() not in (job['name']+' '+job['account']).lower():continue
        selected.append(job)
    page=min(page,max(0,(len(selected)-1)//size))
    return {'live':live,'at':timestamp,'total':len(selected),'page':page,'size':size,'counts':counts,'items':public_value(selected[page*size:(page+1)*size]),'orderNote':'余额查询完成后预排下一轮，未到点显示倒计时；已到点按计划时间从早到晚执行。签到后补查、手动刷新优先，暂停和冷却仍生效。'}

def history_view(db,query):
    value,page,size=filters(query);clauses=["provider in ('raccoon','loomy','codearts','wps-lingxi')"];params=[]
    for k in ['provider','action','status']:
        if value(k):clauses.append(k+'=?');params.append(value(k))
    where=' where '+' and '.join(clauses) if clauses else ''
    with db() as c:
        total=c.execute('select count(*) from jobs'+where,params).fetchone()[0]
        page=min(page,max(0,(total-1)//size))
        rows=[dict(x) for x in c.execute('select * from jobs'+where+' order by created desc,rowid desc limit ? offset ?',(*params,size,page*size))]
    return {'items':public_value(rows),'total':total,'page':page,'size':size}

def enrich(snapshot,config,db,timestamp,tz,routing=None):
    routing=routing or {'at':0,'entries':{},'error':'尚未读取官方调度'}
    day=datetime.datetime.fromtimestamp(timestamp/1000,tz).replace(hour=0,minute=0,second=0,microsecond=0);start=int(day.timestamp()*1000)
    with db() as c:
        stats=[dict(x) for x in c.execute('select provider,action,status,count(*) attempts,count(distinct account) accounts from jobs where created>=? group by provider,action,status',(start,))]
        unique=[dict(x) for x in c.execute('select provider,action,count(distinct account) accounts from jobs where created>=? group by provider,action',(start,))]
        attempts={x[0]:x[1] for x in c.execute("select account,count(*) from jobs where action='checkin' and attempt>=0 and created>=? and status not in ('cancelled','skipped') group by account",(start,))}
        latest={(x['account'],x['action']):dict(x) for x in latest_jobs(c,per_action=True)}
        pending=[dict(x) for x in c.execute("select provider,action,status,count(*) attempts from jobs where provider in ('raccoon','loomy','codearts','wps-lingxi') and status in ('queued','running') group by provider,action,status")]
        queue_timing=[dict(x) for x in c.execute("select provider,action,case when status='running' then 'running' when not_before>? then 'scheduled' else 'ready' end as state,count(*) as total from jobs where status in ('queued','running') group by provider,action,state",(timestamp,))]
        rates=[dict(x) for x in c.execute("select provider,action,count(*) completed,sum(status='ok') succeeded,round(avg((ended-started)/1000.0),2) meanSeconds from jobs where ended>=? and started is not null and status in ('ok','error','cooling','needs_login','unconfirmed') group by provider,action",(timestamp-600000,))]
        invitation_states = {r[0]:{'status':r[1],'nextAt':r[2]} for r in c.execute('select account,status,next_at from invitation_state')} if c.execute("select 1 from sqlite_master where type='table' and name='invitation_state'").fetchone() else {}
    fresh_routing=bool(routing.get('at') and timestamp-routing['at']<=120000 and not routing.get('error'))
    rows=[]
    for original in snapshot['accounts']:
        r={'balance':None,'lastSuccess':0,'lastAttempt':0,'unlimited':False,'enabled':False,'needsLogin':False,'signed':False,'signedAt':0,'supported':False,'cooldownUntil':0,**public_account(original)}
        r['supported']=original.get('supported',r['provider'] in SUPPORTED)
        r['maintenancePaused']=original.get('maintenancePaused') is True
        r['pauseReason']=r.get('pauseReason','') if r['maintenancePaused'] else ''
        r['routingDisabledReason']=r.get('routingDisabledReason','')
        r['home']=r.get('home') or ('miraihub' if r['provider']=='wps-lingxi' else 'agent2api' if r['provider'] in SUPPORTED else '')
        r['syncStatus']=r.get('syncStatus') if r.get('syncStatus') in ('synced','pending','error','not_supported') else 'unknown'
        r['syncAt']=r.get('syncAt',0);r['syncError']=r.get('syncError','')
        if r['signedAt']:r['signed']=bool(r['signed'] and start<=r['signedAt']<start+86400000)
        local_error=r.get('error','')
        r['capacityRetry']=is_capacity_error(local_error) or (r.get('jobStatus')=='queued' and '本地余额容量不足' in r.get('jobMessage',''))
        r['maintenanceMessage']=local_error if is_capacity_error(local_error) else ''
        if is_capacity_error(local_error):r['error']=''
        balance=r['balance'];known=bool(r['lastSuccess'] and isinstance(balance,(int,float)) and math.isfinite(balance))
        r['balanceKind']='unlimited' if r['unlimited'] else 'unknown' if not known else 'positive' if balance>0 else 'zero' if balance==0 else 'negative'
        cfgp=config.get('providers',{}).get(r['provider'],{});cp=cfgp.get('checkin',{});bp={'interval':3600,**cfgp.get('balance',{})};cred=cfgp.get('credential',{})
        j=latest.get((r['id'],'checkin'),{});b=latest.get((r['id'],'balance'),{});cr=latest.get((r['id'],'credential'),{})
        count=attempts.get(r['id'],0);maximum=cp.get('maxAttempts',3);next_sign=0
        sign_cd=operation_cooldown(r,'checkin');balance_cd=operation_cooldown(r,'balance')
        if r['signed']:sign='signed'
        elif not r['supported']:sign='unsupported'
        elif r['needsLogin']:sign='needs_login'
        elif j.get('status') in ('queued','running'):sign=j['status']
        elif not cp:sign='not_configured'
        elif not cp.get('enabled'):sign='disabled'
        elif count>=maximum:sign='exhausted'
        else:
            prev=j.get('created',0);next_sign=max(timestamp,sign_cd,prev+cp.get('retryInterval',1800)*1000 if prev>=start else 0)
            sh,sm=map(int,cp.get('start','00:00').split(':'));eh,em=map(int,cp.get('end','23:00').split(':'))
            ws=int(day.replace(hour=sh,minute=sm).timestamp()*1000);we=int(day.replace(hour=eh,minute=em).timestamp()*1000)
            if next_sign>=we:next_sign=max(next_sign,ws+86400000);sign='outside_window'
            elif next_sign<ws:next_sign=ws;sign='outside_window'
            else:sign='retry_wait' if next_sign>timestamp else 'eligible'
        if not r['signed'] and not r['needsLogin'] and r['supported'] and (r['maintenancePaused'] or config.get('paused',False) or cp.get('paused')) and j.get('status')!='running':sign='paused'
        interval=balance_interval(r,bp);due=balance_next_at(r,b.get('ended',0),timestamp,bp)
        if b.get('status')=='queued' and b.get('not_before'):due=b['not_before']
        if r.get('signedAt',0)>r['lastSuccess']:due=timestamp
        waiting_sign=balance_waits_for_checkin(r) and not (b.get('origin')=='post_checkin' and b.get('required_after',0)>r['lastSuccess'] and b.get('status') in ('queued','running'))
        balance_state='awaiting_checkin' if waiting_sign else 'waiting' if due>timestamp else 'due'
        if balance_cd>timestamp:balance_state='cooling'
        if not bp.get('enabled') and not waiting_sign:balance_state='disabled'
        if not cfgp.get('balance') and not waiting_sign:balance_state='not_configured'
        if r['needsLogin']:balance_state='needs_login'
        if b.get('status')=='running' or (b.get('status')=='queued' and not waiting_sign):balance_state=b['status']
        if balance_state=='queued' and b.get('not_before',0)>timestamp:balance_state='scheduled'
        if r['maintenancePaused'] or config.get('paused',False) or bp.get('paused'):
            if balance_state!='running':balance_state='paused'
        last_at=j.get('ended') or j.get('created',0)
        failed_today=not r['signed'] and start<=last_at<start+86400000 and j.get('status') in FAILED
        category='completed' if r['signed'] else 'failed' if failed_today else 'disabled' if not r['enabled'] else 'unsupported' if not r['supported'] else 'needs_login' if r['needsLogin'] else 'waiting'
        r['checkinDetail']={'todayCategory':category,'lastAt':last_at,'lastMessageIsToday':bool(start<=last_at<start+86400000),'state':sign,'cooldownUntil':sign_cd,'attempts':count,'maxAttempts':maximum,'nextEligibleAt':next_sign,'lastStatus':j.get('status',''),'lastMessage':j.get('message',''),'failedToday':bool(failed_today)}
        r['balanceDetail']={'state':balance_state,'cooldownUntil':balance_cd,'status':b.get('status',''),'message':b.get('message',''),'nextEligibleAt':None if waiting_sign else max(due,balance_cd),'waitingForCheckin':waiting_sign,'dueAt':None if waiting_sign else due,'interval':interval,'lastSuccess':r['lastSuccess'],'origin':b.get('origin',''),'jobId':b.get('id'),'fresh':known and timestamp-r['lastSuccess']<=interval*1000,'due':not waiting_sign and due<=timestamp and not config.get('paused',False) and not r['maintenancePaused'] and not r['needsLogin'] and balance_cd<=timestamp and bp.get('enabled',False) and not bp.get('paused',False) and balance_state not in ('queued','running')}
        route=routing.get('entries',{}).get(r['id'],{});r['routing']={'state':route.get('state','absent') if fresh_routing else 'unknown','reason':route.get('reason','未进入官方调度队列') if fresh_routing else routing.get('error') or '调度快照已过期','at':routing.get('at',0)}
        if r['home']=='miraihub' and not route:r['routing']={'state':'unknown','reason':'MiraiHub 调度状态尚未提供','at':0}
        if r['home']=='miraihub' and route.get('at'):
            fresh=timestamp-route['at']<=(30000 if 'usageAt' in route else 120000)
            r['routing']={'state':route.get('state','unknown') if fresh else 'unknown','reason':route.get('reason','') if fresh else '3066账号快照已过期','at':route['at']}
        if r['home']=='miraihub' and r['enabled'] and r['routing']['state'] in ('usable','concurrency','unknown'):
            verified_at=r.get('verifiedBalanceAt',0)
            verified=bool(verified_at and 0<=timestamp-verified_at<=7200000 and r.get('verificationState')=='ok')
            if r.get('needsLogin') or r.get('verificationState')=='needs_login':
                r['routing'].update(state='auth_failed',reason='官方核验登录态失效')
            elif not verified:
                expired=bool(verified_at and r.get('verificationState')=='ok')
                r['verificationDetail']='expired_verified' if expired else 'credential_changed' if r.get('verificationAt') else 'never_verified'
                r['routing'].update(state='unverified',reason='已核验余额超过2小时，等待重新查询' if expired else '当前凭证尚未完成余额核验' if r.get('verificationAt') else '从未完成官方余额核验')
            elif r['balanceKind']=='zero':
                r['routing'].update(state='limiter',reason='官方已确认零余额')
        r['routing']['reasonKey']=route.get('reasonKey','')
        r['routing']['recovery']=route.get('recovery',[])
        r['routing']['inFlight']=usage_for(route,routing.get('usage',{}),r['id'],timestamp,home=r['home'])
        r['routing']['inUse']=None if r['routing']['inFlight'] is None else r['routing']['inFlight']>0
        r['routing']['usageAt']=route.get('usageAt',0) if r['home']=='miraihub' else routing.get('usage',{}).get('at',0)
        project_availability(r)
        r['unavailableReason']=unavailable_reason(r)
        r['credentialDetail']={'cooldownUntil':operation_cooldown(r,'credential'),'status':cr.get('status',''),'message':cr.get('message',''),'due':credential_due(r,cr.get('created',0),timestamp,cred),'renewable':r.get('credentialRenewable',False),'expiresAt':r.get('credentialExpiresAt',0),'reason':r.get('credentialReason','未知')}
        rows.append(r)
    platforms={}
    for p in sorted(SUPPORTED | {r['provider'] for r in rows}):
        rr=[r for r in rows if r['provider']==p];finite=[r for r in rr if r['balanceKind'] not in ('unknown','unlimited')];usable=[r for r in rr if r['routing']['state'] in ('usable','concurrency')]
        periodic=[r for r in rr if not r['maintenancePaused'] and not r['needsLogin'] and not r['balanceDetail']['waitingForCheckin'] and config.get('providers',{}).get(p,{}).get('balance',{}).get('enabled')]
        sleeping=[r for r in rr if r['balanceDetail']['state']=='awaiting_checkin']
        categories=dict(Counter(r['checkinDetail']['todayCategory'] for r in rr))
        route_known=(fresh_routing or all(r['home']=='miraihub' for r in rr)) and all(r['routing']['state'] not in ('unknown','candidate') for r in rr)
        if p=='wps-lingxi':route_known=route_known and all(r['routing']['inFlight'] is not None for r in rr)
        platforms[p]={'configured':p in config.get('providers',{}),'today':{k:categories.get(k,0) for k in ('completed','failed','waiting','needs_login','unsupported','disabled')},'maintenancePaused':sum(r['maintenancePaused'] for r in rr),'routingDisabled':sum(not r['enabled'] for r in rr),'zeroBalanceSkipped':sum(r['balanceDetail']['waitingForCheckin'] for r in rr),'sync':dict(Counter(r['syncStatus'] for r in rr)),'periodicEligible':len(periodic),'periodicFresh':sum(r['balanceDetail']['fresh'] for r in periodic),'zeroWaitingSigned':sum(r['signed'] for r in sleeping),'zeroWaitingUnsigned':sum(not r['signed'] for r in sleeping),'authRecheck':sum(r.get('authRecheck',False) for r in rr),'authRecovered':sum(r.get('authRecovered',False) for r in rr),'operationCooling':{a:sum(operation_cooldown(r,a)>timestamp for r in rr) for a in ['balance','checkin','credential']},'total':len(rr),'enabled':sum(r['enabled'] for r in rr),'signed':sum(r['signed'] for r in rr),'unsigned':sum(not r['signed'] for r in rr),'balance':dict(Counter(r['balanceKind'] for r in rr)),'checkin':dict(Counter(r['checkinDetail']['state'] for r in rr)),'balanceStates':dict(Counter(r['balanceDetail']['state'] for r in rr)),'positivePoints':sum(max(0,r['balance']) for r in finite),'routable':len(usable) if route_known else None,'ready':sum(r['routing']['state']=='usable' for r in rr) if route_known else None,'occupied':sum(r['routing']['state']=='concurrency' for r in rr) if route_known else None,'routablePoints':sum(max(0,r['balance']) for r in usable if r['balanceKind'] not in ('unknown','unlimited')) if route_known else None,'routableUnknown':sum(r['balanceKind']=='unknown' for r in usable),'routableUnlimited':sum(r['unlimited'] for r in usable),'routingStates':dict(Counter(r['routing']['state'] for r in rr)),'fresh':sum(r['balanceDetail']['fresh'] for r in rr),'due':sum(r['balanceDetail']['due'] for r in rr),'stale':sum(r['lastSuccess']>0 and not r['balanceDetail']['fresh'] for r in rr),'cooling':sum(r['cooldownUntil']>timestamp for r in rr),'needsLogin':sum(r['enabled'] and r['needsLogin'] for r in rr),'renewable':sum(r.get('credentialRenewable',False) for r in rr),'failedUnfinished':sum(r['checkinDetail']['failedToday'] for r in rr)}
    for p,x in platforms.items():
        rr=[r for r in rows if r['provider']==p]
        x['authStates']=dict(Counter(r.get('authStatus','unknown') for r in rr if r['enabled']))
        x['disabledAuthHistory']=sum(not r['enabled'] and r['needsLogin'] for r in rr)
        x['disabledSources']=dict(Counter(r.get('pauseOrigin','source_disabled_unknown') for r in rr if not r['enabled']))
        if p=='wps-lingxi':x['verification']={'verified':sum(r['enabled'] and r.get('verificationState')=='ok' and r.get('verifiedBalanceAt',0)>0 and 0<=timestamp-r['verifiedBalanceAt']<=7200000 for r in rr),'failed':sum(r['enabled'] and (r['needsLogin'] or r.get('verificationState')=='needs_login') for r in rr),'unverified':sum(r['routing']['state']=='unverified' for r in rr),'disabled':sum(not r['enabled'] for r in rr)}
        x['capacityRetry']=sum(r.get('capacityRetry',False) for r in rr)
        x['authRecoveredScope']='current_state'
        x['unavailable']=x['total']-x['routable'] if x['routable'] is not None else None
        x['unavailableBreakdown']=dict(Counter(reason for r in rr if (reason:=unavailable_reason(r)))) if x['unavailable'] is not None else None
        x['signedBalanceBlocked']=sum(awaiting_signed_balance(r) for r in rr) if x['unavailable'] is not None else None
        x['inUse']=sum(r['routing']['inUse'] is True for r in rr) if all(r['routing']['inUse'] is not None for r in rr) else None
        route_known=x['routable'] is not None
        usage_known=all(r['routing']['inUse'] is not None for r in rr)
        x['ready']=sum(r['routing']['ready'] is True for r in rr) if route_known and usage_known else None
        x['occupied']=sum(r['routing']['availableInUse'] is True for r in rr) if route_known and usage_known else None
        x['unavailableInUse']=sum(r['routing']['inUse'] is True and r['routing']['state'] not in ('usable','concurrency') for r in rr) if route_known and usage_known else None
        x['candidates']=sum(r['routing']['state']=='candidate' for r in rr) if p=='wps-lingxi' and rr and all(r['routing']['state']!='unknown' for r in rr) else None
        x['postCheckinBalancePending']=sum(r['signed'] and r['signedAt']>r['lastSuccess'] and not r['maintenancePaused'] and not r['needsLogin'] for r in rr)
        x['queue']={s:sum(j['total'] for j in queue_timing if j['provider']==p and j['state']==s) for s in ('running','ready','scheduled')}
    result=public_value(snapshot);result['accounts']=rows
    result['summary']={**result.get('summary',{}),'total':len(rows),'signedToday':sum(r['signed'] for r in rows),'needsLogin':sum(r['enabled'] and r['needsLogin'] for r in rows),'maintenancePaused':sum(r['maintenancePaused'] for r in rows),'routingDisabled':sum(not r['enabled'] for r in rows),'zeroBalanceSkipped':sum(r['balanceDetail']['waitingForCheckin'] for r in rows)}
    result['dashboard']={'taskBacklog':task_backlogs(rows,config,latest,invitation_states,timestamp,tz),'backlogAt':timestamp,'date':day.strftime('%Y-%m-%d'),'timezone':'Asia/Shanghai','platforms':platforms,'todayAttempts':stats,'todayUnique':unique,'pending':pending,'queueTiming':queue_timing,'throughput10m':rates,'routing':{k:v for k,v in routing.items() if k not in ('entries','usage')},'routingFresh':fresh_routing,'balanceNote':'积分为最近成功查询的记录，不是实时扣费余额；不同平台不合计。','retryNote':'下一轮按上次完成时间排期；到点后按最早时间执行。','recordLimit':150}
    return public_value(result)

