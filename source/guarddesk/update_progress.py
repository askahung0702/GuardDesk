"""Admin-only metadata paging and snapshot-scoped cancellation of unclaimed jobs.

No event history or payload reads. A waiting component may be a download retry;
bulk cancellation therefore requires BOTH roles still unclaimed (received=0).
The existing HTTP POST transaction takes BEGIN IMMEDIATE before any reads,
serializing the final eligibility check with an endpoint's first poll/claim.
"""
import math
import re
import time
from functools import lru_cache
from .management import ManagementError
from .store import Store
from .update_packages import version

LIMIT=50
MAX_CANCEL=1000
FILTERS={'all','not_updated','pending','waiting','running','completed','failed','cancelled','expired'}
ACTIVE="('downloading','verifying','applying','restarting')"
ACCOUNTS="CASE WHEN json_type(d.inventory,'$.user_accounts')='array' THEN json_extract(d.inventory,'$.user_accounts') ELSE '[]' END"


def waiting(alias='j'):
    return f"""{alias}.status='pending' AND {alias}.expires>:now
      AND EXISTS (SELECT 1 FROM update_status s WHERE s.job_id={alias}.id AND s.state IN ('queued','waiting'))
      AND NOT EXISTS (SELECT 1 FROM update_status s WHERE s.job_id={alias}.id AND s.state IN {ACTIVE})
      AND NOT EXISTS (SELECT 1 FROM updater_refresh u WHERE u.device_id={alias}.device_id AND u.state='active' AND u.expires>:now)"""


def cancellable(alias='j'):
    return waiting(alias)+f""" AND (SELECT count(*) FROM update_status s WHERE s.job_id={alias}.id AND s.role IN ('native','main'))=2
      AND NOT EXISTS (SELECT 1 FROM update_status s WHERE s.job_id={alias}.id AND (s.state NOT IN ('queued','waiting') OR s.received<>0))"""


def parameters(db,params,latest):
    if set(params)-{'q','state','release','group','page'} or any(len(v)!=1 for v in params.values()):raise ManagementError(400,'更新進度篩選欄位不正確')
    result={k:params.get(k,[default])[0] for k,default in (('q',''),('state','all'),('release',''),('group',''),('page','1'))}
    if not all(isinstance(v,str) for v in result.values()) or len(result['q'])>200 or result['state'] not in FILTERS:raise ManagementError(400,'更新進度篩選不正確')
    try:page=int(result['page'])
    except ValueError:raise ManagementError(400,'頁碼不正確')
    if not 1<=page<=1000000:raise ManagementError(400,'頁碼不正確')
    result['page']=page;result['q']=result['q'].strip()
    release=result['release']
    if release not in ('','latest') and not re.fullmatch('[0-9a-f]{64}',release):raise ManagementError(400,'目標版本不正確')
    result['release_id']=latest if release=='latest' or not release and result['state']=='not_updated' else release
    row=db.execute('SELECT version FROM update_releases WHERE id=?',(result['release_id'],)).fetchone() if result['release_id'] else None
    if result['release_id'] and not row:raise ManagementError(400,'找不到目標版本')
    result['target_version']=row[0] if row else None
    group=result['group']
    if group not in ('','unassigned') and not db.execute('SELECT 1 FROM endpoint_groups WHERE id=?',(group,)).fetchone():raise ManagementError(400,'找不到群組')
    return result


def conditions(f,now):
    clauses=[];args={'now':now};prefix=''
    if f['q']:
        clauses.append("(instr(lower(d.name||' '||d.department),lower(:q))>0 OR EXISTS (SELECT 1 FROM json_each("+ACCOUNTS+") a WHERE a.type='text' AND instr(lower(a.value),lower(:q))>0))");args['q']=f['q']
    if f['group']=='unassigned':clauses.append('d.group_id IS NULL')
    elif f['group']:
        prefix='WITH RECURSIVE selected_group(id) AS (SELECT :group_id UNION ALL SELECT g.id FROM endpoint_groups g JOIN selected_group p ON g.parent_id=p.id) '
        args['group_id']=f['group'];clauses.append('d.group_id IN (SELECT id FROM selected_group)')
    if f['state']!='not_updated':
        if f['release_id']:clauses.append('j.release_id=:release_id');args['release_id']=f['release_id']
        state=f['state']
        if state=='waiting':clauses.append('('+waiting()+')')
        elif state=='running':clauses.append(f"((j.status='pending' AND j.expires>:now AND EXISTS (SELECT 1 FROM update_status s WHERE s.job_id=j.id AND s.state IN {ACTIVE})) OR EXISTS (SELECT 1 FROM updater_refresh u WHERE u.job_id=j.id AND u.device_id=j.device_id AND u.state='active' AND u.expires>:now))")
        elif state=='pending':clauses.append("j.status='pending' AND j.expires>:now")
        elif state=='expired':clauses.append("j.status='pending' AND j.expires<=:now")
        elif state in ('completed','failed','cancelled'):clauses.append('j.status=:status');args['status']=state
    return prefix,clauses,args


def job_source(f,now):
    prefix,clauses,args=conditions(f,now)
    source=' FROM update_jobs j JOIN devices d ON d.id=j.device_id JOIN update_releases r ON r.id=j.release_id'
    where=' WHERE '+' AND '.join(clauses) if clauses else ' WHERE 1=1'
    return prefix,source,where,args


def page(db,f,now=None):
    now=time.time() if now is None else now
    if f['state']=='not_updated':return devices(db,f,now)
    prefix,source,where,args=job_source(f,now)
    total=db.execute(prefix+'SELECT count(*)'+source+where,args).fetchone()[0]
    available=db.execute(prefix+'SELECT count(*)'+source+where+' AND ('+cancellable()+')',args).fetchone()[0]
    pages=max(1,math.ceil(total/LIMIT));number=min(f['page'],pages)
    values={**args,'limit':LIMIT,'offset':(number-1)*LIMIT}
    rows=[dict(row) for row in db.execute(prefix+'SELECT j.*,d.name,r.version,('+cancellable()+') AS can_cancel_waiting'+source+where+' ORDER BY j.created DESC,j.id DESC LIMIT :limit OFFSET :offset',values)]
    return {'jobs':rows,'pending_devices':[],'progress':meta(f,total,number,pages,available,'jobs')}


def meta(f,total,number,pages,available,mode):
    return {'mode':mode,'total':total,'page':number,'pages':pages,'limit':LIMIT,'cancel_waiting_total':available,'max_cancel':MAX_CANCEL,'target_version':f['target_version'],'filters':{k:f[k] for k in ('q','state','release','group')}}


def at_least(actual,target):
    if not isinstance(actual,str) or not 1<=len(actual)<=30 or not isinstance(target,str) or not 1<=len(target)<=30:return 0
    return _at_least(actual,target)


@lru_cache(maxsize=1024)
def _at_least(actual,target):
    try:return int(version(actual)>=version(target))
    except (ValueError,TypeError):return 0


def devices(db,f,now):
    if not f['target_version']:return {'jobs':[],'pending_devices':[],'progress':meta(f,0,1,1,0,'devices')}
    db.create_function('gd_update_at_least',2,at_least,deterministic=True)
    prefix,clauses,args=conditions(f,now);args['target']=f['target_version']
    # Latest metadata observation wins; a stale updater report must not override
    # a newer main heartbeat/native worker version. Unknowns remain explicit.
    main="CASE WHEN m.received>=d.last_seen AND m.version<>'' THEN m.version ELSE COALESCE(NULLIF(json_extract(d.inventory,'$.agent_version'),''),m.version,'') END"
    native="CASE WHEN n.received>=COALESCE(u.received,0) AND n.version<>'' THEN n.version ELSE COALESCE(NULLIF(json_extract(u.body,'$.worker_version'),''),n.version,'') END"
    main=f"CASE WHEN length({main})<=30 THEN {main} ELSE '' END"
    native=f"CASE WHEN length({native})<=30 THEN {native} ELSE '' END"
    main_received="CASE WHEN m.received>=d.last_seen AND m.version<>'' THEN m.received WHEN NULLIF(json_extract(d.inventory,'$.agent_version'),'') IS NOT NULL THEN d.last_seen ELSE COALESCE(m.received,0) END"
    native_received="CASE WHEN n.received>=COALESCE(u.received,0) AND n.version<>'' THEN n.received WHEN NULLIF(json_extract(u.body,'$.worker_version'),'') IS NOT NULL THEN u.received ELSE COALESCE(n.received,0) END"
    source=' FROM devices d LEFT JOIN update_presence m ON m.device_id=d.id AND m.role=\'main\' LEFT JOIN update_presence n ON n.device_id=d.id AND n.role=\'native\' LEFT JOIN native_usb_status u ON u.device_id=d.id'
    clauses+=['d.revoked=0',f'(gd_update_at_least({main},:target)=0 OR gd_update_at_least({native},:target)=0)']
    where=' WHERE '+' AND '.join(clauses)
    total=db.execute(prefix+'SELECT count(*)'+source+where,args).fetchone()[0];pages=max(1,math.ceil(total/LIMIT));number=min(f['page'],pages)
    values={**args,'limit':LIMIT,'offset':(number-1)*LIMIT}
    accounts="(SELECT json_group_array(substr(value,1,200)) FROM (SELECT value FROM json_each("+ACCOUNTS+") WHERE type='text' LIMIT 32))"
    sql=prefix+f"SELECT d.id,d.name,d.department,d.group_id,d.last_seen,{accounts} AS accounts,{main} AS main_version,{native} AS native_version,{main_received} AS main_received,{native_received} AS native_received"+source+where+' ORDER BY d.name COLLATE NOCASE,d.id LIMIT :limit OFFSET :offset'
    rows=[dict(row) for row in db.execute(sql,values)]
    import json
    for row in rows:
        for key in ('main_version','native_version'):
            try:version(row[key])
            except (ValueError,TypeError):row[key]=''
        row['accounts']=json.loads(row['accounts']) if row['accounts'] else []
        row['accounts']=[a for a in row['accounts'][:32] if isinstance(a,str)] if isinstance(row['accounts'],list) else []
        job=db.execute('SELECT j.id,j.status,j.expires,r.version FROM update_jobs j JOIN update_releases r ON r.id=j.release_id WHERE j.device_id=? ORDER BY j.created DESC,j.id DESC LIMIT 1',(row['id'],)).fetchone()
        row['latest_job']=dict(job) if job else None
    return {'jobs':[],'pending_devices':rows,'progress':meta(f,total,number,pages,0,'devices')}


def preview(db,f):
    if f['state']=='not_updated':raise ManagementError(400,'請切換到更新工作紀錄後取消等待工作')
    prefix,source,where,args=job_source(f,time.time())
    where+=' AND ('+cancellable()+')'
    total=db.execute(prefix+'SELECT count(*)'+source+where,args).fetchone()[0]
    ids=[r[0] for r in db.execute(prefix+'SELECT j.id'+source+where+' ORDER BY j.created DESC,j.id DESC LIMIT :maximum',{**args,'maximum':MAX_CANCEL})]
    return {'job_ids':ids if total<=MAX_CANCEL else [],'total':total,'can_confirm':0<total<=MAX_CANCEL,'max_cancel':MAX_CANCEL}


def cancel_waiting(db,user,body):
    ids=body.get('job_ids')
    if set(body)!={'job_ids','confirm'} or body.get('confirm')!='cancel_waiting' or not isinstance(ids,list) or not 1<=len(ids)<=MAX_CANCEL or any(not isinstance(jid,str) or not re.fullmatch('[0-9a-f]{32}',jid) for jid in ids) or len(set(ids))!=len(ids):raise ManagementError(400,'請確認要取消的等待工作清單（最多 1,000 筆）')
    if not db.in_transaction:db.execute('BEGIN IMMEDIATE')
    now=time.time();cancelled=[]
    for jid in ids:
        row=db.execute('SELECT j.device_id FROM update_jobs j WHERE j.id=:id AND ('+cancellable()+')',{'id':jid,'now':now}).fetchone()
        if not row:continue
        changed=db.execute("UPDATE update_jobs SET status='cancelled' WHERE id=? AND status='pending'",(jid,)).rowcount
        if changed:
            Store.event(db,row['device_id'],'update.cancelled','warning',{'actor':user['username'],'job_id':jid,'reason':'bulk_unclaimed_waiting'})
            cancelled.append(jid)
    return {'ok':True,'job_ids':cancelled,'cancelled':len(cancelled),'skipped':len(ids)-len(cancelled)}
