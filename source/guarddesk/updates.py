"""MIS-authorized releases, bounded jobs, per-component progress and downloads."""
import json
import re
import secrets
import time
from pathlib import Path
from .store import canonical,Store
from . import __version__
from .management import ManagementError
from . import update_packages as packages

STATES={'queued','waiting','downloading','verifying','applying','restarting','healthy','rolled_back','failed'}
FINISHED={'healthy','rolled_back','failed'}


def repository(store):
    from .endpoint_files import secure_directory
    root=packages.plain(store.path.resolve().parent/'update-packages')
    if not root.exists():secure_directory(root)
    return root


def add_release(store,source,staging,actor):
    manifest,temporary=packages.import_release(source,staging)
    return register_package(store,manifest,temporary,actor)


def register_package(store,manifest,temporary,actor,bundled=False):
    packages.validate_manifest(manifest)
    from . import release_scope
    import zipfile
    with zipfile.ZipFile(temporary) as archive:scope=release_scope.from_archive(archive,manifest)
    if scope['scope']=='server_only':raise ManagementError(409,'這是僅管理中心版本，不需要也不可派送到端點')
    with store.connect() as db:
        if db.execute('SELECT 1 FROM update_releases WHERE version=? AND id<>?',(manifest['version'],manifest['sha256'])).fetchone():raise ManagementError(409,'同一版本已有不同成品；請使用新的版本號')
        if db.execute('SELECT count(*) FROM update_releases').fetchone()[0]>=100 and not db.execute('SELECT 1 FROM update_releases WHERE id=?',(manifest['sha256'],)).fetchone():raise ManagementError(409,'發布保留數已達 100 版，請 MIS 歸檔後處理')
    private=packages.signer(store.path.resolve().parent)
    envelope=packages.sign(private,manifest);root=repository(store)
    target=packages.plain(root/(manifest['sha256']+'.zip'))
    if target.exists():
        if packages.file_hash(target)!=manifest['sha256']:raise ValueError('既有發布檔已損壞，保留現狀並交 MIS 處理')
        temporary.unlink()
    else:temporary.rename(target)
    with store.connect() as db:
        same=db.execute('SELECT id FROM update_releases WHERE version=? AND id<>?',(manifest['version'],manifest['sha256'])).fetchone()
        if same:raise ManagementError(409,'同一版本已有不同成品；請使用新的版本號')
        created=db.execute('INSERT OR IGNORE INTO update_releases VALUES (?,?,?,?,?)',(manifest['sha256'],manifest['version'],canonical(envelope),time.time(),actor)).rowcount
        db.execute('INSERT OR REPLACE INTO update_release_scope VALUES (?,?)',(manifest['sha256'],canonical(scope)))
        if created or not bundled:Store.event(db,'console','update.bundled_release_prepared' if bundled else 'update.release_imported','info' if bundled else 'warning',{'release_id':manifest['sha256'],'version':manifest['version'],'actor':actor,'signature':'organization_pinned_ed25519','authenticode_acceptance':'pending'})
    return {'id':manifest['sha256'],'version':manifest['version']}


def catalog(db,signals=None,bundle=None,params=None):
    releases=[dict(r) for r in db.execute('SELECT id,version,created,actor FROM update_releases ORDER BY created DESC LIMIT 100')]
    from . import release_scope
    for release in releases:release['deployment']=release_scope.stored(db,release['id'],release['version'])
    deployable=[r for r in releases if r['deployment']['scope']=='endpoint']
    latest=max(deployable,key=lambda r:packages.version(r['version']))['id'] if deployable else None
    from . import update_progress
    filters=update_progress.parameters(db,params or {},latest)
    progress=update_progress.page(db,filters)
    for value in progress['jobs']:
        value['components']={r['role']:dict(r) for r in db.execute('SELECT role,state,version,error,received FROM update_status WHERE job_id=?',(value['id'],))}
        value['delivery']=delivery(db,value,signals)
    presence=[dict(r) for r in db.execute('SELECT * FROM update_presence')]
    refresh=[dict(r) for r in db.execute('SELECT * FROM updater_refresh')]
    return {'releases':releases,'latest_release_id':latest,'server_release':release_scope.profile(__version__),'bundled_release':bundle,**progress,'presence':presence,'updater_refresh':refresh,'poll_seconds':30,'notification_protocol':1,'signature':'organization_pinned_ed25519','production_signing':'not_accepted'}


DIAGNOSTICS={
    'initialization_failed':'受保護更新器初始化失敗，請 MIS 檢查排程及受保護目錄',
    'recovery_failed':'更新交易復原未完成，請 MIS 檢查；不強制切換程式',
    'transport_failed':'更新器連線／驗證失敗，保留舊版並重試',
    'execution_failed':'更新執行未完成，保留程式與備份，請 MIS 檢查元件狀態',
    'update_key_missing':'端點缺少固定更新公鑰，需 MIS 完成一次更新元件安裝',
    'installation_marker_missing':'缺少既有安裝資訊，需 MIS 核對原端點身分',
}


def delivery(db,job,signals=None):
    did=job['device_id'];now=time.time()
    channels={r:bool(signals and signals.connected(did,r)) for r in ('native','main')}
    def result(code,message):return {'code':code,'message':message,'connected':channels}
    from .updater_maintenance import active
    if active(db,did) and db.execute('SELECT job_id FROM updater_refresh WHERE device_id=?',(did,)).fetchone()[0]==job['id']:return result('updater_refresh','正在背景更新獨立更新器並檢查健康；端點無需核准')
    if job['status']!='pending':return result('finished','工作已結束')
    if job['expires']<=now:return result('expired','工作已過期')
    if job['not_before']>now:return result('scheduled','尚未到排程時間')
    if db.execute("SELECT 1 FROM remote_sessions WHERE device_id=? AND status='active' AND expires>?",(did,now)).fetchone():return result('remote_assistance','等待遠端協助結束後更新')
    device=db.execute('SELECT last_seen FROM devices WHERE id=?',(did,)).fetchone()
    presence={p['role']:p for p in db.execute('SELECT * FROM update_presence WHERE device_id=?',(did,))}
    diagnostics={d['role']:d for d in db.execute('SELECT * FROM update_diagnostics WHERE device_id=?',(did,))}
    for role in ('native','main'):
        c=job['components'].get(role,{})
        if c.get('state') in FINISHED:continue
        if role=='main' and job['components'].get('native',{}).get('state')!='healthy':return result('native_first','等待原生元件更新完成')
        if role=='main':
            row=db.execute('SELECT body,received FROM extended_status WHERE device_id=?',(did,)).fetchone()
            machine=json.loads(row['body']).get('machine_agent',{}) if row else {}
            if row and now-row['received']<180 and machine.get('scope')=='machine' and machine.get('helpers')==0:
                return result('machine_agent_handoff','全機 Agent 尚未啟動使用者收集器；等待全機移交，通知連線不代表更新完成')
        diag=diagnostics.get(role);p=presence.get(role)
        if diag and now-diag['received']<180 and (not p or diag['received']>=p['received']):return result(diag['code'],DIAGNOSTICS.get(diag['code'],'更新元件需要 MIS 檢查'))
        if c.get('state') not in ('queued','waiting'):return result('updating','正在下載、驗證或切換；請查看各元件進度')
        busy=db.execute("SELECT count(*) FROM update_status s JOIN update_jobs j ON j.id=s.job_id WHERE s.role=? AND s.state IN ('downloading','verifying','applying','restarting') AND j.status='pending' AND s.received>?",(role,now-600)).fetchone()[0]
        if busy>=2:return result('batch_slot','等待同類元件的分批更新名額（最多兩台並行）')
        if channels[role]:return result('notified','通知通道已連線；符合條件即可檢查更新')
        if p and now-p['received']<90:return result('legacy_poll','更新器有回報；目前採輪詢，通常 30 秒內檢查。即時通知需升級更新器')
        online=bool(device and now-device['last_seen']<90) or any(now-p['received']<90 for p in presence.values())
        if not online:return result('offline','端點未連線；恢復連線後處理，無法強制更新離線電腦')
        if role=='native':return result('native_unreported','端點在線，但受保護更新器尚未回報；請 MIS 檢查 GuardDesk-AgentUpdater 排程')
        return result('main_unreported','一般 Agent 尚未回報；請確認使用者已登入及背景 Agent 已啟動')
    return result('updating','等待更新狀態確認')


def notify(db,user,body,signals):
    jid=body.get('job_id')
    if set(body)!={'job_id'} or not isinstance(jid,str) or not re.fullmatch('[0-9a-f]{32}',jid):raise ManagementError(400,'更新工作識別碼不正確')
    row=db.execute('SELECT * FROM update_jobs WHERE id=?',(jid,)).fetchone()
    if not row or row['status']!='pending' or row['expires']<=time.time():raise ManagementError(409,'只能通知尚未完成且未過期的更新工作')
    if db.execute("SELECT 1 FROM events WHERE device_id=? AND kind='update.notification_requested' AND received>?",(row['device_id'],time.time()-2)).fetchone():raise ManagementError(429,'剛剛已通知，請稍候查看狀態')
    connected=[r for r in ('native','main') if signals.connected(row['device_id'],r)]
    Store.event(db,row['device_id'],'update.notification_requested','info',{'actor':user['username'],'job_id':row['id'],'connected_roles':connected})
    return {'ok':True,'connected_roles':connected,'message':'已通知已連線的更新元件；離線或未就緒者仍需恢復連線／修復更新器。不略過原排程、驗簽或遠端協助等待。'}


def create_jobs(db,user,body):
    if body.get('confirm')!='deploy':raise ManagementError(400,'請確認派送更新')
    release=body.get('release_id')
    if not isinstance(release,str) or not re.fullmatch('[0-9a-f]{64}',release) or not db.execute('SELECT 1 FROM update_releases WHERE id=?',(release,)).fetchone():raise ManagementError(404,'找不到發布版本')
    from . import release_scope
    version=db.execute('SELECT version FROM update_releases WHERE id=?',(release,)).fetchone()[0]
    scope=release_scope.stored(db,release,version)
    if scope['scope']=='server_only':raise ManagementError(409,'此版本僅更新管理中心，不需要派送 Agent')
    ids=body.get('device_ids');group=body.get('group_id')
    if group:
        if ids or not isinstance(group,str) or not db.execute('SELECT 1 FROM endpoint_groups WHERE id=?',(group,)).fetchone():raise ManagementError(400,'更新群組不正確')
        ids=[r[0] for r in db.execute('WITH RECURSIVE descendants(id) AS (SELECT ? UNION ALL SELECT g.id FROM endpoint_groups g JOIN descendants p ON g.parent_id=p.id) SELECT d.id FROM devices d WHERE d.revoked=0 AND d.group_id IN (SELECT id FROM descendants)',(group,))]
    if not isinstance(ids,list) or not 1<=len(ids)<=100 or any(not isinstance(i,str) or not re.fullmatch('[0-9a-f]{24}',i) for i in ids) or len(set(ids))!=len(ids):raise ManagementError(400,'請選擇 1–100 台不同端點')
    attested=body.get('legacy_preflight_confirmed',False)
    if type(attested) is not bool:raise ManagementError(400,'舊更新器檢查確認不正確')
    if scope['required_updater']:
        legacy=[]
        for did in ids:
            presence=db.execute("SELECT broker_version,received FROM update_presence WHERE device_id=? AND role='native'",(did,)).fetchone()
            try:ready=presence and time.time()-presence['received']<90 and packages.version(presence['broker_version'])>=packages.version(scope['required_updater'])
            except ValueError:ready=False
            if not ready:legacy.append(did)
        if legacy and (not attested or len(ids)!=1 or group):raise ManagementError(409,'舊更新器／版本未知：先執行更新前檢查與必要的一次性修復，再明確確認單台試用；不可直接群組派送')
    when=body.get('not_before',time.time());downgrade=body.get('allow_downgrade',False)
    if type(when) not in (int,float) or not time.time()-60<=when<=time.time()+30*86400 or type(downgrade) is not bool:raise ManagementError(400,'排程時間或回復選項不正確')
    result=[]
    for did in ids:
        from .software import active as software_active
        if software_active(db,did):raise ManagementError(409,'端點有軟體安裝工作，請先完成或取消再更新 Agent')
        from .updater_maintenance import active
        if active(db,did):raise ManagementError(409,'端點正在維護更新器，完成後再建立更新工作')
        if not db.execute('SELECT 1 FROM devices WHERE id=? AND revoked=0',(did,)).fetchone():raise ManagementError(404,'找不到有效端點')
        if db.execute("SELECT 1 FROM endpoint_removals WHERE device_id=? AND status IN ('queued','running','failed')",(did,)).fetchone():raise ManagementError(409,'端點有移除工作，不派送更新')
        if db.execute("SELECT 1 FROM update_jobs WHERE device_id=? AND status='pending' AND expires>?",(did,time.time())).fetchone():raise ManagementError(409,'端點已有更新工作，請先完成或取消')
        jid=secrets.token_hex(16);now=time.time()
        db.execute('INSERT INTO update_jobs VALUES (?,?,?,?,?,?,?,?,?)',(jid,did,release,user['username'],now,when,when+7*86400,int(downgrade),'pending'))
        for role in ('native','main'):db.execute('INSERT INTO update_status VALUES (?,?,?,?,?,?)',(jid,role,'queued','','',0))
        Store.event(db,did,'update.scheduled','warning',{'actor':user['username'],'job_id':jid,'release_id':release,'not_before':when,'allow_downgrade':downgrade,'legacy_preflight_operator_attested':attested})
        result.append(jid)
    return {'job_ids':result}


def cancel(db,user,body):
    jid=body.get('job_id');row=db.execute('SELECT * FROM update_jobs WHERE id=?',(jid,)).fetchone()
    if not row:raise ManagementError(404,'找不到更新工作')
    from .updater_maintenance import active
    if active(db,row['device_id']):raise ManagementError(409,'更新器正在安全切換，請等待維護完成')
    if db.execute("SELECT 1 FROM update_status WHERE job_id=? AND state IN ('applying','restarting')",(jid,)).fetchone():raise ManagementError(409,'端點正在切換程式，請等待完成或回復，不強制中斷')
    db.execute("UPDATE update_jobs SET status='cancelled' WHERE id=? AND status='pending'",(jid,))
    Store.event(db,row['device_id'],'update.cancelled','warning',{'actor':user['username'],'job_id':jid})
    return {'ok':True}


def valid_job(db,device,jid):
    row=db.execute("SELECT * FROM update_jobs WHERE id=? AND device_id=? AND status='pending' AND expires>? AND not_before<=?",(jid,device['id'],time.time(),time.time())).fetchone()
    if not row:raise ManagementError(409,'更新工作已取消、過期或不屬於此端點')
    return row


def agent_route(store,db,device,path,body):
    role=body.get('role');current=body.get('version','')
    if role not in ('native','main') or not isinstance(current,str) or len(current)>30:raise ManagementError(400,'更新元件回報不正確')
    packages.version(current)
    broker=body.get('broker_version','')
    if not isinstance(broker,str) or len(broker)>30:raise ManagementError(400,'更新器版本不正確')
    if broker:packages.version(broker)
    if path.endswith('/diagnostic'):
        code=body.get('code')
        if set(body)!={'role','version','code'} or not isinstance(code,str) or code not in DIAGNOSTICS:raise ManagementError(400,'更新診斷代碼不正確')
        db.execute('INSERT OR REPLACE INTO update_diagnostics VALUES (?,?,?,?,?)',(device['id'],role,code,current,time.time()))
        return {'ok':True}
    db.execute('INSERT OR REPLACE INTO update_presence(device_id,role,version,received,broker_version) VALUES (?,?,?,?,?)',(device['id'],role,current,time.time(),broker))
    if path.endswith('/poll'):
        machine=db.execute('SELECT body FROM extended_status WHERE device_id=?',(device['id'],)).fetchone()
        scope=json.loads(machine[0]).get('machine_agent',{}) if machine else {}
        if role=='main' and scope.get('scope')=='machine' and body.get('machine_scope') is not True:
            # Native 0.4.64 owns the same protected code for all logons. An old
            # per-user updater must not race its migration or reinstall HKCU Run.
            return {'job':None,'waiting_for':'machine_agent_handoff'}
        from .custom_settings import action_leased
        if action_leased(db,device['id']):return {'job':None,'waiting_for':'custom_action'}
    if path.endswith('/status'):
        from .updater_maintenance import active
        if active(db,device['id']):raise ManagementError(409,'更新器維護中，暫停其他程式切換')
        existing=db.execute('SELECT s.state FROM update_status s JOIN update_jobs j ON j.id=s.job_id WHERE s.job_id=? AND s.role=? AND j.device_id=?',(body.get('job_id'),role,device['id'])).fetchone()
        if existing and existing['state'] in FINISHED and existing['state']==body.get('state'):return {'ok':True,'terminal':True}
        job=valid_job(db,device,body.get('job_id'));state=body.get('state');error=body.get('error','')
        if state not in STATES or not isinstance(error,str) or len(error)>300:raise ManagementError(400,'更新狀態不正確')
        old=db.execute('SELECT * FROM update_status WHERE job_id=? AND role=?',(job['id'],role)).fetchone()
        if old['state'] in FINISHED:return {'ok':True,'terminal':True}
        if state=='healthy':
            target=db.execute('SELECT version FROM update_releases WHERE id=?',(job['release_id'],)).fetchone()[0]
            if current!=target:raise ManagementError(409,'健康版本與目標版本不符')
        if role=='main' and state not in ('waiting','failed') and db.execute("SELECT state FROM update_status WHERE job_id=? AND role='native'",(job['id'],)).fetchone()[0]!='healthy':raise ManagementError(409,'等待受保護元件更新完成')
        db.execute('UPDATE update_status SET state=?,version=?,error=?,received=? WHERE job_id=? AND role=?',(state,current,error,time.time(),job['id'],role))
        states=[r[0] for r in db.execute('SELECT state FROM update_status WHERE job_id=?',(job['id'],))]
        status='completed' if all(s=='healthy' for s in states) else 'failed' if any(s in ('rolled_back','failed') for s in states) else 'pending'
        db.execute('UPDATE update_jobs SET status=? WHERE id=?',(status,job['id']))
        if old['state']!=state:Store.event(db,device['id'],'update.component_status','info' if state=='healthy' else 'warning',{'job_id':job['id'],'role':role,'state':state,'version':current,'error':error})
        return {'ok':True}
    from .updater_maintenance import active
    if active(db,device['id']):return {'job':None,'waiting_for':'updater_refresh'}
    if db.execute("SELECT 1 FROM endpoint_removals WHERE device_id=? AND status IN ('queued','running','failed')",(device['id'],)).fetchone():return {'job':None}
    if db.execute("SELECT 1 FROM remote_sessions WHERE device_id=? AND status='active' AND expires>?",(device['id'],time.time())).fetchone():return {'job':None,'waiting_for':'remote_assistance'}
    row=db.execute("SELECT * FROM update_jobs WHERE device_id=? AND status='pending' AND expires>? AND not_before<=? ORDER BY created LIMIT 1",(device['id'],time.time(),time.time())).fetchone()
    if not row:return {'job':None}
    state=db.execute('SELECT state FROM update_status WHERE job_id=? AND role=?',(row['id'],role)).fetchone()[0]
    if state in FINISHED:return {'job':None}
    if role=='native' and state in ('queued','waiting'):
        from . import release_scope
        release_version=db.execute('SELECT version FROM update_releases WHERE id=?',(row['release_id'],)).fetchone()[0]
        if release_scope.stored(db,row['release_id'],release_version)['scope']=='server_only':return {'job':None,'waiting_for':'server_only_release_not_required'}
    if role=='main' and db.execute("SELECT state FROM update_status WHERE job_id=? AND role='native'",(row['id'],)).fetchone()[0]!='healthy':return {'job':None,'waiting_for':'native'}
    # Two native downloads/switches at a time. Offline queued devices take no slot.
    if state in ('queued','waiting'):
        count=db.execute("SELECT count(*) FROM update_status s JOIN update_jobs j ON j.id=s.job_id WHERE s.role=? AND s.state IN ('downloading','verifying','applying','restarting') AND j.status='pending' AND s.received>?",(role,time.time()-600)).fetchone()[0]
        if count>=2:return {'job':None,'waiting_for':'batch_slot'}
        db.execute("UPDATE update_status SET state='downloading',received=? WHERE job_id=? AND role=?",(time.time(),row['id'],role))
    release=db.execute('SELECT envelope FROM update_releases WHERE id=?',(row['release_id'],)).fetchone()
    envelope=json.loads(release[0])
    payload={k:row[k] for k in ('id','device_id','release_id','created','not_before','expires','allow_downgrade')}
    payload['release']=envelope
    return {'job':packages.sign(packages.signer(store.path.resolve().parent),payload)}
