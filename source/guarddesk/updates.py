"""MIS-authorized releases, bounded jobs, per-component progress and downloads."""
import json
import re
import secrets
import time
from pathlib import Path
from .store import canonical,Store
from . import __version__
from .management import ManagementError
from . import update_packages as packages, update_retention

STATES={'queued','waiting','downloading','verifying','applying','restarting','healthy','rolled_back','failed'}
FINISHED={'healthy','rolled_back','failed'}
SWITCHING={'applying','restarting'}
BUSY={'downloading','verifying',*SWITCHING}
SLOT_SECONDS=600
TRANSFER_SECONDS=1200


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
    private=packages.signer(store.path.resolve().parent)
    envelope=packages.sign(private,manifest);root=repository(store)
    target=packages.plain(root/(manifest['sha256']+'.zip'))
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        same=db.execute('SELECT id FROM update_releases WHERE version=? AND id<>?',(manifest['version'],manifest['sha256'])).fetchone()
        if same:raise ManagementError(409,'同一版本已有不同成品；請使用新的版本號')
        keep=update_retention.available(db,store)
        if len(keep)==update_retention.KEEP and packages.version(manifest['version'])<packages.version(keep[-1]['version']):
            raise ManagementError(409,'此套件早於目前最新五個可派送版本')
        published=next((r for r in update_retention.published(db) if r['id']==manifest['sha256']),None)
        if published is None and update_retention.count(db)>=100:
            raise ManagementError(409,'派送套件庫已達上限，請先處理未完成的舊版工作')
        if target.exists():
            if packages.file_hash(target)!=manifest['sha256']:raise ValueError('既有發布檔已損壞，保留現狀並交 MIS 處理')
            temporary.unlink()
        else:temporary.rename(target)
        created=db.execute('INSERT OR IGNORE INTO update_releases VALUES (?,?,?,?,?)',(manifest['sha256'],manifest['version'],canonical(envelope),time.time(),actor)).rowcount
        db.execute('INSERT OR REPLACE INTO update_release_scope VALUES (?,?)',(manifest['sha256'],canonical(scope)))
        restored=db.execute('DELETE FROM update_retired_packages WHERE release_id=?',(manifest['sha256'],)).rowcount
        if created or restored or not bundled:Store.event(db,'console','update.bundled_release_prepared' if bundled else 'update.release_imported','info' if bundled else 'warning',{'release_id':manifest['sha256'],'version':manifest['version'],'actor':actor,'signature':'organization_pinned_ed25519','authenticode_acceptance':'pending'})
    return {'id':manifest['sha256'],'version':manifest['version']}


def catalog(db,signals=None,bundle=None,params=None,store=None):
    releases=update_retention.available(db,store)
    history=[dict(r) for r in db.execute('SELECT id,version FROM update_releases ORDER BY created DESC,id LIMIT 1000')]
    latest=releases[0]['id'] if releases else None
    from . import release_scope
    from . import update_progress
    filters=update_progress.parameters(db,params or {},latest)
    progress=update_progress.page(db,filters)
    for value in progress['jobs']:
        value['components']={r['role']:dict(r) for r in db.execute('SELECT role,state,version,error,received FROM update_status WHERE job_id=?',(value['id'],))}
        value['delivery']=delivery(db,value,signals)
    presence=[dict(r) for r in db.execute('SELECT * FROM update_presence')]
    refresh=[dict(r) for r in db.execute('SELECT * FROM updater_refresh')]
    return {'releases':releases,'history_releases':history,'latest_release_id':latest,'server_release':release_scope.profile(__version__),'bundled_release':bundle,**progress,'presence':presence,'updater_refresh':refresh,'poll_seconds':30,'notification_protocol':1,'signature':'organization_pinned_ed25519','production_signing':'not_accepted'}


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
    if job['status'] not in ('pending','reserved'):return result('finished','工作已結束')
    if job['expires']<=now:
        if any(c.get('state') in SWITCHING for c in job['components'].values()):
            return result('awaiting_result','已開始切換，等候端點補報結果')
        return result('expired','工作已過期')
    if job['not_before']>now:return result('scheduled','尚未到排程時間')
    if db.execute("SELECT 1 FROM remote_sessions WHERE device_id=? AND status='active' AND expires>?",(did,now)).fetchone():return result('remote_assistance','等待遠端協助結束後更新')
    device=db.execute('SELECT last_seen FROM devices WHERE id=?',(did,)).fetchone()
    presence={p['role']:p for p in db.execute('SELECT * FROM update_presence WHERE device_id=?',(did,))}
    diagnostics={d['role']:d for d in db.execute('SELECT * FROM update_diagnostics WHERE device_id=?',(did,))}
    if job['status']=='reserved':
        from . import update_dispatch
        state=update_dispatch.admit(db,job,now,job_scope(db,job))
        if state=='work_conflict':return result(state,'等候端點的其他工作完成')
        if state=='needs_check':return result(state,'更新器版本過舊，需 MIS 核對單台')
        if state=='waiting':
            if not device or not 0<=now-device['last_seen']<90:return result('offline','已預約，等候端點上線')
            return result('native_unreported','已預約，等候獨立更新器版本回報')
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
        if c.get('state') in SWITCHING and now-c.get('received',0)>=90:
            return result('awaiting_result','端點已進入切換階段，等候進度或結果補報')
        if c.get('state') in ('downloading','verifying') and now-c.get('received',0)>=90:
            return result('retrying','等候端點重新連線及續傳')
        if c.get('state') not in ('queued','waiting'):return result('updating','正在下載、驗證或切換；請查看各元件進度')
        if c.get('state')=='waiting' and c.get('error'):return result('retrying',c['error'])
        busy=busy_slots(db,role,now)
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
    if not row or row['status'] not in ('pending','reserved') or row['expires']<=time.time():raise ManagementError(409,'只能通知尚未完成且未過期的更新工作')
    if db.execute("SELECT 1 FROM events WHERE device_id=? AND kind='update.notification_requested' AND received>?",(row['device_id'],time.time()-2)).fetchone():raise ManagementError(429,'剛剛已通知，請稍候查看狀態')
    connected=[r for r in ('native','main') if signals.connected(row['device_id'],r)]
    Store.event(db,row['device_id'],'update.notification_requested','info',{'actor':user['username'],'job_id':row['id'],'connected_roles':connected})
    return {'ok':True,'connected_roles':connected,'message':'已通知已連線的更新元件；離線或未就緒者仍需恢復連線／修復更新器。不略過原排程、驗簽或遠端協助等待。'}


def target_release(db, release, store=None):
    from . import release_scope
    if not isinstance(release,str) or not re.fullmatch('[0-9a-f]{64}',release):
        raise ManagementError(404,'找不到發布版本')
    row=db.execute('SELECT version FROM update_releases WHERE id=?',(release,)).fetchone()
    if not row:raise ManagementError(404,'找不到發布版本')
    if release_scope.stored(db,release,row['version'])['scope']=='server_only':
        raise ManagementError(409,'此版本僅更新管理中心，不需要派送 Agent')
    for item in update_retention.available(db,store):
        if item['id']==release:return item
    raise ManagementError(409,'此版本已退出派送選單，請重新選擇目標版本')


def schedule_options(body,now):
    when=body.get('not_before',now);downgrade=body.get('allow_downgrade',False)
    if type(when) not in (int,float) or not now-60<=when<=now+30*86400 or type(downgrade) is not bool:
        raise ManagementError(400,'排程時間或回復選項不正確')
    return when,downgrade


def record_job(db,did,release,user,now,when,downgrade,attested,status='pending'):
    jid=secrets.token_hex(16)
    db.execute('INSERT INTO update_jobs VALUES (?,?,?,?,?,?,?,?,?)',(jid,did,release,user['username'],now,when,when+7*86400,int(downgrade),status))
    for role in ('native','main'):db.execute('INSERT INTO update_status VALUES (?,?,?,?,?,?)',(jid,role,'queued','','',0))
    Store.event(db,did,'update.scheduled','warning',{'actor':user['username'],'job_id':jid,'release_id':release,
        'not_before':when,'allow_downgrade':downgrade,'legacy_preflight_operator_attested':attested,'dispatch_status':status})
    return jid


def create_jobs(db,user,body,store=None):
    from . import update_dispatch as dispatch
    if 'preview_id' in body:return dispatch.confirm(db,user,body,store)
    if body.get('confirm')!='deploy':raise ManagementError(400,'請確認派送更新')
    release=target_release(db,body.get('release_id'),store)
    ids=dispatch.select_ids(db,body)
    if 'all_endpoints' in body or len(ids)>100:
        raise ManagementError(400,'請先預覽批次派送')
    attested=body.get('legacy_preflight_confirmed',False)
    if type(attested) is not bool or attested and (len(ids)!=1 or 'device_ids' not in body):
        raise ManagementError(400,'舊更新器檢查確認不正確')
    now=time.time();when,downgrade=schedule_options(body,now)
    required=release['deployment']['required_updater']
    for did in ids:
        if not db.execute('SELECT 1 FROM devices WHERE id=? AND revoked=0',(did,)).fetchone():
            raise ManagementError(404,'找不到有效端點')
        if dispatch.broker_state(db,did,required,now)!='ready' and not attested:
            raise ManagementError(409,'更新器尚未就緒，請使用派送預覽或確認單台更新前檢查')
        conflict=dispatch.conflicts(db,did,now)
        if conflict:raise ManagementError(409,conflict)
    return {'job_ids':[record_job(db,did,release['id'],user,now,when,downgrade,attested) for did in ids]}


def cancel(db,user,body):
    jid=body.get('job_id');row=db.execute('SELECT * FROM update_jobs WHERE id=?',(jid,)).fetchone()
    if not row:raise ManagementError(404,'找不到更新工作')
    from .updater_maintenance import active
    if active(db,row['device_id']):raise ManagementError(409,'更新器正在安全切換，請等待維護完成')
    if db.execute("SELECT 1 FROM update_status WHERE job_id=? AND state IN ('applying','restarting')",(jid,)).fetchone():raise ManagementError(409,'端點正在切換程式，請等待完成或回復，不強制中斷')
    db.execute("UPDATE update_jobs SET status='cancelled' WHERE id=? AND status IN ('pending','reserved')",(jid,))
    Store.event(db,row['device_id'],'update.cancelled','warning',{'actor':user['username'],'job_id':jid})
    return {'ok':True}


def valid_job(db,device,jid):
    row=db.execute("SELECT * FROM update_jobs WHERE id=? AND device_id=? AND status='pending' AND expires>? AND not_before<=?",(jid,device['id'],time.time(),time.time())).fetchone()
    if not row:raise ManagementError(409,'更新工作已取消、過期或不屬於此端點')
    return row


def job_scope(db,job):
    from . import release_scope
    version=db.execute('SELECT version FROM update_releases WHERE id=?',(job['release_id'],)).fetchone()[0]
    return release_scope.stored(db,job['release_id'],version)


def switching(db,did,exclude=''):
    return db.execute("""SELECT 1 FROM update_jobs j JOIN update_status s ON s.job_id=j.id
        WHERE j.device_id=? AND j.id<>? AND j.status='pending'
        AND s.state IN ('applying','restarting') LIMIT 1""",(did,exclude)).fetchone() is not None


def work_blocked(db,did,now,job_id=''):
    from . import update_dispatch
    from .custom_settings import action_leased
    from .updater_maintenance import active
    if active(db,did):return 'updater_refresh'
    if db.execute("SELECT 1 FROM remote_sessions WHERE device_id=? AND status='active' AND expires>?",(did,now)).fetchone():
        return 'remote_assistance'
    if action_leased(db,did):return 'custom_action'
    if update_dispatch.activity_conflict(db,did):return 'work_conflict'
    if job_id and db.execute(
            "SELECT 1 FROM update_jobs j JOIN update_status s ON s.job_id=j.id WHERE j.device_id=? "
            "AND j.id<>? AND j.status='pending' AND (s.state IN ('applying','restarting') OR "
            "(j.expires>? AND s.state IN ('downloading','verifying'))) LIMIT 1",(did,job_id,now)).fetchone():
        return 'work_conflict'
    return ''


def busy_slots(db,role,now,exclude=''):
    return db.execute("SELECT count(*) FROM update_status s JOIN update_jobs j ON j.id=s.job_id "
                      "WHERE s.role=? AND s.job_id<>? AND j.status='pending' "
                      "AND ((s.state IN ('applying','restarting') AND s.received>?) OR "
                      "(j.expires>? AND s.state IN ('downloading','verifying') AND "
                      "(s.received>? OR EXISTS(SELECT 1 FROM update_downloads d "
                      "WHERE d.job_id=j.id AND d.role=s.role AND d.expires>?))))",
                      (role,exclude,now-SLOT_SECONDS,now,now-SLOT_SECONDS,now)).fetchone()[0]


def component(db,jid,role):
    return db.execute('SELECT * FROM update_status WHERE job_id=? AND role=?',(jid,role)).fetchone()


def begin_download(db,device,jid,role,range_header):
    now=time.time()
    job=valid_job(db,device,jid)
    if work_blocked(db,device['id'],now,jid):
        raise ManagementError(423,'端點有其他工作，暫停這次下載')
    native=component(db,jid,'native')
    if role is None:
        role='main' if native['state']=='healthy' else 'native'
    if role not in ('native','main') or role=='main' and native['state']!='healthy':
        raise ManagementError(409,'更新元件尚未取得下載資格')
    status=component(db,jid,role)
    if status['state'] not in BUSY:
        raise ManagementError(409,'請先領取端點更新工作')
    size=db.execute('SELECT envelope FROM update_releases WHERE id=?',(job['release_id'],)).fetchone()[0]
    size=json.loads(size)['payload']['bytes']
    offset=0
    if range_header is not None:
        match=re.fullmatch(r'bytes=(0|[1-9][0-9]{0,8})-',range_header)
        if not match or int(match[1])>=size:
            raise ManagementError(416,'更新續傳範圍不正確')
        offset=int(match[1])
    if db.execute('SELECT 1 FROM update_downloads WHERE job_id=? AND role=? AND expires>?',(jid,role,now)).fetchone():
        raise ManagementError(429,'此更新元件已有下載連線')
    active=db.execute('SELECT count(*) FROM update_downloads WHERE role=? AND expires>?',(role,now)).fetchone()[0]
    if active>=2 or busy_slots(db,role,now,jid)>=2:
        raise ManagementError(429,'等待同類元件的分批更新名額')
    lease=secrets.token_hex(16)
    db.execute('INSERT INTO update_downloads VALUES (?,?,?,?)',(lease,jid,role,now+TRANSFER_SECONDS+30))
    db.execute('UPDATE update_status SET received=? WHERE job_id=? AND role=?',(now,jid,role))
    return job['release_id'],size,offset,lease


def finish_download(db,lease,completed):
    row=db.execute('SELECT job_id,role FROM update_downloads WHERE id=?',(lease,)).fetchone()
    if not row:return
    db.execute('DELETE FROM update_downloads WHERE id=?',(lease,))
    if not completed:
        db.execute("UPDATE update_status SET state='waiting',error=?,received=? WHERE job_id=? AND role=? AND state='downloading'",
                   ('下載暫停，等候端點重試',time.time(),row['job_id'],row['role']))


def record_presence(db,did,role,current,broker,now):
    db.execute('INSERT INTO update_presence VALUES (?,?,?,?,?) ON CONFLICT(device_id,role) DO UPDATE SET '
               "version=excluded.version,received=excluded.received,broker_version=COALESCE(NULLIF(excluded.broker_version,''),update_presence.broker_version)",
               (did,role,current,now,broker))


def save_status(db,device,body,role,current,now):
    jid,state,error=body.get('job_id'),body.get('state'),body.get('error','')
    if (not isinstance(jid,str) or not re.fullmatch('[0-9a-f]{32}',jid)
            or not isinstance(state,str) or state not in STATES or not isinstance(error,str) or len(error)>300):
        raise ManagementError(400,'更新狀態不正確')
    before=db.execute('SELECT * FROM update_jobs WHERE id=? AND device_id=?',(jid,device['id'])).fetchone()
    if not before:raise ManagementError(409,'更新工作不存在或不屬於此端點')
    old=component(db,jid,role)
    if old['state'] in FINISHED:
        if old['state']==state and old['version']==current:return {'ok':True,'terminal':True}
        raise ManagementError(409,'更新工作已有不同的結果')
    closing=before['status']=='pending' and old['state'] in SWITCHING and state in FINISHED
    if state=='failed' and old['state'] not in SWITCHING and (before['status']=='cancelled' or before['expires']<=now):
        return {'ok':True,'terminal':True}
    job=before if closing else valid_job(db,device,jid)
    if state=='applying' or state in ('downloading','verifying') and old['state'] not in SWITCHING:
        if work_blocked(db,device['id'],now,jid):
            raise ManagementError(423,'端點有其他工作，暫停這次更新')
        if busy_slots(db,role,now,jid)>=2:
            raise ManagementError(429,'等待同類元件的分批更新名額')
    if state=='healthy':
        target=db.execute('SELECT version FROM update_releases WHERE id=?',(job['release_id'],)).fetchone()[0]
        if current!=target:raise ManagementError(409,'健康版本與目標版本不符')
    if role=='main' and state not in ('waiting','failed') and component(db,jid,'native')['state']!='healthy':
        raise ManagementError(409,'等待受保護元件更新完成')
    if old['state'] in SWITCHING and state in ('waiting','downloading','verifying'):
        return {'ok':True}  # A lost authorization reply must not reopen cancellation.
    if old['state']=='restarting' and state=='applying':
        raise ManagementError(409,'端點已開始切換，請先恢復原交易')
    record_presence(db,device['id'],role,current,'',now)
    db.execute('UPDATE update_status SET state=?,version=?,error=?,received=? WHERE job_id=? AND role=?',
               (state,current,error,now,jid,role))
    states=[r[0] for r in db.execute('SELECT state FROM update_status WHERE job_id=?',(jid,))]
    status='completed' if all(s=='healthy' for s in states) else 'failed' if any(s in ('rolled_back','failed') for s in states) else 'pending'
    db.execute('UPDATE update_jobs SET status=? WHERE id=?',(status,jid))
    return {'ok':True}


def agent_route(store,db,device,path,body):
    from . import update_dispatch
    role=body.get('role');current=body.get('version','')
    if role not in ('native','main') or not isinstance(current,str) or len(current)>30:raise ManagementError(400,'更新元件回報不正確')
    packages.version(current)
    broker=body.get('broker_version','')
    if not isinstance(broker,str) or len(broker)>30:raise ManagementError(400,'更新器版本不正確')
    if broker:packages.version(broker)
    now=time.time();did=device['id']
    if path.endswith('/diagnostic'):
        code=body.get('code')
        if set(body)!={'role','version','code'} or not isinstance(code,str) or code not in DIAGNOSTICS:raise ManagementError(400,'更新診斷代碼不正確')
        db.execute('INSERT OR REPLACE INTO update_diagnostics VALUES (?,?,?,?,?)',(did,role,code,current,now))
        return {'ok':True}
    if path.endswith('/status'):
        return save_status(db,device,body,role,current,now)
    record_presence(db,did,role,current,broker,now)
    if role=='native' and broker:
        update_dispatch.observe(db,did,broker,now)
    machine=db.execute('SELECT body FROM extended_status WHERE device_id=?',(did,)).fetchone()
    machine_scope=json.loads(machine[0]).get('machine_agent',{}) if machine else {}
    if role=='main' and machine_scope.get('scope')=='machine' and body.get('machine_scope') is not True:
        return {'job':None,'waiting_for':'machine_agent_handoff'}
    block=work_blocked(db,did,now)
    if block:return {'job':None,'waiting_for':block}
    row=db.execute("SELECT * FROM update_jobs WHERE device_id=? AND status IN ('pending','reserved') AND expires>? "
                   "AND not_before<=? ORDER BY (status='pending') DESC,created LIMIT 1",(did,now,now)).fetchone()
    if not row:return {'job':None}
    block=work_blocked(db,did,now,row['id'])
    if block:return {'job':None,'waiting_for':block}
    scope=job_scope(db,row)
    state=component(db,row['id'],role)
    if role=='native' and state['state'] in ('queued','waiting') and scope['scope']=='server_only':
        return {'job':None,'waiting_for':'server_only_release_not_required'}
    if row['status']=='reserved':
        if role!='native':return {'job':None,'waiting_for':'native'}
        ready=update_dispatch.admit(db,row,now,scope,reported=bool(broker))
        if ready!='ready':return {'job':None,'waiting_for':ready}
    if state['state'] in FINISHED:return {'job':None}
    if role=='main' and component(db,row['id'],'native')['state']!='healthy':return {'job':None,'waiting_for':'native'}
    if state['state']=='waiting' and state['error'] and now-state['received']<8+int(row['id'][-2:],16)%18:
        return {'job':None,'waiting_for':'retry_delay'}
    if state['state'] in ('queued','waiting') or state['state'] in ('downloading','verifying') and now-state['received']>=SLOT_SECONDS:
        if busy_slots(db,role,now,row['id'])>=2:return {'job':None,'waiting_for':'batch_slot'}
        db.execute("UPDATE update_status SET state='downloading',error='',received=? WHERE job_id=? AND role=?",(now,row['id'],role))
        if row['status']=='reserved':
            db.execute("UPDATE update_jobs SET status='pending' WHERE id=?",(row['id'],))
    # An existing authorization can be reconciled even when the other slots are busy.
    release=db.execute('SELECT envelope FROM update_releases WHERE id=?',(row['release_id'],)).fetchone()
    payload={k:row[k] for k in ('id','device_id','release_id','created','not_before','expires','allow_downgrade')}
    payload['release']=json.loads(release[0])
    if body.get('resume_protocol') is True:
        payload['transfer_role']=role
    return {'job':packages.sign(packages.signer(store.path.resolve().parent),payload)}
