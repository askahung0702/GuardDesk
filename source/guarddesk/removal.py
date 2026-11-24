"""Bounded per-device removal jobs. No arbitrary shell or file-delete commands."""
import json
import secrets
import time
import re
from .management import ManagementError
from .store import Store

TERMINAL=('completed','expired','closed')


def latest(db,device_id):
    row=db.execute('SELECT * FROM endpoint_removals WHERE device_id=? ORDER BY created DESC LIMIT 1',(device_id,)).fetchone()
    if not row:return None
    result=dict(row)
    from . import removal_full
    full=removal_full.get(db,result['id'])
    if full:
        cleanup=removal_full.public(full)
        cleanup['can_close_audit_conflict']=bool(
            result['status']=='failed' and result['main']=='pending' and result['native']=='failed'
            and full['phase']=='review_required' and full['token_hash'] and not full['authorization_issued'] and not full['keep_process_audit']
            and full['error_code'] in ('PROCESS_AUDIT_CONFLICT','PREPARE_OR_RESTORE_FAILED','PREPARATION_FAILED'))
        result.update(mode=removal_full.MODE,cleanup=cleanup)
    if result['status']=='queued' and result['expires']<time.time():
        result['status']='expired'
    return result


def request(db,user,body):
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    from . import removal_full
    full=body.get('mode')==removal_full.MODE
    keep_audit=body.get('keep_process_audit',False)
    if type(keep_audit) is not bool or (keep_audit and not full):
        raise ManagementError(400,'保留程序稽核僅適用於完整移除')
    if body.get('mode') not in (None,'retain_files',removal_full.MODE):raise ManagementError(400,'移除模式不正確')
    if full and body.get('acknowledge_no_backup') is not True:raise ManagementError(400,'請確認永久清除所有本機 Agent 身分、設定與未送出資料；不做完整備份')
    did=body.get('device_id')
    if not isinstance(did,str) or not re.fullmatch('[0-9a-f]{24}',did):raise ManagementError(400,'端點識別碼不正確')
    device=db.execute('SELECT * FROM devices WHERE id=? AND revoked=0',(did,)).fetchone()
    if not device:raise ManagementError(404,'找不到有效端點')
    from .software import active as software_active
    if software_active(db,did):raise ManagementError(409,'端點有軟體安裝工作，請先完成或取消；不在安裝中移除 Agent')
    from .updater_maintenance import active
    if active(db,did):raise ManagementError(409,'端點正在維護更新器，完成後再解除安裝')
    from .custom_settings import action_leased
    if action_leased(db,did):raise ManagementError(409,'端點正在執行自訂動作，完成後再解除安裝')
    from .updates import switching
    if switching(db,did) or db.execute("SELECT 1 FROM update_jobs WHERE device_id=? AND status='pending' AND expires>?",(did,time.time())).fetchone():raise ManagementError(409,'端點有更新工作，請先完成或取消更新再移除')
    if body.get('confirm_name')!=device['name']:raise ManagementError(400,'請輸入完整端點名稱確認')
    reason=body.get('reason')
    if not isinstance(reason,str) or not 1<=len(reason.strip())<=300:raise ManagementError(400,'請填寫 1–300 字移除原因')
    previous=latest(db,did)
    if previous and previous['status']=='completed':raise ManagementError(409,'此端點已完成移除；重新安裝請使用新註冊')
    if previous and previous['status'] not in TERMINAL:raise ManagementError(409,'此端點已有移除工作，請查看狀態')
    inventory=json.loads(device['inventory'])
    native=db.execute('SELECT body FROM native_usb_status WHERE device_id=?',(did,)).fetchone()
    native_report=json.loads(native[0]) if native else {}
    version=native_report.get('worker_version','')
    if keep_audit and native_report.get('removal_keep_process_audit') is not True:
        raise ManagementError(409,'請先更新端點的管理員元件，待其回報支援保留程序稽核後再建立工作')
    try:supported=tuple(int(x) for x in version.split('.'))>=(0,4,4)
    except ValueError:supported=False
    if 'remote_uninstall_v1' not in inventory.get('capabilities',[]) or not supported:raise ManagementError(409,'請先將一般 Agent 與管理員背景元件更新到 0.4.4 以上')
    if full and (removal_full.CAPABILITY not in inventory.get('capabilities',[]) or not version or tuple(int(x) for x in version.split('.'))<(0,4,97)):
        raise ManagementError(409,'此端點尚不支援完整檔案移除；請先更新配套 Agent，或使用通用移除包')
    now=time.time();jid=secrets.token_hex(16)
    db.execute('INSERT INTO endpoint_removals VALUES (?,?,?,?,?,?,?,?,?,?)',(jid,did,user['username'],reason.strip(),now,now+86400,'queued','pending','pending',''))
    if full:removal_full.create(db,jid,did,keep_audit)
    Store.event(db,did,'device.uninstall_requested','warning',{'job_id':jid,'actor':user['username'],'reason':reason.strip(),'retains_files':not full,'keep_process_audit':keep_audit})
    return latest(db,did)


def close_audit_conflict(db,user,body):
    if user['role']!='admin':
        raise ManagementError(403,'需要管理員權限')
    if not isinstance(body,dict) or body.get('verified_audit_conflict') is not True:
        raise ManagementError(400,'請核對同一筆工作的程序稽核衝突及清理尚未啟動')
    did=body.get('device_id')
    if not isinstance(did,str) or not re.fullmatch('[0-9a-f]{24}',did):
        raise ManagementError(400,'端點識別碼不正確')
    device=db.execute('SELECT name FROM devices WHERE id=? AND revoked=0',(did,)).fetchone()
    if not device or body.get('confirm_name')!=device['name']:
        raise ManagementError(400,'請輸入端點完整名稱確認')
    job=latest(db,did)
    if not job or job['id']!=body.get('job_id') or not job.get('cleanup',{}).get('can_close_audit_conflict'):
        raise ManagementError(409,'這筆移除工作目前不能以程序稽核衝突結案')
    db.execute("UPDATE endpoint_removals SET status='closed' WHERE id=?",(job['id'],))
    db.execute("UPDATE endpoint_file_removals SET token_hash='',report_until=0,updated=? WHERE job_id=?",(time.time(),job['id']))
    Store.event(db,did,'device.uninstall_conflict_closed','warning',{'job_id':job['id'],'actor':user['username'],'previous_error':job['error'],'verified_audit_conflict':True})
    return latest(db,did)


def agent_route(db,device,path,body):
    role=body.get('role')
    if role not in ('main','native'):raise ManagementError(400,'收集器角色不正確')
    job=latest(db,device['id'])
    if path.endswith('/poll'):
        if not job or job['status'] in ('expired','closed'):
            return {'job':None}
        if role=='native' and job.get('cleanup',{}).get('keep_process_audit') and body.get('removal_keep_process_audit') is not True:
            return {'job':None}
        return {'job':job}
    if job and job.get('mode')=='remove_files_v1':raise ManagementError(409,'完整移除必須由獨立清理元件回報，不接受舊版完成通知')
    if not job or body.get('job_id')!=job['id']:raise ManagementError(404,'找不到此端點移除工作')
    state=body.get('state')
    if state not in ('working','ready','failed'):raise ManagementError(400,'移除狀態不正確')
    if job['status'] in TERMINAL:return {'job':job}
    if job[role]=='ready':return {'job':job}
    if role=='native' and job['main']!='ready':raise ManagementError(409,'等待一般 Agent 停止採集並補送日誌')
    error=body.get('error','')
    if not isinstance(error,str) or len(error)>500:raise ManagementError(400,'錯誤內容過長')
    changed=job[role]!=state or job['error']!=error
    job[role]=state;job['error']=error
    job['status']='completed' if job['main']==job['native']=='ready' else 'failed' if state=='failed' else 'running'
    db.execute('UPDATE endpoint_removals SET status=?,main=?,native=?,error=? WHERE id=?',(job['status'],job['main'],job['native'],error,job['id']))
    if changed:Store.event(db,device['id'],'device.uninstall_status','warning',{'job_id':job['id'],'role':role,'state':state,'status':job['status'],'error':error,'retains_files':True})
    return {'job':job}
