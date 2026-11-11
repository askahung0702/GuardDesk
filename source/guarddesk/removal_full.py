"""Explicit full-file removal contract; never an arbitrary command channel.

The result capability authorizes only this job's bounded status/claim messages.
It cannot enroll, read policy/data, execute a command, or delete center records.
"""
import hashlib
import hmac
import re
import time
from .management import ManagementError
from .store import Store

CAPABILITY = 'remote_remove_files_v1'
MODE = 'remove_files_v1'
PHASES = ('queued', 'prepared', 'deleting', 'complete', 'review_required')

def get(db, job_id):
    row = db.execute('SELECT * FROM endpoint_file_removals WHERE job_id=?', (job_id,)).fetchone()
    return dict(row) if row else None

def public(row):
    return {k: row[k] for k in ('phase', 'updated', 'error_code', 'winerror', 'helper_cleanup')}

def create(db, jid, did):
    db.execute('INSERT INTO endpoint_file_removals(job_id,device_id,updated) VALUES(?,?,?)', (jid,did,time.time()))

def secret_hash(secret):
    if not isinstance(secret,str) or not re.fullmatch('[0-9a-f]{64}',secret):
        raise ManagementError(400,'移除回報憑證格式不正確')
    return hashlib.sha256(secret.encode('ascii')).hexdigest()

def prepare(db, device, body):
    if (not isinstance(body,dict) or set(body) != {'job_id','secret'} or not isinstance(body.get('job_id'),str)
        or not re.fullmatch('[0-9a-f]{32}',body['job_id'])):raise ManagementError(400,'移除準備欄位不正確')
    row=get(db,body['job_id'])
    job=db.execute('SELECT * FROM endpoint_removals WHERE id=? AND device_id=?',(body['job_id'],device['id'])).fetchone()
    if not row or not job or row['device_id']!=device['id'] or job['status'] in ('expired','completed'):
        raise ManagementError(409,'完整移除工作不可執行')
    digest=secret_hash(body['secret'])
    if row['token_hash'] and not hmac.compare_digest(row['token_hash'],digest):raise ManagementError(409,'移除工作已由另一元件接手')
    if row['phase']=='queued' and job['expires']<=time.time():raise ManagementError(409,'尚未執行的移除工作已過期')
    if row['phase'] in ('complete','review_required'):raise ManagementError(409,'移除工作已結束，不自動重做')
    if row['phase']=='queued':
        db.execute("UPDATE endpoint_file_removals SET token_hash=?,phase='prepared',updated=?,report_until=? WHERE job_id=?",(digest,time.time(),time.time()+86400,job['id']))
        db.execute("UPDATE endpoint_removals SET status='running',native='working',error='' WHERE id=?",(job['id'],))
        Store.event(db,device['id'],'device.full_removal_prepared','warning',{'job_id':job['id'],'backup':False})
    return {'prepared':True}

def preparation_error(db,device,body):
    if (not isinstance(body,dict) or set(body)!={'job_id','winerror'} or not isinstance(body['job_id'],str)
        or (body['winerror'] is not None and (type(body['winerror']) is not int or not 0<=body['winerror']<=0xffffffff))):raise ManagementError(400,'移除準備錯誤格式不正確')
    row=get(db,body['job_id'])
    if not row or row['device_id']!=device['id']:raise ManagementError(404,'移除工作不符')
    if row['phase'] in ('deleting','complete','review_required'):return {'recorded':False}
    db.execute("UPDATE endpoint_file_removals SET phase='review_required',error_code='PREPARATION_FAILED',winerror=?,updated=? WHERE job_id=?",(body['winerror'],time.time(),row['job_id']))
    db.execute("UPDATE endpoint_removals SET status='failed',native='failed',error='PREPARATION_FAILED' WHERE id=?",(row['job_id'],))
    Store.event(db,device['id'],'device.full_removal_prepare_failed','warning',{'job_id':row['job_id'],'winerror':body['winerror']})
    return {'recorded':True}

def result(db, secret, body):
    if not isinstance(body,dict) or not isinstance(body.get('job_id'),str):raise ManagementError(400,'移除回報格式不正確')
    if set(body)-{'job_id','phase','error_code','winerror','helper_cleanup'}:raise ManagementError(400,'移除回報含未知欄位')
    row=get(db,body['job_id'])
    digest=secret_hash(secret)
    if not row or not row['token_hash'] or not hmac.compare_digest(row['token_hash'],digest):raise ManagementError(401,'移除回報憑證無效')
    if row['report_until']<time.time():raise ManagementError(401,'移除回報期限已過；保留本機結果')
    job=db.execute('SELECT * FROM endpoint_removals WHERE id=?',(row['job_id'],)).fetchone()
    if not job:raise ManagementError(410,'中心資料已刪除；不重新建立端點')
    phase=body.get('phase')
    if phase=='authorize':
        device=db.execute('SELECT revoked FROM devices WHERE id=?',(row['device_id'],)).fetchone()
        # Reporting may continue after revoke, but a new destructive claim may not.
        allowed=bool(device and not device['revoked'] and row['phase']=='prepared' and job['status']=='running')
        return {'authorized':allowed,'phase':row['phase']}
    if phase not in ('deleting','complete','review_required'):raise ManagementError(400,'清理階段不正確')
    error=body.get('error_code','');winerror=body.get('winerror');helper=body.get('helper_cleanup','not_scheduled')
    if (not isinstance(error,str) or len(error)>80 or (error and not re.fullmatch('[A-Z0-9_]+',error))
        or (winerror is not None and (type(winerror) is not int or not 0<=winerror<=0xffffffff))
        or helper not in ('not_scheduled','reboot_pending','removed')):raise ManagementError(400,'移除診斷格式不正確')
    if row['phase'] in ('complete','review_required'):
        if phase!=row['phase']:raise ManagementError(409,'終止狀態不可改寫')
        if phase=='complete' and helper=='reboot_pending' and row['helper_cleanup']=='not_scheduled':
            db.execute("UPDATE endpoint_file_removals SET helper_cleanup='reboot_pending',updated=? WHERE job_id=?",(time.time(),row['job_id']))
        return {'acknowledged':True,'phase':row['phase']}
    if phase=='complete' and row['phase']!='deleting':raise ManagementError(409,'尚未進行檔案清理')
    if phase=='complete' and error:raise ManagementError(400,'完成回報不完整')
    if phase=='deleting' and row['phase'] not in ('prepared','deleting'):raise ManagementError(409,'清理階段順序不正確')
    db.execute('UPDATE endpoint_file_removals SET phase=?,updated=?,error_code=?,winerror=?,helper_cleanup=? WHERE job_id=?',
        (phase,time.time(),error,winerror,helper,row['job_id']))
    status='completed' if phase=='complete' else 'failed' if phase=='review_required' else 'running'
    db.execute('UPDATE endpoint_removals SET status=?,main=?,native=?,error=? WHERE id=?',
        (status,'ready' if phase in ('deleting','complete') else job['main'],'ready' if phase=='complete' else 'failed' if phase=='review_required' else 'working',error,row['job_id']))
    if row['phase']!=phase:Store.event(db,row['device_id'],'device.full_removal_status','warning',{'job_id':row['job_id'],'phase':phase,'error_code':error,'winerror':winerror,'helper_cleanup':helper})
    return {'acknowledged':True,'phase':phase}
