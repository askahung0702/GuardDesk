"""Administrator-only immutable MSI library and durable per-endpoint jobs."""
import json
import secrets
import shutil
import time
from . import update_packages as packages
from .software_contract import CAPABILITY, PURPOSE, TERMINAL, MAX_PACKAGE, LIBRARY_LIMIT, MAX_PACKAGES, GIB, hex_id, manifest
from .management import ManagementError
from .store import Store, canonical

SCHEMA='''
CREATE TABLE IF NOT EXISTS software_packages(id TEXT PRIMARY KEY,manifest TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS software_jobs(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,package_id TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,state TEXT NOT NULL,updated REAL NOT NULL,error TEXT NOT NULL DEFAULT '',exit_code INTEGER);
CREATE INDEX IF NOT EXISTS software_job_device ON software_jobs(device_id,state,created);
CREATE INDEX IF NOT EXISTS software_job_created ON software_jobs(created);
CREATE TABLE IF NOT EXISTS software_presence(device_id TEXT PRIMARY KEY,version TEXT NOT NULL,received REAL NOT NULL);
CREATE TABLE IF NOT EXISTS software_limits(id INTEGER PRIMARY KEY CHECK(id=1),package_bytes INTEGER NOT NULL,library_bytes INTEGER NOT NULL);
'''

def limits(db):
    row=db.execute('SELECT package_bytes,library_bytes FROM software_limits WHERE id=1').fetchone()
    return {'package_bytes':row[0] if row else 8*GIB,'library_bytes':row[1] if row else LIBRARY_LIMIT,'package_count':MAX_PACKAGES}

def set_limits(db,user,body):
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    if set(body)!={'package_bytes','library_bytes'} or any(type(v) is not int for v in body.values()) or not GIB<=body['package_bytes']<=MAX_PACKAGE or not body['package_bytes']<=body['library_bytes']<=1024*GIB:raise ValueError('單包 1–64 GiB，總庫須至少等於單包且不超過 1024 GiB')
    db.execute('INSERT OR REPLACE INTO software_limits VALUES (1,?,?)',(body['package_bytes'],body['library_bytes']))
    Store.event(db,'console','software.limits_changed','warning',{'actor':user['username'],**body})
    return limits(db)


def active(db,did):
    return bool(db.execute("SELECT 1 FROM software_jobs WHERE device_id=? AND (state IN ('installing','review_required') OR (state IN ('queued','downloading') AND expires>?)) LIMIT 1",(did,time.time())).fetchone())


def repository(store):
    from .server_setup import secure_directory
    root=packages.plain(store.path.resolve().parent/'software-packages')
    if not root.exists():secure_directory(root,allow_empty=True)
    return root


def add_package(store,source,actor,install_bytes):
    from .software_msi import inspect
    from .native_browser_identity import signed_publisher
    size=source.stat().st_size
    if not 0<size<=MAX_PACKAGE:raise ValueError('MSI exceeds 8 GiB library package limit')
    info=inspect(source)
    publisher=signed_publisher(source)
    value=manifest({'purpose':PURPOSE,'sha256':packages.file_hash(source),'bytes':size,
        'name':info['name'],'product_code':info['product_code'],'version':info['version'],
        'install_bytes':max(install_bytes,info['file_bytes'],size),'publisher':publisher})
    root=repository(store);target=packages.plain(root/(value['sha256']+'.msi'))
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        old=db.execute('SELECT manifest FROM software_packages WHERE id=?',(value['sha256'],)).fetchone()
        if old:return {'package':json.loads(old[0]),'existing':True}
        rows=db.execute('SELECT manifest FROM software_packages').fetchall();quota=limits(db)
        if size>quota['package_bytes'] or len(rows)>=MAX_PACKAGES or sum(json.loads(r[0])['bytes'] for r in rows)+size>quota['library_bytes']:
            raise ManagementError(409,'軟體庫已達配額，請調整容量或移除不再使用的套件')
        if shutil.disk_usage(root).free<GIB:raise ManagementError(409,'軟體庫可用空間不足')
        # Upload and repository are on the same center data volume. Never execute here.
        source.replace(target)
        db.execute('INSERT INTO software_packages VALUES (?,?,?,?)',(value['sha256'],canonical(value),actor,time.time()))
        Store.event(db,'console','software.uploaded','warning',{'actor':actor,'sha256':value['sha256'],'product_code':value['product_code'],'version':value['version']})
    return {'package':value}


def catalog(db):
    return {'packages':[json.loads(r[0]) for r in db.execute('SELECT manifest FROM software_packages ORDER BY created DESC LIMIT 100')],
        'jobs':[dict(r) for r in db.execute('SELECT j.*,d.name AS device_name FROM software_jobs j LEFT JOIN devices d ON d.id=j.device_id ORDER BY created DESC LIMIT 100')],
        'endpoints':[dict(r) for r in db.execute('SELECT d.id,d.name,p.version,p.received FROM devices d JOIN software_presence p ON p.device_id=d.id WHERE d.revoked=0 ORDER BY d.name LIMIT 1000')],
        'limits':limits(db)}

def delete_package(store,db,user,body):
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    if set(body)!={'package_id'}:raise ValueError('Invalid package deletion')
    pid=hex_id(body['package_id'],64)
    if db.execute("SELECT 1 FROM software_jobs WHERE package_id=? AND state IN ('queued','downloading','installing','review_required')",(pid,)).fetchone():raise ManagementError(409,'此套件仍有工作使用，不能刪除')
    packages.plain(repository(store)/(pid+'.msi')).unlink(missing_ok=True)
    db.execute('DELETE FROM software_packages WHERE id=?',(pid,))
    Store.event(db,'console','software.package_deleted','warning',{'actor':user['username'],'sha256':pid})
    return {'ok':True}


def conflicting(db,did):
    from .updater_maintenance import active as updating
    from .custom_settings import action_leased
    return (updating(db,did) or action_leased(db,did) or
        db.execute("SELECT 1 FROM update_jobs WHERE device_id=? AND status='pending' AND expires>?",(did,time.time())).fetchone() or
        db.execute("SELECT 1 FROM endpoint_removals WHERE device_id=? AND status IN ('queued','running','failed')",(did,)).fetchone())


def create_jobs(db,user,body):
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    if set(body)!={'package_id','device_ids','confirm'} or body['confirm']!='install-msi-machine':raise ValueError('請確認以 SYSTEM 靜默安裝此 MSI')
    pid=hex_id(body['package_id'],64);ids=body['device_ids']
    if not isinstance(ids,list) or not 1<=len(ids)<=20 or any(not isinstance(x,str) for x in ids) or len(set(ids))!=len(ids):raise ValueError('請選擇 1–20 台不同端點')
    if not db.execute('SELECT 1 FROM software_packages WHERE id=?',(pid,)).fetchone():raise ManagementError(404,'找不到 MSI 套件')
    # Validate the whole selection before inserting, including callers without an outer transaction.
    for did in ids:
        hex_id(did,24)
        if not db.execute('SELECT 1 FROM devices WHERE id=? AND revoked=0',(did,)).fetchone():raise ManagementError(404,'找不到有效端點')
        presence=db.execute('SELECT received FROM software_presence WHERE device_id=?',(did,)).fetchone()
        if not presence or time.time()-presence[0]>120:raise ManagementError(409,'端點尚未回報 MSI 安裝能力，請先更新配套 Agent 並確認服務上線')
        if active(db,did) or conflicting(db,did):raise ManagementError(409,'端點已有軟體、更新、移除或維護工作')
    result=[];now=time.time()
    for did in ids:
        jid=secrets.token_hex(16);result.append(jid)
        db.execute('INSERT INTO software_jobs VALUES (?,?,?,?,?,?,?,?,?,?)',(jid,did,pid,user['username'],now,now+7*86400,'queued',now,'',None))
        Store.event(db,did,'software.scheduled','warning',{'job_id':jid,'sha256':pid,'actor':user['username'],'scope':'machine'})
    return {'job_ids':result}


def valid(db,device,jid):
    hex_id(jid,32)
    row=db.execute('SELECT * FROM software_jobs WHERE id=? AND device_id=?',(jid,device['id'])).fetchone()
    if not row:raise ManagementError(404,'找不到此端點的軟體工作')
    return row


def cancel(db,user,body):
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    if set(body)!={'job_id'}:raise ValueError('Invalid cancellation')
    jid=hex_id(body['job_id'],32)
    row=db.execute('SELECT * FROM software_jobs WHERE id=?',(jid,)).fetchone()
    if not row or row['state'] not in ('queued','downloading'):raise ManagementError(409,'只能取消尚未開始安裝的工作；不強制終止 Windows Installer')
    db.execute("UPDATE software_jobs SET state='cancelled',updated=? WHERE id=?",(time.time(),jid))
    Store.event(db,row['device_id'],'software.cancelled','warning',{'job_id':jid,'actor':user['username']})
    return {'ok':True}


def close_review(db,user,body):
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    if set(body)!={'job_id','confirm'} or body['confirm']!='installer-stopped-and-result-reviewed':raise ValueError('請先在端點確認該安裝程序已結束並檢查結果')
    jid=hex_id(body['job_id'],32)
    row=db.execute('SELECT * FROM software_jobs WHERE id=?',(jid,)).fetchone()
    if not row or row['state']!='review_required':raise ManagementError(409,'此工作不在待確認狀態')
    db.execute("UPDATE software_jobs SET state='failed',error='MANUAL_REVIEW_CLOSED_NO_RETRY',updated=? WHERE id=?",(time.time(),jid))
    Store.event(db,row['device_id'],'software.review_closed','warning',{'actor':user['username'],'job_id':jid,'installation_success_claimed':False})
    return {'ok':True}


def agent_route(store,db,device,path,body):
    now=time.time()
    if path.endswith('/poll'):
        if set(body)!={'protocol','version'} or body['protocol']!=1:raise ValueError('Invalid software protocol')
        packages.version(body['version'])
        db.execute('INSERT OR REPLACE INTO software_presence VALUES (?,?,?)',(device['id'],body['version'],now))
        db.execute("UPDATE software_jobs SET state='cancelled',error='EXPIRED_BEFORE_INSTALL',updated=? WHERE device_id=? AND state IN ('queued','downloading') AND expires<=?",(now,device['id'],now))
        row=db.execute("SELECT * FROM software_jobs WHERE device_id=? AND state IN ('queued','downloading','installing','review_required') ORDER BY created LIMIT 1",(device['id'],)).fetchone()
        if not row or conflicting(db,device['id']):return {'job':None}
        if row['state']=='queued':
            count=db.execute("SELECT count(*) FROM software_jobs WHERE state IN ('installing','review_required') OR (state='downloading' AND expires>?)",(now,)).fetchone()[0]
            if count>=2:return {'job':None,'waiting_for':'batch_slot'}
            db.execute("UPDATE software_jobs SET state='downloading',updated=? WHERE id=?",(now,row['id']))
        m=json.loads(db.execute('SELECT manifest FROM software_packages WHERE id=?',(row['package_id'],)).fetchone()[0])
        payload={'purpose':PURPOSE,'id':row['id'],'device_id':device['id'],'expires':row['expires'],'package':m}
        return {'job':packages.sign(packages.signer(store.path.resolve().parent),payload),'state':row['state']}
    row=valid(db,device,body.get('job_id'))
    if path.endswith('/state'):
        if set(body)!={'job_id'}:raise ValueError('Invalid job state query')
        return {'state':row['state']}
    if path.endswith('/authorize'):
        if set(body)!={'job_id'} or row['state']!='downloading' or row['expires']<=now or conflicting(db,device['id']):raise ManagementError(409,'工作已取消、過期或端點忙碌；不開始安裝')
        db.execute("UPDATE software_jobs SET state='installing',updated=? WHERE id=?",(now,row['id']))
        Store.event(db,device['id'],'software.installing','warning',{'job_id':row['id']})
        return {'authorized':True}
    if path.endswith('/result'):
        if set(body)!={'job_id','state','error','exit_code'}:raise ValueError('Invalid software result')
        state=body['state'];error=body['error'];code=body['exit_code']
        if state not in (TERMINAL-{'cancelled'})|{'review_required'} or not isinstance(error,str) or len(error)>80 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_' for c in error):raise ValueError('Invalid software result fields')
        if code is not None and (type(code) is not int or not 0<=code<=0xffffffff):raise ValueError('Invalid MSI exit code')
        if row['state'] in TERMINAL:
            # Cancellation/manual review can race a durable late endpoint report.
            # Acknowledge receipt without changing the terminal center decision,
            # otherwise this endpoint would remain stuck retrying the old report.
            return {'ok':True,'terminal_state':row['state']}
        if state in ('succeeded','reboot_required') and row['state'] not in ('installing','review_required'):raise ManagementError(409,'尚未授權安裝')
        db.execute('UPDATE software_jobs SET state=?,error=?,exit_code=?,updated=? WHERE id=?',(state,error,code,now,row['id']))
        Store.event(db,device['id'],'software.result','info' if state in ('succeeded','already_installed') else 'warning',{'job_id':row['id'],'state':state,'error':error,'exit_code':code})
        return {'ok':True}
    raise ManagementError(404,'找不到軟體派送 API')
