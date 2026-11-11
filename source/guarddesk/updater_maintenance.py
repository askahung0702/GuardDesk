"""Short, signed, device-scoped authorization to refresh only GuardDesk's broker."""
import json
import re
import secrets
import time
from . import update_packages as packages
from .management import ManagementError
from .store import Store


def active(db,did):
    return db.execute("SELECT 1 FROM updater_refresh WHERE device_id=? AND state='active' AND expires>?",(did,time.time())).fetchone() is not None


def route(store,db,device,path,body):
    did=device['id'];now=time.time()
    if path.endswith('/observed'):
        if body:raise ManagementError(400,'觀察查詢不接受欄位')
        presence=db.execute("SELECT broker_version,received FROM update_presence WHERE device_id=? AND role='native'",(did,)).fetchone()
        return {'presence':dict(presence) if presence else None}
    if path.endswith('/complete'):
        if set(body)!={'id','state'} or body['state'] not in ('healthy','rolled_back','failed') or not isinstance(body['id'],str) or not re.fullmatch('[0-9a-f]{32}',body['id']):raise ManagementError(400,'更新器維護結果不正確')
        row=db.execute('SELECT * FROM updater_refresh WHERE device_id=? AND id=?',(did,body['id'])).fetchone()
        if not row:raise ManagementError(404,'找不到本端點維護工作')
        if row['state']!='active':return {'ok':True}
        db.execute('UPDATE updater_refresh SET state=? WHERE device_id=? AND id=?',(body['state'],did,body['id']))
        Store.event(db,did,'update.updater_refresh_completed','info' if body['state']=='healthy' else 'warning',{'state':body['state'],'version':row['version'],'job_id':row['job_id']})
        return {'ok':True}
    if set(body)!={'job_id','version'} or not isinstance(body['job_id'],str) or not re.fullmatch('[0-9a-f]{32}',body['job_id']):raise ManagementError(400,'更新器維護欄位不正確')
    packages.version(body['version'])
    from .software import active as software_active
    if software_active(db,did):return {'authorization':None,'waiting_for':'software_install'}
    from .custom_settings import action_leased
    if action_leased(db,did):return {'authorization':None,'waiting_for':'custom_action'}
    if packages.version(body['version'])<(0,4,17):raise ManagementError(400,'此版本尚未支援更新器接手維護')
    if active(db,did):return {'authorization':None,'waiting_for':'updater_refresh'}
    row=db.execute("SELECT j.*,r.version FROM update_jobs j JOIN update_releases r ON r.id=j.release_id WHERE j.id=? AND j.device_id=?",(body['job_id'],did)).fetchone()
    if not row or row['status'] not in ('pending','completed') or row['expires']<=now or row['not_before']>now or row['version']!=body['version']:raise ManagementError(409,'原更新工作不再允許維護')
    if row['status']!='completed':return {'authorization':None,'waiting_for':'main_component'}
    native=db.execute("SELECT state,version FROM update_status WHERE job_id=? AND role='native'",(row['id'],)).fetchone()
    if not native or native['state']!='healthy' or native['version']!=body['version']:raise ManagementError(409,'先完成原生元件健康確認')
    if db.execute("SELECT 1 FROM update_jobs WHERE device_id=? AND status='pending' AND id<>? AND expires>?",(did,row['id'],now)).fetchone():return {'authorization':None,'waiting_for':'another_update'}
    if db.execute("SELECT 1 FROM endpoint_removals WHERE device_id=? AND status IN ('queued','running','failed')",(did,)).fetchone():return {'authorization':None,'waiting_for':'uninstall'}
    if db.execute("SELECT 1 FROM remote_sessions WHERE device_id=? AND status='active' AND expires>?",(did,now)).fetchone():return {'authorization':None,'waiting_for':'remote_assistance'}
    prior=db.execute('SELECT * FROM updater_refresh WHERE device_id=?',(did,)).fetchone()
    if prior and (now-prior['created']<60 or prior['job_id']==row['id'] and prior['state']=='healthy'):return {'authorization':None,'waiting_for':'already_requested'}
    lease={'format':1,'operation':'refresh_guarddesk_updater','id':secrets.token_hex(16),'device_id':did,'job_id':row['id'],'release_id':row['release_id'],'version':body['version'],'created':now,'expires':now+300}
    envelope=packages.sign(packages.signer(store.path.resolve().parent),lease)
    db.execute('INSERT OR REPLACE INTO updater_refresh VALUES (?,?,?,?,?,?,?)',(did,lease['id'],row['id'],body['version'],now,lease['expires'],'active'))
    Store.event(db,did,'update.updater_refresh_started','info',{'job_id':row['id'],'version':body['version'],'expires':lease['expires']})
    return {'authorization':envelope}
