"""Native worker maintains the separate broker, using only signed fixed-scope bytes."""
import json
import math
import os
import re
import sys
import threading
import time
from pathlib import Path
from . import __version__
from . import update_packages as packages
from .update_client import save,probe,verify_tree,storage_budget,remove_managed,failure_details

IN_PROGRESS=('prepared','stopping','switching','starting')


def read(path,maximum=600*1024):
    path=packages.plain(path)
    if path.stat().st_size>maximum:raise ValueError('更新器維護紀錄過大')
    return json.loads(path.read_text(encoding='utf-8'))


def pending(agent):
    from .transaction_status import read_phase
    path=agent.config_path.parent/'updates/updater-refresh.json'
    phase=read_phase(path)
    if phase is None:return False
    if phase not in (*IN_PROGRESS,'healthy','rolled_back','failed'):raise ValueError('更新器維護狀態不正確')
    return phase in IN_PROGRESS


def authorization(envelope,agent,job,manifest,now=None):
    lease=packages.verify(envelope,agent.config['update_key']);now=time.time() if now is None else now
    fields={'format','operation','id','device_id','job_id','release_id','version','created','expires'}
    if not isinstance(lease,dict) or set(lease)!=fields or lease['format']!=1 or lease['operation']!='refresh_guarddesk_updater':raise ValueError('更新器授權用途不正確')
    if not isinstance(lease['id'],str) or not re.fullmatch('[0-9a-f]{32}',lease['id']) or lease['device_id']!=agent.config['device_id'] or lease['job_id']!=job['id'] or lease['release_id']!=manifest['sha256'] or lease['version']!=manifest['version']:raise ValueError('更新器授權與本機版本／端點不符')
    if any(type(lease[k]) not in (int,float) or not math.isfinite(lease[k]) for k in ('created','expires')) or not lease['created']<=now+120 or not now<lease['expires'] or not 0<lease['expires']-lease['created']<=300:raise ValueError('更新器授權已過期或時間不正確')
    return lease


class WindowsAdapter:
    def __init__(self,agent):
        from .windows_privilege import is_admin
        from .update_native import folder,protected_tree
        if os.name!='nt' or not is_admin() or not getattr(sys,'frozen',False):raise PermissionError('僅受保護原生工作可以維護更新器')
        self.agent=agent;self.program=folder(0x26);self.native=self.program/'USBControl';self.current=self.program/'Updater'
        did=agent.config['device_id']
        if not re.fullmatch('[0-9a-f]{24}',did) or agent.config_path!=folder(0x23)/'USBControl'/did/'config.json' or Path(sys.executable).resolve()!=self.native/'GuardDesk.exe':raise ValueError('原生維護身分／路徑不正確')
        self.root=packages.plain(agent.config_path.parent/'updates');self.root.mkdir(exist_ok=True)
        for path in (self.program,self.native,self.current,agent.config_path.parent):protected_tree(path)
        self.name='GuardDesk-AgentUpdater-'+did
        self.validate_task()

    def validate_task(self):
        from .update_native import task_xml
        from .decommission import parse_task_xml,validate_task
        import xml.etree.ElementTree as ET
        root=parse_task_xml(task_xml(self.name));ns={'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
        principals=root.findall('t:Principals/t:Principal',ns)
        if len(principals)!=1 or principals[0].findtext('t:UserId',namespaces=ns) not in ('S-1-5-18','SYSTEM') or principals[0].findtext('t:RunLevel',namespaces=ns)!='HighestAvailable' or principals[0].findtext('t:LogonType',namespaces=ns) not in (None,'ServiceAccount'):raise OSError('更新器工作不屬於固定 SYSTEM 身分')
        actions=root.find('t:Actions',ns)
        if actions is None or actions.get('Context')!=principals[0].get('id') or not principals[0].get('id'):raise OSError('更新器動作與 SYSTEM 身分不符')
        args=root.find('t:Actions/t:Exec/t:Arguments',ns)
        if args is None or args.text!='update-service --config "'+str(self.agent.config_path)+'"':raise OSError('更新器工作命令不符')
        args.text='usb-worker --extended --config "'+str(self.agent.config_path)+'"'
        validate_task(ET.tostring(root),self.current/'GuardDesk.exe',self.agent.config_path)

    def version(self):return probe(self.current)
    def paths(self,jid):
        if not isinstance(jid,str) or not re.fullmatch('[0-9a-f]{32}',jid):raise ValueError('維護工作身分不正確')
        return tuple(packages.plain(self.program/(prefix+jid)) for prefix in ('Updater.stage-','Updater.rollback-','Updater.failed-'))
    def baseline(self):
        from .update_native import protected_tree
        protected_tree(self.current)
        return {p.relative_to(self.current).as_posix():packages.file_hash(p) for p in self.current.rglob('*') if p.is_file()}
    def stage(self,job,manifest):
        from .update_native import protected_tree
        protected_tree(self.native);verify_tree(self.native,manifest)
        stage,backup,failed=self.paths(job['id'])
        if backup.exists() or failed.exists():raise OSError('更新器備份已存在，保留現狀')
        if not stage.exists():
            storage_budget([self.program,self.root],sum(p.stat().st_size for p in self.native.rglob('*') if p.is_file()))
            archive=packages.plain(self.root/job['id']/'package.zip');protected_tree(archive.parent)
            packages.extract(archive,manifest,stage)
        protected_tree(stage);verify_tree(stage,manifest)
        if probe(stage)!=manifest['version']:raise OSError('更新器程式版本不符')
    def stop(self):
        from .update_native import task_command
        from .single_instance import machine_instance
        from .update_windows import image_processes
        self.validate_task()
        with image_processes(self.current/'GuardDesk.exe') as wait:
            deadline=time.monotonic()+30
            task_command(self.name,'/End')
            while True:
                try:
                    with machine_instance('update',self.agent.config['device_id']):break
                except OSError:
                    if time.monotonic()>=deadline:raise OSError('更新器未停止，不替換執行中程式')
                    time.sleep(.25)
            wait(deadline)
    def switch(self,state):
        stage,backup,_=self.paths(state['job_id'])
        from .update_native import protected_tree
        from .update_windows import rename_protected
        for path in (self.current,stage):protected_tree(path)
        rename_protected(self.current,backup);rename_protected(stage,self.current)
    def start(self):
        from .update_native import task_command,protected_tree
        protected_tree(self.current);self.validate_task();task_command(self.name,'/Run')
    def health(self,version,started,timeout=45):
        from .update_native import process_image
        deadline=time.monotonic()+timeout
        while True:
            try:
                value=read(self.agent.config_path.parent/'broker-health.json',4096)
                if value.get('version')==version and value.get('native_version')==__version__ and value.get('time',0)>=started and time.time()-value['time']<30 and process_image(value['pid'])==self.current/'GuardDesk.exe':return True
            except (OSError,ValueError,KeyError):pass
            if time.monotonic()>=deadline:return False
            time.sleep(.5)
    def rollback(self,state):
        from .update_windows import rename_protected
        stage,backup,failed=self.paths(state['job_id'])
        if backup.exists():
            self.stop()
            from .update_native import protected_tree
            protected_tree(backup)
            actual={p.relative_to(backup).as_posix():packages.file_hash(p) for p in backup.rglob('*') if p.is_file()}
            if actual!=state['old_files']:raise OSError('更新器回復備份不符，保留現場')
            if self.current.exists():
                if failed.exists():raise OSError('更新器失敗備份衝突')
                rename_protected(self.current,failed)
            rename_protected(backup,self.current)
        started=time.time();self.start()
        # Pre-0.4.17 brokers do not emit health: verify their fixed version here;
        # server presence/channel remains the independent operational check.
        if self.version()!=state['old_version']:raise OSError('舊更新器版本未確認恢復')
        if packages.version(state['old_version'])>=(0,4,17):
            if not self.health(state['old_version'],started):raise OSError('舊更新器健康尚未恢復')
        else:
            deadline=time.monotonic()+30
            while True:
                value=self.agent.call('/api/agent/updater/observed',{}).get('presence')
                if value and value['broker_version']==state['old_version'] and value['received']>=started:break
                if time.monotonic()>=deadline:raise OSError('舊更新器連線尚未恢復')
                time.sleep(1)
    def cleanup(self,jid):
        keep={p.name for p in self.paths(jid)}
        for path in self.program.iterdir():
            if path.name not in keep and re.fullmatch(r'Updater\.(stage|rollback|failed)-[0-9a-f]{32}',path.name):
                remove_managed(self.program,path,r'Updater\.(stage|rollback|failed)-[0-9a-f]{32}',True)


class Refresh:
    def __init__(self,agent,adapter):
        self.agent=agent;self.adapter=adapter
        self.state=adapter.root/'updater-refresh.json'
        self.probed_job=None;self.current=None
    def finish(self,state,phase):
        state['phase']=phase;state['reported']=False;save(self.state,state)
        try:
            self.agent.call('/api/agent/updater/complete',{'id':state['lease_id'],'state':phase})
            state['reported']=True;save(self.state,state)
        except ConnectionError:pass  # Keep durable local result; lease expires safely.
    def recover(self):
        if not self.state.exists():return
        state=read(self.state)
        from .update_client import _save_plain
        from .transaction_status import publish
        publish(self.state,state,_save_plain)
        if state.get('phase') in IN_PROGRESS:
            self.adapter.rollback(state);self.finish(state,'rolled_back')
        elif state.get('phase') in ('healthy','rolled_back','failed'):
            if not state.get('reported'):self.finish(state,state['phase'])
        else:raise ValueError('更新器維護紀錄不正確')
    def step(self):
        self.recover()
        native=self.adapter.root/'transaction-native.json'
        if not native.exists():return
        record=read(native)
        if record.get('phase')!='healthy' or not record.get('reported'):return
        job=record['job'];manifest=packages.validate_manifest(packages.verify(job['release'],self.agent.config['update_key']))
        if job['device_id']!=self.agent.config['device_id'] or job['release_id']!=manifest['sha256'] or manifest['version']!=__version__ or record.get('version')!=__version__:return
        if not isinstance(job['id'],str) or not re.fullmatch('[0-9a-f]{32}',job['id']):raise ValueError('原更新工作不正確')
        if self.state.exists():
            prior=read(self.state)
            if prior.get('job_id')==job['id'] and prior.get('phase') in ('healthy','rolled_back','failed'):return
        if self.probed_job!=job['id']:
            self.current=self.adapter.version();self.probed_job=job['id']
        current=self.current
        if packages.version(current)>=packages.version(__version__):return
        envelope=self.agent.call('/api/agent/updater/prepare',{'job_id':job['id'],'version':__version__}).get('authorization')
        if not envelope:return
        lease=authorization(envelope,self.agent,job,manifest)
        state={'phase':'prepared','job_id':job['id'],'lease_id':lease['id'],'old_version':current,'target':__version__,'old_files':{},'reported':False}
        # All staging/verification happens before the running broker is stopped.
        try:
            state['old_files']=self.adapter.baseline()
            self.adapter.cleanup(job['id']);self.adapter.stage(job,manifest)
            if lease['expires']-time.time()<150:raise OSError('維護授權剩餘時間不足，不停止原更新器')
        except Exception:
            self.finish(state,'failed');raise
        save(self.state,state)
        operation='stopping'
        try:
            state['phase']='stopping';save(self.state,state);self.adapter.stop()
            operation='switching'
            state['phase']='switching';save(self.state,state);self.adapter.switch(state)
            operation='restarting'
            state['phase']='starting';state['started']=time.time();save(self.state,state);self.adapter.start()
            operation='health'
            if not self.adapter.health(__version__,state['started']):raise OSError('新版更新器未完成健康檢查')
        except Exception as exc:
            state['failure']=failure_details(operation,exc)
            try:save(self.state,state)
            except OSError:pass
            try:self.adapter.rollback(state)
            except Exception as rollback_exc:
                state['rollback_failure']=failure_details('unknown',rollback_exc)
                try:save(self.state,state)
                except OSError:pass
                raise
            self.finish(state,'rolled_back');return
        self.finish(state,'healthy')


def start(agent,stop):
    from .remote_trial import reject
    reject('Automatic updater refresh')
    """One low-priority bounded worker; no PowerShell or new startup task."""
    def work():
        from .performance import background_work
        with background_work():
            refresh=None
            while not stop.is_set():
                try:
                    if refresh is None:refresh=Refresh(agent,WindowsAdapter(agent))
                    refresh.step()
                except Exception as exc:
                    # No raw exception text or credentials in shared logs/API.
                    try:save(agent.config_path.parent/'updater-refresh-error.json',{'error_type':type(exc).__name__,'time':time.time()})
                    except (OSError,ValueError):pass
                stop.wait(15)
    thread=threading.Thread(target=work,name='GuardDesk-UpdaterMaintenance',daemon=True);thread.start()
    return thread
