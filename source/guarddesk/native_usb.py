"""Privileged USB-only companion; never consumes a user-writable policy cache."""
import json
import os
import time
import math
import sqlite3
from pathlib import Path
from . import __version__
from .agent import Agent
from .management import ControlPlane
from .performance import background_work
from .store import Store,canonical
from .windows_controls import WindowsControls,is_admin

MODES={'allow','read_only','block'}


def policy_packet(db,device):
    policy=ControlPlane(db).resolve(dict(device))
    return {'device_id':device['id'],'version':policy['version'],'usb_mode':policy['body']['usb_mode']}


def validate_packet(value):
    if not isinstance(value,dict) or type(value.get('version')) is not int or not 0<=value['version']<=9223372036854775807 or not isinstance(value.get('usb_mode'),str) or value['usb_mode'] not in MODES:
        raise ValueError('USB 策略欄位不正確')
    return {'version':value['version'],'usb_mode':value['usb_mode']}


def readback_matches(mode,registry):
    if not isinstance(registry,dict):return False
    if mode=='read_only':return registry.get('Deny_Write')==1
    if mode=='block':return registry.get('Deny_Read')==1 and registry.get('Deny_Write')==1
    # allow restores the pre-existing company baseline, which can be stricter.
    return set(registry)=={'Deny_Read','Deny_Write'}


def accept_status(db,device,body):
    policy=validate_packet(body)
    status=body.get('status');registry=body.get('registry',{})
    if status not in ('configured_replug_required','failed','restored') or not isinstance(registry,dict) or not set(registry)<={'Deny_Read','Deny_Write'}:
        raise ValueError('USB 回報格式不正確')
    for value in registry.values():
        if value is not None and (type(value) is not int or value not in (0,1)):raise ValueError('USB 登錄回報值不正確')
    error=body.get('error','');version=body.get('worker_version','')
    if not isinstance(error,str) or len(error)>500 or not isinstance(version,str) or len(version)>30:raise ValueError('USB 回報內容過長')
    report={**policy,'status':status,'registry':registry,'error':error,'worker_version':version,'verified_readback':status=='configured_replug_required' and readback_matches(policy['usb_mode'],registry),'proof':'agent_report_not_remote_hardware_attestation'}
    resources=body.get('resources',{})
    if not isinstance(resources,dict):raise ValueError('USB 資源回報不正確')
    cpu=resources.get('cpu_machine_percent')
    if cpu is not None and (type(cpu) not in (int,float) or not math.isfinite(cpu) or not 0<=cpu<=100):raise ValueError('USB CPU 回報不正確')
    memory={}
    for key in ('working_set_bytes','private_bytes'):
        value=resources.get(key)
        if value is not None:
            if type(value) is not int or not 0<=value<=1<<50:raise ValueError('USB 記憶體回報不正確')
            memory[key]=value
    report['resources']={'cpu_machine_percent':cpu,**memory}
    old=db.execute('SELECT body FROM native_usb_status WHERE device_id=?',(device['id'],)).fetchone()
    state={k:v for k,v in report.items() if k!='resources'}
    if not old or {k:v for k,v in json.loads(old[0]).items() if k!='resources'}!=state:
        Store.event(db,device['id'],'usb.native_status','warning' if status=='failed' else 'info',state)
    db.execute('INSERT OR REPLACE INTO native_usb_status VALUES (?,?,?)',(device['id'],canonical(report),time.time()))
    return {'ok':True}


def snapshot(db,device_id,expected_mode):
    row=db.execute('SELECT body,received FROM native_usb_status WHERE device_id=?',(device_id,)).fetchone()
    if not row:return None
    result=json.loads(row['body']);result.update(received=row['received'],expected_mode=expected_mode)
    result['fresh']=time.time()-row['received']<120
    result['matches_policy']=result['usb_mode']==expected_mode
    return result


class UsbWorker:
    def __init__(self,config):
        from .remote_trial import enabled
        if enabled():raise PermissionError('USB controls unavailable in remote-only trial')
        self.agent=Agent(config)
        self.controls=WindowsControls(self.agent)
        self.controls.directory.mkdir(parents=True,exist_ok=True)

    def cycle(self,require_online=False):
        if not is_admin():raise PermissionError('USB 背景工作需要系統管理員／SYSTEM 權限')
        online=True
        try:
            packet=self.agent.call('/api/agent/native-usb-policy',{})
            if packet.get('device_id')!=self.agent.config['device_id']:raise ValueError('端點憑證與識別碼不相符，拒絕安裝／套用 USB 策略')
            policy=validate_packet(packet)
            with self.agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('native_usb_policy',?)",(canonical(policy),))
        except (ConnectionError,OSError):
            if require_online:raise
            online=False
            with self.agent.db() as db:row=db.execute("SELECT value FROM state WHERE key='native_usb_policy'").fetchone()
            if not row:raise ConnectionError('尚無受信任的 USB 策略，首次安裝必須連線管理中心')
            policy=validate_packet(json.loads(row[0]))
        try:
            report={**self.controls.apply_usb(policy['usb_mode']),**policy,'worker_version':__version__}
            if not readback_matches(policy['usb_mode'],report.get('registry')):report.update(status='failed',error='USB 登錄寫入後核對不符，請檢查公司群組原則或其他控制工具')
        except OSError as exc:report={**policy,'status':'failed','registry':{},'error':str(exc)[:500],'worker_version':__version__}
        report['resources']=self.agent._process_sampler.sample()
        with self.agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('native_usb_report',?)",(canonical(report),))
        if online:self.agent.call('/api/agent/native-usb-status',report)
        return report

    def restore(self):
        if not is_admin():raise PermissionError('還原 USB 控制需要系統管理員權限')
        if getattr(self,'custom',None):self.custom.close()
        recovery=self.agent.config_path.parent/'CustomSettings'/'network-lease.json'
        if recovery.exists():
            from .custom_windows import trusted_native
            from .custom_network import NetworkLease
            root=trusted_native(self.agent.config)
            if self.agent.config_path!=root/'config.json':raise OSError('自訂網路還原必須使用受保護設定')
            result=NetworkLease(recovery).restore()
            if result.get('state')=='conflict':raise OSError('網路設定有外部變更，保留現場並交 MIS 核對')
        backup=self.controls.directory/'usb-original.json'
        if not backup.exists():return {'status':'nothing_to_restore'}
        result=self.controls.apply_usb('allow')
        report={'version':0,'usb_mode':'allow','status':'restored','registry':result['registry'],'worker_version':__version__}
        try:self.agent.call('/api/agent/native-usb-status',report)
        except (ConnectionError,OSError):pass
        return report

    def run(self,stop,extended=False):
        from .single_instance import machine_instance
        if not is_admin():raise PermissionError('USB 背景工作需要系統管理員／SYSTEM 權限')
        with machine_instance('usb',self.agent.config['device_id']),background_work(),self.agent.wal_session():
            if extended and self.agent.config.get('update_key'):
                from .updater_refresh import start
                start(self.agent,stop)
            from .application_control import ExtendedWorker
            if extended:
                from .software_client import start as start_software
                try:start_software(self.agent,stop)
                except (OSError,ValueError):self.agent.feature_status['software_install']={'state':'protected_worker_unavailable'}
            self.custom=None
            if extended:
                try:
                    from .custom_client import CustomClient
                    self.custom=CustomClient(self.agent,stop,native=True).start()
                except (OSError,ValueError,sqlite3.Error):self.agent.feature_status['custom_settings']={'state':'requires_protected_native_install'}
            companion=ExtendedWorker(self.agent) if extended else None;self.extended_companion=companion;next_sync=0
            self.machine_sessions=None
            if extended:
                from .machine_agent import eligible,Supervisor
                if eligible(self.agent):
                    try:self.machine_sessions=Supervisor(self.agent,stop).start()
                    except (OSError,ValueError) as exc:
                        self.agent.feature_status['machine_agent']={'scope':'machine','status':'failed','type':type(exc).__name__}
                    if self.machine_sessions:self.agent.feature_status['machine_agent']=self.machine_sessions.snapshot()
            try:
                while not stop.is_set():
                    try:
                        from .decommission import native_step
                        removal=native_step(self)
                        if removal in ('pending','done') and self.custom:self.custom.close()
                        if removal=='done':return
                        if removal=='pending':stop.wait(5);continue
                        if time.monotonic()>=next_sync:
                            self.cycle()
                            if companion:
                                companion.configure()
                            if self.machine_sessions:self.machine_sessions.report_main_update()
                            if self.agent.config.get('update_key'):
                                from .update_client import save
                                health={'version':__version__,'time':time.time(),'pid':os.getpid()}
                                if self.machine_sessions:
                                    from .remote_trial import native_diagnostics,session_diagnostics
                                    health['native_remote']=native_diagnostics(self.machine_sessions)
                                    health['session_startup']=session_diagnostics(self.machine_sessions.snapshot())
                                save(self.agent.config_path.parent/'native-health.json',health)
                            next_sync=time.monotonic()+30
                        elif companion:
                            companion.poll()
                    except (ConnectionError,OSError,ValueError) as exc:
                        if companion and companion.policy is None:
                            try:
                                companion.poll()
                            except (ConnectionError,OSError,ValueError):pass
                        # Keep prior protections. Persist one bounded diagnostic, never default to allow.
                        with self.agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('native_usb_error',?)",(canonical({'error':str(exc)[:500],'time':time.time()}),))
                    if companion and companion.policy:
                        from .policy import agent_policy_wire
                        self.agent.machine_session_policy=agent_policy_wire({'version':0,'body':companion.policy})
                    stop.wait(5 if companion else 30)

            finally:
                if self.machine_sessions:self.machine_sessions.close()
                if companion:companion.close()
