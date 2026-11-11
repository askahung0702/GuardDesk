"""Fixed-purpose Windows installer using Win32 ACLs and Task Scheduler.

No PowerShell host, script-policy override, AV exception or downloaded code.
SYSTEM executes only verified copies in protected fixed installation roots.
"""
import csv
import ctypes
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from . import __version__
from . import update_packages as packages
from .update_native import folder, protected_tree, system_tool, process_image

NS='http://schemas.microsoft.com/windows/2004/02/mit/task'


class NativeInstallFailure(OSError):
    def __init__(self,stage,cause,recovery,failures=None):
        self.stage=stage
        self.recovery_failures=list(failures or [])
        detail=('\nGUARDDESK_RECOVERY='+json.dumps(self.recovery_failures,ensure_ascii=True,separators=(',',':'))) if self.recovery_failures else ''
        super().__init__('GUARDDESK_STAGE='+stage+'\n'+recovery+'\n'+str(cause)+detail)


class InstallObservationError(OSError):
    def __init__(self,message,evidence):
        self.evidence=evidence
        super().__init__(message+'\nGUARDDESK_OBSERVATION='+json.dumps(evidence,ensure_ascii=True,separators=(',',':')))


def failure_evidence(operation,error):
    # Never stringify an OS exception: filenames, arguments or tokens may be in it.
    value={'operation':operation,'error_type':type(error).__name__}
    if type(getattr(error,'winerror',None)) is int:value['winerror']=error.winerror
    if isinstance(error,InstallObservationError):value['observation']=error.evidence
    return value


@contextmanager
def system_query_scope():
    """Enable an existing admin privilege on this thread only, then restore it.

    SYSTEM process DACLs can deny even an elevated admin's limited query. This
    does not add an account privilege or change policy/process ACLs. No memory,
    termination or write process access is requested by process_image().
    """
    from ctypes import wintypes as w
    from .windows_privilege import is_admin
    if os.name!='nt' or not is_admin():raise PermissionError('SYSTEM 元件查詢需要已核准的管理員安裝程序')
    class Luid(ctypes.Structure):_fields_=[('low',w.DWORD),('high',w.LONG)]
    class Privileges(ctypes.Structure):_fields_=[('count',w.DWORD),('luid',Luid),('attributes',w.DWORD)]
    api=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetCurrentThread.restype=w.HANDLE;kernel.CloseHandle.argtypes=[w.HANDLE]
    api.OpenThreadToken.argtypes=[w.HANDLE,w.DWORD,w.BOOL,ctypes.POINTER(w.HANDLE)];api.OpenThreadToken.restype=w.BOOL
    api.ImpersonateSelf.argtypes=[ctypes.c_int];api.ImpersonateSelf.restype=w.BOOL
    api.RevertToSelf.restype=w.BOOL
    api.LookupPrivilegeValueW.argtypes=[w.LPCWSTR,w.LPCWSTR,ctypes.POINTER(Luid)];api.LookupPrivilegeValueW.restype=w.BOOL
    api.AdjustTokenPrivileges.argtypes=[w.HANDLE,w.BOOL,ctypes.POINTER(Privileges),w.DWORD,ctypes.POINTER(Privileges),ctypes.POINTER(w.DWORD)];api.AdjustTokenPrivileges.restype=w.BOOL
    token=w.HANDLE();previous=Privileges();created=False;changed=False
    try:
        if not api.OpenThreadToken(kernel.GetCurrentThread(),0x28,True,ctypes.byref(token)):
            error=ctypes.get_last_error()
            if error!=1008:raise ctypes.WinError(error)
            if not api.ImpersonateSelf(2):raise ctypes.WinError(ctypes.get_last_error())
            created=True
            if not api.OpenThreadToken(kernel.GetCurrentThread(),0x28,True,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
        desired=Privileges();desired.count=1;desired.attributes=2
        if not api.LookupPrivilegeValueW(None,'SeDebugPrivilege',ctypes.byref(desired.luid)):raise ctypes.WinError(ctypes.get_last_error())
        size=w.DWORD();ctypes.set_last_error(0)
        if not api.AdjustTokenPrivileges(token,False,ctypes.byref(desired),ctypes.sizeof(previous),ctypes.byref(previous),ctypes.byref(size)) or ctypes.get_last_error():raise ctypes.WinError(ctypes.get_last_error())
        changed=True;yield
    finally:
        try:
            if changed and not api.AdjustTokenPrivileges(token,False,ctypes.byref(previous),0,None,None):raise SystemExit('無法還原安裝器的暫時查詢權限；停止程序並保留安裝交易。')
        finally:
            if token:kernel.CloseHandle(token)
            if created and not api.RevertToSelf():raise SystemExit('無法結束安裝器的暫時執行緒身分；停止程序並保留安裝交易。')


def health_image(pid):
    try:return process_image(pid)
    except PermissionError as exc:
        if getattr(exc,'winerror',None)!=5:raise
        with system_query_scope():return process_image(pid)


def wait_image_unmapped(executable,timeout=30):
    """Wait on this protected image's Windows file lock, not unrelated PIDs.

    A writable, exclusive OPEN_EXISTING handle cannot be obtained while the
    executable has a running image section. No bytes or attributes are changed.
    This works for an elevated installer without enabling SeDebugPrivilege.
    """
    from ctypes import wintypes as w
    executable=packages.plain(executable)
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE];api.CreateFileW.restype=w.HANDLE
    api.CloseHandle.argtypes=[w.HANDLE]
    deadline=time.monotonic()+timeout
    while True:
        handle=api.CreateFileW(str(executable),0xC0010000,0,None,3,0,None)
        if handle!=ctypes.c_void_p(-1).value:api.CloseHandle(handle);return
        error=ctypes.get_last_error()
        if error not in (5,32,33):raise ctypes.WinError(error)
        if time.monotonic()>=deadline:raise OSError('原生程式仍被占用或無法取得安全存取（Windows '+str(error)+'）；保留程式，未切換。')
        time.sleep(.1)


def read_json(path, limit=65536):
    path=packages.plain(path)
    with path.open('rb') as stream:raw=stream.read(limit+1)
    if len(raw)>limit:raise ValueError('安裝設定／狀態超過大小上限')
    value=json.loads(raw.decode('utf-8-sig'))
    if not isinstance(value,dict):raise ValueError('安裝設定／狀態格式不正確')
    return value


def bounded_hash(path,limit,output=None):
    digest=hashlib.sha256();size=0
    with path.open('rb') as stream:
        while chunk:=stream.read(min(65536,limit-size+1)):
            size+=len(chunk)
            if size>limit:raise ValueError('安裝程式檔案在讀取期間超過容量上限')
            digest.update(chunk)
            if output is not None:output.write(chunk)
    return digest.hexdigest(),size


def source_files(source):
    source=packages.plain(source)
    body=read_json(source/'_internal/agent-release.json',2*1024*1024)
    entries=body.get('files')
    if set(body)!={'format','version','files'} or type(body.get('format')) is not int or body['format']!=1 or body.get('version')!=__version__ or not isinstance(entries,dict) or not 3<=len(entries)<packages.MAX_FILES:
        raise ValueError('安裝程式版本清單不符，請重新下載完整端點包')
    if not {'GuardDesk.exe','GuardDeskAgent.exe'}<=entries.keys():raise ValueError('安裝程式缺少必要執行檔')
    entries={**entries,'_internal/agent-release.json':bounded_hash(source/'_internal/agent-release.json',2*1024*1024)[0]}
    actual={};total=0
    for count,path in enumerate(source.rglob('*'),1):
        if count>2*packages.MAX_FILES:raise ValueError('安裝程式檔案過多')
        packages.plain(path)
        if not path.is_file():continue
        name=packages.safe_name(path.relative_to(source).as_posix());expected=entries.get(name)
        if not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected):raise ValueError('安裝程式包含未知檔案')
        digest,size=bounded_hash(path,packages.MAX_TOTAL-total);total+=size
        if digest!=expected:raise ValueError('安裝程式內容核對失敗')
        actual[name]=expected
    if actual!=entries:raise ValueError('安裝程式缺檔')
    return entries,total


def task_body(executable, config, role):
    if role not in ('native','updater'):raise ValueError('安裝工作種類不正確')
    root=ET.Element('Task',xmlns=NS,version='1.3')
    def sub(parent,name,value=None,**attrs):
        node=ET.SubElement(parent,name,attrs)
        if value is not None:node.text=value
        return node
    info=sub(root,'RegistrationInfo');sub(info,'Description','GuardDesk 全機 Agent 與受保護原生元件' if role=='native' else 'GuardDesk 受保護的簽章更新器')
    trigger=sub(sub(root,'Triggers'),'BootTrigger');sub(trigger,'Enabled','true')
    principal=sub(sub(root,'Principals'),'Principal',id='GuardDeskSystem')
    sub(principal,'UserId','S-1-5-18');sub(principal,'RunLevel','HighestAvailable')
    settings=sub(root,'Settings')
    for name,value in [('MultipleInstancesPolicy','IgnoreNew'),('DisallowStartIfOnBatteries','false'),('StopIfGoingOnBatteries','false'),('AllowHardTerminate','true'),('StartWhenAvailable','true'),('RunOnlyIfNetworkAvailable','false'),('Enabled','true'),('Hidden','false'),('ExecutionTimeLimit','PT0S'),('Priority','7')]:sub(settings,name,value)
    restart=sub(settings,'RestartOnFailure');sub(restart,'Interval','PT1M');sub(restart,'Count','3')
    action=sub(sub(root,'Actions',Context='GuardDeskSystem'),'Exec')
    sub(action,'Command',str(executable))
    sub(action,'Arguments',('usb-worker --extended' if role=='native' else 'update-service')+' --config "'+str(config)+'"')
    sub(action,'WorkingDirectory',str(executable.parent))
    return ET.tostring(root,encoding='utf-16',xml_declaration=True)


def verify_task(raw, executable, config, role):
    from .decommission import parse_task_xml,validate_task
    root=parse_task_xml(raw);ns={'t':NS}
    action=root.find('t:Actions',ns)
    if action is None or len(action)!=1 or action[0].tag!='{'+NS+'}Exec':raise OSError('既有工作動作不符，保留原工作')
    principal=root.find('t:Principals/t:Principal',ns)
    if principal is None or principal.findtext('t:UserId',namespaces=ns) not in ('S-1-5-18','SYSTEM') or principal.findtext('t:RunLevel',namespaces=ns)!='HighestAvailable':raise OSError('既有工作身分不符，保留原工作')
    if role=='native':validate_task(raw,executable,config)
    else:
        if os.path.normcase(action[0].findtext('t:Command',namespaces=ns) or '')!=os.path.normcase(str(executable)) or (action[0].findtext('t:Arguments',namespaces=ns) or '')!='update-service --config "'+str(config)+'"':raise OSError('既有更新工作不符，保留原工作')


from .protected_files import ProtectedFiles

class Windows(ProtectedFiles):
    """Only fixed system tools and explicit trusted paths; no command shell."""

    def tree(self,path):protected_tree(path)

    def public_runtime(self,stage):
        from .context_permissions import prepare_staged_runtime
        return prepare_staged_runtime(stage)

    def names(self):
        result=self.command(['/Query','/FO','CSV','/NH'])
        if len(result)>8*1024*1024:raise OSError('工作清單過大，未進行安裝')
        rows=list(csv.reader(io.StringIO(result.decode('oem'))))
        if len(rows)>65536 or any(len(row)!=3 for row in rows if row):raise OSError('工作清單格式不正確，未進行安裝')
        return {row[0] for row in rows if row}

    def command(self,arguments):
        result=subprocess.run([system_tool('schtasks.exe'),*arguments],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:raise OSError('Windows 工作排程操作失敗（代碼 '+str(result.returncode)+'），保留既有安裝')
        return result.stdout

    def query(self,name):return self.command(['/Query','/TN',name,'/XML'])
    def start(self,name):self.command(['/Run','/TN',name])
    def delete(self,name):self.command(['/Delete','/TN',name,'/F'])
    def register(self,name,raw,directory):
        path=directory/('task-'+secrets.token_hex(8)+'.xml')
        try:
            self.write(path,raw)
            self.command(['/Create','/TN',name,'/XML',str(path),'/F'])
        finally:path.unlink(missing_ok=True)

    def stop(self,name,executable):
        # /End can fail for an already stopped/disabled task. The validated
        # target must still pass an exclusive image-lock check before switching.
        ended=subprocess.run([system_tool('schtasks.exe'),'/End','/TN',name],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        try:wait_image_unmapped(executable)
        except OSError as exc:
            code=getattr(exc,'winerror',None)
            state='image_missing_stop_unconfirmed' if code in (2,3) else 'image_access_or_mapping_unconfirmed'
            raise InstallObservationError('無法確認元件已停止；保留交易與程式。',
                {'operation':'confirm_image_unmapped','state':state,'winerror':code,
                 'task_end_exit_code':ended.returncode}) from exc


    def invoke(self,executable,*arguments):
        result=subprocess.run([str(executable),*map(str,arguments)],capture_output=True,timeout=120,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:
            text=result.stderr.decode('utf-8',errors='replace')[-5000:]
            raise OSError('原生元件首次套用／還原失敗（代碼 '+str(result.returncode)+'）\n'+text)
        return result.stdout

    def health(self,path,version,executable,started):
        deadline=time.monotonic()+45;reason='健康檔尚未產生'
        evidence={'expected_version':version,'started':started,'health_state':'missing','pid_validated':False}
        while time.monotonic()<deadline:
            try:
                evidence={'expected_version':version,'started':started,'health_state':'missing','pid_validated':False}
                if path.exists():
                    value=read_json(path,4096)
                    observed=value.get('version');stamp=value.get('time');pid=value.get('pid')
                    evidence['observed_version']=observed if isinstance(observed,str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+){2}',observed) and len(observed)<=30 else 'invalid'
                    evidence['observed_time']=stamp if type(stamp) in (int,float) and math.isfinite(stamp) else None
                    valid_pid=type(pid) is int and 0<pid<=0xffffffff
                    evidence['observed_pid']=pid if valid_pid else None
                    if observed!=version:
                        reason='健康檔版本不符';evidence['health_state']='version_mismatch'
                    elif type(stamp) not in (int,float) or not math.isfinite(stamp) or stamp<started:
                        reason='健康檔時間早於本次啟動或格式錯誤';evidence['health_state']='stale_or_invalid_time'
                    elif not valid_pid:
                        reason='健康檔 PID 格式錯誤';evidence['health_state']='invalid_pid'
                    elif health_image(pid)!=executable.resolve():
                        reason='健康檔 PID 的執行路徑不符';evidence['health_state']='image_mismatch'
                    else:return
            except (OSError,ValueError,TypeError) as exc:
                error=getattr(exc,'winerror',None)
                reason='健康驗證失敗：'+type(exc).__name__+('（Windows '+str(error)+'）' if error is not None else '')
                evidence.update(health_state='query_failed',error_type=type(exc).__name__,winerror=error)
            time.sleep(.25)
        try:
            packages.plain(executable).stat();evidence['image_state']='present_not_liveness_proof'
        except FileNotFoundError:evidence['image_state']='missing'
        except (OSError,ValueError) as exc:
            evidence['image_state']='query_failed';evidence['image_winerror']=getattr(exc,'winerror',None)
        from .remote_trial import enabled
        if enabled() and path.name=='native-health.json':
            from .worker_startup import snapshot
            evidence['startup']=snapshot(path.parent/'native-startup.json',version,started)
        raise InstallObservationError('原生元件／更新器未在 45 秒內確認啟動：'+path.name+'；'+reason,evidence)


def encode(value):return json.dumps(value,ensure_ascii=False,indent=2).encode('utf-8')


def _capacity_timeout_before_stop(path):
    """Read-only exception for an acknowledged, matching pre-stop failure.

    Never clear journals or infer safety from a last-error file alone. Ordinary
    healthy handoffs keep their small-summary path; only this failed case reads
    a bounded full record while the installer owns the lifecycle transaction.
    """
    from .transaction_status import fingerprint
    failure_path=path.with_name('last-update-failure-native.json')
    try:
        before=(fingerprint(path),fingerprint(failure_path))
        record=read_json(path,4*1024*1024);failure=read_json(failure_path,4096)
        job=record.get('job');detail=record.get('failure')
        valid=(record.get('phase')=='failed' and record.get('reported') is True
            and isinstance(job,dict) and isinstance(job.get('id'),str)
            and re.fullmatch('[0-9a-f]{32}',job['id']) is not None
            and isinstance(detail,dict) and detail.get('stage')=='capacity'
            and detail.get('code')=='scan_timeout' and record.get('stage') is None
            and failure.get('job_id')==job['id'] and failure.get('target')==record.get('target')
            and failure.get('failure')==detail
            and record.get('version')==record.get('old_version'))
        if not valid:return False
        packages.version(record['old_version']);packages.version(record['target'])
        return before==(fingerprint(path),fingerprint(failure_path))
    except (OSError,ValueError,KeyError,TypeError):return False


def assert_quiescent(root,include_install=True):
    from .transaction_status import read_phase,JournalStateError
    names=['updates/transaction-native.json','updates/updater-refresh.json']
    if include_install:names.append('install-transaction.json')
    for filename in names:
        path=root/filename
        phase=read_phase(path) if filename.startswith('updates/') else (read_json(path).get('phase') if path.exists() else None)
        if phase is None and path.exists():raise JournalStateError('journal_invalid_phase')
        if phase=='failed' and filename=='updates/transaction-native.json' and _capacity_timeout_before_stop(path):continue
        if phase is not None and phase not in ('healthy','rolled_back','complete','failed_before_switch'):
            raise JournalStateError('journal_in_progress')


def install(config,action,source,platform=None,*,remote_test=False):
    from .windows_privilege import is_admin
    from .single_instance import machine_instance
    if os.name!='nt' or not is_admin():raise PermissionError('受保護安裝需要 Windows UAC 核准')
    if action not in ('Install','Uninstall','Status'):raise ValueError('安裝動作不正確')
    config=packages.plain(config);settings=read_json(config)
    did=settings.get('device_id')
    if not isinstance(did,str) or not re.fullmatch('[0-9a-f]{24}',did):raise ValueError('端點識別碼不正確')
    with machine_instance('native-installer-machine','all-devices'):
        if remote_test:
            from .remote_test_install import preflight
            checked=preflight(config,settings,source)
            if action=='Status':return checked
        if platform is None:
            from .remote_trial import enabled
            from .machine_service import enabled as full_service
            if enabled() or full_service():
                from .remote_service import platform as service_platform
                platform=service_platform()
            else:platform=Windows()
        return transaction(config,settings,action,source,platform,remote_test=remote_test)


def transaction(config,settings,action,source,ops,*,remote_test=False):
    from .remote_trial import enabled
    from .remote_trial_install import check_settings, PROFILE
    trial=enabled()
    from .machine_service import enabled as full_service,image as service_image
    if action=='Install' and full_service() and not packages.plain(service_image(Path(source)/'GuardDesk.exe')).is_file():
        raise OSError('完整 Agent 缺少已核對的全機服務程式，保留原安裝')
    verify_lifecycle=getattr(ops,'verify',verify_task)
    lifecycle_body=getattr(ops,'body',task_body)
    check_settings(settings)
    did=settings['device_id'];program=folder(38);data=folder(35)
    native=program/'USBControl';updater=program/'Updater';root=data/'USBControl'/did;protected=root/'config.json'
    names={'native':'GuardDesk-USBControl-'+did,'updater':'GuardDesk-AgentUpdater-'+did}
    paths={'native':native,'updater':updater};existing={n.casefold() for n in ops.names()};prior={}
    if trial:
        if updater.exists() or any(n.startswith('\\guarddesk-agentupdater-') for n in existing):
            raise OSError('遠端試用版不接管既有更新器；保留原安裝。')
        if native.exists() and not protected.exists():
            raise OSError('已存在無法確認為本次遠端試用的原生程式，保留原安裝。')
        names.pop('updater');paths.pop('updater')
    for role,name in names.items():
        if ('\\'+name).casefold() in existing:
            raw=ops.query(name);verify_lifecycle(raw,paths[role]/'GuardDesk.exe',protected,role);prior[role]=raw
    if action=='Install' and any(n.startswith('\\guarddesk-usbcontrol-') and n!=('\\'+names['native']).casefold() for n in existing):raise OSError('已有其他端點身分的原生工作；請 MIS 核對，不自動覆寫')
    if root.exists():ops.tree(root)
    for path in paths.values():
        if path.exists():ops.tree(path)
    old={}
    if protected.exists():
        old=read_json(protected)
        check_settings(settings,existing=old)
        if old.get('device_id')!=did:raise OSError('既有端點身分不符')
        if action=='Install' and any(old.get(k)!=settings.get(k) for k in ('server','token')):raise OSError('既有端點連線身分不符，保留原設定')
        if action=='Install' and old.get('update_key') and old['update_key']!=settings.get('update_key'):raise OSError('更新信任金鑰變更，保留原設定')
        if action=='Install' and old.get('browser_deployment') and settings.get('browser_deployment',old['browser_deployment'])!=old['browser_deployment']:raise OSError('既有瀏覽器部署來源變更，請 MIS 先核對／還原')
        assert_quiescent(root)
    if action=='Status':return {'installed':'native' in prior,'task':names['native']}
    if action=='Uninstall':
        for role in ('updater','native'):
            if role in prior:ops.stop(names[role],paths[role]/'GuardDesk.exe')
        if protected.exists():ops.invoke(native/'GuardDesk.exe','usb-worker','--extended','--config',protected,'--restore')
        for role in ('updater','native'):
            if role in prior:ops.delete(names[role])
        return {'status':'removed','files_retained':True}
    for key in ('server','token','watch'):
        if not isinstance(settings.get(key),str) or not settings[key]:raise ValueError('端點安裝設定不完整')
    packages.key_id(settings.get('update_key',''))
    browser=settings.get('browser_deployment') or (old.get('browser_deployment') if protected.exists() else None)
    authorization=None
    if browser:
        from .browser_deployment import verify_authorization
        authorization=settings.get('browser_deployment_authorization') if settings.get('browser_deployment') else old.get('browser_deployment_authorization')
        verify_authorization(browser,authorization,settings['update_key'])
    if (config.parent/'windows/usb-managed.json').exists():raise OSError('已有舊式手動 USB 控制，請 MIS 先核對與還原')
    entries,total=source_files(source);source=packages.plain(source)
    ca=None
    if settings.get('ca'):
        ca=Path(settings['ca'])
        if not ca.is_absolute():ca=config.parent.parent.parent/ca
        ca=packages.plain(ca)
        if ca.stat().st_size>65536 or b'PRIVATE KEY' in ca.read_bytes():raise ValueError('端點 CA 格式不正確')
    browser_trust=settings.get('browser_trust') or (old.get('browser_trust') if protected.exists() else None)
    if browser_trust:
        if protected.exists() and old.get('browser_trust') not in (None,browser_trust):raise ValueError('Browser CA trust migration requires MIS review')
        from .browser_trust import verify
        if not ca:raise ValueError('Original pinned CA required for browser trust')
        verify(browser_trust,settings['update_key'],settings['server'],ca.read_bytes(),browser)
    if shutil.disk_usage(program.parent).free<2*total+64*1024*1024:raise OSError('安裝磁碟空間不足，未停止原工作')
    for path in (program,data,data/'USBControl',root):ops.protect(path,create=True)
    unused=root/'unused-watch';ops.protect(unused,create=True)
    new={'server':settings['server'],'token':settings['token'],'device_id':did,'watch':str(unused),'audit_watch':settings.get('audit_watch',settings['watch']),'ca':str(root/'company-ca.pem') if ca else None,'update_key':settings['update_key']}
    # A repair using the protected config must retain its original audit scope
    # and explicit remote opt-ins, rather than adopting unused-watch as scope.
    for key in ('remote_admin_preview','remote_native_preview'):
        if key in settings or key in old:
            value=settings.get(key,old.get(key))
            if type(value) is not bool:raise ValueError('Remote preview flag must be boolean')
            new[key]=value
    from .machine_service import enabled as full_service
    if full_service():new.setdefault('remote_native_preview',True)
    if remote_test:new['remote_native_preview']=True
    if trial:new.update(install_profile=PROFILE,remote_native_preview=True)
    if browser:
        new['browser_deployment']=browser
        new['browser_deployment_authorization']=authorization
    if browser_trust:new['browser_trust']=browser_trust
    nonce=secrets.token_hex(8);stages={};backups={};switched=[];stopped=[];registered=[]
    prior_versions={}
    for role in prior:
        body=json.loads(ops.invoke(paths[role]/'GuardDesk.exe','component-info').decode('utf-8-sig'))
        packages.version(body.get('version'));prior_versions[role]=body['version']
    journal=root/'install-transaction.json';saved_config=protected.read_bytes() if protected.exists() else None
    saved_ca=(root/'company-ca.pem').read_bytes() if (root/'company-ca.pem').exists() else None
    current_phase=['native_prepare']
    prior_browser_ledger=(root/'browser-policy-owned.json').exists()
    browser_attempted=False
    prior_trust_ledger=(root/'browser-trust-owned.json').exists()
    trust_attempted=False
    def progress(phase):
        current_phase[0]=phase
        print('GUARDDESK_STAGE='+phase,flush=True)
        ops.write(journal,encode({'format':1,'phase':phase,'id':nonce,'version':__version__}))
    try:
        progress('prepare_programs')
        for role,target in paths.items():
            stage=program/(target.name+'.install-stage-'+nonce);ops.protect(stage,create=True);stages[role]=stage
            staged_total=0
            for name,digest in entries.items():
                dest=packages.plain(stage/name)
                for parent in reversed(dest.parent.relative_to(stage).parents):
                    if str(parent)!='.':ops.protect(stage/parent,create=True)
                if dest.parent!=stage:ops.protect(dest.parent,create=True)
                with dest.open('xb') as out:
                    actual,size=bounded_hash(source/name,packages.MAX_TOTAL-staged_total,out);staged_total+=size
                if actual!=digest:raise OSError('複製期間來源程式已變更，未切換原程式')
                ops.protect(dest)
                if packages.file_hash(dest)!=digest:raise OSError('複製後程式雜湊不符，未切換原程式')
            ops.tree(stage)
            if trial and role=='native':
                # Public code RX is installation work, never a startup repair.
                # Complete on the verified stage before stopping any old task.
                ops.public_runtime(stage)
        # Staging may take time. An existing broker/native refresh can have
        # begun since preflight; never overwrite an interrupted update tree.
        assert_quiescent(root,include_install=False)
        if remote_test:
            from .remote_test_install import preflight
            # Recheck the center after copying; a new update/remote request
            # may have appeared during staging. No existing task stopped yet.
            preflight(config,settings,source,staging=True)
        progress('stopping')
        for role in ('updater','native'):
            if role in prior:
                verify_lifecycle(ops.query(names[role]),paths[role]/'GuardDesk.exe',protected,role)
                ops.stop(names[role],paths[role]/'GuardDesk.exe');stopped.append(role)
        assert_quiescent(root,include_install=False)
        progress('switching')
        from .update_windows import rename_protected
        for role,target in paths.items():
            if target.exists():
                backup=program/(target.name+'.install-backup-'+nonce);rename_protected(target,backup);backups[role]=backup
            rename_protected(stages[role],target);switched.append(role)
        if ca:ops.write(root/'company-ca.pem',ca.read_bytes())
        ops.write(protected,encode(new))
        if browser_trust:
            progress('browser_trust');trust_attempted=True
            ops.invoke(native/'GuardDesk.exe','browser-trust','--config',protected,'--action','apply')
        progress('initial_policy')
        ops.invoke(native/'GuardDesk.exe','usb-worker','--extended','--config',protected,'--once')
        # Worker-created databases/baselines must also have trusted owners.
        for path in root.rglob('*'):ops.protect(path)
        progress('register_tasks');started=time.time()
        for role in paths:
            raw=lifecycle_body(paths[role]/'GuardDesk.exe',protected,role)
            registered.append(role)
            ops.register(names[role],raw,root)
            verify_lifecycle(ops.query(names[role]),paths[role]/'GuardDesk.exe',protected,role)
            ops.start(names[role])
            ops.health(root/('native-health.json' if role=='native' else 'broker-health.json'),__version__,paths[role]/'GuardDesk.exe',started)
        if browser:
            progress('browser_policy');browser_attempted=True
            ops.invoke(native/'GuardDesk.exe','browser-policy','--config',protected,'--action','apply')
        installed={'product':'GuardDesk-USBControl','task':names['native'],'config':str(protected),'executable':str(native/'GuardDesk.exe'),'version':__version__,'installed_at':time.time()}
        if isinstance(ops.query(names['native']),dict):installed.update(task=None,service='GuardDeskRemote',lifecycle='native-service-v1')
        ops.write(root/'installation.json',encode(installed))
        progress('complete')
        return {'status':'installer_completed','version':__version__,'backups_retained':list(map(str,backups.values()))}
    except Exception as original:
        failed_stage=current_phase[0]
        errors=[]
        if browser_attempted and not prior_browser_ledger and (root/'browser-policy-owned.json').exists():
            try:ops.invoke(native/'GuardDesk.exe','browser-policy','--config',protected,'--action','restore')
            except OSError as exc:errors.append('browser_policy_restore_'+type(exc).__name__)
        for role in reversed(registered):
            try:ops.stop(names[role],paths[role]/'GuardDesk.exe');ops.delete(names[role])
            except OSError as exc:errors.append(failure_evidence('stop_or_delete_'+role,exc))
        if trust_attempted and not prior_trust_ledger and (root/'browser-trust-owned.json').exists():
            try:ops.invoke(native/'GuardDesk.exe','browser-trust','--config',protected,'--action','restore')
            except OSError as exc:errors.append('browser_trust_restore_'+type(exc).__name__)
        if errors:
            # Never rename/delete files while a new worker may still use them.
            raise NativeInstallFailure(failed_stage,original,'新工作尚未確認停止；保留交易與程式，不自動覆寫。',errors) from original
        if not prior and 'native' in switched and protected.exists():
            try:ops.invoke(native/'GuardDesk.exe','usb-worker','--extended','--config',protected,'--restore')
            except OSError as exc:errors.append(type(exc).__name__)
            if errors:raise NativeInstallFailure(failed_stage,original,'首次安裝的控制還原未完成，保留新程式與原始狀態，不宣告回復成功。') from original
        try:
            from .update_windows import rename_protected
            for role in reversed(list(paths)):
                target=paths[role]
                if role in switched:rename_protected(target,program/(target.name+'.install-failed-'+nonce))
                if role in backups:rename_protected(backups[role],target)
            if saved_config is not None:ops.write(protected,saved_config)
            if saved_ca is not None:ops.write(root/'company-ca.pem',saved_ca)
            recovered_at=time.time()
            for role in reversed(stopped):
                ops.register(names[role],prior[role],root);ops.start(names[role])
                ops.health(root/('native-health.json' if role=='native' else 'broker-health.json'),prior_versions[role],paths[role]/'GuardDesk.exe',recovered_at)
        except OSError as exc:errors.append(type(exc).__name__)
        if not errors:progress('rolled_back' if switched or backups else 'failed_before_switch')
        if errors:raise NativeInstallFailure(failed_stage,original,'回復未確認完成，保留交易與備份，請 MIS 核對。') from original
        raise NativeInstallFailure(failed_stage,original,'已恢復前次程式／控制狀態；本次安裝尚未完成。') from original
