"""Protected SYSTEM broker. Its executable/runtime never share the replaced tree."""
import ctypes
import json
import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager,ExitStack
from pathlib import Path
from . import update_packages as packages
from .update_client import Transaction,probe,save,RetryUpdate
from . import __version__


def folder(csidl):
    buffer=ctypes.create_unicode_buffer(32768)
    if ctypes.windll.shell32.SHGetFolderPathW(None,csidl,None,0,buffer):raise OSError('無法取得 Windows 保護目錄')
    return Path(buffer.value)/'GuardDeskPilot'


def protected_tree(path,allow_current_user=False,recursive=True):
    """Reject writable owners/ACEs and reparse points before privileged execution."""
    from ctypes import wintypes as w
    adv=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32')
    adv.GetNamedSecurityInfoW.argtypes=[w.LPWSTR,ctypes.c_int,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID,ctypes.POINTER(w.LPVOID),w.LPVOID,ctypes.POINTER(w.LPVOID)]
    adv.GetNamedSecurityInfoW.restype=w.DWORD
    adv.ConvertSidToStringSidW.argtypes=[w.LPVOID,ctypes.POINTER(w.LPWSTR)];adv.ConvertSidToStringSidW.restype=w.BOOL
    adv.GetAclInformation.argtypes=[w.LPVOID,w.LPVOID,w.DWORD,ctypes.c_int];adv.GetAclInformation.restype=w.BOOL
    adv.GetAce.argtypes=[w.LPVOID,w.DWORD,ctypes.POINTER(w.LPVOID)];adv.GetAce.restype=w.BOOL
    kernel.LocalFree.argtypes=[w.LPVOID]
    class Info(ctypes.Structure):_fields_=[('count',w.DWORD),('used',w.DWORD),('free',w.DWORD)]
    def sid(value):
        text=w.LPWSTR()
        if not adv.ConvertSidToStringSidW(value,ctypes.byref(text)):raise ctypes.WinError(ctypes.get_last_error())
        try:return text.value
        finally:kernel.LocalFree(ctypes.cast(text,w.LPVOID))
    allowed={'S-1-5-18','S-1-5-32-544'}
    if allow_current_user:
        kernel.GetCurrentProcess.restype=w.HANDLE;kernel.CloseHandle.argtypes=[w.HANDLE]
        adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)];adv.OpenProcessToken.restype=w.BOOL
        adv.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)];adv.GetTokenInformation.restype=w.BOOL
        token=w.HANDLE();size=w.DWORD()
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(),8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
        try:
            adv.GetTokenInformation(token,1,None,0,ctypes.byref(size));buffer=ctypes.create_string_buffer(size.value)
            if not adv.GetTokenInformation(token,1,buffer,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
            allowed.add(sid(ctypes.cast(buffer,ctypes.POINTER(w.LPVOID))[0]))
        finally:kernel.CloseHandle(token)
    path=packages.plain(path)
    for entry in [path,*path.rglob('*')] if recursive else [path]:
        packages.plain(entry);owner=w.LPVOID();acl=w.LPVOID();descriptor=w.LPVOID()
        try:
            code=adv.GetNamedSecurityInfoW(str(entry),1,5,ctypes.byref(owner),None,ctypes.byref(acl),None,ctypes.byref(descriptor))
            if code:raise ctypes.WinError(code)
            if sid(owner) not in allowed or not acl:raise OSError('更新目錄擁有者／權限不受信任')
            info=Info()
            if not adv.GetAclInformation(acl,ctypes.byref(info),ctypes.sizeof(info),2):raise ctypes.WinError(ctypes.get_last_error())
            for index in range(info.count):
                ace=w.LPVOID()
                if not adv.GetAce(acl,index,ctypes.byref(ace)):raise ctypes.WinError(ctypes.get_last_error())
                kind=ctypes.c_ubyte.from_address(ace.value).value
                if kind in (1,2,3,6,7,8,10,12,13,14,15,16,17,18):continue  # deny/audit/labels cannot grant writes
                mask=ctypes.c_uint32.from_address(ace.value+4).value
                if mask&0x500D0156:
                    if kind!=0 or sid(ace.value+8) not in allowed:raise OSError('更新目錄可由非信任帳戶改寫')
        finally:
            if descriptor:kernel.LocalFree(descriptor)


def system_tool(name):
    buffer=ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buffer,len(buffer)):raise OSError('Windows 系統路徑不存在')
    return str(Path(buffer.value)/name)


def task_xml(name):
    result=subprocess.run([system_tool('schtasks.exe'),'/Query','/TN',name,'/XML'],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode or len(result.stdout)>65536:raise OSError('無法驗證受保護工作，保留現狀')
    return result.stdout


def task_command(name,action):
    if action not in ('/End','/Run','/Delete'):raise ValueError('更新工作動作不正確')
    args=[system_tool('schtasks.exe'),action,'/TN',name]+(['/F'] if action=='/Delete' else [])
    result=subprocess.run(args,capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise OSError('受保護工作操作失敗，請 MIS 檢查')


def process_image(pid):
    from ctypes import wintypes as w
    if type(pid) is not int or not 0<pid<=0xffffffff:raise ValueError('程序識別碼不正確')
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
    api.CloseHandle.argtypes=[w.HANDLE]
    api.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)];api.QueryFullProcessImageNameW.restype=w.BOOL
    handle=api.OpenProcess(0x1000,False,pid)
    if not handle:raise ctypes.WinError(ctypes.get_last_error())
    try:
        buffer=ctypes.create_unicode_buffer(32768);size=w.DWORD(len(buffer))
        if not api.QueryFullProcessImageNameW(handle,0,buffer,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        return Path(buffer.value).resolve()
    finally:api.CloseHandle(handle)


class NativeAdapter:
    def __init__(self,agent,check_only=False):
        self.agent=agent;did=agent.config['device_id']
        if not re.fullmatch('[0-9a-f]{24}',did):raise ValueError('端點識別碼不正確')
        self.program=folder(0x26);self.native=self.program/'USBControl';self.updater=self.program/'Updater'
        expected=folder(0x23)/'USBControl'/did/'config.json'
        if agent.config_path!=expected.resolve():raise OSError('受保護設定路徑不正確')
        if not check_only and (Path(sys.executable).resolve()!=self.updater/'GuardDesk.exe' or not getattr(sys,'frozen',False)):raise OSError('只允許受保護安裝的更新元件執行')
        protected_tree(self.updater);protected_tree(agent.config_path.parent)
        if self.native.exists():protected_tree(self.native)
        packages.key_id(agent.config.get('update_key',''))
        self.name='GuardDesk-USBControl-'+did
        self._version=None
        self._validate_task()
    def _validate_task(self):
        self.service=None
        from .machine_service import enabled
        if enabled():
            from .remote_service import Service,description,verify
            service=Service();raw=service.query()
            if raw:
                from .native_installer import Windows
                if ('\\'+self.name).casefold() in {n.casefold() for n in Windows().names()}:
                    raise OSError('Both service and legacy native task exist; preserve installation')
                verify(raw,self.native/'GuardDesk.exe',self.agent.config_path,'native')
                self.service=service;self.service_expected=description(self.native/'GuardDesk.exe',self.agent.config_path)
                return
        from .decommission import validate_task
        validate_task(task_xml(self.name),self.native/'GuardDesk.exe',self.agent.config_path)
    def current(self):
        if self._version is None:self._version=probe(self.native)
        return self._version
    def probe(self,path):return probe(path)
    def stage(self,job):return packages.plain(self.program/('USBControl.stage-'+job['id']))
    def validate_stage(self,path):
        from .remote_components import validate_layout
        protected_tree(path);validate_layout(path)
    def budget(self,incoming):
        from .update_client import storage_budget
        storage_budget([self.program,self.agent.config_path.parent/'updates'],incoming)
    def stop(self):
        from .single_instance import machine_instance
        from .update_windows import image_processes
        from .remote_components import installed_images
        self._validate_task()
        with ExitStack() as stack:
            waits=[stack.enter_context(image_processes(image)) for image in installed_images(self.native)]
            deadline=time.monotonic()+30
            try:
                with machine_instance('usb',self.agent.config['device_id']):running=False
            except OSError:running=True
            if getattr(self,'service',None):self.service.action(self.service_expected,'stop')
            elif running:task_command(self.name,'/End')
            while True:
                try:
                    with machine_instance('usb',self.agent.config['device_id']):break
                except OSError:
                    if time.monotonic()>=deadline:raise OSError('舊版原生元件未停止，未替換程式')
                    time.sleep(.25)
            for wait in waits:wait(deadline)
        # A child may have been starting between the first snapshot and /End.
        # Parent is now gone; capture remaining fixed-image handles once more.
        with ExitStack() as stack:
            waits=[stack.enter_context(image_processes(image)) for image in installed_images(self.native)]
            for wait in waits:wait(deadline)
    def switch(self,state,write):
        from .update_windows import rename_protected
        protected_tree(self.native);protected_tree(Path(state['stage']))
        backup=packages.plain(self.program/('USBControl.rollback-'+state['job']['id']))
        if backup.exists():raise OSError('回復目錄已存在，保留現況')
        state['backup']=str(backup);state['phase']='switching';write(state)
        rename_protected(self.native,backup);state['phase']='old_moved';write(state)
        rename_protected(Path(state['stage']),self.native)
    def start(self,state,rollback):
        protected_tree(self.native);self._validate_task()
        if getattr(self,'service',None):self.service.action(self.service_expected,'start')
        else:task_command(self.name,'/Run')
    def health(self,version,started,timeout):
        deadline=time.monotonic()+timeout
        while True:
            try:
                report=json.loads((self.agent.config_path.parent/'native-health.json').read_text(encoding='utf-8'))
                if report['version']==version and report['time']>=started and time.time()-report['time']<90:
                    from ctypes import wintypes as w
                    api=ctypes.WinDLL('kernel32');api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE;api.CloseHandle.argtypes=[w.HANDLE]
                    api.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)];api.QueryFullProcessImageNameW.restype=w.BOOL
                    handle=api.OpenProcess(0x1000,False,report['pid'])
                    if handle:
                        try:
                            buffer=ctypes.create_unicode_buffer(32768);size=w.DWORD(len(buffer))
                            if api.QueryFullProcessImageNameW(handle,0,buffer,ctypes.byref(size)) and Path(buffer.value).resolve()==self.native/'GuardDesk.exe':
                                self._version=version;return True
                        finally:api.CloseHandle(handle)
            except (OSError,ValueError,KeyError):pass
            if time.monotonic()>=deadline:return False
            time.sleep(.5)
    def rollback(self,state):
        from .update_windows import rename_protected
        backup=packages.plain(self.program/('USBControl.rollback-'+state['job']['id']))
        if backup.exists():
            self.stop();protected_tree(backup)
            if self.native.exists():
                failed=packages.plain(self.program/('USBControl.failed-'+state['job']['id']))
                if failed.exists():raise OSError('失敗程式保留目錄衝突，請 MIS 處理')
                rename_protected(self.native,failed)
            rename_protected(backup,self.native)
        self.start(state,True)
        if not self.health(state['old_version'],time.time()-2,45):raise OSError('舊版原生元件未確認恢復，請 MIS 檢查')
    def cleanup(self,state):
        from .update_client import remove_managed
        # Keep the renamed previous version only until the transaction confirms
        # the replacement is healthy. Do not retain a historical backup after
        # success. An interrupted/failed switch must still be recoverable.
        if state.get('phase')!='healthy':raise OSError('更新未確認成功，不清理交易中的程式')
        for path in self.program.iterdir():
            if re.fullmatch(r'USBControl\.(rollback|failed|stage)-[0-9a-f]{32}',path.name):
                remove_managed(self.program,path,r'USBControl\.(rollback|failed|stage)-[0-9a-f]{32}',True)


def broker_error(agent,code,exc):
    from .update_notify import diagnostic
    try:save(agent.config_path.parent/'update-broker-status.json',{'state':'needs_review_or_retry','code':code,'error_type':type(exc).__name__,'time':time.time()})
    except (OSError,ValueError):pass
    diagnostic(agent,'native',code)


@contextmanager
def broker_scope(agent):
    from .single_instance import machine_instance
    from .performance import background_work
    try:
        with machine_instance('update',agent.config['device_id']),background_work():yield
    except Exception as exc:
        broker_error(agent,'initialization_failed',exc)
        raise


def run(config,stop):
    from .remote_trial import reject
    reject('Automatic native update')
    from .agent import Agent
    from .windows_privilege import is_admin
    if os.name!='nt' or not is_admin():raise PermissionError('更新服務只允許受保護的 SYSTEM／管理員工作')
    agent=Agent(config)
    with broker_scope(agent):
        from .update_notify import Waiter
        adapter=None;transaction=None;waiter=Waiter('native')
        while not stop.is_set():
            phase='initialization_failed'
            try:
                from .decommission import saved
                if saved(agent):return
                if adapter is None:
                    candidate=NativeAdapter(agent)
                    transaction=Transaction(agent,'native',candidate);adapter=candidate
                phase='recovery_failed'
                transaction.recover()
                current=adapter.current()
                save(agent.config_path.parent/'broker-health.json',{'version':__version__,'native_version':current,'pid':os.getpid(),'time':time.time()})
                from .updater_refresh import pending
                if pending(agent):stop.wait(1);continue
                phase='transport_failed'
                reply=agent.call('/api/agent/updates/poll',{'role':'native','version':current,'broker_version':__version__})
                if reply.get('job'):
                    phase='execution_failed'
                    try:transaction.apply(reply['job'])
                    except RetryUpdate:
                        from .update_client import validate_job
                        job,_=validate_job(reply['job'],agent.config['update_key'],agent.config['device_id'])
                        try:transaction.report(job,'waiting',adapter.current(),'下載暫時中斷，連線恢復後重試')
                        except ConnectionError:pass
                    except Exception:
                        state=json.loads(transaction.journal.read_text(encoding='utf-8')) if transaction.journal.is_file() else None
                        if not state or state['phase'] not in ('healthy','rolled_back'):
                            from .update_client import validate_job
                            job,_=validate_job(reply['job'],agent.config['update_key'],agent.config['device_id'])
                            transaction.report(job,'failed',adapter.current(),(state or {}).get('error') or '受保護更新未完成，保留程式與備份，請 MIS 檢查')
                        raise
            except Exception as exc:
                # Protected, bounded diagnostic. Never clear policy or execute a fallback payload.
                broker_error(agent,phase,exc)
                stop.wait(30)
                continue
            waiter.wait(agent,stop)


def check_installed(device_id):
    """Explicit local MIS check: no update transaction, tasks or registry writes."""
    from .windows_privilege import is_admin
    from types import SimpleNamespace
    if os.name!='nt' or not is_admin():raise PermissionError('請 MIS 以系統管理員開啟命令提示字元後執行此唯讀檢查')
    if not isinstance(device_id,str) or not re.fullmatch('[0-9a-f]{24}',device_id):raise ValueError('端點識別碼不正確')
    config=folder(0x23)/'USBControl'/device_id/'config.json'
    try:
        packages.plain(config);protected_tree(config.parent)
        if config.stat().st_size>16384:raise ValueError('設定檔過大')
        agent=SimpleNamespace(config_path=config.resolve(),config=json.loads(config.read_text(encoding='utf-8-sig')))
        if agent.config.get('device_id')!=device_id:raise ValueError('設定端點身分不符')
        adapter=NativeAdapter(agent,check_only=True)
        return {'passed':True,'native_version':adapter.current(),'check_only':True,'note':'驗證目錄、固定公鑰、工作身分及程式版本；未執行更新或啟動／停止工作'}
    except (OSError,ValueError,KeyError) as exc:
        return {'passed':False,'check_only':True,'error_type':type(exc).__name__,'error':str(exc)[:800]}


def remove_broker_task(agent):
    if not agent.config.get('update_key'):return
    from .decommission import validate_task,parse_task_xml
    name='GuardDesk-AgentUpdater-'+agent.config['device_id']
    # Reuse fixed task validation by normalizing only the locally expected verb.
    xml=task_xml(name)
    import xml.etree.ElementTree as ET
    root=parse_task_xml(xml);ns={'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    args=root.find('t:Actions/t:Exec/t:Arguments',ns)
    expected='update-service --config "'+str(agent.config_path)+'"'
    if args is None or args.text!=expected:raise OSError('更新工作身分不符，保留原工作')
    args.text='usb-worker --extended --config "'+str(agent.config_path)+'"'
    validate_task(ET.tostring(root),folder(0x26)/'Updater/GuardDesk.exe',agent.config_path)
    task_command(name,'/End');task_command(name,'/Delete')
