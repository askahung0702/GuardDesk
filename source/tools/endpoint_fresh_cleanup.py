"""Fixed post-uninstall cleanup for DEV-01, user1 and LAB01. Never restores by guess.

Run after the center's two removal roles are complete. No shell, task creation,
process killing, policy changes, endpoint registration, or arbitrary path input.
"""
from contextlib import contextmanager, ExitStack
from contextlib import closing
import csv
import ctypes
import io
from itertools import islice
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import uuid

HOSTS={'DEV-01','user1','LAB01'}
DID=re.compile('[0-9a-f]{24}')
MAX_NODES=50000
MAX_DEPTH=40
RUN=r'Software\Microsoft\Windows\CurrentVersion\Run'
HOST_KEYS=(r'Software\Google\Chrome\NativeMessagingHosts\com.guarddesk.agent',
           r'Software\Microsoft\Edge\NativeMessagingHosts\com.guarddesk.agent')


class CleanupError(OSError):pass


def io_path(path):
    """Extended local DOS path for OS calls only, not an accepted input namespace.

    Keep logical paths for scope comparisons/reporting. Never reinterpret UNC,
    device, relative, ADS or trailing-dot/space paths under extended semantics.
    No OS long-path registry/policy switch is required.
    """
    path=Path(path)
    if os.name!='nt':return str(path)
    value=str(path)
    if (value.startswith('\\\\') or not path.is_absolute() or
        not re.fullmatch('[A-Za-z]:',path.drive) or
        any(part in ('.','..') or ':' in part or part.endswith((' ','.')) for part in path.parts[1:])):
        raise CleanupError('LOCAL_CANONICAL_PATH_REQUIRED')
    if len(value.encode('utf-16-le'))//2+5>=32767:raise CleanupError('EXTENDED_PATH_LIMIT')
    return '\\\\?\\'+value


def entries(path,limit):
    path=Path(path)
    with os.scandir(io_path(path)) as items:
        values=[path/item.name for item in islice(items,limit+1)]
    if len(values)>limit:raise CleanupError('DIRECTORY_ENTRY_LIMIT: '+str(path))
    return values


def optional_entries(path,limit):
    # Missing is distinct from AccessDenied. Never use exists() to hide a
    # permission error and then fall back to a less protected installation.
    try:return entries(plain(path),limit)
    except FileNotFoundError:return []


def read_json(path):
    with Path(path).open('rb') as stream:raw=stream.read(1024*1024+1)
    if len(raw)>1024*1024:raise CleanupError('METADATA_TOO_LARGE')
    value=json.loads(raw)
    if not isinstance(value,dict):raise CleanupError('INVALID_METADATA')
    return value


def contained(path,root):
    # Absolute lexical comparison, never resolve a potentially redirected path.
    path=Path(os.path.abspath(path));root=Path(os.path.abspath(root))
    return path==root or root in path.parents


def plain(path):
    path=Path(os.path.abspath(path))
    if str(path).startswith(('\\\\','\\?\\')):raise CleanupError('LOCAL_PATH_REQUIRED')
    for part in (path,*path.parents):
        if os.path.lexists(io_path(part)):
            info=os.stat(io_path(part),follow_symlinks=False)
            if info.st_file_attributes&0x400:raise CleanupError('REPARSE_POINT: '+str(part))
    return path


class Files:
    """Pin each ancestor against replacement; delete only by its open handle."""
    def __init__(self):
        from ctypes import wintypes as w
        self.w=w;self.api=ctypes.WinDLL('kernel32',use_last_error=True);self.images=set()
        self.api.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE]
        self.api.CreateFileW.restype=w.HANDLE
        self.api.CloseHandle.argtypes=[w.HANDLE]
        self.api.GetFileInformationByHandleEx.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD]
        self.api.GetFileInformationByHandleEx.restype=w.BOOL
        self.api.SetFileInformationByHandle.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD]
        self.api.SetFileInformationByHandle.restype=w.BOOL

    @contextmanager
    def handle(self,path,delete=False):
        # READ_DATA/LIST_DIRECTORY + READ_ATTRIBUTES, optional DELETE.
        # An attributes-only open does not establish the required sharing pin.
        h=self.api.CreateFileW(io_path(path),0x81|(0x10000 if delete else 0),3,None,3,0x02200000,None)
        if h==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
        class Tag(ctypes.Structure):_fields_=[('attributes',self.w.DWORD),('tag',self.w.DWORD)]
        try:
            tag=Tag()
            if not self.api.GetFileInformationByHandleEx(h,9,ctypes.byref(tag),ctypes.sizeof(tag)):
                raise ctypes.WinError(ctypes.get_last_error())
            if tag.attributes&0x400:raise CleanupError('REPARSE_POINT: '+str(path))
            yield h,bool(tag.attributes&0x10)
        finally:self.api.CloseHandle(h)

    @contextmanager
    def pinned(self,path):
        path=plain(path)
        with ExitStack() as stack:
            for parent in reversed(path.parents):stack.enter_context(self.handle(parent))
            stack.enter_context(self.handle(path))
            yield

    def inspect(self,root,deadline):
        count=0;total=0
        def visit(path,depth):
            nonlocal count,total
            count+=1
            if count>MAX_NODES or depth>MAX_DEPTH or time.monotonic()>deadline:raise CleanupError('TREE_LIMIT: '+str(root))
            with self.handle(path) as (_,directory):
                if directory:
                    with os.scandir(io_path(path)) as entries:
                        for entry in entries:visit(path/entry.name,depth+1)
                else:
                    info=os.stat(io_path(path))
                    if info.st_nlink!=1:raise CleanupError('HARDLINK: '+str(path))
                    if path.name.casefold() in ('guarddesk.exe','guarddeskagent.exe','guarddeskmis.exe','guarddeskremote.exe',
                                                'guarddeskremoteworker.exe','guarddeskremotemedia.exe'):
                        self.images.add(path)
                    total+=info.st_size
        with self.pinned(root.parent):visit(root,0)
        return dict(objects=count,bytes=total)

    def delete(self,root,deadline,progress):
        count=0
        def visit(path,depth):
            nonlocal count
            count+=1
            if count>MAX_NODES or depth>MAX_DEPTH or time.monotonic()>deadline:raise CleanupError('DELETE_LIMIT: '+str(root))
            with self.handle(path,delete=True) as (handle,directory):
                if directory:
                    with os.scandir(io_path(path)) as entries:
                        names=[entry.name for entry in islice(entries,MAX_NODES-count+1)]
                    if len(names)+count>MAX_NODES:raise CleanupError('TREE_LIMIT: '+str(root))
                    for name in names:visit(path/name,depth+1)
                elif os.stat(io_path(path)).st_nlink!=1:raise CleanupError('HARDLINK: '+str(path))
                # FileDispositionInfo uses BOOL, no path-based recursive delete.
                flag=self.w.BOOL(True)
                if not self.api.SetFileInformationByHandle(handle,4,ctypes.byref(flag),ctypes.sizeof(flag)):
                    raise ctypes.WinError(ctypes.get_last_error())
            if count%250==0:progress('Deleted objects: '+str(count),flush=True)
        with self.pinned(root.parent):visit(root,0)
        if os.path.lexists(io_path(root)):raise CleanupError('DELETE_NOT_COMPLETE: '+str(root))
        return count


class Registry:
    def __init__(self):
        import winreg
        self.w=winreg;self.hive_journal=None;self.hive_events=[]

    def record_hive(self,event):
        if self.hive_journal is None:return
        if len(self.hive_events)>=2048:raise CleanupError('REGISTRY_MOUNT_JOURNAL_LIMIT')
        self.hive_events.append(event)
        # The backup-first caller supplies its already protected backup path.
        path=plain(self.hive_journal)
        path.write_text(json.dumps(self.hive_events,ensure_ascii=False,indent=2),encoding='utf-8')

    @contextmanager
    def offline_hive(self,hive):
        """Transfer the leaf sharing pin to the registry's exclusive open.

        Keep ancestors pinned throughout. A metadata-only retained handle is
        NOT a sharing pin; compare its file identity after loading, then verify
        that the registry excludes DELETE opens before exposing the hive key.
        Never relax Files.handle's data-access pin used for backup/deletion.
        """
        from ctypes import wintypes as t
        hive=plain(hive);files=Files();api=files.api
        class Info(ctypes.Structure):
            _fields_=[('attributes',t.DWORD),('created',t.FILETIME),('accessed',t.FILETIME),
                      ('written',t.FILETIME),('volume',t.DWORD),('size_high',t.DWORD),
                      ('size_low',t.DWORD),('links',t.DWORD),('index_high',t.DWORD),('index_low',t.DWORD)]
        api.GetFileInformationByHandle.argtypes=[t.HANDLE,ctypes.POINTER(Info)]
        api.GetFileInformationByHandle.restype=t.BOOL
        invalid=ctypes.c_void_p(-1).value
        @contextmanager
        def metadata():
            handle=api.CreateFileW(io_path(hive),0x80,3,None,3,0x02200000,None)
            if handle==invalid:raise ctypes.WinError(ctypes.get_last_error())
            try:
                value=Info()
                if not api.GetFileInformationByHandle(handle,ctypes.byref(value)):raise ctypes.WinError(ctypes.get_last_error())
                if value.attributes&0x410 or value.links!=1:raise CleanupError('OFFLINE_HIVE_REPARSE_DIRECTORY_OR_HARDLINK')
                yield (value.volume,value.index_high,value.index_low)
            finally:api.CloseHandle(handle)
        from tools.endpoint_registry_hive import loaded_user_hive
        with files.pinned(hive.parent),metadata() as before:
            with loaded_user_hive(hive,record=self.record_hive) as key:
                with metadata() as after:
                    if before!=after:raise CleanupError('OFFLINE_HIVE_REPLACED_DURING_LOAD')
                # The loaded hive must now retain the no-rename/no-delete pin.
                probe=api.CreateFileW(io_path(hive),0x10000,7,None,3,0x02200000,None)
                if probe!=invalid:
                    api.CloseHandle(probe);raise CleanupError('OFFLINE_HIVE_EXCLUSIVE_PIN_NOT_ESTABLISHED')
                if ctypes.get_last_error()!=32:raise CleanupError('OFFLINE_HIVE_EXCLUSIVE_PIN_UNVERIFIED')
                yield key

    def profiles(self):
        w=self.w;result=[]
        with w.OpenKey(w.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') as key:
            count=w.QueryInfoKey(key)[0]
            if count>256:raise CleanupError('TOO_MANY_PROFILES')
            for i in range(count):
                sid=w.EnumKey(key,i)
                if not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',sid):continue
                with w.OpenKey(key,sid) as child:path,kind=w.QueryValueEx(child,'ProfileImagePath')
                if kind not in (w.REG_SZ,w.REG_EXPAND_SZ) or not isinstance(path,str):raise CleanupError('PROFILE_PATH_INVALID')
                profile=plain(os.path.expandvars(path))
                if not profile.is_absolute() or profile==Path(profile.anchor):raise CleanupError('PROFILE_PATH_INVALID')
                client=plain(profile/'AppData/Local/GuardDeskPilotClient')
                if client.exists():result.append((sid,profile,client))
        return result

    @contextmanager
    def hive(self,sid,profile):
        w=self.w
        try:key=w.OpenKey(w.HKEY_USERS,sid,0,w.KEY_READ|w.KEY_WRITE)
        except FileNotFoundError:
            hive=plain(profile/'NTUSER.DAT')
            with self.offline_hive(hive) as key:yield key
            return
        try:yield key
        finally:key.Close()

    def changes(self,key,client,did):
        w=self.w;changes=[]
        def value(path,name):
            try:
                with w.OpenKey(key,path) as node:return w.QueryValueEx(node,name)
            except FileNotFoundError:return None
        run=value(RUN,'GuardDesk-Agent-'+did)
        if run is not None:
            command,kind=run
            if kind!=w.REG_SZ or not isinstance(command,str) or len(command)>32768:raise CleanupError('RUN_CONFLICT')
            # Exact leading executable under this client's private app subtree.
            matched=re.fullmatch(r'"([^"\r\n]+)"\s+desktop-agent(?:\s+--config\s+"[^"\r\n]+")?',command)
            if not matched or not contained(matched[1],client/'app') or Path(matched[1]).name!='GuardDeskAgent.exe':
                raise CleanupError('RUN_CONFLICT')
            changes.append((RUN,'GuardDesk-Agent-'+did,run,False))
        enrollment=value(r'Software\GuardDesk','AgentConfig')
        if enrollment is not None:
            pointer,kind=enrollment
            if kind!=w.REG_SZ or not isinstance(pointer,str) or not contained(pointer,client/'runtime'):
                raise CleanupError('NATIVE_HOST_CONFIG_CONFLICT')
            changes.append((r'Software\GuardDesk','AgentConfig',enrollment,False))
        for path in HOST_KEYS:
            manifest=value(path,'')
            if manifest is None:continue
            if manifest[1]!=w.REG_SZ or not isinstance(manifest[0],str) or not contained(manifest[0],client/'runtime'):
                raise CleanupError('NATIVE_HOST_MANIFEST_CONFLICT')
            with w.OpenKey(key,path) as node:
                subkeys,values,_=w.QueryInfoKey(node)
                if subkeys or values!=1:raise CleanupError('NATIVE_HOST_KEY_CONFLICT')
            changes.append((path,'',manifest,True))
        return changes

    def apply(self,key,changes):
        w=self.w
        for path,name,expected,remove_key in changes:
            with w.OpenKey(key,path,0,w.KEY_READ|w.KEY_SET_VALUE) as node:
                if w.QueryValueEx(node,name)!=expected:raise CleanupError('REGISTRY_CHANGED_DURING_CLEANUP')
                if not remove_key:w.DeleteValue(node,name)
            if remove_key:w.DeleteKey(key,path)


def profile_ids(client):
    # Do not mix another center/enrollment into this reset. Never read user files.
    found=set()
    candidates=[client/'runtime/agent/config.json',client/'runtime/agent/pre-machine-config.json']
    machine=client/'runtime/machine-agent'
    if machine.exists():
        children=entries(machine,64)
        for child in children:
            if DID.fullmatch(child.name):found.add(child.name)
    for path in candidates:
        if path.exists():
            plain(path);value=read_json(path).get('device_id')
            if not isinstance(value,str) or not DID.fullmatch(value):raise CleanupError('PROFILE_ID_INVALID')
            found.add(value)
    return found


def check_profile(client,did):
    if profile_ids(client)!={did}:raise CleanupError('PROFILE_ID_CONFLICT_OR_UNKNOWN: '+str(client))
    # PilotDocuments can contain user material: it is not an Agent cache.
    documents=client/'PilotDocuments'
    if documents.exists() and any(documents.iterdir()):raise CleanupError('USER_DOCUMENTS_PRESENT: '+str(documents))


class Windows:
    def __init__(self):
        self.files=Files();self.registry=Registry()
        from guarddesk.update_native import folder,system_tool
        self.program=folder(38);self.data=folder(35);self.tool=system_tool('schtasks.exe')

    def hostname(self):
        from ctypes import wintypes as w
        size=w.DWORD(256);buffer=ctypes.create_unicode_buffer(size.value)
        if not ctypes.windll.kernel32.GetComputerNameW(buffer,ctypes.byref(size)):raise ctypes.WinError()
        return buffer.value.upper()

    def no_tasks(self):
        result=subprocess.run([self.tool,'/Query','/FO','CSV','/NH'],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode or len(result.stdout)>16*1024*1024:raise CleanupError('TASK_CATALOG_UNAVAILABLE')
        for row in csv.reader(io.StringIO(result.stdout.decode('oem'))):
            if row and row[0].casefold().startswith(('\\guarddesk-usbcontrol-','\\guarddesk-agentupdater-')):
                raise CleanupError('UNINSTALL_REQUIRED_TASK_PRESENT: '+row[0])

    def identity(self):
        path=plain(self.data/'USBControl')
        children=optional_entries(path,512)
        values=[entry for entry in children if DID.fullmatch(entry.name) and entry.is_dir()]
        self.identity_profiles=self.registry.profiles()
        if len(values)>1:raise CleanupError('MULTIPLE_MACHINE_IDENTITIES: '+str(len(values)))
        if len(values)!=len(children):raise CleanupError('UNKNOWN_MACHINE_IDENTITY_ENTRY')
        if values:
            root=plain(values[0]);config=read_json(plain(root/'config.json'))
            if config.get('device_id')!=root.name:raise CleanupError('OLD_DEVICE_ID_MISMATCH')
            did=root.name;layout='machine'
        else:
            found=set()
            for _,_,client in self.identity_profiles:found.update(profile_ids(client))
            if not found:raise CleanupError('OLD_IDENTITY_NOT_FOUND_IN_MACHINE_OR_PROFILES')
            if len(found)!=1:raise CleanupError('MULTIPLE_PROFILE_IDENTITIES: '+str(len(found)))
            did=next(iter(found));layout='legacy_profiles';root=None
            for _,_,client in self.identity_profiles:check_profile(client,did)
        marker=plain(self.program/'machine-endpoint.json')
        if marker.exists() and read_json(marker).get('device_id')!=did:
            raise CleanupError('MACHINE_MARKER_ID_CONFLICT')
        self.last_result=dict(company_changed=False,deleted=[],old_device_id=did,
                              identity_layout=layout,profile_count=len(self.identity_profiles),
                              center_state_verified=False)
        return did,root

    def no_processes(self):
        from guarddesk.native_installer import system_query_scope
        from guarddesk.update_windows import image_processes
        with system_query_scope():
            for image in self.files.images:
                with image_processes(image) as wait:wait(time.monotonic())

    def validate_layout(self):
        program=re.compile(r'(?:USBControl|Updater)(?:\.(?:rollback|stage|failed|install-stage|install-backup|install-failed)-[a-zA-Z0-9_-]+)?')
        # The earlier fixed DEV/user1 broker repair tools use uuid4().hex for
        # these three retained trees. Do not accept arbitrary repair-* names,
        # another component's prefix, files, or a redirected directory.
        repair=re.compile(r'Updater\.repair-(?:stage|backup|failed)-[0-9a-f]{32}')
        for item in optional_entries(self.program,512):
            if repair.fullmatch(item.name):
                if not plain(item).is_dir():raise CleanupError('UNKNOWN_PROGRAM_ROOT_ENTRY: '+item.name)
                continue
            if not program.fullmatch(item.name) and item.name!='machine-endpoint.json':
                raise CleanupError('UNKNOWN_PROGRAM_ROOT_ENTRY: '+item.name)
        for item in optional_entries(self.data,512):
            if item.name not in ('USBControl','RepairArchive','OwnedRemoteUacProbe'):
                raise CleanupError('UNKNOWN_DATA_ROOT_ENTRY: '+item.name)

    def removal_complete(self,root):
        if root is None:
            # endpoint_setup.uninstall writes 'removed' only after its native
            # uninstall, Native Host and autostart removal return successfully.
            # A main removal_job=done alone never proves native restoration.
            for _,_,client in self.identity_profiles:
                marker=plain(client/'endpoint-install.json')
                try:state=read_json(marker)
                except FileNotFoundError:raise CleanupError('LEGACY_LOCAL_UNINSTALL_REQUIRED: '+str(client)) from None
                config=plain(client/'runtime/agent/config.json')
                pointer=state.get('config')
                if (state.get('product')!='GuardDeskEndpoint' or not isinstance(pointer,str)
                    or not Path(pointer).is_absolute() or plain(pointer)!=config):
                    raise CleanupError('LEGACY_UNINSTALL_MARKER_CONFLICT: '+str(client))
                if state.get('phase')!='removed':
                    raise CleanupError('LEGACY_LOCAL_UNINSTALL_REQUIRED: '+str(client))
                settings=read_json(config)
                if settings.get('proxy_enabled') or (config.parent/'windows/installed.json').exists():
                    raise CleanupError('LEGACY_CONTROL_RESTORATION_REQUIRED: '+str(client))
            self.completion_source='legacy_endpoint_uninstall_removed'
            return
        database=plain((root/'config.json').with_suffix('.sqlite3'))
        # This is a local completion guard, not a server attestation.
        with closing(sqlite3.connect(database.as_uri()+'?mode=ro',uri=True)) as db:
            deadline=time.monotonic()+3
            db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
            row=db.execute("SELECT value FROM state WHERE key='removal_job'").fetchone()
        if row and (not isinstance(row[0],str) or len(row[0])>16384):raise CleanupError('REMOVAL_METADATA_TOO_LARGE')
        if not row or json.loads(row[0]).get('phase')!='done':raise CleanupError('CENTER_UNINSTALL_COMPLETION_REQUIRED')
        self.completion_source='machine_native_removal_done'


def execute(platform,clean,progress=print):
    host=platform.hostname()
    if host not in HOSTS:raise CleanupError('HOST_NOT_AUTHORIZED: '+host)
    did,root=platform.identity()
    platform.no_tasks();platform.removal_complete(root)
    platform.validate_layout()
    # Exact fixed roots. The workspace / Windows / profile home are never targets.
    targets=[plain(platform.program),plain(platform.data)]
    profiles=platform.identity_profiles
    for sid,profile,client in profiles:check_profile(client,did);targets.append(client)
    executable=Path(sys.executable).absolute()
    for target in targets:
        if target.name not in ('GuardDeskPilot','GuardDeskPilotClient') or contained(executable,target):
            raise CleanupError('TARGET_BOUNDARY_INVALID')
    # Refuse an accidental management-server directory even on the workstation.
    for target in targets[:2]:
        for name in ('server-config.json','server.json','control.sqlite3','tls','server'):
            if (target/name).exists():raise CleanupError('SERVER_DATA_PRESENT: '+str(target/name))
    report=dict(result='CHECKED_READY' if not clean else 'CLEANING',host=host,old_device_id=did,
                identity_layout=platform.last_result['identity_layout'],completion_source=platform.completion_source,
                center_state_verified=False,uninstall_local_completion_checked=True,deleted=[],registry_profiles_cleaned=[],
                company_changed=False,targets=[],server_history_deleted=False,new_endpoint_registered=False)
    platform.last_result=report
    # Keep all target parents pinned across registry and file operations.
    with ExitStack() as stack:
        for target in targets:
            if not target.exists():continue
            stack.enter_context(platform.files.pinned(target.parent))
            measured=platform.files.inspect(target,time.monotonic()+120)
            report['targets'].append(dict(path=str(target),**measured))
        opened=[]
        for sid,profile,client in profiles:
            key=stack.enter_context(platform.registry.hive(sid,profile))
            opened.append((sid,key,platform.registry.changes(key,client,did)))
        platform.no_processes()
        if not clean:return report
        platform.no_tasks()
        report['company_changed']=True
        for sid,key,changes in opened:
            platform.registry.apply(key,changes);report['registry_profiles_cleaned'].append(sid)
        # Private files first; machine identity remains until these are removed.
        for target in [*targets[2:],targets[0],targets[1]]:
            platform.no_tasks();platform.no_processes()
            if target.exists():
                progress('Remove Agent directory: '+str(target),flush=True)
                count=platform.files.delete(target,time.monotonic()+180,progress)
                report['deleted'].append(dict(path=str(target),objects=count))
        report['result']='CLEANED_READY_FOR_NEW_ENROLLMENT'
    return report


def next_action(message):
    if message.startswith('LEGACY_LOCAL_UNINSTALL_REQUIRED'):
        return ('已找到使用者舊安裝，但缺少完整本機解除安裝完成記錄。請在原安裝帳號正常雙擊 '
                '%LOCALAPPDATA%\\GuardDeskPilotClient\\Uninstall-Endpoint.cmd，原生步驟再由 MIS 核准 UAC；'
                '不要先以另一管理員帳號執行整個 CMD。成功後重跑 01 預檢；若解除安裝失敗，保留其完整錯誤，不刪或改完成狀態。')
    if message.startswith('OLD_IDENTITY_NOT_FOUND'):
        return '全機與 ProfileList 固定使用者目錄均未找到舊身分；保留資料，核對原安裝位置，不會猜測裝置 ID 清除。'
    if message.startswith(('MULTIPLE_','PROFILE_ID_CONFLICT','MACHINE_MARKER_ID_CONFLICT')):
        return '發現多筆或不一致的舊身分，已停止；請保留此報告，不要更名設定或任選一筆刪除。'
    if message.startswith('CENTER_UNINSTALL_COMPLETION_REQUIRED'):
        return '仍有全機身分，但原生解除安裝尚無 done 記錄；請先核對中心兩元件移除完成，不用私人移除紀錄取代原生還原。'
    return None


def main():
    from guarddesk.windows_controls import is_admin
    from guarddesk.single_instance import machine_instance
    args=sys.argv[1:]
    if args not in (['--check'],['--cleanup']):print('Use fixed --check or --cleanup only');return 2
    if not is_admin():print('ADMIN_REQUIRED');return 3
    platform=None
    try:
        platform=Windows()
        with machine_instance('native-installer-machine','all-devices'):
            result=execute(platform,args==['--cleanup'])
    except (Exception,KeyboardInterrupt) as exc:
        result=dict(getattr(platform,'last_result',{}))
        # Layout/identity checks precede last_result initialization and every
        # mutation. Make this refusal boundary visible in early failure JSON.
        result.setdefault('company_changed',False)
        result.setdefault('deleted',[])
        result.update(result='STOPPED_REVIEW_REQUIRED',error_type=type(exc).__name__,
                      winerror=getattr(exc,'winerror',None),message=str(exc)[:500])
        action=next_action(str(exc))
        if action:result['next_action']=action
    path=Path(sys.executable).parent/('Fresh-Cleanup-Result-'+uuid.uuid4().hex+'.json')
    with path.open('x',encoding='utf-8') as stream:json.dump(result,stream,ensure_ascii=True,indent=2)
    print('Result='+result['result']);print('Report='+str(path))
    if result.get('message'):print(result['message'])
    if result.get('next_action'):print(result['next_action'])
    return 0 if result['result'] in ('CHECKED_READY','CLEANED_READY_FOR_NEW_ENROLLMENT') else 1


if __name__=='__main__':raise SystemExit(main())
