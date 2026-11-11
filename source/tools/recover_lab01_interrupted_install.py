"""Operator-only recovery of one evidenced remote-trial install interruption.

Archives metadata and the incomplete program directory; never executes, restores,
copies or deletes an executable, creates a task, or changes protection settings.
"""
import csv
import ctypes
from ctypes import wintypes as w
from contextlib import ExitStack, contextmanager
import hashlib
import io
import json
import os
import stat
from pathlib import Path
import subprocess
import sys

DEVICE = 'eea0d7f81091fe91372a924c'
TRANSACTION = '40e66e8229289b7e'
JOURNAL = {'format': 1, 'phase': 'register_tasks', 'id': TRANSACTION, 'version': '0.4.86'}
PROFILE = 'remote-only-trial-v1'
TRUSTED = {'S-1-5-18', 'S-1-5-32-544'}
TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
LEDGERS = ('windows/usb-original.json', 'windows/usb-managed.json', 'windows/installed.json',
           'applications/document-sacl.sqlite3', 'applications/process-audit-original.json',
           'applications/applocker-managed.json', 'applications/appidsvc-original.json',
           'website-policy-chrome.json', 'website-policy-edge.json', 'browser-policy-owned.json',
           'browser-trust-owned.json', 'CustomSettings/network-lease.json')


def require(value, code):
    if not value: raise OSError(code)


class PermissionReviewError(OSError):
    """Only fixed-path ACL metadata; never include configuration contents."""
    def __init__(self, code, path, ancestor, **metadata):
        super().__init__(code)
        self.permission_review={'path':str(path),'ancestor':ancestor,**metadata}


def plain(path):
    path = Path(os.path.abspath(path))
    for entry in reversed((path, *path.parents)):
        try: info = entry.lstat()
        except FileNotFoundError: continue
        require(not info.st_file_attributes & 0x400, 'REPARSE_PATH_REJECTED')
        if stat.S_ISREG(info.st_mode): require(info.st_nlink == 1, 'HARDLINK_REJECTED')
    return path


def present(path):
    try: plain(path).lstat();return True
    except FileNotFoundError:return False


def small(path):
    with plain(path).open('rb') as stream: raw = stream.read(65537)
    require(len(raw) <= 65536, 'STATE_SIZE_LIMIT')
    return raw


def read(path):
    value = json.loads(small(path).decode('utf-8-sig'))
    require(type(value) is dict, 'STATE_OBJECT_REQUIRED')
    return value


def sha(raw): return hashlib.sha256(raw).hexdigest()


@contextmanager
def private_attributes(directory=False):
    adv=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    descriptor=w.LPVOID()
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=w.BOOL
    kernel.LocalFree.argtypes=[w.LPVOID]
    flags='OICI' if directory else ''
    sddl='O:BAD:P(A;'+flags+';FA;;;SY)(A;'+flags+';FA;;;BA)(A;'+flags+';RC;;;OW)'
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(descriptor),None):raise ctypes.WinError(ctypes.get_last_error())
    class Attributes(ctypes.Structure):_fields_=[('length',w.DWORD),('descriptor',w.LPVOID),('inherit',w.BOOL)]
    try:yield Attributes(ctypes.sizeof(Attributes),descriptor,False)
    finally:kernel.LocalFree(descriptor)


def protected(path, ancestor=False):
    path = plain(path)
    adv = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    owner = w.LPVOID(); acl = w.LPVOID(); descriptor = w.LPVOID()
    adv.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, w.DWORD, w.DWORD, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID), w.LPVOID, ctypes.POINTER(w.LPVOID)]
    adv.GetNamedSecurityInfoW.restype = w.DWORD
    adv.ConvertSidToStringSidW.argtypes = [w.LPVOID, ctypes.POINTER(w.LPWSTR)]
    adv.ConvertSidToStringSidW.restype = w.BOOL
    adv.GetAclInformation.argtypes = [w.LPVOID, w.LPVOID, w.DWORD, w.DWORD]
    adv.GetAclInformation.restype = w.BOOL
    adv.GetAce.argtypes = [w.LPVOID, w.DWORD, ctypes.POINTER(w.LPVOID)]
    adv.GetAce.restype = w.BOOL
    kernel.LocalFree.argtypes = [w.LPVOID]
    class Info(ctypes.Structure): _fields_ = [('count',w.DWORD), ('used',w.DWORD), ('free',w.DWORD)]
    def sid(pointer):
        text = w.LPWSTR()
        if not adv.ConvertSidToStringSidW(pointer, ctypes.byref(text)): raise ctypes.WinError(ctypes.get_last_error())
        try: return text.value
        finally: kernel.LocalFree(ctypes.cast(text,w.LPVOID))
    try:
        error = adv.GetNamedSecurityInfoW(str(path),1,5,ctypes.byref(owner),None,ctypes.byref(acl),None,ctypes.byref(descriptor))
        if error: raise ctypes.WinError(error)
        allowed=TRUSTED|({TRUSTED_INSTALLER} if ancestor else set())
        owner_sid=sid(owner) if owner else None
        if not owner or not acl or owner_sid not in allowed:
            raise PermissionReviewError('UNTRUSTED_OWNER_OR_DACL',path,ancestor,owner=owner_sid,dacl_present=bool(acl))
        info = Info()
        if not adv.GetAclInformation(acl,ctypes.byref(info),ctypes.sizeof(info),2): raise ctypes.WinError(ctypes.get_last_error())
        require(info.count <= 4096, 'ACL_SIZE_LIMIT')
        for index in range(info.count):
            ace = w.LPVOID()
            if not adv.GetAce(acl,index,ctypes.byref(ace)): raise ctypes.WinError(ctypes.get_last_error())
            kind = ctypes.c_ubyte.from_address(ace.value).value
            flags = ctypes.c_ubyte.from_address(ace.value+1).value
            size = ctypes.c_uint16.from_address(ace.value+2).value
            require(size >= 8, 'INVALID_ACE')
            if flags & 8 or kind in (1,2,3,6,7,8,10,12,13,14,15,16,17,18,19,20,21): continue
            mask = ctypes.c_uint32.from_address(ace.value+4).value
            # ProgramData may permit creating siblings/EA/attributes. It must
            # not permit replacing an existing protected child or its ACL.
            if mask & (0x500D0156 & ~0x116 if ancestor else 0x500D0156):
                trustee=sid(ace.value+8) if kind==0 else None
                if kind!=0 or trustee not in allowed:
                    raise PermissionReviewError('UNTRUSTED_WRITE',path,ancestor,owner=owner_sid,
                                                ace_index=index,ace_type=kind,ace_flags=flags,
                                                mask='0x%08x'%mask,trustee=trustee)
    finally:
        if descriptor: kernel.LocalFree(descriptor)


@contextmanager
def mutex(kind, device):
    api = ctypes.WinDLL('kernel32',use_last_error=True)
    api.CreateMutexW.argtypes = [w.LPVOID,w.BOOL,w.LPCWSTR]; api.CreateMutexW.restype = w.HANDLE
    api.CloseHandle.argtypes = [w.HANDLE]
    name = 'Global\\GuardDesk-'+kind+'-'+sha(device.encode())[:24]
    ctypes.set_last_error(0)
    handle = api.CreateMutexW(None,False,name); error = ctypes.get_last_error()
    if not handle: raise ctypes.WinError(error)
    try:
        require(error != 183, 'INSTALL_OR_WORKER_MUTEX_BUSY')
        yield
    finally: api.CloseHandle(handle)


def no_processes():
    api = ctypes.WinDLL('kernel32',use_last_error=True)
    class Entry(ctypes.Structure):
        _fields_ = [('size',w.DWORD),('usage',w.DWORD),('pid',w.DWORD),('heap',ctypes.c_size_t),
                    ('module',w.DWORD),('threads',w.DWORD),('parent',w.DWORD),('priority',w.LONG),('flags',w.DWORD),('exe',w.WCHAR*260)]
    api.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD]; api.CreateToolhelp32Snapshot.restype=w.HANDLE
    api.Process32FirstW.argtypes=[w.HANDLE,ctypes.POINTER(Entry)]; api.Process32FirstW.restype=w.BOOL
    api.Process32NextW.argtypes=[w.HANDLE,ctypes.POINTER(Entry)]; api.Process32NextW.restype=w.BOOL
    api.CloseHandle.argtypes=[w.HANDLE]
    handle=api.CreateToolhelp32Snapshot(2,0)
    if handle == ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry=Entry();entry.size=ctypes.sizeof(entry);ok=api.Process32FirstW(handle,ctypes.byref(entry));count=0
        while ok:
            count+=1;require(count<=65536,'PROCESS_LIMIT')
            require(entry.pid==os.getpid() or not entry.exe.casefold().startswith('guarddesk'), 'GUARDDESK_PROCESS_PRESENT')
            ok=api.Process32NextW(handle,ctypes.byref(entry))
        require(ctypes.get_last_error()==18, 'PROCESS_ENUMERATION_INCOMPLETE')
    finally:api.CloseHandle(handle)


class Windows:
    def __init__(self):
        require(os.name=='nt' and os.environ.get('COMPUTERNAME','').casefold()=='lab01','LAB01_ONLY')
        require(bool(ctypes.windll.shell32.IsUserAnAdmin()), 'ADMINISTRATOR_REQUIRED')
        def folder(id):
            buf=ctypes.create_unicode_buffer(32768)
            require(ctypes.windll.shell32.SHGetFolderPathW(None,id,None,0,buf)==0,'KNOWN_FOLDER_FAILED')
            return Path(buf.value)/'GuardDeskPilot'
        self.program=folder(38);self.data=folder(35)
    def security(self,path,ancestor=False): protected(path,ancestor)
    def mkdir(self,path):
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        with private_attributes(True) as attributes:
            api.CreateDirectoryW.argtypes=[w.LPCWSTR,ctypes.POINTER(type(attributes))];api.CreateDirectoryW.restype=w.BOOL
            if not api.CreateDirectoryW(str(path),ctypes.byref(attributes)):raise ctypes.WinError(ctypes.get_last_error())
    def write_new(self,path,raw):
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        with private_attributes() as attributes:
            api.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,ctypes.POINTER(type(attributes)),w.DWORD,w.DWORD,w.HANDLE];api.CreateFileW.restype=w.HANDLE
            api.CloseHandle.argtypes=[w.HANDLE];api.FlushFileBuffers.argtypes=[w.HANDLE];api.FlushFileBuffers.restype=w.BOOL
            api.WriteFile.argtypes=[w.HANDLE,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD),w.LPVOID];api.WriteFile.restype=w.BOOL
            handle=api.CreateFileW(str(path),0x40000000,0,ctypes.byref(attributes),1,0,None)
            if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
            try:
                data=ctypes.create_string_buffer(raw);written=w.DWORD()
                if not api.WriteFile(handle,data,len(raw),ctypes.byref(written),None):raise ctypes.WinError(ctypes.get_last_error())
                require(written.value==len(raw),'RECOVERY_PLAN_SHORT_WRITE')
                if not api.FlushFileBuffers(handle):raise ctypes.WinError(ctypes.get_last_error())
            finally:api.CloseHandle(handle)
    def quiescent(self):
        buf=ctypes.create_unicode_buffer(32768)
        require(bool(ctypes.windll.kernel32.GetSystemDirectoryW(buf,len(buf))),'SYSTEM_PATH_FAILED')
        result=subprocess.run([str(Path(buf.value)/'schtasks.exe'),'/Query','/FO','CSV','/NH'],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        require(result.returncode==0,'TASK_QUERY_FAILED')
        require(len(result.stdout)<=8*1024*1024,'TASK_QUERY_SIZE_LIMIT')
        rows=list(csv.reader(io.StringIO(result.stdout.decode('oem'))))
        require(len(rows)<=65536 and all(len(row)==3 for row in rows if row),'TASK_QUERY_FORMAT')
        require(not any('guarddesk-' in row[0].casefold() for row in rows if row),'GUARDDESK_TASK_PRESENT')
        no_processes()


def prepare(ops, apply=False):
    program=plain(ops.program);data=plain(ops.data);root=plain(data/'USBControl'/DEVICE)
    current=plain(program/'USBControl');backup=plain(program/('USBControl.install-backup-'+TRANSACTION))
    archived=plain(program/('USBControl.install-interrupted-'+TRANSACTION))
    journal=plain(root/'install-transaction.json');archive=plain(root/('install-recovery-'+TRANSACTION))
    config=plain(root/'config.json');old_journal=archive/'install-transaction.json';plan=archive/'plan.json'
    for p in (program.parent,data.parent):ops.security(p,ancestor=True)
    for p in (program,data,data/'USBControl',root,config,backup): ops.security(p)
    require(not present(program/'Updater'),'STANDARD_UPDATER_PRESENT')
    require(not any(present(root/name) for name in LEDGERS),'CONTROL_RESTORE_REQUIRED')
    settings=read(config)
    require(settings.get('device_id')==DEVICE and settings.get('install_profile')==PROFILE,'TRIAL_IDENTITY_MISMATCH')
    require(not any(settings.get(k) for k in ('browser_deployment','browser_deployment_authorization','browser_trust','proxy_enabled')),'STANDARD_SETTINGS_PRESENT')
    for name in ('updates/transaction-native.json','updates/updater-refresh.json'):
        # A remote-only build does not need update journals. Unknown state is not guessed safe.
        require(not present(root/name) and not present(root/(name+'.state.json')),'UPDATE_TRANSACTION_PRESENT')
    for p in (current,archived,archive,journal,old_journal,plan):
        if present(p):ops.security(p)
    require(not present(current/'GuardDesk.exe'),'INSTALLED_EXE_PRESENT')
    config_hash=sha(small(config))
    original=small(journal if present(journal) else old_journal)
    require(json.loads(original)==JOURNAL,'TRANSACTION_MISMATCH')
    expected={'format':1,'tool':'GuardDesk interrupted remote-trial recovery 001','device_id':DEVICE,
              'transaction_id':TRANSACTION,'config_sha256':config_hash,'journal_sha256':sha(original),
              'archive_program':str(archived),'source_program':str(current),
              'operation':'archive_incomplete_install_without_restoring_or_starting_agent'}
    if present(archive):
        require(present(plan) and read(plan)==expected,'RECOVERY_PLAN_MISMATCH')
        require(present(current)!=present(archived),'RECOVERY_TREE_CONFLICT')
    else:
        require(current.is_dir() and not present(archived) and present(journal),'RECOVERY_INITIAL_STATE_MISMATCH')
    if present(old_journal):require(small(old_journal)==original and not present(journal) and archived.is_dir(),'ARCHIVED_JOURNAL_CONFLICT')
    ops.quiescent()
    result={'format':1,'tool':expected['tool'],'device_id':DEVICE,'result':'CHECK_PASSED_NO_CHANGES',
            'agent_started':False,'tasks_changed':False,'defender_changed':False,'files_deleted':False,
            'identity_preserved':True,'installed':False,'archive':str(archive),'program_archive':str(archived)}
    if not apply:return result
    if not present(archive):
        ops.mkdir(archive);ops.security(archive)
        ops.write_new(plan,json.dumps(expected,ensure_ascii=False,indent=2).encode('utf-8'))
        ops.security(plan)
    ops.quiescent()
    require(sha(small(config))==config_hash,'CONFIG_CHANGED')
    if present(current):
        require(present(journal) and small(journal)==original,'JOURNAL_CHANGED')
        require(not present(archived),'ARCHIVE_ALREADY_EXISTS')
        os.rename(current,archived)
    if present(journal):
        ops.quiescent()
        require(sha(small(config))==config_hash and small(journal)==original,'STATE_CHANGED')
        require(not present(old_journal),'JOURNAL_ARCHIVE_EXISTS')
        os.rename(journal,old_journal)
    require(small(old_journal)==original and sha(small(config))==config_hash,'POSTCHECK_FAILED')
    result['result']='RECOVERY_PREPARED_NOT_INSTALLED'
    return result


def main():
    args=sys.argv[1:]
    if args not in (['--check'],['--prepare']):
        print('Usage: GuardDeskInstallRecovery.exe --check | --prepare');return 2
    try:
        ops=Windows()
        with ExitStack() as stack:
            for kind,device in (('native-installer-machine','all-devices'),('usb',DEVICE),('update',DEVICE)):
                stack.enter_context(mutex(kind,device))
            result=prepare(ops,apply=args==['--prepare'])
        print(json.dumps(result,ensure_ascii=True,indent=2));return 0
    except Exception as exc:
        # Avoid arbitrary exception text containing paths/config values.
        print(json.dumps({'result':'STOPPED_REVIEW_REQUIRED','error_type':type(exc).__name__,
                          'winerror':getattr(exc,'winerror',None),
                          'code':str(exc) if str(exc).replace('_','').isalnum() and len(str(exc))<100 else 'RECOVERY_IO_OR_STATE_ERROR',
                          'permission_review':getattr(exc,'permission_review',None),
                          'installed':False,'manual_review_required':True},indent=2));return 1


if __name__=='__main__':raise SystemExit(main())
