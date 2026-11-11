"""Query audit policy via Win32 and configure via auditpol, without scripts."""
import ctypes
import json
import os
import subprocess
import uuid
import threading
from contextlib import contextmanager
from pathlib import Path

IDS=('{0CCE922B-69AE-11D9-BED3-505054503030}','{0CCE922C-69AE-11D9-BED3-505054503030}')
_PRIVILEGE_LOCK=threading.RLock()


def auditpol(*arguments):
    if os.name!='nt':raise OSError('Windows process auditing requires Windows')
    system=ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(system,len(system)):raise OSError('Windows system directory unavailable')
    result=subprocess.run([str(Path(system.value)/'auditpol.exe'),*arguments],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW|subprocess.BELOW_NORMAL_PRIORITY_CLASS)
    if result.returncode:raise OSError(f'Windows auditpol failed (exit {result.returncode}); review company audit permissions/policy')


@contextmanager
def security_privilege(api,name='SeSecurityPrivilege'):
    # AdjustTokenPrivileges changes the process token. Serialize nested users
    # so two companion threads cannot restore each other's prior privilege.
    with _PRIVILEGE_LOCK:
        with _security_privilege(api,name):yield


@contextmanager
def _security_privilege(api,name):
    from ctypes import wintypes as w
    class Luid(ctypes.Structure):_fields_=[('low',w.DWORD),('high',w.LONG)]
    class Privileges(ctypes.Structure):_fields_=[('count',w.DWORD),('luid',Luid),('attributes',w.DWORD)]
    api.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)];api.OpenProcessToken.restype=w.BOOL
    api.LookupPrivilegeValueW.argtypes=[w.LPCWSTR,w.LPCWSTR,ctypes.POINTER(Luid)];api.LookupPrivilegeValueW.restype=w.BOOL
    api.AdjustTokenPrivileges.argtypes=[w.HANDLE,w.BOOL,ctypes.POINTER(Privileges),w.DWORD,ctypes.POINTER(Privileges),ctypes.POINTER(w.DWORD)];api.AdjustTokenPrivileges.restype=w.BOOL
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);kernel.CloseHandle.argtypes=[w.HANDLE];kernel.CloseHandle.restype=w.BOOL
    token=w.HANDLE();previous=Privileges();changed=False
    if not api.OpenProcessToken(w.HANDLE(-1),0x28,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
    try:
        desired=Privileges();desired.count=1;desired.attributes=2
        if not api.LookupPrivilegeValueW(None,name,ctypes.byref(desired.luid)):raise ctypes.WinError(ctypes.get_last_error())
        size=w.DWORD();ctypes.set_last_error(0)
        if not api.AdjustTokenPrivileges(token,False,ctypes.byref(desired),ctypes.sizeof(previous),ctypes.byref(previous),ctypes.byref(size)) or ctypes.get_last_error():raise ctypes.WinError(ctypes.get_last_error())
        changed=True;yield
    finally:
        try:
            if changed and not api.AdjustTokenPrivileges(token,False,ctypes.byref(previous),0,None,None):raise ctypes.WinError(ctypes.get_last_error())
        finally:kernel.CloseHandle(token)


def normalized_flags(value):
    if value not in (0,1,2,3,4):raise OSError('Unsupported process audit flags')
    return value&3


def read_flags(directory,ids=IDS):
    if os.name!='nt':raise OSError('Windows process auditing requires Windows')
    from ctypes import wintypes as w
    class Guid(ctypes.Structure):_fields_=[('a',w.DWORD),('b',w.WORD),('c',w.WORD),('d',ctypes.c_ubyte*8)]
    class Info(ctypes.Structure):_fields_=[('guid',Guid),('flags',w.ULONG),('category',Guid)]
    api=ctypes.WinDLL('advapi32',use_last_error=True)
    api.AuditQuerySystemPolicy.argtypes=[ctypes.POINTER(Guid),w.ULONG,ctypes.POINTER(ctypes.POINTER(Info))];api.AuditQuerySystemPolicy.restype=ctypes.c_ubyte
    api.AuditFree.argtypes=[ctypes.c_void_p];api.AuditFree.restype=None
    guids=(Guid*len(ids))(*(Guid.from_buffer_copy(uuid.UUID(key).bytes_le) for key in ids));pointer=ctypes.POINTER(Info)()
    with security_privilege(api):
        if not api.AuditQuerySystemPolicy(guids,len(ids),ctypes.byref(pointer)):raise ctypes.WinError(ctypes.get_last_error())
        try:values={'{'+str(uuid.UUID(bytes_le=bytes(pointer[i].guid))).upper()+'}':normalized_flags(pointer[i].flags) for i in range(len(ids))}
        finally:api.AuditFree(pointer)
    if set(values)!=set(ids):raise OSError('Missing audit subcategory')
    return values


def configure(directory,enabled):
    directory=Path(directory);directory.mkdir(exist_ok=True)
    backup=directory/'process-audit-original.json'
    if not enabled and not backup.exists():return {'process_audit_enabled':False,'process_audit_configuration':'not_managed'}
    current=read_flags(directory)
    if backup.exists():
        saved=json.loads(backup.read_text(encoding='utf-8'))
        if set(saved)!=set(IDS) or any(type(v)is not int or v not in (0,1,2,3) for v in saved.values()):raise OSError('Invalid process audit baseline')
    else:
        saved=current
        with backup.open('x',encoding='utf-8') as stream:json.dump(saved,stream)
    if any(current[key] not in (saved[key],saved[key]|1) for key in IDS):raise OSError('Process audit changed outside GuardDesk; preserve company policy')
    desired={key:(saved[key]|1) if enabled else saved[key] for key in IDS}
    for key in IDS:
        if current[key]!=desired[key]:
            auditpol('/set',f'/subcategory:{key}',f"/success:{'enable' if desired[key]&1 else 'disable'}",f"/failure:{'enable' if desired[key]&2 else 'disable'}")
    verified=read_flags(directory) if current!=desired else current
    if verified!=desired:raise OSError('Process audit readback mismatch; review company policy')
    if not enabled:backup.unlink()
    return {'process_audit_enabled':bool(enabled),'process_audit_configuration':'verified_windows_audit_api' if enabled else 'restored'}
