"""Windows user-hive maintenance, restricted to an elevated local caller.

RegLoadAppKey is deliberately not used: a user hive can contain distinct key
security descriptors. No profile repair, ACL rewriting, or registry restore.
"""
from contextlib import contextmanager
import ctypes,uuid,winreg
from ctypes import wintypes as w

@contextmanager
def existing_registry_privileges():
    from guarddesk.windows_privilege import is_admin
    if not is_admin():raise PermissionError('User-hive maintenance requires approved administrator elevation')
    class Luid(ctypes.Structure):_fields_=[('low',w.DWORD),('high',w.LONG)]
    class Item(ctypes.Structure):_fields_=[('luid',Luid),('attributes',w.DWORD)]
    class Privileges(ctypes.Structure):_fields_=[('count',w.DWORD),('items',Item*2)]
    api=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetCurrentThread.restype=w.HANDLE;kernel.CloseHandle.argtypes=[w.HANDLE]
    api.OpenThreadToken.argtypes=[w.HANDLE,w.DWORD,w.BOOL,ctypes.POINTER(w.HANDLE)];api.OpenThreadToken.restype=w.BOOL
    api.ImpersonateSelf.argtypes=[ctypes.c_int];api.ImpersonateSelf.restype=w.BOOL
    api.RevertToSelf.restype=w.BOOL
    api.LookupPrivilegeValueW.argtypes=[w.LPCWSTR,w.LPCWSTR,ctypes.POINTER(Luid)];api.LookupPrivilegeValueW.restype=w.BOOL
    api.AdjustTokenPrivileges.argtypes=[w.HANDLE,w.BOOL,ctypes.POINTER(Privileges),w.DWORD,ctypes.POINTER(Privileges),ctypes.POINTER(w.DWORD)];api.AdjustTokenPrivileges.restype=w.BOOL
    token=w.HANDLE();old=Privileges();created=False;changed=False
    try:
        if not api.OpenThreadToken(kernel.GetCurrentThread(),0x28,True,ctypes.byref(token)):
            error=ctypes.get_last_error()
            if error!=1008:raise ctypes.WinError(error)
            if not api.ImpersonateSelf(2):raise ctypes.WinError(ctypes.get_last_error())
            created=True
            if not api.OpenThreadToken(kernel.GetCurrentThread(),0x28,True,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
        desired=Privileges();desired.count=2
        for i,name in enumerate(('SeBackupPrivilege','SeRestorePrivilege')):
            desired.items[i].attributes=2
            if not api.LookupPrivilegeValueW(None,name,ctypes.byref(desired.items[i].luid)):raise ctypes.WinError(ctypes.get_last_error())
        size=w.DWORD();ctypes.set_last_error(0)
        ok=api.AdjustTokenPrivileges(token,False,ctypes.byref(desired),ctypes.sizeof(old),ctypes.byref(old),ctypes.byref(size))
        error=ctypes.get_last_error();changed=bool(old.count)
        if not ok or error:raise ctypes.WinError(error)
        yield
    finally:
        try:
            if changed:
                ctypes.set_last_error(0)
                if not api.AdjustTokenPrivileges(token,False,ctypes.byref(old),0,None,None) or ctypes.get_last_error():
                    raise SystemExit('Registry maintenance privilege restoration failed; no further cleanup allowed')
        finally:
            if token:kernel.CloseHandle(token)
            if created and not api.RevertToSelf():raise SystemExit('Registry maintenance thread restoration failed')

@contextmanager
def loaded_user_hive(path,record=None):
    """Caller pins/checks the path. Privileges apply only to load/unload calls."""
    name='GuardDesk-Cleanup-'+uuid.uuid4().hex
    try:
        with winreg.OpenKey(winreg.HKEY_USERS,name):pass
    except FileNotFoundError:pass
    else:raise OSError('Temporary registry mount already exists')
    loaded=False
    try:
        if record:record({'state':'before_load','mount':name,'hive':str(path)})
        with existing_registry_privileges():
            winreg.LoadKey(winreg.HKEY_USERS,name,str(path))
            loaded=True
        if record:record({'state':'loaded','mount':name,'hive':str(path)})
        with winreg.OpenKey(winreg.HKEY_USERS,name,0,winreg.KEY_READ|winreg.KEY_WRITE) as key:yield key
    finally:
        if loaded:
            api=ctypes.WinDLL('advapi32',use_last_error=True)
            api.RegUnLoadKeyW.argtypes=[w.HANDLE,w.LPCWSTR];api.RegUnLoadKeyW.restype=w.LONG
            with existing_registry_privileges():code=api.RegUnLoadKeyW(w.HANDLE(int(winreg.HKEY_USERS)),name)
            if code:
                error=ctypes.WinError(code);error.registry_mount=name
                if record:record({'state':'unload_failed','mount':name,'hive':str(path),'winerror':code})
                raise error
            if record:record({'state':'unloaded','mount':name,'hive':str(path)})
