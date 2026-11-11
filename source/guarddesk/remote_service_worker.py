"""Cooperative worker lifetime, inherited from the fixed native SCM host."""
import ctypes
import re
import threading
from ctypes import wintypes as w

def run(did,handle,stop):
    if not isinstance(did,str) or not re.fullmatch('[0-9a-f]{24}',did):raise ValueError('Invalid service device')
    if type(handle) is not int or not 0<handle<2**64:raise ValueError('Invalid service lifetime handle')
    from .remote_trial import enabled as trial,worker as trial_worker
    from .machine_service import worker as full_worker
    from .update_native import folder,protected_tree
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    adv=ctypes.WinDLL('advapi32',use_last_error=True)
    kernel.GetCurrentProcess.restype=w.HANDLE
    kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];kernel.WaitForSingleObject.restype=w.DWORD
    kernel.CloseHandle.argtypes=[w.HANDLE]
    adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)];adv.OpenProcessToken.restype=w.BOOL
    adv.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
    adv.IsWellKnownSid.argtypes=[w.LPVOID,ctypes.c_int];adv.IsWellKnownSid.restype=w.BOOL
    token=w.HANDLE();size=w.DWORD()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(),8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
    try:
        adv.GetTokenInformation(token,1,None,0,ctypes.byref(size))
        if not 0<size.value<=4096:raise PermissionError('Invalid service token')
        data=ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token,1,data,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        sid=ctypes.cast(data,ctypes.POINTER(w.LPVOID))[0]
        if not adv.IsWellKnownSid(sid,22):raise PermissionError('Service worker requires LocalSystem')
    finally:kernel.CloseHandle(token)
    adv.GetSecurityInfo.argtypes=[w.HANDLE,ctypes.c_int,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID,w.LPVOID,w.LPVOID,ctypes.POINTER(w.LPVOID)]
    adv.GetSecurityInfo.restype=w.DWORD
    kernel.LocalFree.argtypes=[w.LPVOID];kernel.LocalFree.restype=w.LPVOID
    owner=w.LPVOID();descriptor=w.LPVOID()
    try:
        error=adv.GetSecurityInfo(handle,6,1,ctypes.byref(owner),None,None,None,ctypes.byref(descriptor))
        if error:raise ctypes.WinError(error)
        if not owner or not adv.IsWellKnownSid(owner,22):raise PermissionError('Service stop event owner must be SYSTEM')
    finally:
        if descriptor:kernel.LocalFree(descriptor)
    data_root=folder(35);root=data_root/'USBControl'/did;config=root/'config.json'
    for path in (data_root,data_root/'USBControl',root,config):protected_tree(path,recursive=False)
    for suffix in ('.sqlite3','.sqlite3-wal','.sqlite3-shm'):
        path=config.with_suffix(suffix)
        if path.exists():protected_tree(path,recursive=False)
    wait=kernel.WaitForSingleObject(handle,0)
    if wait not in (0,258):raise PermissionError('Invalid service lifetime event')
    if wait==0:stop.set();return
    finished=threading.Event()
    def watch():
        while not finished.is_set():
            result=kernel.WaitForSingleObject(handle,250)
            if result!=258:stop.set();return
    watcher=threading.Thread(target=watch,name='GuardDesk-service-stop',daemon=True);watcher.start()
    try:return (trial_worker if trial() else full_worker)(config,stop)
    finally:
        stop.set();finished.set();watcher.join(1);kernel.CloseHandle(handle)
