"""Machine-wide exclusion for privileged scheduled workers."""
import ctypes
import hashlib
import os
from contextlib import contextmanager


@contextmanager
def machine_instance(kind,device_id):
    if os.name!='nt':yield;return
    from ctypes import wintypes as w
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.CreateMutexW.argtypes=[w.LPVOID,w.BOOL,w.LPCWSTR];api.CreateMutexW.restype=w.HANDLE
    api.CloseHandle.argtypes=[w.HANDLE];api.CloseHandle.restype=w.BOOL
    name='Global\\GuardDesk-'+kind+'-'+hashlib.sha256(device_id.encode()).hexdigest()[:24]
    ctypes.set_last_error(0)
    handle=api.CreateMutexW(None,False,name);error=ctypes.get_last_error()
    if not handle:raise ctypes.WinError(error)
    try:
        if error==183:raise OSError('同一端點已有 USB 背景工作，拒絕重複啟動')
        yield
    finally:api.CloseHandle(handle)
