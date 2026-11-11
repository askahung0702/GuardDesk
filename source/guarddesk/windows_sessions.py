"""Read-only WTS session metadata shared by remote and standard components.

No account control, scheduling, process launch, policy or power operations.
"""
import ctypes
from ctypes import wintypes as w


def session_information(session):
    class Info(ctypes.Structure):
        _fields_=[('SessionId',w.DWORD),('State',ctypes.c_int),('Flags',w.LONG),('WinStationName',w.WCHAR*33),('UserName',w.WCHAR*21),('Domain',w.WCHAR*18),('LogonTime',ctypes.c_longlong),('ConnectTime',ctypes.c_longlong),('DisconnectTime',ctypes.c_longlong),('LastInputTime',ctypes.c_longlong),('CurrentTime',ctypes.c_longlong),('Counters',w.DWORD*6)]
    class Union(ctypes.Union):_fields_=[('level1',Info)]
    class Extended(ctypes.Structure):_fields_=[('Level',w.DWORD),('Data',Union)]
    api=ctypes.WinDLL('wtsapi32',use_last_error=True);ptr=w.LPVOID();size=w.DWORD()
    api.WTSQuerySessionInformationW.argtypes=[w.HANDLE,w.DWORD,ctypes.c_int,ctypes.POINTER(w.LPVOID),ctypes.POINTER(w.DWORD)]
    api.WTSFreeMemory.argtypes=[w.LPVOID]
    if not api.WTSQuerySessionInformationW(None,session,25,ctypes.byref(ptr),ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
    try:
        if size.value<ctypes.sizeof(Extended):raise OSError('Incomplete session report')
        extended=ctypes.cast(ptr,ctypes.POINTER(Extended)).contents;info=extended.Data.level1
        if extended.Level!=1 or info.SessionId!=session:raise OSError('Session information identity mismatch')
        delta=(info.CurrentTime-info.LastInputTime)/10_000_000
        return {'locked':info.Flags!=1,'logon':info.LogonTime,'idle':delta/60 if info.LastInputTime>0 and 0<=delta<365*86400 else None}
    finally:api.WTSFreeMemory(ptr)
