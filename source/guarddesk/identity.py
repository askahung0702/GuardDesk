"""Read-only local identity/session metadata; not an AD authentication source."""
import ctypes
import getpass
import os
import socket
import time
import uuid


def current_account():
    if os.name=='nt':
        from ctypes import wintypes as w
        api=ctypes.WinDLL('secur32',use_last_error=True)
        api.GetUserNameExW.argtypes=[ctypes.c_int,w.LPWSTR,ctypes.POINTER(w.ULONG)];api.GetUserNameExW.restype=w.BOOL
        buffer=ctypes.create_unicode_buffer(512);size=w.ULONG(len(buffer))
        if api.GetUserNameExW(2,buffer,ctypes.byref(size)):return buffer.value
    return (os.environ.get('USERDOMAIN') or socket.gethostname())+'\\'+getpass.getuser()


def session_metadata():
    accounts={current_account()};sessions=[];coverage='process_account_only';boot=None
    if os.name=='nt':
        from ctypes import wintypes as w
        class Info(ctypes.Structure):_fields_=[('id',w.DWORD),('station',w.LPWSTR),('state',ctypes.c_int)]
        api=ctypes.WinDLL('wtsapi32',use_last_error=True)
        api.WTSEnumerateSessionsW.argtypes=[w.HANDLE,w.DWORD,w.DWORD,ctypes.POINTER(ctypes.POINTER(Info)),ctypes.POINTER(w.DWORD)];api.WTSEnumerateSessionsW.restype=w.BOOL
        api.WTSQuerySessionInformationW.argtypes=[w.HANDLE,w.DWORD,ctypes.c_int,ctypes.POINTER(w.LPWSTR),ctypes.POINTER(w.DWORD)];api.WTSQuerySessionInformationW.restype=w.BOOL
        api.WTSFreeMemory.argtypes=[w.LPVOID]
        def query(sid,kind):
            pointer=w.LPWSTR();size=w.DWORD()
            if not api.WTSQuerySessionInformationW(None,sid,kind,ctypes.byref(pointer),ctypes.byref(size)):return ''
            try:return pointer.value or ''
            finally:api.WTSFreeMemory(ctypes.cast(pointer,w.LPVOID))
        values=ctypes.POINTER(Info)();count=w.DWORD()
        if api.WTSEnumerateSessionsW(None,0,1,ctypes.byref(values),ctypes.byref(count)):
            try:
                for i in range(min(count.value,64)):
                    entry=values[i];name=query(entry.id,5);domain=query(entry.id,7)
                    if not name:continue
                    account=(domain or socket.gethostname())+'\\'+name
                    accounts.add(account);sessions.append({'id':entry.id,'user':account,'state':entry.state,'active':entry.state==0})
                coverage='WTS_visible_sessions'
            finally:api.WTSFreeMemory(ctypes.cast(values,w.LPVOID))
        kernel=ctypes.WinDLL('kernel32');kernel.GetTickCount64.restype=ctypes.c_ulonglong
        boot=time.time()-kernel.GetTickCount64()/1000
    addresses=[]
    try:addresses=sorted({r[4][0] for r in socket.getaddrinfo(socket.gethostname(),None)})
    except OSError:pass
    node=uuid.getnode();mac=None if node&(1<<40) else ':'.join(f'{(node>>shift)&255:02X}' for shift in range(40,-1,-8))
    return {'user_accounts':sorted(accounts)[:32],'sessions':sessions[:32],'session_coverage':coverage,'boot_time':boot,'network_addresses':addresses[:16],'mac_address':mac,'agent_account':current_account()}
