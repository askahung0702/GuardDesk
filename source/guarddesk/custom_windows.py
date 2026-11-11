"""Fixed official Windows APIs for disclosed custom actions, never a remote shell."""
import ctypes
import datetime as dt
import os
import re
import subprocess
import sys
import time
from ctypes import wintypes as w
from contextlib import contextmanager

ACTION_NAMES={'shutdown':'關機','restart':'重新啟動','sleep':'睡眠','hibernate':'休眠','logoff':'登出','lock':'鎖定'}

def trusted_native(config):
    from .update_native import folder,protected_tree
    if not isinstance(config.get('device_id'),str) or not re.fullmatch('[0-9a-f]{24}',config['device_id']):raise ValueError('Invalid installed device identity')
    executable=folder(38)/'USBControl'/'GuardDesk.exe'
    if not getattr(sys,'frozen',False) or os.path.normcase(os.path.realpath(sys.executable))!=os.path.normcase(str(executable.resolve())):raise OSError('Custom native controls require the fixed protected executable')
    protected_tree(executable.parent,recursive=False);protected_tree(executable)
    root=folder(35)/'USBControl'/config['device_id']
    protected_tree(root,recursive=False)
    return root

def sessions():
    from .identity import session_metadata
    result=session_metadata()['sessions']
    if not result or len(result)>8 or any(not r['active'] for r in result):raise OSError('No promptable session or disconnected/many sessions present')
    for entry in result:
        information=session_information(entry['id'])
        if information['locked'] or information['logon']<=0:raise OSError('Locked or unknown session cannot confirm a prompt')
        entry['logon']=information['logon']
    return sorted(result,key=lambda r:r['id'])

# Preserve the standard component API while keeping the shared metadata
# implementation independent from this control/action module.
from .windows_sessions import session_information


def idle_minutes(session):
    report=session_information(session)
    if report['locked']:raise OSError('Session is locked')
    if report['idle'] is not None:return report['idle']
    # Some console sessions don't populate WTS LastInputTime. A fixed protected
    # helper queries only its own session; a bounded exit code carries seconds.
    return launch_session_action(session,'idle')/60

def prompt(session,rule,seconds):
    seconds=max(1,min(3600,int(seconds)));title='GuardDesk 排程提醒：'+rule['name']
    deadline=(dt.datetime.now(dt.timezone(dt.timedelta(hours=8)))+dt.timedelta(seconds=seconds)).strftime('%H:%M:%S')+'（台北）'
    message=rule['message']+'\n\n預計於 '+deadline+' 執行「'+ACTION_NAMES[rule['action']]+'」。請先儲存文件。'
    if rule['allow_cancel']:
        style=3|0x200|0x30
        if 'repeat' in rule:
            message+='\n是：依倒數執行；否／取消：'+str(rule['repeat']['interval_minutes'])+' 分鐘後再次提示（可重複）；未回應將依倒數提出動作。\n本次截止 '+rule['repeat']['until']+'（台北）；到截止只停止本次提醒。'
        else:message+='\n是：依時間執行；否：'+('延後 '+str(rule['defer_minutes'])+' 分鐘（限一次）' if rule['defer_minutes'] else '取消本次')+'；取消：取消本次。'
    else:style=0x30;message+='\n此排程由 MIS 設定為不可取消；確定僅關閉提示，不會提早執行。'
    api=ctypes.WinDLL('wtsapi32',use_last_error=True);response=w.DWORD()
    api.WTSSendMessageW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,w.DWORD,w.LPWSTR,w.DWORD,w.DWORD,w.DWORD,ctypes.POINTER(w.DWORD),w.BOOL]
    if not api.WTSSendMessageW(None,session,title,len(title.encode('utf-16le')),message,len(message.encode('utf-16le')),style,seconds,ctypes.byref(response),True):raise ctypes.WinError(ctypes.get_last_error())
    if response.value==2:return 'defer' if 'repeat' in rule else 'cancel'
    if response.value==7:return 'defer' if 'repeat' in rule or rule['defer_minutes'] else 'cancel'
    if response.value not in (1,6,32000):raise OSError('Unexpected prompt response')
    return 'continue'

@contextmanager
def enable_shutdown():
    class Luid(ctypes.Structure):_fields_=[('LowPart',w.DWORD),('HighPart',w.LONG)]
    class Privilege(ctypes.Structure):_fields_=[('count',w.DWORD),('luid',Luid),('attributes',w.DWORD)]
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);api=ctypes.WinDLL('advapi32',use_last_error=True)
    kernel.GetCurrentProcess.restype=w.HANDLE;kernel.CloseHandle.argtypes=[w.HANDLE]
    api.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)]
    api.LookupPrivilegeValueW.argtypes=[w.LPCWSTR,w.LPCWSTR,ctypes.POINTER(Luid)]
    api.AdjustTokenPrivileges.argtypes=[w.HANDLE,w.BOOL,ctypes.POINTER(Privilege),w.DWORD,ctypes.POINTER(Privilege),ctypes.POINTER(w.DWORD)]
    token=w.HANDLE();new=Privilege();old=Privilege();size=w.DWORD();new.count=1;new.attributes=2
    if not api.OpenProcessToken(kernel.GetCurrentProcess(),0x28,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not api.LookupPrivilegeValueW(None,'SeShutdownPrivilege',ctypes.byref(new.luid)):raise ctypes.WinError(ctypes.get_last_error())
        ctypes.set_last_error(0)
        if not api.AdjustTokenPrivileges(token,False,ctypes.byref(new),ctypes.sizeof(old),ctypes.byref(old),ctypes.byref(size)) or ctypes.get_last_error():raise OSError('Shutdown privilege unavailable')
        yield
    finally:
        if old.count:api.AdjustTokenPrivileges(token,False,ctypes.byref(old),0,None,None)
        kernel.CloseHandle(token)

def session_action(action):
    # This command runs only as the actual session user; no privileged action.
    from .remote_windows import interactive_desktop
    if not interactive_desktop():raise OSError('Interactive desktop required')
    user=ctypes.WinDLL('user32',use_last_error=True)
    if action=='idle':
        class Last(ctypes.Structure):_fields_=[('size',w.UINT),('tick',w.DWORD)]
        info=Last();info.size=ctypes.sizeof(info);user.GetLastInputInfo.argtypes=[ctypes.POINTER(Last)]
        if not user.GetLastInputInfo(ctypes.byref(info)):raise ctypes.WinError(ctypes.get_last_error())
        kernel=ctypes.WinDLL('kernel32');kernel.GetTickCount.restype=w.DWORD
        return 0x10000+min(604800,((kernel.GetTickCount()-info.tick)&0xffffffff)//1000)
    if action=='lock':ok=user.LockWorkStation()
    elif action=='logoff':ok=user.ExitWindowsEx(0,0x80040000)
    else:raise ValueError('Only fixed session actions supported')
    if not ok:raise ctypes.WinError(ctypes.get_last_error())

def launch_session_action(session,action):
    if action not in ('lock','logoff','idle'):raise ValueError('Unsupported session action')
    if not getattr(sys,'frozen',False):raise OSError('Session action requires the protected installed executable')
    from .update_native import folder,protected_tree
    exe=folder(38)/'USBControl'/'GuardDesk.exe'
    if os.path.normcase(os.path.realpath(sys.executable))!=os.path.normcase(str(exe.resolve())):raise OSError('Fixed installed native executable required')
    protected_tree(exe.parent,recursive=False);protected_tree(exe)
    class Startup(ctypes.Structure):
        _fields_=[('cb',w.DWORD),('reserved',w.LPWSTR),('desktop',w.LPWSTR),('title',w.LPWSTR),('x',w.DWORD),('y',w.DWORD),('xs',w.DWORD),('ys',w.DWORD),('xc',w.DWORD),('yc',w.DWORD),('fill',w.DWORD),('flags',w.DWORD),('show',w.WORD),('reserved2',w.WORD),('reserved_ptr',w.LPVOID),('stdin',w.HANDLE),('stdout',w.HANDLE),('stderr',w.HANDLE)]
    class Process(ctypes.Structure):_fields_=[('process',w.HANDLE),('thread',w.HANDLE),('pid',w.DWORD),('tid',w.DWORD)]
    wts=ctypes.WinDLL('wtsapi32',use_last_error=True);adv=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    wts.WTSQueryUserToken.argtypes=[w.ULONG,ctypes.POINTER(w.HANDLE)]
    adv.CreateProcessAsUserW.argtypes=[w.HANDLE,w.LPCWSTR,w.LPWSTR,w.LPVOID,w.LPVOID,w.BOOL,w.DWORD,w.LPVOID,w.LPCWSTR,ctypes.POINTER(Startup),ctypes.POINTER(Process)]
    kernel.CloseHandle.argtypes=[w.HANDLE];kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];kernel.GetExitCodeProcess.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)]
    token=w.HANDLE();process=Process();startup=Startup();startup.cb=ctypes.sizeof(startup);startup.desktop='winsta0\\default'
    if not wts.WTSQueryUserToken(session,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
    try:
        command=ctypes.create_unicode_buffer(subprocess.list2cmdline([str(exe),'custom-session-action','--action',action]))
        if not adv.CreateProcessAsUserW(token,str(exe),command,None,None,False,0x08000000,None,str(exe.parent),ctypes.byref(startup),ctypes.byref(process)):raise ctypes.WinError(ctypes.get_last_error())
        if kernel.WaitForSingleObject(process.process,5000)!=0:raise OSError('Session action confirmation timed out')
        code=w.DWORD()
        if not kernel.GetExitCodeProcess(process.process,ctypes.byref(code)):raise OSError('Session action was not accepted')
        if action=='idle':
            if not 0x10000<=code.value<=0x10000+604800:raise OSError('Invalid idle helper response')
            return code.value-0x10000
        if code.value:raise OSError('Session action was not accepted')
    finally:
        for handle in (process.thread,process.process,token):
            if handle:kernel.CloseHandle(handle)

def execute(action,session_ids):
    if action not in ACTION_NAMES:raise ValueError('Unsupported fixed action')
    if action in ('lock','logoff'):
        for session in session_ids:launch_session_action(session,action)
        return
    with enable_shutdown():
        if action in ('shutdown','restart'):
            api=ctypes.WinDLL('advapi32',use_last_error=True)
            api.InitiateSystemShutdownExW.argtypes=[w.LPWSTR,w.LPWSTR,w.DWORD,w.BOOL,w.BOOL,w.DWORD]
            if not api.InitiateSystemShutdownExW(None,'GuardDesk 已授權排程',0,False,action=='restart',0x80040000):raise ctypes.WinError(ctypes.get_last_error())
        else:
            api=ctypes.WinDLL('powrprof',use_last_error=True);api.SetSuspendState.argtypes=[ctypes.c_ubyte,ctypes.c_ubyte,ctypes.c_ubyte];api.SetSuspendState.restype=ctypes.c_ubyte
            if not api.SetSuspendState(action=='hibernate',False,False):raise ctypes.WinError(ctypes.get_last_error())

class WindowsActions:
    sessions=staticmethod(sessions)
    idle_minutes=staticmethod(idle_minutes)
    prompt=staticmethod(prompt)
    execute=staticmethod(execute)
    @staticmethod
    def boot_age():
        api=ctypes.WinDLL('kernel32');api.GetTickCount64.restype=ctypes.c_ulonglong
        return api.GetTickCount64()/1000
