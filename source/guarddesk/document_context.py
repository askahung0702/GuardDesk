"""Bounded session metadata for ordinary file-access correlation, never authority.

No keyboard hooks, key contents, pointer coordinates, window titles or screens.
The protected parent launches only its fixed executable as the session user.
The one-way local pipe admits only that exact child PID; payloads cannot request
any privileged operation. Missing context is reported rather than called human.
"""
import collections
import ctypes
import json
import math
import os
import re
import subprocess
import sys
import time
import uuid
from ctypes import wintypes as w

PIPE_PREFIX=r'\\.\pipe\GuardDesk-DocumentContext-'
MAX_SESSIONS=8


def valid_sample(value,session,now):
    if not isinstance(value,dict) or set(value)!={'session','time','idle_ms','input_tick','foreground_pid','desktop'}:return False
    if type(value['session']) is not int or value['session']!=session:return False
    if type(value['time']) not in (int,float) or not math.isfinite(value['time']) or not -1<=now-value['time']<=3:return False
    for key,limit in (('idle_ms',0xffffffff),('input_tick',0xffffffff),('foreground_pid',0xffffffff)):
        if type(value[key]) is not int or not 0<=value[key]<=limit:return False
    return type(value['desktop']) is bool


def sample():
    from .remote_windows import interactive_desktop
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);user=ctypes.WinDLL('user32',use_last_error=True)
    class Last(ctypes.Structure):_fields_=[('size',w.UINT),('tick',w.DWORD)]
    last=Last();last.size=ctypes.sizeof(last)
    user.GetLastInputInfo.argtypes=[ctypes.POINTER(Last)];user.GetLastInputInfo.restype=w.BOOL
    kernel.GetTickCount.restype=w.DWORD
    kernel.ProcessIdToSessionId.argtypes=[w.DWORD,ctypes.POINTER(w.DWORD)]
    user.GetForegroundWindow.restype=w.HWND
    user.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
    session=w.DWORD();pid=w.DWORD()
    if not kernel.ProcessIdToSessionId(os.getpid(),ctypes.byref(session)) or not session.value:raise OSError('User session required')
    if not user.GetLastInputInfo(ctypes.byref(last)):raise ctypes.WinError(ctypes.get_last_error())
    hwnd=user.GetForegroundWindow()
    if hwnd:user.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
    return {'session':session.value,'time':time.time(),'idle_ms':(kernel.GetTickCount()-last.tick)&0xffffffff,
            'input_tick':last.tick,'foreground_pid':pid.value,'desktop':interactive_desktop()}


def kernel_api():
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.CloseHandle.argtypes=[w.HANDLE]
    api.CreateNamedPipeW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.LPVOID];api.CreateNamedPipeW.restype=w.HANDLE
    api.ConnectNamedPipe.argtypes=[w.HANDLE,w.LPVOID];api.ConnectNamedPipe.restype=w.BOOL
    api.DisconnectNamedPipe.argtypes=[w.HANDLE]
    api.GetNamedPipeClientProcessId.argtypes=[w.HANDLE,ctypes.POINTER(w.ULONG)]
    api.GetNamedPipeServerProcessId.argtypes=[w.HANDLE,ctypes.POINTER(w.ULONG)]
    api.PeekNamedPipe.argtypes=[w.HANDLE,w.LPVOID,w.DWORD,w.LPVOID,ctypes.POINTER(w.DWORD),w.LPVOID]
    api.ReadFile.argtypes=[w.HANDLE,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD),w.LPVOID]
    api.WriteFile.argtypes=[w.HANDLE,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD),w.LPVOID]
    api.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE];api.CreateFileW.restype=w.HANDLE
    api.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];api.WaitForSingleObject.restype=w.DWORD
    api.TerminateProcess.argtypes=[w.HANDLE,w.UINT]
    api.SetNamedPipeHandleState.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD),w.LPVOID,w.LPVOID]
    api.LocalFree.argtypes=[w.LPVOID]
    return api


def run_helper(pipe,parent_pid):
    if not re.fullmatch(re.escape(PIPE_PREFIX)+r'[0-9a-f]{32}',pipe) or not 4<parent_pid<2**32:raise ValueError('Invalid document context endpoint')
    api=kernel_api();handle=None;deadline=time.monotonic()+10
    try:
        api.GetCurrentThread.restype=w.HANDLE;api.SetThreadPriority.argtypes=[w.HANDLE,ctypes.c_int]
        api.SetThreadPriority(api.GetCurrentThread(),-1)
        while time.monotonic()<deadline:
            handle=api.CreateFileW(pipe,0x40000000,0,None,3,0,None)
            if handle!=ctypes.c_void_p(-1).value:break
            handle=None;time.sleep(.1)
        if not handle:raise OSError('Document context pipe unavailable')
        server=w.ULONG()
        if not api.GetNamedPipeServerProcessId(handle,ctypes.byref(server)) or server.value!=parent_pid:raise OSError('Document context parent mismatch')
        mode=w.DWORD(1)
        if not api.SetNamedPipeHandleState(handle,ctypes.byref(mode),None,None):raise ctypes.WinError(ctypes.get_last_error())
        # Never block writing into a stalled parent. Pipe closure/full buffer,
        # logout or parent exit ends this fixed-frequency, bounded helper.
        while True:
            value=sample();payload=(json.dumps(value,separators=(',',':'))+'\n').encode('ascii');count=w.DWORD()
            if not api.WriteFile(handle,payload,len(payload),ctypes.byref(count),None) or count.value!=len(payload):break
            time.sleep(.5)
    finally:
        if handle:api.CloseHandle(handle)


def token_sid(token):
    class User(ctypes.Structure):_fields_=[('sid',w.LPVOID),('attributes',w.DWORD)]
    api=ctypes.WinDLL('advapi32',use_last_error=True);kernel=kernel_api();size=w.DWORD()
    api.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
    api.ConvertSidToStringSidW.argtypes=[w.LPVOID,ctypes.POINTER(w.LPWSTR)]
    api.GetTokenInformation(token,1,None,0,ctypes.byref(size))
    if not 0<size.value<65536:raise OSError('Invalid token information size')
    buffer=ctypes.create_string_buffer(size.value);text=w.LPWSTR()
    if not api.GetTokenInformation(token,1,buffer,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
    if not api.ConvertSidToStringSidW(ctypes.cast(buffer,ctypes.POINTER(User)).contents.sid,ctypes.byref(text)):raise ctypes.WinError(ctypes.get_last_error())
    try:return text.value
    finally:kernel.LocalFree(text)


class Channel:
    """Local one-writer stream with restricted DACL and child PID binding."""
    def __init__(self,sid):
        if not re.fullmatch(r'S-1-(?:\d+-)*\d+',sid):raise ValueError('Invalid SID')
        self.api=kernel_api();self.handle=None;self.process=None;self.pid=None;self.connected=False;self.buffer=b''
        self.pipe=PIPE_PREFIX+uuid.uuid4().hex
        class Security(ctypes.Structure):_fields_=[('size',w.DWORD),('descriptor',w.LPVOID),('inherit',w.BOOL)]
        adv=ctypes.WinDLL('advapi32',use_last_error=True);descriptor=w.LPVOID()
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID]
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW('D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;GW;;;'+sid+')',1,ctypes.byref(descriptor),None):raise ctypes.WinError(ctypes.get_last_error())
        try:
            security=Security(ctypes.sizeof(Security),descriptor,False)
            self.handle=self.api.CreateNamedPipeW(self.pipe,1|0x80000,1|8,1,4096,4096,0,ctypes.byref(security))
            if self.handle==ctypes.c_void_p(-1).value:self.handle=None;raise ctypes.WinError(ctypes.get_last_error())
        finally:self.api.LocalFree(descriptor)

    def poll(self):
        if not self.pid or not self.process:return []
        if self.api.WaitForSingleObject(self.process,0)==0:raise OSError('Session context helper exited')
        if not self.connected:
            ok=self.api.ConnectNamedPipe(self.handle,None);error=ctypes.get_last_error()
            if not ok and error not in (535,):
                if error in (536,232):return []
                raise ctypes.WinError(error)
            peer=w.ULONG()
            if not self.api.GetNamedPipeClientProcessId(self.handle,ctypes.byref(peer)) or peer.value!=self.pid:
                self.api.DisconnectNamedPipe(self.handle);raise OSError('Session context writer identity mismatch')
            self.connected=True
        available=w.DWORD()
        if not self.api.PeekNamedPipe(self.handle,None,0,None,ctypes.byref(available),None):raise ctypes.WinError(ctypes.get_last_error())
        if available.value:
            buffer=ctypes.create_string_buffer(min(4096,available.value));count=w.DWORD()
            if not self.api.ReadFile(self.handle,buffer,len(buffer),ctypes.byref(count),None):raise ctypes.WinError(ctypes.get_last_error())
            self.buffer+=buffer.raw[:count.value]
        if len(self.buffer)>8192:raise OSError('Session context stream exceeded limit')
        lines=self.buffer.split(b'\n');self.buffer=lines.pop()
        if len(lines)>16 or any(len(line)>512 for line in lines):raise OSError('Session context frame exceeded limit')
        return [json.loads(line) for line in lines]

    def close(self):
        if self.handle:self.api.CloseHandle(self.handle);self.handle=None
        if self.process:
            # Only the exact child HANDLE created by us, never a PID lookup.
            if self.api.WaitForSingleObject(self.process,100)!=0:self.api.TerminateProcess(self.process,0)
            self.api.CloseHandle(self.process);self.process=None


def launch(session):
    from .update_native import folder,protected_tree
    exe=folder(38)/'USBControl'/'GuardDesk.exe'
    if not getattr(sys,'frozen',False) or os.path.normcase(os.path.realpath(sys.executable))!=os.path.normcase(str(exe.resolve())):raise OSError('Installed protected native executable required')
    protected_tree(exe.parent,recursive=False);protected_tree(exe)
    # A standard session token must be able to execute this immutable code.
    # This runs in the NEW native worker, so old updater copies are covered.
    from .context_permissions import ensure_installed_runtime
    try:ensure_installed_runtime()
    except OSError as exc:
        exc.context_stage='runtime_permissions';raise
    class Startup(ctypes.Structure):
        _fields_=[('cb',w.DWORD),('reserved',w.LPWSTR),('desktop',w.LPWSTR),('title',w.LPWSTR),('x',w.DWORD),('y',w.DWORD),('xs',w.DWORD),('ys',w.DWORD),('xc',w.DWORD),('yc',w.DWORD),('fill',w.DWORD),('flags',w.DWORD),('show',w.WORD),('reserved2',w.WORD),('reserved_ptr',w.LPVOID),('stdin',w.HANDLE),('stdout',w.HANDLE),('stderr',w.HANDLE)]
    class Process(ctypes.Structure):_fields_=[('process',w.HANDLE),('thread',w.HANDLE),('pid',w.DWORD),('tid',w.DWORD)]
    wts=ctypes.WinDLL('wtsapi32',use_last_error=True);adv=ctypes.WinDLL('advapi32',use_last_error=True);api=kernel_api()
    wts.WTSQueryUserToken.argtypes=[w.ULONG,ctypes.POINTER(w.HANDLE)]
    adv.CreateProcessAsUserW.argtypes=[w.HANDLE,w.LPCWSTR,w.LPWSTR,w.LPVOID,w.LPVOID,w.BOOL,w.DWORD,w.LPVOID,w.LPCWSTR,ctypes.POINTER(Startup),ctypes.POINTER(Process)]
    token=w.HANDLE();channel=None;process=Process()
    if not wts.WTSQueryUserToken(session,ctypes.byref(token)):
        exc=ctypes.WinError(ctypes.get_last_error());exc.context_stage='user_token';raise exc
    try:
        channel=Channel(token_sid(token));startup=Startup();startup.cb=ctypes.sizeof(startup);startup.desktop='winsta0\\default'
        command=ctypes.create_unicode_buffer(subprocess.list2cmdline([str(exe),'document-session-context','--pipe',channel.pipe,'--parent',str(os.getpid())]))
        if not adv.CreateProcessAsUserW(token,str(exe),command,None,None,False,0x08000000,None,str(exe.parent),ctypes.byref(startup),ctypes.byref(process)):
            exc=ctypes.WinError(ctypes.get_last_error());exc.context_stage='create_user_process';raise exc
        channel.process=process.process;channel.pid=process.pid;return channel
    except BaseException:
        if channel:channel.close()
        raise
    finally:
        if process.thread:api.CloseHandle(process.thread)
        api.CloseHandle(token)


def user_session_states(rows):
    """Listeners/reset/down entries are not logged-on user sessions.

    A failed real session remains explicitly unknown; it must neither erase
    other sessions nor be reported as a verified locked/inactive session.
    """
    from .windows_sessions import session_information
    result={}
    for session,state in rows:
        if not session or state not in (0,1,2,3,4):continue
        if len(result)>=MAX_SESSIONS:raise OSError('Too many user sessions')
        try:info=session_information(session)
        except OSError as exc:
            result[session]={'active':state==0,'locked':False,'logon':0,'time':time.time(),'query_failed':True,
                             'query_error':{'error_type':type(exc).__name__,'winerror':getattr(exc,'winerror',None)}}
            continue
        if info['logon']>0:result[session]={**info,'active':state==0,'time':time.time()}
    return result


def session_states():
    """WTS metadata only: no DNS, account inventory or subprocess per poll."""
    class Info(ctypes.Structure):_fields_=[('id',w.DWORD),('station',w.LPWSTR),('state',ctypes.c_int)]
    api=ctypes.WinDLL('wtsapi32',use_last_error=True);values=ctypes.POINTER(Info)();count=w.DWORD()
    api.WTSEnumerateSessionsW.argtypes=[w.HANDLE,w.DWORD,w.DWORD,ctypes.POINTER(ctypes.POINTER(Info)),ctypes.POINTER(w.DWORD)]
    api.WTSFreeMemory.argtypes=[w.LPVOID]
    if not api.WTSEnumerateSessionsW(None,0,1,ctypes.byref(values),ctypes.byref(count)):raise ctypes.WinError(ctypes.get_last_error())
    try:
        if count.value>32:raise OSError('Too many sessions')
        return user_session_states([(entry.id,entry.state) for entry in values[:count.value]])
    finally:api.WTSFreeMemory(values)


class Context:
    def __init__(self):
        self.channels={};self.samples={};self.states={};self.next_scan=0;self.retry={};self.errors=0;self.query_ok=False;self.last_error=None
    def failure(self,operation,exc):
        self.errors+=1
        self.last_error={'operation':getattr(exc,'context_stage',operation),'winerror':getattr(exc,'winerror',None),'error_type':type(exc).__name__,'time':time.time()}
    def close(self):
        for channel in self.channels.values():channel.close()
        self.channels.clear();self.samples.clear();self.states.clear();self.retry.clear();self.query_ok=False;self.next_scan=0
    def poll(self):
        if time.monotonic()>=self.next_scan:
            self.next_scan=time.monotonic()+2
            previous=self.states
            try:
                self.states=session_states();self.query_ok=True
            except OSError as exc:self.states={};self.failure('session_query',exc);self.query_ok=False
            for sid in list(self.channels):
                state=self.states.get(sid,{})
                if not state.get('active') or state.get('locked') or state.get('query_failed') or previous.get(sid,{}).get('logon')!=state.get('logon'):
                    self.channels.pop(sid).close();self.samples.pop(sid,None);self.retry.pop(sid,None)
            for sid,state in self.states.items():
                if not sid or not state['active'] or state['locked'] or state.get('query_failed') or sid in self.channels or time.monotonic()<self.retry.get(sid,0):continue
                self.retry[sid]=time.monotonic()+30
                try:self.channels[sid]=launch(sid)
                except OSError as exc:self.failure('launch',exc)
            self.retry={sid:stamp for sid,stamp in self.retry.items() if sid in self.states}
        for sid,channel in list(self.channels.items()):
            try:
                for value in channel.poll():
                    # WTS queries/launches can be delayed by OS security scans.
                    # Validate against receipt time, never a pre-launch clock.
                    if not valid_sample(value,sid,time.time()):raise ValueError('Invalid session context')
                    history=self.samples.setdefault(sid,collections.deque(maxlen=20))
                    if history and value['time']<=history[-1]['time']:raise ValueError('Replayed session context')
                    history.append(value)
            except (OSError,ValueError) as exc:
                self.failure('pipe_or_sample',exc);channel.close();self.channels.pop(sid,None);self.samples.pop(sid,None)
                self.retry[sid]=time.monotonic()+30
    def classify(self,details,occurred,seconds):
        sid=details.get('process_session_id');state=self.states.get(sid)
        if details.get('process_identity_status')!='creation_time_checked' or not state:return 'context_unavailable',None
        if state.get('query_failed'):return 'context_unavailable',None
        if not state['active'] or state['locked']:return 'session_inactive',None
        if not 0<=time.time()-state['time']<4:return 'context_unavailable',None
        candidates=[s for s in self.samples.get(sid,()) if -5<=occurred-s['time']<=2]
        if not candidates:return 'context_unavailable',None
        # A foreground switch can happen just after an open. Samples on either
        # side within this bounded interval can establish only an association.
        recent=False
        for value in reversed(candidates):
            if type(details.get('process_created')) not in (int,float) or value['time']<details['process_created']:continue
            age=max(0,occurred-value['time'])+value['idle_ms']/1000
            input_at=value['time']-value['idle_ms']/1000
            eligible=value['desktop'] and input_at<=occurred+.05 and age<=seconds
            recent=recent or eligible
            if eligible and value['foreground_pid']==details.get('process_id'):
                return None,{'interaction':'recent_input_foreground','input_age_seconds':round(age,3),'physical_input_confirmed':False,
                             'context_source':'user_session_metadata','_interaction_key':(sid,state['logon'],value['input_tick'])}
        return ('foreground_not_observed' if recent else 'background_or_idle'),None
    def status(self):
        return {'sessions':len(self.states),'active_sessions':sum(bool(s['active'] and not s['locked']) for s in self.states.values()),'session_query_available':self.query_ok or bool(self.states),
                'helpers':len(self.channels),'fresh_samples':sum(bool(v and 0<=time.time()-v[-1]['time']<3) for v in self.samples.values()),'errors':self.errors,'last_error':self.last_error,
                'session_query_failures':sum(bool(s.get('query_failed')) for s in self.states.values())}
