"""Consent-bound SYSTEM child in the existing user's WTS session.

No service GUI, alternate credential collection, token theft, policy changes,
shell, new listener or persistent task. Only the fixed installed image runs.
The ordinary helper owns consent/stop; this child owns capture and input.
"""
import ctypes
from ctypes import wintypes as w
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time

# SetTokenInformation(TokenSessionId) checks both ADJUST_DEFAULT and
# ADJUST_SESSIONID. No privilege adjustment is needed on this child token.
# QUERY / DUPLICATE / ASSIGN_PRIMARY are required by CreateProcessAsUserW.
PRIMARY_SESSION_ACCESS=0x0080|0x0100|0x0008|0x0002|0x0001
# A capture-only desktop handle omits playback rights needed by input on the
# secure desktop. Request this right from the existing ACL; never change it.
# No hook, journal-record, create-window, WRITE_DAC or generic-all access.
CONTROL_DESKTOP_ACCESS=0x0001|0x0080|0x0100|0x0020


def identity():
    from .native_browser_identity import _windows,_process_sid,_snapshot
    api=_windows();api.GetCurrentProcess.restype=w.HANDLE
    if _process_sid(api.GetCurrentProcess())!='S-1-5-18':
        raise PermissionError('Management assistance requires the installed SYSTEM broker')
    return api,_snapshot(api,api.GetCurrentProcess())


def ticket_path(did,sid):
    if not isinstance(did,str) or not re.fullmatch('[0-9a-f]{24}',did):raise ValueError('Invalid device')
    if not isinstance(sid,str) or not re.fullmatch('[0-9a-f]{32}',sid):raise ValueError('Invalid session')
    from .update_native import folder
    return folder(35)/'USBControl'/did/'remote-admin'/('lease-'+sid+'.json')


def validate_ticket(value,did,sid,now=None):
    now=time.time() if now is None else now
    fields={'format','device_id','session_id','session','sid','logon','parent','parent_created','expires','admin_nonce','quality','operator','cancel_handle'}
    if not isinstance(value,dict) or set(value)!=fields or value['format']!=1:
        raise ValueError('Invalid management lease')
    if value['device_id']!=did or value['session_id']!=sid:raise PermissionError('Management lease identity mismatch')
    if (type(value['session']) is not int or not 0<value['session']<2**32
        or type(value['parent']) is not int or not 4<value['parent']<2**32
        or type(value['cancel_handle']) is not int or not 0<value['cancel_handle']<2**64
        or any(type(value[k]) is not int or value[k]<=0 for k in ('logon','parent_created'))
        or not isinstance(value['sid'],str) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){2,}[0-9]+',value['sid'])
        or type(value['expires']) not in (int,float) or not now<value['expires']<=now+610
        or not isinstance(value['admin_nonce'],str) or not re.fullmatch('[0-9a-f]{64}',value['admin_nonce'])
        or value['quality'] not in ('balanced','clarity','economy')
        or not isinstance(value['operator'],str) or not 0<len(value['operator'])<=80):
        raise ValueError('Invalid management lease values')
    return value


@contextmanager
def session_privilege():
    """Enable the already held SeTcbPrivilege on this thread, restore afterwards."""
    identity()
    api=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    class Luid(ctypes.Structure):_fields_=[('low',w.DWORD),('high',w.LONG)]
    class Privileges(ctypes.Structure):_fields_=[('count',w.DWORD),('luid',Luid),('attributes',w.DWORD)]
    kernel.GetCurrentThread.restype=w.HANDLE;kernel.CloseHandle.argtypes=[w.HANDLE]
    api.ImpersonateSelf.argtypes=[ctypes.c_int];api.RevertToSelf.restype=w.BOOL
    api.OpenThreadToken.argtypes=[w.HANDLE,w.DWORD,w.BOOL,ctypes.POINTER(w.HANDLE)]
    api.LookupPrivilegeValueW.argtypes=[w.LPCWSTR,w.LPCWSTR,ctypes.POINTER(Luid)]
    api.AdjustTokenPrivileges.argtypes=[w.HANDLE,w.BOOL,ctypes.POINTER(Privileges),w.DWORD,ctypes.POINTER(Privileges),ctypes.POINTER(w.DWORD)]
    token=w.HANDLE();old=Privileges();changed=False
    # Caller must not be impersonating a pipe client. Listener reverts first.
    existing=w.HANDLE()
    if api.OpenThreadToken(kernel.GetCurrentThread(),8,True,ctypes.byref(existing)):
        kernel.CloseHandle(existing);raise PermissionError('Unexpected impersonation context')
    if ctypes.get_last_error()!=1008:raise ctypes.WinError(ctypes.get_last_error())
    if not api.ImpersonateSelf(2):raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not api.OpenThreadToken(kernel.GetCurrentThread(),0x28,True,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
        wanted=Privileges(1,Luid(),2);size=w.DWORD()
        if not api.LookupPrivilegeValueW(None,'SeTcbPrivilege',ctypes.byref(wanted.luid)):raise ctypes.WinError(ctypes.get_last_error())
        ctypes.set_last_error(0)
        if not api.AdjustTokenPrivileges(token,False,ctypes.byref(wanted),ctypes.sizeof(old),ctypes.byref(old),ctypes.byref(size)) or ctypes.get_last_error():
            raise ctypes.WinError(ctypes.get_last_error())
        changed=True;yield
    finally:
        try:
            if changed and not api.AdjustTokenPrivileges(token,False,ctypes.byref(old),0,None,None):raise SystemExit('Cannot restore management privilege')
        finally:
            if token:kernel.CloseHandle(token)
            if not api.RevertToSelf():raise SystemExit('Cannot restore management identity')


def spawn_system_session(exe,arguments,session):
    """Internal primitive; caller validates fixed image/arguments and lease first."""
    api,_=identity()
    class Startup(ctypes.Structure):
        _fields_=[('cb',w.DWORD),('reserved',w.LPWSTR),('desktop',w.LPWSTR),('title',w.LPWSTR),('x',w.DWORD),('y',w.DWORD),('xs',w.DWORD),('ys',w.DWORD),('xc',w.DWORD),('yc',w.DWORD),('fill',w.DWORD),('flags',w.DWORD),('show',w.WORD),('reserved2',w.WORD),('reserved_ptr',w.LPVOID),('stdin',w.HANDLE),('stdout',w.HANDLE),('stderr',w.HANDLE)]
    class Process(ctypes.Structure):_fields_=[('process',w.HANDLE),('thread',w.HANDLE),('pid',w.DWORD),('tid',w.DWORD)]
    adv=ctypes.WinDLL('advapi32',use_last_error=True)
    adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)]
    adv.DuplicateTokenEx.argtypes=[w.HANDLE,w.DWORD,w.LPVOID,ctypes.c_int,ctypes.c_int,ctypes.POINTER(w.HANDLE)]
    adv.SetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD]
    adv.CreateProcessAsUserW.argtypes=[w.HANDLE,w.LPCWSTR,w.LPWSTR,w.LPVOID,w.LPVOID,w.BOOL,w.DWORD,w.LPVOID,w.LPCWSTR,ctypes.POINTER(Startup),ctypes.POINTER(Process)]
    source=w.HANDLE();token=w.HANDLE();process=Process()
    try:
        if not adv.OpenProcessToken(api.GetCurrentProcess(),0x0b,ctypes.byref(source)):raise ctypes.WinError(ctypes.get_last_error())
        if not adv.DuplicateTokenEx(source,PRIMARY_SESSION_ACCESS,None,2,1,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
        target=w.DWORD(session)
        with session_privilege():
            if not adv.SetTokenInformation(token,12,ctypes.byref(target),ctypes.sizeof(target)):raise ctypes.WinError(ctypes.get_last_error())
        startup=Startup();startup.cb=ctypes.sizeof(startup);startup.desktop='winsta0\\default'
        command=ctypes.create_unicode_buffer(subprocess.list2cmdline([str(exe),*arguments]))
        # Inherit broker's SYSTEM environment, never an employee's PATH/PYTHONPATH.
        # Task Scheduler normally starts the SYSTEM broker below normal. An
        # explicitly consented interactive worker must not inherit background
        # CPU/I/O scheduling. NORMAL is not HIGH/REALTIME and adds no rights.
        if not adv.CreateProcessAsUserW(token,str(exe),command,None,None,False,0x08000000|0x20,None,str(exe.parent),ctypes.byref(startup),ctypes.byref(process)):
            raise ctypes.WinError(ctypes.get_last_error())
        from .machine_agent_windows import Child
        return Child(api,process.process)
    finally:
        if process.thread:api.CloseHandle(process.thread)
        if token:api.CloseHandle(token)
        if source:api.CloseHandle(source)


class Launcher:
    def __init__(self,agent):
        self.agent=agent;self.children={};self.lock=threading.Lock()
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel.CreateEventW.argtypes=[w.LPVOID,w.BOOL,w.BOOL,w.LPCWSTR]
        self.kernel.CreateEventW.restype=w.HANDLE
        self.kernel.SetEvent.argtypes=[w.HANDLE]
        self.kernel.CloseHandle.argtypes=[w.HANDLE]

    def reserve(self,sid):
        with self.lock:
            if sid in self.children:return
            if len(self.children)>=4:raise PermissionError('Management reservation capacity exceeded')
            self.children[sid]={'cancelled':False,'launching':False,'event':None,'child':None,'path':None}

    def revoke(self,sid):
        # Called while Router owns its local lock: no network, disk or wait.
        with self.lock:
            item=self.children.get(sid)
            if not item:return
            item['cancelled']=True
            if item['event'] and not self.kernel.SetEvent(item['event']):
                raise ctypes.WinError(ctypes.get_last_error())

    def launch(self,session,peer,state,result):
        from .machine_agent import eligible
        from .machine_agent_windows import installed_image
        from .protected_files import ProtectedFiles as Windows,encode
        from .update_native import protected_tree
        if not eligible(self.agent):raise PermissionError('Installed broker required')
        api,snapshot=identity();sid=session['id'];did=self.agent.config['device_id']
        with self.lock:
            item=self.children.get(sid)
            if not item or item['cancelled'] or item['launching'] or item['child']:
                raise PermissionError('Management approval no longer available')
            item['launching']=True
            event=self.kernel.CreateEventW(None,True,False,None)
            if not event:
                item['launching']=False
                raise ctypes.WinError(ctypes.get_last_error())
            item['event']=event
        try:
            path=ticket_path(did,sid)
            for directory in (self.agent.config_path.parent,path.parent):
                if directory.exists():protected_tree(directory,recursive=False)
                else:Windows().protect(directory,create=True)
            protected_tree(self.agent.config_path,recursive=False)
            protected_tree(installed_image(),recursive=False)
            for count,_ in enumerate(path.parent.iterdir(),1):
                if count>32:raise OSError('Management lease directory needs MIS review')
            value=dict(format=1,device_id=did,session_id=sid,session=peer['session'],sid=state['sid'],logon=state['logon'],
                parent=os.getpid(),parent_created=snapshot[1],expires=result['expires'],admin_nonce=result['admin_nonce'],
                quality=session.get('quality','balanced'),operator=session['operator'],cancel_handle=int(event))
            validate_ticket(value,did,sid)
            if path.exists():raise PermissionError('Management lease already exists')
            Windows().write(path,encode(value));item['path']=path
            with self.lock:
                if item['cancelled']:raise PermissionError('Management launch cancelled')
            child=spawn_system_session(installed_image(),['remote-admin-session','--device-id',did,'--session-id',sid],peer['session'])
            with self.lock:
                item['child']=child;item['launching']=False
                cancelled=item['cancelled']
            if cancelled:
                self.stop(sid);raise PermissionError('Management launch cancelled')
        except BaseException:
            with self.lock:item['launching']=False
            self.stop(sid)
            raise

    def alive(self,sid):
        with self.lock:
            item=self.children.get(sid)
            return bool(item and not item['cancelled'] and item['child'] and item['child'].alive())

    def stop(self,sid):
        self.revoke(sid)
        with self.lock:
            item=self.children.get(sid)
            if not item or item['launching']:return  # launch observes its cancellation event
            self.children.pop(sid,None)
        child,path=item['child'],item['path']
        try:
            if child and child.alive():child.api.WaitForSingleObject(child.handle,1000)
            if child and child.alive():
                child.api.TerminateProcess.argtypes=[w.HANDLE,w.UINT]
                if not child.api.TerminateProcess(child.handle,0):raise ctypes.WinError(ctypes.get_last_error())
                if child.api.WaitForSingleObject(child.handle,3000)!=0:raise OSError('Management child has not exited')
        finally:
            if child:child.close()
            if path:path.unlink(missing_ok=True)
            if item['event']:self.kernel.CloseHandle(item['event'])


class DesktopTransition(OSError):pass


def uac_foreground(user, lease, verified):
    """Require the actual signed Microsoft UAC foreground in this WTS logon.

    Winlogon alone also covers other Windows secure UI and is not authority.
    Cache only the signature proof for the same live process identity.
    """
    from .native_browser_identity import _windows, _snapshot, signed_publisher
    api = _windows()
    user.GetForegroundWindow.restype = w.HWND
    user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    hwnd = user.GetForegroundWindow();pid = w.DWORD()
    if not hwnd or not user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid)):
        raise DesktopTransition('UAC foreground unavailable')
    handle = api.OpenProcess(0x1000 | 0x100000, False, pid.value)
    if not handle:raise DesktopTransition('UAC process unavailable')
    try:
        actual,created,session,image = _snapshot(api,handle)
        api.GetSystemDirectoryW.argtypes = [w.LPWSTR,w.UINT]
        directory = ctypes.create_unicode_buffer(32768)
        if not api.GetSystemDirectoryW(directory,len(directory)):
            raise DesktopTransition('System directory unavailable')
        expected = Path(directory.value)/'consent.exe'
        if (actual != pid.value or session != lease['session'] or Path(image) != expected
            or created/1e7-11644473600 < lease['expires']-600):
            raise DesktopTransition('Secure foreground is not the current UAC prompt')
        proof = (actual,created,session,str(expected))
        if verified != proof:
            # Windows binaries normally belong to TrustedInstaller, unlike
            # GuardDesk's SYSTEM/admin-only program tree. Use the existing
            # signed machine-image checker with that explicit OS owner policy.
            from .native_browser_identity import protected_browser_image
            protected_browser_image(expected)
            if signed_publisher(expected) != 'Microsoft Corporation':
                raise PermissionError('UAC publisher mismatch')
        if api.WaitForSingleObject(handle,0) != 258 or user.GetForegroundWindow() != hwnd:
            raise DesktopTransition('UAC foreground changed')
        return proof
    finally:api.CloseHandle(handle)


class Desktop:
    """Single capture/input thread; no GUI or hooks on its desktops."""
    def __init__(self,lease,parent_alive=lambda:True):
        self.lease=lease;self.parent_alive=parent_alive;self.handle=None;self.name=None;self.epoch=None
        self.verified_prompt=None
        self.generation=0
        self.authorization_deadline=0
        self.consent_deadline=time.monotonic()+min(600,max(0,lease['expires']-time.time()))
        self.api=ctypes.WinDLL('user32',use_last_error=True)
        self.api.OpenInputDesktop.argtypes=[w.DWORD,w.BOOL,w.DWORD];self.api.OpenInputDesktop.restype=w.HANDLE
        self.api.GetUserObjectInformationW.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
        self.api.SetThreadDesktop.argtypes=[w.HANDLE];self.api.CloseDesktop.argtypes=[w.HANDLE]
        self.api.GetThreadDesktop.argtypes=[w.DWORD];self.api.GetThreadDesktop.restype=w.HANDLE
        kernel=ctypes.WinDLL('kernel32');kernel.GetCurrentThreadId.restype=w.DWORD
        self.original=self.api.GetThreadDesktop(kernel.GetCurrentThreadId())
    def check_session(self):
        from .document_context import session_states
        states=session_states();target=states.get(self.lease['session'],{})
        if (not self.parent_alive() or time.time()>=self.lease['expires']
            or time.monotonic()>=getattr(self,'consent_deadline',float('inf')) or target.get('query_failed')
            or not target.get('active') or target.get('locked') or target.get('logon')!=self.lease['logon']
            or any(s.get('query_failed') for s in states.values())
            or sum(bool(s.get('active') and not s.get('locked')) for s in states.values())!=1):
            raise PermissionError('Management assistance logon ended or locked')

    def authorize(self,request_started=None):
        # Called only after an authenticated center response. Monotonic time
        # bounds a disconnected center even if the system clock moves back.
        self.authorization_deadline=(time.monotonic() if request_started is None else request_started)+5
        self.check_authorization()

    def check_authorization(self):
        if time.monotonic() >= self.authorization_deadline:
            raise PermissionError('Management control lease expired')

    def select(self):
        self.check_session()
        self.check_authorization()
        handle=self.api.OpenInputDesktop(0,False,CONTROL_DESKTOP_ACCESS)
        if not handle:raise DesktopTransition('Desktop transition not ready')
        try:
            name=ctypes.create_unicode_buffer(256);size=w.DWORD()
            if not self.api.GetUserObjectInformationW(handle,2,name,ctypes.sizeof(name),ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            name=name.value.casefold()
            if name not in ('default','winlogon'):raise PermissionError('Unsupported management desktop')
            if name==self.name:
                if name=='winlogon':self.verified_prompt=uac_foreground(self.api,self.lease,self.verified_prompt)
                return False
            if not self.api.SetThreadDesktop(handle):raise ctypes.WinError(ctypes.get_last_error())
            old=self.handle;self.handle=handle;handle=None;self.name=name;self.epoch=secrets.token_hex(16)
            self.generation+=1
            if old:self.api.CloseDesktop(old)
            if name=='winlogon':self.verified_prompt=uac_foreground(self.api,self.lease,self.verified_prompt)
            else:self.verified_prompt=None
            self.check_session();return True
        finally:
            if handle:self.api.CloseDesktop(handle)
    def guard(self):
        # Do not switch inside SendInput: the frame epoch must change first.
        before=self.epoch
        changed=self.select()
        if changed or self.epoch!=before:raise DesktopTransition('Desktop changed; discard pending frame/input')
        return True

    def release_guard(self):
        # Expired/revoked authority permits only release of keys we already
        # tracked, on the same desktop epoch. It never permits a new key down.
        from .document_context import session_states
        state=session_states().get(self.lease['session'],{})
        if state.get('query_failed') or not state.get('active') or state.get('locked') or state.get('logon')!=self.lease['logon']:
            return False
        handle=self.api.OpenInputDesktop(0,False,0x0001)
        if not handle:return False
        try:
            name=ctypes.create_unicode_buffer(256);size=w.DWORD()
            if not self.api.GetUserObjectInformationW(handle,2,name,ctypes.sizeof(name),ctypes.byref(size)):return False
            if name.value.casefold()!=self.name:return False
            if self.name=='winlogon':self.verified_prompt=uac_foreground(self.api,self.lease,self.verified_prompt)
            return True
        finally:self.api.CloseDesktop(handle)
    def close(self):
        if self.handle:
            if self.api.SetThreadDesktop(self.original):self.api.CloseDesktop(self.handle)
            self.handle=None


def assist(lease,call,desktop,stop):
    """Transport-independent loop, tested with synthetic desktop transitions."""
    from .remote_windows import Input,jpeg_frame,clarity_frame,capture_bgr
    inputs=Input(guard=desktop.guard,release_guard=desktop.release_guard,epoch=lambda:desktop.epoch)
    last=None;last_epoch=None;paused=False;phase='authorize'
    def invoke(action,**body):
        return call({'session_id':lease['session_id'],'action':action,'admin_nonce':lease['admin_nonce'],
            'desktop_epoch':desktop.epoch,'desktop_generation':desktop.generation,'desktop':desktop.name,**body})
    try:
        consent_deadline=time.monotonic()+min(600,max(0,lease['expires']-time.time()))
        while not stop.is_set() and time.time()<lease['expires'] and time.monotonic()<consent_deadline:
            started=time.monotonic()
            try:
                phase='authorize'
                authorized=invoke('admin_validate')
                if authorized.get('status')!='active':break
                if authorized.get('admin_protocol')!=6:raise PermissionError('Management Server protocol changed')
                desktop.authorize(started)
                changed=desktop.select()
                if paused:
                    # Even returning to the same desktop invalidates in-flight
                    # input from before the interruption.
                    desktop.epoch=secrets.token_hex(16)
                    desktop.generation+=1
                if changed or paused or last_epoch!=desktop.epoch:
                    inputs.release();last=None
                capture=lambda *args,**kwargs:capture_bgr(*args,**kwargs,_desktop_guard=desktop.guard)
                phase='capture'
                try:
                    frame=clarity_frame(_capture=capture) if lease['quality']=='clarity' else jpeg_frame(lease['quality']=='economy',_capture=capture)
                except DesktopTransition:raise
                except OSError:
                    # GDI may fail between the pre-capture guard and a desktop
                    # switch. Only a verified transition is resumable; a stable
                    # desktop's capture failure retains the original exception.
                    desktop.guard()
                    raise
                # A transition during capture must discard the old pixels.
                if not desktop.guard():continue
                encoded=frame.get('png') or frame.get('jpeg')
                phase='frame_transport'
                result=invoke('repeat_frame') if encoded==last and last_epoch==desktop.epoch else invoke('frame',frame=frame)
                if result['status']!='active':break
                last=encoded;last_epoch=desktop.epoch;paused=False
                phase='commands_transport';packet=invoke('commands')
                if packet['status']!='active':break
                for action in packet.get('commands',[]):
                    phase='input'
                    if stop.is_set() or not desktop.guard():break
                    if action.get('desktop_epoch')!=desktop.epoch:continue
                    inputs.send({k:v for k,v in action.items() if k not in ('time','desktop_epoch')})
            except DesktopTransition:
                phase='desktop_transition'
                paused=True;last=None
                # Keep the lease alive while Windows changes desktops, but
                # immediately invalidate both old video and pending input.
                # Never extend the original consent lease. Recheck WTS/lock,
                # parent, expiry and center authorization on every retry.
                desktop.check_session()
                if invoke('admin_pause')['status']!='active':break
            target=.5 if lease['quality']=='clarity' else 1/3 if lease['quality']=='economy' else 1/8
            if paused:target=max(.25,target)
            stop.wait(max(.02,target-(time.monotonic()-started)))
    except (OSError,ValueError) as error:
        kind=type(error).__name__
        if kind not in ('OSError','PermissionError','ValueError','InputFailure','ConnectionError','TimeoutError'):kind='OSError'
        code=getattr(error,'winerror',None)
        if type(code) is not int or not 0<=code<=0xffffffff:code=None
        try:invoke('admin_failure',failure_phase=phase,error_type=kind,native_code=code)
        except (OSError,ValueError):pass
        raise
    finally:
        inputs.release();desktop.close()
        try:invoke('stop')
        except (OSError,ValueError):pass


def run(did,sid,stop):
    from .machine_agent_windows import installed_image,process_lease
    from .update_native import protected_tree
    from .protected_files import read_json
    api,own=identity()
    if not getattr(sys,'frozen',False) or Path(sys.executable).resolve()!=installed_image():raise PermissionError('Installed management child required')
    path=ticket_path(did,sid);config=path.parent.parent/'config.json'
    for p in (installed_image().parent,installed_image(),path.parent.parent,path.parent,path,config):protected_tree(p,recursive=False)
    lease=validate_ticket(read_json(path,8192),did,sid)
    if own[2]!=lease['session']:raise PermissionError('Management child WTS mismatch')
    parent=api.OpenProcess(0x1000|0x100000|0x40,False,lease['parent'])
    if not parent:raise ctypes.WinError(ctypes.get_last_error())
    cancel=w.HANDLE()
    try:
        with process_lease(api,lease['parent']) as actual:
            if actual['sid']!='S-1-5-18' or actual['created']!=lease['parent_created'] or actual['session']!=0:
                raise PermissionError('Management parent identity mismatch')
        api.GetCurrentProcess.restype=w.HANDLE
        api.DuplicateHandle.argtypes=[w.HANDLE,w.HANDLE,w.HANDLE,ctypes.POINTER(w.HANDLE),w.DWORD,w.BOOL,w.DWORD]
        if not api.DuplicateHandle(parent,w.HANDLE(lease['cancel_handle']),api.GetCurrentProcess(),ctypes.byref(cancel),0x100000,False,0):
            raise ctypes.WinError(ctypes.get_last_error())
        from .endpoint_transport import request,transport
        settings=read_json(config,65536)
        if settings['device_id']!=did:raise PermissionError('Management device mismatch')
        from .document_context import token_sid
        wts=ctypes.WinDLL('wtsapi32',use_last_error=True);token=w.HANDLE()
        wts.WTSQueryUserToken.argtypes=[w.ULONG,ctypes.POINTER(w.HANDLE)]
        with session_privilege():
            if not wts.WTSQueryUserToken(lease['session'],ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
        try:
            if token_sid(token)!=lease['sid']:raise PermissionError('Management target user changed')
        finally:api.CloseHandle(token)
        opener=transport(settings['server'],settings.get('ca'))
        call=lambda body:request(settings['server'],'/api/agent/remote/update',body,token=settings['token'],ca=settings.get('ca'),opener=opener,timeout=3)
        desktop=Desktop(lease,lambda:api.WaitForSingleObject(parent,0)==258 and api.WaitForSingleObject(cancel,0)==258)
        try:
            user=ctypes.WinDLL('user32',use_last_error=True)
            user.SetThreadDpiAwarenessContext.argtypes=[w.HANDLE];user.SetThreadDpiAwarenessContext.restype=w.HANDLE
            user.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
        except AttributeError:pass
        # Consume the private ticket; nonce remains only in RAM until shutdown.
        path.unlink()
        assist(lease,call,desktop,stop)
    finally:
        if cancel:api.CloseHandle(cancel)
        api.CloseHandle(parent)
