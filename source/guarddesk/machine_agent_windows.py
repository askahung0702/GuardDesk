"""Fixed installed Windows image, local authenticated bounded pipe, WTS launch."""
import ctypes
from ctypes import wintypes as w
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from .machine_agent import PIPE, MAX_MESSAGE
from .native_connector_pipe import _api, _IO, _Security, _client_sid, _ImpersonationFailure

# A SYSTEM service token may default newly created objects to Administrators.
# The session client authenticates this owner; never inherit that token default.
PIPE_SECURITY = 'O:SYD:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;GRGW;;;IU)'


class MachineBusy(TimeoutError):
    """Capacity pressure is not evidence the SYSTEM parent has exited."""


def installed_image():
    from .update_native import folder
    return folder(38)/'USBControl/GuardDesk.exe'


def marker_path():
    from .update_native import folder
    return folder(38)/'machine-endpoint.json'


def publish_marker(agent):
    from .protected_files import ProtectedFiles as Windows,encode
    from .context_permissions import grant_read_execute
    import hashlib
    path=marker_path()
    ca=Path(agent.config['ca']).read_bytes() if agent.config.get('ca') else b''
    value={'format':1,'device_id':agent.config['device_id'],'server':agent.config['server'],
           'ca_sha256':hashlib.sha256(ca).hexdigest(),'scope':'machine','version':__import__('guarddesk').__version__}
    if agent.config.get('install_profile') is not None:value['install_profile']=agent.config['install_profile']
    if path.exists():
        from .update_native import protected_tree
        protected_tree(path,recursive=False)
        previous=json.loads(path.read_text(encoding='utf-8'))
        if any(previous.get(k)!=value[k] for k in ('device_id','server','ca_sha256')):
            raise OSError('Existing machine identity marker conflict; preserve enrollment')
        if previous==value:return
    Windows().write(path,encode(value));grant_read_execute(path)


def read_marker():
    path=marker_path()
    if not path.exists():return None
    from .update_native import protected_tree
    protected_tree(path.parent,recursive=False);protected_tree(path,recursive=False)
    if path.stat().st_size>4096:raise ValueError('Machine marker too large')
    body=json.loads(path.read_text(encoding='utf-8'))
    import re
    if (set(body)-{'install_profile'}!={'format','device_id','server','ca_sha256','scope','version'}
        or body.get('install_profile','standard') not in ('standard','remote-only-trial-v1') or body['format']!=1
        or not re.fullmatch('[0-9a-f]{24}',body['device_id']) or body['scope']!='machine'):
        raise ValueError('Invalid machine marker')
    return body


def pipe_owner(api,handle):
    adv=ctypes.WinDLL('advapi32',use_last_error=True)
    adv.GetSecurityInfo.argtypes=[w.HANDLE,ctypes.c_int,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID,w.LPVOID,w.LPVOID,ctypes.POINTER(w.LPVOID)]
    adv.ConvertSidToStringSidW.argtypes=[w.LPVOID,ctypes.POINTER(w.LPWSTR)]
    owner=w.LPVOID();descriptor=w.LPVOID();text=w.LPWSTR()
    try:
        error=adv.GetSecurityInfo(handle,1,1,ctypes.byref(owner),None,None,None,ctypes.byref(descriptor))
        if error: raise ctypes.WinError(error)
        if not owner or not adv.ConvertSidToStringSidW(owner,ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        return text.value
    finally:
        if text: api.LocalFree(text)
        if descriptor: api.LocalFree(descriptor)


@contextmanager
def process_lease(api, pid):
    handle = api.OpenProcess(0x1000 | 0x100000, False, pid)
    if not handle: raise ctypes.WinError(ctypes.get_last_error())
    try:
        from .native_browser_identity import _snapshot, _process_sid
        actual_pid, created, session, image = _snapshot(api, handle)
        if actual_pid != pid or Path(image).resolve() != installed_image():
            raise PermissionError('Machine Agent process image mismatch')
        yield {'pid': pid, 'created': created, 'session': session, 'sid': _process_sid(handle)}
        if api.WaitForSingleObject(handle, 0) != 258: raise OSError('Machine peer exited')
    finally: api.CloseHandle(handle)


class Listener:
    """Eight precreated instances, no unbounded accept/thread/queue allocation."""
    def __init__(self, router):
        self.router = router; self.stop = threading.Event(); self.api = _api()
        self.handles = []; self.threads = []
        from .update_native import protected_tree
        protected_tree(installed_image().parent, recursive=False)
        protected_tree(installed_image())
        try:
            for i in range(8): self.handles.append(self.pipe(i == 0))
            for handle in self.handles:
                thread = threading.Thread(target=self.serve, args=(handle,), name='GuardDesk session RPC', daemon=True)
                thread.start(); self.threads.append(thread)
        except BaseException: self.close(); raise

    def pipe(self, first):
        adv = ctypes.WinDLL('advapi32', use_last_error=True); descriptor = w.LPVOID()
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID]
        # IU includes local/RDP interactive users. REJECT_REMOTE_CLIENTS below
        # still rejects SMB pipes. Only /local/status is usable without image auth.
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(PIPE_SECURITY,1,ctypes.byref(descriptor),None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            security = _Security(ctypes.sizeof(_Security), descriptor, False)
            handle = self.api.CreateNamedPipeW(PIPE,3|0x40000000|(0x80000 if first else 0),4|2|8,8,
                65536,65536,0,ctypes.byref(security))
            if handle == ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
            try:
                if pipe_owner(self.api, handle) != 'S-1-5-18':
                    raise PermissionError('Machine Agent pipe owner mismatch at creation')
            except BaseException:
                self.api.CloseHandle(handle)
                raise
            return handle
        finally: self.api.LocalFree(descriptor)

    def serve(self, handle):
        api = self.api; io = _IO(api,handle,self.stop,MAX_MESSAGE)
        while not self.stop.is_set():
            try:
                io.operation('connect', timeout=60)
                request = json.loads(io.operation('read',timeout=5))
                if not isinstance(request,dict):raise ValueError('Invalid request envelope')
                generation=request.pop('generation',None)
                if request.get('path') not in ('/local/status','/local/bootstrap','/local/remote-bootstrap') and generation!=self.router.generation:
                    raise PermissionError('Machine generation changed')
                if generation is not None and generation!=self.router.generation:
                    raise PermissionError('Machine generation changed')
                if request == {'path': '/local/status', 'body': {}}:
                    result = self.router.dispatch(request)
                else:
                    pid = w.ULONG()
                    if not api.GetNamedPipeClientProcessId(handle,ctypes.byref(pid)):
                        raise ctypes.WinError(ctypes.get_last_error())
                    sid = _client_sid(api,handle)  # Always revert before network/disk operations.
                    with process_lease(api,pid.value) as peer:
                        state = self.router.sessions().get(peer['session'])
                        if peer['sid'] != sid or not state or state['sid'] != sid:
                            raise PermissionError('Machine Agent session identity mismatch')
                        peer['logon'] = state['logon']
                        result = self.router.dispatch(request,peer)
                payload = json.dumps({'ok':True,'result':result,'generation':self.router.generation},ensure_ascii=False).encode('utf-8')
                io.operation('write',payload,timeout=3)
                # DisconnectNamedPipe discards unread buffered data. Wait for
                # a tiny bounded delivery ACK instead of blocking FlushFileBuffers.
                if io.operation('read',timeout=3)!=b'{}':raise ValueError('Invalid delivery ACK')
            except _ImpersonationFailure:
                # Never continue privileged operations on an impersonated thread.
                self.stop.set(); return
            except (OSError,ValueError,TypeError,KeyError):
                if not self.stop.is_set():
                    try: io.operation('write',b'{"ok":false,"error":"machine_request_failed"}',timeout=1)
                    except (OSError,ValueError): pass
                    else:
                        # Preserve a rejected reply until the peer reads/closes,
                        # with the same bounded IO used for successful delivery.
                        try:io.operation('read',timeout=1)
                        except (OSError,ValueError):pass
            finally: api.DisconnectNamedPipe(handle)

    def close(self):
        self.stop.set()
        for thread in self.threads: thread.join(12)
        if any(thread.is_alive() for thread in self.threads):
            raise OSError('Machine RPC still winding down; retain installed runtime')
        for handle in self.handles: self.api.CloseHandle(handle)
        self.handles.clear()


def request(path, body, timeout=15, parent=None, generation=None):
    """One request per connection; impersonation level limited to identification."""
    api = _api()
    api.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE]
    api.CreateFileW.restype=w.HANDLE
    api.GetNamedPipeServerProcessId.argtypes=[w.HANDLE,ctypes.POINTER(w.ULONG)]
    api.SetNamedPipeHandleState.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD),w.LPVOID,w.LPVOID]
    envelope={'path':path,'body':body}
    if generation is not None:envelope['generation']=generation
    payload=json.dumps(envelope,ensure_ascii=False).encode('utf-8')
    if len(payload)>MAX_MESSAGE: raise ValueError('Machine RPC message too large')
    deadline=time.monotonic()+min(max(timeout,1),15); handle=None;last_error=None
    try:
        while time.monotonic()<deadline:
            # OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
            value=api.CreateFileW(PIPE,0xc0000000,0,None,3,0x40000000|0x100000|0x10000,None)
            if value!=ctypes.c_void_p(-1).value: handle=value; break
            error=ctypes.get_last_error()
            last_error=error
            if error not in (2,231): raise ctypes.WinError(error)
            time.sleep(.05)
        if not handle:
            if last_error==231:raise MachineBusy('Machine Agent capacity busy')
            raise ConnectionError('Machine Agent unavailable')
        server=w.ULONG()
        if not api.GetNamedPipeServerProcessId(handle,ctypes.byref(server)) or (parent and server.value!=parent):
            raise PermissionError('Machine Agent parent mismatch')
        # An unprivileged process cannot create an object owned by SYSTEM.
        # Verify the actual pipe object, not a user-writable PID/config file.
        # This avoids granting users query/token access to the SYSTEM process.
        if pipe_owner(api,handle)!='S-1-5-18':
            raise PermissionError('Machine Agent pipe owner must be SYSTEM')
        mode=w.DWORD(2)
        if not api.SetNamedPipeHandleState(handle,ctypes.byref(mode),None,None):
            raise ctypes.WinError(ctypes.get_last_error())
        io=_IO(api,handle,threading.Event(),MAX_MESSAGE)
        io.operation('write',payload,timeout=timeout)
        reply=json.loads(io.operation('read',timeout=timeout))
        if not isinstance(reply,dict) or reply.get('ok') is not True:
            raise ConnectionError('Machine Agent request rejected')
        if generation is not None and reply.get('generation')!=generation:
            raise ConnectionError('Machine Agent generation changed')
        io.operation('write',b'{}',timeout=1)
        return reply['result']
    finally:
        if handle: api.CloseHandle(handle)


class Child:
    def __init__(self, api, handle, pid=0):
        self.api,self.handle,self.pid=api,handle,int(pid)
        # Observation time, not Windows process creation time. No tokens/args.
        self.launch_observed_at=time.time()
    def alive(self): return bool(self.handle and self.api.WaitForSingleObject(self.handle,0)==258)
    def close(self):
        # Parent owns only this child. No broad process termination. On parent
        # exit the helper's retained parent HANDLE signals a graceful stop.
        if self.handle: self.api.CloseHandle(self.handle); self.handle=None


class Platform:
    def __init__(self, agent):
        from .machine_agent import eligible
        if not eligible(agent): raise PermissionError('Installed protected native worker required')
        self.agent=agent
        from .context_permissions import ensure_installed_runtime
        ensure_installed_runtime()
        publish_marker(agent)
        # Development gate: only protected broker configuration can enable it.
        # The default installed endpoint must not advertise unaccepted UAC support.
        self.admin_launcher = None
        self.native_launcher=None
        if agent.config.get('remote_native_preview') is True:
            from .remote_native_broker import Launcher
            self.native_launcher=Launcher(agent)
        if agent.config.get('remote_admin_preview') is True:
            from .remote_admin_windows import Launcher
            self.admin_launcher = Launcher(agent)
    def listen(self,router): return Listener(router)
    def can_launch(self):
        from .protected_files import assert_quiescent
        try:
            assert_quiescent(self.agent.config_path.parent)
            self.handoff={'status':'ready'};return True
        except (OSError,ValueError) as exc:
            self.handoff={'status':'waiting','code':getattr(exc,'code','journal_unavailable')};return False
    def sessions(self):
        from .document_context import session_states, token_sid
        states=session_states();result={}
        api=_api();wts=ctypes.WinDLL('wtsapi32',use_last_error=True)
        wts.WTSQueryUserToken.argtypes=[w.ULONG,ctypes.POINTER(w.HANDLE)]
        adv=ctypes.WinDLL('advapi32',use_last_error=True)
        adv.LookupAccountSidW.argtypes=[w.LPCWSTR,w.LPVOID,w.LPWSTR,ctypes.POINTER(w.DWORD),w.LPWSTR,ctypes.POINTER(w.DWORD),ctypes.POINTER(w.DWORD)]
        adv.ConvertStringSidToSidW.argtypes=[w.LPCWSTR,ctypes.POINTER(w.LPVOID)]
        for session,state in states.items():
            if state.get('query_failed'): raise OSError('WTS logon identity unavailable')
            token=w.HANDLE();sid_ptr=w.LPVOID()
            try:
                if not wts.WTSQueryUserToken(session,ctypes.byref(token)): raise ctypes.WinError(ctypes.get_last_error())
                sid=token_sid(token)
                if not adv.ConvertStringSidToSidW(sid,ctypes.byref(sid_ptr)): raise ctypes.WinError(ctypes.get_last_error())
                name=ctypes.create_unicode_buffer(512);domain=ctypes.create_unicode_buffer(512)
                nl,dl,use=w.DWORD(512),w.DWORD(512),w.DWORD()
                if not adv.LookupAccountSidW(None,sid_ptr,name,ctypes.byref(nl),domain,ctypes.byref(dl),ctypes.byref(use)):
                    raise ctypes.WinError(ctypes.get_last_error())
                result[session]={**state,'sid':sid,'account':domain.value+'\\'+name.value}
            finally:
                if sid_ptr: api.LocalFree(sid_ptr)
                if token: api.CloseHandle(token)
        return result
    def launch(self,session,state,agent):
        class Startup(ctypes.Structure):
            _fields_=[('cb',w.DWORD),('reserved',w.LPWSTR),('desktop',w.LPWSTR),('title',w.LPWSTR),('x',w.DWORD),('y',w.DWORD),('xs',w.DWORD),('ys',w.DWORD),('xc',w.DWORD),('yc',w.DWORD),('fill',w.DWORD),('flags',w.DWORD),('show',w.WORD),('reserved2',w.WORD),('reserved_ptr',w.LPVOID),('stdin',w.HANDLE),('stdout',w.HANDLE),('stderr',w.HANDLE)]
        class Process(ctypes.Structure):
            _fields_=[('process',w.HANDLE),('thread',w.HANDLE),('pid',w.DWORD),('tid',w.DWORD)]
        api=_api();adv=ctypes.WinDLL('advapi32',use_last_error=True)
        wts=ctypes.WinDLL('wtsapi32',use_last_error=True);envapi=ctypes.WinDLL('userenv',use_last_error=True)
        wts.WTSQueryUserToken.argtypes=[w.ULONG,ctypes.POINTER(w.HANDLE)]
        envapi.CreateEnvironmentBlock.argtypes=[ctypes.POINTER(w.LPVOID),w.HANDLE,w.BOOL]
        envapi.DestroyEnvironmentBlock.argtypes=[w.LPVOID]
        adv.CreateProcessAsUserW.argtypes=[w.HANDLE,w.LPCWSTR,w.LPWSTR,w.LPVOID,w.LPVOID,w.BOOL,w.DWORD,w.LPVOID,w.LPCWSTR,ctypes.POINTER(Startup),ctypes.POINTER(Process)]
        token=w.HANDLE();environment=w.LPVOID();process=Process()
        try:
            if not wts.WTSQueryUserToken(session,ctypes.byref(token)): raise ctypes.WinError(ctypes.get_last_error())
            from .document_context import token_sid
            if token_sid(token)!=state['sid']: raise PermissionError('Logon identity changed')
            if not envapi.CreateEnvironmentBlock(ctypes.byref(environment),token,False): raise ctypes.WinError(ctypes.get_last_error())
            exe=installed_image();startup=Startup();startup.cb=ctypes.sizeof(startup);startup.desktop='winsta0\\default'
            command=ctypes.create_unicode_buffer(subprocess.list2cmdline([str(exe),'machine-session','--parent',str(os.getpid())]))
            if not adv.CreateProcessAsUserW(token,str(exe),command,None,None,False,0x08000000|0x400,environment,str(exe.parent),ctypes.byref(startup),ctypes.byref(process)):
                raise ctypes.WinError(ctypes.get_last_error())
            return Child(api,process.process,process.pid)
        finally:
            if process.thread: api.CloseHandle(process.thread)
            if environment: envapi.DestroyEnvironmentBlock(environment)
            if token: api.CloseHandle(token)
