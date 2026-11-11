"""Cancelable, local-only transport building block, NOT a browser provider.

No installed Agent selects this source. GuardDesk-private random endpoints
cannot replace Chromium's registered provider. Never binds path_user or a
third-party pipe, writes policy, changes profiles, or starts/injects browsers.
Session allowlist comes from trusted local code, never a request/config field.
"""
import ctypes
from ctypes import wintypes as w
import re
import threading
import time
import uuid

from .native_browser_identity import _windows, verify_browser, IdentityError
from .native_connector import MAX_MESSAGE, NativeAttachmentSession

PREFIX = r'\\.\pipe\GuardDesk-NativeHandoff-'
MAX_CONNECTIONS = 8


class _ImpersonationFailure(BaseException):
    pass


class _Security(ctypes.Structure):
    _fields_ = [('size',w.DWORD),('descriptor',w.LPVOID),('inherit',w.BOOL)]


class _Overlapped(ctypes.Structure):
    _fields_ = [('internal',ctypes.c_size_t),('internal_high',ctypes.c_size_t),
                ('offset',w.DWORD),('offset_high',w.DWORD),('event',w.HANDLE)]


def _api():
    api = _windows()
    api.CreateNamedPipeW.argtypes = [w.LPCWSTR,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,ctypes.POINTER(_Security)]
    api.CreateNamedPipeW.restype = w.HANDLE
    api.CreateEventW.argtypes = [w.LPVOID,w.BOOL,w.BOOL,w.LPCWSTR]
    api.CreateEventW.restype = w.HANDLE
    api.ConnectNamedPipe.argtypes = [w.HANDLE,ctypes.POINTER(_Overlapped)]
    api.ReadFile.argtypes = [w.HANDLE,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD),ctypes.POINTER(_Overlapped)]
    api.WriteFile.argtypes = api.ReadFile.argtypes
    api.GetOverlappedResult.argtypes = [w.HANDLE,ctypes.POINTER(_Overlapped),ctypes.POINTER(w.DWORD),w.BOOL]
    api.CancelIoEx.argtypes = [w.HANDLE,ctypes.POINTER(_Overlapped)]
    api.DisconnectNamedPipe.argtypes = [w.HANDLE]
    api.GetNamedPipeClientProcessId.argtypes = [w.HANDLE,ctypes.POINTER(w.ULONG)]
    api.GetCurrentThread.restype = w.HANDLE
    api.LocalFree.argtypes = [w.LPVOID]
    return api


def _client_sid(api, pipe):
    from .document_context import token_sid
    adv = ctypes.WinDLL('advapi32',use_last_error=True)
    adv.ImpersonateNamedPipeClient.argtypes = [w.HANDLE]
    adv.OpenThreadToken.argtypes = [w.HANDLE,w.DWORD,w.BOOL,ctypes.POINTER(w.HANDLE)]
    adv.RevertToSelf.argtypes = []
    if not adv.ImpersonateNamedPipeClient(pipe):
        raise IdentityError('pipe_impersonation_failed')
    token = w.HANDLE()
    try:
        if not adv.OpenThreadToken(api.GetCurrentThread(),8,True,ctypes.byref(token)):
            raise IdentityError('pipe_token_unreadable')
        return token_sid(token)
    finally:
        if token:api.CloseHandle(token)
        if not adv.RevertToSelf():
            # End this worker; never continue disk/network work impersonating
            # a client, and never swallow a failed RevertToSelf as normal input.
            raise _ImpersonationFailure()


class _IO:
    def __init__(self, api, handle, stop, max_message=MAX_MESSAGE):
        self.api,self.handle,self.stop = api,handle,stop
        self.max_message = max_message

    def operation(self, kind, data=None, timeout=60):
        api = self.api
        event = api.CreateEventW(None,True,False,None)
        if not event:raise OSError('IPC event unavailable')
        overlapped = _Overlapped()
        overlapped.event = event
        count = w.DWORD()
        buffer = None
        pending = False
        try:
            if self.stop.is_set():raise InterruptedError('IPC stopped')
            if kind == 'connect':
                ok = api.ConnectNamedPipe(self.handle,ctypes.byref(overlapped))
            elif kind == 'read':
                buffer = ctypes.create_string_buffer(self.max_message+1)
                ok = api.ReadFile(self.handle,buffer,len(buffer),ctypes.byref(count),ctypes.byref(overlapped))
            else:
                if not isinstance(data,bytes) or not 0 < len(data) <= self.max_message:
                    raise ValueError('IPC output bound')
                buffer = ctypes.create_string_buffer(data)
                ok = api.WriteFile(self.handle,buffer,len(data),ctypes.byref(count),ctypes.byref(overlapped))
            error = ctypes.get_last_error() if not ok else 0
            if kind == 'connect' and error == 535:
                return b''
            if not ok and error != 997:
                raise ctypes.WinError(error)
            pending = not ok
            if pending:
                deadline = time.monotonic()+timeout
                while api.WaitForSingleObject(event,100) != 0:
                    if self.stop.is_set():raise InterruptedError('IPC stopped')
                    if time.monotonic() >= deadline:raise TimeoutError('IPC deadline')
                pending = False
                if not api.GetOverlappedResult(self.handle,ctypes.byref(overlapped),ctypes.byref(count),False):
                    raise ctypes.WinError(ctypes.get_last_error())
            if kind == 'read':
                if not 0 < count.value <= self.max_message:
                    raise ValueError('IPC input bound')
                return buffer.raw[:count.value]
            if kind == 'write' and count.value != len(data):
                raise OSError('Incomplete IPC reply')
            return b''
        finally:
            if pending:
                # Keep OVERLAPPED/buffer alive until the cancellation completes.
                # A stuck driver leaves this owned worker stopping; supervisor
                # does not spawn more generations or close an in-flight handle.
                api.CancelIoEx(self.handle,ctypes.byref(overlapped))
                api.GetOverlappedResult(self.handle,ctypes.byref(overlapped),ctypes.byref(count),True)
            api.CloseHandle(event)


class LocalConnectorSource:
    def __init__(self, sessions, *, _verify=verify_browser):
        if (not isinstance(sessions,dict) or not 1 <= len(sessions) <= MAX_CONNECTIONS
                or any(type(k) is not int or not 0 < k < 2**32 or not isinstance(v,str)
                       or not re.fullmatch(r'S-1-(?:\d+-)*\d+',v) for k,v in sessions.items())):
            raise ValueError('Trusted session allowlist required')
        self.sessions = dict(sessions)
        self.name = PREFIX+uuid.uuid4().hex
        self._verify = _verify  # Code dependency for isolated tests, not remote configuration.
        self.ready = threading.Event()
        self._lock = threading.Lock()
        self._stats = {'authenticated':0,'rejected':0,'received':0,'active':0}

    def snapshot(self):
        with self._lock:return dict(self._stats)

    def _count(self, **values):
        with self._lock:
            for key,value in values.items():self._stats[key] += value

    def _pipe(self, api, first):
        adv = ctypes.WinDLL('advapi32',use_last_error=True)
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID]
        descriptor = w.LPVOID()
        sddl = 'D:P(A;;GA;;;SY)'+''.join('(A;;GRGW;;;'+sid+')' for sid in sorted(set(self.sessions.values())))
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(descriptor),None):
            raise OSError('IPC security descriptor unavailable')
        try:
            security = _Security(ctypes.sizeof(_Security),descriptor,False)
            # DUPLEX | OVERLAPPED | first instance; message mode, reject remote.
            handle = api.CreateNamedPipeW(self.name,3|0x40000000|(0x80000 if first else 0),4|2|8,
                                          MAX_CONNECTIONS,MAX_MESSAGE,MAX_MESSAGE,0,ctypes.byref(security))
            if handle == ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
            return handle
        finally:
            api.LocalFree(descriptor)

    def run(self, stop, inbox):
        api = _api()
        handles,workers = [],[]
        fatal = threading.Event()
        try:
            # Keep all instances open for the complete source lifetime; a
            # reconnect cannot race an interval with no owned pipe object.
            for i in range(MAX_CONNECTIONS):handles.append(self._pipe(api,i==0))

            def worker(handle):
                io = _IO(api,handle,stop)
                try:
                    while not stop.is_set():
                        authenticated = False
                        try:
                            io.operation('connect')
                            # Read one bounded frame before impersonating: the
                            # token is that of the client that wrote this frame.
                            first = io.operation('read')
                            pid,session = w.ULONG(),w.DWORD()
                            if not api.GetNamedPipeClientProcessId(handle,ctypes.byref(pid)) or not api.ProcessIdToSessionId(pid,ctypes.byref(session)):
                                raise IdentityError('pipe_process_unreadable')
                            sid = _client_sid(api,handle)
                            if self.sessions.get(session.value) != sid:
                                raise IdentityError('pipe_session_mismatch')
                            with self._verify(pid.value,session=session.value,sid=sid) as lease:
                                if lease.identity.pid != pid.value or lease.identity.session != session.value or lease.sid != sid:
                                    raise IdentityError('pipe_process_identity_mismatch')
                                channel = NativeAttachmentSession(lease,inbox)
                                self._count(authenticated=1,active=1)
                                authenticated = True
                                raw = first
                                for _ in range(256):
                                    accepted = channel.receive(raw,lambda reply: io.operation('write',reply,timeout=1))
                                    self._count(received=int(accepted),rejected=int(not accepted))
                                    if stop.is_set():break
                                    raw = io.operation('read')
                        except _ImpersonationFailure:
                            fatal.set()
                            stop.set()
                            break
                        except (OSError,ValueError):
                            if not stop.is_set():self._count(rejected=1)
                        finally:
                            if authenticated:self._count(active=-1)
                            api.DisconnectNamedPipe(handle)
                except BaseException:
                    fatal.set()
                    stop.set()

            for handle in handles:
                thread = threading.Thread(target=worker,args=(handle,),name='GuardDesk native pipe session',daemon=True)
                workers.append(thread)
                thread.start()
            self.ready.set()
            while any(thread.is_alive() for thread in workers):
                for thread in workers:thread.join(.05)
            if fatal.is_set():raise OSError('IPC worker stopped unexpectedly')
        finally:
            stop.set()
            for thread in workers:thread.join()
            for handle in handles:api.CloseHandle(handle)
            self.ready.set()
