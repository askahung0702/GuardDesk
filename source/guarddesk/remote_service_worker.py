"""Cooperative worker lifetime, inherited from the fixed native SCM host."""
import ctypes
import re
import threading
from ctypes import wintypes as w

FAULT_LOG='worker-fault.log'
FAULT_LIMIT=256*1024
EXIT_EVIDENCE='worker-exit.json'


def fault_trace(root):
    """Python-level stack on a fatal native fault; no memory or data content.

    The file lives in the already verified protected device directory. It is a
    local MIS diagnostic only: never uploaded, never an authorization input.
    Any failure here leaves the worker running without the trace.
    """
    import faulthandler,time
    try:
        path=root/FAULT_LOG
        if path.is_symlink():return None
        # Keep the previous run's evidence once, then start a bounded file.
        if path.exists() and path.stat().st_size>FAULT_LIMIT:
            path.replace(path.with_suffix('.previous.log'))
        stream=path.open('a',encoding='utf-8',errors='replace')
        from . import __version__
        stream.write('worker_start version=%s time=%d\n'%(__version__,int(time.time())));stream.flush()
        faulthandler.enable(file=stream,all_threads=True)
        return stream
    except (OSError,ValueError,RuntimeError):return None


def fault_bounded(stream):
    # Handled native exceptions may also be traced. Stop tracing rather than
    # let a noisy component grow the file without limit.
    import faulthandler,os
    try:
        if os.fstat(stream.fileno()).st_size<=FAULT_LIMIT:return stream
    except (OSError,ValueError):pass
    fault_close(stream);return None


def fault_close(stream):
    if stream is None:return
    import faulthandler
    try:faulthandler.disable()
    except (OSError,ValueError,RuntimeError):pass
    try:stream.close()
    except (OSError,ValueError):pass


def exit_evidence(root,exc):
    """One small fixed-field record of an unexpected worker exit."""
    import json,time
    try:
        from . import __version__
        code=getattr(exc,'winerror',None)
        body={'format':1,'version':__version__,'time':time.time(),'type':type(exc).__name__[:80],
              'winerror':code if type(code) is int else None}
        path=root/EXIT_EVIDENCE
        if path.is_symlink():return
        temporary=path.with_suffix('.json.new')
        temporary.write_text(json.dumps(body),encoding='utf-8');temporary.replace(path)
    except (OSError,ValueError,TypeError):pass


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
    fault=fault_trace(root)
    def watch():
        nonlocal fault
        rounds=0
        while not finished.is_set():
            result=kernel.WaitForSingleObject(handle,250)
            if result!=258:stop.set();return
            rounds+=1
            if fault and rounds%240==0:fault=fault_bounded(fault)
    watcher=threading.Thread(target=watch,name='GuardDesk-service-stop',daemon=True);watcher.start()
    try:return (trial_worker if trial() else full_worker)(config,stop)
    except BaseException as exc:
        if not isinstance(exc,(SystemExit,KeyboardInterrupt)):exit_evidence(root,exc)
        raise
    finally:
        stop.set();finished.set();watcher.join(1);kernel.CloseHandle(handle)
        fault_close(fault)
