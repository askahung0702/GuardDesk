"""Cooperative Windows background scheduling; no process-wide memory trimming."""
import ctypes
import os
import sys
import time
from contextlib import contextmanager


@contextmanager
def background_work():
    api=None;entered=False;previous=0
    if os.name=='nt':
        from ctypes import wintypes as w
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.GetCurrentThread.restype=w.HANDLE
        api.GetThreadPriority.argtypes=[w.HANDLE];api.GetThreadPriority.restype=ctypes.c_int
        api.SetThreadPriority.argtypes=[w.HANDLE,ctypes.c_int];api.SetThreadPriority.restype=w.BOOL
        previous=api.GetThreadPriority(api.GetCurrentThread())
        if previous==0x7fffffff:previous=0
        # Full THREAD_MODE_BACKGROUND_BEGIN throttles SQLite I/O while holding
        # the shared writer lock. Use lower CPU priority plus explicit I/O slices.
        entered=bool(api.SetThreadPriority(api.GetCurrentThread(),min(previous,-1)))
    try:yield {'background_scheduling':entered,'scheduling_mode':'below_normal_cpu_cooperative_io','platform':os.name}
    finally:
        if entered:api.SetThreadPriority(api.GetCurrentThread(),previous)


class ProcessSampler:
    def __init__(self):self.previous=None

    def sample(self):
        now=time.monotonic();cpu=time.process_time();percent=None
        if self.previous and now>self.previous[0]:percent=max(0,(cpu-self.previous[1])/(now-self.previous[0])*100/(os.cpu_count() or 1))
        self.previous=(now,cpu)
        result={'cpu_machine_percent':round(percent,3) if percent is not None else None,'logical_cpus':os.cpu_count(),'sampled_at':time.time(),'process_scope':'server_and_agent_demo' if len(sys.argv)>1 and sys.argv[1]=='demo' else 'agent_process','includes':'current_process_only_excludes_browser_host_and_powershell'}
        if os.name=='nt':
            from ctypes import wintypes as w
            class Counters(ctypes.Structure):
                _fields_=[('cb',w.DWORD),('faults',w.DWORD)]+[(name,ctypes.c_size_t) for name in ('peak_working','working','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile','private')]
            api=ctypes.WinDLL('kernel32',use_last_error=True);api.GetCurrentProcess.restype=w.HANDLE
            api.K32GetProcessMemoryInfo.argtypes=[w.HANDLE,ctypes.POINTER(Counters),w.DWORD];api.K32GetProcessMemoryInfo.restype=w.BOOL
            counters=Counters();counters.cb=ctypes.sizeof(counters)
            if api.K32GetProcessMemoryInfo(api.GetCurrentProcess(),ctypes.byref(counters),counters.cb):result.update(working_set_bytes=counters.working,private_bytes=counters.private)
        return result
