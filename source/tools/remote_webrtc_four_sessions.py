"""Four concurrent, fixed synthetic loopback sessions. No real desktop/input.

Only launches the exact locally built owned executable, retains those process
handles and terminates only those children on timeout. Does not change firewall,
Agent, policy or installation. These two-peer-per-process samples are not the
product's endpoint/MIS CPU or actual GPU-present acceptance.
"""
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from tools.check_remote_webrtc_syntax import VENDOR,WORKSPACE


class MemoryStatus(ctypes.Structure):
    _fields_=[('length',w.DWORD),('load',w.DWORD),*[(name,ctypes.c_ulonglong) for name in
        ('total_phys','avail_phys','total_page','avail_page','total_virtual','avail_virtual','avail_extended')]]


class ProcessMemory(ctypes.Structure):
    _fields_=[('cb',w.DWORD),('faults',w.DWORD),*[(name,ctypes.c_size_t) for name in
        ('peak_ws','working','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile','private')]]


def main():
    if os.name!='nt' or sys.argv[1:]!=['--owned-1080p']:raise SystemExit('Windows only: --owned-1080p')
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);psapi=ctypes.WinDLL('psapi',use_last_error=True)
    kernel.GlobalMemoryStatusEx.argtypes=[ctypes.POINTER(MemoryStatus)];kernel.GlobalMemoryStatusEx.restype=w.BOOL
    kernel.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(w.FILETIME)]*4)];kernel.GetProcessTimes.restype=w.BOOL
    psapi.GetProcessMemoryInfo.argtypes=[w.HANDLE,ctypes.POINTER(ProcessMemory),w.DWORD];psapi.GetProcessMemoryInfo.restype=w.BOOL
    status=MemoryStatus();status.length=ctypes.sizeof(status)
    if not kernel.GlobalMemoryStatusEx(ctypes.byref(status)):raise ctypes.WinError(ctypes.get_last_error())
    if status.avail_phys<2*1024**3:raise SystemExit('Four-session synthetic test deferred: less than 2 GiB free RAM; no child launched')
    manifests=sorted((WORKSPACE/'runtime').glob('webrtc-owned-build-*.json'))
    if not manifests:raise RuntimeError('Owned build manifest required')
    manifest=json.loads(manifests[-1].read_text(encoding='utf-8'));exe=VENDOR/'out/GuardDesk/remote_video_probe.exe'
    with exe.open('rb') as stream:checksum=hashlib.file_digest(stream,'sha256').hexdigest()
    if not manifest.get('passed') or not manifest.get('runtime_tests_requested') or checksum!=manifest['artifacts']['remote_video_probe.exe']['sha256']:
        raise RuntimeError('Latest complete owned build and executable must match')
    children=[];start=time.monotonic();peak_group_private=0;peak_group_working=0;latest_cpu={};measurement_failed=False
    try:
        for _ in range(4):
            children.append(subprocess.Popen([str(exe),'--owned-1080p'],cwd=exe.parent,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW))
        deadline=start+60
        while True:
            private=working=0;alive=False
            for child in children:
                running=child.poll() is None;alive=running or alive
                handle=w.HANDLE(int(child._handle));memory=ProcessMemory();memory.cb=ctypes.sizeof(memory)
                if running:
                    if psapi.GetProcessMemoryInfo(handle,ctypes.byref(memory),memory.cb):private+=memory.private;working+=memory.working
                    else:measurement_failed=True
                stamps=[w.FILETIME() for _ in range(4)]
                if kernel.GetProcessTimes(handle,*[ctypes.byref(value) for value in stamps]):
                    latest_cpu[child.pid]=sum((item.dwHighDateTime<<32)|item.dwLowDateTime for item in stamps[2:])/10000000
                else:measurement_failed=True
            peak_group_private=max(private,peak_group_private);peak_group_working=max(working,peak_group_working)
            if not alive:break
            if time.monotonic()>=deadline:break
            time.sleep(.1)
        results=[]
        for child in children:
            timed_out=child.poll() is None
            if timed_out:child.terminate()
            raw=child.communicate(timeout=5)[0]
            if len(raw)>65536:raise RuntimeError('Owned output exceeded fixed diagnostic bound')
            try:value=json.loads(raw)
            except (UnicodeError,ValueError):value={'passed':False,'diagnostic':'owned_output_not_scalar_JSON'}
            results.append({'pid':child.pid,'exit':child.returncode,'timed_out':timed_out,'result':value})
    finally:
        for child in children:
            if child.poll() is None:child.terminate();child.wait(timeout=5)
    elapsed=time.monotonic()-start
    report={'format':1,'scope':'Four concurrent synthetic H264 DTLS/SRTP loopback pairs; two peers per process',
        'artifact_sha256':checksum,'build_manifest':manifests[-1].name,'elapsed_seconds':elapsed,
        'available_physical_bytes_before':status.avail_phys,'sampled_group_peak_private_bytes':peak_group_private,
        'sampled_group_peak_working_bytes':peak_group_working,'process_CPU_seconds':sum(latest_cpu.values()),
        'group_machine_CPU_mean_percent':100*sum(latest_cpu.values())/(elapsed*(os.cpu_count() or 1)),
        'resource_measurement_failed':measurement_failed,'results':results,
        'passed':not measurement_failed and all(item['exit']==0 and item['result'].get('passed') is True for item in results),
        'doc108_full_performance_acceptance':False,'desktop_capture':False,'os_input':False,'deployable':False}
    number=1
    while (WORKSPACE/f'runtime/webrtc-four-session-{number:03}.json').exists():number+=1
    target=WORKSPACE/f'runtime/webrtc-four-session-{number:03}.json'
    with target.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps({'result':str(target),'passed':report['passed'],'deployable':False}))
    if not report['passed']:raise SystemExit(1)


if __name__=='__main__':main()
