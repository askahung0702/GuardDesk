"""Actual frozen user-session helper; owned local pipe, no enrollment or files."""
import ctypes,hashlib,json,os,subprocess,sys,time
from ctypes import wintypes as w
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.document_context import Channel,kernel_api,token_sid,valid_sample


def main():
    api=kernel_api();adv=ctypes.WinDLL('advapi32',use_last_error=True);token=w.HANDLE()
    api.GetCurrentProcess.restype=w.HANDLE;adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)]
    if not adv.OpenProcessToken(api.GetCurrentProcess(),8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
    try:channel=Channel(token_sid(token))
    finally:api.CloseHandle(token)
    exe=ROOT/'dist/GuardDesk/GuardDesk.exe';child=None;records=[]
    class Counters(ctypes.Structure):
        _fields_=[('cb',w.DWORD),('faults',w.DWORD)]+[(name,ctypes.c_size_t) for name in ('peak_working','working','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile','private')]
    api.K32GetProcessMemoryInfo.argtypes=[w.HANDLE,ctypes.POINTER(Counters),w.DWORD]
    api.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(w.FILETIME)]*4)]
    def measured():
        c=Counters();c.cb=ctypes.sizeof(c);times=[w.FILETIME() for _ in range(4)]
        if not api.K32GetProcessMemoryInfo(channel.process,ctypes.byref(c),c.cb) or not api.GetProcessTimes(channel.process,*[ctypes.byref(v) for v in times]):raise ctypes.WinError(ctypes.get_last_error())
        cpu=sum((t.dwHighDateTime<<32)|t.dwLowDateTime for t in times[2:])/1e7
        return {'private_bytes':c.private,'working_set_bytes':c.working,'cpu':cpu,'time':time.monotonic()}
    try:
        started=time.monotonic()
        child=subprocess.Popen([str(exe),'document-session-context','--pipe',channel.pipe,'--parent',str(os.getpid())],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
        api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
        channel.process=api.OpenProcess(0x101001,False,child.pid);channel.pid=child.pid
        deadline=started+12
        while time.monotonic()<deadline and len(records)<2:
            records.extend(channel.poll());time.sleep(.05)
        assert len(records)>=2,'Frozen helper did not provide metadata'
        first_latency=time.monotonic()-started;before=measured();peak=before['private_bytes'];end=time.monotonic()+10
        while time.monotonic()<end:
            batch=channel.poll()
            for value in batch:assert valid_sample(value,records[0]['session'],time.time())
            records.extend(batch);peak=max(peak,measured()['private_bytes']);time.sleep(.1)
        after=measured();assert len(records)>10
        report={'passed':True,'version':'0.4.58','exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
                'scope':'one_owned_standard_user_session_frozen_helper_not_SYSTEM_to_WTS_launch',
                'frames':len(records),'first_two_frames_seconds':round(first_latency,3),'sample_seconds':round(after['time']-before['time'],3),
                'cpu_machine_percent':round((after['cpu']-before['cpu'])/(after['time']-before['time'])*100/(os.cpu_count() or 1),4),
                'logical_cpus':os.cpu_count(),'private_bytes_peak':peak,'working_set_bytes':after['working_set_bytes'],
                'key_contents_or_coordinates_collected':False,'company_profiles_or_documents_read':False,'office_changed':False,
                'SYSTEM_WTS_launch_and_office_acceptance_pending':True,'full_workload_Defender_performance_accepted':False}
    finally:
        channel.close()
        if child:child.wait(timeout=5);child.stderr.close()
    report['own_helper_stopped']=True
    (ROOT/'evidence/document-context-frozen-0.4.58.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
