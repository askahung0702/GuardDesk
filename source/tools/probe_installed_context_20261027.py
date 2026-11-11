"""Owned user-token helper probe against installed code, no Agent initialization."""
import ctypes,json,os,subprocess,sys,time
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
    exe=Path('C:/Program Files/GuardDeskPilot/USBControl/GuardDesk.exe');child=None;records=[];result={'scope':'installed_exe_standard_user_owned_pipe','existing_agent_changed':False}
    try:
        start=time.monotonic()
        child=subprocess.Popen([str(exe),'document-session-context','--pipe',channel.pipe,'--parent',str(os.getpid())],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
        api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
        channel.process=api.OpenProcess(0x101001,False,child.pid);channel.pid=child.pid
        while time.monotonic()-start<12 and len(records)<4:
            records.extend(channel.poll());time.sleep(.05)
        result.update(passed=len(records)>=4,frames=len(records),elapsed_seconds=round(time.monotonic()-start,3),valid=all(valid_sample(v,records[0]['session'],time.time()) for v in records))
    except Exception as exc:
        result.update(passed=False,error_type=type(exc).__name__,winerror=getattr(exc,'winerror',None))
    finally:
        channel.close()
        if child:
            child.wait(timeout=5);result['child_exit_code']=child.returncode
            result['child_error']=child.stderr.read(4096).decode('utf-8',errors='replace');child.stderr.close()
    (ROOT/'evidence/maintenance/installed-context-user-probe-20261027.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
