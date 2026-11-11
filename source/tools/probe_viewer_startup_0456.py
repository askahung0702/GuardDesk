"""Own login window only; record startup, no remote session or other titles."""
import ctypes,hashlib,json,subprocess,time
from ctypes import wintypes as w
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def main():
    exe=ROOT/'dist/GuardDesk/_internal/GuardDeskRemote.exe'
    process=subprocess.Popen([str(exe)],cwd=ROOT,creationflags=subprocess.CREATE_NO_WINDOW)
    api=ctypes.WinDLL('user32',use_last_error=True)
    api.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
    api.GetWindowTextW.argtypes=[w.HWND,w.LPWSTR,ctypes.c_int]
    api.PostMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM]
    callback=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM);api.EnumWindows.argtypes=[callback,w.LPARAM]
    matches=[];titles=[];errors=[]
    api.EnumChildWindows.argtypes=[w.HWND,callback,w.LPARAM]
    api.SendMessageTimeoutW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM,w.UINT,w.UINT,ctypes.POINTER(ctypes.c_size_t)]
    api.SendMessageTimeoutW.restype=w.LPARAM
    def child(hwnd,param):
        text=ctypes.create_unicode_buffer(8192);result=ctypes.c_size_t();api.SendMessageTimeoutW(hwnd,0xD,len(text),ctypes.addressof(text),2,500,ctypes.byref(result))
        if text.value:errors.append(text.value)
        return True
    child_callback=callback(child)
    def visit(hwnd,param):
        pid=w.DWORD();api.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
        if pid.value==process.pid:
            title=ctypes.create_unicode_buffer(256);api.GetWindowTextW(hwnd,title,256)
            if title.value and title.value not in titles:titles.append(title.value)
            if title.value=='GuardDesk 遠端協助':matches.append(hwnd)
            if title.value=='Unhandled exception in script':api.EnumChildWindows(hwnd,child_callback,0)
        return True
    start=time.monotonic();function=callback(visit);result={}
    try:
        while time.monotonic()-start<75 and process.poll() is None:
            api.EnumWindows(function,0)
            if matches or errors:break
            time.sleep(.1)
        elapsed=round(time.monotonic()-start,3)
        if matches:api.PostMessageW(matches[0],0x10,0,0);process.wait(15)
        result={'passed':bool(matches) and process.returncode==0,'login_window_seconds':elapsed,'own_window_titles':titles,'own_exception_dialog':errors,'exit_code':process.poll(),'viewer_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'scope':'owned_login_window_only_no_remote_session','company_or_protection_changed':False}
    finally:
        if process.poll() is None:process.terminate();process.wait(15)
    result['own_process_stopped']=True
    (ROOT/'evidence/viewer-startup-0.4.56.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
