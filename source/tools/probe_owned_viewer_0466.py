"""Report only windows belonging to a newly launched owned test process."""
import ctypes
from ctypes import wintypes as w
import json
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
api=ctypes.WinDLL('user32',use_last_error=True)
api.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
api.GetWindowTextW.argtypes=[w.HWND,w.LPWSTR,ctypes.c_int]
api.GetClassNameW.argtypes=[w.HWND,w.LPWSTR,ctypes.c_int]
api.IsWindowVisible.argtypes=[w.HWND]
api.PostMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM]
callback=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
api.EnumWindows.argtypes=[callback,w.LPARAM]
api.EnumChildWindows.argtypes=[w.HWND,callback,w.LPARAM]
exe=ROOT/'dist/GuardDesk/_internal/GuardDeskRemote.exe'
p=subprocess.Popen([str(exe)],cwd=ROOT,creationflags=subprocess.CREATE_NO_WINDOW)
found=[];start=time.monotonic()
def visit(hwnd,param):
    pid=w.DWORD();api.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
    if pid.value==p.pid:
        title=ctypes.create_unicode_buffer(256);kind=ctypes.create_unicode_buffer(128)
        api.GetWindowTextW(hwnd,title,256);api.GetClassNameW(hwnd,kind,128)
        found.append(dict(hwnd=hwnd,title=title.value,kind=kind.value,visible=bool(api.IsWindowVisible(hwnd))))
    return True
visitor=callback(visit)
try:
    while time.monotonic()-start<25:
        found.clear();api.EnumWindows(visitor,0)
        if any(x['title'] in ('GuardDesk 遠端協助','Unhandled exception in script') for x in found):break
        if p.poll() is not None:break
        time.sleep(.1)
    errors=[]
    def child(hwnd,param):
        text=ctypes.create_unicode_buffer(4096);api.GetWindowTextW(hwnd,text,4096)
        if text.value:errors.append(text.value)
        return True
    child_callback=callback(child)
    for item in found:
        if item['title']=='Unhandled exception in script':api.EnumChildWindows(item['hwnd'],child_callback,0)
    result=dict(pid=p.pid,seconds=time.monotonic()-start,exit=p.poll(),owned_windows=found,error_dialog=errors,company_changed=False)
    print(json.dumps(result,ensure_ascii=False))
    (ROOT/'evidence/owned-viewer-0466-diagnostic.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    for item in found:
        if item['title']=='GuardDesk 遠端協助':api.PostMessageW(item['hwnd'],0x10,0,0)
    try:p.wait(timeout=3)
    except subprocess.TimeoutExpired:pass
finally:
    if p.poll() is None:p.terminate();p.wait(timeout=5)
