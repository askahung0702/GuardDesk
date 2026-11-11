"""Real CMD + frozen GUI from a clean Chinese/space path; own windows only."""
import ctypes
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def run():
    api=ctypes.windll.user32;kernel=ctypes.windll.kernel32
    api.GetWindowTextW.argtypes=[w.HWND,w.LPWSTR,ctypes.c_int]
    api.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
    api.PostMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM]
    api.IsWindowVisible.argtypes=[w.HWND];api.IsWindowVisible.restype=w.BOOL
    kernel.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];kernel.OpenProcess.restype=w.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)]
    kernel.GetExitCodeProcess.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)];kernel.CloseHandle.argtypes=[w.HANDLE]
    callback=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
    api.EnumWindows.argtypes=[callback,w.LPARAM];api.EnumChildWindows.argtypes=[w.HWND,callback,w.LPARAM]
    checks=[]
    with tempfile.TemporaryDirectory(prefix='remote-cmd-',dir=ROOT/'runtime') as temp:
        folder=Path(temp)/'中文版 遠端程式';folder.mkdir()
        shutil.copytree(ROOT/'dist/GuardDesk',folder/'GuardDesk')
        for name in ('Start-Remote.cmd','Diagnose-Remote.cmd'):shutil.copyfile(ROOT/name,folder/name)
        # Reproduce the exact previously shipped bytes before testing the fix.
        with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.14-windows-x64.zip') as z:old=z.read('Start-Remote.cmd')
        broken=folder/'Old-Start-Remote.cmd';broken.write_bytes(old)
        result=subprocess.run([os.environ['COMSPEC'],'/d','/c',str(broken)],cwd=ROOT,input=b'\r\n',capture_output=True,timeout=15)
        assert result.returncode!=0 and b'not recognized' in result.stderr
        checks.append('original 0.4.14 LF launcher reproduced CMD parse failure before GUI startup')
        for name,exe in [('Start-Remote.cmd',folder/'GuardDesk/_internal/GuardDeskRemote.exe'),('Diagnose-Remote.cmd',folder/'GuardDesk/GuardDesk.exe')]:
            owned=[]
            def visit(hwnd,param):
                title=ctypes.create_unicode_buffer(256);api.GetWindowTextW(hwnd,title,256)
                if title.value!='GuardDesk 遠端協助':return True
                pid=w.DWORD();api.GetWindowThreadProcessId(hwnd,ctypes.byref(pid));handle=kernel.OpenProcess(0x1000,False,pid.value)
                if not handle:return True
                try:
                    path=ctypes.create_unicode_buffer(32768);size=w.DWORD(len(path))
                    if kernel.QueryFullProcessImageNameW(handle,0,path,ctypes.byref(size)) and Path(path.value).resolve()==exe.resolve():owned.append((hwnd,pid.value))
                finally:kernel.CloseHandle(handle)
                return True
            cb=callback(visit)
            with (folder/(name+'.stdout')).open('wb') as out,(folder/(name+'.stderr')).open('wb') as err:
                process=subprocess.Popen([os.environ['COMSPEC'],'/d','/c',str(folder/name)],cwd=ROOT,
                    stdin=subprocess.DEVNULL,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW)
                handle=None
                try:
                    deadline=time.monotonic()+12
                    while time.monotonic()<deadline:
                        owned.clear();api.EnumWindows(cb,0)
                        if owned and api.IsWindowVisible(owned[0][0]):break
                        time.sleep(.1)
                    else:raise AssertionError('Launcher did not open its own frozen GUI: '+name)
                    hwnd,pid=owned[0];handle=kernel.OpenProcess(0x1000,False,pid);assert handle
                    # Ensure constructor and event loop finish; a title alone is insufficient.
                    children=[];child=callback(lambda h,p:(children.append(h) or True))
                    deadline=time.monotonic()+5
                    while time.monotonic()<deadline:
                        children.clear();api.EnumChildWindows(hwnd,child,0)
                        if len(children)>=10:break
                        time.sleep(.1)
                    assert len(children)>=10,(name,len(children))
                    time.sleep(.5);code=w.DWORD();kernel.GetExitCodeProcess(handle,ctypes.byref(code));assert code.value==259
                    api.PostMessageW(hwnd,0x0010,0,0)
                    deadline=time.monotonic()+5
                    while time.monotonic()<deadline:
                        kernel.GetExitCodeProcess(handle,ctypes.byref(code))
                        if code.value!=259:break
                        time.sleep(.1)
                    assert code.value==0,(name,code.value)
                    assert process.wait(timeout=5)==0
                finally:
                    for hwnd,pid in owned:api.PostMessageW(hwnd,0x0010,0,0)
                    if handle:kernel.CloseHandle(handle)
                    if process.poll() is None:process.terminate();process.wait(timeout=5)
            assert (folder/(name+'.stderr')).read_bytes()==b''
            checks.append(name+' opens complete frozen login window and closes cleanly from unrelated CWD')
    report={'passed':True,'fix':'CRLF Windows command-script line endings','version':'0.4.14-launcher-fix',
            'checks':checks,'company_Agent_or_Server_modified':False,'real_remote_session_started':False,
            'office_Windows_Server_retest':'pending user confirmation'}
    (ROOT/'evidence/remote-launcher-fix-smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':run()
