"""Owned Popen descendant windows only; no other window titles or UI input."""
import ctypes as c
from ctypes import wintypes as w
import time


def exercise(process,expected_exe):
    kernel=c.WinDLL('kernel32',use_last_error=True);user=c.WinDLL('user32',use_last_error=True)
    class PE(c.Structure):
        _fields_=[('size',w.DWORD),('usage',w.DWORD),('pid',w.DWORD),('heap',c.c_size_t),('module',w.DWORD),('threads',w.DWORD),('parent',w.DWORD),('priority',w.LONG),('flags',w.DWORD),('name',w.WCHAR*260)]
    kernel.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD];kernel.CreateToolhelp32Snapshot.restype=w.HANDLE
    kernel.Process32FirstW.argtypes=[w.HANDLE,c.POINTER(PE)];kernel.Process32NextW.argtypes=[w.HANDLE,c.POINTER(PE)]
    kernel.CloseHandle.argtypes=[w.HANDLE]
    kernel.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];kernel.OpenProcess.restype=w.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,c.POINTER(w.DWORD)]
    user.GetWindowThreadProcessId.argtypes=[w.HWND,c.POINTER(w.DWORD)];user.GetWindowTextW.argtypes=[w.HWND,w.LPWSTR,c.c_int]
    user.IsWindowVisible.argtypes=[w.HWND];user.PostMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM]
    CB=c.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM);user.EnumWindows.argtypes=[CB,w.LPARAM]
    def owned():
        snap=kernel.CreateToolhelp32Snapshot(2,0);table={};entry=PE();entry.size=c.sizeof(PE)
        try:
            more=kernel.Process32FirstW(snap,c.byref(entry))
            while more:table[entry.pid]=entry.parent;more=kernel.Process32NextW(snap,c.byref(entry))
        finally:kernel.CloseHandle(snap)
        ids={process.pid}
        for _ in range(4):ids.update(pid for pid,parent in table.items() if parent in ids)
        assert len(ids)<10
        verified=set()
        for pid in ids:
            handle=kernel.OpenProcess(0x1000,False,pid)
            if not handle:continue
            try:
                buf=c.create_unicode_buffer(32768);length=w.DWORD(len(buf))
                if kernel.QueryFullProcessImageNameW(handle,0,buf,c.byref(length)) and buf.value.casefold()==str(expected_exe).casefold():verified.add(pid)
            finally:kernel.CloseHandle(handle)
        found={}
        @CB
        def visit(hwnd,_):
            pid=w.DWORD();user.GetWindowThreadProcessId(hwnd,c.byref(pid))
            if pid.value in verified:
                title=c.create_unicode_buffer(256);user.GetWindowTextW(hwnd,title,256)
                if title.value in ('GuardDesk 遠端協助','GuardDesk MIS notification window'):found[title.value]=hwnd
            return True
        user.EnumWindows(visit,0);return found
    stage='startup'
    def wait(predicate,seconds=45):
        deadline=time.monotonic()+seconds
        while True:
            assert process.poll() is None,'owned onefile exited early at '+stage+'; code='+str(process.poll())
            result=predicate()
            if result:return result
            if time.monotonic()>deadline:raise TimeoutError('owned onefile lifecycle window timeout')
            time.sleep(.05)
    start=time.monotonic()
    windows=wait(lambda: (v if len(v)==2 else None) if (v:=owned()) else None)
    main=windows['GuardDesk 遠端協助'];tray=windows['GuardDesk MIS notification window'];elapsed=time.monotonic()-start
    for cycle in range(3):
        stage='hide '+str(cycle)
        user.PostMessageW(main,0x10,0,0);wait(lambda:not user.IsWindowVisible(main),5)
        assert process.poll() is None
        stage='restore '+str(cycle)
        user.PostMessageW(tray,0x111,1,0)
        main=wait(lambda: (candidate if user.IsWindowVisible(candidate) else None) if (candidate:=owned().get('GuardDesk 遠端協助')) else None,5)
    user.PostMessageW(tray,0x111,3,0);assert process.wait(timeout=15)==0
    return {'startup_seconds':elapsed,'hide_restore_cycles':3,'actual_single_file_gui_started':True,'close_hides_to_tray':True,'tray_restores_window':True,'tray_exit_terminates_own_process':True,'scope':'known_process_tree_exact_image_only_no_other_titles_or_input'}
