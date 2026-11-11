"""Bounded Windows update waits; no process termination or privilege changes."""
import ctypes
from contextlib import contextmanager
import os
from pathlib import Path
import time


@contextmanager
def image_processes(executable):
    """Retain handles to exact-image processes, so waits cannot follow reused PIDs.

    Called before ending the validated scheduled task. Other users' browser hosts
    with this same image are only waited for; they are never terminated here.
    """
    from ctypes import wintypes as w
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    class Entry(ctypes.Structure):
        _fields_ = [('dwSize', w.DWORD), ('cntUsage', w.DWORD),
                    ('th32ProcessID', w.DWORD), ('th32DefaultHeapID', ctypes.c_size_t),
                    ('th32ModuleID', w.DWORD), ('cntThreads', w.DWORD),
                    ('th32ParentProcessID', w.DWORD), ('pcPriClassBase', w.LONG),
                    ('dwFlags', w.DWORD), ('szExeFile', w.WCHAR * 260)]
    api.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
    api.CreateToolhelp32Snapshot.restype = w.HANDLE
    api.Process32FirstW.argtypes = api.Process32NextW.argtypes = [w.HANDLE, ctypes.POINTER(Entry)]
    api.Process32FirstW.restype = api.Process32NextW.restype = w.BOOL
    api.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    api.OpenProcess.restype = w.HANDLE
    api.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)]
    api.QueryFullProcessImageNameW.restype = w.BOOL
    api.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    api.WaitForSingleObject.restype = w.DWORD
    api.CloseHandle.argtypes = [w.HANDLE]
    executable = Path(executable)
    expected = os.path.normcase(str(executable.resolve()))
    handles = []
    snapshot = api.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = Entry()
        entry.dwSize = ctypes.sizeof(entry)
        more = api.Process32FirstW(snapshot, ctypes.byref(entry))
        count = 0
        while more:
            count += 1
            if count > 16384:
                raise OSError('程序清單超過更新安全上限')
            if entry.szExeFile.casefold() == executable.name.casefold():
                handle = api.OpenProcess(0x1000 | 0x100000, False, entry.th32ProcessID)
                if not handle:
                    error = ctypes.get_last_error()
                    if error != 87:  # Process may have exited since snapshot.
                        raise ctypes.WinError(error)
                else:
                    try:
                        buffer = ctypes.create_unicode_buffer(32768)
                        size = w.DWORD(len(buffer))
                        if not api.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                            error = ctypes.get_last_error()
                            # An already exited process no longer holds files.
                            if api.WaitForSingleObject(handle, 0) != 0:
                                raise ctypes.WinError(error)
                        elif os.path.normcase(buffer.value) == expected:
                            if len(handles) >= 64:
                                raise OSError('相同程式的程序數超過更新安全上限')
                            handles.append(handle)
                            handle = None
                    finally:
                        if handle:
                            api.CloseHandle(handle)
            more = api.Process32NextW(snapshot, ctypes.byref(entry))
        error = ctypes.get_last_error()
        if error != 18:  # ERROR_NO_MORE_FILES; do not accept partial enumeration.
            raise ctypes.WinError(error)
        api.CloseHandle(snapshot)
        snapshot = None

        def wait(deadline):
            for handle in handles:
                milliseconds = max(0, min(30000, int((deadline - time.monotonic()) * 1000)))
                result = api.WaitForSingleObject(handle, milliseconds)
                if result == 258:
                    raise ctypes.WinError(1460)  # ERROR_TIMEOUT
                if result != 0:
                    raise ctypes.WinError(ctypes.get_last_error())
        yield wait
    finally:
        if snapshot is not None:
            api.CloseHandle(snapshot)
        for handle in handles:
            api.CloseHandle(handle)


def rename_protected(source, destination, timeout=5):
    """Retry only transient Windows sharing/access errors, without replacing data."""
    from .update_native import protected_tree
    from .update_packages import plain
    source, destination = Path(source), Path(destination)
    if source.parent != destination.parent:
        raise ValueError('更新目錄必須位於同一個受保護父目錄')
    deadline = time.monotonic() + timeout
    for attempt in range(21):
        # Deep ACL checks remain at the adapter boundary; recheck the small
        # roots and every path/reparse component on each retry, not whole trees.
        plain(source)
        plain(destination)
        protected_tree(source.parent, recursive=False)
        protected_tree(source, recursive=False)
        if destination.exists():
            raise FileExistsError('更新目標目錄已存在，保留現場')
        try:
            source.rename(destination)
            return
        except OSError as exc:
            if getattr(exc, 'winerror', None) not in (5, 32, 33):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0 or attempt == 20:
                raise
            time.sleep(min(.25, remaining))
