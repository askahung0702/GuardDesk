"""Local MIS window activation only. No remote input or authority changes."""
import ctypes
from ctypes import wintypes as w

CLASS_NAME='GuardDeskNativeMediaViewerV1'


def api():
    user=ctypes.WinDLL('user32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    for name in ('GetCurrentProcessId','GetCurrentThreadId'):
        fn=getattr(kernel,name);fn.argtypes=[];fn.restype=w.DWORD
    callback=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
    user.EnumThreadWindows.argtypes=[w.DWORD,callback,w.LPARAM];user.EnumThreadWindows.restype=w.BOOL
    user.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)];user.GetWindowThreadProcessId.restype=w.DWORD
    user.GetClassNameW.argtypes=[w.HWND,w.LPWSTR,ctypes.c_int];user.GetClassNameW.restype=ctypes.c_int
    for name in ('GetForegroundWindow','GetFocus'):getattr(user,name).restype=w.HWND
    for name in ('IsIconic','IsZoomed','SetForegroundWindow'):
        fn=getattr(user,name);fn.argtypes=[w.HWND];fn.restype=w.BOOL
    user.SetFocus.argtypes=[w.HWND];user.SetFocus.restype=w.HWND
    user.ShowWindow.argtypes=[w.HWND,ctypes.c_int];user.ShowWindow.restype=w.BOOL
    return user,kernel,callback


def find_owned_window(user,kernel,callback):
    """Exactly one fixed-class window on this native UI thread/process."""
    pid=kernel.GetCurrentProcessId();thread=kernel.GetCurrentThreadId();found=[];count=0
    @callback
    def visit(hwnd,unused):
        nonlocal count
        count+=1
        if count>64:return False
        owner=w.DWORD();actual=user.GetWindowThreadProcessId(hwnd,ctypes.byref(owner))
        name=ctypes.create_unicode_buffer(128)
        if actual==thread and owner.value==pid and user.GetClassNameW(hwnd,name,len(name)) and name.value==CLASS_NAME:
            found.append(hwnd)
        return True
    if not user.EnumThreadWindows(thread,visit,0) or len(found)!=1:return None
    return found[0]


def activate(toggle_maximize=False):
    if type(toggle_maximize) is not bool:raise ValueError('Invalid local viewer action')
    user,kernel,callback=api();hwnd=find_owned_window(user,kernel,callback)
    if not hwnd:return False
    foreground=user.GetForegroundWindow();owner=w.DWORD()
    if not foreground or not user.GetWindowThreadProcessId(foreground,ctypes.byref(owner)) or owner.value!=kernel.GetCurrentProcessId():
        return False # Never steal another application's foreground/focus.
    if toggle_maximize:user.ShowWindow(hwnd,9 if user.IsZoomed(hwnd) else 3)
    elif user.IsIconic(hwnd):user.ShowWindow(hwnd,9)
    if not user.SetForegroundWindow(hwnd):return False
    user.SetFocus(hwnd)
    return user.GetForegroundWindow()==hwnd and user.GetFocus()==hwnd
