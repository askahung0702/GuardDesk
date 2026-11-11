"""Visible Windows notification icon, on the Tk message thread; no startup task."""
import ctypes as c
from ctypes import wintypes as w
import os
import uuid
import threading


class _NativeIcon:
    def __init__(self,schedule,show,stop,exit):
        if os.name!='nt':raise OSError('通知區圖示僅支援 Windows')
        self.schedule=schedule;self.actions={1:show,2:stop,3:exit};self.hwnd=None;self.added=False
        self.user=c.WinDLL('user32',use_last_error=True);self.shell=c.WinDLL('shell32',use_last_error=True);self.kernel=c.WinDLL('kernel32',use_last_error=True)
        proc=c.WINFUNCTYPE(c.c_ssize_t,w.HWND,w.UINT,w.WPARAM,w.LPARAM)
        class WC(c.Structure):
            _fields_=[('style',w.UINT),('proc',proc),('extra',c.c_int),('window_extra',c.c_int),('instance',w.HINSTANCE),('icon',w.HICON),('cursor',w.HANDLE),('brush',w.HBRUSH),('menu',w.LPCWSTR),('name',w.LPCWSTR)]
        class NID(c.Structure):
            _fields_=[('size',w.DWORD),('window',w.HWND),('id',w.UINT),('flags',w.UINT),('callback',w.UINT),('icon',w.HICON),('tip',w.WCHAR*128),('state',w.DWORD),('mask',w.DWORD),('info',w.WCHAR*256),('version',w.UINT),('title',w.WCHAR*64),('infoflags',w.DWORD),('guid',c.c_byte*16),('balloon',w.HICON)]
        self.user.DefWindowProcW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM];self.user.DefWindowProcW.restype=c.c_ssize_t
        self.kernel.GetModuleHandleW.argtypes=[w.LPCWSTR];self.kernel.GetModuleHandleW.restype=w.HMODULE
        self.user.RegisterClassW.argtypes=[c.POINTER(WC)];self.user.RegisterClassW.restype=w.ATOM
        self.user.UnregisterClassW.argtypes=[w.LPCWSTR,w.HINSTANCE]
        self.user.CreateWindowExW.argtypes=[w.DWORD,w.LPCWSTR,w.LPCWSTR,w.DWORD,c.c_int,c.c_int,c.c_int,c.c_int,w.HWND,w.HMENU,w.HINSTANCE,c.c_void_p];self.user.CreateWindowExW.restype=w.HWND
        self.user.DestroyWindow.argtypes=[w.HWND]
        self.user.LoadIconW.argtypes=[w.HINSTANCE,c.c_void_p];self.user.LoadIconW.restype=w.HICON
        self.user.RegisterWindowMessageW.argtypes=[w.LPCWSTR];self.user.RegisterWindowMessageW.restype=w.UINT
        self.user.CreatePopupMenu.restype=w.HMENU
        self.user.AppendMenuW.argtypes=[w.HMENU,w.UINT,c.c_size_t,w.LPCWSTR]
        self.user.TrackPopupMenu.argtypes=[w.HMENU,w.UINT,c.c_int,c.c_int,c.c_int,w.HWND,c.c_void_p];self.user.TrackPopupMenu.restype=w.UINT
        self.user.DestroyMenu.argtypes=[w.HMENU];self.user.SetForegroundWindow.argtypes=[w.HWND]
        self.user.GetCursorPos.argtypes=[c.POINTER(w.POINT)]
        self.user.PostQuitMessage.argtypes=[c.c_int]
        self.shell.Shell_NotifyIconW.argtypes=[w.DWORD,c.POINTER(NID)];self.shell.Shell_NotifyIconW.restype=w.BOOL
        self.callback=0x8000+63;self.taskbar=self.user.RegisterWindowMessageW('TaskbarCreated')
        self.instance=self.kernel.GetModuleHandleW(None);self.name='GuardDeskMISTray'+uuid.uuid4().hex
        self.proc=proc(self.message);self.wc=WC();self.wc.proc=self.proc;self.wc.instance=self.instance;self.wc.name=self.name
        if not self.user.RegisterClassW(c.byref(self.wc)):raise c.WinError(c.get_last_error())
        self.hwnd=self.user.CreateWindowExW(0,self.name,'GuardDesk MIS notification window',0,0,0,0,0,None,None,self.instance,None)
        if not self.hwnd:self.close();raise c.WinError(c.get_last_error())
        self.nid=NID();self.nid.size=c.sizeof(NID);self.nid.window=self.hwnd;self.nid.id=1;self.nid.flags=1|2|4;self.nid.callback=self.callback
        self.nid.icon=self.user.LoadIconW(None,c.c_void_p(32512));self.nid.tip='GuardDesk MIS 遠端協助 — 點擊開啟，右鍵結束'
        if not self.add():self.close();raise OSError('無法建立 Windows 通知區圖示；保留視窗')

    def add(self):
        self.added=bool(self.shell.Shell_NotifyIconW(0,c.byref(self.nid)))
        if self.added:self.nid.version=4;self.shell.Shell_NotifyIconW(4,c.byref(self.nid))
        return self.added

    def message(self,hwnd,msg,wp,lp):
        try:
            if msg==0x10:
                self.close();self.user.PostQuitMessage(0);return 0
            if msg==self.taskbar:
                self.add();return 0
            if msg==self.callback:
                event=int(lp)&0xffff
                if event in (0x202,0x203,0x400,0x401):self.schedule(self.actions[1])
                elif event in (0x205,0x7b):self.menu()
                return 0
            if msg==0x111 and int(wp)&0xffff in self.actions:
                self.schedule(self.actions[int(wp)&0xffff]);return 0
        except Exception:
            # Never propagate a Python exception through a native WNDPROC.
            return 0
        return self.user.DefWindowProcW(hwnd,msg,wp,lp)

    def menu(self):
        menu=self.user.CreatePopupMenu()
        if not menu:return
        try:
            for key,label in ((1,'開啟遠端協助'),(2,'停止目前協助'),(3,'完全結束')):self.user.AppendMenuW(menu,0,key,label)
            point=w.POINT();self.user.GetCursorPos(c.byref(point));self.user.SetForegroundWindow(self.hwnd)
            action=self.user.TrackPopupMenu(menu,0x100|2,point.x,point.y,0,self.hwnd,None)
            if action in self.actions:self.schedule(self.actions[action])
        finally:self.user.DestroyMenu(menu)

    def close(self):
        if self.added:self.shell.Shell_NotifyIconW(2,c.byref(self.nid));self.added=False
        if self.hwnd:self.user.DestroyWindow(self.hwnd);self.hwnd=None
        self.user.UnregisterClassW(self.name,self.instance)


class TrayIcon:
    """Dedicated native message loop. schedule must enqueue, never call Tk."""
    def __init__(self,schedule,show,stop,exit):
        self.native=None;self.error=None;self.cancelled=threading.Event();ready=threading.Event()
        def run():
            try:
                self.native=_NativeIcon(schedule,show,stop,exit)
                if self.cancelled.is_set():return
                user=self.native.user
                user.GetMessageW.argtypes=[c.POINTER(w.MSG),w.HWND,w.UINT,w.UINT];user.GetMessageW.restype=w.BOOL
                user.TranslateMessage.argtypes=[c.POINTER(w.MSG)];user.DispatchMessageW.argtypes=[c.POINTER(w.MSG)];user.DispatchMessageW.restype=c.c_ssize_t
                ready.set();msg=w.MSG()
                while user.GetMessageW(c.byref(msg),None,0,0)>0:user.TranslateMessage(c.byref(msg));user.DispatchMessageW(c.byref(msg))
            except (OSError,ValueError) as exc:self.error=exc
            finally:
                ready.set()
                if self.native and self.native.hwnd:self.native.close()
        self.thread=threading.Thread(target=run,name='GuardDesk MIS notification icon',daemon=True);self.thread.start()
        if not ready.wait(3):self.cancelled.set();raise OSError('通知區初始化逾時，保留視窗')
        if self.error:raise self.error
        if not self.native or not self.native.added:raise OSError('通知區尚未就緒，保留視窗')

    @property
    def added(self):return bool(self.native and self.native.added)
    @property
    def hwnd(self):return self.native.hwnd if self.native else None
    @property
    def callback(self):return self.native.callback
    def message(self,*args):return self.native.message(*args)
    def close(self):
        if self.hwnd:
            user=self.native.user;user.PostMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM]
            user.PostMessageW(self.hwnd,0x10,0,0)
        self.thread.join(1)
