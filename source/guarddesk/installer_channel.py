"""Local, one-use installation diagnostics. No files are written with UAC rights.

The parent owns the pipe and persists the result using its ordinary user rights.
This channel conveys diagnostics only, never commands, credentials or authority.
"""
import ctypes
import json
import re
import secrets
from ctypes import wintypes as w

LIMIT = 16384
PREFIX = '\\\\.\\pipe\\GuardDesk-Install-'


def pipe_name(value):
    if not isinstance(value, str) or not re.fullmatch(re.escape(PREFIX) + '[0-9a-f]{32}', value):
        raise ValueError('安裝診斷通道格式不正確')
    return value


def api():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CreateNamedPipeW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.DWORD, w.DWORD, w.DWORD, w.DWORD, w.LPVOID]
    kernel.CreateNamedPipeW.restype = w.HANDLE
    kernel.ConnectNamedPipe.argtypes = [w.HANDLE, w.LPVOID]; kernel.ConnectNamedPipe.restype = w.BOOL
    kernel.ReadFile.argtypes = [w.HANDLE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]; kernel.ReadFile.restype = w.BOOL
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.WriteFile.argtypes = [w.HANDLE, w.LPCVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]; kernel.WriteFile.restype = w.BOOL
    return kernel


class Receiver:
    def __init__(self):
        from .source_permissions import WindowsSecurity
        security = WindowsSecurity(); descriptor = w.LPVOID()
        adv = security.adv
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), w.LPVOID]
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
        # Read/write only for this user and elevated MIS/SYSTEM; reject remote
        # clients and name reuse. No world-accessible temporary result file.
        sddl = 'D:P(A;;GA;;;' + security.current_user() + ')(A;;GA;;;BA)(A;;GA;;;SY)'
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        self.kernel = api(); self.name = PREFIX + secrets.token_hex(16); self.data = bytearray(); self.connected = False
        class Attributes(ctypes.Structure):
            _fields_ = [('length', w.DWORD), ('descriptor', w.LPVOID), ('inherit', w.BOOL)]
        attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
        try:
            self.handle = self.kernel.CreateNamedPipeW(self.name, 1 | 0x80000, 1 | 8, 1, LIMIT, LIMIT, 0, ctypes.byref(attributes))
            if self.handle == ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
        finally: security.kernel.LocalFree(descriptor)

    def poll(self):
        if not self.connected:
            result = self.kernel.ConnectNamedPipe(self.handle, None)
            error = ctypes.get_last_error() if not result else 0
            if error == 536: return None  # PIPE_LISTENING; never block the UI.
            if error not in (0, 535, 232): raise ctypes.WinError(error)
            self.connected = True
        buffer = ctypes.create_string_buffer(LIMIT + 1); read = w.DWORD()
        ok = self.kernel.ReadFile(self.handle, buffer, len(buffer), ctypes.byref(read), None)
        if not ok and ctypes.get_last_error() not in (109, 232): raise ctypes.WinError(ctypes.get_last_error())
        self.data.extend(buffer.raw[:read.value])
        if len(self.data) > LIMIT: raise ValueError('安裝診斷超過大小限制')
        if b'\n' in self.data:
            return json.loads(self.data.decode('utf-8'))
        return None

    def close(self):
        if self.handle: self.kernel.CloseHandle(self.handle); self.handle = None


def connect(name):
    kernel = api()
    handle = kernel.CreateFileW(pipe_name(name), 0x40000000, 0, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
    return kernel, handle


def send(channel, body):
    kernel, handle = channel
    raw = (json.dumps(body, ensure_ascii=False) + '\n').encode('utf-8')
    if len(raw) > LIMIT: raise ValueError('安裝診斷超過大小限制')
    written = w.DWORD()
    if not kernel.WriteFile(handle, raw, len(raw), ctypes.byref(written), None) or written.value != len(raw):
        raise ctypes.WinError(ctypes.get_last_error())
