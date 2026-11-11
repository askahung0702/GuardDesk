"""Shared private-directory and public connection validation; no center startup."""
import ctypes
import hashlib
import json
import os
from pathlib import Path


def secure_directory(path, allow_empty=False):
    """Create a private directory; optionally recreate only an empty directory."""
    path = Path(os.path.abspath(path))
    for ancestor in (path.parent, *path.parent.parents):
        if getattr(ancestor.lstat(), 'st_file_attributes', 0) & 0x400 or ancestor.is_symlink():
            raise ValueError('資料目錄不可經過 junction／符號連結')
    if os.path.lexists(path):
        if not allow_empty:
            raise ValueError('目錄已存在，為保留原資料不覆寫；請選尚不存在的專用目錄')
        if (getattr(path.lstat(), 'st_file_attributes', 0) & 0x400 or path.is_symlink() or
                not path.is_dir() or path == Path(path.anchor)):
            raise ValueError('請使用一般專用資料夾，不可使用磁碟根目錄或 junction／符號連結')
        if any(path.iterdir()):
            raise ValueError('資料夾已有資料，未覆寫或刪除；請保留原資料並選另一個空資料夾')
        # Non-recursive rmdir fails if any file appears during the check. The
        # subsequent atomic private mkdir also fails if someone replaces it.
        path.rmdir()
    if os.name != 'nt':
        path.mkdir(mode=0o700)
        return path
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.LocalFree.argtypes = [w.HLOCAL]; kernel.LocalFree.restype = w.HLOCAL
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.OpenProcessToken.restype = w.BOOL
    advapi.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)]
    advapi.GetTokenInformation.restype = w.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [w.LPVOID, ctypes.POINTER(w.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = w.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.DWORD)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    token = w.HANDLE(); descriptor = w.LPVOID(); sid_text = w.LPWSTR()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        size = w.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buffer, ctypes.POINTER(w.LPVOID))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        sddl = f'O:{sid_text.value}D:P(A;OICI;FA;;;{sid_text.value})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        class Attributes(ctypes.Structure):
            _fields_ = [('length', w.DWORD), ('descriptor', w.LPVOID), ('inherit', w.BOOL)]
        attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
        kernel.CreateDirectoryW.argtypes = [w.LPCWSTR, ctypes.POINTER(Attributes)]
        kernel.CreateDirectoryW.restype = w.BOOL
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if token: kernel.CloseHandle(token)
        if sid_text: kernel.LocalFree(ctypes.cast(sid_text, w.HLOCAL))
        if descriptor: kernel.LocalFree(descriptor)
    return path


def read_connection(path):
    path = Path(path).resolve(strict=True)
    if path.stat().st_size > 8192: raise ValueError('連線檔過大')
    body = json.loads(path.read_text(encoding='utf-8-sig'))
    from .connection_contract import validate_body
    validate_body(body)
    if not all(isinstance(body[key], str) and body[key] for key in ('server', 'ca', 'ca_sha256')):
        raise ValueError('端點連線檔欄位不正確')
    from urllib.parse import urlsplit
    parsed = urlsplit(body['server'])
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('端點連線網址不正確')
    ca = (path.parent / body['ca']).resolve(strict=True)
    if not ca.is_relative_to(path.parent) or ca.stat().st_size > 65536:
        raise ValueError('CA 必須位於 MIS 連線包目錄內')
    if hashlib.sha256(ca.read_bytes()).hexdigest() != body['ca_sha256']:
        raise ValueError('連線包 CA 雜湊不符，請向 MIS 重新取得')
    return body['server'], str(ca)



def plain(path):
    path = Path(path).absolute()
    for candidate in (path, *path.parents):
        if os.path.lexists(candidate) and (candidate.is_symlink() or getattr(candidate.lstat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('安裝路徑不可包含 junction／符號連結')


def save(path, body):
    temporary = Path(path).with_suffix('.tmp')
    temporary.write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(temporary, path)
