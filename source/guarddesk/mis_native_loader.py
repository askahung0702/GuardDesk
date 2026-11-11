"""Standard-user MIS image pins. Never reused for SYSTEM launch policy.

Current-user ownership is allowed here because this DLL runs in that same
standard-user process. Other users may not rewrite it. Handles deny concurrent
write/delete until the library's session owner releases the pins.
"""
import ctypes
import hashlib
import os
from pathlib import Path
from ctypes import wintypes as w


def plain(path):
    path=Path(path).absolute()
    for part in (path,*path.parents):
        if os.path.lexists(part) and (part.is_symlink() or getattr(part.lstat(),'st_file_attributes',0)&0x400):
            raise ValueError('MIS native path contains a reparse point')
    return path


class ImagePins:
    def __init__(self,root):
        self.handles=[];self.root=plain(root);self.api=ctypes.WinDLL('kernel32',use_last_error=True)
        self.adv=ctypes.WinDLL('advapi32',use_last_error=True)
        self.api.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE];self.api.CreateFileW.restype=w.HANDLE
        self.api.CloseHandle.argtypes=[w.HANDLE];self.api.LocalFree.argtypes=[w.LPVOID]
        self.api.GetCurrentProcess.restype=w.HANDLE
        self.api.GetFileInformationByHandleEx.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD];self.api.GetFileInformationByHandleEx.restype=w.BOOL
        self.adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)];self.adv.OpenProcessToken.restype=w.BOOL
        self.adv.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)];self.adv.GetTokenInformation.restype=w.BOOL
        self.adv.GetSecurityInfo.argtypes=[w.HANDLE,ctypes.c_int,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID,ctypes.POINTER(w.LPVOID),w.LPVOID,ctypes.POINTER(w.LPVOID)]
        self.adv.GetSecurityInfo.restype=w.DWORD
        self.adv.ConvertSidToStringSidW.argtypes=[w.LPVOID,ctypes.POINTER(w.LPWSTR)];self.adv.ConvertSidToStringSidW.restype=w.BOOL
        self.adv.GetAclInformation.argtypes=[w.LPVOID,w.LPVOID,w.DWORD,ctypes.c_int];self.adv.GetAclInformation.restype=w.BOOL
        self.adv.GetAce.argtypes=[w.LPVOID,w.DWORD,ctypes.POINTER(w.LPVOID)];self.adv.GetAce.restype=w.BOOL
        token=w.HANDLE();size=w.DWORD()
        if not self.adv.OpenProcessToken(self.api.GetCurrentProcess(),8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
        try:
            self.adv.GetTokenInformation(token,1,None,0,ctypes.byref(size))
            if not 0<size.value<=65536:raise OSError('MIS token size')
            buffer=ctypes.create_string_buffer(size.value)
            if not self.adv.GetTokenInformation(token,1,buffer,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
            self.allowed={'S-1-5-18','S-1-5-32-544',self._sid(ctypes.cast(buffer,ctypes.POINTER(w.LPVOID))[0])}
            elevated=w.DWORD()
            if not self.adv.GetTokenInformation(token,20,ctypes.byref(elevated),ctypes.sizeof(elevated),ctypes.byref(size)) or elevated.value:
                raise OSError('Native MIS requires a standard-user process')
        finally:self.api.CloseHandle(token)
        try:
            from .remote_components import MIS_REMOTE_FILES,COHORT_MANIFEST,read_cohort
            folder=self.root/'_internal'/'remote'
            for path in (self.root,self.root/'_internal',folder):self._pin(path,True)
            for name in (*MIS_REMOTE_FILES,COHORT_MANIFEST):self._pin(folder/name,False)
            self.cohort=read_cohort(self.root,role='mis')
            if 'GuardDeskMisNative.dll' not in self.cohort['files']:raise ValueError('Native renderer not in cohort')
        except Exception:self.close();raise

    def _sid(self,value):
        text=w.LPWSTR()
        if not self.adv.ConvertSidToStringSidW(value,ctypes.byref(text)):raise ctypes.WinError(ctypes.get_last_error())
        try:return text.value
        finally:self.api.LocalFree(ctypes.cast(text,w.LPVOID))

    def _pin(self,path,directory):
        path=plain(path)
        handle=self.api.CreateFileW(str(path),0x80020080,1,None,3,0x02200000 if directory else 0x00200000,None)
        if handle in (None,ctypes.c_void_p(-1).value):raise ctypes.WinError(ctypes.get_last_error())
        self.handles.append(handle)
        class Tag(ctypes.Structure):_fields_=[('attributes',w.DWORD),('tag',w.DWORD)]
        tag=Tag()
        if not self.api.GetFileInformationByHandleEx(handle,9,ctypes.byref(tag),ctypes.sizeof(tag)) or tag.attributes&0x400 or bool(tag.attributes&16)!=directory:
            raise ValueError('MIS image path type/reparse mismatch')
        owner=w.LPVOID();acl=w.LPVOID();descriptor=w.LPVOID()
        code=self.adv.GetSecurityInfo(handle,1,5,ctypes.byref(owner),None,ctypes.byref(acl),None,ctypes.byref(descriptor))
        if code:raise ctypes.WinError(code)
        try:
            if self._sid(owner) not in self.allowed or not acl:raise PermissionError('MIS image owner/DACL')
            class Info(ctypes.Structure):_fields_=[('count',w.DWORD),('used',w.DWORD),('free',w.DWORD)]
            info=Info()
            if not self.adv.GetAclInformation(acl,ctypes.byref(info),ctypes.sizeof(info),2) or info.count>4096:raise OSError('MIS image ACL')
            for i in range(info.count):
                ace=w.LPVOID()
                if not self.adv.GetAce(acl,i,ctypes.byref(ace)):raise ctypes.WinError(ctypes.get_last_error())
                kind=ctypes.c_ubyte.from_address(ace.value).value
                if kind in (1,2,3,6,7,8,10,12,13,14,15,16,17,18):continue
                mask=ctypes.c_uint32.from_address(ace.value+4).value
                if mask&0x500D0156 and (kind!=0 or self._sid(ace.value+8) not in self.allowed):
                    raise PermissionError('Another account can modify MIS native images')
        finally:self.api.LocalFree(descriptor)

    def close(self):
        for handle in reversed(self.handles):self.api.CloseHandle(handle)
        self.handles.clear()

    def __del__(self):
        if getattr(self,'handles',None):self.close()
