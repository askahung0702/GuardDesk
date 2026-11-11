"""Read-only permissions check for the MIS server's bundled update source.

This is separate from the SYSTEM broker's stricter protected_tree contract.
Ancestors may allow creating unrelated subdirectories; they must not allow
replacing an existing protected descendant. The source itself stays private.
"""
import ctypes
from pathlib import Path
from . import update_packages as packages

SYSTEM='S-1-5-18'
ADMINISTRATORS='S-1-5-32-544'
TRUSTED_INSTALLER='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
WRITE_SOURCE=0x500D0156
# FILE_ADD_SUBDIRECTORY (0x4) on an ancestor alone cannot replace the existing
# protected child. All other previously rejected write rights stay rejected.
WRITE_ANCESTOR=WRITE_SOURCE & ~0x4
NON_GRANTING={1,2,3,6,7,8,10,12,13,14,15,16,17,18,19,20,21}


class SourcePermissionError(OSError):
    def __init__(self,path,reason):
        self.path,self.reason=str(path),reason
        super().__init__('隨附版本來源權限檢查未通過')


class WindowsSecurity:
    def __init__(self):
        from ctypes import wintypes as w
        self.w=w;self.adv=ctypes.WinDLL('advapi32',use_last_error=True);self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.adv.GetNamedSecurityInfoW.argtypes=[w.LPWSTR,ctypes.c_int,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID,ctypes.POINTER(w.LPVOID),w.LPVOID,ctypes.POINTER(w.LPVOID)]
        self.adv.GetNamedSecurityInfoW.restype=w.DWORD
        self.adv.ConvertSidToStringSidW.argtypes=[w.LPVOID,ctypes.POINTER(w.LPWSTR)];self.adv.ConvertSidToStringSidW.restype=w.BOOL
        self.adv.GetAclInformation.argtypes=[w.LPVOID,w.LPVOID,w.DWORD,ctypes.c_int];self.adv.GetAclInformation.restype=w.BOOL
        self.adv.GetAce.argtypes=[w.LPVOID,w.DWORD,ctypes.POINTER(w.LPVOID)];self.adv.GetAce.restype=w.BOOL
        self.kernel.LocalFree.argtypes=[w.LPVOID];self.kernel.LocalFree.restype=w.LPVOID
        self.kernel.GetCurrentProcess.restype=w.HANDLE;self.kernel.CloseHandle.argtypes=[w.HANDLE]
        self.adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)];self.adv.OpenProcessToken.restype=w.BOOL
        self.adv.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)];self.adv.GetTokenInformation.restype=w.BOOL

    def sid(self,value):
        text=self.w.LPWSTR()
        if not self.adv.ConvertSidToStringSidW(value,ctypes.byref(text)):raise ctypes.WinError(ctypes.get_last_error())
        try:return text.value
        finally:self.kernel.LocalFree(ctypes.cast(text,self.w.LPVOID))

    def current_user(self):
        w=self.w;token=w.HANDLE();size=w.DWORD()
        if not self.adv.OpenProcessToken(self.kernel.GetCurrentProcess(),8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
        try:
            self.adv.GetTokenInformation(token,1,None,0,ctypes.byref(size));buffer=ctypes.create_string_buffer(size.value)
            if not self.adv.GetTokenInformation(token,1,buffer,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
            return self.sid(ctypes.cast(buffer,ctypes.POINTER(w.LPVOID))[0])
        finally:self.kernel.CloseHandle(token)

    def descriptor(self,path):
        w=self.w;owner=w.LPVOID();acl=w.LPVOID();descriptor=w.LPVOID()
        class Info(ctypes.Structure):_fields_=[('count',w.DWORD),('used',w.DWORD),('free',w.DWORD)]
        try:
            code=self.adv.GetNamedSecurityInfoW(str(path),1,5,ctypes.byref(owner),None,ctypes.byref(acl),None,ctypes.byref(descriptor))
            if code:raise ctypes.WinError(code)
            if not acl:raise SourcePermissionError(path,'null_dacl')
            info=Info()
            if not self.adv.GetAclInformation(acl,ctypes.byref(info),ctypes.sizeof(info),2):raise ctypes.WinError(ctypes.get_last_error())
            if info.count>4096:raise SourcePermissionError(path,'acl_too_large')
            entries=[]
            for index in range(info.count):
                ace=w.LPVOID()
                if not self.adv.GetAce(acl,index,ctypes.byref(ace)):raise ctypes.WinError(ctypes.get_last_error())
                kind=ctypes.c_ubyte.from_address(ace.value).value;flags=ctypes.c_ubyte.from_address(ace.value+1).value
                size=ctypes.c_uint16.from_address(ace.value+2).value
                if size<8:raise SourcePermissionError(path,'invalid_acl')
                mask=ctypes.c_uint32.from_address(ace.value+4).value
                entries.append((kind,flags,mask,self.sid(ace.value+8) if kind==0 else None))
            return self.sid(owner),entries
        finally:
            if descriptor:self.kernel.LocalFree(descriptor)


def validate_descriptor(path,owner,entries,allowed,ancestor=False):
    if owner not in allowed:raise SourcePermissionError(path,'untrusted_owner')
    for kind,flags,mask,trustee in entries:
        if flags&8 or kind in NON_GRANTING:continue  # inherit-only never grants on this object
        if mask&(WRITE_ANCESTOR if ancestor else WRITE_SOURCE):
            if kind!=0 or trustee not in allowed:raise SourcePermissionError(path,'untrusted_write')


def check_source(path,stop):
    api=WindowsSecurity();allowed={SYSTEM,ADMINISTRATORS,TRUSTED_INSTALLER,api.current_user()}
    path=packages.plain(path)
    if len(path.parents)>64:raise SourcePermissionError(path,'path_too_deep')
    # Preserve the original source/parent validation boundary. The parent's
    # child-replacement rights matter; unrelated folder creation does not.
    # packages.plain separately rejects reparse points throughout the path.
    for parent in (path.parent,):
        if stop.is_set():raise InterruptedError('stopped')
        try:validate_descriptor(parent,*api.descriptor(parent),allowed,ancestor=True)
        except SourcePermissionError:raise
        except OSError:raise SourcePermissionError(parent,'permission_unreadable') from None
    for count,entry in enumerate(_entries(path),1):
        if stop.is_set():raise InterruptedError('stopped')
        if count>2*packages.MAX_FILES:raise SourcePermissionError(path,'source_too_large')
        try:
            packages.plain(entry)
            validate_descriptor(entry,*api.descriptor(entry),allowed)
        except SourcePermissionError:raise
        except (OSError,ValueError):raise SourcePermissionError(entry,'permission_unreadable') from None


def _entries(path):
    yield path
    yield from path.rglob('*')
