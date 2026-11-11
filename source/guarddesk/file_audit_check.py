"""Read-only inspection of ONE selected object's SACL; never enumerate a tree."""
import ctypes
import os
from pathlib import Path

FILE_SYSTEM='{0CCE921D-69AE-11D9-BED3-505054503030}'


def inspect(path):
    if os.name!='nt':raise OSError('Windows File System auditing requires Windows')
    from ctypes import wintypes as w
    from .process_audit import read_flags,security_privilege
    path=Path(path).absolute()
    if not path.exists():raise ValueError('請指定一個既有文件或資料夾')
    api=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    api.GetNamedSecurityInfoW.argtypes=[w.LPWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(w.LPVOID),ctypes.POINTER(w.LPVOID)]
    api.GetNamedSecurityInfoW.restype=w.DWORD
    api.GetAclInformation.argtypes=[w.LPVOID,w.LPVOID,w.DWORD,ctypes.c_int];api.GetAclInformation.restype=w.BOOL
    api.GetAce.argtypes=[w.LPVOID,w.DWORD,ctypes.POINTER(w.LPVOID)];api.GetAce.restype=w.BOOL
    kernel.LocalFree.argtypes=[w.LPVOID];kernel.LocalFree.restype=w.LPVOID
    class ACL_SIZE(ctypes.Structure):_fields_=[('count',w.DWORD),('used',w.DWORD),('free',w.DWORD)]
    class ACE_HEADER(ctypes.Structure):_fields_=[('kind',ctypes.c_ubyte),('flags',ctypes.c_ubyte),('size',w.WORD)]
    sacl=w.LPVOID();descriptor=w.LPVOID();count=0;inheritable=0
    with security_privilege(api):
        code=api.GetNamedSecurityInfoW(str(path),1,8,None,None,None,ctypes.byref(sacl),ctypes.byref(descriptor))
        if code:raise ctypes.WinError(code)
        try:
            if sacl:
                info=ACL_SIZE()
                if not api.GetAclInformation(sacl,ctypes.byref(info),ctypes.sizeof(info),2):raise ctypes.WinError(ctypes.get_last_error())
                if info.count>65535:raise OSError('SACL entry limit exceeded')
                for i in range(info.count):
                    ace=w.LPVOID()
                    if not api.GetAce(sacl,i,ctypes.byref(ace)):raise ctypes.WinError(ctypes.get_last_error())
                    head=ctypes.cast(ace,ctypes.POINTER(ACE_HEADER)).contents
                    # Standard SYSTEM_AUDIT_ACE only. Object/callback-specific
                    # ACEs need their own applicability checks, so not promoted.
                    if head.kind==2 and head.size>=12 and head.flags&0x40:
                        mask=ctypes.c_uint32.from_address(ace.value+4).value
                        if mask&1:
                            if not head.flags&8:count+=1 # INHERIT_ONLY is not active on this object
                            if head.flags&3:inheritable+=1
        finally:
            if descriptor:kernel.LocalFree(descriptor)
    flags=read_flags(None,(FILE_SYSTEM,))[FILE_SYSTEM]
    return {'path':str(path),'check_only':True,'success_auditing':bool(flags&1),
            'standard_success_read_aces':count,'inheritable_read_aces':inheritable,
            'coverage':'selected_object_only_not_child_coverage','principal_applicability':'not_verified',
            'note':'不讀取文件內容，不修改稽核原則或 SACL；存在 ACE 不代表所有帳號／子目錄都適用。'}
