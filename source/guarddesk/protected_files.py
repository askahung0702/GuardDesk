"""Protected file primitives shared by runtime and installer; no installation API."""
import ctypes
import json
import os
import secrets
from . import update_packages as packages
from .update_native import protected_tree

def read_json(path, limit=65536):
    path=packages.plain(path)
    with path.open('rb') as stream:raw=stream.read(limit+1)
    if len(raw)>limit:raise ValueError('安裝設定／狀態超過大小上限')
    value=json.loads(raw.decode('utf-8-sig'))
    if not isinstance(value,dict):raise ValueError('安裝設定／狀態格式不正確')
    return value

def encode(value):return json.dumps(value,ensure_ascii=False,indent=2).encode('utf-8')

def assert_quiescent(root,include_install=True):
    from .transaction_status import read_phase,JournalStateError
    names=['updates/transaction-native.json','updates/updater-refresh.json']
    if include_install:names.append('install-transaction.json')
    for filename in names:
        path=root/filename
        phase=read_phase(path) if filename.startswith('updates/') else (read_json(path).get('phase') if path.exists() else None)
        if phase is None and path.exists():raise JournalStateError('journal_invalid_phase')
        if phase is not None and phase not in ('healthy','rolled_back','complete','failed_before_switch'):
            raise JournalStateError('journal_in_progress')

class ProtectedFiles:
    def protect(self,path,create=False):
        from ctypes import wintypes as w
        path=packages.plain(path)
        if path.exists() and create:
            protected_tree(path,recursive=False);return
        if create:
            from .source_permissions import WindowsSecurity,TRUSTED_INSTALLER,SYSTEM,ADMINISTRATORS,WRITE_SOURCE,NON_GRANTING
            owner,entries=WindowsSecurity().descriptor(path.parent)
            allowed={TRUSTED_INSTALLER,SYSTEM,ADMINISTRATORS}
            if owner not in allowed:raise OSError('安裝父目錄擁有者不受信任')
            for kind,inheritance,mask,trustee in entries:
                if inheritance&8 or kind in NON_GRANTING:continue
                # Windows ProgramData normally lets Users add siblings and
                # write the parent's attributes/EA (0x116). These rights do
                # not replace a private child; DELETE_CHILD, DELETE, owner,
                # DACL and generic writes remain rejected.
                if mask&(WRITE_SOURCE & ~0x116) and (kind!=0 or trustee not in allowed):raise OSError('安裝父目錄可由非信任帳戶替換子目錄')
        kernel=ctypes.WinDLL('kernel32',use_last_error=True);adv=ctypes.WinDLL('advapi32',use_last_error=True)
        descriptor=w.LPVOID();owner=w.LPVOID();acl=w.LPVOID();present=w.BOOL();defaulted=w.BOOL()
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID];adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=w.BOOL
        kernel.LocalFree.argtypes=[w.LPVOID]
        flags='OICI' if create or path.is_dir() else ''
        sddl='O:BAD:P(A;'+flags+';FA;;;SY)(A;'+flags+';FA;;;BA)(A;'+flags+';RC;;;OW)'
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(descriptor),None):raise ctypes.WinError(ctypes.get_last_error())
        try:
            if create:
                class Attributes(ctypes.Structure):_fields_=[('length',w.DWORD),('descriptor',w.LPVOID),('inherit',w.BOOL)]
                attributes=Attributes(ctypes.sizeof(Attributes),descriptor,False)
                kernel.CreateDirectoryW.argtypes=[w.LPCWSTR,ctypes.POINTER(Attributes)];kernel.CreateDirectoryW.restype=w.BOOL
                if not kernel.CreateDirectoryW(str(path),ctypes.byref(attributes)):raise ctypes.WinError(ctypes.get_last_error())
            else:
                adv.GetSecurityDescriptorOwner.argtypes=[w.LPVOID,ctypes.POINTER(w.LPVOID),ctypes.POINTER(w.BOOL)];adv.GetSecurityDescriptorOwner.restype=w.BOOL
                adv.GetSecurityDescriptorDacl.argtypes=[w.LPVOID,ctypes.POINTER(w.BOOL),ctypes.POINTER(w.LPVOID),ctypes.POINTER(w.BOOL)];adv.GetSecurityDescriptorDacl.restype=w.BOOL
                if not adv.GetSecurityDescriptorOwner(descriptor,ctypes.byref(owner),ctypes.byref(defaulted)) or not adv.GetSecurityDescriptorDacl(descriptor,ctypes.byref(present),ctypes.byref(acl),ctypes.byref(defaulted)) or not present or not acl:raise OSError('安裝安全描述元不完整')
                adv.SetNamedSecurityInfoW.argtypes=[w.LPWSTR,ctypes.c_int,w.DWORD,w.LPVOID,w.LPVOID,w.LPVOID,w.LPVOID];adv.SetNamedSecurityInfoW.restype=w.DWORD
                error=adv.SetNamedSecurityInfoW(str(path),1,0x80000005,owner,None,acl,None)
                if error:raise ctypes.WinError(error)
        finally:kernel.LocalFree(descriptor)
        protected_tree(path,recursive=False)

    def write(self,path,raw):
        path=packages.plain(path);temporary=packages.plain(path.with_name(path.name+'.'+secrets.token_hex(8)+'.tmp'))
        try:
            with temporary.open('xb') as stream:stream.write(raw)
            self.protect(temporary);os.replace(temporary,path)
        finally:temporary.unlink(missing_ok=True)

