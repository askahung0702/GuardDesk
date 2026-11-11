"""Public immutable runtime RX; credentials and state remain private.

The trial installer provisions its fixed protected USBControl stage; trial
startup only verifies it. Standard Agents retain the older updater repair path.
"""
import ctypes
import os
import re
from ctypes import wintypes as w
from . import update_packages as packages

USERS='S-1-5-32-545'
READ_EXECUTE=0x1200a9
_ready=False


def grant_read_execute(path):
    """Merge one non-inheriting RX ACE, preserving owner and other ACEs."""
    from .source_permissions import WindowsSecurity
    security=WindowsSecurity()
    _,entries=security.descriptor(path)
    if any(kind==0 and not flags&8 and sid==USERS and mask&READ_EXECUTE==READ_EXECUTE for kind,flags,mask,sid in entries):return False
    adv=security.adv;kernel=security.kernel
    class Trustee(ctypes.Structure):
        _fields_=[('multiple',w.LPVOID),('operation',ctypes.c_int),('form',ctypes.c_int),('type',ctypes.c_int),('name',w.LPVOID)]
    class Access(ctypes.Structure):
        _fields_=[('mask',w.DWORD),('mode',ctypes.c_int),('inheritance',w.DWORD),('trustee',Trustee)]
    adv.ConvertStringSidToSidW.argtypes=[w.LPCWSTR,ctypes.POINTER(w.LPVOID)];adv.ConvertStringSidToSidW.restype=w.BOOL
    adv.SetEntriesInAclW.argtypes=[w.ULONG,ctypes.POINTER(Access),w.LPVOID,ctypes.POINTER(w.LPVOID)];adv.SetEntriesInAclW.restype=w.DWORD
    adv.SetNamedSecurityInfoW.argtypes=[w.LPWSTR,ctypes.c_int,w.DWORD,w.LPVOID,w.LPVOID,w.LPVOID,w.LPVOID];adv.SetNamedSecurityInfoW.restype=w.DWORD
    sid=w.LPVOID();descriptor=w.LPVOID();old_acl=w.LPVOID();new_acl=w.LPVOID()
    try:
        if not adv.ConvertStringSidToSidW(USERS,ctypes.byref(sid)):raise ctypes.WinError(ctypes.get_last_error())
        code=adv.GetNamedSecurityInfoW(str(path),1,4,None,None,ctypes.byref(old_acl),None,ctypes.byref(descriptor))
        if code:raise ctypes.WinError(code)
        if not old_acl:raise OSError('Public runtime cannot have a null DACL')
        access=Access(READ_EXECUTE,1,0,Trustee(None,0,0,2,sid))
        code=adv.SetEntriesInAclW(1,ctypes.byref(access),old_acl,ctypes.byref(new_acl))
        if code:raise ctypes.WinError(code)
        code=adv.SetNamedSecurityInfoW(str(path),1,4,None,None,new_acl,None)
        if code:raise ctypes.WinError(code)
        return True
    finally:
        for pointer in (new_acl,descriptor,sid):
            if pointer:kernel.LocalFree(pointer)


def runtime_entries(program,native):
    from .update_native import protected_tree
    program=packages.plain(program);native=packages.plain(native)
    # Validate every path/owner/write grant before making anything public.
    protected_tree(program,recursive=False)
    entries=[program,native]
    for path in native.rglob('*'):
        if len(entries)>=2*packages.MAX_FILES:raise OSError('Installed runtime exceeds permission repair limit')
        packages.plain(path)
        if path.is_file():packages.safe_name(path.relative_to(native).as_posix())
        entries.append(path)
    if not (native/'GuardDesk.exe').is_file():raise OSError('Installed runtime is incomplete')
    for path in entries[1:]:protected_tree(path,recursive=False)
    return entries


def publish_runtime(entries):
    from .update_native import protected_tree
    changed=0
    # No inheritable Users ACE: ProgramData and sibling Updater are untouched.
    for path in reversed(entries):changed+=grant_read_execute(path)
    for path in entries:protected_tree(path,recursive=False)
    return {'checked':len(entries),'changed':changed,'scope':'fixed_public_native_runtime_only'}


def prepare_staged_runtime(stage):
    """Only the existing protected installer stage, before stop/switch/start."""
    from .windows_privilege import is_admin
    from .update_native import folder
    if os.name!='nt' or not is_admin():raise PermissionError('Staged runtime permissions require administrator')
    program=packages.plain(folder(38));stage=packages.plain(stage)
    if stage.parent!=program or not re.fullmatch(r'USBControl\.install-stage-[0-9a-f]{16}',stage.name):
        raise ValueError('Only the fixed native installer stage can receive public RX')
    return publish_runtime(runtime_entries(program,stage))


def repair_installed_runtime():
    # Retained for the standard Agent's older centralized updater contract.
    from .windows_privilege import is_admin
    from .update_native import folder
    if os.name!='nt' or not is_admin():raise PermissionError('Protected runtime permission repair requires administrator')
    program=packages.plain(folder(38))
    return publish_runtime(runtime_entries(program,program/'USBControl'))


def verify_installed_runtime():
    """Read-only trial startup: never fix an installer permission failure here."""
    from .source_permissions import WindowsSecurity
    from .update_native import folder
    program=packages.plain(folder(38));entries=runtime_entries(program,program/'USBControl')
    security=WindowsSecurity()
    for path in entries:
        _,aces=security.descriptor(path)
        if not any(kind==0 and not flags&8 and sid==USERS and mask&READ_EXECUTE==READ_EXECUTE for kind,flags,mask,sid in aces):
            raise PermissionError('Installed runtime lacks installer-provisioned public RX; preserve installation')
    return {'checked':len(entries),'changed':0,'scope':'fixed_public_native_runtime_only'}


def ensure_installed_runtime():
    global _ready
    if not _ready:
        from .remote_trial import enabled
        if enabled():verify_installed_runtime()
        else:repair_installed_runtime()
        _ready=True
