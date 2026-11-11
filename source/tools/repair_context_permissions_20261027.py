"""Explicit admin maintenance of DEV's fixed public runtime; never config/data."""
import ctypes
import datetime
import json
import sys
import time
from ctypes import wintypes as w
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.context_permissions import repair_installed_runtime
from guarddesk.update_native import folder,protected_tree
from guarddesk.windows_controls import is_admin
from guarddesk.source_permissions import WindowsSecurity


def main():
    if not is_admin():raise PermissionError('Explicit administrator UAC required')
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    output=ROOT/'evidence/maintenance'/('context-permission-repair-'+stamp+'.json')
    backup=ROOT/'runtime/maintenance'/('context-permission-backup-'+stamp+'.json');backup.parent.mkdir(parents=True,exist_ok=True)
    security=WindowsSecurity();adv=security.adv
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes=[w.LPVOID,w.DWORD,w.DWORD,ctypes.POINTER(w.LPWSTR),w.LPVOID]
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype=w.BOOL
    program=folder(38);native=program/'USBControl';records=[]
    entries=[program,native,*native.rglob('*')]
    if len(entries)>10000:raise OSError('Runtime exceeds maintenance bound')
    started=time.monotonic()
    for path in entries:
        protected_tree(path,recursive=False)
        descriptor=w.LPVOID();text=w.LPWSTR()
        try:
            code=adv.GetNamedSecurityInfoW(str(path),1,5,None,None,None,None,ctypes.byref(descriptor))
            if code:raise ctypes.WinError(code)
            if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,1,5,ctypes.byref(text),None):raise ctypes.WinError(ctypes.get_last_error())
            records.append({'path':str(path),'sddl':text.value})
        finally:
            if text:security.kernel.LocalFree(ctypes.cast(text,w.LPVOID))
            if descriptor:security.kernel.LocalFree(descriptor)
    backup.write_text(json.dumps({'format':1,'scope':'fixed_public_runtime_only','acl':records},indent=2),encoding='utf-8')
    result={'observed_at':datetime.datetime.now().astimezone().isoformat(),'company_changed':True,'backup':str(backup.relative_to(ROOT)),
            'operation':'public_code_users_read_execute_no_write','config_or_identity_or_outbox_changed':False,
            'defender_or_audit_policy_changed':False,'processes_restarted':False}
    try:result.update(repair_installed_runtime(),passed=True)
    except Exception as exc:result.update(passed=False,error_type=type(exc).__name__,winerror=getattr(exc,'winerror',None))
    result['seconds']=round(time.monotonic()-started,3)
    output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
