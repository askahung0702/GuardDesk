"""Read-only identity smoke; no tabs, documents, policy, attach or process writes.

Checks installed machine browsers and at most one existing root per browser.
No process command lines, user names, SIDs, URLs or certificate bytes are saved.
"""
import ctypes
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guarddesk import native_browser_identity as identity


def roots():
    class Entry(ctypes.Structure):
        _fields_ = [('size',w.DWORD),('usage',w.DWORD),('pid',w.DWORD),('heap',ctypes.c_size_t),
                    ('module',w.DWORD),('threads',w.DWORD),('parent',w.DWORD),('priority',w.LONG),
                    ('flags',w.DWORD),('exe',w.WCHAR*260)]
    api = identity._windows()
    api.CreateToolhelp32Snapshot.argtypes = [w.DWORD,w.DWORD]
    api.CreateToolhelp32Snapshot.restype = w.HANDLE
    api.Process32FirstW.argtypes = [w.HANDLE,ctypes.POINTER(Entry)]
    api.Process32NextW.argtypes = [w.HANDLE,ctypes.POINTER(Entry)]
    handle = api.CreateToolhelp32Snapshot(2,0)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError('Process snapshot unavailable')
    found = {}
    try:
        entry = Entry()
        entry.size = ctypes.sizeof(entry)
        ok = api.Process32FirstW(handle,ctypes.byref(entry))
        for _ in range(32768):
            if not ok:break
            if entry.exe.lower() in ('chrome.exe','msedge.exe'):
                found[entry.pid] = (entry.exe.lower(),entry.parent)
            ok = api.Process32NextW(handle,ctypes.byref(entry))
        else:raise OSError('Process inventory exceeds diagnostic bound')
    finally:
        api.CloseHandle(handle)
    chosen = {}
    for pid,(exe,parent) in found.items():
        if parent not in found and exe not in chosen:
            chosen[exe] = pid
    return chosen


def main():
    report = {'date':'2026-10-28','scope':'readonly_installed_image_and_live_process_identity_only',
              'attachment_capture_tested':False,'deployed_native_source':False,
              'browser_or_company_state_mutation':False,'installed_images':[],'live_processes':[]}
    for path,vendor in identity.machine_browser_paths().items():
        if not Path(path).is_file():continue
        row = {'browser':Path(path).name,'expected_publisher':vendor}
        start = time.perf_counter()
        try:
            row['publisher'] = identity.signed_publisher(path)
            row['signature_match'] = row['publisher'] == vendor
            identity.protected_browser_image(path)
            row['protected_path'] = True
        except OSError as exc:
            row.update(error_code=getattr(exc,'code',type(exc).__name__),native_code=getattr(exc,'native_code',None))
        row['check_ms'] = round((time.perf_counter()-start)*1000,3)
        report['installed_images'].append(row)
    api = identity._windows()
    api.GetCurrentProcess.restype = w.HANDLE
    own = api.GetCurrentProcess()
    _,_,session,_ = identity._snapshot(api,own)
    sid = identity._process_sid(own)
    for browser,pid in roots().items():
        row = {'browser':browser,'pid':pid}
        process = api.OpenProcess(0x1000 | 0x100000, False, pid)
        try:
            if not process:
                raise identity.IdentityError('process_unreadable')
            _,_,target_session,_ = identity._snapshot(api,process)
            target_sid = identity._process_sid(process)
            row['matches_diagnostic_scope'] = target_session == session and target_sid == sid
            # OS-read scope for this diagnostic only. A future production
            # source must bind expected scope to its authenticated transport.
            row['scope_source'] = 'readonly_os_snapshot_not_pipe_authentication'
            with identity.verify_browser(pid,session=target_session,sid=target_sid) as lease:
                row.update(verified_live_lease=lease.authenticated(),publisher=lease.identity.publisher,
                           process_created_filetime=lease.identity.created_filetime,session=lease.identity.session)
            row['lease_closed'] = lease.handle is None
        except OSError as exc:
            row.update(error_code=getattr(exc,'code',type(exc).__name__),native_code=getattr(exc,'native_code',None))
        finally:
            if process:api.CloseHandle(process)
        report['live_processes'].append(row)
    try:
        with identity.verify_browser(api.GetProcessId(own),session=session,sid=sid):
            report['python_rejected_as_browser'] = False
    except identity.IdentityError as exc:
        report['python_rejected_as_browser'] = exc.code == 'image_not_supported'
    helper = ROOT/'runtime/file-handoff-build/GuardDeskOwnedOleDrop.exe'
    if helper.is_file():
        try:
            identity.signed_publisher(helper)
            report['unsigned_helper_rejected'] = False
        except identity.IdentityError as exc:
            report['unsigned_helper_rejected'] = exc.code == 'signature_not_trusted'
            report['unsigned_helper_native_code'] = exc.native_code
    else:
        report['unsigned_helper_test'] = 'not_run_missing_fixture'
    report['source_sha256'] = hashlib.sha256((ROOT/'guarddesk/native_browser_identity.py').read_bytes()).hexdigest()
    destination = ROOT/'evidence/native-browser-identity-os-smoke-20261028.json'
    destination.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2))
    ok = report['installed_images'] and all(row.get('signature_match') and row.get('protected_path') for row in report['installed_images'])
    return 0 if ok and report['python_rejected_as_browser'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
