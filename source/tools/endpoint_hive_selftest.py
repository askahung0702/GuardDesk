"""Elevated AIO-only acceptance on new owned registry keys/hive files.

Never opens an installed Agent or a real user's NTUSER.DAT. Tests precisely
the frozen cleanup Registry implementation, including a mixed-DACL hive.
"""
import ctypes,json,os,sys,uuid,winreg
from pathlib import Path
from ctypes import wintypes as w
from tools.endpoint_fresh_cleanup import Registry,Files
from tools.endpoint_agent_reset import ResetRegistry
from tools.endpoint_registry_hive import existing_registry_privileges

def security(key):
    api=ctypes.WinDLL('advapi32',use_last_error=True)
    api.RegGetKeySecurity.argtypes=[w.HANDLE,w.DWORD,w.LPVOID,ctypes.POINTER(w.DWORD)];api.RegGetKeySecurity.restype=w.LONG
    size=w.DWORD();code=api.RegGetKeySecurity(w.HANDLE(int(key)),4,None,ctypes.byref(size))
    if code!=122:raise ctypes.WinError(code)
    buffer=ctypes.create_string_buffer(size.value);code=api.RegGetKeySecurity(w.HANDLE(int(key)),4,buffer,ctypes.byref(size))
    if code:raise ctypes.WinError(code)
    return buffer.raw[:size.value]

def different_dacl(key):
    api=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,ctypes.POINTER(w.LPVOID),ctypes.POINTER(w.DWORD)];api.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=w.BOOL
    api.RegSetKeySecurity.argtypes=[w.HANDLE,w.DWORD,w.LPVOID];api.RegSetKeySecurity.restype=w.LONG
    kernel.LocalFree.argtypes=[w.LPVOID];sd=w.LPVOID()
    if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW('D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)',1,ctypes.byref(sd),None):raise ctypes.WinError(ctypes.get_last_error())
    try:
        code=api.RegSetKeySecurity(w.HANDLE(int(key)),4,sd)
        if code:raise ctypes.WinError(code)
    finally:kernel.LocalFree(sd)

def mounts():
    result=set();count=winreg.QueryInfoKey(winreg.HKEY_USERS)[0]
    for i in range(count):
        name=winreg.EnumKey(winreg.HKEY_USERS,i)
        if name.startswith('GuardDesk-Cleanup-'):result.add(name)
    return result

def run(folder,report):
    keyname='Software\\GuardDeskOwnedHiveTest\\'+uuid.uuid4().hex
    client=folder/'GuardDeskPilotClient';client.mkdir();hive=folder/'NTUSER.DAT'
    before=mounts();cases=[];report['cases']=cases
    # Save a valid Windows registry tree with differing per-key security.
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,keyname,0,winreg.KEY_ALL_ACCESS) as root:
        with winreg.CreateKeyEx(root,'UnrelatedOwnedFixture',0,winreg.KEY_ALL_ACCESS) as node:
            winreg.SetValueEx(node,'keep',0,winreg.REG_SZ,'KEEP');different_dacl(node);expected_sd=security(node)
        assert security(root)!=expected_sd,'fixture DACLs must differ'
        with winreg.CreateKey(root,r'Software\GuardDesk') as node:winreg.SetValueEx(node,'AgentConfig',0,winreg.REG_SZ,str(client/'runtime/agent/config.json'))
        with existing_registry_privileges():winreg.SaveKey(root,str(hive))
    report['owned_registry_fixture']=keyname
    cases.append('valid hive saved with different key DACLs')
    adv=ctypes.WinDLL('advapi32',use_last_error=True)
    adv.RegLoadAppKeyW.argtypes=[w.LPCWSTR,ctypes.POINTER(w.HANDLE),w.DWORD,w.DWORD,w.DWORD];adv.RegLoadAppKeyW.restype=w.LONG
    handle=w.HANDLE();code=adv.RegLoadAppKeyW(str(hive),ctypes.byref(handle),winreg.KEY_READ|winreg.KEY_WRITE,1,0)
    if code==0:winreg.CloseKey(handle.value)
    report['old_application_hive_api_code']=code
    # This is an observation, not a precondition for testing the replacement.
    # AIO fixture 002 returned success, disproving the assumption that different
    # DACLs alone necessarily reproduce LAB01's 1009 on this Windows build.
    report['field_1009_reproduced']=(code==1009)
    report['field_root_cause_confirmed']=False
    report['stage']='new_user_hive_load_and_exact_cleanup'
    registry=Registry();reset=ResetRegistry()
    registry.hive_journal=folder/'registry-mounts.json'
    with registry.offline_hive(hive) as root:
        with winreg.OpenKey(root,'UnrelatedOwnedFixture') as key:
            assert winreg.QueryValueEx(key,'keep')[0]=='KEEP';assert security(key)==expected_sd
        changes=reset.changes_all(root,client,{'preserved_external_registry':[]});assert len(changes)==1
        reset.apply(root,changes)
    assert mounts()==before
    cases.append('new user-hive API loads, cleans only GuardDesk pointer, unloads its own mount')
    report['stage']='reopen_and_preservation'
    with registry.offline_hive(hive) as root:
        with winreg.OpenKey(root,r'Software\GuardDesk') as key:
            try:winreg.QueryValueEx(key,'AgentConfig')
            except FileNotFoundError:pass
            else:raise AssertionError('GuardDesk value remained')
        with winreg.OpenKey(root,'UnrelatedOwnedFixture') as key:
            assert winreg.QueryValueEx(key,'keep')[0]=='KEEP';assert security(key)==expected_sd
    cases.append('reopen verifies persistence and unrelated value/DACL unchanged')
    report['stage']='exception_unload'
    try:
        with registry.offline_hive(hive):raise ValueError('owned injected exception')
    except ValueError:pass
    assert mounts()==before
    cases.append('exception closes key and unloads temporary mount')
    report['stage']='external_data_lock'
    with Files().handle(hive):
        try:
            with registry.offline_hive(hive):raise AssertionError('external data lock bypassed')
        except OSError as exc:assert exc.winerror==32
    assert mounts()==before;cases.append('real data lock remains refused')
    report['stage']='invalid_hive'
    corrupt=folder/'owned-corrupt.dat';corrupt.write_bytes(b'owned invalid hive')
    try:
        with registry.offline_hive(corrupt):raise AssertionError('invalid hive accepted')
    except OSError as exc:report['genuinely_invalid_hive_code']=exc.winerror
    assert mounts()==before;cases.append('genuinely invalid fixture rejected with no leftover mount')
    # Only delete the known keys created above, never enumerate/delete company data.
    report['stage']='owned_fixture_cleanup'
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,keyname,0,winreg.KEY_ALL_ACCESS) as root:
        winreg.DeleteKey(root,r'Software\GuardDesk');winreg.DeleteKey(root,'Software');winreg.DeleteKey(root,'UnrelatedOwnedFixture')
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER,keyname)
    cases.append('owned registry fixture removed; own hive files retained as evidence')
    report['stage']='owned_fixture_complete_field_acceptance_pending'

def main():
    from guarddesk.windows_privilege import is_admin
    if os.environ.get('COMPUTERNAME','').upper()!='DEV-01':print('DEV_01_OWNED_TEST_ONLY');return 4
    if not is_admin():print('ADMIN_REQUIRED_FOR_OWNED_USER_HIVE_TEST');return 3
    from guarddesk.endpoint_files import secure_directory
    root=Path(sys.executable).parent;folder=root/('Owned-Hive-Test-'+uuid.uuid4().hex);secure_directory(folder)
    report={'format':1,'tool':'GuardDesk owned mixed-security user-hive acceptance','result':'REVIEW_REQUIRED','company_hives_accessed':False,'Agent_changed':False,'Defender_changed':False,'fixture':str(folder)}
    try:run(folder,report);report['result']='OWNED_USER_HIVE_TEST_PASSED'
    except BaseException as exc:report.update(error_type=type(exc).__name__,winerror=getattr(exc,'winerror',None),message=str(exc)[:700])
    path=root/('Owned-Hive-Test-'+uuid.uuid4().hex+'.json');path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Result='+report['result']);print('Report='+str(path));return 0 if report['result']=='OWNED_USER_HIVE_TEST_PASSED' else 1
