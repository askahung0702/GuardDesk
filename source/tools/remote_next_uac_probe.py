"""Owned real RunAs elevation probe. No endpoint config, images or keys saved.

Install an on-demand SYSTEM task only in a new protected probe directory;
no boot/logon trigger. A separately invoked prompt contains synthetic data,
is cancelled only after matching its nonce filename in Microsoft consent.exe.
This is a test-only successor; preserve the historical CredUI probe and bytes.
"""
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid

def active_session_check():
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.ProcessIdToSessionId.argtypes=[w.DWORD,ctypes.POINTER(w.DWORD)]
    session=w.DWORD()
    if not kernel.ProcessIdToSessionId(os.getpid(),ctypes.byref(session)):
        raise ctypes.WinError(ctypes.get_last_error())
    from guarddesk.document_context import session_states
    states=session_states();target=states.get(session.value,{})
    if (not session.value or not target.get('active') or target.get('locked')
        or target.get('query_failed') or target.get('logon',0)<=0 or any(s.get('query_failed') for s in states.values())
        or sum(bool(s.get('active') and not s.get('locked')) for s in states.values())!=1):
        raise PermissionError('A single active unlocked logged-on session is required')
    return session.value


def own_ui_context():
    """Own process/session/station only, no window inventory or titles."""
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);user=ctypes.WinDLL('user32',use_last_error=True)
    kernel.GetCurrentThreadId.restype=w.DWORD
    user.GetProcessWindowStation.restype=w.HANDLE
    user.GetThreadDesktop.argtypes=[w.DWORD];user.GetThreadDesktop.restype=w.HANDLE
    user.GetUserObjectInformationW.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
    def name(handle):
        value=ctypes.create_unicode_buffer(256);size=w.DWORD()
        if not user.GetUserObjectInformationW(handle,2,value,ctypes.sizeof(value),ctypes.byref(size)):
            return {'winerror':ctypes.get_last_error()}
        return value.value
    return dict(session=active_session_check(),station=name(user.GetProcessWindowStation()),
        desktop=name(user.GetThreadDesktop(kernel.GetCurrentThreadId())))


def interactive():
    # The operator opens this in their existing WTS session, including RDP.
    # Physical console ID is not evidence of the active user's desktop.
    session=active_session_check()
    if not getattr(sys,'frozen',False):raise PermissionError('Frozen owned probe only')
    from guarddesk.windows_controls import is_admin
    if is_admin():raise PermissionError('Open normally; only setup requests UAC')
    print('Approve SETUP only. The SECOND real UAC request is cancelled by the test. Do not approve it or enter credentials.',flush=True)
    class Info(ctypes.Structure):
        _fields_=[('cbSize',w.DWORD),('fMask',w.ULONG),('hwnd',w.HWND),('lpVerb',w.LPCWSTR),('lpFile',w.LPCWSTR),('lpParameters',w.LPCWSTR),('lpDirectory',w.LPCWSTR),('nShow',ctypes.c_int),('hInstApp',w.HINSTANCE),('lpIDList',w.LPVOID),('lpClass',w.LPCWSTR),('hkeyClass',w.HKEY),('dwHotKey',w.DWORD),('hIcon',w.HANDLE),('hProcess',w.HANDLE)]
    shell=ctypes.WinDLL('shell32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    shell.ShellExecuteExW.argtypes=[ctypes.POINTER(Info)];shell.ShellExecuteExW.restype=w.BOOL
    kernel.GetProcessId.argtypes=[w.HANDLE];kernel.GetProcessId.restype=w.DWORD
    kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];kernel.WaitForSingleObject.restype=w.DWORD
    kernel.CloseHandle.argtypes=[w.HANDLE]
    nonce=uuid.uuid4().hex
    info=Info();info.cbSize=ctypes.sizeof(info);info.fMask=0x40
    info.lpVerb='runas';info.lpFile=sys.executable;info.lpParameters='--setup '+nonce
    info.lpDirectory=str(Path(sys.executable).parent);info.nShow=0
    if not shell.ShellExecuteExW(ctypes.byref(info)):raise ctypes.WinError(ctypes.get_last_error())
    try:
        pid=kernel.GetProcessId(info.hProcess)
        if not pid:raise ctypes.WinError(ctypes.get_last_error())
        if kernel.WaitForSingleObject(info.hProcess,60000)!=0:raise TimeoutError('Setup still running; no prompt started')
    finally:kernel.CloseHandle(info.hProcess)
    from guarddesk.update_native import folder,protected_tree
    # Same protected location even when UAC uses another administrator account.
    root=root_path(str(folder(35)/'OwnedRemoteNextUacProbe'/('probe-'+nonce)))
    protected_tree(root,recursive=False)
    deadline=time.monotonic()+30
    while not (root/'ready.json').exists():
        if any((root/name).exists() for name in ('failure-broker.json','failure-worker.json','cleanup.json')):break
        if time.monotonic()>deadline:break
        time.sleep(.2)
    child=None;prompt_result={};prompt_diagnostics=[]
    if (root/'ready.json').exists():
        active_session_check()
        child=subprocess.Popen([sys.executable,'--prompt',str(root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            stdout,stderr=child.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            child.terminate();stdout,stderr=child.communicate(timeout=5)
            print('Owned prompt timed out; only its retained process was stopped.',flush=True)
        for line in stdout.decode('utf-8',errors='replace').splitlines()[:4]:
            print(line,flush=True)
            try:packet=json.loads(line)
            except ValueError:continue
            if not isinstance(packet,dict):continue
            if 'cancelled' in packet:prompt_result=packet
            else:prompt_diagnostics.append(packet)
    deadline=time.monotonic()+110
    while not (root/'cleanup.json').exists() and time.monotonic()<deadline:time.sleep(.5)
    report={'test_kind':'remote_next_component_real_runas_not_MIS_acceptance','session':session,'root':str(root),'company_agent_changed':False,'prompt':prompt_result,'prompt_diagnostics':prompt_diagnostics,'reports':{}}
    for name in ('ready','result','cleanup','failure-broker','failure-worker'):
        p=root/(name+'.json')
        if p.exists():report['reports'][name]=json.loads(p.read_text(encoding='utf-8'))
    report['passed']=bool(report['reports'].get('result',{}).get('passed') and prompt_result.get('cancelled')
        and report['reports'].get('cleanup',{}).get('task_deleted'))
    out=Path(sys.executable).parent.parent/('uac-console-result-'+root.name[6:]+'.json')
    out.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('Result: '+str(out),flush=True)
    if not report['reports'].get('cleanup',{}).get('task_deleted'):raise OSError('Task cleanup not confirmed; retain exact test root')
    if not report['passed']:raise OSError('Real UAC probe did not pass; retain result. If the SECOND UAC remains visible, cancel it manually.')

def record(root,name,value):
    target=root/(name+'.json')
    target.write_text(json.dumps(value,indent=2),encoding='utf-8')
    from guarddesk.context_permissions import grant_read_execute
    grant_read_execute(target)

def root_path(value):
    p=Path(value)
    from guarddesk.update_native import folder
    base=folder(35)/'OwnedRemoteNextUacProbe'
    if p.parent!=base or not re.fullmatch('probe-[0-9a-f]{32}',p.name):raise PermissionError('Owned probe path only')
    return p


def cleanup_first_attempt():
    """Remove only the exact on-demand task from this turn's failed v1 test.

    No process-by-name kill, product task, directory deletion or ACL change.
    The fixed, protected setup manifest and copied executable must both match.
    """
    from guarddesk.update_native import folder,protected_tree,system_tool
    nonce='ca79e986ff3a4dac854f315cc8f581cc'
    root=folder(35)/'OwnedRemoteNextUacProbe'/('probe-'+nonce)
    if not root.exists():return {'previous_test':'absent'}
    protected_tree(root,recursive=False)
    name='GuardDesk-Owned-RemoteNext-UAC-Probe-'+nonce
    setup=json.loads((root/'setup.json').read_text(encoding='utf-8'))
    exe=root/'runtime/GuardDeskUacProbe.exe';protected_tree(exe,recursive=False)
    expected='09059a4c7ee90a57f8da0155a6313f455d9d2b0681c09add9142ab1b16555ec3'
    if setup.get('task')!=name or hashlib.sha256(exe.read_bytes()).hexdigest()!=expected:
        raise PermissionError('Previous owned test identity mismatch; preserve it')
    for action,extra in (('/End',[]),('/Delete',['/F'])):
        subprocess.run([system_tool('schtasks.exe'),action,'/TN',name,*extra],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
    query=subprocess.run([system_tool('schtasks.exe'),'/Query','/TN',name,'/XML'],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
    if query.returncode==0:raise OSError('Previous owned test task remains; preserve reports')
    return {'previous_test':nonce,'fixed_task_no_longer_queryable':True,'files_preserved':True}

def setup(nonce):
    from guarddesk.windows_controls import is_admin
    from guarddesk.update_native import folder,protected_tree
    from guarddesk.native_installer import Windows
    if not is_admin():raise PermissionError('Owned probe setup requires UAC')
    if not re.fullmatch('[0-9a-f]{32}',nonce):raise ValueError('Invalid probe nonce')
    active_session_check()
    source=Path(sys.executable).parent
    if source.name!='GuardDeskUacProbe' or not getattr(sys,'frozen',False):raise PermissionError('Frozen owned probe only')
    win=Windows();base=folder(35)/'OwnedRemoteNextUacProbe'
    if not folder(35).exists():win.protect(folder(35),create=True)
    win.protect(base,create=True);root=base/('probe-'+nonce)
    if root.exists():raise PermissionError('Never reuse an existing probe root')
    win.protect(root,create=True)
    record(root,'previous-cleanup',cleanup_first_attempt())
    runtime=root/'runtime';win.protect(runtime,create=True)
    hashes={}
    for path in source.rglob('*'):
        if path.is_symlink() or path.stat().st_file_attributes&0x400:raise PermissionError('Probe reparse refused')
        target=runtime/path.relative_to(source)
        if path.is_dir():win.protect(target,create=True)
        else:
            data=path.read_bytes();win.write(target,data)
            digest=hashlib.sha256(data).hexdigest()
            if hashlib.sha256(target.read_bytes()).hexdigest()!=digest:raise OSError('Probe copy mismatch')
            hashes[str(path.relative_to(source))]=digest
    protected_tree(runtime)
    # Stable, protected bytes, unique basename visibly identifying this request.
    # No disguised name, injected code or security-policy changes.
    target=runtime/('GuardDesk-UAC-'+root.name[6:]+'.exe')
    win.write(target,(runtime/'GuardDeskUacProbe.exe').read_bytes())
    hashes[target.name]=hashlib.sha256(target.read_bytes()).hexdigest()
    from guarddesk.context_permissions import grant_read_execute
    for entry in (runtime,*runtime.rglob('*')):grant_read_execute(entry)
    protected_tree(runtime)
    name='GuardDesk-Owned-RemoteNext-UAC-Probe-'+root.name[6:]
    from xml.sax.saxutils import escape
    exe=runtime/'GuardDeskUacProbe.exe'
    args=subprocess.list2cmdline(['--broker',str(root)])
    xml=('<?xml version="1.0" encoding="UTF-16"?><Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
      '<RegistrationInfo><Description>GuardDesk owned UAC test; on-demand only; no credentials retained</Description></RegistrationInfo>'
      '<Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
      '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT4M</ExecutionTimeLimit><Hidden>false</Hidden><Priority>4</Priority></Settings>'
      '<Actions Context="System"><Exec><Command>'+escape(str(exe))+'</Command><Arguments>'+escape(args)+'</Arguments><WorkingDirectory>'+escape(str(runtime))+'</WorkingDirectory></Exec></Actions></Task>')
    win.register(name,xml.encode('utf-16'),root)
    record(root,'setup',dict(task=name,hashes=hashes,created=time.time(),no_trigger=True,task_priority=4))
    # Standard user can read scalar reports but cannot alter protected inputs.
    from guarddesk.context_permissions import grant_read_execute
    grant_read_execute(root)
    win.start(name)

def broker(root):
    from guarddesk.remote_admin_windows import identity,spawn_system_session
    from guarddesk.document_context import session_states
    from guarddesk.update_native import protected_tree
    api,_=identity();protected_tree(root);child=None
    try:
        states=session_states();active=[(sid,s) for sid,s in states.items() if s.get('active') and not s.get('locked') and not s.get('query_failed')]
        if len(active)!=1:raise OSError('Single unlocked probe session required')
        sid,state=active[0]
        record(root,'launch',dict(session=sid,logon=state['logon'],parent=os.getpid(),started=time.time(),expires=time.time()+90))
        child=spawn_system_session(Path(sys.executable),['--worker',str(root)],sid)
        api.WaitForSingleObject(child.handle,90000)
    finally:
        if child:
            if child.alive():
                api.TerminateProcess.argtypes=[w.HANDLE,w.UINT]
                api.TerminateProcess(child.handle,0);api.WaitForSingleObject(child.handle,3000)
            child.close()
        from guarddesk.native_installer import Windows
        name='GuardDesk-Owned-RemoteNext-UAC-Probe-'+root.name[6:]
        Windows().delete(name)
        record(root,'cleanup',dict(task_deleted=True,task=name,owned_process_stopped=True))

def worker(root):
    from guarddesk.remote_admin_windows import identity,Desktop,DesktopTransition,CONTROL_DESKTOP_ACCESS
    from guarddesk.remote_windows import capture_bgr,Input
    from guarddesk.native_browser_identity import _windows
    api,own=identity();lease=json.loads((root/'launch.json').read_text())
    if own[2]!=lease['session']:raise OSError('Probe target session mismatch')
    handle=api.OpenProcess(0x1000|0x100000,False,lease['parent'])
    if not handle:raise ctypes.WinError(ctypes.get_last_error())
    desktop=Desktop(lease,lambda:api.WaitForSingleObject(handle,0)==258)
    result={'authorization_source':'owned_test_timer_not_center','MIS_end_to_end_acceptance':False,'system':True,'target_session':own[2],'default_before':False,'secure_capture':False,'secure_cancel_input':False,'default_after':False,'images_saved':False,'credentials_collected':False,
        'own_ui_context':own_ui_context(),'transition_waits':0,'transition_winerrors':{}}
    # Access check only: do not switch desktops, capture, or send input here.
    desktop.api.OpenDesktopW.argtypes=[w.LPCWSTR,w.DWORD,w.BOOL,w.DWORD];desktop.api.OpenDesktopW.restype=w.HANDLE
    secure_handle=desktop.api.OpenDesktopW('Winlogon',0,False,CONTROL_DESKTOP_ACCESS)
    result['winlogon_access_check']={'opened':bool(secure_handle),'winerror':0 if secure_handle else ctypes.get_last_error(),'requested_access':CONTROL_DESKTOP_ACCESS}
    if secure_handle:desktop.api.CloseDesktop(secure_handle)
    proof={}
    def owned_guard():
        desktop.guard()
        if desktop.name!='winlogon':raise PermissionError('Owned UAC is not on secure desktop')
        current=foreground_identity(desktop.api,lease,verify_signature=False)
        from tools.uac_prompt_identity import guard_proof
        if not guard_proof(proof,**current,now=time.time()):raise PermissionError('Owned UAC changed or proof expired')
        return True
    inputs=Input(guard=owned_guard,release_guard=desktop.release_guard,epoch=lambda:desktop.epoch);start=time.monotonic();secure_seen=False
    try:
        while time.monotonic()-start<80:
            try:
                ctypes.set_last_error(0);desktop.authorize();desktop.select()
                if desktop.name=='default' and not secure_seen:
                    if not result['default_before']:
                        result['default_before']=True;record(root,'ready',dict(ready=True,session=own[2]))
                        from guarddesk.context_permissions import grant_read_execute
                        grant_read_execute(root/'ready.json')
                elif desktop.name=='winlogon' and not secure_seen:
                    # Pause briefly so the real Windows prompt can paint.
                    time.sleep(.7);desktop.guard()
                    # UIA runs in a disposable child because COM can create
                    # windows and block future SetThreadDesktop on this thread.
                    try:
                        check=subprocess.run([sys.executable,'--identify',str(root)],capture_output=True,timeout=5,creationflags=subprocess.CREATE_NO_WINDOW)
                        proof=json.loads(check.stdout.decode('utf-8')) if check.returncode==0 else {}
                        result['identity_exit']=check.returncode
                    except (subprocess.TimeoutExpired,ValueError):
                        proof={};result['identity_timeout_or_invalid']=True
                    if not proof.get('matched'):
                        result['foreign_or_unidentified_secure_prompt_refused']=True
                        result['identity_reason']=proof.get('reason','identity_child_failed');break
                    owned_guard()
                    width,height,stride,raw=capture_bgr(320,180,_desktop_guard=owned_guard)
                    result['secure_capture']=len(raw)==stride*height and len(set(raw))>8
                    result['capture_size']=[width,height];del raw
                    # Escape is the only synthesized key. No password/username.
                    for down in (True,False):inputs.send(dict(type='key',key=27,down=down))
                    result['secure_cancel_input']=True;secure_seen=True
                elif secure_seen and desktop.name=='default':
                    result['default_after']=True;break
            except DesktopTransition:
                error=str(ctypes.get_last_error());result['transition_waits']+=1
                if len(result['transition_winerrors'])<8 or error in result['transition_winerrors']:
                    result['transition_winerrors'][error]=result['transition_winerrors'].get(error,0)+1
            time.sleep(.1)
    finally:
        inputs.release();desktop.close();api.CloseHandle(handle)
        result['passed']=all(result[k] for k in ('system','default_before','secure_capture','secure_cancel_input','default_after'))
        record(root,'result',result)
        from guarddesk.context_permissions import grant_read_execute
        for name in ('result','ready','launch'):grant_read_execute(root/(name+'.json'))

def foreground_identity(user,lease,verify_signature=True):
    from guarddesk.native_browser_identity import _windows,_snapshot,signed_publisher
    api=_windows();user.GetForegroundWindow.restype=w.HWND
    user.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
    hwnd=user.GetForegroundWindow();pid=w.DWORD()
    if not hwnd or not user.GetWindowThreadProcessId(hwnd,ctypes.byref(pid)):raise PermissionError('No UAC foreground')
    handle=api.OpenProcess(0x1000|0x100000,False,pid.value)
    if not handle:raise ctypes.WinError(ctypes.get_last_error())
    try:
        actual_pid,created,session,image=_snapshot(api,handle)
        api.GetSystemDirectoryW.argtypes=[w.LPWSTR,w.UINT]
        buffer=ctypes.create_unicode_buffer(32768)
        if not api.GetSystemDirectoryW(buffer,len(buffer)):raise ctypes.WinError(ctypes.get_last_error())
        expected=Path(buffer.value)/'consent.exe'
        if Path(image)!=expected or session!=lease['session'] or created/1e7-11644473600<lease['started']:
            raise PermissionError('Foreground is not this new consent process')
        if verify_signature and signed_publisher(expected)!='Microsoft Corporation':raise PermissionError('Consent signature mismatch')
        return dict(hwnd=hwnd,pid=actual_pid,created=created,session=session)
    finally:api.CloseHandle(handle)

def identify(root):
    from guarddesk.remote_admin_windows import identity,Desktop
    from guarddesk.update_native import protected_tree
    from tools.uac_prompt_identity import exact_label
    identity();protected_tree(root,recursive=False)
    lease=json.loads((root/'launch.json').read_text());desktop=Desktop(lease)
    # This disposable process makes no further desktop switches after COM starts.
    desktop.authorize();desktop.select()
    if desktop.name!='winlogon':raise PermissionError('No secure desktop')
    before=foreground_identity(desktop.api,lease)
    matched=exact_label(before['hwnd'],'GuardDesk-UAC-'+root.name[6:]+'.exe',before['pid'])
    desktop.guard();after=foreground_identity(desktop.api,lease,verify_signature=False)
    print(json.dumps(dict(**before,matched=bool(matched and before==after),checked_at=time.time(),reason='matched' if matched else 'nonce_label_unavailable')),flush=True)

def prompt(root):
    from guarddesk.windows_controls import is_admin
    from guarddesk.update_native import protected_tree
    if is_admin():raise PermissionError('Real RunAs requester must be unelevated')
    ready=json.loads((root/'ready.json').read_text())
    if not ready.get('ready') or ready['session']!=active_session_check():raise PermissionError('Worker not ready in this session')
    target=root/'runtime'/('GuardDesk-UAC-'+root.name[6:]+'.exe')
    protected_tree(target,recursive=False)
    print(json.dumps(dict(prompt_api_entering=True,api='ShellExecuteW:runas',worker_ready=True)),flush=True)
    shell=ctypes.WinDLL('shell32',use_last_error=True)
    shell.ShellExecuteW.argtypes=[w.HWND,w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,ctypes.c_int];shell.ShellExecuteW.restype=ctypes.c_ssize_t
    ctypes.set_last_error(0)
    result=shell.ShellExecuteW(None,'runas',str(target),'--elevation-target',str(target.parent),0)
    error=ctypes.get_last_error() if result<=32 else 0
    print(json.dumps(dict(cancelled=result<=32 and error==1223,code=error,unexpectedly_approved=result>32,credentials_unpacked=False)),flush=True)

def main():
    try:
        if sys.argv[1:]==['--check']:print(json.dumps(dict(active_session=active_session_check(),check_only=True)))
        elif sys.argv[1:]==['--interactive']:interactive()
        elif len(sys.argv)==3 and sys.argv[1]=='--setup':setup(sys.argv[2])
        elif len(sys.argv)==3 and sys.argv[1]=='--prompt':prompt(root_path(sys.argv[2]))
        elif len(sys.argv)==3 and sys.argv[1]=='--identify':identify(root_path(sys.argv[2]))
        elif sys.argv[1:]==['--elevation-target']:
            # An accidentally approved request does no work and exits immediately.
            print('Owned UAC target: no operation performed',flush=True)
        elif len(sys.argv)==3 and sys.argv[1] in ('--broker','--worker'):
            root=root_path(sys.argv[2]);(broker if sys.argv[1]=='--broker' else worker)(root)
        else:raise ValueError('Fixed owned test mode required')
    except BaseException as exc:
        if len(sys.argv)==3 and sys.argv[1] in ('--broker','--worker'):
            root=root_path(sys.argv[2]);record(root,'failure-'+sys.argv[1][2:],dict(type=type(exc).__name__,winerror=getattr(exc,'winerror',None),input_size=getattr(exc,'input_size',None),accepted=getattr(exc,'accepted',None),message=str(exc)[:180],
                frames=[dict(file=Path(f.filename).name,function=f.name,line=f.lineno) for f in traceback.extract_tb(exc.__traceback__)[-8:]]))
        elif len(sys.argv)==3 and sys.argv[1]=='--identify':
            print(json.dumps(dict(matched=False,reason=type(exc).__name__,winerror=getattr(exc,'winerror',None))),flush=True)
        else:print(type(exc).__name__+': '+str(exc)[:180],flush=True)
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
