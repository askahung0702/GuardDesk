"""Protected, fixed-root handoff to the universal no-backup removal engine.

Only the installed worker can prepare a job. The independent scheduled worker
uses a job-only callback secret; no endpoint credential is copied. Interrupted
deletion is reported for review, never automatically replayed after reboot.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
import xml.etree.ElementTree as ET
from .protected_files import ProtectedFiles, read_json, encode, assert_quiescent
from .update_native import folder, protected_tree

def job_root(jid):
    if not isinstance(jid,str) or not re.fullmatch('[0-9a-f]{32}',jid):raise ValueError('INVALID_REMOVAL_JOB')
    return folder(35).parent/'GuardDeskRemovalJobs'/jid

def task_name(jid):
    job_root(jid)
    return 'GuardDesk-Removal-'+jid

def task_body(executable,jid):
    from .native_installer import task_body as template,NS
    root=ET.fromstring(template(executable,executable,'updater'));ns={'t':NS}
    root.find('t:Actions/t:Exec/t:Arguments',ns).text='endpoint-remove-job --job-id '+jid
    root.find('t:RegistrationInfo/t:Description',ns).text='GuardDesk authorized complete Agent removal and result delivery'
    settings=root.find('t:Settings',ns)
    settings.find('t:ExecutionTimeLimit',ns).text='PT30M'
    settings.remove(settings.find('t:RestartOnFailure',ns))
    return ET.tostring(root,encoding='utf-16',xml_declaration=True)

def verify_task(raw,executable,jid):
    from .decommission import parse_task_xml
    from .native_installer import NS
    root=parse_task_xml(raw);ns={'t':NS};actions=root.find('t:Actions',ns)
    if actions is None or len(actions)!=1 or actions[0].tag!='{'+NS+'}Exec':raise PermissionError('REMOVAL_TASK_ACTION_MISMATCH')
    principal=root.find('t:Principals',ns)
    if principal is None or len(principal)!=1:raise PermissionError('REMOVAL_TASK_PRINCIPAL_MISMATCH')
    if principal[0].findtext('t:UserId',namespaces=ns) not in ('S-1-5-18','SYSTEM') or principal[0].findtext('t:RunLevel',namespaces=ns)!='HighestAvailable':raise PermissionError('REMOVAL_TASK_IDENTITY_MISMATCH')
    values=[actions[0].findtext('t:'+k,namespaces=ns) for k in ('Command','Arguments','WorkingDirectory')]
    if values!=[str(executable),'endpoint-remove-job --job-id '+jid,str(executable.parent)]:raise PermissionError('REMOVAL_TASK_COMMAND_MISMATCH')

def require_system():
    from ctypes import wintypes as w
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);adv=ctypes.WinDLL('advapi32',use_last_error=True)
    kernel.GetCurrentProcess.restype=w.HANDLE;kernel.CloseHandle.argtypes=[w.HANDLE]
    adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)];adv.OpenProcessToken.restype=w.BOOL
    adv.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)];adv.GetTokenInformation.restype=w.BOOL
    adv.IsWellKnownSid.argtypes=[w.LPVOID,ctypes.c_int];adv.IsWellKnownSid.restype=w.BOOL
    token=w.HANDLE();size=w.DWORD()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(),8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
    try:
        adv.GetTokenInformation(token,1,None,0,ctypes.byref(size))
        if not 0<size.value<=4096:raise PermissionError('INVALID_SYSTEM_TOKEN')
        data=ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token,1,data,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        if not adv.IsWellKnownSid(ctypes.cast(data,ctypes.POINTER(w.LPVOID))[0],22):raise PermissionError('REMOVAL_REQUIRES_SYSTEM')
    finally:kernel.CloseHandle(token)

def copy_program(source,target,files):
    from .native_installer import bounded_hash
    from .update_packages import plain,MAX_TOTAL
    from tools.endpoint_fresh_cleanup import io_path
    total=0
    for name,digest in sorted(files.items()):
        origin=plain(source/name);destination=plain(target/name)
        destination.parent.mkdir(parents=True,exist_ok=True)
        with open(io_path(destination),'xb') as output:
            actual,size=bounded_hash(origin,MAX_TOTAL-total,output)
        total+=size
        if actual!=digest:raise OSError('REMOVAL_RUNTIME_CHANGED')
    protected_tree(target)

def check_identity(state,config,marker,version,ca_hash):
    if (not marker or config.get('device_id')!=state['device_id'] or config.get('server')!=state['server']
        or marker.get('device_id')!=state['device_id'] or marker.get('server')!=state['server']
        or marker.get('version')!=version or marker.get('ca_sha256')!=ca_hash):
        raise PermissionError('REMOVAL_IDENTITY_OR_VERSION_CHANGED')

def prepare(worker,job):
    if job.get('cleanup',{}).get('phase') in ('complete','review_required'):return
    require_system()
    agent=worker.agent;did=agent.config['device_id'];jid=job['id'];root=job_root(jid)
    expected=folder(35)/'USBControl'/did/'config.json';source=folder(38)/'USBControl'
    if (not re.fullmatch('[0-9a-f]{24}',did) or agent.config_path!=expected
        or not getattr(sys,'frozen',False) or Path(sys.executable)!=source/'GuardDesk.exe'):
        raise PermissionError('REMOVAL_INSTALLED_WORKER_REQUIRED')
    from .single_instance import machine_instance
    from .native_installer import Windows,source_files
    with machine_instance('native-installer-machine','all-devices'):
        protected_tree(source);protected_tree(expected.parent)
        assert_quiescent(expected.parent)
        if agent.config.get('proxy_enabled') or (expected.parent/'windows/installed.json').exists():
            raise OSError('LEGACY_CONTROL_RESTORE_REQUIRED')
        io=Windows();io.protect(root.parent,create=True);io.protect(root,create=True)
        state_path=root/'handoff.json'
        if state_path.exists():
            state=read_json(state_path)
            if state.get('device_id')!=did or state.get('job_id')!=jid:raise PermissionError('REMOVAL_HANDOFF_IDENTITY_MISMATCH')
            if state.get('launched'):return
        else:
            files,_=source_files(source)
            program=root/'program';io.protect(program,create=True)
            if any(program.iterdir()):raise OSError('INCOMPLETE_REMOVAL_STAGING_PRESERVED')
            copy_program(source,program,files)
            ca=agent.config.get('ca')
            if ca:
                ca_path=Path(ca);protected_tree(ca_path,recursive=False)
                with ca_path.open('rb') as f:raw=f.read(65537)
                if len(raw)>65536:raise ValueError('REMOVAL_CA_TOO_LARGE')
                io.write(root/'center-ca.pem',raw)
            from urllib.parse import urlsplit
            url=agent.config['server'];parts=urlsplit(url)
            if parts.scheme!='https' or not parts.hostname or parts.username or parts.password:raise ValueError('REMOVAL_HTTPS_REQUIRED')
            state={'format':1,'job_id':jid,'device_id':did,'server':url,'secret':secrets.token_hex(32),
                   'ca':bool(ca),'restored':False,'launched':False,'phase':'prepared'}
            io.write(state_path,encode(state))
        # The center acknowledges the job-only secret before any destructive work.
        agent.call('/api/agent/uninstall/prepare-files',{'job_id':jid,'secret':state['secret']})
        try:
            if not state['restored']:
                companion=getattr(worker,'extended_companion',None)
                if companion:companion.close()
                from .application_control import ExtendedWorker
                outcome=ExtendedWorker(agent).restore();usb=worker.restore()
                for result in (outcome,usb):
                    if isinstance(result,dict) and result.get('status') in ('failed','conflict','partial_or_failed'):raise OSError('CONTROL_RESTORE_INCOMPLETE')
                state['restored']=True;io.write(state_path,encode(state))
            exe=root/'program/GuardDesk.exe';name=task_name(jid)
            if '\\'+name in io.names():verify_task(io.query(name),exe,jid)
            else:io.register(name,task_body(exe,jid),root)
            verify_task(io.query(name),exe,jid)
            state['launched']=True;io.write(state_path,encode(state))
        except (OSError,ValueError) as exc:
            # Keep the exact local error; center receives only bounded codes.
            io.write(root/'prepare-error.json',encode({'type':type(exc).__name__,'winerror':getattr(exc,'winerror',None),'message':str(exc)[:700]}))
            call(state,root,{'phase':'review_required','error_code':'PREPARE_OR_RESTORE_FAILED','winerror':getattr(exc,'winerror',None)})
            raise
    # The child takes the SAME installer exclusion. Release it before starting
    # the scheduled process, rather than racing its frozen-runtime startup.
    try:io.start(name)
    except OSError as exc:
        call(state,root,{'phase':'review_required','error_code':'CLEANUP_TASK_START_FAILED','winerror':getattr(exc,'winerror',None)})
        raise

def call(state,root,body):
    from .agent import request
    return request(state['server'],'/api/removal-result',{'job_id':state['job_id'],**body},state['secret'],
                   str(root/'center-ca.pem') if state['ca'] else None,timeout=10)

def cleaned_platform(did,on_stopped):
    from tools.endpoint_remove_direct import Windows,control_changes
    class Platform(Windows):
        def quiesce(self,tasks,report):
            super().quiesce(tasks,report)
            on_stopped()
        def check_control_changes(self,profiles,report):
            # Only the current protected identity was restored by the parent.
            # All other machine identities and user-owned ledgers keep the
            # universal tool's refusal contract, rather than guessing baselines.
            control_changes(self,profiles,report,restored_root=self.data/'USBControl'/did)
    return Platform()

def execute_job(state,load_result,save_result,authorize,remove,post):
    """Deterministic state machine; adapters are explicit OS/network boundaries."""
    previous=load_result()
    if previous is not None:
        if previous.get('phase')=='deleting':
            previous={'phase':'review_required','error_code':'INTERRUPTED_REMOVAL_REVIEW_REQUIRED','winerror':None}
            save_result(previous)
        post(previous);return previous
    if not state.get('restored'):raise PermissionError('CONTROL_RESTORE_NOT_CONFIRMED')
    if authorize().get('authorized') is not True:raise PermissionError('REMOVAL_NOT_AUTHORIZED')
    starting={'phase':'deleting','error_code':'','winerror':None}
    # Persist before stopping anything. A power failure never auto-replays deletion.
    save_result(starting)
    try:
        report=remove()
        if report.get('result')!='AGENT_REMOVED_NO_BACKUP':raise OSError('REMOVAL_INCOMPLETE')
        final={'phase':'complete','error_code':'','winerror':None,'helper_cleanup':'not_scheduled'}
    except Exception as exc:
        final={'phase':'review_required','error_code':'CLEANUP_FAILED','winerror':getattr(exc,'winerror',None)}
    save_result(final);post(final);return final

def schedule_program_cleanup(root):
    """Only our private staged runtime, never Agent roots or arbitrary paths."""
    from .update_packages import plain
    require_system();program=plain(root/'program');protected_tree(program)
    paths=list(program.rglob('*'))
    if len(paths)>20000:raise ValueError('REMOVAL_HELPER_FILE_LIMIT')
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.MoveFileExW.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32];kernel.MoveFileExW.restype=ctypes.c_int
    from tools.endpoint_fresh_cleanup import io_path
    for path in sorted(paths,key=lambda p:len(p.parts),reverse=True)+[program]:
        plain(path)
        if not kernel.MoveFileExW(io_path(path),None,4):raise ctypes.WinError(ctypes.get_last_error())

def run(jid):
    require_system();root=job_root(jid);exe=root/'program/GuardDesk.exe'
    if not getattr(sys,'frozen',False) or Path(sys.executable)!=exe:raise PermissionError('REMOVAL_STAGED_RUNTIME_REQUIRED')
    for path in (root.parent,root,root/'handoff.json'):protected_tree(path,recursive=False)
    from .native_installer import source_files,Windows
    source_files(exe.parent);protected_tree(exe.parent)
    state=read_json(root/'handoff.json')
    if state.get('job_id')!=jid or not re.fullmatch('[0-9a-f]{24}',state.get('device_id','')):raise PermissionError('INVALID_REMOVAL_HANDOFF')
    from .single_instance import machine_instance
    io=Windows();name=task_name(jid);verify_task(io.query(name),exe,jid)
    result_path=root/'result.json'
    def load():return read_json(result_path) if result_path.exists() else None
    def save(body):io.write(result_path,encode(body))
    def post(body):return call(state,root,body)
    def remove():
        from tools.endpoint_remove_direct import execute
        # A queued old job must not erase a new enrollment installed meanwhile.
        current=folder(35)/'USBControl'/state['device_id']/'config.json'
        protected_tree(current,recursive=False)
        config=read_json(current)
        installed=read_json(folder(38)/'USBControl/_internal/agent-release.json',2*1024*1024)
        from . import __version__
        if installed.get('version')!=__version__:raise PermissionError('REMOVAL_INSTALLED_VERSION_CHANGED')
        from .machine_agent_windows import read_marker
        ca_hash=hashlib.sha256((root/'center-ca.pem').read_bytes() if state['ca'] else b'').hexdigest()
        check_identity(state,config,read_marker(),__version__,ca_hash)
        platform=cleaned_platform(state['device_id'],lambda:post({'phase':'deleting'}))
        try:return execute(platform,True,lambda *a,**k:None)
        finally:
            io.write(root/'cleanup-detail.json',encode(platform.last_result))
    with machine_instance('native-installer-machine','all-devices'):
        try:final=execute_job(state,load,save,lambda:post({'phase':'authorize'}),remove,post)
        except (OSError,ConnectionError):
            final=load()
            if not final or final.get('phase')=='deleting':raise
            # Delivery only; never invoke remove() again. A reboot task retains
            # this same terminal result if the bounded retry window expires.
            for attempt in range(12):
                time.sleep(15)
                try:post(final);break
                except (OSError,ConnectionError):
                    if attempt==11:raise
    # ACK first: offline results remain with the visible boot task for retry.
    # Never rerun deletion to deliver a missing response.
    verify_task(io.query(name),exe,jid);io.delete(name)
    if final['phase']=='complete':
        schedule_program_cleanup(root)
        final={**final,'helper_cleanup':'reboot_pending'};save(final)
        post(final)
    # No endpoint token was staged. The narrow result token is no longer needed.
    (root/'handoff.json').unlink();(root/'center-ca.pem').unlink(missing_ok=True)
    return 0 if final['phase']=='complete' else 1
