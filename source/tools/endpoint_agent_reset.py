"""Explicit local test-Agent file reset. All enrollments, fixed roots only.

No host/DID/completion gate. No old-code execution, policy restoration, arbitrary
shell/path arguments, ACL changes or removal of management-server data.
"""
from contextlib import ExitStack
import csv
import ctypes
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
from tools.endpoint_fresh_cleanup import Files,Registry,plain,contained,entries,optional_entries,RUN,HOST_KEYS,CleanupError

IMAGES={'guarddesk.exe','guarddeskagent.exe','guarddeskremote.exe','guarddeskmis.exe',
        'guarddeskremoteworker.exe','guarddeskremotemedia.exe'}


def task_target(name,raw,program,data):
    matched=re.fullmatch(r'\\?GuardDesk-(USBControl|AgentUpdater)-([0-9a-f]{24})',name,re.I)
    if not matched:return False
    from guarddesk.decommission import parse_task_xml
    root=parse_task_xml(raw);ns={'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    action=root.find('t:Actions',ns)
    if action is None or len(action)!=1 or action[0].tag!='{'+ns['t']+'}Exec':return False
    native=matched[1].casefold()=='usbcontrol'
    exe=program/('USBControl' if native else 'Updater')/'GuardDesk.exe'
    command=action[0].findtext('t:Command',namespaces=ns) or ''
    arguments=action[0].findtext('t:Arguments',namespaces=ns) or ''
    config=data/'USBControl'/matched[2].lower()/'config.json'
    prefix=r'usb-worker(?:\s+--extended)?' if native else 'update-service'
    pattern=prefix+r'\s+--config\s+(?:"'+re.escape(str(config))+r'"|'+re.escape(str(config))+r')'
    return os.path.normcase(command)==os.path.normcase(str(exe)) and bool(re.fullmatch(pattern,arguments.strip(),re.I))


class ResetRegistry(Registry):
    def changes_all(self,key,client,report):
        w=self.w;changes=[]
        try:
            with w.OpenKey(key,RUN) as node:
                count=w.QueryInfoKey(node)[1]
                if count>2048:raise CleanupError('RUN_VALUE_LIMIT')
                values=[w.EnumValue(node,i) for i in range(count)]
        except FileNotFoundError:values=[]
        for name,command,kind in values:
            if not name.startswith('GuardDesk-Agent-'):continue
            match=re.fullmatch(r'"([^"\r\n]+)"\s+desktop-agent(?:\s+--config\s+"[^"\r\n]+")?',command) if isinstance(command,str) else None
            if kind==w.REG_SZ and match and contained(match[1],client/'app') and Path(match[1]).name.casefold()=='guarddeskagent.exe':
                changes.append((RUN,name,(command,kind),False))
            else:report['preserved_external_registry'].append(name)
        for path,name,remove in [(r'Software\GuardDesk','AgentConfig',False),*[(p,'',True) for p in HOST_KEYS]]:
            try:
                with w.OpenKey(key,path) as node:
                    value=w.QueryValueEx(node,name)
                    structure=w.QueryInfoKey(node)
            except FileNotFoundError:continue
            if (value[1]==w.REG_SZ and isinstance(value[0],str) and contained(value[0],client/'runtime')
                and (not remove or structure[0]==0 and structure[1]==1)):
                changes.append((path,name,value,remove))
            else:report['preserved_external_registry'].append(path)
        return changes


def process_pass(images,terminate=False,roots=()):
    """Query and terminate on the SAME retained handle; never kill by name/PID."""
    from ctypes import wintypes as w
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    class Entry(ctypes.Structure):
        _fields_=[('size',w.DWORD),('usage',w.DWORD),('pid',w.DWORD),('heap',ctypes.c_size_t),
                  ('module',w.DWORD),('threads',w.DWORD),('parent',w.DWORD),('priority',w.LONG),
                  ('flags',w.DWORD),('exe',w.WCHAR*260)]
    api.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD];api.CreateToolhelp32Snapshot.restype=w.HANDLE
    for name in ('Process32FirstW','Process32NextW'):
        getattr(api,name).argtypes=[w.HANDLE,ctypes.POINTER(Entry)];getattr(api,name).restype=w.BOOL
    api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
    api.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)];api.QueryFullProcessImageNameW.restype=w.BOOL
    api.TerminateProcess.argtypes=[w.HANDLE,w.UINT];api.TerminateProcess.restype=w.BOOL
    api.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];api.WaitForSingleObject.restype=w.DWORD
    api.CloseHandle.argtypes=[w.HANDLE]
    expected={os.path.normcase(str(p)) for p in images};found=[];handles=[]
    # Direct removal discovers live images before opening any Agent data files.
    # Roots are internal fixed GuardDesk paths, never command-line arguments.
    owned_roots=tuple(plain(p) for p in roots)
    names=IMAGES|{Path(p).name.casefold() for p in images}
    def matches(path):
        if os.path.normcase(path) in expected:return True
        if not owned_roots:return False
        path=plain(path)
        return any(contained(path,root) for root in owned_roots)
    snapshot=api.CreateToolhelp32Snapshot(2,0)
    if snapshot==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    try:
        item=Entry();item.size=ctypes.sizeof(item);more=api.Process32FirstW(snapshot,ctypes.byref(item));count=0
        while more:
            count+=1
            if count>16384:raise CleanupError('PROCESS_LIMIT')
            if item.exe.casefold() in names and item.pid!=os.getpid():
                handle=api.OpenProcess(0x1000|0x100000,False,item.pid)
                if not handle:
                    if ctypes.get_last_error()!=87:raise ctypes.WinError(ctypes.get_last_error())
                else:
                    handles.append(handle);size=w.DWORD(32768);name=ctypes.create_unicode_buffer(size.value)
                    if not api.QueryFullProcessImageNameW(handle,0,name,ctypes.byref(size)):
                        if api.WaitForSingleObject(handle,0)!=0:raise ctypes.WinError(ctypes.get_last_error())
                    elif matches(name.value) and api.WaitForSingleObject(handle,0)!=0:
                        if terminate:
                            owned=api.OpenProcess(0x1000|0x100000|1,False,item.pid)
                            if not owned:
                                if api.WaitForSingleObject(handle,0)!=0:raise ctypes.WinError(ctypes.get_last_error())
                            else:
                                handles.append(owned);verify=ctypes.create_unicode_buffer(32768);length=w.DWORD(len(verify))
                                if not api.QueryFullProcessImageNameW(owned,0,verify,ctypes.byref(length)):
                                    if api.WaitForSingleObject(owned,0)!=0:raise ctypes.WinError(ctypes.get_last_error())
                                elif os.path.normcase(verify.value)!=os.path.normcase(name.value):raise CleanupError('PROCESS_IMAGE_CHANGED')
                                else:found.append((owned,name.value))
                        else:found.append((handle,name.value))
            more=api.Process32NextW(snapshot,ctypes.byref(item))
        if ctypes.get_last_error()!=18:raise ctypes.WinError(ctypes.get_last_error())
        if len(found)>256:raise CleanupError('AGENT_PROCESS_LIMIT')
        # Complete catalog validation before the first termination.
        if terminate:
            deadline=time.monotonic()+15
            for handle,name in found:
                if api.WaitForSingleObject(handle,0)==0:continue
                if not api.TerminateProcess(handle,0):raise ctypes.WinError(ctypes.get_last_error())
            for handle,name in found:
                if api.WaitForSingleObject(handle,max(0,int((deadline-time.monotonic())*1000)))!=0:
                    raise CleanupError('AGENT_EXIT_TIMEOUT: '+name)
        return [name for _,name in found]
    finally:
        api.CloseHandle(snapshot)
        for handle in handles:api.CloseHandle(handle)


class Windows:
    def __init__(self):
        from guarddesk.update_native import folder,system_tool
        self.program=folder(38);self.data=folder(35);self.tool=system_tool('schtasks.exe')
        self.files=Files();self.registry=ResetRegistry()

    def command(self,*args):
        return subprocess.run([str(self.tool),*args],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)

    def tasks(self,report):
        result=self.command('/Query','/FO','CSV','/NH')
        if result.returncode or len(result.stdout)>16*1024**2:raise CleanupError('TASK_CATALOG_UNAVAILABLE')
        found=[]
        for row in csv.reader(io.StringIO(result.stdout.decode('oem'))):
            if not row or not re.fullmatch(r'\\GuardDesk-(?:USBControl|AgentUpdater)-[0-9a-f]{24}',row[0],re.I):continue
            name=row[0];query=self.command('/Query','/TN',name,'/XML')
            if query.returncode:raise CleanupError('TASK_QUERY_FAILED: '+name)
            if task_target(name,query.stdout,self.program,self.data):found.append((name,query.stdout))
            else:report['preserved_external_tasks'].append(name)
        return found

    def stop_tasks(self,tasks,report):
        for name,raw in tasks:
            current=self.command('/Query','/TN',name,'/XML')
            if current.returncode or current.stdout!=raw:raise CleanupError('TASK_CHANGED: '+name)
            # An already stopped task can return a nonzero /End code.
            self.command('/End','/TN',name)
            if self.command('/Delete','/TN',name,'/F').returncode:raise CleanupError('TASK_DELETE_FAILED: '+name)
            report['removed_tasks'].append(name)

    def processes(self,terminate):
        from guarddesk.native_installer import system_query_scope
        with system_query_scope():return process_pass(self.files.images,terminate)


def execute(platform,clean,progress=print):
    report=dict(result='PREPARING',company_changed=False,deleted=[],removed_tasks=[],stopped_processes=[],
                registry_profiles_cleaned=[],preserved_user_documents=[],preserved_external_registry=[],preserved_external_tasks=[],
                targets=[],mode='all_local_test_agent_files',host_or_device_lock=False,completion_marker_required=False,
                center_changed=False,managed_controls_restored=False)
    platform.last_result=report
    program=plain(platform.program);data=plain(platform.data)
    if program.name!='GuardDeskPilot' or data.name!='GuardDeskPilot':raise CleanupError('FIXED_ROOT_REQUIRED')
    profiles=platform.registry.profiles();targets=[program,data];clients=[]
    for _,_,client in profiles:
        client=plain(client)
        if client.name!='GuardDeskPilotClient':raise CleanupError('FIXED_CLIENT_ROOT_REQUIRED')
        clients.append(client)
        for child in optional_entries(client,512):
            if child.name.casefold()=='pilotdocuments':report['preserved_user_documents'].append(str(child))
            else:targets.append(plain(child))
    # No DID/config/phase parsing. Two or more stale enrollments are all covered.
    for target in (program,data):
        for name in ('server-config.json','server.json','control.sqlite3','tls','server'):
            if (target/name).exists():raise CleanupError('SERVER_DATA_PRESENT: '+str(target/name))
    executable=Path(sys.executable).absolute()
    if any(contained(executable,r) for r in (program,data,*clients)):raise CleanupError('MOVE_RESET_TOOL_OUTSIDE_AGENT_DIRECTORIES')
    with ExitStack() as stack:
        # Validate whole deletion scope before stopping jobs or changing data.
        for target in targets:
            if not target.exists():continue
            stack.enter_context(platform.files.pinned(target.parent))
            report['targets'].append(dict(path=str(target),**platform.files.inspect(target,time.monotonic()+120)))
        opened=[]
        for sid,profile,client in profiles:
            key=stack.enter_context(platform.registry.hive(sid,profile))
            opened.append((sid,key,platform.registry.changes_all(key,client,report)))
        tasks=platform.tasks(report)
        report['tasks_to_remove']=[name for name,_ in tasks]
        report['processes_to_stop']=platform.processes(False)
        if not clean:report['result']='RESET_PREVIEW';return report
        report['company_changed']=True;report['stage']='stop_agent'
        progress('Stopping GuardDesk Agent tasks and processes...',flush=True)
        platform.stop_tasks(tasks,report)
        report['stopped_processes']=platform.processes(True)
        for sid,key,changes in opened:
            platform.registry.apply(key,changes);report['registry_profiles_cleaned'].append(sid)
        # Release private-root parent pins before deleting now-empty clients.
        report['stage']='delete_files'
        for target in [*targets[2:],program,data]:
            if not target.exists():continue
            progress('Remove: '+str(target),flush=True)
            report['deleted'].append(dict(path=str(target),objects=platform.files.delete(target,time.monotonic()+180,progress)))
    for client in clients:
        if not client.exists():continue
        documents=client/'PilotDocuments'
        if documents.is_dir() and not documents.lstat().st_file_attributes&0x400:
            with os.scandir(documents) as items:empty=next(items,None) is None
            if empty:documents.rmdir()
        with os.scandir(client) as items:empty=next(items,None) is None
        if empty:client.rmdir()
    report['preserved_user_documents']=[p for p in report['preserved_user_documents'] if os.path.lexists(p)]
    report.update(result='RESET_FILES_COMPLETE',stage='complete')
    return report


def main():
    from guarddesk.windows_controls import is_admin
    from guarddesk.single_instance import machine_instance
    args=sys.argv[1:]
    if args not in (['--preview'],['--reset-agent-files']):print('Use fixed --preview or --reset-agent-files only');return 2
    if not is_admin():print('ADMIN_REQUIRED');return 3
    platform=None
    try:
        platform=Windows()
        with machine_instance('native-installer-machine','all-devices'):result=execute(platform,args==['--reset-agent-files'])
    except (Exception,KeyboardInterrupt) as exc:
        result=dict(getattr(platform,'last_result',dict(company_changed=False,deleted=[])))
        result.update(result='RESET_INCOMPLETE',error_type=type(exc).__name__,winerror=getattr(exc,'winerror',None),message=str(exc)[:500])
    path=Path(sys.executable).parent/('Agent-Reset-Result-'+uuid.uuid4().hex+'.json')
    with path.open('x',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print('Result='+result['result']);print('Report='+str(path))
    if result.get('message'):print(result['message'])
    return 0 if result['result'] in ('RESET_PREVIEW','RESET_FILES_COMPLETE') else 1


if __name__=='__main__':raise SystemExit(main())
