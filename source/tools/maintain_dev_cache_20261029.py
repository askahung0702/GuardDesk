"""Fixed DEV-01 maintenance. Archive two reviewed ZIP-only trees, never delete.

No shell, PowerShell, config edits, re-enrollment, program replacement, or new
service. The operator must attest no center job is active before --apply.
"""
import argparse
from contextlib import contextmanager
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import update_packages as packages

DID='ee44c5652fe51572ce2718af'
OLD_JOB='c7eedd773ead701bb54e80e3d5c2b99b'
JOB='60dcddd019dae19330bbcabde3363667'
PINS={OLD_JOB:(55127383,'182a51cbd86eabedf31d62793160867ed80ce5e65368345973adee88b656eb09'),
      JOB:(55155846,'79414564b1c704e0f86922a1375c2b5acfd8c06929a395c2a7906cfae0723ce4')}
UPDATER_SHA='97097e2e1b94df9fc64f4ac3f162ef1925d855783ad1135a9012ff8a14c49c24'
INCOMING=85908082
CAP=512*1024*1024


def read(path):
    path=packages.plain(path)
    with path.open('rb') as stream:raw=stream.read(600*1024+1)
    if len(raw)>600*1024:raise ValueError('State exceeds reviewed limit')
    value=json.loads(raw)
    if not isinstance(value,dict):raise ValueError('State type')
    return value


def validate_state(data):
    native=read(data/'updates/transaction-native.json')
    refresh=read(data/'updates/updater-refresh.json')
    config=read(data/'config.json')
    if (native.get('phase')!='downloading' or native.get('job',{}).get('id')!=JOB
        or native.get('old_version')!='0.4.64' or native.get('target')!='0.4.66'
        or native.get('job',{}).get('release_id')!=PINS[JOB][1]):raise ValueError('Native transaction changed; preserve it')
    if (refresh.get('phase')!='healthy' or refresh.get('reported') is not True
        or refresh.get('job_id')!='22900d93ff9a78d48b1669875d53f952'
        or refresh.get('target')!='0.4.60'):raise ValueError('Updater recovery changed; preserve it')
    if config.get('device_id')!=DID:raise ValueError('Device identity mismatch')
    install=data/'install-transaction.json'
    if install.exists() and read(install).get('phase')!='complete':raise ValueError('Installer transaction active')


def unchanged_files(data):
    names=('config.json','install-transaction.json','updates/transaction-native.json','updates/updater-refresh.json')
    return {name:packages.file_hash(packages.plain(data/name)) for name in names if (data/name).exists()}


def validate_move(source,destination,updates,archive):
    source=packages.plain(source);destination=packages.plain(destination)
    if source.resolve().parent!=updates.resolve() or source.name not in PINS:raise ValueError('Source outside fixed jobs')
    if destination.resolve().parent!=archive.resolve() or destination.name!=source.name:raise ValueError('Destination outside new archive')
    if destination.exists():raise FileExistsError('Never merge or replace archive')
    if source.stat().st_dev!=archive.stat().st_dev:raise ValueError('Same NTFS volume required')


class WindowsPlatform:
    def __init__(self,program,data,archive_parent):
        self.program=program;self.data=data;self.archive_parent=archive_parent
        self.exe=program/'Updater/GuardDesk.exe';self.name='GuardDesk-AgentUpdater-'+DID
        self.task_digest=None

    def check_task(self):
        from guarddesk.native_installer import verify_task
        from guarddesk.decommission import parse_task_xml
        from guarddesk.update_native import task_xml,protected_tree
        raw=task_xml(self.name);verify_task(raw,self.exe,self.data/'config.json','updater')
        tree=parse_task_xml(raw);ns={'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
        principals=tree.findall('t:Principals/t:Principal',ns);action=tree.find('t:Actions',ns)
        if len(principals)!=1 or action.get('Context')!=principals[0].get('id') or not principals[0].get('id'):raise ValueError('Task context mismatch')
        if tree.findtext('t:Settings/t:Enabled',namespaces=ns)=='false':raise ValueError('Task disabled; preserve it')
        if tree.findtext('t:Principals/t:Principal/t:LogonType',namespaces=ns) not in (None,'ServiceAccount'):raise ValueError('Task logon mismatch')
        protected_tree(self.exe.parent);protected_tree(self.exe)
        if packages.file_hash(self.exe)!=UPDATER_SHA:raise ValueError('Installed updater changed')
        digest=hashlib.sha256(raw).hexdigest()
        if self.task_digest and digest!=self.task_digest:raise ValueError('Task changed during maintenance')
        self.task_digest=digest

    def check_root(self,path):
        from guarddesk.update_native import protected_tree
        protected_tree(path,recursive=False)

    def descriptor(self,path):
        import ctypes
        from ctypes import wintypes as w
        adv=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        adv.GetNamedSecurityInfoW.argtypes=[w.LPWSTR,w.DWORD,w.DWORD,w.LPVOID,w.LPVOID,w.LPVOID,w.LPVOID,ctypes.POINTER(w.LPVOID)]
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes=[w.LPVOID,w.DWORD,w.DWORD,ctypes.POINTER(w.LPWSTR),w.LPVOID]
        kernel.LocalFree.argtypes=[w.LPVOID]
        sd=w.LPVOID();text=w.LPWSTR()
        try:
            result=adv.GetNamedSecurityInfoW(str(path),1,7,None,None,None,None,ctypes.byref(sd))
            if result:raise ctypes.WinError(result)
            if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd,1,7,ctypes.byref(text),None):raise ctypes.WinError(ctypes.get_last_error())
            return text.value
        finally:
            if text:kernel.LocalFree(ctypes.cast(text,w.LPVOID))
            if sd:kernel.LocalFree(sd)

    def snapshot(self,path):
        from guarddesk.update_native import protected_tree
        path=packages.plain(path);protected_tree(path,recursive=False)
        entries=list(path.iterdir())
        if len(entries)!=1 or entries[0].name!='package.zip':raise ValueError('Unexpected files in download directory')
        package=packages.plain(entries[0]);protected_tree(package)
        info=package.stat();expected=PINS[path.name]
        digest=packages.file_hash(package)
        if (info.st_size,digest)!=expected:raise ValueError('Package differs from reviewed metadata')
        return dict(directory_id=path.stat().st_ino,file_id=info.st_ino,bytes=info.st_size,sha256=digest,
                    mtime_ns=info.st_mtime_ns,directory_security=self.descriptor(path),file_security=self.descriptor(package))

    @contextmanager
    def stopped(self):
        from guarddesk.native_installer import system_query_scope
        from guarddesk.update_windows import image_processes
        from guarddesk.update_native import task_command
        from guarddesk.single_instance import machine_instance
        stopped=False
        try:
            self.check_task()
            with system_query_scope(),image_processes(self.exe) as wait:
                stopped=True;task_command(self.name,'/End');wait(time.monotonic()+30)
            # Presence mutex excludes a new broker for the duration of moves.
            with machine_instance('update',DID):yield
        finally:
            if stopped:
                self.check_task();self.restart_time=time.time();task_command(self.name,'/Run')

    def create_archive(self):
        from guarddesk.native_installer import Windows
        platform=Windows()
        for path in (self.archive_parent.parent,self.archive_parent):
            if path.exists():self.check_root(path)
            else:platform.protect(path,create=True)
        archive=self.archive_parent/('20261029-'+datetime.datetime.now().strftime('%H%M%S')+'-'+uuid.uuid4().hex[:12])
        if archive.exists():raise FileExistsError('New archive required')
        platform.protect(archive,create=True)
        return archive

    def move(self,source,destination):
        import ctypes
        from ctypes import wintypes as w
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.MoveFileW.argtypes=[w.LPCWSTR,w.LPCWSTR];api.MoveFileW.restype=w.BOOL
        if not api.MoveFileW(str(source),str(destination)):raise ctypes.WinError(ctypes.get_last_error())

    def record(self,archive,value):
        from guarddesk.native_installer import Windows
        Windows().write(archive/'maintenance.json',json.dumps(value,ensure_ascii=False,indent=2).encode('utf-8'))

    def usage(self):
        from tools.diagnose_dev_update_20261029 import usage
        return {label:usage(path) for label,path in [('program',self.program),('updates',self.data/'updates')]}

    def healthy(self):
        from guarddesk.native_installer import health_image
        deadline=time.monotonic()+35
        while time.monotonic()<deadline:
            try:
                body=read(self.data/'broker-health.json')
                if (body.get('version')=='0.4.60' and body.get('native_version')=='0.4.64'
                    and body.get('time',0)>=self.restart_time and time.time()-body['time']<30
                    and health_image(body.get('pid'))==self.exe):return True
            except (OSError,ValueError):pass
            time.sleep(.5)
        return False


def maintain(platform,apply=False,center_idle=False):
    if apply and not center_idle:raise ValueError('Operator must verify center has no active job')
    data=packages.plain(platform.data);updates=packages.plain(data/'updates')
    for path in (platform.program,data,updates):platform.check_root(path)
    validate_state(data);platform.check_task();original=unchanged_files(data)
    source={job:platform.snapshot(updates/job) for job in PINS}
    result=dict(device_id=DID,operation='DEV fixed download archive',center_idle_attested=center_idle,
                mode='apply' if apply else 'check',sources=source,moved=[],restored=[],company_changed=False)
    if not apply:result['result']='CHECKED';return result
    archive=None
    with platform.stopped():
        validate_state(data)
        if unchanged_files(data)!=original:raise ValueError('State changed before archive; no move')
        for job in PINS:
            if platform.snapshot(updates/job)!=source[job]:raise ValueError('Source changed before archive')
        archive=platform.create_archive();result['archive']=str(archive);result['company_changed']=True
        platform.record(archive,result)
        try:
            for job in PINS:
                start=updates/job;target=archive/job
                validate_move(start,target,updates,archive)
                platform.check_root(updates);platform.check_root(archive)
                if platform.snapshot(start)!=source[job]:raise ValueError('Source changed at move boundary')
                platform.move(start,target);result['moved'].append(job);platform.record(archive,result)
                if platform.snapshot(target)!=source[job]:raise ValueError('Archive inode/hash/owner/DACL changed')
            if unchanged_files(data)!=original:raise ValueError('State changed during archive')
            result['usage_after_archive']=platform.usage()
            result['fresh_job_projected_bytes']=sum(v['bytes'] for v in result['usage_after_archive'].values())+PINS[JOB][0]+INCOMING
            if result['fresh_job_projected_bytes']>CAP:raise ValueError('Fresh download plus extraction still exceeds old budget')
            result['identity_and_state_preserved']=True;result['result']='ARCHIVED_AWAITING_HEALTH'
            platform.record(archive,result)
        except BaseException as exc:
            result['failure']={'type':type(exc).__name__,'winerror':getattr(exc,'winerror',None)}
            result['rollback_errors']=[]
            # Never overwrite a reappeared source; retain partial archive evidence.
            for job in reversed(result['moved']):
                try:
                    target=archive/job;start=updates/job
                    if start.exists() or platform.snapshot(target)!=source[job]:raise ValueError('Restore boundary changed; retain archive')
                    packages.plain(start);platform.check_root(updates);platform.move(target,start)
                    result['restored'].append(job)
                except (OSError,ValueError) as restore:
                    result['rollback_errors'].append({'job':job,'type':type(restore).__name__,'winerror':getattr(restore,'winerror',None)})
            result['result']='FAILED_REVIEW_REQUIRED'
            try:platform.record(archive,result)
            except OSError:pass
            raise
    result['updater_restarted']=True
    result['fresh_broker_health']=platform.healthy()
    result['identity_and_state_preserved']=unchanged_files(data)==original
    result['result']='READY_FOR_FRESH_JOB' if result['fresh_broker_health'] and result['identity_and_state_preserved'] else 'ARCHIVED_REVIEW_HEALTH'
    platform.record(archive,result)
    return result


def main():
    from guarddesk.windows_controls import is_admin
    parser=argparse.ArgumentParser(description='Fixed DEV-01 reviewed cache maintenance, no free path/device input')
    parser.add_argument('--apply',action='store_true');parser.add_argument('--center-idle-attested',action='store_true')
    args=parser.parse_args()
    if os.environ.get('COMPUTERNAME','').upper()!='DEV-01' or not is_admin():raise SystemExit('DEV-01 administrator only')
    program=Path(r'C:\Program Files\GuardDeskPilot');data=Path(r'C:\ProgramData\GuardDeskPilot\USBControl')/DID
    platform=WindowsPlatform(program,data,Path(r'C:\ProgramData\GuardDeskPilot\RepairArchive')/DID)
    report=ROOT/'evidence/maintenance'/('dev-cache-maintenance-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'.json')
    try:result=maintain(platform,args.apply,args.center_idle_attested)
    except BaseException as exc:
        result=dict(result='FAILED_REVIEW_REQUIRED',error_type=type(exc).__name__,message=str(exc)[:300],
                    winerror=getattr(exc,'winerror',None),device_id=DID,company_change_requires_review=True)
    with packages.plain(report).open('x',encoding='utf-8') as stream:json.dump(result,stream,ensure_ascii=False,indent=2)
    print(json.dumps(result,ensure_ascii=False),flush=True)
    return 0 if result['result'] in ('CHECKED','READY_FOR_FRESH_JOB') else 1


if __name__=='__main__':raise SystemExit(main())
