"""Explicit no-backup test-Agent removal. Fixed roots; no old code execution.

Quiesce startup sources and owned processes before opening Agent data or user
hives. No backup/hash/copy phase. A small result report is the only retained log.
"""
import json,os,re,subprocess,sys,time,uuid
from contextlib import contextmanager
from pathlib import Path
from tools import endpoint_agent_reset as reset
from tools.endpoint_remove import scope,LEDGERS,json_file
from tools.endpoint_fresh_cleanup import CleanupError,Files,plain,contained,io_path,optional_entries


class DirectFiles(Files):
    @contextmanager
    def handle(self,path,delete=False):
        try:
            with super().handle(path,delete=delete) as result:yield result
        except OSError as exc:
            if not exc.filename:exc.filename=str(path)
            raise


def control_changes(platform,profiles,report,restored_root=None):
    """Ignore broken identity metadata; refuse only actual control evidence."""
    roots=[]
    for path in optional_entries(platform.data/'USBControl',256):
        if re.fullmatch('[0-9a-f]{24}',path.name):roots.append(plain(path))
    roots.extend(plain(client/'runtime/agent') for _,_,client in profiles)
    for root in roots:
        restored=False
        if restored_root is not None and root==plain(restored_root):
            # Internal remote handoff only: the protected current identity was
            # restored before its independent worker was authorized. Never
            # exempt a user root or another historical machine identity.
            if root.parent!=plain(platform.data/'USBControl') or not re.fullmatch('[0-9a-f]{24}',root.name):raise CleanupError('INVALID_RESTORED_ROOT')
            if (root/'windows/installed.json').exists():raise CleanupError('LEGACY_WINDOWS_CONTROL_RESTORE_REQUIRED')
            restored=True
        if not restored and any((root/name).exists() for name in LEDGERS):
            raise CleanupError('OWNED_CONTROL_RESTORE_REQUIRED: '+str(root))
        config=root/'config.json'
        try:value=json_file(config)
        except FileNotFoundError:continue
        except (ValueError,CleanupError):
            report['invalid_identity_metadata_ignored']=report.get('invalid_identity_metadata_ignored',0)+1
            continue
        if value.get('proxy_enabled'):
            raise CleanupError('OWNED_PROXY_RESTORE_REQUIRED: '+str(root))


def owned_service(raw,program):
    """Recognize both shipped layouts, independently of this tool's build flag."""
    did=raw.get('device_id')
    if not isinstance(did,str) or not re.fullmatch('[0-9a-f]{24}',did):return False
    for relative in ('USBControl/GuardDeskService.exe','USBControl/_internal/GuardDeskService.exe'):
        expected={'kind':'remote-service-v1','device_id':did,
                  'binary':subprocess.list2cmdline([str(program/relative),'--device-id',did])}
        if raw==expected:return True
    return False


class Windows(reset.Windows):
    def __init__(self):
        super().__init__()
        self.files=DirectFiles()
        from guarddesk.remote_service import Service
        self.service=Service();self.saved_service=self.service.query()
        if self.saved_service:
            if not owned_service(self.saved_service,self.program):raise CleanupError('FOREIGN_SERVICE_PRESERVED')
        self.process_roots=()
        for name in ('GuardDeskService.exe','GuardDeskInstaller.exe'):
            self.files.images.add(self.program/'USBControl'/name)

    def processes(self,terminate):
        from guarddesk.native_installer import system_query_scope
        with system_query_scope():return reset.process_pass(self.files.images,terminate,self.process_roots)

    def quiesce(self,tasks,report):
        # Remove verified tasks first so they cannot restart any stopped worker.
        self.stop_tasks(tasks,report)
        if self.saved_service:
            report['service_stop_requested']='GuardDeskRemote'
            try:self.service.action(self.saved_service,'stop')
            except TimeoutError:
                report['service_stop_timed_out']=True
                report['stopped_processes'].extend(self.processes(True))
                self.service.action(self.saved_service,'stop')
            self.service.action(self.saved_service,'delete')
            report['service_removed']='GuardDeskRemote'
        report['stopped_processes'].extend(self.processes(True))
        if self.processes(False):raise CleanupError('OWNED_PROCESS_STILL_RUNNING')


def execute(platform,remove,progress=print):
    report={'format':1,'tool':'GuardDesk direct test-Agent removal','result':'PREPARING',
        'backup_requested':False,'backup_created':False,'rollback_automatic':False,
        'company_changed':False,'files_deleted':False,'center_changed':False,
        'defender_settings_changed':False,'old_agent_code_executed':False,
        'host_or_device_lock':False,'removed_tasks':[],'stopped_processes':[],
        'registry_profiles_cleaned':[],'preserved_external_tasks':[],
        'preserved_external_registry':[],'deleted':[]}
    platform.last_result=report
    report['phase']='fixed_scope'
    targets,profiles=scope(platform)
    clients=[plain(client) for _,_,client in profiles]
    if any(contained(sys.executable,p) for p in (platform.program,platform.data,*clients)):
        raise CleanupError('MOVE_REMOVAL_TOOL_OUTSIDE_AGENT_ROOTS')
    # Never include PilotDocuments or another product/server in process scope.
    platform.process_roots=(plain(platform.program),plain(platform.data),
        *(p for p in targets if p not in (platform.program,platform.data)))
    report['targets']=[str(p) for p in targets]
    tasks=platform.tasks(report)
    if report['preserved_external_tasks']:raise CleanupError('NONSTANDARD_AGENT_TASK_ACTION_PRESERVED')
    report['tasks_to_remove']=[n for n,_ in tasks]
    if not remove:
        report['processes_to_stop']=platform.processes(False)
        report['result']='REMOVAL_PREVIEW';return report
    report['phase']='stop_owned_agent';report['company_changed']=True
    progress('1/4 Stop GuardDesk startup sources and processes...',flush=True)
    platform.quiesce(tasks,report)
    # An uninstall must not strand machine policy changes. This explicit test
    # reset never executes an old/quarantined binary or guesses a baseline.
    report['phase']='check_control_changes'
    checker=getattr(platform,'check_control_changes',None)
    if checker:checker(profiles,report)
    else:control_changes(platform,profiles,report)
    report['phase']='remove_owned_registry'
    progress('2/4 Remove GuardDesk startup and browser registrations...',flush=True)
    for sid,profile,client in profiles:
        report['registry_profile']=str(profile)
        with platform.registry.hive(sid,profile) as key:
            changes=platform.registry.changes_all(key,client,report)
            platform.registry.apply(key,changes)
        report['registry_profiles_cleaned'].append(sid)
    report.pop('registry_profile',None)
    report['phase']='delete_agent_files'
    report['file_deletion_started']=True
    progress('3/4 Delete GuardDesk program and runtime files (no backup)...',flush=True)
    # No pre-delete content scan and no second reset pass. The handle-based
    # walker checks scope/reparse/hardlinks as it deletes, with extended paths.
    for path in [p for p in targets if p not in (platform.program,platform.data)]+[platform.program,platform.data]:
        if not os.path.lexists(io_path(path)):continue
        report['current_path']=str(path)
        count=platform.files.delete(path,time.monotonic()+180,progress)
        report['deleted'].append({'path':str(path),'objects':count})
    report['phase']='verify_removed'
    progress('4/4 Verify GuardDesk removal...',flush=True)
    if platform.processes(False):raise CleanupError('OWNED_PROCESS_REMAINED')
    remaining=platform.tasks(report)
    if remaining or report['preserved_external_tasks']:raise CleanupError('OWNED_STARTUP_REMAINED')
    if any(os.path.lexists(io_path(p)) for p in targets):raise CleanupError('AGENT_PATH_REMAINED')
    if getattr(platform,'service',None) and platform.service.query():raise CleanupError('OWNED_SERVICE_REMAINED')
    for client in clients:
        # User documents are intentionally excluded. Remove only empty wrapper.
        if client.is_dir():
            with os.scandir(io_path(client)) as items:empty=next(items,None) is None
            if empty:os.rmdir(io_path(client))
    report.pop('current_path',None)
    report.update(result='AGENT_REMOVED_NO_BACKUP',files_deleted=True,phase='complete')
    return report


def main():
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8',errors='replace')
    args=sys.argv[1:]
    if args not in (['--preview'],['--remove-agent']):return 2
    from guarddesk.windows_privilege import is_admin
    from guarddesk.single_instance import machine_instance
    if not is_admin():print('ADMIN_REQUIRED');return 3
    platform=None
    try:
        platform=Windows()
        with machine_instance('native-installer-machine','all-devices'):
            result=execute(platform,args==['--remove-agent'])
    except (Exception,KeyboardInterrupt) as exc:
        result=dict(getattr(platform,'last_result',{}))
        result.update(result='REMOVAL_INCOMPLETE',error_type=type(exc).__name__,
            winerror=getattr(exc,'winerror',None),message=str(exc)[:700])
        if getattr(exc,'filename',None):result['failed_path']=str(exc.filename)
        if getattr(exc,'registry_mount',None):result['registry_mount_remaining']=exc.registry_mount
    path=Path(sys.executable).parent/('Agent-Direct-Removal-'+uuid.uuid4().hex+'.json')
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Result='+result['result']);print('Report='+str(path))
    if result.get('message'):print(result['message'])
    return 0 if result['result'] in ('REMOVAL_PREVIEW','AGENT_REMOVED_NO_BACKUP') else 1


if __name__=='__main__':raise SystemExit(main())
