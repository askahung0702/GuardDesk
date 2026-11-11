"""Fixed-root, backup-first internal removal. Never executed by a center/SYSTEM job.

No arbitrary path/command arguments, re-enrollment, policy defaults, or ACL repair.
Restore uses the *installed protected* worker, preserving its original semantics.
"""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid
from tools import endpoint_agent_reset as reset
from tools.endpoint_fresh_cleanup import CleanupError, plain, optional_entries, contained, io_path

LEDGERS=('windows/usb-original.json','windows/usb-managed.json','windows/installed.json',
         'applications/document-sacl.sqlite3','applications/process-audit-original.json',
         'applications/applocker-managed.json','applications/appidsvc-original.json',
         'website-policy-chrome.json','website-policy-edge.json','browser-policy-owned.json',
         'browser-trust-owned.json','CustomSettings/network-lease.json')


def digest(path,deadline,expected):
    h=hashlib.sha256();total=0
    with open(io_path(path),'rb') as stream:
        while chunk:=stream.read(min(1024*1024,expected-total+1)):
            total+=len(chunk)
            if total>expected or time.monotonic()>deadline:raise CleanupError('BACKUP_HASH_LIMIT')
            h.update(chunk)
    if total!=expected:raise CleanupError('BACKUP_HASH_SIZE_CHANGED')
    return h.hexdigest()


def json_file(path):
    with path.open('rb') as stream:raw=stream.read(1024*1024+1)
    if len(raw)>1024*1024:raise CleanupError('CONFIG_TOO_LARGE')
    result=json.loads(raw)
    if not isinstance(result,dict):raise CleanupError('CONFIG_OBJECT_REQUIRED')
    return result


def scope(platform):
    targets=[plain(platform.program),plain(platform.data)];profiles=platform.registry.profiles()
    for target in targets:
        if target.name!='GuardDeskPilot':raise CleanupError('FIXED_ROOT_REQUIRED')
        if any((target/n).exists() for n in ('server-config.json','server.json','control.sqlite3','tls','server')):
            raise CleanupError('SERVER_DATA_PRESENT')
    for _,_,client in profiles:
        client=plain(client)
        if client.name!='GuardDeskPilotClient':raise CleanupError('FIXED_CLIENT_REQUIRED')
        targets.extend(plain(p) for p in optional_entries(client,512) if p.name.casefold()!='pilotdocuments')
    return [p for p in targets if p.exists()],profiles


def restore_plan(platform,profiles):
    configs=[];machine=platform.data/'USBControl'
    for path in optional_entries(machine,256):
        if path.is_dir() and re.fullmatch('[0-9a-f]{24}',path.name):
            config=path/'config.json';ledgers=[n for n in LEDGERS if (path/n).exists()]
            if not config.exists():
                if ledgers:raise CleanupError('CONTROL_BASELINE_WITHOUT_CONFIG: '+str(path))
                continue
            settings=json_file(config)
            if settings.get('device_id')!=path.name:raise CleanupError('CONFIG_IDENTITY_MISMATCH')
            if settings.get('proxy_enabled') or (path/'windows/installed.json').exists():
                raise CleanupError('LEGACY_PROXY_OR_WINDOWS_AUDIT_RESTORE_REQUIRED: '+str(config))
            if ledgers:configs.append(config)
    for _,_,client in profiles:
        config=client/'runtime/agent/config.json';parent=config.parent
        # User-writable ledgers must not drive privileged restoration. Keep all
        # files/backups rather than guessing baselines from another account.
        if any((parent/n).exists() for n in LEDGERS):
            raise CleanupError('LEGACY_USER_CONTROL_RESTORE_REQUIRED: '+str(parent))
        if config.exists() and json_file(config).get('proxy_enabled'):
            raise CleanupError('LEGACY_USER_PROXY_RESTORE_REQUIRED: '+str(parent))
    return configs


def copy_tree(files,source,target,manifest,deadline,progress):
    count=0
    def visit(src,dst,depth):
        nonlocal count
        count+=1
        if count>50000 or depth>40 or time.monotonic()>deadline:raise CleanupError('BACKUP_LIMIT')
        with files.handle(src) as (_,directory):
            if directory:
                os.mkdir(io_path(dst))
                for child in optional_entries(src,50000-count):visit(child,dst/child.name,depth+1)
            else:
                before=os.stat(io_path(src))
                if before.st_nlink!=1:raise CleanupError('BACKUP_HARDLINK')
                h=hashlib.sha256()
                with open(io_path(src),'rb') as reader,open(io_path(dst),'xb') as writer:
                    while chunk:=reader.read(1024*1024):
                        if time.monotonic()>deadline:raise CleanupError('BACKUP_TIMEOUT')
                        h.update(chunk);writer.write(chunk)
                    writer.flush();os.fsync(writer.fileno())
                after=os.stat(io_path(src))
                if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns) or digest(src,deadline,after.st_size)!=h.hexdigest() or digest(dst,deadline,after.st_size)!=h.hexdigest():
                    raise CleanupError('SOURCE_CHANGED_DURING_BACKUP')
                manifest.append({'source':str(src),'backup':str(dst),'bytes':after.st_size,'sha256':h.hexdigest()})
        if count%250==0:progress('Backed up objects: '+str(count),flush=True)
    with files.pinned(source.parent):visit(source,target,0)


class Windows(reset.Windows):
    def backup_root(self):
        from guarddesk.native_installer import Windows as Installer
        root=plain(self.data.parent/'GuardDeskMaintenanceBackups')
        installer=Installer()
        if not root.exists():installer.protect(root,create=True)
        from guarddesk.update_native import protected_tree
        # The directory is outside GuardDeskPilot; repeated removal keeps prior
        # backups. Never adds an ordinary user to its ACL.
        protected_tree(root,recursive=False)
        backup=root/('Agent-'+time.strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8])
        installer.protect(backup,create=True)
        return backup

    def trust(self,configs):
        from guarddesk.update_native import protected_tree
        if not configs:return
        for root in (self.program/'USBControl',*(c.parent for c in configs)):
            # Bounds already checked by the scope preflight.
            protected_tree(root)

    def quiesce(self,tasks,report):
        for name,raw in tasks:
            current=self.command('/Query','/TN',name,'/XML')
            if current.returncode or current.stdout!=raw:raise CleanupError('TASK_CHANGED')
            if self.command('/Change','/TN',name,'/DISABLE').returncode:raise CleanupError('TASK_DISABLE_FAILED')
            report['disabled_tasks'].append(name)
            self.command('/End','/TN',name)
        report['stopped_processes']=self.processes(True)
        if self.processes(False):raise CleanupError('AGENT_RESTARTED')

    def restore(self,config,backup):
        executable=self.program/'USBControl/GuardDesk.exe'
        # No user-writable/backup executable is ever launched.
        with self.files.pinned(executable.parent),self.files.handle(executable):
            self.trust([config])
            log=backup/('restore-'+config.parent.name+'.log')
            with log.open('xb') as stream:
                result=subprocess.run([str(executable),'usb-worker','--extended','--config',str(config),'--restore'],
                    stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,timeout=300,
                    creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode:raise CleanupError('CONTROL_RESTORE_FAILED: '+str(log))


def execute(platform,remove,progress=print):
    report={'format':1,'tool':'GuardDesk universal backup-first removal','revision':3,'result':'PREPARING',
            'host_or_device_lock':False,'center_changed':False,'company_changed':False,
            'files_deleted':False,'disabled_tasks':[],'stopped_processes':[],'restored':[],
            'backup_complete':False,'rollback_automatic':False}
    platform.last_result=report
    targets,profiles=scope(platform)
    if any(contained(sys.executable,p) for p in targets):raise CleanupError('MOVE_REMOVAL_TOOL_OUTSIDE_AGENT_ROOTS')
    report['targets']=[]
    # Validate all fixed scope first, even when no config exists / several IDs.
    for target in targets:
        info=platform.files.inspect(target,time.monotonic()+120)
        report['targets'].append({'path':str(target),**info})
    catalog={'preserved_external_tasks':[]}
    tasks=platform.tasks(catalog)
    report.update(catalog);report['tasks_to_remove']=[n for n,_ in tasks]
    if catalog['preserved_external_tasks']:raise CleanupError('NONSTANDARD_AGENT_TASK_ACTION_PRESERVED')
    platform.processes(False)
    if not remove:
        report['result']='REMOVAL_PREVIEW';return report
    report['phase']='create_backup_directory'
    backup=platform.backup_root();report['backup']=str(backup)
    required=sum(v['bytes'] for v in report['targets'])
    if shutil.disk_usage(backup).free<required+max(64*1024*1024,required//10):raise CleanupError('BACKUP_SPACE_REQUIRED')
    # Preserve complete original task definitions before disabling them.
    for index,(name,raw) in enumerate(tasks):(backup/('task-'+str(index)+'.xml')).write_bytes(raw)
    report['phase']='backup_registry';registries=[]
    platform.registry.hive_journal=backup/'registry-mounts.json'
    with ExitStack() as stack:
        for sid,profile,client in profiles:
            report['registry_profile']=str(profile)
            key=stack.enter_context(platform.registry.hive(sid,profile))
            changes=platform.registry.changes_all(key,client,{'preserved_external_registry':[]})
            registries.append({'sid':sid,'values':changes})
    (backup/'registry.json').write_text(json.dumps(registries,ensure_ascii=False,indent=2),encoding='utf-8')
    report['phase']='stop_owned_agent';report['company_changed']=True
    progress('Stopping fixed GuardDesk Agent tasks/processes...',flush=True)
    platform.quiesce(tasks,report)
    report['phase']='backup_agent_files';manifest=[]
    for index,target in enumerate(targets):
        progress('Backup: '+str(target),flush=True)
        copy_tree(platform.files,target,backup/('root-'+str(index)),manifest,time.monotonic()+600,progress)
    (backup/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    report['backup_complete']=True
    report['phase']='review_control_baselines';configs=restore_plan(platform,profiles)
    platform.trust(configs)
    for config in configs:
        progress('Restore GuardDesk-owned controls: '+str(config),flush=True)
        platform.restore(config,backup);report['restored'].append(str(config))
    if platform.processes(False):raise CleanupError('AGENT_RESTARTED_BEFORE_CLEANUP')
    progress('Removing fixed Agent files and startup registrations...',flush=True)
    report['phase']='remove_agent_files';report['file_deletion_started']=True
    try:cleanup=reset.execute(platform,True,progress)
    except BaseException:
        report['cleanup']=platform.last_result
        raise
    finally:platform.last_result=report
    report['cleanup']=cleanup
    if cleanup['result']!='RESET_FILES_COMPLETE':raise CleanupError('CLEANUP_INCOMPLETE')
    report.update(result='AGENT_REMOVED_BACKUP_RETAINED',files_deleted=True,phase='complete')
    (backup/'removal-result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    platform.last_result=report
    return report


def main():
    args=sys.argv[1:]
    if args not in (['--preview'],['--remove-agent']):print('Use --preview or --remove-agent only');return 2
    from guarddesk.windows_controls import is_admin
    from guarddesk.single_instance import machine_instance
    if not is_admin():print('ADMIN_REQUIRED');return 3
    platform=None
    try:
        platform=Windows()
        with machine_instance('native-installer-machine','all-devices'):
            result=execute(platform,args==['--remove-agent'])
    except (Exception,KeyboardInterrupt) as exc:
        result=dict(getattr(platform,'last_result',{}))
        result.update(result='REMOVAL_INCOMPLETE',error_type=type(exc).__name__,message=str(exc)[:700])
    output=Path(sys.executable).parent/('Agent-Removal-Result-'+uuid.uuid4().hex+'.json')
    with output.open('x',encoding='utf-8') as stream:json.dump(result,stream,ensure_ascii=False,indent=2)
    print('Result='+result['result']);print('Report='+str(output))
    if result.get('backup'):print('Backup='+result['backup'])
    if result.get('message'):print(result['message'])
    return 0 if result['result'] in ('REMOVAL_PREVIEW','AGENT_REMOVED_BACKUP_RETAINED') else 1


if __name__=='__main__':raise SystemExit(main())
