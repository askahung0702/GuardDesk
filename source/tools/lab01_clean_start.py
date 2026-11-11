"""Explicit LAB01 backup-first removal; never run a quarantined/old Agent.

Shares the long-path, pinned-handle backup/removal implementation. This is an
interactive maintenance entry, not a center command or resident role.
"""
import json,os,sys,uuid
from pathlib import Path
from tools import endpoint_remove as removal
from tools.endpoint_fresh_cleanup import CleanupError
from guarddesk.remote_service import Service,description

class Windows(removal.Windows):
    def __init__(self):
        super().__init__();self.service=Service();self.saved_service=self.service.query()
        if self.saved_service:
            expected=description(self.program/'USBControl/GuardDesk.exe',self.data/'USBControl'/self.saved_service['device_id']/'config.json')
            if self.saved_service!=expected:raise CleanupError('FOREIGN_SERVICE_PRESERVED')
    def backup_root(self):
        root=super().backup_root()
        if self.saved_service:(root/'service.json').write_text(json.dumps(self.saved_service),encoding='utf-8')
        return root
    def quiesce(self,tasks,report):
        if self.saved_service:
            from guarddesk.native_installer import wait_image_unmapped
            self.service.action(self.saved_service,'stop')
            wait_image_unmapped(self.program/'USBControl/GuardDeskService.exe')
            report['service_stopped']='GuardDeskRemote'
        super().quiesce(tasks,report)
    def stop_tasks(self,tasks,report):
        if self.saved_service:
            self.service.action(self.saved_service,'delete')
            report['service_removed']='GuardDeskRemote'
        super().stop_tasks(tasks,report)
    def restore(self,config,backup):
        # The previous endpoint was Defender-blocked. No old EXE, including a
        # backup, may be restored/executed as a way to remove controls.
        raise CleanupError('CONTROL_BASELINE_REQUIRES_REVIEW_BACKUP_RETAINED_NO_OLD_CODE_RUN')

def main():
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8',errors='replace')
    args=sys.argv[1:]
    if args==['--self-test-user-hive']:
        from tools.endpoint_hive_selftest import main as test
        return test()
    if args not in (['--preview'],['--remove-agent']):return 2
    if os.environ.get('COMPUTERNAME','').upper()!='LAB01':print('LAB01_ONLY_NO_CHANGES');return 4
    from guarddesk.windows_privilege import is_admin
    from guarddesk.single_instance import machine_instance
    if not is_admin():print('ADMIN_REQUIRED');return 3
    platform=None
    try:
        platform=Windows()
        with machine_instance('native-installer-machine','all-devices'):
            result=removal.execute(platform,args==['--remove-agent'])
    except (Exception,KeyboardInterrupt) as exc:
        result=dict(getattr(platform,'last_result',{}))
        result.update(result='REMOVAL_INCOMPLETE',error_type=type(exc).__name__,winerror=getattr(exc,'winerror',None),message=str(exc)[:700])
        if getattr(exc,'registry_mount',None):result['registry_mount_remaining']=exc.registry_mount
    result.update(tool='GuardDesk LAB01 backup-first clean start 088-003',old_agent_code_executed=False,
                  defender_settings_changed=False,center_changed=False)
    output=Path(sys.executable).parent/('LAB01-Cleanup-'+uuid.uuid4().hex+'.json')
    with output.open('x',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print('Result='+result['result']);print('Report='+str(output))
    if result.get('backup'):print('Backup='+result['backup'])
    if result.get('message'):print(result['message'])
    return 0 if result['result'] in ('REMOVAL_PREVIEW','AGENT_REMOVED_BACKUP_RETAINED') else 1

if __name__=='__main__':raise SystemExit(main())
