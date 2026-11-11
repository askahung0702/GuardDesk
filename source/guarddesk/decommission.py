"""Execute only the fixed GuardDesk removal operation; retain all files."""
import ctypes
import json
import ntpath
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def saved(agent):
    with agent.db() as db:row=db.execute("SELECT value FROM state WHERE key='removal_job'").fetchone()
    return json.loads(row[0]) if row else None


def remember(agent,job,phase):
    with agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('removal_job',?)",(json.dumps({'id':job['id'],'phase':phase}),))


def report(agent,job,role,state,error=''):
    result=agent.call('/api/agent/uninstall/status',{'job_id':job['id'],'role':role,'state':state,'error':error[:500]})
    if state=='working' and result['job']['status'] not in ('running','failed'):raise OSError('移除工作已失效，保留現況')
    return result


def main_step(agent):
    marker=saved(agent)
    if marker and marker['phase']=='done':agent.decommissioned=True;return True
    try:job=agent.call('/api/agent/uninstall/poll',{'role':'main'}).get('job')
    except ConnectionError as exc:
        if marker and marker['phase']=='ready' and 'HTTP 401' in str(exc):agent.decommissioned=True;return True
        raise
    if not job or job['status']=='expired':return False
    # Complete file removal is performed independently, including other users'
    # explicitly abandoned queues. Do not acknowledge legacy retain-files here.
    if job.get('mode')=='remove_files_v1':return False
    try:
        if not marker:
            settings=json.loads(agent.config_path.read_text(encoding='utf-8'))
            if settings.get('proxy_enabled'):raise OSError('請先由使用者移除瀏覽器擴充及 browser-uninstall，關閉一般 Agent 後重啟，再重試；保留既有代理避免中斷網路')
            if (agent.config_path.parent/'windows/installed.json').exists():raise OSError('此端點有舊式 SACL／QoS 適配器，請先由 MIS 執行 windows-uninstall')
            report(agent,job,'main','working');remember(agent,job,'stopping')
        agent.close_collectors()
        from .browser_host import unregister_owned
        unregister_owned(agent.config_path)
        from .endpoint_setup import remove_autostart_for_config
        remove_autostart_for_config(agent.config_path)
        if hasattr(agent,'remote_stop'):agent.remote_stop.set()
        if hasattr(agent,'remote'):agent.remote.local_stop.set();agent.remote.close_indicator()
        # Stable identity prevents duplicate audit records after lost ACKs.
        if not marker:
            agent.queue('agent.uninstall_prepared',{'job_id':job['id'],'retains_files':True},event_id='uninstall-main-'+job['id'])
        flushed=agent.flush(max_batches=8,require_empty=False)
        if flushed['pending']:return False
        remember(agent,job,'ready')
        report(agent,job,'main','ready');remember(agent,job,'done')
        agent.decommissioned=True;return True
    except (OSError,ConnectionError,ValueError) as exc:
        try:report(agent,job,'main','failed',str(exc))
        except (OSError,ConnectionError):pass
        return False


def parse_task_xml(xml):
    """Handle schtasks' OEM pipe output with its unchanged UTF-16 declaration.

    Genuine XML bytes keep their declared encoding. Only the known, NUL-free
    schtasks declaration mismatch may use strict Windows OEM decoding; malformed
    input still fails closed and every identity check remains mandatory.
    """
    if not isinstance(xml,(str,bytes)) or len(xml)>65536:
        raise OSError('Cannot parse scheduled task identity; preserve it')
    try:return ET.fromstring(xml)
    except ET.ParseError:
        if isinstance(xml,bytes) and b'\x00' not in xml and re.match(br'^<\?xml\s+version=[\"\']1\.0[\"\']\s+encoding=[\"\']UTF-16[\"\']\s*\?>',xml,re.I):
            try:return ET.fromstring(xml.decode(_task_output_encoding(),errors='strict'))
            except (UnicodeError,LookupError,ET.ParseError):pass
        raise OSError('Cannot parse scheduled task identity; preserve it') from None


def _task_output_encoding():
    return 'oem'


def validate_task(xml,executable,config):
    root=parse_task_xml(xml)
    ns={'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    actions=root.findall('t:Actions/t:Exec',ns)
    action_root=root.find('t:Actions',ns)
    if action_root is None or len(actions)!=1 or len(action_root)!=1:raise OSError('Scheduled task actions do not match GuardDesk')
    command=actions[0].findtext('t:Command',namespaces=ns) or ''
    arguments=actions[0].findtext('t:Arguments',namespaces=ns) or ''
    pattern=r'usb-worker\s+--extended\s+--config\s+"?'+re.escape(str(config))+r'"?'
    if ntpath.normcase(ntpath.normpath(command))!=ntpath.normcase(ntpath.normpath(str(executable))) or not re.fullmatch(pattern,arguments.strip(),re.I):raise OSError('Scheduled task identity/config mismatch; preserve it')


def remove_task(agent):
    from .windows_privilege import is_admin
    if not is_admin() or not getattr(sys,'frozen',False):raise OSError('Remote native removal requires the protected Windows worker')
    did=agent.config['device_id']
    if not re.fullmatch('[0-9a-f]{24}',did):raise OSError('Invalid device identity')
    executable=Path(sys.executable).resolve();config=agent.config_path.resolve()
    program=Path(os.environ['ProgramFiles'])/'GuardDeskPilot/USBControl/GuardDesk.exe'
    expected=Path(os.environ['ProgramData'])/'GuardDeskPilot/USBControl'/did/'config.json'
    if executable!=program.resolve() or config!=expected.resolve():raise OSError('Refuse removal outside protected installation')
    from .remote_trial import enabled
    from .machine_service import enabled as full_service
    if enabled():
        from .remote_service import Service,description
        Service().retire_self(description(executable,config))
        return
    if full_service():
        from .remote_service import Service,description
        service=Service()
        if service.query():
            service.retire_self(description(executable,config))
            return
    directory=ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(directory,len(directory)):raise OSError('System directory unavailable')
    tool=str(Path(directory.value)/'schtasks.exe');name='GuardDesk-USBControl-'+did
    def command(*args):return subprocess.run([tool,*args],capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
    result=command('/Query','/TN',name,'/XML')
    if result.returncode:raise OSError('Cannot verify GuardDesk scheduled task; MIS review required')
    validate_task(result.stdout,executable,config)
    if command('/Delete','/TN',name,'/F').returncode:raise OSError('Cannot remove verified GuardDesk scheduled task')


def native_step(worker):
    agent=worker.agent;marker=saved(agent)
    if marker and marker['phase']=='done':return 'done'
    try:job=agent.call('/api/agent/uninstall/poll',{'role':'native'}).get('job')
    except (OSError,ConnectionError) as exc:
        # A completed ACK can be lost just before the administrator revokes the
        # credential. Cleanup is already durable; do not keep a retired process.
        if marker and marker['phase']=='removed' and 'HTTP 401' in str(exc):return 'done'
        return 'pending' if marker else 'normal'
    if job and job.get('mode')=='remove_files_v1':
        from .remote_removal import prepare
        try:prepare(worker,job)
        except (OSError,ConnectionError,ValueError) as exc:
            try:agent.call('/api/agent/uninstall/files-error',{'job_id':job['id'],'winerror':getattr(exc,'winerror',None)})
            except (OSError,ConnectionError,ValueError):pass
            # Fixed local evidence, not a misleading legacy completion ACK.
            from .protected_files import ProtectedFiles,encode
            ProtectedFiles().write(agent.config_path.parent/'removal-prepare-error.json',encode({'job_id':job['id'],'error_type':type(exc).__name__,'winerror':getattr(exc,'winerror',None)}))
        return 'pending'
    if not job or job['main']!='ready':return 'pending' if marker else 'normal'
    try:
        if not marker:
            report(agent,job,'native','working');remember(agent,job,'restoring')
        if not marker or marker['phase']!='removed':
            if agent.flush(max_batches=8,require_empty=False)['pending']:return 'pending'
            companion=getattr(worker,'extended_companion',None)
            if companion:companion.close()
            if agent.flush(max_batches=8,require_empty=False)['pending']:return 'pending'
            from . import remote_trial
            if remote_trial.enabled():remote_trial.no_control_ledgers(agent)
            else:
                from .application_control import ExtendedWorker
                ExtendedWorker(agent).restore();worker.restore()
            if not remote_trial.enabled():
                from .update_native import remove_broker_task
                remove_broker_task(agent)
            remove_task(agent)
            remember(agent,job,'removed')
        report(agent,job,'native','ready');remember(agent,job,'done');return 'done'
    except (OSError,ConnectionError,ValueError) as exc:
        try:report(agent,job,'native','failed',str(exc))
        except (OSError,ConnectionError):pass
        return 'pending'
