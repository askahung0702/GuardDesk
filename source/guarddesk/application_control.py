"""Deterministic, reviewable AppLocker policy; no process-killing loop."""
import hashlib
import json
import subprocess
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from .policy import validate_app_control

NAMESPACE=uuid.UUID('f2a943f0-38e2-4383-87bd-40bddcd119e1')

def package_info(name):
    import ctypes,os,re
    if os.name!='nt' or not isinstance(name,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,199}',name):raise ValueError('請指定單一已安裝的封裝應用程式名稱')
    directory=ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(directory,len(directory)):raise OSError('Windows system directory unavailable')
    exe=Path(directory.value)/'WindowsPowerShell/v1.0/powershell.exe';script=Path(__file__).with_name('windows')/'package-info.ps1'
    result=subprocess.run([str(exe),'-NoLogo','-NoProfile','-NonInteractive','-File',str(script)],input=json.dumps({'name':name}).encode(),capture_output=True,timeout=60,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise OSError('無法取得指定的封裝應用程式識別')
    return json.loads(result.stdout.decode('utf-8-sig'))


def file_info(path):
    import ctypes,os
    if os.name!='nt':raise OSError('AppLocker file information requires Windows')
    path=Path(path).resolve()
    if not path.is_file() or path.suffix.lower() not in ('.exe','.com','.msi','.msp','.mst'):raise ValueError('請選擇既有 EXE／MSI 檔案')
    directory=ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(directory,len(directory)):raise OSError('Windows system directory unavailable')
    exe=Path(directory.value)/'WindowsPowerShell/v1.0/powershell.exe';script=Path(__file__).with_name('windows')/'application-info.ps1'
    result=subprocess.run([str(exe),'-NoLogo','-NoProfile','-NonInteractive','-File',str(script)],input=json.dumps({'path':str(path)}).encode('utf-8'),capture_output=True,timeout=60,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise OSError(result.stderr.decode('utf-8',errors='replace')[-700:])
    return json.loads(result.stdout.decode('utf-8-sig'))


def applocker_xml(control):
    validate_app_control(control)
    root=ET.Element('AppLockerPolicy',Version='1')
    def path_rule(collection,name,value,sid='S-1-1-0',action='Allow'):
        node=ET.SubElement(collection,'FilePathRule',Id=str(uuid.uuid5(NAMESPACE,collection.attrib['Type']+'|'+name+'|'+value+'|'+sid+'|'+action)),Name='GuardDesk: '+name,Description='GuardDesk managed application policy',UserOrGroupSid=sid,Action=action)
        ET.SubElement(ET.SubElement(node,'Conditions'),'FilePathCondition',Path=value)
    for kind in ('Exe','Msi'):
        collection=ET.SubElement(root,'RuleCollection',Type=kind,EnforcementMode='Enabled')
        if control['mode']=='denylist' and not(kind=='Msi' and control['block_msi']):path_rule(collection,'Default allow','*')
        else:
            path_rule(collection,'Administrators','*','S-1-5-32-544');path_rule(collection,'SYSTEM','*','S-1-5-18')
            if kind=='Exe':
                path_rule(collection,'Windows','%WINDIR%\\*');path_rule(collection,'Program Files','%PROGRAMFILES%\\*')
        for rule in control['rules']:
            if rule['collection']!=kind:continue
            action='Deny' if control['mode']=='denylist' else 'Allow'
            if rule['type']=='path':path_rule(collection,rule['name'],rule['value'],action=action)
            else:
                node=ET.SubElement(collection,'FileHashRule',Id=str(uuid.uuid5(NAMESPACE,kind+'|'+action+'|'+rule['value'].lower())),Name='GuardDesk: '+rule['name'],Description='GuardDesk SHA-256 policy',UserOrGroupSid='S-1-1-0',Action=action)
                condition=ET.SubElement(node,'Conditions');hashes=ET.SubElement(condition,'FileHashCondition')
                ET.SubElement(hashes,'FileHash',Type='SHA256',Data='0x'+rule['value'].upper(),SourceFileName=rule['name'],SourceFileLength='0')
    return ET.tostring(root,encoding='unicode')


def native_action(directory,action,**values):
    import ctypes
    system=ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(system,len(system)):raise OSError('Windows system directory unavailable')
    exe=Path(system.value)/'WindowsPowerShell/v1.0/powershell.exe'
    script=Path(__file__).with_name('windows')/'applications.ps1'
    result=subprocess.run([str(exe),'-NoLogo','-NoProfile','-NonInteractive','-File',str(script),'-Action',action],input=json.dumps({'state_dir':str(directory),**values}).encode('utf-8'),capture_output=True,timeout=60,creationflags=subprocess.CREATE_NO_WINDOW|subprocess.BELOW_NORMAL_PRIORITY_CLASS)
    if result.returncode:raise OSError(result.stderr.decode('utf-8',errors='replace')[-700:])
    return json.loads(result.stdout.decode('utf-8-sig'))


class ExtendedWorker:
    def __init__(self,agent,*,start_documents=True):
        self.agent=agent;self.directory=agent.config_path.parent/'applications';self.directory.mkdir(exist_ok=True)
        self.collector=None;self.signature=None;self.policy=None;self.status={};self.next_verify=0;self.block_collector=None
        self.documents=None
        self.start_documents=start_documents

    def configure_documents(self):
        from .custom_client import load_custom
        load_custom(self.agent)
        rules=(getattr(self.agent,'custom_packet',None) or {}).get('documents',{}).get('rules',[])
        if self.policy['file_audit']['enabled'] or rules or (self.directory/'document-sacl.sqlite3').exists():
            if self.documents is None:
                from .document_worker import DocumentWorker
                child=DocumentWorker(self.agent,self.directory)
                if self.start_documents:self.documents=child.start()
                else:
                    # Installer --once applies controls; the registered native
                    # worker owns long-lived ETW/context/SACL collection.
                    self.documents=child
                    child.report={'status':'waiting_persistent_worker'}
                    child.read_report={'status':'waiting_persistent_worker','source':'general_file_policy'}
                    child.copy_report={'status':'waiting_persistent_worker','whole_file_copy_confirmed':False}
        if self.documents:self.documents.policy=self.policy

    def configure(self):
        packet=self.agent.call('/api/agent/extended-policy',{})
        if packet.get('device_id')!=self.agent.config['device_id']:raise ValueError('端點識別不符')
        from .policy import decode_agent_policy,agent_policy_wire
        has_target_projection='target_controls' in packet
        if not has_target_projection:
            with self.agent.db() as db:cached_targets=db.execute("SELECT value FROM state WHERE key='extended_target_controls'").fetchone()
            if cached_targets:packet['target_controls']=json.loads(cached_targets[0])
        policy=decode_agent_policy(packet)['body']
        from .browser_dispatch import sync
        self.browser_deployment_status=sync(self.agent,packet.get('browser_dispatch'),native=True,enabled=policy['browser_audit'])
        if policy['browser_audit']:
            from .browser_trust import sync as sync_trust
            self.browser_deployment_status['tls_trust']=sync_trust(self.agent,packet.get('browser_trust'))
        wire=agent_policy_wire({'body':policy})
        with self.agent.db() as db:
            db.execute("INSERT OR REPLACE INTO state VALUES ('extended_policy',?)",(json.dumps(wire['body']),))
            db.execute("INSERT OR REPLACE INTO state VALUES ('extended_audit_options',?)",(json.dumps(wire['audit_options']),))
            if has_target_projection:
                db.execute("INSERT OR REPLACE INTO state VALUES ('extended_target_controls',?)",(json.dumps(wire['target_controls']),))
            if 'file_access_options' in wire:db.execute("INSERT OR REPLACE INTO state VALUES ('extended_file_access_options',?)",(json.dumps(wire['file_access_options']),))
            else:db.execute("DELETE FROM state WHERE key='extended_file_access_options'")
        self.policy=policy
        if has_target_projection:
            desired=hashlib.sha256(json.dumps(policy['website_control'],sort_keys=True).encode()).hexdigest()
            import time
            if desired!=getattr(self,'website_signature',None) or time.monotonic()>=getattr(self,'website_verify_at',0):
                try:
                    if policy['website_control']['enabled'] or any((self.agent.config_path.parent/('website-policy-'+b+'.json')).exists() for b in ('chrome','edge')):
                        from .website_control import sync as sync_website
                        self.website_status=sync_website(self.agent,policy['website_control'])
                    else:self.website_status={'protocol':1,'state':'disabled','browsers':{}}
                    self.website_signature=desired;self.website_verify_at=time.monotonic()+900
                except (OSError,ValueError):
                    self.website_status={'protocol':1,'state':'failed','reason':'protected_worker_or_registry_unavailable'}
                    self.website_signature=desired;self.website_verify_at=time.monotonic()+60
        else:self.website_status={'protocol':1,'state':'upstream_unsupported_cached_policy_preserved'}
        from .custom_client import effective_body,load_custom
        load_custom(self.agent)
        self.configure_documents()
        settings=effective_body(self.agent)
        if settings['software'] or settings['compatibility'] or policy['application_publishers']:
            from .custom_windows import trusted_native
            root=trusted_native(self.agent.config)
            if self.agent.config_path!=root/'config.json':raise OSError('Custom application controls require the protected configuration')
        original_policy=policy
        signature=hashlib.sha256(json.dumps({'audit':policy['application_audit'],'control':policy['application_control']},sort_keys=True).encode()).hexdigest()
        self.base_signature=hashlib.sha256(json.dumps({'audit':original_policy['application_audit'],'control':original_policy['application_control']},sort_keys=True).encode()).hexdigest()
        from .category_rules import merge_publishers
        software=merge_publishers(settings['software'],policy['application_publishers'] if 'target_controls' in packet else [])
        if software:signature=hashlib.sha256((signature+json.dumps(software,sort_keys=True)).encode()).hexdigest()
        import time
        if self.signature!=signature or time.monotonic()>=self.next_verify:
            try:
                control=policy['application_control']
                from .process_audit import configure
                self.status=configure(self.directory,policy['application_audit'])
                if control['enabled'] or software or any((self.directory/name).exists() for name in ('applocker-managed.json','appidsvc-original.json')):
                    from .custom_software import publisher_xml
                    result=native_action(self.directory,'Configure',manage_audit=False,audit=policy['application_audit'],enabled=control['enabled'] or bool(software),xml=publisher_xml(control,software) if software else applocker_xml(control) if control['enabled'] else '')
                else:result={'application_control':'disabled'}
                self.status={**result,**self.status,'status':'configured'}
                self.signature=signature
                self.custom_software_hash=hashlib.sha256(json.dumps(settings['software'],sort_keys=True).encode()).hexdigest()
                self.custom_software_count=len(settings['software'])
                self.next_verify=time.monotonic()+900
            except OSError as exc:self.status={**self.status,'status':'failed','error':str(exc)[:500]}
        return self.poll()

    def poll(self):
        if self.policy is None:
            with self.agent.db() as db:
                row=db.execute("SELECT value FROM state WHERE key='extended_policy'").fetchone()
                options=db.execute("SELECT value FROM state WHERE key='extended_audit_options'").fetchone()
                access_options=db.execute("SELECT value FROM state WHERE key='extended_file_access_options'").fetchone()
            if not row:return
            from .policy import decode_agent_policy
            packet={'body':json.loads(row[0])}
            with self.agent.db() as db:targets=db.execute("SELECT value FROM state WHERE key='extended_target_controls'").fetchone()
            if targets:packet['target_controls']=json.loads(targets[0])
            if options:packet['audit_options']=json.loads(options[0])
            if access_options:packet['file_access_options']=json.loads(access_options[0])
            self.policy=decode_agent_policy(packet)['body']
        self.configure_documents()
        report=dict(self.status)
        if 'machine_agent' in self.agent.feature_status:report['machine_agent']=self.agent.feature_status['machine_agent']
        report['website_control']=getattr(self,'website_status',{'protocol':1,'state':'cached_requires_sync'})
        from .serialization import digest,canonical
        report['category_application_control']={'protocol':1,'fingerprint':digest(canonical(self.policy['application_publishers'])),'state':'configured_requires_execution_test' if self.status.get('status')=='configured' else 'pending'}
        if hasattr(self,'browser_deployment_status'):report['browser_deployment']=self.browser_deployment_status
        from . import __version__
        report.update(applied_signature=getattr(self,'base_signature',self.signature),worker_version=__version__)
        if self.documents:
            document_status=self.documents.status()
            report['document_provisioning']=document_status['provisioning'];report['document_copy']=document_status['copy'];report['document_fingerprint']=document_status['fingerprint'];report['document_applied']=document_status['applied']
            report['document_native_read']=document_status.get('read',{'status':'worker_not_reported'})
        from .custom_settings import compatible_policy
        from .custom_client import effective_body
        desired_hash=hashlib.sha256(json.dumps(effective_body(self.agent)['software'],sort_keys=True).encode()).hexdigest()
        self.agent.custom_software_status={'state':'failed' if self.status.get('status')=='failed' else 'reported_requires_execution_test' if getattr(self,'custom_software_hash',None)==desired_hash else 'pending','rules':getattr(self,'custom_software_count',0)}
        import sys
        policy=compatible_policy(self.policy,effective_body(self.agent),sys.getwindowsversion().build if hasattr(sys,'getwindowsversion') else 0)
        if self.policy['application_audit'] or self.policy['file_audit']['enabled']:
            report['document_read']={'status':'collector_failed'}
            try:
                from .windows_events import SecurityCollector,EventLog
                if not self.collector:self.collector=SecurityCollector(self.agent,EventLog())
                # File-open events depend on existing SACLs; this worker never
                # silently traverses the whole disk to add auditing ACLs.
                body=policy
                if self.documents:
                    from .file_access import options
                    if options(policy['file_audit']['exclude_paths'])['mode']=='interactive':
                        body={**policy,'_native_interactive_open_primary':True}
                polled=self.collector.poll(body)
                report['process_audit']={'status':('collecting' if self.status.get('process_audit_enabled') else 'reading_existing_policy_not_verified') if policy['application_audit'] else 'disabled',**polled}
                report['file_open_audit']='compatibility_paused' if body.get('_custom_skip_security_files') else 'native_interactive_primary_security_mutations_preserved' if body.get('_native_interactive_open_primary') else 'collects_existing_sacl_events_no_sacl_provisioning' if policy['file_audit']['enabled'] else 'disabled'
                # Query only, at most once per 15 minutes. Presence of the
                # worker does not prove File System success auditing or SACLs.
                import time
                if time.monotonic()>=getattr(self,'next_read_check',0):
                    from .process_audit import read_flags
                    key='{0CCE921D-69AE-11D9-BED3-505054503030}'
                    try:
                        flags=read_flags(self.directory,(key,))[key]
                        self.read_status={'status':'existing_sacl_only' if flags&1 else 'audit_policy_missing','success_auditing':bool(flags&1),'sacl_coverage':'not_provisioned','checked_at':time.time()}
                    except OSError:
                        self.read_status={'status':'prerequisite_check_failed','checked_at':time.time()}
                    self.next_read_check=time.monotonic()+900
                report['document_read']={'status':'compatibility_paused'} if body.get('_custom_skip_security_files') else {'status':'disabled'} if not policy['file_audit']['enabled'] else self.read_status
                with self.agent.db() as db:
                    last=db.execute("SELECT value FROM state WHERE key='document_last_read'").fetchone()
                if last:report['document_read']={**report['document_read'],'last_read_observed':float(last[0])}
            except OSError as exc:report['process_audit']={'status':'failed','error':str(exc)[:300]}
        else:
            report['process_audit']={'status':'disabled'}
            report['document_read']={'status':'disabled'}
        if policy['application_control']['enabled'] or effective_body(self.agent)['software'] or (self.directory/'applocker-managed.json').exists():
            try:
                from .windows_events import AppLockerCollector
                if not self.block_collector:self.block_collector=AppLockerCollector(self.agent)
                report['application_block_log']=self.block_collector.poll()
            except OSError as exc:report['application_block_log']={'status':'failed','error':str(exc)[:300]}
        self.agent.flush(max_batches=2,require_empty=False)
        self.agent.call('/api/agent/extended-status',report)
        return report

    def close(self):
        if self.documents:self.documents.close()

    def restore(self):
        if any((self.agent.config_path.parent/('website-policy-'+b+'.json')).exists() for b in ('chrome','edge')):
            from .website_control import sync as sync_website
            from .category_rules import WEBSITE_DEFAULT
            restored=sync_website(self.agent,WEBSITE_DEFAULT)
            if restored['state']=='partial_or_failed':raise OSError('Website policy restoration conflict; preserve journal')
        if self.documents:self.documents.restore()
        elif (self.directory/'document-sacl.sqlite3').exists():
            from .document_worker import DocumentWorker
            DocumentWorker(self.agent,self.directory).restore()
        # Only policies installed by the explicit MIS deployment command are
        # owned here. Keep unrelated browser policies and refuse conflicts.
        if (self.agent.config_path.parent/'browser-policy-owned.json').exists():
            from .browser_deployment import execute,Registry
            execute(None,'restore',self.agent.config_path.parent,Registry())
        if (self.agent.config_path.parent/'browser-trust-owned.json').exists():
            from .browser_trust import protected,execute as restore_trust,WindowsRoots
            config,root=protected(self.agent.config_path)
            if restore_trust(config,'restore',root,WindowsRoots())['status']=='preserved_after_interruption':raise OSError('CA 信任歸屬無法確認；已保留憑證與復原紀錄，請 MIS 核對')
        from .process_audit import configure
        report=configure(self.directory,False)
        if any((self.directory/name).exists() for name in ('applocker-managed.json','appidsvc-original.json')):return {**native_action(self.directory,'Restore'),**report}
        return {'status':'restored',**report}
