"""Privileged Windows adapters. No controls are installed implicitly by demo."""
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from .serialization import canonical

USB_KEY=r'SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
SCRIPT=Path(__file__).with_name('windows')/'controls.ps1'


from .windows_privilege import is_admin


def powershell(action,payload,timeout=120):
    """All variable data travels as JSON stdin, never interpolated shell code."""
    if os.name!='nt':raise OSError('Windows required')
    executable=str(Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe')
    result=subprocess.run([executable,'-NoLogo','-NoProfile','-NonInteractive','-File',str(SCRIPT),'-Action',action],input=canonical(payload).encode('utf-8'),capture_output=True,timeout=timeout,creationflags=subprocess.CREATE_NO_WINDOW|subprocess.BELOW_NORMAL_PRIORITY_CLASS)
    if result.returncode:
        raise OSError(result.stderr.decode('utf-8',errors='replace')[-2000:])
    return json.loads(result.stdout.decode('utf-8-sig'))


def qos_plan(rules):
    # A machine-wide QoS rule per application/user, plus intersections so an app
    # rule cannot override a stricter user rule through precedence.
    apps=[r for r in rules if r['type']=='app'];users=[r for r in rules if r['type']=='user']
    planned=[]
    for rule in apps+users:
        entry={'app':rule['target'] if rule['type']=='app' else None,'user':rule['target'] if rule['type']=='user' else None,'rate_bps':rule['rate_kbps']*1000,'precedence':120}
        planned.append(entry)
    for app in apps:
        for user in users:
            planned.append({'app':app['target'],'user':user['target'],'rate_bps':min(app['rate_kbps'],user['rate_kbps'])*1000,'precedence':200})
    if len(planned)>200:raise ValueError('程式與使用者交叉規則最多 200 項，請減少規則')
    for item in planned:
        item['name']='GuardDesk-'+hashlib.sha256(canonical(item).encode()).hexdigest()[:20]
    return planned


class WindowsControls:
    def __init__(self,agent):
        self.agent=agent
        self.directory=agent.config_path.parent/'windows'
        self.manifest=self.directory/'installed.json'

    @property
    def installed(self):return self.manifest.exists()

    def install(self,policy):
        if not is_admin():raise PermissionError('請使用系統管理員 PowerShell 執行 windows-install')
        with self.agent.db() as db:
            cursor=db.execute("SELECT value FROM state WHERE key='security_cursor'").fetchone()
        if not cursor:
            from .windows_events import EventLog
            high=EventLog().bounds()[1]
            with self.agent.db() as db:
                db.execute("INSERT OR IGNORE INTO state VALUES ('security_cursor',?)",(str(high),))
        self.directory.mkdir(parents=True,exist_ok=True)
        report=powershell('InstallAudit',{'state_dir':str(self.directory),'scope':policy['file_audit']['scope'],'managed':str(self.agent.root),'exclude_paths':policy['file_audit']['exclude_paths']},timeout=600)
        report['root_count']=len(report.get('roots',[]));report['roots']=report.get('roots',[])[:40]
        report['error_count']=len(report.get('errors',[]));report['errors']=[str(e)[:300] for e in report.get('errors',[])[:8]]
        self.manifest.write_text(canonical({'file_audit':report,'config':str(self.agent.config_path),'audit_settings':policy['file_audit'],'audit_checked_at':time.time()}),encoding='utf-8')
        return report

    def apply_usb(self,mode):
        import winreg
        backup=self.directory/'usb-original.json'
        managed=self.directory/'usb-managed.json'
        current={}
        for name in ('Deny_Read','Deny_Write'):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,USB_KEY) as key:
                    value,kind=winreg.QueryValueEx(key,name);current[name]={'value':value,'kind':kind}
            except FileNotFoundError:current[name]=None
        if managed.exists() and current!=json.loads(managed.read_text(encoding='utf-8')):
            raise OSError('USB policy changed outside GuardDesk; preserve company policy and review conflict')
        if not backup.exists():
            backup.write_text(canonical(current),encoding='utf-8')
        previous=json.loads(backup.read_text(encoding='utf-8'))
        desired={'Deny_Read':int(mode=='block'),'Deny_Write':int(mode in ('block','read_only'))}
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,USB_KEY,0,winreg.KEY_SET_VALUE|winreg.KEY_QUERY_VALUE) as key:
            for name,value in desired.items():
                # allow restores prior policy instead of weakening an existing company restriction.
                original=previous.get(name)
                if mode=='allow':
                    if original:winreg.SetValueEx(key,name,0,original['kind'],original['value'])
                    else:
                        try:winreg.DeleteValue(key,name)
                        except FileNotFoundError:pass
                else:
                    # Never weaken a previously configured company denial.
                    if original and original.get('value')==1:value=1
                    winreg.SetValueEx(key,name,0,winreg.REG_DWORD,value)
            actual={}
            managed_state={}
            for name in desired:
                try:
                    value,kind=winreg.QueryValueEx(key,name);actual[name]=value;managed_state[name]={'value':value,'kind':kind}
                except FileNotFoundError:actual[name]=None;managed_state[name]=None
        managed.write_text(canonical(managed_state),encoding='utf-8')
        return {'status':'configured_replug_required','mode':mode,'registry':actual,'scope':'machine_removable_disks'}

    def apply(self,policy):
        if os.name!='nt':return {'status':'unsupported_platform'}
        if not self.installed:return {'status':'not_installed','hint':'以系統管理員執行 windows-install'}
        if not is_admin():return {'status':'requires_admin'}
        result={}
        saved=json.loads(self.manifest.read_text(encoding='utf-8'))
        if policy['file_audit']['enabled']:
            try:
                if saved.get('audit_settings')!=policy['file_audit'] or time.time()-saved.get('audit_checked_at',0)>=900 or saved.get('file_audit',{}).get('status')!='configured':
                    self.install(policy)
            except (OSError,subprocess.TimeoutExpired) as exc:
                result['file_audit']={'status':'failed','error':str(exc)[:500]}
        try:result['usb']=self.apply_usb(policy['usb_mode'])
        except OSError as exc:result['usb']={'status':'failed','error':str(exc)[:500]}
        try:
            rules=qos_plan(policy['upload_rules']);cache_path=self.directory/'qos-status.json'
            cache=json.loads(cache_path.read_text(encoding='utf-8')) if cache_path.exists() else {}
            if not self.agent._qos_verified or cache.get('rules')!=rules or time.time()-cache.get('checked_at',0)>=900 or cache.get('report',{}).get('status') not in ('configured','no_rules'):
                report=powershell('ApplyQos',{'rules':rules,'state_dir':str(self.directory)})
                cache={'rules':rules,'checked_at':time.time(),'report':report}
                cache_path.write_text(canonical(cache),encoding='utf-8')
            result['qos']=cache['report']
            self.agent._qos_verified=result['qos'].get('status') in ('configured','no_rules')
        except (OSError,ValueError,subprocess.TimeoutExpired) as exc:result['qos']={'status':'failed','error':str(exc)[:500]}
        if 'file_audit' not in result:
            result['file_audit']=json.loads(self.manifest.read_text(encoding='utf-8'))['file_audit'] if policy['file_audit']['enabled'] else {'status':'disabled'}
        result['status']='partial' if any(v.get('status') in ('partial','failed','conflict') for v in result.values() if isinstance(v,dict)) else 'configured'
        return result

    def uninstall(self):
        if not is_admin():raise PermissionError('需要系統管理員權限')
        if not self.installed:return {'status':'not_installed'}
        report=powershell('Restore',{'state_dir':str(self.directory)},timeout=600)
        if (self.directory/'usb-original.json').exists():self.apply_usb('allow')
        if report.get('conflicts'):return report
        self.manifest.unlink()
        stamp='.restored-'+str(time.time_ns())
        for name in ('usb-original.json','usb-managed.json','audit-policy.csv','audit-original.json','sacl-backup.json','qos-owned.json','qos-status.json'):
            source=self.directory/name
            if source.exists():source.rename(source.with_name(source.name+stamp))
        return report
