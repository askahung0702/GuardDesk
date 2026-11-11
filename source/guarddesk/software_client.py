"""Protected SYSTEM MSI installer. One durable intent, no arbitrary shell."""
import json
import os
import shutil
import subprocess
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
from . import __version__, update_packages as packages
from .endpoint_transport import transport
from .software_contract import job as validate_job, outcome, version, GIB
from .update_client import save


def download(agent,job,target,stop):
    try:return _download(agent,job,target,stop)
    except urllib.error.HTTPError as exc:
        code=exc.code;exc.close()
        if code in (429,500,502,503,504):raise ConnectionError('MSI download temporarily unavailable') from None
        raise ValueError('MSI download no longer authorized') from None
    except (urllib.error.URLError,TimeoutError,ConnectionResetError,ConnectionAbortedError):
        raise ConnectionError('MSI download interrupted; preserve partial file') from None


def _download(agent,job,target,stop):
    m=job['package'];target=packages.plain(target);part=packages.plain(target.with_suffix('.part'))
    if target.exists() and target.stat().st_size==m['bytes'] and packages.file_hash(target)==m['sha256']:return
    target.unlink(missing_ok=True)
    offset=part.stat().st_size if part.exists() else 0
    if offset>m['bytes']:part.unlink();offset=0
    if offset<m['bytes']:
        headers={'Authorization':'Bearer '+agent.config['token']}
        if offset:headers['Range']='bytes='+str(offset)+'-'
        req=urllib.request.Request(agent.config['server'].rstrip('/')+'/api/agent/software/download?job_id='+job['id'],headers=headers)
        with transport(agent.config['server'],agent.config.get('ca')).open(req,timeout=30) as response:
            if response.status!=(206 if offset else 200) or response.headers.get('Content-Length')!=str(m['bytes']-offset):raise ValueError('Invalid MSI response length')
            if offset and response.headers.get('Content-Range')!=f"bytes {offset}-{m['bytes']-1}/{m['bytes']}":raise ValueError('Invalid MSI range')
            with part.open('ab' if offset else 'wb') as output:
                while offset<m['bytes']:
                    if stop.is_set():raise ConnectionError('Service stopping')
                    chunk=response.read(min(65536,m['bytes']-offset))
                    if not chunk:raise ConnectionError('MSI download interrupted')
                    output.write(chunk);offset+=len(chunk)
                output.flush();os.fsync(output.fileno())
    if packages.file_hash(part)!=m['sha256']:part.unlink();raise ValueError('MSI hash mismatch')
    os.replace(part,target)


def command(msi,system_dir):
    # Arguments are fixed, passed as an argv list, never cmd/PowerShell or shell=True.
    return [str(system_dir/'msiexec.exe'),'/i',str(msi),'/qn','/norestart','ALLUSERS=1','REBOOT=ReallySuppress']


class Worker:
    def __init__(self,agent,stop,root):
        self.agent=agent;self.stop=stop;self.root=root
        self.journal=root/'job.json';self.payload=root/'package.msi'

    def report(self,record):
        self.agent.call('/api/agent/software/result',record['result'])
        record['acknowledged']=True;save(self.journal,record)
        if record['result']['state']!='review_required':
            for path in (self.payload,self.payload.with_suffix('.part')):
                try:path.unlink(missing_ok=True)
                except OSError:pass  # retry cleanup before the next job; no extra copies

    def finish(self,record,state,error='',code=None):
        record['phase']='result';record['result']={'job_id':record['id'],'state':state,'error':error,'exit_code':code}
        save(self.journal,record);self.report(record)

    def cycle(self):
        from .software_msi import inspect,installed_version
        from .native_browser_identity import signed_publisher
        from .update_native import protected_tree
        from .single_instance import machine_instance
        old=None
        if self.journal.exists():
            if self.journal.stat().st_size>16384:raise ValueError('MSI journal too large')
            old=json.loads(self.journal.read_text(encoding='utf-8'))
            if old['phase']=='result' and not old.get('acknowledged'):
                self.report(old);return
            if old['phase']=='intent':
                # A process may have outlived the service. Detection cannot prove that
                # all custom actions finished, so never replay or release the conflict.
                self.finish(old,'review_required','INTERRUPTED_INSTALL_REQUIRES_REVIEW');return
        packet=self.agent.call('/api/agent/software/poll',{'protocol':1,'version':__version__})
        if not packet.get('job'):
            if old and old['phase']=='download':
                status=self.agent.call('/api/agent/software/state',{'job_id':old['id']})
                if status.get('state')=='cancelled':
                    for path in (self.payload,self.payload.with_suffix('.part')):path.unlink(missing_ok=True)
                    save(self.journal,{'id':old['id'],'phase':'result','acknowledged':True,'result':{'job_id':old['id'],'state':'cancelled','error':'','exit_code':None}})
            return
        job=validate_job(packages.verify(packet['job'],self.agent.config['update_key']),self.agent.config['device_id'],time.time())
        if old and old['id']==job['id'] and old['phase']=='result':return
        record={'id':job['id'],'phase':'download','package_hash':job['package']['sha256']}
        if not old or old['id']!=job['id']:
            self.payload.unlink(missing_ok=True);self.payload.with_suffix('.part').unlink(missing_ok=True)
        save(self.journal,record)
        if packet.get('state') in ('installing','review_required'):
            self.finish(record,'review_required','MISSING_LOCAL_INSTALL_RESULT');return
        m=job['package']
        try:
            current=installed_version(m['product_code'])
            if current==m['version']:self.finish(record,'already_installed');return
            if current is not None:
                # Same ProductCode servicing needs vendor-specific reinstall flags.
                self.finish(record,'failed','SAME_PRODUCT_CODE_OTHER_VERSION');return
            # Cache and system volume, conservatively budget download + MSI cache +
            # vendor installation space on each. No whole-disk inventory or backup.
            import ctypes
            from ctypes import wintypes as w
            kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            kernel.GetSystemDirectoryW.argtypes=[w.LPWSTR,w.UINT];kernel.GetSystemDirectoryW.restype=w.UINT
            buffer=ctypes.create_unicode_buffer(32768);n=kernel.GetSystemDirectoryW(buffer,len(buffer))
            if not 0<n<len(buffer):raise ctypes.WinError(ctypes.get_last_error())
            system=Path(buffer.value)
            required=2*m['bytes']+m['install_bytes']+GIB
            for path in (self.root,system):
                if shutil.disk_usage(path).free<required:
                    self.finish(record,'failed','INSUFFICIENT_INSTALL_SPACE');return
            download(self.agent,job,self.payload,self.stop)
            protected_tree(self.root,recursive=False);protected_tree(self.payload)
            actual=inspect(self.payload)
            if any(actual[k]!=m[k] for k in ('name','product_code','version')) or signed_publisher(self.payload)!=m['publisher']:
                self.finish(record,'failed','MSI_METADATA_OR_PUBLISHER_MISMATCH');return
            # Same global installation mutex as our installer, plus Agent updater mutex.
            with machine_instance('native-installer-machine','all-devices'),machine_instance('update',self.agent.config['device_id']):
                protected_tree(self.payload)
                if packages.file_hash(self.payload)!=m['sha256']:raise ValueError('MSI changed before launch')
                if self.stop.is_set():return
                authorization=self.agent.call('/api/agent/software/authorize',{'job_id':job['id']})
                if authorization!={'authorized':True}:raise ValueError('Explicit MSI authorization missing')
                record['phase']='intent';save(self.journal,record)
                process=subprocess.Popen(command(self.payload,system),cwd=self.root,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
                started=time.monotonic();warned=False
                while process.poll() is None:
                    if self.stop.wait(1):return  # preserve intent; never kill third-party MSI
                    if not warned and time.monotonic()-started>3600:
                        try:self.agent.call('/api/agent/software/result',{'job_id':job['id'],'state':'review_required','error':'INSTALL_RUNNING_OVER_ONE_HOUR','exit_code':None});warned=True
                        except (OSError,ConnectionError):pass
                state,error=outcome(process.returncode,installed_version(m['product_code']),m['version'])
                self.finish(record,state,error,process.returncode)
        except ValueError:
            self.finish(record,'review_required' if record['phase']=='intent' else 'failed','MSI_VALIDATION_FAILED')
        except OSError as exc:
            # Transport failure keeps .part/intent; never guess malicious software.
            if record['phase']=='intent':
                self.finish(record,'review_required','INSTALL_API_OR_IO_ERROR',getattr(exc,'winerror',None))
            elif isinstance(exc,ConnectionError):raise
            else:self.finish(record,'failed','INSTALL_PREPARATION_API_OR_IO_ERROR',getattr(exc,'winerror',None))


def start(agent,stop):
    from .machine_service import enabled
    from .remote_trial import enabled as trial
    if not enabled() or trial() or not agent.config.get('update_key'):return None
    from .remote_removal import require_system
    from .custom_windows import trusted_native
    from .update_native import protected_tree
    require_system();root=trusted_native(agent.config)
    if agent.config_path!=root/'config.json':raise PermissionError('Software install requires protected configuration')
    root=packages.plain(root/'Software');root.mkdir(exist_ok=True);protected_tree(root,recursive=False)
    worker=Worker(agent,stop,root)
    def run():
        while not stop.is_set():
            try:
                # Only the fixed bounded working set, including any preexisting ACLs.
                for name in ('job.json','job.new','package.msi','package.part'):
                    path=packages.plain(root/name)
                    if path.exists():protected_tree(path,recursive=False)
                worker.cycle();agent.feature_status['software_install']={'state':'ready','protocol':1}
            except (OSError,ValueError,KeyError) as exc:
                agent.feature_status['software_install']={'state':'attention','error_type':type(exc).__name__}
            stop.wait(20)
    thread=threading.Thread(target=run,name='GuardDesk-MSI',daemon=True);thread.start();return thread
