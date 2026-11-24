"""Verified downloads and resumable local update transactions; no server shell."""
import http.client
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
from contextlib import nullcontext
from . import __version__
from .endpoint_transport import transport
from .serialization import canonical
from .transport_errors import CenterTransportError
from . import update_packages as packages

class RetryUpdate(ConnectionError):pass

SWITCH_PHASES = ('stopping','old_moved','switching','restarting')


def failure_details(stage,exc):
    """Safe diagnostics only: never persist raw exception text or command lines."""
    stages={'stopping','switching','restarting','health','preflight','download','archive_verify','capacity','extract','verify','authorize','probe'}
    kinds={'OSError','PermissionError','FileNotFoundError','FileExistsError',
           'TimeoutError','TimeoutExpired','ValueError','ConnectionError'}
    value={'stage':stage if stage in stages else 'unknown',
           'type':type(exc).__name__ if type(exc).__name__ in kinds else 'Exception'}
    for key in ('winerror','errno'):
        code=getattr(exc,key,None)
        if type(code) is int and 0<=code<=65535:value[key]=code
    from .update_storage import CapacityError
    if isinstance(exc,CapacityError):
        value.update(type='OSError',code=exc.code)
        for key in ('used_bytes','incoming_bytes','limit_bytes','free_bytes','entries','elapsed_ms','root_index'):
            number=getattr(exc,key,None)
            if type(number) is int and 0<=number<2**63:value[key]=number
    return value


def failure_message(failure):
    labels={'stopping':'停止舊版失敗','switching':'程式目錄切換失敗',
            'restarting':'新版啟動失敗','health':'新版健康檢查失敗'}
    text=labels.get(failure.get('stage'),'更新失敗')
    if type(failure.get('winerror')) is int:text+='（Windows '+str(failure['winerror'])+'）'
    elif type(failure.get('errno')) is int:text+='（errno '+str(failure['errno'])+'）'
    return text+'，已回復前一版'


def _save_plain(path,body):
    path=packages.plain(path);temporary=packages.plain(path.with_suffix('.new'))
    with temporary.open('w',encoding='utf-8') as stream:stream.write(canonical(body));stream.flush();os.fsync(stream.fileno())
    for attempt in range(11):
        try:os.replace(temporary,path);return
        except PermissionError:
            if attempt==10:raise
            time.sleep(.05)


def save(path,body):
    from . import transaction_status
    path=packages.plain(path)
    if path.name in transaction_status.JOURNALS:
        transaction_status.write(path,body,_save_plain)
    else:_save_plain(path,body)


def validate_job(envelope,pinned,device_id,now=None):
    job=packages.verify(envelope,pinned);now=time.time() if now is None else now
    fields={'id','device_id','release_id','created','not_before','expires','allow_downgrade','release'}
    if not isinstance(job,dict) or set(job)-{'transfer_role'}!=fields or job['device_id']!=device_id or not isinstance(job['id'],str) or not re.fullmatch('[0-9a-f]{32}',job['id']):raise ValueError('更新工作不屬於本端點')
    if any(type(job[k]) not in (int,float) for k in ('created','not_before','expires')) or not job['created']<=now+120 or not job['not_before']<=now+120 or not now<job['expires'] or job['expires']-job['created']>38*86400 or job['allow_downgrade'] not in (0,1):raise ValueError('更新工作時間或回復授權不正確')
    if 'transfer_role' in job and job['transfer_role'] not in ('native','main'):raise ValueError('更新下載元件不正確')
    manifest=packages.validate_manifest(packages.verify(job['release'],pinned))
    if manifest['sha256']!=job['release_id']:raise ValueError('更新工作與發布雜湊不符')
    return job,manifest


def partial_path(target,job,manifest):
    role=job.get('transfer_role')
    return packages.plain(target.with_suffix(f'.{role}.{manifest["sha256"]}.part' if role else '.part'))


def download(agent,job,manifest,target,stop=None,rate=1024*1024):
    target=packages.plain(target)
    role=job.get('transfer_role')
    partial=partial_path(target,job,manifest)
    size=manifest['bytes'];expected=manifest['sha256']
    if target.exists() and target.stat().st_size==size and packages.file_hash(target)==expected:return target
    offset=partial.stat().st_size if role and partial.exists() else 0
    if offset>size:
        partial.unlink();raise ValueError('部分更新檔長度不正確')
    if shutil.disk_usage(target.parent).free<size-offset+1024*1024*1024:raise OSError('更新磁碟可用空間不足，保留舊版')
    headers={'Authorization':'Bearer '+agent.config['token']}
    url=agent.config['server'].rstrip('/')+'/api/agent/updates/download?job_id='+job['id']
    if role:url+='&role='+role
    if 0<offset<size:headers['Range']=f'bytes={offset}-'
    started=time.monotonic();count=offset
    try:
        if offset<size:
            opener=transport(agent.config['server'],agent.config.get('ca'))
            request=urllib.request.Request(url,headers=headers)
            with opener.open(request,timeout=15) as response:
                if offset:
                    if response.status==200:count=offset=0
                    elif response.status!=206 or response.headers.get('Content-Range')!=f'bytes {offset}-{size-1}/{size}':
                        raise ValueError('更新續傳範圍不符')
                elif role and response.status!=200:
                    raise ValueError('更新下載回應不正確')
                if response.headers.get('Content-Length')!=str(size-offset):raise ValueError('更新下載長度不符')
                with partial.open('ab' if offset else 'wb') as output:
                    while count<size:
                        if stop and stop.is_set():raise RetryUpdate('更新下載已暫停')
                        if time.monotonic()-started>1200:raise RetryUpdate('更新下載已暫停，等候重試')
                        try:chunk=response.read(min(65536,size-count))
                        except http.client.IncompleteRead as exc:chunk=exc.partial
                        if not chunk:raise RetryUpdate('下載暫時中斷，連線恢復後重試')
                        count+=len(chunk)
                        if count>size:raise ValueError('更新下載超過套件長度')
                        output.write(chunk)
                        delay=(count-offset)/rate-(time.monotonic()-started)
                        if delay>0:
                            if stop:stop.wait(min(delay,.2))
                            else:time.sleep(min(delay,.2))
        if count!=size or packages.file_hash(partial)!=expected:raise ValueError('更新下載不完整或雜湊不符')
        os.replace(partial,target)
        return target
    except urllib.error.HTTPError as exc:
        code=exc.code
        exc.close()
        if code in (408,423,429,502,503,504):
            if not role:partial.unlink(missing_ok=True)
            raise RetryUpdate('等候下載名額或管理中心連線') from None
        partial.unlink(missing_ok=True)
        raise
    except (RetryUpdate,urllib.error.URLError,TimeoutError,ConnectionResetError,ConnectionAbortedError,
            BrokenPipeError,http.client.RemoteDisconnected) as exc:
        if isinstance(exc,urllib.error.URLError) and isinstance(exc.reason,ssl.SSLError):
            partial.unlink(missing_ok=True)
            raise
        if not role:partial.unlink(missing_ok=True)
        if isinstance(exc,RetryUpdate):raise
        raise RetryUpdate('下載暫時中斷，連線恢復後重試') from None
    except Exception:
        partial.unlink(missing_ok=True)
        raise


def probe(app):
    result=subprocess.run([str(app/'GuardDesk.exe'),'component-info'],capture_output=True,timeout=15,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode:raise OSError('新版程式自我檢查失敗')
    body=json.loads(result.stdout)
    packages.version(body.get('version'))
    if body.get('update_protocol')!=1:raise ValueError('新版不支援目前更新協定')
    return body['version']


def verify_tree(app,manifest):
    packages.plain(app)
    found=[]
    for path in app.rglob('*'):
        packages.plain(path)
        if path.is_file():found.append(path.relative_to(app).as_posix())
    if set(found)!=set(manifest['files']):raise ValueError('暫存程式與簽章清單不符')
    for name,expected in manifest['files'].items():
        if packages.file_hash(app/name)!=expected:raise ValueError('暫存程式已被修改')


def remove_managed(parent,target,pattern,privileged=False):
    parent=packages.plain(parent).resolve();target=packages.plain(target)
    if target.parent.resolve()!=parent or not re.fullmatch(pattern,target.name):raise ValueError('拒絕清理更新管理範圍外的路徑')
    if not target.exists():return
    for entry in target.rglob('*'):packages.plain(entry)
    if privileged:
        from .update_native import protected_tree
        protected_tree(target)
    shutil.rmtree(target)


def storage_budget(roots,incoming):
    from .update_storage import budget
    return budget(roots,incoming)


class Transaction:
    """Adapters restrict the privilege boundary; journal is outside program dirs."""
    def __init__(self,agent,role,adapter,*,coordination=None):
        self.agent=agent;self.role=role;self.adapter=adapter
        self.coordination=coordination or nullcontext
        self.root=packages.plain(agent.config_path.parent/'updates');self.root.mkdir(exist_ok=True)
        self.journal=self.root/('transaction-'+role+'.json')

    def report(self,job,state,version,error=''):
        try:
            reply=self.agent.call('/api/agent/updates/status',{'job_id':job['id'],'role':self.role,'state':state,'version':version,'error':error[:250]})
        except CenterTransportError as exc:
            if exc.category not in ('temporary_network','network_unclassified','invalid_reply') and exc.http_status not in (408,423,429,502,503,504):raise
            raise RetryUpdate('等候管理中心重新確認更新狀態') from None
        except (ConnectionError,TimeoutError,json.JSONDecodeError,UnicodeDecodeError,http.client.IncompleteRead):
            raise RetryUpdate('等候管理中心重新確認更新狀態') from None
        if not isinstance(reply,dict) or reply.get('ok') is not True:
            raise RetryUpdate('等候管理中心確認更新狀態')
        return reply

    def write(self,state):save(self.journal,state)

    def finish(self,state,phase,version,error=''):
        state.update(phase=phase,version=version,error=error[:250],reported=False);self.write(state)
        try:self.report(state['job'],phase,version,error)
        except RetryUpdate:return
        state['reported']=True;self.write(state)
        self.receipt(state)

    def receipt(self,state):
        from .update_cache import record
        try:record(self.root,state,save)
        except (OSError,ValueError):
            if not state.get('cleanup_deferred'):state['cleanup_deferred']=True;self.write(state)

    def recover(self):
        if not self.journal.is_file():return
        state=json.loads(self.journal.read_text(encoding='utf-8'))
        from .transaction_status import publish
        publish(self.journal,state,_save_plain)
        if state['phase'] in ('healthy','rolled_back','failed'):
            if not state.get('reported'):
                try:self.report(state['job'],state['phase'],state['version'],state.get('error',''))
                except ConnectionError:return
                state['reported']=True;self.write(state)
            self.receipt(state)
            return
        if state['phase'] in ('authorizing','prepared') and state['job']['expires']<=time.time():
            self.finish(state,'failed',state['old_version'],'更新工作已過期，舊版持續運作')
            return
        if state['phase'] in SWITCH_PHASES:
            with self.coordination():
                if self.adapter.health(state['target'],state['started'],timeout=2):self.finish(state,'healthy',state['target'])
                else:
                    self.adapter.rollback(state)
                    self.finish(state,'rolled_back',state['old_version'],failure_message(state['failure']) if state.get('failure') else '更新中斷，已回復前一版')

    def apply(self,envelope):
        with self.coordination():return self._apply(envelope)

    def _apply(self,envelope):
        job,manifest=validate_job(envelope,self.agent.config['update_key'],self.agent.config['device_id'])
        if job.get('transfer_role',self.role)!=self.role:raise ValueError('更新工作的下載元件不符')
        previous=None
        if self.journal.is_file():
            previous=json.loads(self.journal.read_text(encoding='utf-8'))
            if previous['job']['created']>job['created']:raise ValueError('拒絕重播舊更新工作')
            if previous['phase'] in SWITCH_PHASES:
                raise RetryUpdate('等候原更新交易完成復原')
            if previous['phase'] in ('healthy','rolled_back','failed'):
                if previous['job']['id']==job['id']:return
                if not previous.get('reported'):
                    raise RetryUpdate('等候原更新結果補報')
        current=self.adapter.current()
        if packages.version(manifest['version'])<packages.version(current) and not job['allow_downgrade']:raise ValueError('需要 MIS 明確勾選回復舊版')
        if current==manifest['version'] and self.adapter.health(current,0,timeout=2):
            self.report(job,'healthy',current);return
        directory=packages.plain(self.root/job['id']);directory.mkdir(exist_ok=True)
        resuming_authorization=bool(previous and previous['job']['id']==job['id'] and previous['phase']=='authorizing')
        state=previous if resuming_authorization else {'job':job,'phase':'downloading','old_version':current,'target':manifest['version'],'started':time.time(),'reported':False}
        if not resuming_authorization:
            self.write(state);self.report(job,'downloading',current)
        operation='preflight'
        try:
            # Retry the existing post-health cleanup before the next download.
            # Keep the previous recovery tree; never do this for unknown/active state.
            if previous and previous.get('phase')=='healthy' and previous.get('reported') and previous.get('version')==current and self.adapter.health(current,0,timeout=2):
                try:self.adapter.cleanup(previous)
                except OSError:state['cleanup_deferred']=True;self.write(state)
            from .update_cache import prune
            try:state['pruned_caches']=prune(self.root,job['id'],self.role=='native')
            except (OSError,ValueError):state['cleanup_deferred']=True
            self.write(state)
            archive_path=packages.plain(directory/'package.zip')
            remaining=manifest['bytes']
            if archive_path.is_file() and archive_path.stat().st_size==remaining and packages.file_hash(archive_path)==manifest['sha256']:
                remaining=0
            elif job.get('transfer_role'):
                partial=partial_path(archive_path,job,manifest)
                if partial.is_file():remaining=max(0,remaining-partial.stat().st_size)
            storage_budget([self.root],remaining)
            operation='download';download(self.agent,job,manifest,archive_path)
            operation='archive_verify'
            if packages.file_hash(directory/'package.zip')!=manifest['sha256']:raise ValueError('更新下載已被修改，未停止舊版')
            import zipfile
            with zipfile.ZipFile(directory/'package.zip') as archive:
                packages.inspect_zip(archive,manifest['files']);incoming=sum(i.file_size for i in archive.infolist())
            operation='capacity';stage=self.adapter.stage(job)
            self.adapter.budget(0 if stage.exists() else incoming)
            if not resuming_authorization:self.report(job,'verifying',current)
            operation='extract'
            if not stage.exists():packages.extract(directory/'package.zip',manifest,stage)
            operation='verify';verify_tree(stage,manifest);self.adapter.validate_stage(stage)
            # Freeze cancellation before executing even the candidate's probe.
            operation='authorize';state.update(stage=str(stage),phase='authorizing');self.write(state)
            self.report(job,'applying',current)
            operation='probe'
            if self.adapter.probe(stage)!=manifest['version']:raise ValueError('程式實際版本與發布版本不符')
            state.update(stage=str(stage),phase='prepared');self.write(state)
        except RetryUpdate:raise
        except Exception as exc:
            state['failure']=failure_details(operation,exc)
            try:save(self.root/('last-update-failure-'+self.role+'.json'),{'job_id':job['id'],'target':manifest['version'],'failure':state['failure'],'time':time.time()})
            except OSError:pass
            labels={'preflight':'更新前檢查失敗','download':'更新下載失敗','archive_verify':'更新套件驗證失敗',
                'capacity':'更新容量檢查未通過','extract':'更新暫存解壓失敗','verify':'更新暫存驗證失敗','authorize':'更新授權已失效','probe':'候選程式自我檢查失敗'}
            message=labels[operation]+'；舊版持續運作，尚未停止'
            code=state['failure'].get('code')
            if code=='disk_space':message='更新磁碟可用空間不足；舊版持續運作，尚未停止'
            elif code=='working_set_limit':message='更新工作集 '+str(round((exc.used_bytes+exc.incoming_bytes)/1048576,1))+' MiB 超過 '+str(exc.limit_bytes//1048576)+' MiB；保留舊版與回復副本，尚未停止'
            elif code=='entry_limit':message='更新保留項目數超過上限；舊版持續運作，尚未停止'
            elif code=='scan_timeout':message='更新容量檢查超時；舊版持續運作，尚未停止'
            self.finish(state,'failed',current,message)
            raise
        # This online status is the final authorization check after download.
        state['phase']='stopping';self.write(state)
        operation='stopping'
        try:
            self.adapter.stop()
            operation='switching'
            self.adapter.switch(state,self.write)
            operation='restarting'
            state['phase']='restarting';state['started']=time.time();self.write(state)
            try:self.report(job,'restarting',manifest['version'])
            except ConnectionError:pass  # Already authorized; continue with locally verified bytes.
            self.adapter.start(state,False)
            operation='health'
            if not self.adapter.health(manifest['version'],state['started'],timeout=60):raise OSError('新版未完成健康回報')
        except Exception as exc:
            state['failure']=failure_details(operation,exc)
            try:self.write(state)
            except OSError:pass  # A diagnostic write must not prevent rollback.
            try:self.adapter.rollback(state)
            except Exception as rollback_exc:
                state['rollback_failure']=failure_details('unknown',rollback_exc)
                try:self.write(state)
                except OSError:pass
                raise
            self.finish(state,'rolled_back',current,failure_message(state['failure']))
            return
        self.finish(state,'healthy',manifest['version'])
        if not state['reported']:return
        try:
            self.adapter.cleanup(state)
            for old in self.root.iterdir():
                if old.is_dir() and re.fullmatch('[0-9a-f]{32}',old.name) and old.name!=job['id']:
                    remove_managed(self.root,old,'[0-9a-f]{32}',self.role=='native')
        except OSError:pass  # A browser host can retain an older executable mapping.


class UserAdapter:
    def __init__(self,agent):
        from .desktop_agent import client_root
        self.agent=agent;self.root=agent.config_path.parent.parent.parent
        if self.root.resolve()!=client_root().resolve():raise ValueError('一般 Agent 更新只適用新版簡易安裝')
        self.marker=self.root/'endpoint-install.json';self.old=json.loads(self.marker.read_text(encoding='utf-8'))
        if self.old.get('product')!='GuardDeskEndpoint' or Path(self.old['config']).resolve()!=agent.config_path:raise ValueError('安裝身分不符')
    def current(self):return probe(Path(self.old['app']))
    def probe(self,path):return probe(path)
    def stage(self,job):return packages.plain(self.root/'app'/('update-'+job['id']))
    def validate_stage(self,path):packages.plain(path)
    def budget(self,incoming):storage_budget([self.root/'app',self.agent.config_path.parent/'updates'],incoming)
    def stop(self):
        from .desktop_agent import stop_running
        stop_running(self.agent.config_path,timeout=30)
    def switch(self,state,write):
        state['old_install']=self.old;state['phase']='switching';write(state)
        self._select(Path(state['stage']),state['target'])
    def _select(self,app,version):
        from .endpoint_setup import autostart
        command=subprocess.list2cmdline([str(app/'GuardDeskAgent.exe'),'desktop-agent'])
        current=json.loads(self.marker.read_text(encoding='utf-8'))
        autostart(self.old['startup_name'],command,current['startup_command'])
        updated={**self.old,'app':str(app),'version':version,'startup_command':command,'phase':'ready'}
        save(self.marker,updated)
        native_host=self.agent.config_path.parent/'com.guarddesk.agent.json'
        if native_host.is_file():
            host=json.loads(native_host.read_text(encoding='utf-8'))
            if host.get('name')!='com.guarddesk.agent' or Path(host.get('path','')).name!='GuardDesk.exe':raise OSError('瀏覽器 host 設定不符，停止更新')
            host['path']=str(app/'GuardDesk.exe');save(native_host,host)
        # Maintenance launchers follow the current version after a remote update.
        for name,action in [('Start-Agent.cmd','desktop-agent'),('Stop-Agent.cmd','endpoint-stop'),('Uninstall-Endpoint.cmd','endpoint-uninstall')]:
            exe='GuardDeskAgent.exe' if action=='desktop-agent' else 'GuardDesk.exe'
            (self.root/name).write_text('@echo off\r\nsetlocal DisableDelayedExpansion\r\n"'+str(app/exe).replace('%','%%')+'" '+action+'\r\n'+('pause\r\n' if action!='desktop-agent' else ''),encoding='utf-8')
    def start(self,state,rollback):
        from .endpoint_setup import launch
        launch(Path(self.old['app']) if rollback else Path(state['stage']),self.agent.config_path)
    def health(self,version,started,timeout):
        from .desktop_agent import active
        deadline=time.monotonic()+timeout
        while True:
            try:
                body=json.loads((self.agent.config_path.parent/'runtime-health.json').read_text(encoding='utf-8'))
                if body['version']==version and body['time']>=started and time.time()-body['time']<90 and active(self.agent.config_path):return True
            except (OSError,ValueError,KeyError):pass
            if time.monotonic()>=deadline:return False
            time.sleep(.5)
    def rollback(self,state):
        self.stop()
        if 'old_install' in state:self.old=state['old_install']
        self._select(Path(self.old['app']),self.old['version']);self.start(state,True)
        if not self.health(self.old['version'],time.time()-2,30):raise OSError('舊版一般 Agent 尚未確認復原，請 MIS 檢查')
    def cleanup(self,state):
        keep={Path(self.old['app']).resolve(),Path(state['stage']).resolve()}
        for path in (self.root/'app').iterdir():
            if path.resolve() not in keep and re.fullmatch(r'(update-[0-9a-f]{32}|[0-9.]+-[0-9a-f]{16})',path.name):
                try:remove_managed(self.root/'app',path,r'(update-[0-9a-f]{32}|[0-9.]+-[0-9a-f]{16})')
                except OSError:pass


def apply_user(config,jid):
    from .remote_trial import reject
    reject('Automatic user update')
    from .agent import Agent
    from .desktop_agent import instance
    from .windows_privilege import is_admin
    from .performance import background_work
    if is_admin():raise PermissionError('一般 Agent 更新必須使用實際使用者權限，不以管理員／SYSTEM 執行使用者目錄的程式')
    if not re.fullmatch('[0-9a-f]{32}',jid):raise ValueError('更新工作識別碼不正確')
    agent=Agent(config)
    with instance(str(agent.config_path)+'.update') as acquired,background_work():
        if not acquired:return
        transaction=Transaction(agent,'main',UserAdapter(agent));transaction.recover()
        if transaction.journal.is_file():
            previous=json.loads(transaction.journal.read_text(encoding='utf-8'))
            if previous['job']['id']==jid and previous['phase'] in ('healthy','rolled_back','failed'):
                return
        path=packages.plain(transaction.root/jid/'job.json')
        if path.stat().st_size>600*1024:raise ValueError('更新工作過大')
        envelope=json.loads(path.read_text(encoding='utf-8'))
        try:transaction.apply(envelope)
        except RetryUpdate as exc:
            try:
                job,_=validate_job(envelope,agent.config['update_key'],agent.config['device_id'])
                transaction.report(job,'waiting',__version__,str(exc))
            except ConnectionError:pass
            return
        except Exception:
            state=json.loads(transaction.journal.read_text(encoding='utf-8')) if transaction.journal.is_file() else {}
            if state.get('phase') in ('healthy','rolled_back',*SWITCH_PHASES):return
            try:
                job,_=validate_job(envelope,agent.config['update_key'],agent.config['device_id'])
                transaction.report(job,'failed',__version__,state.get('error') or '一般 Agent 更新未完成，保留日誌與安裝身分，請 MIS 檢查')
            except Exception:pass
            raise


class UserPoller(threading.Thread):
    def __init__(self,agent,stop):
        from .remote_trial import reject
        reject('Automatic user update')
        super().__init__(daemon=True);self.agent=agent;self.stop=stop;self.child=None

    def start_child(self,jid):
        if not isinstance(jid,str) or not re.fullmatch('[0-9a-f]{32}',jid):
            raise ValueError('更新工作識別碼不正確')
        exe=Path(sys.executable).resolve()
        if getattr(sys,'frozen',False) and exe.name=='GuardDeskAgent.exe':
            self.child=subprocess.Popen([str(exe),'apply-user-update','--config',str(self.agent.config_path),'--job-id',jid],creationflags=subprocess.CREATE_NO_WINDOW,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

    def reconcile(self,journal):
        from .desktop_agent import instance
        with instance(str(self.agent.config_path)+'.update') as acquired:
            if not acquired:return False
            state=json.loads(journal.read_text(encoding='utf-8'))
            if state['phase'] not in SWITCH_PHASES:
                Transaction(self.agent,'main',UserAdapter(self.agent)).recover()
                return True
            jid=state['job']['id']
        # Rollback can stop this desktop agent. Only its independent updater
        # may perform it; that process acquires the mutex and rereads the journal.
        self.start_child(jid)
        return False

    def run(self):
        from .update_notify import Waiter,diagnostic
        if not self.agent.config.get('update_key'):diagnostic(self.agent,'main','update_key_missing');return
        if not (self.agent.config_path.parent.parent.parent/'endpoint-install.json').is_file():diagnostic(self.agent,'main','installation_marker_missing');return
        waiter=Waiter('main')
        while not self.stop.is_set():
            if self.child and self.child.poll() is None:self.stop.wait(1);continue
            try:
                journal=packages.plain(self.agent.config_path.parent/'updates'/'transaction-main.json')
                if journal.is_file() and not self.reconcile(journal):
                    self.stop.wait(5)
                    continue
                reply=self.agent.call('/api/agent/updates/poll',{'role':'main','version':__version__,'resume_protocol':True})
                if reply.get('job'):
                    job,manifest=validate_job(reply['job'],self.agent.config['update_key'],self.agent.config['device_id'])
                    if manifest['version']==__version__:
                        self.agent.call('/api/agent/updates/status',{'job_id':job['id'],'role':'main','state':'healthy','version':__version__})
                    else:
                        root=packages.plain(self.agent.config_path.parent/'updates');root.mkdir(exist_ok=True)
                        directory=packages.plain(root/job['id']);directory.mkdir(exist_ok=True);save(directory/'job.json',reply['job'])
                        self.start_child(job['id'])
            except Exception:diagnostic(self.agent,'main','transport_failed')
            waiter.wait(self.agent,self.stop)
