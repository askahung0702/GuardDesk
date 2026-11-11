"""Standard-user session collector. No enrollment or machine credential on disk."""
import ctypes
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import re
import sqlite3
import secrets
import sys
import threading
import time
from contextlib import closing


def session_id():
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.ProcessIdToSessionId.argtypes=[w.DWORD,ctypes.POINTER(w.DWORD)]
    value=w.DWORD()
    if not api.ProcessIdToSessionId(os.getpid(),ctypes.byref(value)) or not value.value:
        raise OSError('Interactive user session required')
    return value.value


def config_path(did, session=None):
    if not isinstance(did,str) or not re.fullmatch('[0-9a-f]{24}',did): raise ValueError('Invalid endpoint identity')
    from .desktop_agent import client_root
    return client_root()/'runtime/machine-agent'/did/str(session or session_id())/'agent/config.json'


def cleanup_status(value):
    """Only bounded diagnostic codes may leave a user's session config."""
    if not isinstance(value,dict):return {}
    result={}
    for name in ('browser_host','autostart'):
        item=value.get(name)
        if not isinstance(item,dict) or item.get('state')!='pending_review':continue
        kind=item.get('error_type')
        if kind not in ('OSError','PermissionError','ValueError','JSONDecodeError','FileNotFoundError',
                        'NotADirectoryError','IsADirectoryError','FileExistsError','UnicodeDecodeError'):
            kind='OtherError'
        code=item.get('winerror')
        result[name]={'state':'pending_review','error_type':kind,'winerror':code if type(code) is int and 0<=code<2**31 else None}
    return result


def prepare(bootstrap, session, root=None):
    from .endpoint_files import plain, save
    from .endpoint_files import secure_directory
    from .machine_agent import PIPE
    settings=bootstrap['config'];did=settings['device_id']
    if bootstrap['session']!=session or not isinstance(bootstrap['sid'],str): raise ValueError('Bootstrap logon mismatch')
    if set(settings)-{'server','device_id','update_key','browser_deployment','browser_deployment_authorization'}:
        raise ValueError('Machine bootstrap contains private or unsupported fields')
    target=Path(root) if root else config_path(did,session)
    plain(target)
    from .desktop_agent import client_root
    base=target.parent
    # Create each missing parent atomically/private; never recursively replace
    # an existing directory or follow a user-created reparse point.
    missing=[];parent=base
    while not parent.exists(): missing.append(parent);parent=parent.parent
    for parent in reversed(missing): secure_directory(parent)
    ca=base/'company-ca.pem';raw=bootstrap['ca_pem'].encode('ascii')
    if len(raw)>65536 or b'PRIVATE KEY' in raw: raise ValueError('Invalid public CA')
    plain(ca);ca.write_bytes(raw)
    watch=base/'unused-watch';plain(watch)
    if not watch.exists(): secure_directory(watch)
    legacy=client_root()/'runtime/agent/config.json'
    cleanup={}
    if target.exists():
        previous=json.loads(target.read_text(encoding='utf-8'))
        if previous.get('device_id')!=did or previous.get('server')!=settings['server']:
            raise ValueError('Existing session identity conflict; retain outbox')
        cleanup=cleanup_status(previous.get('legacy_cleanup'))
    elif legacy.exists():
        plain(legacy)
        previous=json.loads(legacy.read_text(encoding='utf-8'))
        if previous.get('device_id')!=did or previous.get('server')!=settings['server']:
            raise ValueError('Existing per-user enrollment conflict; MIS review required')
        if previous.get('proxy_enabled') or (legacy.parent/'windows/installed.json').exists():
            raise OSError('Legacy proxy/SACL controls require MIS migration; preserve old Agent')
        from .desktop_agent import stop_running
        stop_running(legacy)
        # Preserve originals for rollback, never empty the old queue.
        backup=legacy.with_name('pre-machine-config.json');plain(backup)
        if not backup.exists(): backup.write_bytes(legacy.read_bytes())
        source=legacy.with_suffix('.sqlite3');dest=target.with_suffix('.sqlite3');plain(source);plain(dest)
        if source.exists():
            identity=json.dumps({'device_id':did,'server':settings['server'],'source':str(legacy.resolve())},sort_keys=True)
            if dest.exists():
                with closing(sqlite3.connect(dest)) as db:
                    row=db.execute("SELECT value FROM state WHERE key='machine_migration_source'").fetchone()
                if not row or row[0]!=identity:raise OSError('Incomplete session migration; preserve both queues for MIS review')
            else:
                temporary=dest.with_name(dest.name+'.migration-'+secrets.token_hex(8));plain(temporary)
                try:
                    with closing(sqlite3.connect(source)) as old,closing(sqlite3.connect(temporary)) as new:
                        old.backup(new,pages=128,sleep=.01)
                        new.execute("INSERT OR REPLACE INTO state VALUES ('machine_migration_source',?)",(identity,));new.commit()
                    os.replace(temporary,dest)
                finally:temporary.unlink(missing_ok=True)
        # Registration cleanup must retain its ownership guards, but cannot
        # strand an already verified queue migration before config publication.
        # Keep conflicts untouched and report them through the user collector.
        from .browser_host import unregister_owned
        try:unregister_owned(legacy)
        except (OSError,ValueError) as exc:
            cleanup['browser_host']={'state':'pending_review','error_type':type(exc).__name__,'winerror':getattr(exc,'winerror',None)}
        from .endpoint_setup import remove_autostart_for_config
        try:
            marker=legacy.parent.parent.parent/'endpoint-install.json'
            if marker.exists():
                plain(marker);original=marker.with_name('pre-machine-install.json');plain(original)
                if not original.exists():original.write_bytes(marker.read_bytes())
            remove_autostart_for_config(legacy)
        except (OSError,ValueError) as exc:
            cleanup['autostart']={'state':'pending_review','error_type':type(exc).__name__,'winerror':getattr(exc,'winerror',None)}
    value={**settings,'token':'','watch':str(watch),'ca':str(ca) if raw else None,
           'machine_session':{'protocol':1,'pipe':PIPE,'session':session,'sid':bootstrap['sid'],
                              'logon':bootstrap['logon'],'parent':bootstrap['parent'],'generation':bootstrap['generation']}}
    if cleanup:value['legacy_cleanup']=cleanup
    save(target,value)
    if root is None:
        from .machine_agent_windows import installed_image
        import subprocess
        launcher=client_root()/'Start-Agent.cmd';plain(launcher)
        command=subprocess.list2cmdline([str(installed_image().with_name('GuardDeskAgent.exe')),'desktop-agent','--config',str(target)])
        launcher.write_bytes(('@echo off\r\nchcp 65001 >nul\r\nsetlocal DisableDelayedExpansion\r\n'+command.replace('%','%%')+'\r\n').encode('utf-8'))
    from .agent import Agent
    agent=Agent(target)
    with agent.db() as db:
        # Preserve an existing policy/cursors; on a new B login seed the last
        # protected policy even offline, before the first center heartbeat.
        if not db.execute("SELECT 1 FROM state WHERE key='policy'").fetchone():
            db.execute("INSERT INTO state VALUES ('policy',?)",(json.dumps(bootstrap['policy']),))
    return target


class RemoteBridge:
    """Remote-only authenticated IPC; no profile DB, enrollment or credentials."""
    def __init__(self,bootstrap,request):self.bootstrap=bootstrap;self.request=request
    def call(self,path,body,timeout=3):
        if path not in ('/api/agent/remote/poll','/api/agent/remote/update'):raise PermissionError('Remote bridge route unavailable')
        return self.request(path,body,timeout=timeout,parent=self.bootstrap['parent'],generation=self.bootstrap['generation'])


def serve_session(bootstrap,session,stop,request,remote_factory=None,retry_seconds=30):
    """One existing WTS process: remote survives private collector preparation.

    The parent owns lifetime/authentication; collector stop and profile errors
    must not silently remove the computer-wide remote component for user B.
    """
    from . import remote_trial
    if remote_trial.enabled():
        return remote_trial.session(bootstrap,session,stop,request,remote_factory)
    from .remote_windows import RemoteAgent
    from .desktop_agent import run as run_agent
    if bootstrap['session']!=session:raise PermissionError('Remote bootstrap session mismatch')
    remote_stop=threading.Event();collector_stop=threading.Event()
    remote=(remote_factory or RemoteAgent)(RemoteBridge(bootstrap,request),remote_stop,stop)
    def monitor():
        try:
            while not stop.wait(.5):
                try:request('/local/status',{},timeout=1,parent=bootstrap['parent'],generation=bootstrap['generation'])
                except TimeoutError:pass
                except (OSError,ValueError,ConnectionError):stop.set();return
                stop.wait(2)
        finally:collector_stop.set()
    watcher=threading.Thread(target=monitor,name='GuardDesk machine lifetime',daemon=True);watcher.start()
    try:
        if bootstrap['enabled']:remote.start()
        else:
            from .identity import current_account
            try:remote.call('poll',{'account':current_account(),'ready':False,'protocol':3,'readiness':'disabled'})
            except (OSError,ValueError):pass
        while not stop.is_set() and not remote_stop.is_set():
            try:
                packet=request('/local/bootstrap',{},parent=bootstrap['parent'],generation=bootstrap['generation'])
                if any(packet.get(key)!=bootstrap[key] for key in ('parent','generation','session','sid','logon')):
                    stop.set();raise PermissionError('Collector logon changed')
                path=prepare(packet,session)
                collector_stop.clear()
                if stop.is_set():break
                run_agent(path,collector_stop,managed_session=True,managed_remote=remote)
            except (OSError,ValueError,sqlite3.Error):
                # Do not print private paths/config or loop without backoff.
                # The remote component still requires normal user consent.
                pass
            if stop.wait(retry_seconds):break
    finally:
        stop.set();collector_stop.set();remote_stop.set();remote.local_stop.set()
        remote.close_indicator();watcher.join(3)


def run(parent, stop):
    from .machine_agent_windows import request, installed_image
    if not getattr(sys,'frozen',False) or Path(sys.executable).resolve()!=installed_image():
        raise PermissionError('Installed machine session entry required')
    if type(parent) is not int or not 4<parent<2**32:raise ValueError('Invalid parent')
    bootstrap=request('/local/remote-bootstrap',{},parent=parent)
    if bootstrap['parent']!=parent:raise PermissionError('Machine parent changed')
    try:
        session=session_id()
        from .desktop_agent import instance
        path=config_path(bootstrap['device_id'],session)
        with instance(path.with_name('session-bootstrap')) as acquired:
            if acquired:serve_session(bootstrap,session,stop,request)
    finally:stop.set()


def discover(timeout=.5):
    """Read only, token-free machine identity; never enroll another user."""
    from .machine_agent_windows import request
    try: return request('/local/status',{},timeout=timeout)
    except (OSError,ValueError,ConnectionError):
        from .machine_agent_windows import read_marker,installed_image
        marker=read_marker()
        if marker:return {**marker,'status':'supervisor_unavailable'}
        from .desktop_agent import client_root
        if installed_image().exists() and not (client_root()/'runtime/agent/config.json').exists():
            raise OSError('此電腦已有受保護元件，但尚未取得全機身分；請 MIS 修復原安裝，不重新註冊')
        return None
