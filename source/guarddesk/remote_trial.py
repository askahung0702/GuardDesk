"""Build-time remote-only trial. Never enabled by configuration or center policy."""
import json
import os
import platform
import threading
import time
from pathlib import Path

ENABLED = False
PROFILE = 'remote-only-trial-v1'


def enabled():
    return ENABLED is True


def require_profile(config):
    if not enabled() or config.get('install_profile') != PROFILE:
        raise PermissionError('Remote-only trial build/profile mismatch')


def reject(feature):
    if enabled():raise PermissionError(feature+' unavailable in remote-only trial')


def command_allowed(command):
    # The full Python payload may still contain standard modules; no alternate
    # CLI may activate their collectors, policy adapters or automatic updater.
    if enabled() and command not in {'component-info','endpoint-setup','endpoint-uninstall',
            'usb-install','usb-worker','endpoint-native-install','machine-session','remote-admin-session',
            'serve','server-setup','server-check','add-user','remote-viewer'}:
        raise PermissionError('This remote-only trial disables collection, controls and automatic updates')


def inventory():
    from . import __version__
    return {'agent_version': __version__, 'os': platform.system(),
            'architecture': platform.machine(), 'install_profile': PROFILE,
            'capabilities': ['remote_uninstall_v1','remote_only_trial_v1'],
            'software': [], 'software_coverage': 'disabled_remote_only_trial',
            'collectors': {'remote_only_trial': {'state': 'fixed_disabled_collectors'}}}


def native_diagnostics(supervisor=None,*,launcher=None):
    """Fixed native failure metadata, never WTS accounts, SDP or input data."""
    if launcher is None:launcher=getattr(getattr(supervisor,'platform',None),'native_launcher',None)
    if launcher is None:return None
    snapshot=launcher.snapshot()
    if not isinstance(snapshot,dict):return None
    result={'contexts':[]}
    def clean(error):
        if not isinstance(error,dict):return None
        value={}
        for key in ('phase','error_type','diagnostic'):
            item=error.get(key)
            if isinstance(item,str) and 0<len(item)<=127 and all(c.isascii() and (c.isalnum() or c in '_/:=.-') for c in item):value[key]=item
        code=error.get('native_code')
        if type(code) is int and 0<=code<=0xffffffff:value['native_code']=code
        return value or None
    result['last_failure']=clean(snapshot.get('last_failure'))
    contexts=snapshot.get('contexts',[])
    for item in (contexts if isinstance(contexts,list) else [])[:4]:
        if isinstance(item,dict):
            value=clean({k:item.get(k) for k in ('phase',)}) or {}
            value['error']=clean(item.get('error'))
            if item.get('state') in ('active','stopping','ended'):value['state']=item['state']
            lifecycle=item.get('lifecycle')
            if isinstance(lifecycle,dict) and lifecycle.get('state') in ('starting','negotiating','streaming','recovering','stopping','ended'):
                fields={'state':lifecycle['state']}
                for key,limit in (('lease_remaining_ms',5000),('transient_retries',0xffffffff)):
                    if type(lifecycle.get(key)) is int and 0<=lifecycle[key]<=limit:fields[key]=lifecycle[key]
                value['lifecycle']=fields # observation only, never input authority
            media=item.get('media')
            if isinstance(media,dict):
                # Carry only the bounded, content-free transport counters from
                # the protected launcher through the actual heartbeat boundary.
                fields={}
                for key in ('peer_connected','channel_open','codec_failed','stale_slot'):
                    if type(media.get(key)) is bool:fields[key]=media[key]
                for key in ('capture_sequence','encoded_frames','age_ms'):
                    if type(media.get(key)) is int and 0<=media[key]<=0xffffffffffffffff:fields[key]=media[key]
                if fields:value['media']=fields
            worker=item.get('worker')
            if isinstance(worker,dict):
                fields={}
                for key in ('stage','api','error','polls','acquired','published','resets','age_ms',
                    'input_received','input_accepted','input_rejected','input_stale','moves_coalesced',
                    'queue_high_water','queue_age_max_ms','command_max_ms'):
                    if type(worker.get(key)) is int and 0<=worker[key]<=0xffffffff:fields[key]=worker[key]
                if fields:value['worker']=fields
            ages=[value[k]['age_ms'] for k in ('media','worker') if isinstance(value.get(k),dict) and type(value[k].get('age_ms')) is int]
            value['fresh']=value.get('state')=='active' and len(ages)==2 and max(ages)<=5000
            result['contexts'].append(value)
    return result


def session_diagnostics(snapshot):
    """Bounded startup state only; no WTS identities, paths, PIDs or messages."""
    if not isinstance(snapshot,dict):return None
    result={}
    for key in ('sessions','helpers','errors'):
        value=snapshot.get(key)
        if type(value) is int and 0<=value<=0xffffffff:result[key]=value
    error=snapshot.get('last_error')
    if isinstance(error,dict):
        value={}
        if error.get('operation') in ('query_sessions','launch','session_cycle','supervisor_thread'):value['operation']=error['operation']
        if error.get('type') in ('OSError','PermissionError','FileNotFoundError','TimeoutError','ValueError','ConnectionError','ImportError','ModuleNotFoundError','AttributeError','KeyError','TypeError','RuntimeError'):
            value['error_type']=error['type']
        code=error.get('winerror')
        if type(code) is int and 0<=code<=0xffffffff:value['winerror']=code
        if value:result['last_error']=value
    handoff=snapshot.get('handoff')
    if isinstance(handoff,dict):
        value={}
        if handoff.get('status') in ('ready','waiting'):value['status']=handoff['status']
        if handoff.get('code') in ('journal_in_progress','journal_unavailable','journal_invalid_phase'):
            value['code']=handoff['code']
        if value:result['handoff']=value
    return result or None


def heartbeat(agent,supervisor=None):
    require_profile(agent.config)
    assets=inventory();diagnostics=native_diagnostics(supervisor)
    if diagnostics is not None:assets['collectors']['remote_only_trial']['native_remote']=diagnostics
    startup=session_diagnostics(supervisor.snapshot()) if supervisor is not None and callable(getattr(supervisor,'snapshot',None)) else None
    if startup is not None:assets['collectors']['remote_only_trial']['session_startup']=startup
    return agent.call('/api/agent/heartbeat', {'policy_version': 0, 'inventory': assets},timeout=3)


def no_control_files(config_path):
    # A trial must never adopt/restore a standard installation's controls.
    root=config_path.parent
    forbidden=['usb-original.json','windows','applications','CustomSettings','browser-policy-owned.json',
               'browser-trust-owned.json','website-policy-chrome.json','website-policy-edge.json']
    if any((root/name).exists() for name in forbidden):
        raise PermissionError('Existing control state requires original installer removal')


def no_control_ledgers(agent):
    no_control_files(agent.config_path)
    with agent.db() as db:
        if db.execute('SELECT 1 FROM outbox LIMIT 1').fetchone():
            raise PermissionError('Existing audit outbox cannot be adopted by remote-only trial')


def worker(config, stop, *, once=False, restore=False):
    from .remote_endpoint_state import RemoteEndpointState
    from .machine_agent import eligible, Supervisor
    from .windows_privilege import is_admin
    agent=RemoteEndpointState(config)
    require_profile(agent.config)
    if not is_admin() or not eligible(agent):
        raise PermissionError('Protected installed SYSTEM remote-only worker required')
    no_control_ledgers(agent)
    if restore:
        return {'status':'nothing_to_restore','install_profile':PROFILE}
    if once:
        from .remote_components import read_cohort
        from .update_native import folder
        read_cohort(folder(38)/'USBControl')
        heartbeat(agent)
        return {'status':'configured_remote_only','install_profile':PROFILE}
    from .single_instance import machine_instance
    from .performance import background_work
    with machine_instance('usb',agent.config['device_id']), background_work(), agent.wal_session():
        from .worker_startup import Trace
        trace=Trace(agent.config_path.parent)
        trace.record('construct_supervisor')
        try:
            supervisor=Supervisor(agent,stop)
            trace.record('start_supervisor')
            supervisor.start()
        except Exception as exc:
            trace.record(trace.phase,exc)
            raise
        trace.record('running')
        wrapper=type('RemoteTrialWorker',(),{'agent':agent,'extended_companion':None,
                                         'restore':lambda self:no_control_ledgers(self.agent)})()
        next_heartbeat=0
        failed=False
        try:
            while not stop.is_set():
                from .decommission import native_step
                if native_step(wrapper)=='done':return
                if time.monotonic()>=next_heartbeat:
                    try:heartbeat(agent,supervisor)
                    except (OSError,ValueError,ConnectionError):pass
                    next_heartbeat=time.monotonic()+30
                from .update_client import save
                from . import __version__
                health={'version':__version__,'time':time.time(),'pid':os.getpid(),'install_profile':PROFILE,
                      'native_remote':native_diagnostics(supervisor),
                      'process_diagnostics':supervisor.local_process_diagnostics()}
                startup=session_diagnostics(supervisor.snapshot())
                if startup is not None:health['session_startup']=startup
                save(agent.config_path.parent/'native-health.json',health)
                stop.wait(5)
            if isinstance(getattr(supervisor,'fatal_error',None),dict):
                raise RuntimeError('Machine session supervisor failed; preserve startup diagnostic')
        except Exception as exc:
            failed=True
            trace.record(trace.phase,exc)
            raise
        finally:
            try:supervisor.close()
            except Exception as exc:
                trace.record('stopped',exc)
                raise
            else:
                if not failed:trace.record('stopped')


def session(bootstrap, session_id, stop, request, remote_factory=None):
    """Token-free remote helper; never prepare a profile DB/browser collector."""
    from .remote_windows import RemoteAgent
    from .machine_agent_session import RemoteBridge, config_path
    from .desktop_agent import instance
    from .endpoint_files import plain, save
    from .endpoint_files import secure_directory
    from . import __version__
    if not enabled() or bootstrap['session']!=session_id:
        raise PermissionError('Remote-only bootstrap mismatch')
    path=config_path(bootstrap['device_id'],session_id)
    plain(path)
    # Do not overwrite an existing collector profile or migrate its private data.
    if path.exists():raise PermissionError('Existing collector profile must be removed separately')
    missing=[];parent=path.parent
    while not parent.exists():missing.append(parent);parent=parent.parent
    for parent in reversed(missing):secure_directory(parent)
    status=path.parent/'desktop-status.json'
    remote_stop=threading.Event()
    remote=(remote_factory or RemoteAgent)(RemoteBridge(bootstrap,request),remote_stop,stop)
    def call(route, body, timeout=3):
        return request(route,body,timeout=timeout,parent=bootstrap['parent'],generation=bootstrap['generation'])
    with instance(path) as acquired:
        if not acquired:return
        try:
            if bootstrap['enabled']:remote.start()
            save(status,{'state':'running','pid':os.getpid(),'version':__version__,
                         'install_profile':PROFILE,'started':time.time(),'console_attached':False})
            next_heartbeat=0
            while not stop.is_set() and not remote_stop.is_set():
                try:
                    call('/local/status',{},1)
                except TimeoutError:
                    stop.wait(2);continue
                except (OSError,ValueError,ConnectionError):
                    stop.set();return
                try:
                    if time.monotonic()>=next_heartbeat:
                        call('/api/agent/heartbeat',{'policy_version':0,'inventory':inventory()})
                        next_heartbeat=time.monotonic()+30
                    job=call('/api/agent/uninstall/poll',{'role':'main'}).get('job')
                    if job and job.get('status')!='expired':
                        remote_stop.set();remote.local_stop.set();remote.close_indicator()
                        call('/api/agent/uninstall/status',{'role':'main','job_id':job['id'],'state':'ready','error':''})
                        return
                except (OSError,ValueError,ConnectionError):
                    # Network failure never reopens collectors or extends consent.
                    # Local parent lifetime is checked independently each round.
                    pass
                stop.wait(2)
        finally:
            remote_stop.set();remote.local_stop.set();remote.close_indicator()
            save(status,{'state':'stopped','pid':os.getpid(),'version':__version__,'install_profile':PROFILE})
