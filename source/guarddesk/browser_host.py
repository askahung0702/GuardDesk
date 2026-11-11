"""Chrome/Edge native messaging host. Writes directly into the durable outbox."""
import base64
import getpass
import hashlib
import json
import os
import struct
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit,urlunsplit,parse_qsl,urlencode
from .identity import current_account

HOST_NAME='com.guarddesk.agent'
EXTENSION=Path(__file__).resolve().parents[1]/'browser-extension'


def extension_id():
    key=json.loads((EXTENSION/'manifest.json').read_text(encoding='utf-8'))['key']
    digest=hashlib.sha256(base64.b64decode(key)).hexdigest()[:32]
    return ''.join(chr(ord('a')+int(c,16)) for c in digest)


def allowed_extension_ids(config):
    ids=[extension_id()]
    settings=json.loads(Path(config).read_text(encoding='utf-8'))
    if settings.get('browser_deployment'):
        from .browser_deployment import verify_authorization
        desired=verify_authorization(settings['browser_deployment'],settings.get('browser_deployment_authorization'),settings.get('update_key'))['extension_id']
        if desired not in ids:ids.append(desired)
    return ids


def native_read(stream):
    header=stream.read(4)
    if not header:return None
    if len(header)!=4:raise ValueError('Truncated native message')
    size=struct.unpack('<I',header)[0]
    if size>1024*1024:raise ValueError('Native message too large')
    data=stream.read(size)
    if len(data)!=size:raise ValueError('Truncated native message')
    return json.loads(data)


def native_write(stream,value):
    data=json.dumps(value,ensure_ascii=False).encode('utf-8')
    stream.write(struct.pack('<I',len(data))+data);stream.flush()


def sanitize_url(url):
    """Shared URL boundary for extension and built-in history sources."""
    if not isinstance(url,str) or len(url)>8192:raise ValueError('Invalid URL')
    parsed=urlsplit(url)
    if parsed.scheme not in ('http','https') or not parsed.hostname:return None
    host=parsed.hostname
    if ':' in host:host='['+host+']'
    if parsed.port:host+=':'+str(parsed.port)
    sensitive={'token','access_token','id_token','refresh_token','password','passwd','secret','client_secret','authorization','code','sig','signature','api_key','apikey'}
    query=urlencode([(k,'[REDACTED]' if k.casefold() in sensitive else v) for k,v in parse_qsl(parsed.query,keep_blank_values=True,max_num_fields=200)])
    return urlunsplit((parsed.scheme,host,parsed.path,query,'')),parsed.hostname


def handle_message(agent,message):
    from .upload_proxy import pac_script
    if not isinstance(message,dict):raise ValueError('Invalid message')
    username=current_account()
    policy=agent.policy_for_user(username)['body']
    from .decommission import saved
    if saved(agent):
        policy={**policy,'browser_audit':False,'upload_rules':[]}
    if message.get('type')=='status':
        # Legacy extensions remain valid; only the versioned handshake is used
        # as new readiness evidence. Never infer it from host registration.
        if 'extension_version' in message:
            from .document_audit import browser_handshake
            browser_handshake(agent,message)
        wants_proxy=any(r['type']=='domain' for r in policy['upload_rules'])
        proxy_configured=bool(agent.config.get('proxy_enabled'))
        return {'ok':True,'browser_audit':policy['browser_audit'],'pac':pac_script(policy['upload_rules'],agent.config.get('proxy_port',17879)),
                'web_upload_audit':policy['browser_audit'],'memory_upload_v1':True,'proxy_required':wants_proxy and proxy_configured,
                'proxy_policy_state':'proxy_not_configured' if wants_proxy and not proxy_configured else 'configured_requires_runtime_check' if wants_proxy else 'not_required',
                'device_id':agent.config['device_id']}
    if message.get('type') not in ('navigation','page_title','web_upload','upload_gap'):raise ValueError('Unknown native operation')
    if not policy['browser_audit']:return {'ok':True,'recorded':False}
    url=message.get('url','')
    cleaned=sanitize_url(url)
    if not cleaned:return {'ok':True,'recorded':False}
    safe,domain=cleaned
    browser=message.get('browser','chromium')
    if browser not in ('chrome','edge','chromium'):browser='chromium'
    tab=message.get('tab_id')
    if type(tab) is not int:tab=None
    event_id=message.get('event_id')
    if event_id is not None and (not isinstance(event_id,str) or not event_id.startswith('browser-') or len(event_id)>100):raise ValueError('Invalid event identity')
    timestamp=message.get('timestamp')
    occurred=timestamp/1000 if type(timestamp) in (int,float) and 0<=timestamp/1000<=time.time()+300 else time.time()
    title=message.get('title','')
    if not isinstance(title,str) or len(title)>500:raise ValueError('Invalid page title')
    if message['type']=='web_upload':
        from .web_upload import upload_details
        details=upload_details(message,sanitize_url)
        details.update(user=username,browser=browser,tab_id=tab)
        eid=agent.queue('web.upload_'+details['phase'],details,occurred=occurred,event_id=event_id)
        return {'ok':True,'recorded':True,'event_id':eid}
    if message['type']=='upload_gap':
        reason=message.get('reason')
        if reason not in ('request_body_unavailable','queue_capacity','request_capacity','body_metadata_unresolved'):raise ValueError('Invalid gap reason')
        count=message.get('lost_count',0)
        if type(count) is not int or not 0<=count<=2**53-1:raise ValueError('Invalid gap count')
        eid=agent.queue('web.upload_gap',{'source':'browser_webrequest','reason':reason,'lost_count':count,'url':safe,'domain':domain,'user':username,'browser':browser},'warning',occurred=occurred,event_id=event_id)
        return {'ok':True,'recorded':True,'event_id':eid}
    eid=agent.queue('web.page_title' if message['type']=='page_title' else 'web.navigation',{'url':safe,'title':title,'domain':domain,'user':username,'browser':browser,'tab_id':tab,'source':'browser_extension'},occurred=occurred,event_id=event_id)
    return {'ok':True,'recorded':True,'event_id':eid}


def manifest_path_for(config):
    settings=json.loads(Path(config).read_text(encoding='utf-8')) if Path(config).is_file() else {}
    if settings.get('machine_session'):
        from .desktop_agent import client_root
        return client_root()/'runtime/machine-agent'/(HOST_NAME+'.json')
    return Path(config).parent/(HOST_NAME+'.json')


def run_host(config=None,input_stream=None,output_stream=None):
    message=None
    if config is None:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\GuardDesk') as key:config=winreg.QueryValueEx(key,'AgentConfig')[0]
    from .agent import Agent
    settings=json.loads(Path(config).read_text(encoding='utf-8'))
    if settings.get('machine_session'):
        from .machine_agent_session import config_path
        config=config_path(settings['device_id'])
    agent=Agent(config)
    if agent.config.get('machine_session') and input_stream is None:
        import threading
        def lifetime():
            from .machine_agent_windows import request
            parent=agent.config['machine_session']['parent']
            while True:
                time.sleep(2)
                try:request('/local/status',{},timeout=1,parent=parent,generation=agent.config['machine_session']['generation'])
                except TimeoutError:continue
                except (OSError,ValueError,ConnectionError):os._exit(0)
        # A host can sit in stdin forever. On parent replacement only this
        # process exits; committed SQLite/WAL survives, the browser reconnects.
        threading.Thread(target=lifetime,name='GuardDesk Native Host lifetime',daemon=True).start()
    source=input_stream or sys.stdin.buffer;target=output_stream or sys.stdout.buffer
    with agent.wal_session():serve_messages(agent,source,target)


def serve_messages(agent,source,target):
    message=None
    while True:
        try:
            message=native_read(source)
            if message is None:return
            native_write(target,{**handle_message(agent,message),'request_id':message.get('request_id')})
            # User updates select an immutable new application directory. Let
            # Chrome reconnect to its newly registered host on the next alarm,
            # without closing a browser or deleting a mapped old executable.
            if getattr(sys,'frozen',False):
                manifest=manifest_path_for(agent.config_path)
                if manifest.is_file():
                    if manifest.stat().st_size>16384:raise OSError('Native Host manifest exceeds size limit')
                    selected=json.loads(manifest.read_text(encoding='utf-8')).get('path')
                    if isinstance(selected,str) and Path(selected).resolve()!=Path(sys.executable).resolve():return
        except (ValueError,OSError,KeyError,TypeError) as exc:
            native_write(target,{'ok':False,'error':str(exc)[:300],'request_id':message.get('request_id') if isinstance(message,dict) else None})
            if isinstance(exc,OSError):return


def register(config,host_exe=None,*,enable_proxy=True):
    if os.name!='nt':raise OSError('Browser native host requires Windows')
    import winreg
    config=Path(config).resolve()
    if not config.is_file():raise ValueError('請先註冊 Agent')
    default_exe=sys.executable if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[1]/'dist/GuardDesk/GuardDesk.exe'
    executable=Path(host_exe or default_exe).resolve()
    if not executable.is_file():raise ValueError('找不到 GuardDesk.exe；請使用完整 Windows 執行包')
    manifest_path=manifest_path_for(config)
    manifest={'name':HOST_NAME,'description':'GuardDesk disclosed browser audit and upload policy','path':str(executable),'type':'stdio','allowed_origins':['chrome-extension://'+eid+'/' for eid in allowed_extension_ids(config)]}
    encoded=json.dumps(manifest,indent=2)
    if not manifest_path.exists() or manifest_path.stat().st_size>16384 or manifest_path.read_text(encoding='utf-8')!=encoded:
        manifest_path.write_text(encoded,encoding='utf-8')
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,r'Software\GuardDesk') as key:winreg.SetValueEx(key,'AgentConfig',0,winreg.REG_SZ,str(config))
    for key_name in (r'Software\Google\Chrome\NativeMessagingHosts'+'\\'+HOST_NAME,r'Software\Microsoft\Edge\NativeMessagingHosts'+'\\'+HOST_NAME):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER,key_name) as key:winreg.SetValueEx(key,'',0,winreg.REG_SZ,str(manifest_path))
    if enable_proxy:
        settings=json.loads(config.read_text(encoding='utf-8'));settings['proxy_enabled']=True;settings.setdefault('proxy_port',17879)
        config.write_text(json.dumps(settings,ensure_ascii=False),encoding='utf-8')
    return {'extension_id':extension_id(),'manifest':str(manifest_path),'extension_directory':str(EXTENSION),'restart_agent':True}


def installed_user_host(config, executable):
    """Automatic HKCU registration is for a selected installation, not probes.

    A frozen desktop smoke process may use a disposable config. It must never
    claim the signed-in user's live browser registrations, even on a clean HKCU.
    This is a scope check, not a replacement for publisher verification.
    """
    from .endpoint_files import plain
    config=Path(config).resolve();executable=Path(executable).resolve()
    if config.is_file():
        settings=json.loads(config.read_text(encoding='utf-8'))
        if settings.get('machine_session'):
            from .machine_agent_session import config_path
            from .machine_agent_windows import installed_image
            return (config==config_path(settings['device_id']) and executable==installed_image()
                    and Path(sys.executable).resolve()==installed_image())
    root=config.parent.parent.parent;marker=root/'endpoint-install.json'
    if config!=root/'runtime/agent/config.json' or not marker.is_file():return False
    plain(marker);plain(config);plain(executable)
    if marker.stat().st_size>16384:raise ValueError('Endpoint installation marker exceeds size limit')
    state=json.loads(marker.read_text(encoding='utf-8'))
    app=Path(state.get('app','')).resolve()
    return (state.get('product')=='GuardDeskEndpoint'
            and Path(state.get('config','')).resolve()==config
            and app.parent==root/'app' and executable==app/'GuardDesk.exe'
            and Path(sys.executable).resolve()==app/'GuardDeskAgent.exe')


def ensure_user_host(config):
    """Called only by the interactive user's frozen desktop Agent at startup.

    Never enable a proxy or force-install a browser extension as a side effect.
    Preserve a conflicting per-user enrollment instead of redirecting its host.
    """
    if os.name!='nt' or not getattr(sys,'frozen',False):return {'status':'packaged_desktop_required'}
    import winreg
    config=Path(config).resolve()
    executable=Path(sys.executable).with_name('GuardDesk.exe')
    if not installed_user_host(config,executable):return {'status':'installation_not_selected'}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\GuardDesk') as key:
            previous=winreg.QueryValueEx(key,'AgentConfig')[0]
        if not isinstance(previous,str):raise OSError('Existing per-user Native Host belongs to a different enrollment')
        if Path(previous).resolve()!=config:
            if not Path(previous).is_file():raise OSError('Existing per-user Native Host belongs to a different enrollment')
            old=json.loads(Path(previous).read_text(encoding='utf-8'))
            selected=json.loads(config.read_text(encoding='utf-8'))
            if not (old.get('machine_session') and selected.get('machine_session') and old.get('device_id')==selected.get('device_id')):
                raise OSError('Existing per-user Native Host belongs to a different enrollment')
    except FileNotFoundError:pass
    manifest=manifest_path_for(config)
    for key_name in (r'Software\Google\Chrome\NativeMessagingHosts',r'Software\Microsoft\Edge\NativeMessagingHosts'):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,key_name+'\\'+HOST_NAME) as key:previous=winreg.QueryValueEx(key,'')[0]
        except FileNotFoundError:continue
        if not isinstance(previous,str) or Path(previous).resolve()!=manifest:raise OSError('Existing per-user Native Host manifest belongs to a different enrollment')
    register(config,executable,enable_proxy=False)
    return {'status':'registered_awaiting_extension','extension_id':allowed_extension_ids(config)[-1]}


def unregister_owned(config):
    """Do not remove another enrollment's per-user Native Messaging host."""
    config=Path(config).resolve();manifest=manifest_path_for(config)
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\GuardDesk') as key:
            previous=winreg.QueryValueEx(key,'AgentConfig')[0]
    except FileNotFoundError:return
    if not isinstance(previous,str) or Path(previous).resolve()!=config:raise OSError('Native Host enrollment changed; preserve per-user registration')
    keys=(r'Software\Google\Chrome\NativeMessagingHosts'+'\\'+HOST_NAME,r'Software\Microsoft\Edge\NativeMessagingHosts'+'\\'+HOST_NAME)
    for name in keys:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,name) as key:value=winreg.QueryValueEx(key,'')[0]
        except FileNotFoundError:continue
        if not isinstance(value,str) or Path(value).resolve()!=manifest:raise OSError('Native Host manifest changed; preserve per-user registration')
    for name in keys:
        try:winreg.DeleteKey(winreg.HKEY_CURRENT_USER,name)
        except FileNotFoundError:pass
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,r'Software\GuardDesk') as key:
        try:previous=winreg.QueryValueEx(key,'AgentConfig')[0]
        except FileNotFoundError:return
        if not isinstance(previous,str) or Path(previous).resolve()!=config:
            raise OSError('Native Host enrollment changed during cleanup; preserve it')
        winreg.DeleteValue(key,'AgentConfig')


def unregister(config=None):
    if os.name!='nt':raise OSError('Windows required')
    import winreg
    for name in (r'Software\Google\Chrome\NativeMessagingHosts'+'\\'+HOST_NAME,r'Software\Microsoft\Edge\NativeMessagingHosts'+'\\'+HOST_NAME):
        try:winreg.DeleteKey(winreg.HKEY_CURRENT_USER,name)
        except FileNotFoundError:pass
    if config and Path(config).exists():
        path=Path(config);settings=json.loads(path.read_text(encoding='utf-8'));settings['proxy_enabled']=False
        path.write_text(json.dumps(settings,ensure_ascii=False),encoding='utf-8')
    return {'status':'unregistered','note':'停用瀏覽器擴充並重新啟動 Agent；不刪除 outbox'}
