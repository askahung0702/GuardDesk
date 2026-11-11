"""Signed first deployment through existing authenticated Agent policy traffic.

This projection authorizes only fixed extension settings, never arbitrary
elevated commands or profile writes. Version 0.4.59 carries separately signed
TLS trust authorization. Old Agents ignore that separate projection.
"""
import copy
import json
from .browser_deployment import authorize,verify_authorization


def projection(root):
    from pathlib import Path
    try:return _projection(Path(root))
    except (OSError,ValueError,KeyError,TypeError):return {'status':'publication_unavailable'}


def _projection(root):
    from .browser_publication import selected,public_file
    from .update_packages import signer
    state=selected(root)
    if not state:return {'status':'publication_required'}
    # Verify the exact selected public bytes, not just a policy URL selector.
    for name in state['hashes']:public_file(root,name)
    if not (root/'update-signing/private.key').is_file():raise OSError('Original organization update signer required')
    return {'status':'published','settings':state['settings'],'authorization':authorize(state['settings'],signer(root))}


def adopt(agent,packet):
    """Verify with the EXISTING pin, persist only public signed settings."""
    if not isinstance(packet,dict) or set(packet)!={'status','settings','authorization'} or packet.get('status')!='published':raise ValueError('Invalid browser dispatch projection')
    settings=verify_authorization(packet['settings'],packet['authorization'],agent.config.get('update_key'))
    old=agent.config.get('browser_deployment')
    if old and old!=settings:raise ValueError('Browser identity/source migration requires MIS review')
    from .update_client import save
    current=json.loads(agent.config_path.read_text(encoding='utf-8-sig'))
    for key in ('device_id','token','update_key'):
        if current.get(key)!=agent.config.get(key):raise OSError('Endpoint configuration changed during browser deployment')
    if current.get('browser_deployment') and current['browser_deployment']!=settings:raise OSError('Conflicting browser deployment')
    desired={**current,'browser_deployment':copy.deepcopy(settings),'browser_deployment_authorization':copy.deepcopy(packet['authorization'])}
    changed=desired!=current
    if changed:save(agent.config_path,desired)
    agent.config=desired
    return settings,changed


def sync(agent,packet,*,native=False,enabled=True):
    """Never prevent ordinary auditing/heartbeat when deployment is blocked."""
    if not enabled:return {'status':'audit_disabled'}
    if packet is None:return {'status':'center_upgrade_required'}
    if packet=={'status':'publication_required'}:return {'status':'publication_required'}
    try:
        if native:
            import os,sys
            from pathlib import Path
            from .custom_windows import trusted_native
            from .update_native import folder,protected_tree
            from .windows_privilege import is_admin
            expected=folder(38)/'USBControl/GuardDesk.exe'
            if os.name!='nt' or not is_admin() or not getattr(sys,'frozen',False) or Path(sys.executable).resolve()!=expected.resolve():raise PermissionError('Installed protected native worker required')
            root=trusted_native(agent.config)
            if agent.config_path!=root/'config.json':raise PermissionError('Protected native configuration required')
            protected_tree(root,recursive=False);protected_tree(agent.config_path);protected_tree(expected)
            ledger=root/'browser-policy-owned.json'
            if ledger.exists():protected_tree(ledger)
            settings,_=adopt(agent,packet)
            from .browser_deployment import execute,Registry
            outcome=execute(settings,'apply',root,Registry())
            return {'status':outcome['status'],'policy_applied':True,'browser_installation_verified':False}
        # Called only in the selected installed desktop Agent, not a demo,
        # browser host, SYSTEM broker or disposable --once smoke process.
        from .browser_host import installed_user_host,ensure_user_host
        import sys
        from pathlib import Path
        if not installed_user_host(agent.config_path,Path(sys.executable).with_name('GuardDesk.exe')):return {'status':'installation_not_selected'}
        _,changed=adopt(agent,packet)
        if changed or agent.feature_status.get('browser_deployment',{}).get('status')!='host_ready_await_extension':
            host=ensure_user_host(agent.config_path)
            agent.feature_status['browser_native_host']=host
            if host.get('status')!='registered_awaiting_extension':return {'status':'host_registration_pending'}
        return {'status':'host_ready_await_extension','browser_installation_verified':False}
    except (OSError,ValueError,TypeError,KeyError) as exc:
        return {'status':'deployment_failed','error_type':type(exc).__name__,'winerror':getattr(exc,'winerror',None),'browser_installation_verified':False}
