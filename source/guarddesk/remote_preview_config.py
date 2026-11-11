"""Explicit protected startup opt-in. No HTTP settings or automatic networking."""
import os
from pathlib import Path
from .remote_relay import RelayAuthority,policy,ipv4,require

def parse(value,config_path):
    require(isinstance(value,dict) and {'enabled'}<=set(value)<= {'enabled','console_ipv4','relay','secret_file'})
    require(type(value['enabled']) is bool)
    addresses=value.get('console_ipv4',[])
    require(isinstance(addresses,list) and len(addresses)<=8 and all(isinstance(x,str) for x in addresses) and len(set(addresses))==len(addresses))
    for address in addresses:ipv4(address,False)
    relay=value.get('relay')
    if relay is not None:
        policy(relay);require(value['enabled'] and value.get('secret_file')=='remote-turn.secret')
    else:require('secret_file' not in value)
    require(value['enabled'] or (not addresses and relay is None))
    return {'enabled':value['enabled'],'console_ipv4':list(addresses),'relay':relay,
        'secret_file':Path(config_path).parent/'remote-turn.secret' if relay is not None else None,'config_path':Path(config_path)}

def check_permissions(path,*,secret=False):
    from .update_packages import plain
    path=plain(path)
    if not path.is_file():raise ValueError('Native preview configuration file missing')
    if os.name=='nt':
        from .source_permissions import WindowsSecurity,validate_descriptor,SYSTEM,ADMINISTRATORS,TRUSTED_INSTALLER,NON_GRANTING
        api=WindowsSecurity();allowed={SYSTEM,ADMINISTRATORS,TRUSTED_INSTALLER,api.current_user()}
        require(len(path.parents)<=64)
        def descriptor(item):
            owner,entries=api.descriptor(item)
            # OWNER RIGHTS grants only the object's actual owner. Resolve it
            # against the queried owner; never add the special SID globally
            # to trusted principals or ignore another account's write ACE.
            return owner,[(kind,flags,mask,owner if sid=='S-1-3-4' else sid) for kind,flags,mask,sid in entries]
        for parent in path.parents:validate_descriptor(parent,*descriptor(parent),allowed,ancestor=True)
        owner,entries=descriptor(path);validate_descriptor(path,owner,entries,allowed)
        if secret:
            for kind,flags,mask,sid in entries:
                if flags&8 or kind in NON_GRANTING:continue
                require(not (mask&0x90000001) or (kind==0 and sid in allowed))
    else:
        require(path.stat().st_mode&0o022==0)
        if secret:require(path.stat().st_mode&0o077==0)

def prepare(value):
    if value is None:return None
    if not value['enabled']:return {'enabled':False,'console_ipv4':[],'authority':None}
    check_permissions(value['config_path'])
    authority=None
    if value['relay'] is not None:
        check_permissions(value['secret_file'],secret=True)
        with value['secret_file'].open('rb') as stream:secret=stream.read(131)
        require(len(secret)<=130)
        if secret.endswith(b'\r\n'):secret=secret[:-2]
        elif secret.endswith(b'\n'):secret=secret[:-1]
        require(32<=len(secret)<=128 and all(33<=c<=126 for c in secret))
        authority=RelayAuthority(value['relay'],secret)
    return {'enabled':True,'console_ipv4':list(value['console_ipv4']),'authority':authority}

def apply(server,value):
    if value is None:return
    server.remote_native_preview=value['enabled']
    server.remote_native_console_ipv4=list(value['console_ipv4'])
    server.remote_native_relay_authority=value['authority']
