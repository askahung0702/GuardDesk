"""Authenticated fleet summaries and bounded page selection."""
import json
import ipaddress
import re
import time
from . import native_usb,policy_progress,removal
from .management import ManagementError


def catalog(db,plane):
    devices=[];now=time.time()
    for row in db.execute('SELECT id,name,department,last_seen,policy_version,policy_fingerprint,revoked,inventory,group_id,management_revision,last_address,enrolled_at FROM devices ORDER BY last_seen DESC'):
        device=dict(row);device['inventory']=json.loads(device['inventory'])
        device['status']='revoked' if device['revoked'] else 'online' if now-device['last_seen']<90 else 'offline'
        effective=plane.bundle(device)
        device['native_usb']=native_usb.snapshot(db,device['id'],effective['body']['usb_mode'])
        ext=db.execute('SELECT body,received FROM extended_status WHERE device_id=?',(device['id'],)).fetchone()
        device['extended_status']={**json.loads(ext['body']),'received':ext['received']} if ext else None
        device['uninstall']=removal.latest(db,device['id'])
        device.update(expected_version=effective['version'],expected_fingerprint=effective['fingerprint'],group_path=effective['group_path'],policy_received=bool(device['policy_version']==effective['version'] and device['policy_fingerprint']==effective['fingerprint']),policy_conflicts=len(effective['conflicts']))
        device['policy_progress']=policy_progress.progress(device,effective)
        devices.append(device)
    return devices


def compact(device):
    result=dict(device);inventory=device['inventory']
    result['inventory']={key:inventory[key] for key in ('agent_version','user_accounts','outbox','collectors') if key in inventory}
    return result


def matches_query(device,query):
    """Search only existing endpoint identity/network fields, never raw inventory."""
    assets=device['inventory']
    accounts=assets.get('user_accounts')
    addresses=assets.get('network_addresses')
    accounts=[a for a in accounts[:32] if isinstance(a,str)] if isinstance(accounts,list) else []
    addresses=[a for a in addresses[:16] if isinstance(a,str)] if isinstance(addresses,list) else []
    source=device.get('last_address');mac=assets.get('mac_address')
    if isinstance(source,str):addresses.append(source)
    values=[device['name'],device['department'],*accounts,*addresses]
    if isinstance(mac,str):values.append(mac)
    if query in ' '.join(values).casefold():return True
    try:target=ipaddress.ip_address(query)
    except ValueError:target=None
    if target is not None:
        for address in addresses:
            try:
                if ipaddress.ip_address(address)==target:return True
            except ValueError:pass
        return False
    # MAC separators are interchangeable. Other query characters stay literal.
    if isinstance(mac,str):
        clean=lambda value:re.sub(r'[:.\s-]','',value).casefold()
        needle=clean(query);address=clean(mac)
        if re.fullmatch(r'[0-9a-f]{4,12}',needle) and re.fullmatch(r'[0-9a-f]{12}',address) and needle in address:return True
    return False


def page(db,plane,params):
    group=params.get('group',['all'])[0];query=params.get('q',[''])[0][:200].strip().casefold()
    health=params.get('health',['all'])[0];sort=params.get('sort',['name'])[0]
    try:offset=int(params.get('offset',['0'])[0])
    except (ValueError,TypeError):raise ManagementError(400,'端點分頁不正確')
    if not 0<=offset<=100000 or health not in ('all','offline','pending','backlog','failed') or sort not in ('name','seen','backlog'):raise ManagementError(400,'端點篩選不正確')
    if group not in ('all','unassigned','revoked') and group not in plane.groups:raise ManagementError(400,'群組不存在')
    def backlog(d):
        try:return max(0,int(policy_progress.mapping(d['inventory'].get('outbox')).get('pending',0)))
        except (ValueError,TypeError,OverflowError):return 0
    rows=[]
    for d in catalog(db,plane):
        if bool(d['revoked'])!=(group=='revoked'):continue
        if group=='unassigned' and d['group_id']:continue
        if group in plane.groups and group not in [g['id'] for g in plane.chain(d['group_id'])]:continue
        if not matches_query(d,query):continue
        pending=backlog(d)
        if health=='offline' and d['status']!='offline' or health=='pending' and d['policy_received'] or health=='backlog' and pending<=0 or health=='failed' and not any(r['state']=='failed' for r in d['policy_progress']):continue
        rows.append(compact(d))
    def key(d):
        return (d['name'].casefold(),d['id']) if sort=='name' else (-d['last_seen'],d['id']) if sort=='seen' else (-backlog(d),d['id'])
    rows.sort(key=key)
    return {'items':rows[offset:offset+50],'total':len(rows),'offset':offset,'limit':50,'has_more':offset+50<len(rows),'generation':plane.version}
