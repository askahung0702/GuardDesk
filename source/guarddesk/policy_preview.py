"""Bounded, non-mutating effective-policy differences for MIS review."""
import copy
import time
from .policy_operations import PATHS, get_value


def compare_planes(before, after, devices, account=None, offset=0, limit=50):
    rows=[];affected=0;changed=0;offline=0;conflicts=0
    now=time.time()
    for device in devices:
        if device['revoked']:
            continue
        old=before.resolve(device,account);new=after.resolve(device,account)
        changes=[]
        for path in sorted(PATHS):
            a,b=get_value(old['body'],path),get_value(new['body'],path)
            if a!=b:
                changes.append({'path':path,'before':a,'after':b,
                                'source':new['setting_sources'][path]})
        source_changed=old['sources']!=new['sources']
        if not changes and not source_changed:
            continue
        affected+=1;changed+=bool(changes);offline+=now-device['last_seen']>=90
        conflicts+=len(new['conflicts'])
        if offset<=affected-1<offset+limit:
            rows.append({'id':device['id'],'name':device['name'],
                         'online':now-device['last_seen']<90,'changes':changes,
                         'conflicts':new['conflicts'],'source_only':not bool(changes)})
    return {'affected_count':affected,'changed_count':changed,'offline_count':offline,
            'conflict_count':conflicts,'items':rows,'offset':offset,'limit':limit,
            'has_more':offset+len(rows)<affected}


def assignment_after(plane,item,identifier=None):
    result=copy.copy(plane)
    result.assignments=[dict(a) for a in plane.assignments if a['id']!=identifier]
    previous=next((a for a in plane.assignments if a['id']==identifier),None)
    result.assignments.append({**item,'id':identifier or 'preview-new',
                               'created':previous['created'] if previous else time.time()})
    return result
