"""Fixed remote sidecar locations, shared by packaging and updater waits.

Paths never come from a caller, a network request or an unsigned manifest.
Presence is not capability/health proof. Development workers are not installed.
"""
import os
import json
import re
from pathlib import Path
from .remote_file_paths import plain,file_hash

REMOTE_IMAGES=('GuardDeskRemoteWorker.exe','GuardDeskRemoteMedia.exe')
REMOTE_FILES=(*REMOTE_IMAGES,'GuardDeskRemoteBridge.dll','GuardDeskMisNative.dll')
ENDPOINT_REMOTE_FILES=(*REMOTE_IMAGES,'GuardDeskRemoteBridge.dll')
MIS_REMOTE_FILES=('GuardDeskMisNative.dll',)
COHORT_MANIFEST='remote-cohort.json'


def cohort_manifest(files,*,build_id):
    """Generate an internal-development manifest, never field acceptance."""
    if set(files)!=set(REMOTE_FILES) or not re.fullmatch('[0-9a-f]{64}',build_id):raise ValueError('Incomplete remote cohort')
    return {'format':1,'private_wire':2,'media_wire':1,'build_id':build_id,
        'state':'development_only_not_deployable','files':dict(files)}


def read_cohort(root,*,role='endpoint'):
    if role not in ('endpoint','mis'):raise ValueError('Unknown remote cohort role')
    required=set(ENDPOINT_REMOTE_FILES if role=='endpoint' else MIS_REMOTE_FILES)
    folder=plain(Path(root)/'_internal'/'remote');path=plain(folder/COHORT_MANIFEST)
    if not path.is_file() or path.stat().st_size>8192:raise ValueError('Remote cohort manifest missing or too large')
    value=json.loads(path.read_text(encoding='utf-8'))
    if (not isinstance(value,dict) or set(value)!={'format','private_wire','media_wire','build_id','state','files'}
        or type(value['format']) is not int or value['format']!=1 or type(value['private_wire']) is not int or value['private_wire']!=2
        or type(value['media_wire']) is not int or value['media_wire']!=1
        or value['state']!='development_only_not_deployable' or not isinstance(value['build_id'],str)
        or not re.fullmatch('[0-9a-f]{64}',value['build_id']) or not isinstance(value['files'],dict)
        or set(value['files'])!=set(REMOTE_FILES)):
        raise ValueError('Remote cohort contract mismatch')
    for name,expected in value['files'].items():
        path=plain(folder/name)
        if not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected):raise ValueError('Remote cohort hash format')
        if not path.exists() and name not in required:continue
        if not path.is_file() or file_hash(path)!=expected:
            raise ValueError('Remote cohort file missing or hash mismatch: '+name)
    return value


def validate_layout(root):
    root=plain(root)
    for name in (*REMOTE_FILES,COHORT_MANIFEST):
        if os.path.lexists(root/name):
            raise ValueError('Remote sidecars must be under _internal/remote; refusing an incomplete endpoint package')
    result=[]
    for name in REMOTE_FILES:
        path=plain(root/'_internal'/'remote'/name)
        if path.exists():
            if not path.is_file():raise ValueError('Remote component must be a regular file')
            result.append(path)
    manifest=plain(root/'_internal'/'remote'/COHORT_MANIFEST)
    if result or manifest.exists():
        if not set(ENDPOINT_REMOTE_FILES)<={p.name for p in result}:raise ValueError('Incomplete remote cohort; refuse before stopping the installed Agent')
        read_cohort(root)
    return result


def installed_images(root):
    root=Path(root)
    from .machine_service import enabled,image
    host=image(root/'GuardDesk.exe')
    return [root/'GuardDesk.exe',*(path for path in validate_layout(root) if path.name in REMOTE_IMAGES),
            *([host] if enabled() and host.exists() else [])]
