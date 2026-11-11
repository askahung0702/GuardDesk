"""Project a verified center runtime into an endpoint runtime without MIS tools.

The center keeps and verifies its full original manifest. Only the endpoint's
inner manifest is regenerated; signed outer manifests describe those exact
projected bytes. Never rewrites the installed source or an existing release.
"""
import hashlib
import io
import json
from contextlib import contextmanager
from pathlib import Path

METADATA='_internal/agent-release.json'
CONSOLE_ONLY=frozenset({'_internal/GuardDeskMIS.exe'})

def project_manifest(raw):
    if len(raw)>2*1024*1024:raise ValueError('Endpoint source manifest too large')
    body=json.loads(raw)
    if (not isinstance(body,dict) or set(body)!={'format','version','files'} or body['format']!=1
        or not isinstance(body['files'],dict) or METADATA in body['files']):raise ValueError('Endpoint source manifest invalid')
    files=body['files'];removed=CONSOLE_ONLY&files.keys()
    if not removed:return {**files,METADATA:hashlib.sha256(raw).hexdigest()},{}
    clean={name:value for name,value in files.items() if name not in removed}
    projected=json.dumps({**body,'files':clean},sort_keys=True).encode('utf-8')
    return {**clean,METADATA:hashlib.sha256(projected).hexdigest()},{METADATA:projected}

def project(source,expected):
    from .update_packages import plain,file_hash,MAX_TOTAL
    source=Path(source)
    with plain(source/METADATA).open('rb') as stream:raw=stream.read(2*1024*1024+1)
    if len(raw)>2*1024*1024:raise ValueError('Endpoint source manifest too large')
    if hashlib.sha256(raw).hexdigest()!=expected.get(METADATA):raise ValueError('Endpoint source manifest changed')
    original=json.loads(raw)
    if {**original['files'],METADATA:hashlib.sha256(raw).hexdigest()}!=expected:raise ValueError('Endpoint source manifest disagrees')
    # Removed files remain part of the center integrity boundary. Never make
    # a corrupt/foreign MIS disappear merely by excluding it from the ZIP.
    for name in CONSOLE_ONLY&expected.keys():
        path=plain(source/name)
        if path.stat().st_size>MAX_TOTAL or file_hash(path)!=expected[name]:raise ValueError('Center MIS source changed')
    return project_manifest(raw)

@contextmanager
def entry(source,name,overrides):
    from .update_packages import plain,safe_name
    safe_name(name)
    if name in overrides:
        with io.BytesIO(overrides[name]) as stream:yield stream
    else:
        with plain(Path(source)/name).open('rb') as stream:yield stream
