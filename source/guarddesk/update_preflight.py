"""Explicit MIS read-only capacity estimate; never authorizes a center job."""
import hashlib
import json
from pathlib import Path
import re
import sys
import time
import zipfile
from . import __version__,update_packages as packages


class Counter:
    def __init__(self):self.position=0;self.size=0
    def tell(self):return self.position
    def seek(self,position,whence=0):
        if whence!=0 or position<0:raise ValueError('Invalid ZIP counter seek')
        self.position=position;return position
    def write(self,data):
        self.position+=len(data);self.size=max(self.size,self.position);return len(data)
    def flush(self):pass


def candidate_size(source):
    source=packages.plain(source);meta=packages.plain(source/'_internal/agent-release.json')
    if meta.stat().st_size>2*1024*1024:raise ValueError('候選清單過大')
    body=json.loads(meta.read_text(encoding='utf-8'))
    if set(body)!={'format','version','files'} or body['format']!=1 or body['version']!=__version__:raise ValueError('候選版本不符')
    expected={**body['files'],'_internal/agent-release.json':packages.file_hash(meta)}
    from .endpoint_payload import project,entry
    expected,overrides=project(source,expected)
    manifest={'format':1,'version':__version__,'architecture':'windows-x64','sha256':'0'*64,'bytes':1,'files':expected}
    packages.validate_manifest(manifest)
    counter=Counter();total=0;start=time.monotonic()
    with zipfile.ZipFile(counter,'w',zipfile.ZIP_DEFLATED) as archive:
        for name,wanted in sorted(expected.items()):
            digest=hashlib.sha256()
            with entry(source,name,overrides) as stream,archive.open(name,'w') as output:
                while chunk:=stream.read(65536):
                    if time.monotonic()-start>30:raise OSError('候選容量檢查超時')
                    total+=len(chunk)
                    if total>packages.MAX_TOTAL:raise ValueError('候選套件過大')
                    digest.update(chunk);output.write(chunk)
            if digest.hexdigest()!=wanted:raise ValueError('候選內容與清單不符')
    if counter.size>packages.MAX_ZIP:raise ValueError('候選壓縮套件過大')
    return {'compressed_bytes':counter.size,'incoming_bytes':total,'files':len(expected)}


def inspect(device_id):
    from .windows_privilege import is_admin
    from .update_native import folder,check_installed,probe
    from .transaction_status import read_phase
    from .release_scope import profile
    from .update_storage import budget
    import os
    if os.name!='nt' or not is_admin():raise PermissionError('請 MIS 以管理員執行唯讀更新前檢查')
    if not isinstance(device_id,str) or not re.fullmatch('[0-9a-f]{24}',device_id):raise ValueError('端點識別碼不正確')
    if not getattr(sys,'frozen',False):raise ValueError('請使用待發布包的 GuardDesk.exe 執行')
    if profile(__version__)['scope']=='server_only':return {'check_only':True,'agent_update_required':False,'version':__version__}
    checked=check_installed(device_id)
    if not checked['passed']:return {**checked,'capacity_passed':False,'center_confirmation_required':True}
    source=Path(sys.executable).resolve().parent;candidate=candidate_size(source)
    installed=probe(folder(0x26)/'Updater');root=folder(0x23)/'USBControl'/device_id/'updates'
    usage=budget([folder(0x26),root],0)
    projected=usage['used_bytes']+candidate['compressed_bytes']+candidate['incoming_bytes']
    legacy=packages.version(installed)<packages.version('0.4.69')
    limit=512*1024*1024 if legacy else usage['limit_bytes']
    phase=read_phase(root/'transaction-native.json')
    return {'check_only':True,'version':__version__,'installed_updater':installed,'candidate':candidate,
        'usage':usage,'projected_bytes':projected,'limit_bytes':limit,
        'capacity_passed':projected<=limit and usage['free_bytes']>=candidate['compressed_bytes']+candidate['incoming_bytes']+1024**3 and (not legacy or usage['entries']+candidate['files']<=20000),
        'transaction_phase':phase,'center_confirmation_required':True,
        'note':'僅唯讀估算；重試可能重用既有 ZIP，仍按新增 ZIP 保守計算。須另核對中心無進行中工作；不停止、清理、派送或授權更新。'}
