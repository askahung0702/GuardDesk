"""Fixed DEV update metadata only; no config/token dump or installed mutation."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
DID='ee44c5652fe51572ce2718af'


def error(exc):return dict(error_type=type(exc).__name__,winerror=getattr(exc,'winerror',None),errno=getattr(exc,'errno',None))


def read(path):
    from guarddesk.update_packages import plain
    path=plain(path)
    with path.open('rb') as stream:raw=stream.read(2*1024*1024+1)
    if len(raw)>2*1024*1024:raise ValueError('Metadata size')
    value=json.loads(raw)
    if not isinstance(value,dict):raise ValueError('Metadata type')
    return value


def usage(path):
    # Only the two fixed GuardDesk update roots, never other files on the disk.
    todo=[path];files=0;size=0;start=time.monotonic();dirs=0
    while todo:
        directory=todo.pop();dirs+=1
        with os.scandir(directory) as entries:
            for entry in entries:
                if time.monotonic()-start>5 or files+dirs>20000:raise TimeoutError('Bounded metadata walk')
                info=entry.stat(follow_symlinks=False)
                if info.st_file_attributes & 0x400:raise ValueError('Reparse point')
                if stat.S_ISDIR(info.st_mode):todo.append(Path(entry.path))
                elif stat.S_ISREG(info.st_mode):files+=1;size+=info.st_size
    return dict(bytes=size,files=files,directories=dirs,seconds=time.monotonic()-start)


def main():
    if os.environ.get('COMPUTERNAME','').upper()!='DEV-01':raise SystemExit('Fixed DEV-01 diagnostic only')
    from guarddesk.windows_controls import is_admin
    from guarddesk.machine_agent_windows import request
    private=Path(os.environ['ProgramData'])/'GuardDeskPilot/USBControl'/DID
    program=Path(os.environ['ProgramFiles'])/'GuardDeskPilot'
    result=dict(observed_at=datetime.datetime.now().astimezone().isoformat(),device_id=DID,
                admin=bool(is_admin()),company_changed=False,scope='fixed_DEV_update_metadata_no_config_or_contents')
    try:result['public_machine_status']=request('/local/status',{},timeout=3)
    except (OSError,ValueError) as exc:result['public_machine_status']=error(exc)
    for name in ('broker-health.json','native-health.json','update-broker-status.json'):
        try:
            body=read(private/name)
            result[name]={k:body[k] for k in ('version','native_version','time','pid','state','code','error_type') if k in body}
        except (OSError,ValueError) as exc:result[name]=error(exc)
    job=None
    for name in ('transaction-native.json','updater-refresh.json'):
        try:
            path=private/'updates'/name;body=read(path)
            selected={k:body[k] for k in ('phase','version','old_version','target','started','reported','job_id') if k in body}
            selected['bytes']=path.stat().st_size
            for key in ('failure','rollback_failure'):
                if isinstance(body.get(key),dict):selected[key]={k:v for k,v in body[key].items() if k in ('stage','type','winerror','errno')}
            if isinstance(body.get('job'),dict):
                job=body['job'];release=job.get('release',{}).get('payload',{})
                selected['job']={k:job.get(k) for k in ('id','created','release_id')}
                selected['release']={k:release.get(k) for k in ('version','bytes','sha256')}
                selected['release']['files']=len(release.get('files',{}))
            result[name]=selected
        except (OSError,ValueError) as exc:result[name]=error(exc)
    for name in ('Updater','USBControl'):
        try:
            body=read(program/name/'_internal/agent-release.json')
            result[name]=dict(version=body.get('version'),files=len(body.get('files',{})))
        except (OSError,ValueError) as exc:result[name]=error(exc)
    if is_admin():
        # These checks are read-only and nonrecursive; do not repair any ACL.
        from guarddesk.update_native import protected_tree
        result['protected_paths']={}
        for label,path in [('program',program),('data',private),('updates',private/'updates')]:
            try:protected_tree(path,recursive=False);result['protected_paths'][label]={'passed':True}
            except (OSError,ValueError) as exc:result['protected_paths'][label]=error(exc)
        result['usage']={}
        for label,path in [('program',program),('updates',private/'updates')]:
            try:result['usage'][label]=usage(path)
            except (OSError,ValueError) as exc:result['usage'][label]=error(exc)
        try:
            result['managed_program_directories']=[p.name for p in program.iterdir() if re.fullmatch(r'(?:Updater|USBControl)(?:\.(?:rollback|stage|failed|install-failed)-[0-9a-f]{16,32})?',p.name)]
        except OSError as exc:result['managed_program_directories']=error(exc)
        if job and re.fullmatch('[0-9a-f]{32}',str(job.get('id',''))):
            path=private/'updates'/job['id']/'package.zip'
            try:
                from guarddesk.update_packages import plain
                path=plain(path);info=path.stat()
                selected=dict(bytes=info.st_size,modified=info.st_mtime)
                if info.st_size<=64*1024*1024:
                    with zipfile.ZipFile(path) as archive:
                        entries=archive.infolist()
                        if len(entries)>5000:raise ValueError('ZIP entries')
                        selected.update(incoming_bytes=sum(i.file_size for i in entries),files=len(entries))
                    digest=hashlib.sha256()
                    with path.open('rb') as stream:
                        for chunk in iter(lambda:stream.read(65536),b''):digest.update(chunk)
                    selected['sha256_matches_manifest']=digest.hexdigest()==job.get('release',{}).get('payload',{}).get('sha256')
                result['current_package']=selected
            except (OSError,ValueError,zipfile.BadZipFile) as exc:result['current_package']=error(exc)
    path=ROOT/'evidence/maintenance'/('dev-update-failure-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'.json')
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False),flush=True)


if __name__=='__main__':main()
