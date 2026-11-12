"""Portable source staging. Only generated runtime files may be replaced."""
from pathlib import Path
import hashlib,json,os,stat,sys,subprocess

def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def files(root):
    result={};root=Path(root).resolve(strict=True)
    for folder,dirs,names in os.walk(root,followlinks=False):
        dirs[:]=[n for n in dirs if n not in ('__pycache__','.svn','.git')]
        for name in dirs+names:
            path=Path(folder)/name
            if path.lstat().st_file_attributes&stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise ValueError('Reparse point in source/staging: '+str(path))
        for name in names:
            path=Path(folder)/name
            if path.suffix in ('.pyc','.pyo'):continue
            result[path.relative_to(root).as_posix()]=digest(path)
    return result

def contained(root,path):
    root=Path(root).resolve(strict=True);path=Path(path).resolve()
    if path==root or not path.is_relative_to(root):raise ValueError('Path escaped owned checkout')
    return path

def stage(root):
    root=Path(root).resolve(strict=True);source=root/'source'
    expected=files(source)
    runtime=contained(root,root/'runtime');runtime.mkdir(exist_ok=True)
    target=contained(runtime,runtime/'remote-next-src')
    marker=runtime/'source-stage.json'
    old=json.loads(marker.read_text(encoding='utf-8')) if marker.exists() else None
    if target.exists():
        if not old:raise ValueError('Unowned staging directory; preserve it and review')
        for rel,wanted in old['files'].items():
            path=contained(target,target/rel)
            if not path.is_file() or digest(path)!=wanted:
                raise ValueError('Generated source was edited; move edits to source/ first: '+rel)
        for rel in files(target):
            if rel in old['files']:continue
            if rel.startswith(('runtime/','dist/')) or rel in old.get('generated_allowlist',[]):continue
            if rel in ('guarddesk/windows/native/GuardDeskFileTrace.dll','guarddesk/windows/native/document-trace-build.json'):continue
            raise ValueError('Unmanaged file in staged source; preserve and review: '+rel)
    target.mkdir(exist_ok=True)
    if old:
        for rel in old['files'].keys()-expected.keys():
            path=contained(target,target/rel)
            path.unlink()  # only one previously hashed, unchanged generated file
    for rel,wanted in expected.items():
        dest=contained(target,target/rel);dest.parent.mkdir(parents=True,exist_ok=True)
        if not dest.exists() or digest(dest)!=wanted:dest.write_bytes((source/rel).read_bytes())
    # Instructions in the generated tree must point to the canonical checkout.
    entry=target/'AGENTS.md'
    entry.write_text('# Generated source stage\n\nRead ../../AGENTS.md. Edit source/ in the checkout, not this generated directory.\n',encoding='utf-8')
    staged=dict(expected);staged['AGENTS.md']=digest(entry)
    record={'format':1,'files':staged,'canonical_files':expected,'generated_allowlist':[],
            'canonical_source':'source','stage':'runtime/remote-next-src','source_stable':expected==files(source)}
    marker.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    (target/'runtime').mkdir(exist_ok=True)
    return target,record

def environment(root):
    root=Path(root).resolve();env=os.environ.copy()
    env.update(PYTHONNOUSERSITE='1',PYTHONDONTWRITEBYTECODE='1',
        PYTHONPATH=str(root/'runtime/remote-next-src'),
        GUARDDESK_BUILD_LOCK=str(root/'runtime/dev-environment/dependencies.json'))
    return env

def python(root):
    path=Path(root)/'runtime/dev-environment/venv/Scripts/python.exe'
    if not path.is_file():raise ValueError('Run: python dev/bootstrap.py --wheelhouse <folder> (or --download)')
    return path

def webrtc_source(root,explicit=None):
    """Explicit existing checkout only; never downloads or changes Git trust."""
    path=(Path(explicit) if explicit is not None else Path(root)/'runtime/w/src').resolve(strict=True)
    if not (path/'.git').exists():raise ValueError('Pinned WebRTC checkout missing')
    expected=json.loads((Path(root)/'dependencies/toolchains.lock.json').read_text(encoding='utf-8'))['webrtc']['revision']
    result=subprocess.run(['git','-c','safe.directory='+str(path),'-C',str(path),'rev-parse','HEAD'],capture_output=True,text=True,check=True,timeout=30)
    if result.stdout.strip()!=expected:raise ValueError('Pinned WebRTC revision differs')
    dirty=subprocess.run(['git','-c','safe.directory='+str(path),'-C',str(path),'diff','--quiet','HEAD','--'],check=False,timeout=30)
    if dirty.returncode:raise ValueError('Tracked WebRTC source has local changes; preserve and review')
    return path
