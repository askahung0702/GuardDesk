"""Verify a closed, hash-locked build environment before packaging hooks run."""
import base64,hashlib,importlib.metadata,json,os,re,site,sys
from pathlib import Path

def canonical(name):
    return re.sub(r'[-_.]+','-',name).lower()

def verify_record(prefix,distribution):
    checked=0
    for entry in distribution.files or ():
        path=Path(distribution.locate_file(entry)).resolve(strict=True)
        if not path.is_relative_to(prefix):raise ValueError('Dependency RECORD escapes build environment')
        if not entry.hash:
            if path.name=='RECORD' or path.suffix=='.pyc':continue
            raise ValueError('Unhashed dependency file: '+str(entry))
        if entry.hash.mode!='sha256':raise ValueError('Unsupported dependency hash')
        with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').digest()
        if base64.urlsafe_b64encode(digest).decode().rstrip('=')!=entry.hash.value or path.stat().st_size!=entry.size:
            raise ValueError('Installed dependency differs from RECORD: '+str(entry))
        checked+=1
    if not checked:raise ValueError('Dependency RECORD is empty')
    return checked

def verify(root):
    root=Path(root).resolve()
    lock=os.environ.get('GUARDDESK_BUILD_LOCK')
    if not lock:raise ValueError('Explicit reviewed build dependency lock required')
    lock=Path(lock).resolve(strict=True)
    if not lock.is_relative_to(root.parents[1]/'runtime'):raise ValueError('Build lock escaped workspace runtime')
    prefix=Path(sys.prefix).resolve()
    if sys.prefix==sys.base_prefix or site.ENABLE_USER_SITE is not False:
        raise ValueError('Dedicated virtual environment with user site disabled required')
    for value in sys.path:
        path=Path(value or '.').resolve()
        if 'site-packages' in path.parts and not path.is_relative_to(prefix):
            raise ValueError('External site-packages on build path')
    body=json.loads(lock.read_text(encoding='utf-8'))
    expected={canonical(p['name']):p for p in body['packages']}
    if len(expected)!=len(body['packages']):raise ValueError('Duplicate build dependency')
    installed={}
    for dist in importlib.metadata.distributions():
        name=canonical(dist.metadata['Name'])
        if name in installed:raise ValueError('Duplicate installed distribution: '+name)
        installed[name]=dist
    if set(installed)!=set(expected):raise ValueError('Installed dependency set differs from lock')
    required=dict(line.strip().split('==') for filename in ('requirements.txt','requirements-build.txt')
                  for line in (root/filename).read_text().splitlines() if '==' in line)
    for name,version in required.items():
        if expected.get(canonical(name),{}).get('version')!=version:raise ValueError('Source requirements differ from build lock')
    counts={}
    for name,row in expected.items():
        if Path(row['filename']).name!=row['filename']:raise ValueError('Invalid wheel filename')
        wheel=lock.parent/'wheelhouse'/row['filename']
        with wheel.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        if digest!=row['sha256']:raise ValueError('Locked wheel changed: '+name)
        dist=installed[name]
        if dist.version!=row['version']:raise ValueError('Installed dependency version differs: '+name)
        counts[name]=verify_record(prefix,dist)
    import PIL
    if PIL.__version__!=required['Pillow'] or not Path(PIL.__file__).resolve().is_relative_to(prefix):
        raise ValueError('Build imported Pillow outside locked environment')
    return {'environment':str(prefix),'lock_sha256':hashlib.sha256(lock.read_bytes()).hexdigest(),
            'packages':{name:row['version'] for name,row in expected.items()},'record_verified_file_counts':counts,
            'provenance':'Hash-locked wheels and installed RECORD checked; not a malware verdict'}
