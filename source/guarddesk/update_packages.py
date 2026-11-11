"""Bounded executable packages and organization-pinned Ed25519 release signatures."""
import base64
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from .serialization import canonical

MAX_ZIP = 64 * 1024 * 1024
MAX_FILES = 5000
MAX_TOTAL = 512 * 1024 * 1024
DEVICE_NAMES={'CON','PRN','AUX','NUL','CONIN$','CONOUT$',*[f'{prefix}{i}' for prefix in ('COM','LPT') for i in '0123456789¹²³']}


def version(value):
    if not isinstance(value,str) or not re.fullmatch(r'(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})',value):raise ValueError('版本格式必須為 x.y.z')
    return tuple(map(int,value.split('.')))


def plain(path):
    path=Path(path).absolute()
    for part in (path,*path.parents):
        if os.path.lexists(part) and (part.is_symlink() or getattr(part.lstat(),'st_file_attributes',0)&0x400):raise ValueError('更新路徑不可包含 junction／符號連結')
    return path


def file_hash(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def safe_name(name):
    if not isinstance(name,str) or len(name)>400 or re.search(r'[\x00-\x1f<>"|?*]',name) or '\\' in name or ':' in name:raise ValueError('更新檔案路徑不正確')
    for part in name.split('/'):
        if part in ('','.','..') or part.endswith((' ','.')) or part.split('.')[0].rstrip(' ').upper() in DEVICE_NAMES:raise ValueError('更新檔案路徑不正確')
    from .remote_trial import enabled
    roots=('GuardDesk.exe','GuardDeskAgent.exe')
    if enabled():roots+=('GuardDeskInstaller.exe','GuardDeskService.exe')
    if name not in roots and not name.startswith('_internal/'):raise ValueError('更新包包含未允許的程式路徑')
    if Path(name).suffix.lower() in ('.key','.pem','.sqlite3') or any(p.casefold() in ('runtime','deployment') for p in name.split('/')):raise ValueError('更新包不可含設定、私鑰或資料庫')
    return name


def public_key(private):return base64.b64encode(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode('ascii')


def key_id(value):
    raw=base64.b64decode(value,validate=True)
    if len(raw)!=32:raise ValueError('更新信任金鑰格式不正確')
    return hashlib.sha256(raw).hexdigest()


def signer(root):
    from .endpoint_files import secure_directory
    folder=plain(Path(root)/'update-signing'); secret=folder/'private.key'; reference=folder/'public.json'
    if not folder.exists():
        secure_directory(folder)
        private=Ed25519PrivateKey.generate()
        with secret.open('xb') as stream:stream.write(private.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
        reference.write_text(canonical({'format':1,'public_key':public_key(private)}),encoding='utf-8')
    plain(secret);plain(reference)
    if not secret.is_file() or secret.stat().st_size!=32 or not reference.is_file() or reference.stat().st_size>4096:raise ValueError('更新簽章金鑰不完整，請 MIS 還原原金鑰，不自動重建')
    private=Ed25519PrivateKey.from_private_bytes(secret.read_bytes())
    if json.loads(reference.read_text(encoding='utf-8'))!={'format':1,'public_key':public_key(private)}:raise ValueError('更新簽章金鑰不一致')
    return private


def trust_file(path):
    path=plain(path)
    if path.stat().st_size>4096:raise ValueError('更新信任檔過大')
    body=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(body,dict) or set(body)!={'format','public_key'} or body['format']!=1:raise ValueError('更新信任檔不正確')
    key_id(body['public_key'])
    return body['public_key']


def sign(private,body):
    raw=canonical(body).encode()
    if len(raw)>512*1024:raise ValueError('更新中繼資料過大')
    return {'payload':body,'key_id':key_id(public_key(private)),'signature':base64.b64encode(private.sign(raw)).decode('ascii')}


def verify(envelope,pinned):
    if not isinstance(envelope,dict) or set(envelope)!={'payload','key_id','signature'} or envelope['key_id']!=key_id(pinned):raise ValueError('更新簽章來源與安裝時信任來源不符')
    raw=canonical(envelope['payload']).encode()
    if len(raw)>512*1024:raise ValueError('更新中繼資料過大')
    try:Ed25519PublicKey.from_public_bytes(base64.b64decode(pinned,validate=True)).verify(base64.b64decode(envelope['signature'],validate=True),raw)
    except Exception:raise ValueError('更新簽章驗證失敗') from None
    return envelope['payload']


def validate_manifest(body):
    if not isinstance(body,dict) or set(body)!={'format','version','architecture','sha256','bytes','files'} or body['format']!=1 or body['architecture']!='windows-x64':raise ValueError('更新包格式不支援')
    version(body['version'])
    if version(body['version'])<(0,4,11):raise ValueError('此版本早於集中更新協定，請使用 0.4.11 以上成品')
    if not re.fullmatch('[0-9a-f]{64}',body['sha256']) or type(body['bytes']) is not int or not 0<body['bytes']<=MAX_ZIP:raise ValueError('更新包大小或雜湊不正確')
    entries=body['files']
    if not isinstance(entries,dict) or not 3<=len(entries)<=MAX_FILES or not {'GuardDesk.exe','GuardDeskAgent.exe'}<=entries.keys():raise ValueError('更新程式清單不完整')
    names=set()
    for name,digest in entries.items():
        safe_name(name)
        if name.casefold() in names or not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('更新清單重複或格式不正確')
        names.add(name.casefold())
    return body


def inspect_zip(archive,expected):
    infos=archive.infolist()
    if len(infos)>MAX_FILES or {i.filename for i in infos}!=set(expected) or len(infos)!=len(expected):raise ValueError('更新壓縮檔與簽章清單不符')
    if sum(i.file_size for i in infos)>MAX_TOTAL:raise ValueError('更新解壓後過大')
    for info in infos:
        safe_name(info.filename)
        if info.is_dir() or info.flag_bits&1 or stat.S_ISLNK(info.external_attr>>16) or info.file_size>MAX_TOTAL or info.file_size>max(1,info.compress_size)*1000:raise ValueError('更新壓縮格式或檔案類型不允許')


def extract(archive_path,manifest,destination):
    validate_manifest(manifest)
    archive_path=plain(archive_path);destination=plain(destination)
    if archive_path.stat().st_size!=manifest['bytes'] or file_hash(archive_path)!=manifest['sha256']:raise ValueError('更新下載完整性驗證失敗')
    if destination.exists():raise ValueError('更新暫存目錄已存在，保留現狀')
    with zipfile.ZipFile(archive_path) as archive:
        inspect_zip(archive,manifest['files'])
        destination.mkdir()
        for name,expected in manifest['files'].items():
            target=plain(destination/name);target.parent.mkdir(parents=True,exist_ok=True)
            digest=hashlib.sha256()
            with archive.open(name) as source,target.open('xb') as output:
                while chunk:=source.read(65536):digest.update(chunk);output.write(chunk)
            if digest.hexdigest()!=expected:raise ValueError('更新檔案內容與簽章不符')
    return destination


def import_release(source,repository):
    """Accept a generic GuardDesk release, repack only its hashed application tree."""
    repository=plain(repository)
    if source.stat().st_size>MAX_ZIP:raise ValueError('發布 ZIP 超過 64 MiB')
    with zipfile.ZipFile(source) as original:
        if len(original.infolist())>10000:raise ValueError('發布 ZIP 檔案過多')
        for meta in ('MANIFEST-SHA256.json','build-info.json'):
            if original.getinfo(meta).file_size>2*1024*1024:raise ValueError('發布中繼資料過大')
        hashes=json.loads(original.read('MANIFEST-SHA256.json'));build=json.loads(original.read('build-info.json'))
        selected={i.filename[10:]:i for i in original.infolist() if i.filename.startswith('GuardDesk/') and not i.is_dir()}
        if len(selected)<3 or len(selected)>MAX_FILES or sum(i.file_size for i in selected.values())>MAX_TOTAL:raise ValueError('發布程式檔案大小或數量不正確')
        if len(selected)!=sum(1 for i in original.infolist() if i.filename.startswith('GuardDesk/') and not i.is_dir()):raise ValueError('發布 ZIP 包含重複路徑')
        version(build['GuardDesk']);digests={}
        from .endpoint_payload import project_manifest,METADATA,CONSOLE_ONLY
        overrides={};excluded=set()
        if METADATA in selected:
            raw=original.read(selected[METADATA])
            if hashlib.sha256(raw).hexdigest()!=hashes.get('GuardDesk/'+METADATA):raise ValueError('發布 ZIP 清單雜湊不符')
            projected,overrides=project_manifest(raw)
            excluded=CONSOLE_ONLY&selected.keys() if overrides else set()
            if overrides:
                inner=json.loads(raw)
                listed={name:hashes.get('GuardDesk/'+name) for name in selected}
                if inner['version']!=build['GuardDesk'] or {**inner['files'],METADATA:hashlib.sha256(raw).hexdigest()}!=listed:
                    raise ValueError('發布 ZIP 內外清單不一致')
        target=repository/'package.tmp'
        with zipfile.ZipFile(target,'x',zipfile.ZIP_DEFLATED) as output:
            for name,info in selected.items():
                safe_name(name)
                if stat.S_ISLNK(info.external_attr>>16) or info.flag_bits&1 or info.file_size>max(1,info.compress_size)*1000:raise ValueError('發布 ZIP 檔案格式不允許')
                digest=hashlib.sha256()
                if name in excluded or name in overrides:
                    with original.open(info) as reader:
                        while chunk:=reader.read(65536):digest.update(chunk)
                    if hashes.get('GuardDesk/'+name)!=digest.hexdigest():raise ValueError('發布 ZIP 檔案雜湊不符')
                    if name in overrides:
                        output.writestr(name,overrides[name]);digests[name]=hashlib.sha256(overrides[name]).hexdigest()
                else:
                    with original.open(info) as reader,output.open(name,'w') as writer:
                        while chunk:=reader.read(65536):digest.update(chunk);writer.write(chunk)
                    digests[name]=digest.hexdigest()
                    if hashes.get('GuardDesk/'+name)!=digests[name]:raise ValueError('發布 ZIP 檔案雜湊不符')
    manifest={'format':1,'version':build['GuardDesk'],'architecture':'windows-x64','sha256':file_hash(target),'bytes':target.stat().st_size,'files':digests}
    validate_manifest(manifest)
    return manifest,target
