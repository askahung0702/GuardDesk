"""Bounded public CRX/XML service; only verified extension bytes, never keys.

MIS signs offline with the pinned extension identity and imports a small ZIP.
An atomic selector retains previous immutable generations for rollback. No
network fetch, arbitrary file serving, root-CA install or browser-profile edits.
"""
import base64
import hashlib
import io
import json
import os
import re
import struct
import zipfile
from pathlib import Path
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from . import browser_host,browser_release
from .browser_deployment import validate
from .deployment import plain

MAX_BUNDLE=2*1024*1024
PUBLIC_PREFIX='/browser-extension/'


def private_signer(folder,key_file):
    """Validate a tiny key boundary; never recursively scan Server data."""
    plain(folder);plain(key_file)
    if os.name=='nt':
        from .source_permissions import WindowsSecurity,validate_descriptor,SYSTEM,ADMINISTRATORS
        api=WindowsSecurity();allowed={SYSTEM,ADMINISTRATORS,api.current_user()}
        validate_descriptor(folder.parent,*api.descriptor(folder.parent),allowed,ancestor=True)
        for path in (folder,key_file):
            if not path.exists():continue
            owner,entries=api.descriptor(path);validate_descriptor(path,owner,entries,allowed)
            if any(kind==0 and not flags&8 and mask&0x90000001 and sid not in allowed for kind,flags,mask,sid in entries):raise PermissionError('公司擴充金鑰目錄可由其他帳戶讀取；保留原資料，請 MIS 修正權限')
    elif folder.stat().st_mode&0o077 or key_file.exists() and key_file.stat().st_mode&0o077:
        raise PermissionError('Company extension key requires private permissions')


def fields(raw):
    result={};offset=0
    def integer():
        nonlocal offset
        value=0
        for shift in range(0,35,7):
            if offset>=len(raw):raise ValueError('CRX header truncated')
            part=raw[offset];offset+=1;value|=(part&127)<<shift
            if part<128:return value
        raise ValueError('CRX header integer overflow')
    while offset<len(raw):
        tag=integer()
        if tag&7!=2:raise ValueError('Unsupported CRX header field')
        size=integer();end=offset+size
        if end>len(raw) or tag>>3 in result:raise ValueError('Invalid CRX header length/duplicate')
        result[tag>>3]=raw[offset:end];offset=end
    return result


def verify_crx(data,update_url,public_key=None):
    if len(data)>MAX_BUNDLE or len(data)<12 or data[:4]!=b'Cr24':raise ValueError('Invalid CRX')
    version,length=struct.unpack('<II',data[4:12])
    if version!=3 or not 0<length<=32768 or 12+length>=len(data):raise ValueError('Invalid CRX3 header')
    header=fields(data[12:12+length])
    if set(header)!={2,10000}:raise ValueError('Unsupported CRX proof')
    proof=fields(header[2]);signed=fields(header[10000])
    manifest=json.loads((browser_host.EXTENSION/'manifest.json').read_text(encoding='utf-8'))
    expected=base64.b64decode(public_key or manifest['key'],validate=True)
    if set(proof)!={1,2} or proof[1]!=expected or signed!={1:hashlib.sha256(expected).digest()[:16]}:raise ValueError('CRX identity differs from Native Host')
    public=serialization.load_der_public_key(expected)
    if not isinstance(public,rsa.RSAPublicKey) or public.key_size<2048:raise ValueError('Invalid CRX RSA key')
    archive=data[12+length:]
    try:public.verify(proof[2],b'CRX3 SignedData\x00'+struct.pack('<I',len(header[10000]))+header[10000]+archive,padding.PKCS1v15(),hashes.SHA256())
    except Exception as exc:raise ValueError('CRX signature verification failed') from exc
    expected_archive,_=browser_release.archive_source(update_url,public_key)
    if archive!=expected_archive:raise ValueError('CRX source/version differs from this Server; build the matching extension release')
    return manifest['version']


def inspect_bundle(payload):
    if not isinstance(payload,bytes) or not 0<len(payload)<=MAX_BUNDLE:raise ValueError('Publication ZIP too large')
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        entries=archive.infolist()
        if len(entries)!=3 or len({p.filename for p in entries})!=3 or sum(p.file_size for p in entries)>MAX_BUNDLE:raise ValueError('Invalid publication ZIP entries')
        names={p.filename for p in entries}
        if not {'updates.xml','browser-deployment.json'}<=names:raise ValueError('Publication ZIP missing manifest')
        filename=next(iter(names-{'updates.xml','browser-deployment.json'}))
        if not re.fullmatch(r'guarddesk-[0-9]+\.[0-9]+\.[0-9]+\.crx',filename):raise ValueError('Invalid CRX filename')
        if archive.getinfo('browser-deployment.json').file_size>8192 or archive.getinfo('updates.xml').file_size>8192:raise ValueError('Publication metadata too large')
        settings=validate(json.loads(archive.read('browser-deployment.json')))
        url=settings['chrome_update_url']
        if settings['edge_update_url']!=url:raise ValueError('Internal publication requires the same browser source')
        if not url.endswith(PUBLIC_PREFIX+'updates.xml'):raise ValueError('Use the management center HTTPS /browser-extension/ directory')
        crx=archive.read(filename);version=verify_crx(crx,url,settings.get('public_key'))
        if filename!='guarddesk-'+version+'.crx':raise ValueError('CRX version/filename mismatch')
        import xml.etree.ElementTree as ET
        root=ET.Element('gupdate',xmlns='http://www.google.com/update2/response',protocol='2.0')
        app=ET.SubElement(root,'app',appid=settings['extension_id'])
        ET.SubElement(app,'updatecheck',codebase=url.rsplit('/',1)[0]+'/'+filename,version=version)
        xml=ET.tostring(root,encoding='utf-8',xml_declaration=True)
        if archive.read('updates.xml')!=xml:raise ValueError('Update XML differs from verified CRX/source')
        return settings,{'updates.xml':xml,filename:crx},version


def directory(root):
    target=Path(root)/'BrowserPublication';plain(target);return target


def install(root,payload):
    settings,files,version=inspect_bundle(payload)
    prior=selected(root)
    if prior and prior['settings']!=settings:raise ValueError('發布身分或來源已改變；保留原發布，請 MIS 另行執行受控遷移')
    folder=directory(root)
    from .server_setup import secure_directory
    if not folder.exists():secure_directory(folder)
    digest=hashlib.sha256(b''.join(name.encode()+b'\0'+content for name,content in sorted(files.items()))).hexdigest();generation=folder/digest;plain(generation)
    if not generation.exists() and sum(1 for p in folder.iterdir() if p.is_dir())>=64:raise ValueError('已保留 64 份擴充發布；請 MIS 先封存舊版，未自動刪除')
    if not generation.exists():secure_directory(generation)
    for name,content in {**files,'browser-deployment.json':json.dumps(settings,sort_keys=True).encode()}.items():
        target=generation/name;plain(target)
        if target.exists():
            with target.open('rb') as stream:existing=stream.read(MAX_BUNDLE+1)
            if existing!=content:raise ValueError('Publication generation damaged; preserve and reimport a new bundle')
        else:
            with target.open('xb') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
    # Validate existing generation too; incomplete prior imports stay unselected.
    for name,content in files.items():
        with (generation/name).open('rb') as stream:existing=stream.read(MAX_BUNDLE+1)
        if existing!=content:raise ValueError('Publication generation damaged; preserve and reimport a new bundle')
    state={'format':1,'generation':digest,'version':version,'settings':settings,'hashes':{n:hashlib.sha256(b).hexdigest() for n,b in files.items()}}
    import secrets
    temporary=folder/('current-'+secrets.token_hex(8)+'.tmp');plain(temporary)
    try:
        with temporary.open('xb') as stream:stream.write(json.dumps(state,sort_keys=True).encode());stream.flush();os.fsync(stream.fileno())
        from .deployment import replace_with_retry
        replace_with_retry(temporary,folder/'current.json')
    finally:temporary.unlink(missing_ok=True)
    return status(root)


def selected(root):
    folder=directory(root);selector=folder/'current.json';plain(selector)
    if not selector.exists():return None
    if selector.stat().st_size>8192:raise ValueError('Invalid publication selector')
    state=json.loads(selector.read_text(encoding='utf-8'))
    if set(state)!={'format','generation','version','settings','hashes'} or state['format']!=1 or not re.fullmatch('[0-9a-f]{64}',state['generation']):raise ValueError('Invalid publication selection')
    validate(state['settings'])
    expected={'updates.xml','guarddesk-'+state['version']+'.crx'}
    if set(state['hashes'])!=expected:raise ValueError('Invalid publication names')
    for name in expected:
        if not re.fullmatch(r'updates\.xml|guarddesk-[0-9]+\.[0-9]+\.[0-9]+\.crx',name):raise ValueError('Invalid publication path')
    return state


def status(root):
    state=selected(root)
    if not state:return {'status':'publication_required','extension_id':browser_host.extension_id(),'private_key_required':True,'browser_trust':'company_configuration_required'}
    return {'status':'published_await_browser_acceptance','extension_id':state['settings']['extension_id'],'extension_version':state['version'],'settings':state['settings'],'browser_trust':'not_verified','generation':state['generation']}


def create_managed(root,base_url):
    """Explicit MIS action: create a stable company identity, then self-host.

    Never replaces an existing identity or modifies browser/system TLS trust.
    The one private key stays outside the public generation/package tree.
    """
    if not isinstance(base_url,str) or not base_url.endswith(PUBLIC_PREFIX):raise ValueError('請輸入管理中心 HTTPS /browser-extension/ 目錄網址')
    from .browser_deployment import validate
    validate({'extension_id':browser_host.extension_id(),'chrome_update_url':base_url+'updates.xml','edge_update_url':base_url+'updates.xml'})
    folder=Path(root)/'BrowserSigner';plain(folder)
    key_file=folder/'extension-signing.pem';plain(key_file)
    from .server_setup import secure_directory
    prior=selected(root)
    if prior and not key_file.exists():raise ValueError('現有發布使用外部金鑰；保留原身分，不建立替代金鑰')
    if not folder.exists():secure_directory(folder)
    private_signer(folder,key_file)
    if not key_file.exists():
        key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
        with key_file.open('xb') as stream:
            stream.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));stream.flush();os.fsync(stream.fileno())
        if os.name!='nt':key_file.chmod(0o600)
    private_signer(folder,key_file)
    # Build owns a new temporary output below the private signer folder. Only
    # the three verified public files go into BrowserPublication.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='release-',dir=folder) as temporary:
        output=Path(temporary)/'output'
        browser_release.build(output,base_url,key_file,company_identity=True)
        return install(root,(output/'GuardDesk-Browser-Publication.zip').read_bytes())


def public_file(root,name):
    state=selected(root)
    if not state or name not in state['hashes']:raise FileNotFoundError('Extension publication not found')
    path=directory(root)/state['generation']/name;plain(path)
    with path.open('rb') as stream:payload=stream.read(MAX_BUNDLE+1)
    if len(payload)>MAX_BUNDLE or hashlib.sha256(payload).hexdigest()!=state['hashes'][name]:raise ValueError('Published file integrity mismatch')
    return payload,'application/xml' if name=='updates.xml' else 'application/x-chrome-extension'
