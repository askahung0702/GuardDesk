"""Offline enterprise publication build; no network or private keys in output.

CRX3 encoding follows Chromium's crx_creator.cc. Existing Native Host identity
is pinned: an unrelated signing key is rejected before creating any output.
"""
import base64
import hashlib
import io
import json
import struct
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from .browser_host import EXTENSION,extension_id
from .browser_deployment import validate


def varint(n):
    result=bytearray()
    while n>127:result.append((n&127)|128);n>>=7
    result.append(n);return bytes(result)


def blob(field,data):return varint(field*8+2)+varint(len(data))+data


def sign_crx(archive,key,expected_public):
    if not isinstance(key,rsa.RSAPrivateKey) or key.key_size<2048:raise ValueError('企業 CRX 簽署需要至少 2048 位元 RSA 金鑰')
    public=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    if public!=expected_public:raise ValueError('簽署公鑰與已部署 Native Host 身分不同；停止產生，不會偷偷更換擴充 ID')
    signed=blob(1,hashlib.sha256(public).digest()[:16])
    payload=b'CRX3 SignedData\x00'+struct.pack('<I',len(signed))+signed+archive
    signature=key.sign(payload,padding.PKCS1v15(),hashes.SHA256())
    key.public_key().verify(signature,payload,padding.PKCS1v15(),hashes.SHA256())
    header=blob(2,blob(1,public)+blob(2,signature))+blob(10000,signed)
    return b'Cr24'+struct.pack('<II',3,len(header))+header+archive


def archive_source(update_url=None,public_key=None):
    manifest=json.loads((EXTENSION/'manifest.json').read_text(encoding='utf-8'))
    if public_key:
        from .browser_identity import identity
        identity(public_key);manifest['key']=public_key
    if update_url:manifest['update_url']=update_url
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(EXTENSION.iterdir()):
            if not path.is_file() or path.suffix not in ('.json','.html','.js','.css'):continue
            data=json.dumps(manifest,ensure_ascii=False,indent=2).encode('utf-8') if path.name=='manifest.json' else path.read_bytes()
            entry=zipfile.ZipInfo(path.name,(2026,10,22,0,0,0));entry.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(entry,data)
    return output.getvalue(),manifest


def build(output,base_url=None,key_path=None,password=None,company_identity=False):
    output=Path(output).absolute()
    if output.exists():raise ValueError('發布輸出目錄已存在；請另用新目錄，保留上一版與回復包')
    if bool(base_url)!=bool(key_path):raise ValueError('自架發布需同時提供公司 HTTPS 基底網址及匹配簽署金鑰；省略兩者則產生商店待發布來源')
    files={};state='store_publication_required';settings=None
    if base_url:
        if not isinstance(base_url,str) or not base_url.endswith('/') or any(s in base_url for s in ('..','%','\\')):raise ValueError('請指定公司 HTTPS 目錄網址並以 / 結尾')
        update_url=base_url+'updates.xml'
        settings={'extension_id':extension_id(),'chrome_update_url':update_url,'edge_update_url':update_url}
        key_path=Path(key_path).resolve()
        if key_path==output or output in key_path.parents:raise ValueError('金鑰不可置於發布輸出目錄')
        if key_path.stat().st_size>32768:raise ValueError('金鑰檔案過大')
        key=serialization.load_pem_private_key(key_path.read_bytes(),password=password)
        if company_identity:
            from .browser_identity import identity
            public=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
            settings.update(public_key=public,extension_id=identity(public))
        validate(settings)
        archive,manifest=archive_source(update_url,settings.get('public_key'))
        crx=sign_crx(archive,key,base64.b64decode(manifest['key'],validate=True))
        filename='guarddesk-'+manifest['version']+'.crx';files[filename]=crx
        root=ET.Element('gupdate',xmlns='http://www.google.com/update2/response',protocol='2.0')
        app=ET.SubElement(root,'app',appid=settings['extension_id']);ET.SubElement(app,'updatecheck',codebase=base_url+filename,version=manifest['version'])
        files['updates.xml']=ET.tostring(root,encoding='utf-8',xml_declaration=True)
        files['browser-deployment.json']=json.dumps(settings,indent=2).encode()
        files['http-headers.json']=json.dumps({'updates.xml':{'Content-Type':'application/xml','Cache-Control':'no-cache'},filename:{'Content-Type':'application/x-chrome-extension','Cache-Control':'public, max-age=3600'}},indent=2).encode()
        # Import only these three public files into the management center.
        bundle=io.BytesIO()
        with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED) as publication:
            for name in (filename,'updates.xml','browser-deployment.json'):publication.writestr(name,files[name])
        files['GuardDesk-Browser-Publication.zip']=bundle.getvalue()
        state='signed_self_host_bundle_not_published'
    else:archive,manifest=archive_source()
    files['extension-source.zip']=archive
    actual_id=settings['extension_id'] if settings else extension_id()
    files['publication.json']=json.dumps({'status':state,'extension_id':actual_id,'extension_version':manifest['version'],'private_key_included':False,'network_requests':0,'force_policy_applied':False,'employee_action_required':False,'browser_installation_verified':False},indent=2).encode()
    files['README.txt']=('GuardDesk 企業瀏覽器發布套件（內部試用）\n'
        '商店：以企業發布帳號完成審查；核對商店實際 ID 與 publication.json 一致。ID 不同不可派送；必須重新設計 Native Host 信任與遷移。\n'
        '自架：將 CRX 及 updates.xml 上傳公司核定 HTTPS 靜態站台，保留舊版；依 http-headers.json 設定。此工具不會上傳。\n'
        '先以受保護 GuardDesk.exe browser-policy --config <原生 config.json> --settings browser-deployment.json --action plan，再由公司管理工具執行 apply；restore 只撤回本工具擁有的項目。\n'
        '也可透過公司 GPO／Intune 設定 ExtensionInstallForcelist，但須合併既有項目，不能以整份覆寫。\n'
        'Chrome 自架來源需要符合受管理裝置條件；Edge 同樣受公司瀏覽器政策限制。員工不用手動安裝。\n'
        '先單台驗證 chrome://policy／edge://policy、Native Host 連線及非機密測試文件；再小批部署。\n'
        'HTTP 回應不代表業務保存成功，來源路徑可能只有檔名候選；瀏覽器設定檔／無痕與切片上傳另依能力狀態驗收。\n').encode('utf-8-sig')
    files['SHA256.json']=json.dumps({n:hashlib.sha256(b).hexdigest() for n,b in files.items()},indent=2).encode()
    output.mkdir(parents=True,exist_ok=False)
    for name,data in files.items():
        with (output/name).open('xb') as stream:stream.write(data)
    return {'status':state,'output':str(output),'files':len(files),'extension_id':actual_id,'version':manifest['version']}
