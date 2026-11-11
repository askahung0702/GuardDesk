"""Standalone MIS executable plus bounded, public-only connection trailer.

Dynamic public configuration changes the EXE hash. Current artifacts are
unsigned trials; configured executables must be signed after configuration
before any future signed release. The digest below is a corruption check.
"""
import hashlib
import json
import ssl
import os
import struct
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

MAGIC=b'\nGuardDesk-MIS-Public-v1\0'
MAX_PAYLOAD=100000
MAX_EXE=64*1024*1024


def native_media_root():
    """Only a pinned, hash-checked user-private cohort enables native media.

    This standard-user gate allows the current user as owner. It never grants
    SYSTEM execution trust to an extraction folder or changes installed ACLs.
    """
    from .mis_native_loader import ImagePins
    root=Path(getattr(sys,'_MEIPASS',Path(sys.executable).resolve().parent))
    pins=ImagePins(root)
    pins.close()
    return root


def public_payload(server,ca):
    from .mis_support import server_url
    if not isinstance(ca,bytes) or not 1<=len(ca)<=65536 or b'PRIVATE KEY' in ca:raise ValueError('MIS 公開 CA 格式不正確')
    text=ca.decode('ascii');ssl.create_default_context(cadata=text)
    return {'format':1,'server':server_url(server),'ca_pem':text,'ca_sha256':hashlib.sha256(ca).hexdigest()}


def append_connection(template,server,ca):
    payload=json.dumps(public_payload(server,ca),ensure_ascii=True,separators=(',',':')).encode('ascii')
    if not template.startswith(b'MZ') or len(template)+len(payload)+len(MAGIC)+36>MAX_EXE or len(payload)>MAX_PAYLOAD:raise ValueError('MIS EXE 模板或大小不正確')
    return template+payload+hashlib.sha256(payload).digest()+struct.pack('<I',len(payload))+MAGIC


def embedded(path):
    path=Path(path)
    with path.open('rb') as stream:
        size=stream.seek(0,2)
        if size<len(MAGIC)+36:return None
        stream.seek(-len(MAGIC),2)
        if stream.read()!=MAGIC:return None
        if size>MAX_EXE:raise ValueError('MIS EXE 大小超過上限')
        stream.seek(-len(MAGIC)-4,2);length=struct.unpack('<I',stream.read(4))[0]
        if not 1<=length<=MAX_PAYLOAD or size-length-36-len(MAGIC)<2:raise ValueError('MIS 公開連線長度不正確')
        stream.seek(-len(MAGIC)-36-length,2);data=stream.read(length);digest=stream.read(32)
        if hashlib.sha256(data).digest()!=digest:raise ValueError('MIS 公開連線資料損毀')
    body=json.loads(data)
    if not isinstance(body,dict) or set(body)!={'format','server','ca_pem','ca_sha256'} or type(body['format']) is not int or body['format']!=1 or not isinstance(body['ca_pem'],str):raise ValueError('MIS 公開連線欄位不正確')
    checked=public_payload(body['server'],body['ca_pem'].encode('ascii'))
    if checked!=body:raise ValueError('MIS 公開 CA 雜湊不符')
    return body


def executable(root,application):
    from .endpoint_package import files,public_connection
    application=Path(application);entries=files(application)
    template=application/'_internal/GuardDeskMIS.exe'
    if template not in entries:raise ValueError('缺少單一 EXE 模板，請更新完整 Server 程式')
    if not 1<=template.stat().st_size<=MAX_EXE:raise ValueError('MIS EXE 模板大小超過上限')
    blob=template.read_bytes()
    if root is None:return blob
    descriptor,ca=public_connection(Path(root)/'Endpoint-Connection.zip')
    return append_connection(blob,json.loads(descriptor)['server'],ca)


@contextmanager
def defaults(path):
    body=embedded(path)
    if body:
        # Public certificate only. No global CA installation or persisted login.
        with tempfile.TemporaryDirectory(prefix='GuardDeskMIS-CA-') as folder:
            ca=Path(folder)/'GuardDesk-CA.pem';ca.write_bytes(body['ca_pem'].encode('ascii'))
            yield ['--workstation','--server',body['server'],'--ca',str(ca)]
    else:
        config=Path(os.environ['LOCALAPPDATA'])/'GuardDeskPilotClient/runtime/agent/config.json'
        yield ['--workstation','--agent-config',str(config)] if config.is_file() else ['--workstation']


def run():
    from .remote_viewer import run as viewer
    # A configured file cannot silently be redirected by appended CLI flags.
    if sys.argv[1:]:raise ValueError('請直接執行 MIS 工具，不接受額外命令列參數')
    with defaults(sys.executable) as args:viewer(args,tray=True)
