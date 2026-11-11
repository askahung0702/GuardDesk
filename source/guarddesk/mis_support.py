"""TLS-only workstation support surface and public operator package.

Same endpoint TLS listener; no general management surface, OS trust changes,
enrollment credentials, startup tasks or autonomous desktop control.
"""
import hashlib
import io
import json
import sys
from pathlib import Path
import ssl
import zipfile
from urllib.parse import urlsplit

METHODS={'login':'POST','logout':'POST','catalog':'GET','request':'POST','session':'GET','input':'POST','stop':'POST','presented':'POST','native':'POST'}

def route(handler,db,method,path,body,query):
    from . import remote
    from .store import Store
    remote.require(handler.server.tls,'MIS 工作站遠端協助必須使用 HTTPS',403)
    action=path.removeprefix('/api/support/')
    remote.require(action in METHODS and METHODS[action]==method,'不支援的 MIS 遠端協助操作',404)
    if action=='login':
        remote.require(set(body)=={'username','password'},'登入欄位不正確',400)
        return handler.login(db,body,support=True)
    user=handler.session(db,mutate=method=='POST',support=True)
    if action=='logout':
        remote.require(not body,'登出欄位不正確',400)
        db.execute('DELETE FROM sessions WHERE token=?',(user['token'],))
        remote.sweep(handler.server,db)
        Store.event(db,'console','remote.operator_logout','info',{'actor':user['username']})
        return {'ok':True},{'Set-Cookie':'gd_mis=; HttpOnly; Secure; SameSite=Strict; Path=/api/support; Max-Age=0'},'application/json; charset=utf-8'
    # Even an admin login through this surface has only its own support view.
    limited={**dict(user),'role':'support','_remote_address':handler.client_address[0]}
    value=remote.route(handler.server,db,limited,method,'/api/remote/'+action,body,query)
    return value,{},'application/json; charset=utf-8'

def server_url(value):
    if not isinstance(value,str) or not value or len(value)>300 or value!=value.strip() or any(ord(c)<=32 for c in value):raise ValueError('請填寫公司 Server 的 HTTPS 位址')
    try:
        u=urlsplit(value);port=u.port
        if u.scheme!='https' or not u.hostname or u.username is not None or u.password is not None or u.path not in ('','/') or u.query or u.fragment or (port is not None and not 1<=port<=65535) or '\\' in value:raise ValueError()
    except ValueError:raise ValueError('請使用 https://公司Server:連接埠，不含帳密或路徑') from None
    return value.rstrip('/')

def connection(path,agent=False):
    path=Path(path).resolve(strict=True)
    if path.stat().st_size>16384:raise ValueError('連線設定過大')
    body=json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(body,dict):raise ValueError('連線設定格式不正確')
    if not agent and (set(body)!={'format','server','ca','ca_sha256'} or body['format']!=1):raise ValueError('MIS 連線設定格式不正確')
    server=server_url(body.get('server'));ca=body.get('ca')
    if agent and ca is None:return server,None
    if not isinstance(ca,str) or not ca:raise ValueError('找不到原連線 CA 憑證')
    if not agent and (Path(ca).name!=ca or '/' in ca or '\\' in ca):raise ValueError('MIS CA 必須是套件內的單一檔名')
    ca_path=(path.parent/ca).resolve(strict=True)
    if ca_path.stat().st_size>65536:raise ValueError('CA 檔案過大')
    blob=ca_path.read_bytes()
    if b'PRIVATE KEY' in blob or (not agent and hashlib.sha256(blob).hexdigest()!=body['ca_sha256']):raise ValueError('CA 憑證內容或雜湊不符')
    ssl.create_default_context(cadata=blob.decode('ascii'))
    return server,str(ca_path)

def package(root,application):
    from .endpoint_package import files,public_connection
    from . import __version__
    entries=files(application)  # Exact manifest, reparse and program ACL checks.
    public=None
    if root is not None:
        descriptor,ca=public_connection(Path(root)/'Endpoint-Connection.zip')
        descriptor=json.loads(descriptor)
        public={'format':1,'server':server_url(descriptor['server']),'ca':'GuardDesk-CA.pem','ca_sha256':hashlib.sha256(ca).hexdigest()}
    output=io.BytesIO();manifest={}
    def write(z,name,blob):manifest[name]=hashlib.sha256(blob).hexdigest();z.writestr(name,blob)
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as z:
        # Viewer uses contents_directory='.' and lives beside Python runtime.
        for path in entries:
            relative=path.relative_to(application)
            if relative.parts[0]=='_internal':write(z,'Runtime/'+Path(*relative.parts[1:]).as_posix(),path.read_bytes())
        if public:
            write(z,'mis-connection.json',json.dumps(public,indent=2).encode())
            write(z,'GuardDesk-CA.pem',ca)
            launch='start "" "%~dp0Runtime\\GuardDeskRemote.exe" --workstation --connection "%~dp0mis-connection.json"\r\n'
        else:
            launch='if exist "%LOCALAPPDATA%\\GuardDeskPilotClient\\runtime\\agent\\config.json" goto :agent\r\nstart "" "%~dp0Runtime\\GuardDeskRemote.exe" --workstation\r\nexit /b 0\r\n:agent\r\nstart "" "%~dp0Runtime\\GuardDeskRemote.exe" --workstation --agent-config "%LOCALAPPDATA%\\GuardDeskPilotClient\\runtime\\agent\\config.json"\r\n'
        write(z,'Start-MIS-Remote.cmd',('@echo off\r\nchcp 65001 >nul\r\nsetlocal DisableDelayedExpansion\r\n'+launch+'exit /b 0\r\n').encode('utf-8'))
        write(z,'README-MIS.txt',('GuardDesk '+__version__+' MIS 遠端協助／未簽章內部試用\r\n完整解壓，雙擊 Start-MIS-Remote.cmd，以 MIS／支援帳號登入。需管理員授權及使用者每次同意；密碼不存檔。'+('使用套件內公開連線設定與 CA 驗證 HTTPS。' if public else '優先沿用本機既有 Agent 的 Server／CA；未安裝 Agent 時請向管理員取得含連線設定的工具包，或填寫公司 HTTPS 位址及 CA 檔案。')+'不安裝全機信任。此包不含端點註冊碼或公司私鑰，不會安裝 Agent／開機工作。停止或關閉視窗即結束協助。\r\n').encode('utf-8-sig'))
        z.writestr('MANIFEST-SHA256.json',json.dumps(manifest,indent=2))
    if output.tell()>64*1024*1024:raise ValueError('MIS 工具套件超過 64 MiB')
    return output.getvalue()

def write_launcher(root,application,config):
    from .update_packages import plain
    target=plain(Path(root)/'Start-MIS-Remote.cmd')
    viewer=str(Path(application)/'_internal/GuardDeskRemote.exe').replace('%','%%')
    config=str(Path(config)).replace('%','%%')
    target.write_bytes(('@echo off\r\nchcp 65001 >nul\r\nsetlocal DisableDelayedExpansion\r\n'
        'if not exist "'+viewer+'" goto :missing\r\n'
        'start "" "'+viewer+'" --workstation --agent-config "'+config+'"\r\nexit /b 0\r\n'
        ':missing\r\necho MIS 遠端協助元件缺失，請由管理中心下載完整 MIS 工具。\r\npause\r\nexit /b 2\r\n').encode('utf-8'))

def ensure_agent_launcher(config):
    """User-session startup after an old updater switches to the new Agent."""
    if not getattr(sys,'frozen',False):return
    from .desktop_agent import client_root
    config=Path(config).resolve();root=client_root().resolve()
    if config!=root/'runtime/agent/config.json':return
    marker=root/'endpoint-install.json'
    if not marker.is_file() or marker.stat().st_size>16384:return
    state=json.loads(marker.read_text(encoding='utf-8'));application=Path(sys.executable).resolve().parent
    if state.get('product')!='GuardDeskEndpoint' or Path(state.get('app','')).resolve()!=application:return
    if not (application/'_internal/GuardDeskRemote.exe').is_file():return
    write_launcher(root,application,config)
