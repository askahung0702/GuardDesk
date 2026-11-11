"""Corporate deployment artifacts and additive, reversible browser policy.

Does not publish, sign, fetch CRX files, edit user profiles, or disable controls.
The privileged entry point requires the existing protected native installation.
"""
import io
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import urlsplit
from .browser_host import EXTENSION,extension_id

KEYS={'chrome':r'Software\Policies\Google\Chrome\ExtensionInstallForcelist',
      'edge':r'Software\Policies\Microsoft\Edge\ExtensionInstallForcelist'}


def authorize(settings,private):
    """Organization update signer authorizes one fixed public deployment."""
    import base64
    from .serialization import canonical
    validate(settings)
    return {'format':1,'signature':base64.b64encode(private.sign(b'GuardDesk browser deployment v1\0'+canonical(settings).encode('utf-8'))).decode()}


def verify_authorization(settings,authorization,public):
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from .serialization import canonical
    from .update_packages import key_id
    validate(settings)
    if not isinstance(authorization,dict) or set(authorization)!={'format','signature'} or type(authorization['format']) is not int or authorization['format']!=1 or not isinstance(authorization['signature'],str) or len(authorization['signature'])>128:raise ValueError('缺少公司擴充部署授權簽章；請從原管理中心重新下載端點安裝包')
    try:
        key_id(public);signature=base64.b64decode(authorization['signature'],validate=True)
        if len(signature)!=64:raise ValueError('Invalid signature size')
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public,validate=True)).verify(signature,b'GuardDesk browser deployment v1\0'+canonical(settings).encode('utf-8'))
    except Exception as exc:raise ValueError('公司擴充部署授權簽章不符；保留既有端點，請重新取得原中心安裝包') from exc
    return settings


def validate(settings):
    if not isinstance(settings,dict) or set(settings) not in ({'extension_id','chrome_update_url','edge_update_url'},{'extension_id','chrome_update_url','edge_update_url','public_key'}):
        raise ValueError('Invalid browser deployment settings')
    from .browser_identity import identity
    expected=identity(settings['public_key']) if 'public_key' in settings else extension_id()
    if settings['extension_id']!=expected:
        raise ValueError('擴充 ID 必須與 GuardDesk Native Host 公鑰一致；變更身分須另做遷移')
    for name in ('chrome_update_url','edge_update_url'):
        url=settings[name]
        if not isinstance(url,str) or len(url)>2048 or any(ord(c)<33 for c in url):raise ValueError('請設定公司核定的 HTTPS 更新來源')
        p=urlsplit(url)
        if p.scheme!='https' or not p.hostname or p.username or p.password or p.fragment or p.query or (p.port is not None and not 1<=p.port<=65535):
            raise ValueError('更新來源須使用 HTTPS，不可包含帳密或查詢參數')
    return settings


def changes(settings,existing):
    validate(settings);result=[]
    for browser,key in KEYS.items():
        values=existing.get(browser,{})
        if len(values)>1000:raise ValueError('瀏覽器企業策略超過可管理上限')
        desired=settings['extension_id']+';'+settings[browser+'_update_url']
        matching=[v for v in values.values() if isinstance(v,str) and v.split(';')[0]==settings['extension_id']]
        if matching:
            if any(v!=desired for v in matching):raise ValueError('既有公司擴充策略的更新來源不同；請由 MIS 核對，不自動覆寫')
            continue
        slot=next((str(i) for i in range(1,1001) if str(i) not in values),None)
        if not slot:raise ValueError('沒有可用的瀏覽器策略位置')
        result.append({'browser':browser,'key':key,'name':slot,'before':None,'after':desired})
    return result


def artifact():
    """Source package for MIS publication, not a silently installable CRX."""
    manifest=json.loads((EXTENSION/'manifest.json').read_text(encoding='utf-8'))
    template={'extension_id':extension_id(),'chrome_update_url':'','edge_update_url':''}
    source=io.BytesIO()
    with zipfile.ZipFile(source,'w',zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(EXTENSION.iterdir()):
            if path.is_file() and path.suffix in ('.js','.json','.html','.css'):archive.writestr(path.name,path.read_bytes())
    notes='''GuardDesk 企業瀏覽器部署套件（內部試用）
此套件尚未發布至商店／公司更新站台，不是已簽署 CRX。
1. MIS 透過公司核定流程發布 extension-source.zip，保留 manifest 公鑰與 Native Host ID 一致。
   自架 CRX 必須持有匹配的受控簽署私鑰；本套件不包含私鑰，也不產生替代身分。
2. 填寫 browser-deployment.json 的 Chrome 與 Edge HTTPS 更新 URL。
   自架來源須符合各瀏覽器企業管理／網域資格；一般非受管理電腦不可假設能強制安裝。
3. 先用已安裝的受保護原生 GuardDesk.exe browser-policy --config <受保護的 config.json>
   --settings <browser-deployment.json> --action plan 檢視增量；公司管理工具以管理員執行 apply。
   員工不用操作。不啟動／關閉員工瀏覽器，不修改瀏覽器使用者資料。
4. 中心端點明細須收到新版 Agent／原生工作／擴充實際連線回報，再做非機密測試文件驗收。
   註冊 Native Host 或寫入策略都不等於擴充已連線；檢查 chrome://policy、edge://policy。
5. 同一指令 --action restore 僅撤回本工具建立且未被外部修改的項目；不刪其他公司策略。
   移除策略不保證瀏覽器立即卸載，按公司政策與瀏覽器實際回報驗收。
不處理無痕模式、非標準 Native Host 註冊帳戶或所有切片／記憶體上傳。
HTTP 2xx 不代表網站保存成功；只選檔未送出不應產生上傳事件。
0.4.49 可在自訂設定庫指派指定範圍的讀取稽核與複製候選關聯；仍須原生元件實際回報驗收。
另可使用 GuardDesk.exe browser-release --output <新目錄> 產生商店待發布來源；自架加 --base-url <HTTPS目錄/> --signer-key <受控且匹配現有公鑰的金鑰>，產生 CRX3 與更新 XML。
金鑰／正式發布來源未設定前不可假稱企業擴充已安裝。
官方規範：
https://support.google.com/chrome/a/answer/7532015
https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/extensioninstallforcelist
'''
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('extension-source.zip',source.getvalue())
        archive.writestr('browser-deployment.json',json.dumps(template,indent=2))
        archive.writestr('README.txt',notes.encode('utf-8-sig'))
        archive.writestr('deployment-status.json',json.dumps({'status':'publication_required','extension_id':extension_id(),'extension_version':manifest['version'],'employee_action_required':False,'signed_crx_included':False},indent=2))
    return output.getvalue()


class Registry:
    def __init__(self):
        import winreg
        self.w=winreg

    def read(self,browser):
        w=self.w;values={}
        try:
            with w.OpenKey(w.HKEY_LOCAL_MACHINE,KEYS[browser],0,w.KEY_READ|w.KEY_WOW64_64KEY) as key:
                for i in range(1001):
                    try:name,value,kind=w.EnumValue(key,i)
                    except OSError as exc:
                        if exc.winerror==259:break
                        raise
                    # Occupied non-string slots must also be preserved.
                    values[name]=value if kind==w.REG_SZ else {'registry_type':kind}
        except FileNotFoundError:pass
        return values

    def write(self,item,value):
        w=self.w
        with w.CreateKeyEx(w.HKEY_LOCAL_MACHINE,item['key'],0,w.KEY_SET_VALUE|w.KEY_QUERY_VALUE|w.KEY_WOW64_64KEY) as key:
            try:current,kind=w.QueryValueEx(key,item['name'])
            except FileNotFoundError:current=None;kind=w.REG_SZ
            if kind!=w.REG_SZ or current not in (item['before'],item['after']):raise OSError('企業策略已由外部修改；停止以保留公司設定')
            # A periodic signed-policy retry is a readback, not another hive
            # flush. FlushKey can stall unrelated registry users on Windows.
            if current==value:return
            if value is None:
                if current is not None:w.DeleteValue(key,item['name'])
            else:w.SetValueEx(key,item['name'],0,w.REG_SZ,value)
            w.FlushKey(key)


def execute(settings,action,directory,registry):
    """Caller has validated the fixed protected executable/configuration root."""
    ledger=Path(directory)/'browser-policy-owned.json'
    if action not in ('plan','apply','restore'):raise ValueError('Invalid deployment action')
    if action=='restore':
        if not ledger.exists():return {'status':'not_managed'}
        owned=json.loads(ledger.read_text(encoding='utf-8'))
        if not isinstance(owned,list) or len(owned)>2:raise ValueError('Invalid policy ownership journal')
        for item in owned:
            if set(item)!={'browser','key','name','before','after'} or item['browser'] not in KEYS or item['key']!=KEYS[item['browser']] or not re.fullmatch('[0-9]{1,4}',item['name']) or item['before'] is not None or not isinstance(item['after'],str) or not re.fullmatch('[a-p]{32};https://[^\x00-\x20]{1,2048}',item['after']):raise ValueError('Invalid policy ownership journal')
        # Check every entry before changing any; restore also accepts an entry
        # already absent after a crash partway through rollback.
        for item in owned:
            if registry.read(item['browser']).get(item['name']) not in (item['before'],item['after']):raise OSError('企業策略已由外部修改；保留復原紀錄')
        for item in reversed(owned):registry.write(item,item['before'])
        ledger.unlink();return {'status':'restored','count':len(owned)}
    if ledger.exists():
        if action=='apply':
            # Same-installer retry/update is idempotent, including a crash
            # between journaling and writing one of our exact slots.
            owned=json.loads(ledger.read_text(encoding='utf-8'))
            if not isinstance(owned,list) or len(owned)>2:raise ValueError('Invalid policy ownership journal')
            validate(settings)
            for item in owned:
                if (not isinstance(item,dict) or set(item)!={'browser','key','name','before','after'} or item['browser'] not in KEYS or item['key']!=KEYS[item['browser']] or not re.fullmatch('[0-9]{1,4}',item['name']) or item['before'] is not None or item['after']!=settings['extension_id']+';'+settings[item['browser']+'_update_url']):raise OSError('已有不同部署紀錄；先核對／還原再變更來源')
                if registry.read(item['browser']).get(item['name']) not in (None,item['after']):raise OSError('企業策略已由外部修改；保留復原紀錄')
            for item in owned:registry.write(item,item['after'])
            if changes(settings,{b:registry.read(b) for b in KEYS}):raise OSError('企業策略不完整；保留復原紀錄並交 MIS 核對')
            return {'status':'policy_written_await_browser','changes':owned,'browser_installation_verified':False}
    planned=changes(settings,{b:registry.read(b) for b in KEYS})
    if action=='plan':return {'status':'plan_only','changes':planned,'browser_installation_verified':False}
    # Atomic exclusive journal creation before the first registry mutation.
    with ledger.open('x',encoding='utf-8') as stream:
        json.dump(planned,stream);stream.flush()
        import os
        os.fsync(stream.fileno())
    try:
        for item in planned:registry.write(item,item['after'])
        for item in planned:
            if registry.read(item['browser']).get(item['name'])!=item['after']:raise OSError('Browser policy readback mismatch')
    except OSError:
        # Leave the durable journal even if rollback fails; never lose which
        # exact slots this transaction owns.
        for item in reversed(planned):registry.write(item,item['before'])
        raise
    return {'status':'policy_written_await_browser','changes':planned,'browser_installation_verified':False}
