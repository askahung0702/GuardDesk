"""Offline endpoint bundle: application files plus authorized reusable enrollment bootstrap."""
import hashlib
import json
import os
import sys
import threading
import zipfile
from pathlib import Path
from . import __version__

REQUIRED = {'GuardDesk.exe', 'GuardDeskAgent.exe', '_internal/agent-release.json',
    *('_internal/guarddesk/windows/' + name for name in ('install-usb.ps1', 'controls.ps1', 'applications.ps1'))}


def package_roots():
    from .remote_trial import enabled
    return ('GuardDesk.exe','GuardDeskAgent.exe','GuardDeskInstaller.exe','GuardDeskService.exe') if enabled() else ('GuardDesk.exe','GuardDeskAgent.exe')


def required_files():
    # Build-time profile only. A config file may not relax the standard package.
    from .remote_trial import enabled
    if not enabled():
        from .machine_service import enabled as full_service
        return set(REQUIRED)|({'_internal/GuardDeskService.exe'} if full_service() else set())
    from .remote_components import ENDPOINT_REMOTE_FILES,COHORT_MANIFEST
    return {*package_roots(),'_internal/agent-release.json',
            *('_internal/remote/'+name for name in (*ENDPOINT_REMOTE_FILES,COHORT_MANIFEST))}

def _endpoint_entry(upgrade=False):
    # Keep CMD control flow ASCII/CRLF. Localized product messages belong in
    # the executable/readme, not a batch file whose parser code page varies.
    label='Existing Endpoint Upgrade' if upgrade else 'Endpoint Setup'
    flag=' --upgrade-existing' if upgrade else ''
    lines=['@echo off','setlocal DisableDelayedExpansion',
        'title GuardDesk '+label,
        'echo GuardDesk: '+('upgrade the existing identity; no new enrollment.' if upgrade else 'endpoint setup.'),
        'echo Extract the COMPLETE endpoint ZIP first. Approve Windows UAC when requested.']
    for name in ('GuardDesk\\GuardDesk.exe','GuardDesk\\GuardDeskAgent.exe',
            'GuardDesk\\_internal\\agent-release.json','endpoint-files.json',
            'endpoint-connection.json','update-trust.json'):
        lines+=['set "missing_file='+name+'"','if not exist "%~dp0%missing_file%" goto :missing']
    lines+=['"%~dp0GuardDesk\\GuardDesk.exe" endpoint-setup'+flag+' --connection "%~dp0endpoint-connection.json"',
        'set "setup_result=%errorlevel%"','echo ExitCode=%setup_result%',
        'if not "%setup_result%"=="0" echo Setup incomplete. Preserve the installed identity and diagnostic report.',
        'pause','exit /b %setup_result%',':missing','echo ERROR: Required package file is missing:',
        'echo "%~dp0%missing_file%"',
        'echo Use the complete GuardDesk-Endpoint ZIP from the management center.',
        'echo Endpoint-Connection.zip alone cannot install or upgrade an Agent.',
        'echo Keep every extracted file together. This entry has not started the installer.',
        'echo ExitCode=2','pause','exit /b 2']
    return ('\r\n'.join(lines)+'\r\n').encode('ascii')


SETUP=_endpoint_entry()
# Separate opt-in path: ordinary Setup must never take over a completed Agent.
UPGRADE=_endpoint_entry(True)


def application_directory():
    return Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[1] / 'dist/GuardDesk'


def files(source,version=None):
    source = Path(source).absolute()
    from .remote_components import validate_layout
    validate_layout(source)
    result = []
    roots = [*(source/name for name in package_roots()),source/'_internal']
    if not all(p.exists() for p in roots):
        raise ValueError('請使用含 GuardDeskAgent.exe 的完整新版執行包')
    for path in [*roots, *(source / '_internal').rglob('*')]:
        if path.is_symlink() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('程式目錄不可包含 junction／符號連結')
        if path.is_file():
            if path.suffix.lower() in ('.key', '.pem', '.sqlite3') or 'runtime' in path.relative_to(source).parts:
                raise ValueError('程式目錄含資料／金鑰檔，拒絕打包')
            result.append(path)
        if len(result) > 10000: raise ValueError('程式檔案過多')
    if not all((source / name).is_file() for name in ('GuardDesk.exe', 'GuardDeskAgent.exe')) or not (source / '_internal').is_dir():
        raise ValueError('請使用含 GuardDeskAgent.exe 的完整新版執行包')
    if sum(path.stat().st_size for path in result) > 512 * 1024 * 1024: raise ValueError('程式目錄過大')
    if not required_files() <= {p.relative_to(source).as_posix() for p in result}:
        raise ValueError('缺少端點安裝必要元件；請更新完整 Server 程式目錄後重新下載，不能只替換 EXE。')
    from .bundle_manifest import inspect, BundleError
    try: inspect(source, version or __version__, threading.Event())
    except BundleError as exc:
        raise ValueError('Server 程式檔案或版本清單不一致；請更新完整程式目錄並重新啟動管理中心，再下載端點安裝包。') from exc
    return result


def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def public_connection(connection_zip):
    with zipfile.ZipFile(connection_zip) as archive:
        for name, limit in [('endpoint-connection.json', 8192), ('GuardDesk-CA.pem', 65536)]:
            if archive.getinfo(name).file_size > limit: raise ValueError('連線包過大')
        manifest = archive.read('endpoint-connection.json'); ca = archive.read('GuardDesk-CA.pem')
    body = json.loads(manifest)
    from .connection_contract import validate_body
    validate_body(body)
    if not isinstance(body['server'], str) or body['ca'] != 'GuardDesk-CA.pem' or body['ca_sha256'] != hashlib.sha256(ca).hexdigest() or b'PRIVATE KEY' in ca:
        raise ValueError('連線包格式或 CA 雜湊不正確')
    from urllib.parse import urlsplit
    address = urlsplit(body.get('server', ''))
    if address.scheme != 'https' or not address.hostname or address.username or address.password or address.path not in ('', '/') or address.query or address.fragment:
        raise ValueError('連線包必須提供 HTTPS Server 位址')
    return manifest, ca


def build(source, connection_zip, output,*,version=None,manifest_sha256=None):
    version=version or __version__
    source = Path(source).resolve(); output = Path(output)
    entries = files(source,version); manifest, ca = public_connection(connection_zip)
    from .remote_trial import enabled
    trial=enabled()
    with zipfile.ZipFile(connection_zip) as connection:
        if 'update-trust.json' not in connection.namelist() or connection.getinfo('update-trust.json').file_size > 4096:
            raise ValueError('缺少更新信任公鑰，請由新版管理中心重新產生端點安裝包。')
        trust = connection.read('update-trust.json'); body = json.loads(trust)
        if not isinstance(body, dict) or set(body) != {'format', 'public_key'} or body['format'] != 1:
            raise ValueError('更新信任檔不正確，未提供安裝包。')
        from .update_packages import key_id
        key_id(body['public_key'])
        descriptor=json.loads(manifest)
        if trial and (descriptor.get('browser_deployment') or descriptor.get('browser_deployment_authorization') or 'browser-trust.json' in connection.namelist()):
            raise ValueError('僅遠端試用包不可包含瀏覽器政策或系統信任授權。')
        browser_trust=None
        if 'browser-trust.json' in connection.namelist():
            if connection.getinfo('browser-trust.json').file_size>2048:raise ValueError('Browser trust authorization too large')
            browser_trust=connection.read('browser-trust.json')
            from .browser_trust import verify
            verify(json.loads(browser_trust),body['public_key'],descriptor['server'],ca,descriptor.get('browser_deployment'))
        if descriptor.get('browser_deployment'):
            from .browser_deployment import verify_authorization
            verify_authorization(descriptor['browser_deployment'],descriptor.get('browser_deployment_authorization'),body['public_key'])
    hashes = {p.relative_to(source).as_posix(): sha(p) for p in entries}
    if manifest_sha256 is not None and hashes.get('_internal/agent-release.json')!=manifest_sha256:
        raise ValueError('Dedicated endpoint manifest changed during packaging')
    from .endpoint_payload import project,entry
    hashes,overrides=project(source,hashes)
    with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED) as archive:
        for path in entries:
            name = path.relative_to(source).as_posix(); digest = hashlib.sha256()
            if name not in hashes:continue
            with entry(source,name,overrides) as stream, archive.open('GuardDesk/' + name, 'w') as target:
                while chunk := stream.read(65536): digest.update(chunk); target.write(chunk)
            if digest.hexdigest() != hashes[name]: raise ValueError('製作期間程式檔案已變動，未提供安裝包；請停止更新程式目錄後重試。')
        archive.writestr('endpoint-files.json', json.dumps({'version': version, 'files': hashes}, indent=2))
        archive.writestr('endpoint-connection.json', manifest)
        archive.writestr('GuardDesk-CA.pem', ca)
        archive.writestr('update-trust.json', trust)
        if browser_trust:archive.writestr('browser-trust.json',browser_trust)
        if trial:
            from .remote_trial_install import package_notes
            package_notes(archive,SETUP.replace(b'GuardDesk.exe',b'GuardDeskInstaller.exe'),version=version)
            return output
        browser=json.loads(manifest).get('browser_deployment')
        archive.writestr('browser-deployment-status.json',json.dumps({'status':'policy_will_apply_during_uac' if browser else 'publication_required','browser_installation_verified':False,'manual_publication_required':not bool(browser),'requires_enterprise_browser_management':True,'requires_browser_trusted_https':True,'ca_trust_will_apply_during_uac':bool(browser_trust),'settings':browser},indent=2))
        archive.writestr('README-Browser.txt',('網站檔案上傳需要企業擴充 0.5.0；免設定部署與 CA 信任需管理中心及原生元件 0.4.59。\n'+('此包已包含公開發布設定，安裝器會在同一次 UAC 套用 Chrome／Edge 企業政策；員工不用手動安裝。瀏覽器須符合企業管理條件並信任該 HTTPS 憑證；安裝成功後仍需中心觀察擴充連線，再以非機密檔案驗收。\n' if browser else '管理中心自動發布尚未完成；此包不會自動安裝擴充，網站上傳收集尚未就緒。請由 MIS 核對中心準備狀態與原連線／金鑰資料後重新下載此包，再執行同一入口；原端點身分與待補送資料會保留。\n')+'若包內含原中心金鑰簽署的 browser-trust.json，同一次 UAC 會安裝與原連線一致的 GuardDesk CA 至 Windows 全機根憑證庫；保留原先存在的憑證，移除只撤回本工具可確認擁有的項目。未有信任授權的外部發布來源須由 MIS 依公司流程信任。不關閉瀏覽器或防護、不刪其他企業擴充政策。File／記憶體格式可僅有檔名候選，HTTP 回應不代表網站保存成功。\n').encode('utf-8-sig'))
        archive.writestr('Setup-Endpoint.cmd', SETUP)
        archive.writestr('Upgrade-Endpoint.cmd', UPGRADE)
        archive.writestr('README-Upgrade.txt',('既有全機 Agent 明確升級（內部試用）\n'
            '集中更新受舊更新器阻擋時，先確認中心該端點工作已結束，並結束協助。\n'
            '在最初完成安裝的使用者桌面，完整解壓本中心新下載的端點包，正常雙擊 Upgrade-Endpoint.cmd；依畫面核准 UAC。\n'
            '此入口只接受同中心／CA、原端點設定與安裝紀錄相符、較新且同安裝類型的包；保留原身分與資料，不重新註冊。\n'
            '缺少原紀錄、中心不同、版本較舊或完整安裝的服務未連線時會停止，不刪檔、不假稱更新完成。\n'
            '一般 Setup-Endpoint.cmd 仍不會覆蓋已完成的安裝。新裝使用 Setup，原身分升級使用 Upgrade。\n'
            '升級完成後，須在中心核對原生、一般 Agent 與獨立更新器均為目標版本；後續再驗收一次集中更新。\n').encode('utf-8-sig'))
        archive.writestr('Connect-Endpoint.cmd', SETUP)
        archive.writestr('README-Endpoint.txt', f'GuardDesk {__version__} 端點簡易安裝（內部未簽章試用版）\n1. 將整份 ZIP 解壓到本機私人資料夾。\n2. 以實際使用者身分雙擊 Setup-Endpoint.cmd，不要先以管理員執行。\n3. 新版包已內建共用部署碼，自動註冊，不必輸入 IP 或註冊碼；舊版未內建碼時才需手動輸入。\n4. 由 MIS 核准 Windows 管理員 UAC，等待完成。\n一般 Agent 於使用者登入後自動啟動；原生 USB／程序元件於開機啟動。\n全機程式位於 %ProgramFiles%\\GuardDeskPilot，受保護設定位於 %ProgramData%\\GuardDeskPilot；登入者的私人佇列仍位於 %LOCALAPPDATA%\\GuardDeskPilotClient，請勿刪除這些資料夾。\n0.4.12 起 Chrome／Edge 一般瀏覽紀錄由 Agent 自動收集，不需另裝擴充或設定瀏覽器；需開啟網址稽核策略，不涵蓋無痕與未保存紀錄。網站上傳限速仍使用原擴充與代理機制。\n若取消 UAC 或安裝中斷，雙擊同一個 Setup-Endpoint.cmd 重試，沿用原端點與待補送資料；不需要手動執行 PS1。安裝會顯示五個步驟；失敗請保留視窗內容及 %LOCALAPPDATA%\\GuardDeskPilotClient\\runtime\\agent\\installation-diagnostic.json 給 MIS。公司腳本簽章政策仍須遵守；安裝器不會略過政策。\n安裝包內含共用註冊祕密，只交內部授權人員保管。僅使用 MIS 提供的包；安裝後由 MIS 核對在線、收集器及策略實際套用狀態。\n')
    return output


def server_installer(executable, connection):
    """Create the ready-to-install ZIP beside server data, never private keys.

    Python source-mode tests may not have a distributable application. A real
    GuardDesk.exe must have its complete application directory or fail clearly.
    """
    executable = Path(executable).resolve()
    if executable.name.casefold() != 'guarddesk.exe':
        return None
    from .deployment import plain,replace_with_retry
    import tempfile
    connection = Path(connection)
    target = connection.parent/'GuardDesk-Endpoint.zip'; plain(target)
    with tempfile.TemporaryDirectory(prefix='endpoint-build-', dir=connection.parent) as folder:
        from .endpoint_files import secure_directory
        secure_directory(Path(folder), allow_empty=True)
        temporary = Path(folder)/'endpoint.zip'
        build(executable.parent, connection, temporary)
        replace_with_retry(temporary, target)
    return target
