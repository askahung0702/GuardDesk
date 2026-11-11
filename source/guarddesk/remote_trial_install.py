"""Install boundary for a compiled remote-only internal trial, never a policy toggle."""
import copy

PROFILE = 'remote-only-trial-v1'


def check_settings(settings, *, existing=None):
    from .remote_trial import enabled
    trial = enabled()
    for value in (settings, existing):
        if value is None:
            continue
        marker = value.get('install_profile')
        if trial:
            if marker != PROFILE:
                raise ValueError('遠端測試包不可接管一般 Agent；請保留原安裝，使用沒有 GuardDesk 的測試電腦。')
            if any(value.get(k) for k in ('browser_deployment', 'browser_deployment_authorization', 'browser_trust', 'proxy_enabled')):
                raise ValueError('遠端測試包不允許瀏覽器部署、系統 CA 信任或代理設定。')
        elif marker not in (None, 'standard'):
            raise ValueError('請先明確解除遠端試用版，再安裝一般 Agent；不自動轉為完整收集版。')


def check_connection(body, package):
    from .remote_trial import enabled
    if enabled() and (any(body.get(k) for k in ('browser_deployment', 'browser_deployment_authorization'))
                      or (package / 'browser-trust.json').exists()):
        raise ValueError('此連線包包含一般瀏覽器部署，不能用於僅遠端測試。')


def policy():
    from .policy import DEFAULT_POLICY, validate_policy
    body = copy.deepcopy(DEFAULT_POLICY)
    body.update(mode='monitor', allow_export=False, blocked_extensions=[], keywords=[],
                browser_audit=False, application_audit=False, upload_rules=[], application_publishers=[])
    body['file_audit'] = {'enabled': False, 'scope': 'managed', 'exclude_paths': []}
    body['application_control'] = {'enabled': False, 'mode': 'denylist', 'block_msi': False, 'rules': []}
    body['website_control'] = {'enabled': False, 'browsers': ['chrome', 'edge'], 'blocked': [], 'allowed': []}
    return validate_policy(body)


def package_notes(archive, setup,*,version=None):
    from . import __version__
    version=version or __version__
    archive.writestr('Setup-Endpoint.cmd', setup)
    archive.writestr('Repair-Remote-Test.cmd', (
        '@echo off\r\nchcp 65001 >nul\r\nsetlocal DisableDelayedExpansion\r\n'
        'title GuardDesk Remote Trial Repair\r\n'
        'if not exist "%LOCALAPPDATA%\\GuardDeskPilotClient\\runtime\\agent\\config.json" goto :missing\r\n'
        'echo GuardDesk: preserve the existing trial identity; approve its Windows UAC prompt.\r\n'
        '"%~dp0GuardDesk\\GuardDeskInstaller.exe" usb-install --config "%LOCALAPPDATA%\\GuardDeskPilotClient\\runtime\\agent\\config.json" --action Install\r\n'
        'set "result=%errorlevel%"\r\necho ExitCode=%result%\r\npause\r\nexit /b %result%\r\n'
        ':missing\r\necho Existing trial configuration not found. No enrollment or cleanup performed.\r\npause\r\nexit /b 2\r\n').encode('utf-8'))
    archive.writestr('Uninstall-Remote-Test.cmd', (
        '@echo off\r\nchcp 65001 >nul\r\nsetlocal DisableDelayedExpansion\r\n'
        'title GuardDesk Remote Trial Uninstall\r\n'
        '"%~dp0GuardDesk\\GuardDeskInstaller.exe" endpoint-uninstall\r\n'
        'set "result=%errorlevel%"\r\npause\r\nexit /b %result%\r\n').encode('utf-8'))
    archive.writestr('README-Remote-Test.txt', (
        f'GuardDesk {version} 僅遠端協助測試版（內部未簽章；非正式發布）\n'
        '只供 MIS 明確授權的獨立 Windows 10／11 x64 測試端點使用。\n'
        '不要使用 0.4.75 或舊開發快照，不要用於公司群派。\n'
        '1. 連上 VPN，完整解壓 ZIP 到本機私人資料夾。\n'
        '2. 正常雙擊 Setup-Endpoint.cmd；原生安裝另顯示 UAC，核對來源後由你允許。\n'
        '3. 保持桌面解鎖，管理端提出協助後由你在此電腦同意。\n'
        '已安裝本次同一中心的遠端試用版要更新診斷元件時，以原安裝帳號雙擊 Repair-Remote-Test.cmd；'
        '沿用原設定／身分，UAC 安裝完成後仍須中心核對新版本與功能。不重新註冊或清除原檔。\n'
        '4. 測試真正 UAC 前另約操作時段；不要將帳密貼進報告。\n'
        '試用版固定不收集文件、瀏覽紀錄、程式使用紀錄及已安裝軟體清單；'
        '不套用 USB／應用程式／瀏覽器控制、不安裝瀏覽器擴充或系統根 CA、不自動更新。\n'
        '會回報裝置及登入工作階段識別、OS／架構／版本、遠端就緒及效能狀態；'
        '失敗診斷僅含原生階段、錯誤型別及代碼，不傳送帳密、鍵入文字或額外畫面；'
        '協助期間傳送畫面、游標與操作，中心保留協助授權與開始／結束紀錄。\n'
        '全機受保護程式及 Windows 服務 GuardDeskRemote 使用 Program Files／ProgramData 下 GuardDeskPilot；'
        '私人安裝與就緒資料使用目前帳號 LocalAppData 下 GuardDeskPilotClient。\n'
        '不可覆蓋已有的一般 Agent；若偵測到原安裝會保留並停止。\n'
        '結束測試：以原安裝帳號雙擊 Uninstall-Remote-Test.cmd，核准 UAC。'
        '解除啟動工作並停止協助；診斷與程式檔案會保留，沒有自動刪除其他帳號資料。\n'
        '此包含測試中心註冊碼，請只在這次測試使用，勿公開分享。\n'
        '目前為單一未旋轉螢幕，輸出最多 1080p；VPN 可達性、真 UAC／效能尚待驗收。'
        '安裝成功不代表上述驗收完成，也不保證防護軟體不告警。\n'
    ).encode('utf-8-sig'))
