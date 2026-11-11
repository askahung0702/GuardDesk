"""One endpoint entry: private stage, enroll once, UAC, logon start, launch."""
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from . import __version__
from .endpoint_transport import enroll
from .desktop_agent import client_root, active, stop_running
from .endpoint_package import sha, required_files, package_roots
from .endpoint_files import read_connection, secure_directory, plain, save

RUN_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'








def autostart(name, command, previous=None, remove=False):
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        try: old, kind = winreg.QueryValueEx(key, name)
        except FileNotFoundError: old, kind = None, None
        if old is not None and (kind != winreg.REG_SZ or old not in (command, previous)):
            raise OSError('同名登入啟動設定不屬於目前安裝，保留原設定並交 MIS 核對')
        if remove:
            if old is not None: winreg.DeleteValue(key, name)
        else: winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)


def remove_autostart_for_config(config):
    config = Path(config).resolve(); root = config.parent.parent.parent
    marker = root / 'endpoint-install.json'
    if not marker.is_file(): return
    state = json.loads(marker.read_text(encoding='utf-8'))
    if state.get('product') != 'GuardDeskEndpoint' or Path(state.get('config', '')).resolve() != config:
        raise OSError('端點安裝資訊不符，保留登入啟動設定')
    if state.get('startup_name') and state.get('startup_command'):
        autostart(state['startup_name'], state['startup_command'], remove=True)
        state['autostart'] = False; save(marker, state)


def stage_application(package, root):
    plain(package); plain(root)
    package = Path(package).resolve()
    manifest_path = package / 'endpoint-files.json'
    if manifest_path.stat().st_size > 2 * 1024 * 1024: raise ValueError('程式清單過大')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if not isinstance(manifest, dict): raise ValueError('端點程式清單不正確')
    hashes = manifest.get('files')
    if not isinstance(hashes, dict) or not 2 <= len(hashes) <= 10000 or not re.fullmatch(r'[0-9.]+', manifest.get('version', '')):
        raise ValueError('端點程式清單不正確')
    if not required_files() <= hashes.keys(): raise ValueError('端點執行包不完整，請從新版管理中心重新下載')
    if manifest['version'] != __version__: raise ValueError('端點程式與安裝清單版本不一致，請重新取得完整包')
    sources = []
    for relative, expected in hashes.items():
        if not isinstance(relative, str) or not (relative in package_roots() or relative.startswith('_internal/')) or any(part in ('', '.', '..') for part in relative.split('/')) or '\\' in relative or ':' in relative:
            raise ValueError('端點程式路徑不正確')
        path = package / 'GuardDesk' / relative
        plain(path)
        if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected): raise ValueError('程式雜湊格式不正確')
        if not path.resolve().is_relative_to(package / 'GuardDesk') or path.is_symlink() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('端點程式路徑不正確')
        if sha(path) != expected: raise ValueError('端點程式雜湊不符，請重新向 MIS 取得安裝包')
        sources.append((relative, path, expected))
    if sum(p.stat().st_size for _, p, _ in sources) > 512 * 1024 * 1024: raise ValueError('端點程式過大')
    app_parent = root / 'app'; plain(app_parent); app_parent.mkdir(exist_ok=True)
    target = app_parent / (manifest['version'] + '-' + hashes['GuardDesk.exe'][:16])
    plain(target)
    target.mkdir(exist_ok=True)
    for relative, source, expected in sources:
        destination = target / relative
        plain(destination)
        if not destination.resolve().is_relative_to(target) or destination.is_symlink(): raise ValueError('安裝路徑不正確')
        if destination.is_file() and sha(destination) == expected: continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        if sha(destination) != expected: raise OSError('複製後雜湊核對失敗')
    return target


def launch(app, config):
    if active(config): return 'already_running'
    status = Path(config).parent / 'desktop-status.json'
    status.unlink(missing_ok=True)
    process = subprocess.Popen([str(app / 'GuardDeskAgent.exe'), 'desktop-agent', '--config', str(config)],
        cwd=app, creationflags=subprocess.CREATE_NO_WINDOW, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if status.exists():
            try:
                if json.loads(status.read_text()).get('state') == 'running' and active(config): return 'running'
            except (OSError, ValueError): pass
        if process.poll() is not None: break
        time.sleep(.2)
    raise OSError('一般 Agent 未確認啟動，請查看私人 runtime 下 agent-background.log 並重試')


def session_ready(did,expected_version):
    from .machine_agent_session import config_path
    try:
        ready=config_path(did).parent/'desktop-status.json';plain(ready)
        if ready.stat().st_size>4096:return False
        status=json.loads(ready.read_text(encoding='utf-8'))
        return isinstance(status,dict) and status.get('state')=='running' and status.get('version')==expected_version and active(ready.with_name('config.json'))
    except (OSError,ValueError):return False


def install(connection, root=None, token_provider=None, native_install=None, start_agent=None, *, upgrade_existing=False):
    from .desktop_agent import instance
    if type(upgrade_existing) is not bool:raise ValueError('Invalid upgrade mode')
    if upgrade_existing:
        from .remote_trial import enabled
        from .machine_service import enabled as full_service
        if root is not None or not (enabled() or full_service()):raise ValueError('Explicit upgrade requires the compiled service installer')
    if root is None:
        from .machine_agent_session import discover
        url,ca=read_connection(Path(connection).resolve())
        machine=discover()
        if upgrade_existing and not machine:raise OSError('Existing machine identity required for explicit upgrade')
        if machine:
            from .remote_trial_install import check_settings
            check_settings(machine)
            if machine['server']!=url or machine.get('ca_sha256')!=sha(ca):
                raise ValueError('此電腦已有不同中心或憑證的全機 Agent，保留原身分並交 MIS 核對')
            # A failed initial install retains this user's original enrollment.
            # Allow a newer verified package to resume it instead of returning
            # already_installed merely because the SYSTEM identity is visible.
            destination=client_root();marker=destination/'endpoint-install.json';saved_config=destination/'runtime/agent/config.json'
            resume=False;matching=False
            if marker.is_file() and saved_config.is_file():
                plain(marker);plain(saved_config)
                if marker.stat().st_size>16384 or saved_config.stat().st_size>65536:raise ValueError('既有安裝資料過大，保留現狀並交 MIS 檢查')
                state=json.loads(marker.read_text(encoding='utf-8'));settings=json.loads(saved_config.read_text(encoding='utf-8'))
                if not isinstance(state,dict) or not isinstance(settings,dict):raise ValueError('既有安裝資料格式不符，保留原身分')
                from .update_packages import version
                matching=(state.get('product')=='GuardDeskEndpoint'
                        and Path(state.get('config','')).resolve()==saved_config.resolve()
                        and settings.get('device_id')==machine['device_id'] and settings.get('server')==machine['server'])
                pending=matching and state.get('last_result')=='incomplete_retry_same_installer'
                # A protected marker can authenticate the existing machine
                # identity even when its broken supervisor has no live pipe.
                # Only this user's matching incomplete install may repair it;
                # no fresh enrollment, implicit downgrade or completed-install
                # takeover is authorized by a missing connection.
                unavailable=machine.get('status')=='supervisor_unavailable'
                resume=pending and (version(machine['version'])<version(__version__) or
                    unavailable and version(machine['version'])==version(__version__))
                # Only the explicit same-identity entry may update a completed
                # live original install. Default setup keeps
                # their original boundaries; never reenroll or downgrade.
                completed=matching and state.get('last_result')=='completed'
                if upgrade_existing:
                    if (unavailable and not pending) or not (pending or completed) or version(machine['version'])>version(__version__):
                        raise OSError('Matching live original installation required; preserve identity')
                    resume=resume or completed and version(machine['version'])<version(__version__)
                if unavailable and not resume:
                    raise OSError('此電腦監督工作未連線，且沒有符合原身分的未完成安裝；保留原端點')
                if pending and not resume:
                    from .usb_install import diagnostic,InstallError
                    if not session_ready(machine['device_id'],machine['version']):
                        report=diagnostic(1,'GUARDDESK_STAGE=user_session\n全機元件已安裝，但本次使用者收集器仍未確認就緒；保留身分與佇列，請核對本次工作階段診斷',settings)
                        save(saved_config.parent/'installation-diagnostic.json',{**report,'version':__version__})
                        raise InstallError(report)
                    state.update(phase='ready',autostart='machine',last_result='completed');save(marker,state)
                    save(saved_config.parent/'installation-diagnostic.json',{'format':1,'version':__version__,'code':'completed','stage':'machine_ready'})
            if machine.get('status')=='supervisor_unavailable' and not resume:
                raise OSError('此電腦監督工作未連線，且沒有符合原身分的未完成安裝；保留原端點')
            if upgrade_existing and not matching:raise OSError('Original user install marker and configuration required for explicit upgrade')
            if not resume:
                return {'status':'already_installed','scope':'machine','device_id':machine['device_id'],
                        'version':machine['version'],'autostart':'all_user_sessions','registration':'preserved'}
    destination = Path(root or client_root()).absolute()
    with instance(destination / 'endpoint-setup') as acquired:
        if not acquired: raise OSError('端點安裝正在進行，請回到原本的安裝視窗；不要同時執行多份安裝程式。')
        return _install(connection, destination, token_provider, native_install, start_agent)


def _install(connection, root=None, token_provider=None, native_install=None, start_agent=None):
    if os.name != 'nt': raise OSError('簡易端點安裝只支援 Windows')
    from .windows_privilege import is_admin
    if is_admin(): raise PermissionError('請以實際使用者身分直接雙擊，不要先以管理員執行；原生元件會另顯示 UAC')
    connection = Path(connection).resolve(); package = connection.parent
    url, ca = read_connection(connection)
    from .update_packages import trust_file
    trust = package / 'update-trust.json'
    if not trust.is_file(): raise ValueError('缺少更新信任公鑰，請從新版管理中心重新下載完整端點安裝包。')
    pinned = trust_file(trust)  # Reject missing/corrupt update material before enrollment.
    body=json.loads(connection.read_text(encoding='utf-8-sig'))
    from .remote_trial_install import check_connection,check_settings
    check_connection(body,package)
    desired=body.get('browser_deployment');authorization=body.get('browser_deployment_authorization')
    if desired:
        from .browser_deployment import verify_authorization
        verify_authorization(desired,authorization,pinned)
    browser_trust=None
    if (package/'browser-trust.json').exists():
        if (package/'browser-trust.json').stat().st_size>2048:raise ValueError('Browser trust authorization too large')
        browser_trust=json.loads((package/'browser-trust.json').read_text(encoding='utf-8'))
        from .browser_trust import verify
        verify(browser_trust,pinned,url,Path(ca).read_bytes(),desired)
    root = Path(root or client_root()).absolute(); plain(root)
    if root.exists() and (root.is_symlink() or getattr(root.lstat(), 'st_file_attributes', 0) & 0x400): raise ValueError('安裝目錄不可為 junction／符號連結')
    marker = root / 'endpoint-install.json'
    config = root / 'runtime/agent/config.json'
    plain(marker); plain(config)
    if not marker.is_file():
        # Full removal deliberately preserves user documents. An empty wrapper
        # is not an old endpoint identity. Inspect at most two top-level entries;
        # never scan/delete document contents or adopt orphaned runtime/config.
        if root.exists():
            with os.scandir(root) as entries:
                entry = next(entries, None)
                extra = next(entries, None)
            if entry is not None:
                if extra is not None or entry.name.casefold() != 'pilotdocuments':
                    raise ValueError('目錄已有其他資料，保留現狀並由 MIS 檢查')
                documents = root / entry.name
                plain(documents)
                if not documents.is_dir():
                    raise ValueError('文件目錄類型不符，保留現狀並由 MIS 檢查')
                with os.scandir(documents) as children:
                    if next(children, None) is not None:
                        raise ValueError('PilotDocuments 尚有文件，請先移至其他文件目錄保留，再重新安裝')
                # Nonrecursive removal fails if a file appears concurrently.
                documents.rmdir()
        # Recreate only an empty root using the existing private-ACL creation
        # contract. This also refuses new entries or replacement junctions.
        secure_directory(root, allow_empty=True)
        save(marker, {'product': 'GuardDeskEndpoint', 'phase': 'created', 'config': str(config)})
    if not marker.is_file(): raise ValueError('目錄已有其他資料，保留現狀並由 MIS 檢查')
    state = json.loads(marker.read_text(encoding='utf-8'))
    if state.get('product') != 'GuardDeskEndpoint' or Path(state.get('config', '')).resolve() != config.resolve():
        raise ValueError('既有安裝資訊不符')
    if state.get('phase') != 'created' and not config.is_file():
        raise ValueError('既有端點設定遺失，請 MIS 還原原身分；不重新註冊')
    if config.exists():check_settings(json.loads(config.read_text(encoding='utf-8')))
    if (package / 'runtime/agent/config.json').exists() and not config.exists():
        raise ValueError('此執行包已有舊端點身分，請 MIS 移轉原身分，不重新註冊')
    was_running = config.exists() and active(config)
    previous_app = state.get('last_ready_app', state.get('app'))
    print('[1/5] 核對安裝包與檔案完整性。', flush=True)
    app = stage_application(package, root)
    runtime = config.parent; plain(runtime); runtime.mkdir(parents=True, exist_ok=True)
    stored_ca = runtime / 'GuardDesk-CA.pem'
    print('[2/5] 核對並保留既有端點；新端點才註冊。', flush=True)
    if config.exists():
        settings = json.loads(config.read_text(encoding='utf-8'))
        if settings['server'] != url or not stored_ca.is_file() or sha(stored_ca) != sha(ca):
            raise ValueError('連線包與既有 Server 身分不符，請 MIS 執行搬移，不覆寫端點')
        from .remote_trial import enabled
        if enabled():
            from .remote_endpoint_state import RemoteEndpointState
            agent = RemoteEndpointState(config)
        else:
            from .agent import Agent
            agent = Agent(config)
        from .decommission import saved
        if saved(agent): raise ValueError('此端點正在移除或已移除，請 MIS 檢查')
    else:
        shutil.copyfile(ca, stored_ca)
        watch = root / 'PilotDocuments'; watch.mkdir(exist_ok=True)
        code = body.get('deployment_code') or (token_provider or (lambda: getpass.getpass('一次性註冊碼: ')))()
        enroll(config, url, code, watch, ca=str(stored_ca))
    state.update(phase='enrolled', app=str(app), version=__version__); save(marker, state)
    settings=json.loads(config.read_text(encoding='utf-8'))
    if settings.get('update_key') and settings['update_key']!=pinned:raise ValueError('更新信任金鑰已變更，請 MIS 核對，未自動更換')
    settings['update_key']=pinned
    if desired:
        if settings.get('browser_deployment') not in (None,desired):raise ValueError('瀏覽器發布來源已改變；請 MIS 先核對／還原原政策，不自動替換')
        settings['browser_deployment']=desired
        settings['browser_deployment_authorization']=authorization
    if browser_trust:
        if settings.get('browser_trust') not in (None,browser_trust):raise ValueError('CA 信任授權改變，請 MIS 核對，不自動更換')
        settings['browser_trust']=browser_trust
    save(config,settings)
    print('[3/5] 註冊已保存。接著安裝受保護元件，請 MIS 核准 Windows UAC；不需要手動執行 PowerShell。', flush=True)
    from .usb_install import install as normal_native_install
    stopped = False
    try:
        (native_install or (lambda cfg: normal_native_install(cfg, source=app)))(config)
        from .remote_trial import enabled
        if enabled():print('僅遠端協助測試：不安裝瀏覽器擴充、不啟用日誌收集或自動升級。',flush=True)
        else:print('瀏覽器擴充：'+('企業部署政策已交由瀏覽器套用；需等待擴充實際連線，請 MIS 在中心核對。' if settings.get('browser_deployment') else '發布來源尚未設定；網站上傳收集尚未就緒，請 MIS 設定發布後重跑同一安裝包。'),flush=True)
        state['phase'] = 'native_installed'; save(marker, state)
        if native_install is None:
            from .machine_agent_session import discover
            machine=discover()
            if not machine or machine['device_id']!=settings['device_id']:
                raise OSError('受保護元件已安裝，但尚未確認全機 Agent；保留身分，請重試同一安裝包')
            deadline=time.monotonic()+60
            while time.monotonic()<deadline:
                if session_ready(settings['device_id'],__version__):break
                time.sleep(.2)
            else:raise OSError('GUARDDESK_STAGE=user_session\n全機元件已安裝，但本次使用者收集器尚未確認就緒；保留身分與佇列，請核對本次工作階段診斷')
            remove_autostart_for_config(config)
            state.update(phase='ready',autostart='machine',last_result='completed',last_ready_app=str(app));save(marker,state)
            save(runtime/'installation-diagnostic.json',{'format':1,'version':__version__,'code':'completed','stage':'machine_ready'})
            return {'status':'installed','scope':'machine','device_id':settings['device_id'],'root':str(root),
                    'autostart':'all_user_sessions','background_agent':'started'}
        print('[4/5] 設定登入啟動，準備一般 Agent。', flush=True)
        settings = json.loads(config.read_text(encoding='utf-8'))
        name = 'GuardDesk-Agent-' + settings['device_id']
        command = subprocess.list2cmdline([str(app / 'GuardDeskAgent.exe'), 'desktop-agent'])
        if len(command) > 260: raise OSError('登入啟動命令過長，請 MIS 調整安裝位置')
        autostart(name, command, state.get('startup_command'))
        state.update(startup_name=name, startup_command=command, autostart=True); save(marker, state)
        for filename, action in [('Start-Agent.cmd', 'desktop-agent'), ('Stop-Agent.cmd', 'endpoint-stop'), ('Uninstall-Endpoint.cmd', 'endpoint-uninstall')]:
            cli = 'GuardDeskAgent.exe' if action == 'desktop-agent' else 'GuardDesk.exe'
            text = '@echo off\r\nchcp 65001 >nul\r\nsetlocal DisableDelayedExpansion\r\n"' + str(app / cli).replace('%', '%%') + '" ' + action + '\r\n'
            if action != 'desktop-agent': text += 'pause\r\n'
            (root / filename).write_text(text, encoding='utf-8')
        from .mis_support import write_launcher
        write_launcher(root,app,config)
        print('[5/5] 確認一般 Agent 在背景啟動。', flush=True)
        if was_running: stop_running(config); stopped = True
        (start_agent or launch)(app, config)
        state.update(phase='ready', last_result='completed', last_ready_app=str(app)); save(marker, state)
        log = runtime / 'installation-diagnostic.json'; plain(log)
        save(log, {'format': 1, 'version': __version__, 'code': 'completed', 'stage': 'ready'})
        return {'status': 'installed', 'device_id': settings['device_id'], 'root': str(root), 'autostart': 'current_user_logon', 'background_agent': 'started', 'browser_extension':'policy_written_await_browser' if settings.get('browser_deployment') else 'publication_required'}
    except (OSError, ValueError, ConnectionError) as exc:
        state['last_result'] = 'incomplete_retry_same_installer'; save(marker, state)
        from .usb_install import diagnostic, InstallError
        report = getattr(exc, 'report', None) or diagnostic(1, str(exc), json.loads(config.read_text(encoding='utf-8')))
        log = runtime / 'installation-diagnostic.json'; plain(log)
        save(log, {**report, 'version': __version__})
        print('尚未完成。可重跑同一個 Setup-Endpoint.cmd，沿用既有身分與待補送資料。\n安裝診斷：' + str(log), flush=True)
        if stopped and previous_app:
            try: (start_agent or launch)(Path(previous_app), config)
            except (OSError, ValueError): print('舊一般 Agent 尚未恢復，請 MIS 依診斷處理並重試。', flush=True)
        if isinstance(exc, PermissionError): raise PermissionError(str(InstallError(report))) from None
        if isinstance(exc, ValueError): raise ValueError(str(InstallError(report))) from None
        raise InstallError(report) from None


def uninstall(root=None):
    root = Path(root or client_root()); config = root / 'runtime/agent/config.json'
    settings = json.loads(config.read_text(encoding='utf-8'))
    if settings.get('proxy_enabled') or (config.parent / 'windows/installed.json').exists():
        raise OSError('請先由 MIS 處理瀏覽器擴充／代理及舊式 SACL/QoS，保留目前保護')
    stop_running(config)
    state = json.loads((root / 'endpoint-install.json').read_text(encoding='utf-8'))
    from .usb_install import install as native_install
    native_install(config, 'Uninstall', source=Path(state['app']))
    from .browser_host import unregister_owned
    unregister_owned(config)
    remove_autostart_for_config(config)
    state = json.loads((root / 'endpoint-install.json').read_text(encoding='utf-8'))
    state['phase'] = 'removed'; save(root / 'endpoint-install.json', state)
    return {'status': 'removed', 'files_retained': True}
