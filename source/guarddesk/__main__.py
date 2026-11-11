import argparse
import getpass
import json
import logging
import os
import secrets
import signal
import sys
import threading
import time
from pathlib import Path
from .agent import Agent, enroll, private_write, request


def main():
    for stream in (sys.stdout, sys.stderr):
        if stream and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="GuardDesk 公司內部端點防護試用版")
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add-user", help="建立管理員／稽核員，密碼以互動方式輸入")
    add.add_argument("username")
    add.add_argument("--role", choices=["admin", "auditor", "support"], default="admin")
    add.add_argument("--db", default="runtime/control.sqlite3")
    server = sub.add_parser("serve")
    server.add_argument("--config", help="Server JSON 設定；相對路徑以設定檔目錄為準")
    server.add_argument("--db")
    server.add_argument("--host")
    server.add_argument("--port", type=int)
    server.add_argument("--cert")
    server.add_argument("--key")
    server.add_argument('--open-console', action='store_true', help='啟動後開啟 Server 本機管理畫面')
    setup = sub.add_parser('server-setup', help='互動式建立 Server 資料目錄、MIS 帳號與內網連線檔')
    setup.add_argument('--root', help='專用資料目錄；必須尚不存在')
    check = sub.add_parser('server-check', help='檢查 Server 設定、既有資料庫與 TLS；不啟動、不建立資料庫')
    check.add_argument('--config', required=True)
    register = sub.add_parser("enroll")
    register.add_argument("--server")
    register.add_argument('--connection', help='MIS 提供的 endpoint-connection.json')
    register.add_argument('--private-runtime', action='store_true', help='為新端點建立受保護的設定目錄')
    register.add_argument("--watch", required=True)
    register.add_argument("--config", default="runtime/agent/config.json")
    register.add_argument("--name")
    register.add_argument("--department", default="試用組")
    register.add_argument("--ca")
    run = sub.add_parser("agent")
    run.add_argument("--config", default="runtime/agent/config.json")
    run.add_argument("--once", action="store_true")
    endpoint = sub.add_parser('endpoint-setup', help='輸入註冊碼後接續安裝原生元件及登入自動啟動')
    endpoint.add_argument('--connection', required=True)
    endpoint.add_argument('--upgrade-existing', action='store_true', help='明確升級同中心、同原身分的既有全機 Agent，不建立新端點')
    native_setup = sub.add_parser('endpoint-native-install', help='安裝入口的 UAC 子程序；使用者請雙擊 Setup-Endpoint.cmd')
    native_setup.add_argument('--config', required=True)
    native_setup.add_argument('--action', choices=['Install', 'Uninstall', 'Status'], required=True)
    native_setup.add_argument('--diagnostic-pipe', required=True)
    native_setup.add_argument('--lab01-remote-test',action='store_true',help='LAB01 單機原生測試；先核對既有中心與原身分')
    lab01=sub.add_parser('lab01-remote-test',help='LAB01 既有完整 Agent 原生遠端測試；不重新註冊')
    lab01.add_argument('--check-only',action='store_true')
    desktop = sub.add_parser('desktop-agent', help='以使用者權限在背景執行一般 Agent')
    desktop.add_argument('--config')
    machine_session = sub.add_parser('machine-session', help='全機 Agent 的標準使用者工作階段；不註冊新端點')
    machine_session.add_argument('--parent', type=int, required=True)
    remote_admin=sub.add_parser('remote-admin-session',help='受保護、已同意的管理員遠端工作階段')
    remote_admin.add_argument('--device-id',required=True);remote_admin.add_argument('--session-id',required=True)
    sub.add_parser('component-info',help='輸出程式版本與更新協定，不啟動收集器')
    custom_session=sub.add_parser('custom-session-action',help='在使用者互動桌面執行固定鎖定／登出動作')
    custom_session.add_argument('--action',required=True,choices=['lock','logoff','idle'])
    document_context=sub.add_parser('document-session-context',help='文件稽核的每會話輸入時間與前景程序 metadata；不收按鍵或畫面')
    document_context.add_argument('--pipe',required=True);document_context.add_argument('--parent',required=True,type=int)
    verify_archive=sub.add_parser('verify-audit-archive',help='唯讀驗證匯出備份資料夾的 SHA-256 與原始事件雜湊')
    verify_archive.add_argument('--directory',required=True)
    viewer=sub.add_parser('remote-viewer',help='開啟獨立 Windows 遠端協助程式')
    viewer.add_argument('--server',default='http://127.0.0.1:8788')
    updater=sub.add_parser('update-service',help='受保護的 SYSTEM 更新元件')
    updater.add_argument('--config',required=True)
    apply_update=sub.add_parser('apply-user-update',help='一般 Agent 的已授權更新交易')
    apply_update.add_argument('--config',required=True);apply_update.add_argument('--job-id',required=True)
    sub.add_parser('endpoint-stop', help='停止目前使用者的一般背景 Agent')
    sub.add_parser('endpoint-uninstall', help='還原原生元件、移除本使用者登入啟動，保留資料')
    removal_job=sub.add_parser('endpoint-remove-job',help='受保護的完整移除工作；只接受既有工作識別碼')
    removal_job.add_argument('--job-id',required=True)
    package = sub.add_parser('endpoint-package', help='將公開連線 ZIP 與新版程式整合為單一端點安裝 ZIP')
    package.add_argument('--connection-zip', required=True); package.add_argument('--output', required=True)
    export = sub.add_parser("export")
    export.add_argument("source")
    export.add_argument("target")
    export.add_argument("--config", default="runtime/agent/config.json")
    for command in ("encrypt", "decrypt"):
        vault = sub.add_parser(command)
        vault.add_argument("source")
        vault.add_argument("target")
        vault.add_argument("--key", required=True)
    sub.add_parser("demo", help="建立本機試用資料夾、管理員與真實 Agent；前景執行")
    sub.add_parser('process-audit-status',help='唯讀查詢 Windows 程序稽核設定；需要稽核權限')
    file_check=sub.add_parser('file-audit-check',help='唯讀檢查單一文件／資料夾的 SACL 與 File System 原則；不掃磁碟')
    file_check.add_argument('--path',required=True)
    browser_policy=sub.add_parser('browser-policy',help='MIS 企業擴充策略；保留其他公司策略及可回復紀錄')
    browser_policy.add_argument('--config',required=True)
    browser_policy.add_argument('--settings')
    browser_policy.add_argument('--action',choices=['plan','apply','restore'],default='plan')
    browser_trust=sub.add_parser('browser-trust',help='公司授權的原中心 CA 信任；只接受受保護原生設定')
    browser_trust.add_argument('--config',required=True)
    browser_trust.add_argument('--action',choices=['status','apply','restore'],default='status')
    browser_release=sub.add_parser('browser-release',help='離線產生企業擴充發布來源／匹配金鑰的自架 CRX3；不套用政策、不上傳')
    browser_release.add_argument('--output',required=True)
    browser_release.add_argument('--base-url')
    browser_release.add_argument('--signer-key')
    browser_release.add_argument('--encrypted-key',action='store_true',help='由互動提示讀取金鑰密碼，不放命令列')
    backup=sub.add_parser('server-backup',help='一致性備份管理中心 SQLite；輸出目錄必須事先限制存取')
    backup.add_argument('--db',default='runtime/control.sqlite3');backup.add_argument('--output',required=True);backup.add_argument('--migration',action='store_true')
    optimize=sub.add_parser('optimize-storage',help='停止中心後：備份、搬移舊事件至分日日檔、驗證並壓縮主庫')
    optimize_source=optimize.add_mutually_exclusive_group(required=True)
    optimize_source.add_argument('--config');optimize_source.add_argument('--db')
    for command in ('windows-install','windows-uninstall','windows-status','browser-install','browser-uninstall'):
        control=sub.add_parser(command)
        control.add_argument('--config',default='runtime/agent/config.json')
        if command=='browser-install':control.add_argument('--host-exe')
    native=sub.add_parser('browser-host',help='瀏覽器 native-messaging stdio 收集器')
    native.add_argument('--config',default='runtime/agent/config.json')
    usb=sub.add_parser('usb-worker',help='以管理員／SYSTEM 執行 USB 原生控制背景工作')
    usb.add_argument('--config',required=True)
    usb.add_argument('--once',action='store_true')
    usb.add_argument('--restore',action='store_true')
    usb.add_argument('--extended',action='store_true',help='另啟用應用程式稽核與 AppLocker 策略適配器')
    service=sub.add_parser('remote-service-worker',help='固定全機服務的受保護工作元件')
    service.add_argument('--device-id',required=True)
    service.add_argument('--stop-handle',type=int,required=True)
    install=sub.add_parser('usb-install',help='以 Windows UAC 安裝 USB 控制與開機工作')
    install.add_argument('--config',default='runtime/agent/config.json')
    install.add_argument('--action',choices=['Install','Uninstall','Status'],default='Install')
    inspect_app=sub.add_parser('app-file-info',help='取得 Windows AppLocker 專用 SHA-256；不同於一般檔案 SHA-256')
    inspect_app.add_argument('path')
    inspect_package=sub.add_parser('app-package-info',help='唯讀取得目前使用者已安裝封裝應用程式的精確識別')
    inspect_package.add_argument('name')
    updater_check=sub.add_parser('updater-check',help='MIS 管理員唯讀檢查既有更新器；不執行更新')
    updater_check.add_argument('--device-id',required=True)
    preflight=sub.add_parser('updater-preflight',help='MIS 唯讀檢查候選版本與既有更新工作集；不清理或派送')
    preflight.add_argument('--device-id',required=True)
    args = parser.parse_args()
    from .remote_trial import command_allowed
    command_allowed(args.command)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if args.command=='document-session-context':
        from .document_context import run_helper
        run_helper(args.pipe,args.parent)
    elif args.command=='file-audit-check':
        from .file_audit_check import inspect
        print(json.dumps(inspect(args.path),ensure_ascii=False,indent=2))
    elif args.command=='browser-release':
        from .browser_release import build
        password=getpass.getpass('企業 CRX 金鑰密碼：').encode('utf-8') if args.encrypted_key else None
        print(json.dumps(build(args.output,args.base_url,args.signer_key,password),ensure_ascii=False,indent=2))
    elif args.command=='browser-trust':
        from .browser_trust import protected,execute,WindowsRoots
        config,root=protected(args.config)
        result=execute(config,args.action,root,WindowsRoots())
        print(json.dumps(result,ensure_ascii=False,indent=2))
        if result['status']=='preserved_after_interruption':raise OSError('CA 信任歸屬無法確認；已保留憑證與復原紀錄，請 MIS 核對')
    elif args.command=='browser-policy':
        from .custom_windows import trusted_native
        from .browser_deployment import execute,Registry
        config_path=Path(args.config).resolve()
        config=json.loads(config_path.read_text(encoding='utf-8'))
        root=trusted_native(config)
        if config_path!=root/'config.json':raise ValueError('Browser deployment requires the protected configuration')
        from .update_native import protected_tree
        protected_tree(config_path,recursive=False)
        if args.settings and Path(args.settings).stat().st_size>8192:raise ValueError('Browser policy settings too large')
        settings=json.loads(Path(args.settings).read_text(encoding='utf-8-sig')) if args.settings else config.get('browser_deployment')
        if args.action!='restore' and not settings:raise ValueError('請指定公司核定的 browser-deployment.json 或使用已安裝的發布設定')
        if args.action!='restore' and (not args.settings or 'public_key' in settings):
            from .browser_deployment import verify_authorization
            if settings!=config.get('browser_deployment'):raise ValueError('Company deployment differs from authorized protected configuration')
            verify_authorization(settings,config.get('browser_deployment_authorization'),config.get('update_key'))
        result=execute(settings,args.action,root,Registry())
        print(json.dumps(result,ensure_ascii=False,indent=2))
    elif args.command == 'custom-session-action':
        from .custom_windows import session_action
        result=session_action(args.action)
        if result is not None:raise SystemExit(result)
    elif args.command == 'app-package-info':
        from .application_control import package_info
        print(json.dumps(package_info(args.name),ensure_ascii=False,indent=2))
    elif args.command == 'updater-check':
        from .update_native import check_installed
        result=check_installed(args.device_id)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        if not result['passed']:raise SystemExit(2)
    elif args.command == 'updater-preflight':
        from .update_preflight import inspect
        result=inspect(args.device_id)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        if result.get('capacity_passed') is False:raise SystemExit(2)
    elif args.command == "add-user":
        from .store import Store
        password = getpass.getpass("密碼（不可空白）: ")
        if password != getpass.getpass("再輸入一次: "):
            raise ValueError("兩次密碼不一致")
        Store(args.db).add_user(args.username, password, args.role)
        print("帳號已建立")
    elif args.command == "serve":
        if args.config:
            if any(getattr(args, key) is not None for key in ('db', 'host', 'port', 'cert', 'key')):
                raise ValueError('--config 不可與 --db／--host／--port／--cert／--key 混用')
            from .server_config import load, start
            settings = load(args.config)
            from .server_setup import maintenance_launcher
            maintenance_launcher(Path(args.config).resolve().parent,Path(sys.executable))
            if args.open_console and 'local_console_port' not in settings:
                raise ValueError('--open-console 需使用有 local_console_port 的設定檔')
            servers = start(settings)
            console_url = f"http://127.0.0.1:{settings['local_console_port']}" if args.open_console else None
            run_servers(servers, stop, console_url)
        else:
            if args.open_console:
                raise ValueError('--open-console 請搭配 --config')
            # Endpoint roles share this CLI but must not load the center merely
            # to start. This is an import boundary, not a role authorization gate.
            from .server import serve
            server = serve(args.db or 'runtime/control.sqlite3', args.host or '127.0.0.1',
                           args.port if args.port is not None else 8787, args.cert, args.key)
            run_server(server, stop)
    elif args.command == 'server-setup':
        from .server_setup import wizard
        wizard(args.root)
    elif args.command == 'server-check':
        from .server_config import load, check
        print(json.dumps(check(load(args.config)), ensure_ascii=False, indent=2))
    elif args.command == "enroll":
        embedded_code = None
        url, ca = args.server or 'http://127.0.0.1:8787', args.ca
        if args.connection:
            if args.server or args.ca: raise ValueError('--connection 不可與 --server／--ca 混用')
            from .server_setup import read_connection
            url, ca = read_connection(args.connection)
            embedded_code = json.loads(Path(args.connection).read_text(encoding='utf-8-sig')).get('deployment_code')
        directory = None
        created_directory = False
        try:
            if args.private_runtime:
                from .server_setup import secure_directory
                directory = Path(args.config).resolve().parent
                directory.parent.mkdir(parents=True, exist_ok=True)
                directory = secure_directory(directory)
                created_directory = True
            eid = enroll(args.config, url, embedded_code or getpass.getpass("一次性註冊碼: "), args.watch, args.name, args.department, ca)
        except BaseException:
            if created_directory and directory.exists():
                try: directory.rmdir()  # Only an empty directory created for this enrollment.
                except OSError: pass
            raise
        print("端點註冊完成：" + eid)
    elif args.command == "agent":
        agent = Agent(args.config)
        if args.once:
            agent.scan()
            agent.heartbeat()
            agent.flush()
            agent.heartbeat()
        else:
            agent.run(stop)
    elif args.command == 'component-info':
        from . import __version__
        print(json.dumps({'version':__version__,'update_protocol':1,'architecture':'windows-x64'}))
    elif args.command == 'update-service':
        from .update_native import run
        run(args.config,stop)
    elif args.command == 'apply-user-update':
        from .update_client import apply_user
        apply_user(args.config,args.job_id)
    elif args.command == 'endpoint-setup':
        from .endpoint_setup import install
        result=install(args.connection,upgrade_existing=True) if args.upgrade_existing else install(args.connection)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        from .remote_trial import enabled
        if enabled():
            print('完成：僅遠端協助測試元件已啟動；請由測試中心核對連線，UAC／效能仍待驗收。')
        else:
            print('完成：一般 Agent 已在背景啟動，以後使用者登入會自動執行。請由 MIS 核對端點在線與策略狀態。')
    elif args.command == 'machine-session':
        from .machine_agent_session import run
        run(args.parent, stop)
    elif args.command == 'remote-admin-session':
        from .remote_admin_windows import run
        run(args.device_id,args.session_id,stop)
    elif args.command == 'desktop-agent':
        from .desktop_agent import client_root, run
        config = Path(args.config).resolve() if args.config else client_root() / 'runtime/agent/config.json'
        marker = config.parent.parent.parent / 'endpoint-install.json'
        if marker.is_file() and json.loads(marker.read_text(encoding='utf-8')).get('phase') == 'removed': return
        run(config, stop)
    elif args.command == 'endpoint-native-install':
        from .usb_install import helper
        if args.lab01_remote_test:raise SystemExit(helper(args.config,args.action,args.diagnostic_pipe,remote_test=True))
        raise SystemExit(helper(args.config, args.action, args.diagnostic_pipe))
    elif args.command=='lab01-remote-test':
        from .remote_test_install import run
        print(json.dumps(run(args.check_only),ensure_ascii=False))
    elif args.command == 'endpoint-stop':
        from .desktop_agent import client_root, stop_running
        stop_running(client_root() / 'runtime/agent/config.json')
        print('一般 Agent 已停止；原生 USB／程序稽核背景工作保留。')
    elif args.command == 'endpoint-uninstall':
        from .endpoint_setup import uninstall
        print(json.dumps(uninstall(), ensure_ascii=False))
    elif args.command == 'endpoint-remove-job':
        from .remote_removal import run
        raise SystemExit(run(args.job_id))
    elif args.command == 'endpoint-package':
        from .endpoint_package import build, application_directory
        print(build(application_directory(), args.connection_zip, args.output))
    elif args.command == "export":
        print(json.dumps(Agent(args.config).export(args.source, args.target), ensure_ascii=False))
    elif args.command in ("encrypt", "decrypt"):
        from .vault import load_key, encrypt, decrypt
        key = load_key(args.key, create=args.command == "encrypt")
        action = encrypt if args.command == "encrypt" else decrypt
        print("已建立：" + str(action(args.source, args.target, key)))
    elif args.command == 'remote-viewer':
        from .remote_viewer import run
        run(['--server',args.server])
    elif args.command == "demo":
        demo(stop)
    elif args.command in ('windows-install','windows-uninstall','windows-status'):
        from .windows_controls import WindowsControls
        agent=Agent(args.config);controls=WindowsControls(agent)
        if args.command=='windows-install':
            policy=agent.heartbeat()['body']
            result={'audit':controls.install(policy),'controls':controls.apply(policy)}
        elif args.command=='windows-uninstall':result=controls.uninstall()
        else:result={'installed':controls.installed,'queue':agent.queue_status(),'cached_policy_version':agent.cached_policy()['version'],'runtime':str(agent.state)}
        print(json.dumps(result,ensure_ascii=False,indent=2))
    elif args.command=='browser-install':
        from .browser_host import register
        print(json.dumps(register(args.config,args.host_exe),ensure_ascii=False,indent=2))
    elif args.command=='browser-uninstall':
        from .browser_host import unregister
        print(json.dumps(unregister(args.config),ensure_ascii=False,indent=2))
    elif args.command=='browser-host':
        from .browser_host import run_host
        run_host(args.config)
    elif args.command=='remote-service-worker':
        from .remote_service_worker import run
        return run(args.device_id,args.stop_handle,stop)
    elif args.command=='usb-worker':
        from . import remote_trial
        if remote_trial.enabled():
            result=remote_trial.worker(args.config,stop,once=args.once,restore=args.restore)
            if result is not None:print(json.dumps(result,ensure_ascii=False))
            return
        from .native_usb import UsbWorker
        worker=UsbWorker(args.config)
        if args.restore:
            if args.extended:
                from .application_control import ExtendedWorker
                ExtendedWorker(worker.agent).restore()
            print(json.dumps(worker.restore(),ensure_ascii=False))
        elif args.once:
            result=worker.cycle(require_online=True)
            print(json.dumps(result,ensure_ascii=False))
            if result['status']=='failed':raise OSError(result.get('error','USB 套用失敗'))
            if args.extended:
                from .application_control import ExtendedWorker
                companion=ExtendedWorker(worker.agent,start_documents=False)
                try:extended=companion.configure()
                finally:companion.close()
                if extended.get('status')=='failed':raise OSError(extended.get('error','應用程式控制套用失敗'))
        else:worker.run(stop,extended=args.extended)
    elif args.command=='usb-install':
        from .usb_install import install
        print(json.dumps(install(args.config,args.action),ensure_ascii=False))
    elif args.command=='server-backup':
        from .server_backup import snapshot
        print(json.dumps(snapshot(args.db,args.output,args.migration),ensure_ascii=False))
    elif args.command=='optimize-storage':
        from .storage_maintenance import optimize
        from .server_config import load
        path=load(args.config)['db'] if args.config else args.db
        def progress(value):print(json.dumps(value,ensure_ascii=False),file=sys.stderr,flush=True)
        print(json.dumps(optimize(path,progress),ensure_ascii=False))
    elif args.command=='verify-audit-archive':
        from .audit_archive import verify_directory
        from .audit_reports import AuditError
        try:result=verify_directory(args.directory)
        except AuditError as exc:print(json.dumps({'valid':False,'error':exc.message},ensure_ascii=False));raise SystemExit(2)
        print(json.dumps(result,ensure_ascii=False))
    elif args.command=='process-audit-status':
        from .process_audit import read_flags
        print(json.dumps({'source':'AuditQuerySystemPolicy','flags':read_flags(None)}))
    elif args.command=='app-file-info':
        from .application_control import file_info
        print(json.dumps(file_info(args.path),ensure_ascii=False))


def run_server(server, stop):
    run_servers([server], stop)


def run_servers(servers, stop, console_url=None):
    threads = []
    try:
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start(); threads.append(thread)
            print(f"GuardDesk 已啟動：{'https' if server.tls else 'http'}://{server.server_address[0]}:{server.server_address[1]}，Ctrl+C 停止", flush=True)
        if console_url:
            import webbrowser
            webbrowser.open(console_url)
        while not stop.wait(0.5):
            if not all(thread.is_alive() for thread in threads):
                raise RuntimeError("管理中心已停止")
    finally:
        for server, thread in zip(servers, threads):
            server.shutdown(); thread.join(5)
        for server in servers:
            server.server_close()


def demo(stop):
    from .server import serve
    from .store import Store, digest
    root = Path("runtime").resolve()
    root.mkdir(exist_ok=True)
    store = Store(root / "control.sqlite3")
    credentials = root / "access.txt"
    with store.connect() as db:
        exists = db.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    if not exists:
        password = secrets.token_urlsafe(18)
        store.add_user("admin", password)
        with credentials.open("x", encoding="utf-8") as stream:
            stream.write("URL: http://127.0.0.1:8787\nUsername: admin\nPassword: " + password + "\n")
        if os.name != "nt":
            credentials.chmod(0o600)
    watch = root / "managed"
    watch.mkdir(exist_ok=True)
    if not (watch / "welcome.txt").exists():
        (watch / "welcome.txt").write_text("GuardDesk 受控外發測試文件\n", encoding="utf-8")
    if not (watch / "confidential.txt").exists():
        (watch / "confidential.txt").write_text("CONFIDENTIAL — 外發測試用虛構內容\n", encoding="utf-8")
    (root / "exports").mkdir(exist_ok=True)
    server = serve(store.path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = root / "agent" / "config.json"
    try:
        if not config.exists():
            token = secrets.token_urlsafe(24)
            with store.connect() as db:
                db.execute("INSERT INTO enrollments(token,expires) VALUES (?,?)", (digest(token), time.time() + 900))
            enroll(config, "http://127.0.0.1:8787", token, watch, department="本機試用")
        agent = Agent(config)
        agent_thread = threading.Thread(target=agent.run, args=(stop,), daemon=True)
        agent_thread.start()
        print("GuardDesk：http://127.0.0.1:8787\n登入資料：" + str(credentials) + "\n監看資料夾：" + str(watch) + "\nCtrl+C 停止", flush=True)
        while not stop.wait(0.5):
            if not agent_thread.is_alive() and not getattr(agent,'decommissioned',False):
                raise RuntimeError("Agent 已停止")
    finally:
        stop.set()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, PermissionError, ConnectionError, OSError) as exc:
        raise SystemExit(str(exc))
