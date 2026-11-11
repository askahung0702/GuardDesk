"""Local-only console setup; private agent transport, no global trust changes."""
import ctypes
import datetime
import getpass
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sys
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from .server_config import local_database, load, check
from .server_backup import snapshot
from .store import Store, validate_password




def destination_state(path):
    """Read-only wizard preflight before requesting a name or password."""
    path = Path(os.path.abspath(path))
    local_database(path / 'control.sqlite3')
    for candidate in (path.parent, *path.parent.parents):
        if getattr(candidate.lstat(), 'st_file_attributes', 0) & 0x400 or candidate.is_symlink():
            raise ValueError('資料目錄不可經過 junction／符號連結')
    if not os.path.lexists(path): return 'new'
    if (getattr(path.lstat(), 'st_file_attributes', 0) & 0x400 or path.is_symlink() or
            not path.is_dir() or path == Path(path.anchor)):
        raise ValueError('請使用一般專用資料夾，不可使用磁碟根目錄或 junction／符號連結')
    if not any(path.iterdir()): return 'empty'
    if (path / 'server.json').is_file() and (path / 'Start-Management.cmd').is_file():
        settings = load(path / 'server.json')
        if settings['db'].is_file() and 'local_console_port' in settings:
            return 'installed'
    raise ValueError('資料夾已有資料，未變更任何檔案；若是未完成的安裝，請保留原資料並選另一個空資料夾')


def server_name(value):
    value = value.strip().lower()
    try:
        address = ipaddress.ip_address(value)
        if address.version != 4 or address.is_unspecified or address.is_loopback or address.is_multicast:
            raise ValueError('請填固定內網 IPv4，不可使用 0.0.0.0／127.0.0.1')
        return str(address), x509.IPAddress(address)
    except ValueError:
        if value == 'localhost' or len(value) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value):
            raise ValueError('請填 Server 固定 IPv4 或內網 DNS 名稱，不含 http、連接埠或斜線') from None
        labels = value.split('.')
        if all(label.isdigit() for label in labels) or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
            raise ValueError('Server IP／DNS 名稱不正確') from None
        return value, x509.DNSName(value)


def write(path, data):
    with Path(path).open('xb') as stream:
        stream.write(data)
    if os.name != 'nt': Path(path).chmod(0o600)


def certificates(folder, san):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'GuardDesk private CA ' + secrets.token_hex(6))])
    ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'GuardDesk endpoint transport')])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    for name, value in [('ca.key', ca_key), ('server.key', key)]:
        write(folder / name, value.private_bytes(serialization.Encoding.PEM,
              serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    write(folder / 'ca.pem', ca_pem)
    write(folder / 'server.crt', cert.public_bytes(serialization.Encoding.PEM) + ca_pem)
    return ca_pem


def native_settings(address, console_ipv4=None):
    """Fresh internal build opt-in, never a migration or policy override."""
    from .machine_service import enabled
    if not enabled():return None
    if console_ipv4 is None:
        try:
            candidate=ipaddress.IPv4Address(address)
            console_ipv4=[str(candidate)] if candidate.is_private and not candidate.is_loopback and not candidate.is_link_local else []
        except ValueError:console_ipv4=[]
    from .remote_preview_config import parse
    value={'enabled':True,'console_ipv4':console_ipv4}
    parse(value,Path('server.json')) # The same strict private-address schema.
    return value


def create(root, address, username=None, password=None, source=None, exe=None, port=8787, console_port=8788, native_console_ipv4=None):
    from .remote_trial import enabled
    if enabled() and source:raise ValueError('遠端試用中心只使用全新測試資料庫，不匯入既有中心。')
    address, san = server_name(address)
    root = Path(os.path.abspath(root))
    local_database(root / 'control.sqlite3')
    if type(port) is not int or type(console_port) is not int or not 1 <= port <= 65535 or not 1 <= console_port <= 65535 or port == console_port:
        raise ValueError('連接埠不正確')
    if not source:
        validate_password(password)
        if not isinstance(username, str) or not username.strip() or len(username) > 80:
            raise ValueError('請填 MIS 帳號')
    if source and not Path(source).is_file(): raise ValueError('找不到舊中心搬移快照')
    native=None if source else native_settings(address,native_console_ipv4)
    exe = Path(exe).resolve(strict=True)
    if exe.name.casefold() == 'guarddesk.exe':
        from .endpoint_package import files
        files(exe.parent)  # Validate before creating any server data.
    secure_directory(root, allow_empty=True)
    tls = root / 'tls'; tls.mkdir()
    if source:
        snapshot(source, root / 'control.sqlite3', migration=True)
    else:
        fresh=Store(root / 'control.sqlite3');fresh.add_user(username.strip(), password)
        from .event_storage import enable
        with fresh.connect() as db:enable(db,fresh.path)
    ca_pem = certificates(tls, san)
    config = root / 'server.json'
    settings={'host': '0.0.0.0', 'port': port, 'local_console_port': console_port,
          'db': 'control.sqlite3', 'cert': 'tls/server.crt', 'key': 'tls/server.key'}
    if native is not None:settings['remote_native']=native
    write(config, json.dumps(settings, indent=2).encode())
    check(load(config))
    connection = {'version': 1, 'server': f'https://{address}:{port}', 'ca': 'GuardDesk-CA.pem',
                  'ca_sha256': hashlib.sha256(ca_pem).hexdigest()}
    register = ('@echo off\r\nsetlocal DisableDelayedExpansion\r\n'
        'if not exist "%~dp0GuardDesk\\GuardDesk.exe" (\r\n'
        '  echo Extract these connection files into the complete GuardDesk Windows package first.\r\n  pause\r\n  exit /b 1\r\n)\r\n'
        'if not exist "%~dp0PilotDocuments" mkdir "%~dp0PilotDocuments"\r\n'
        '"%~dp0GuardDesk\\GuardDesk.exe" enroll --connection "%~dp0endpoint-connection.json" '
        '--watch "%~dp0PilotDocuments" --config "%~dp0runtime\\agent\\config.json" --private-runtime\r\npause\r\n')
    with zipfile.ZipFile(root / 'Endpoint-Connection.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('GuardDesk-CA.pem', ca_pem)
        archive.writestr('endpoint-connection.json', json.dumps(connection, indent=2))
        archive.writestr('Connect-Endpoint.cmd', register)
        archive.writestr('README-Connection.txt', 'Only obtain this bundle directly from MIS. Extract into a clean GuardDesk Windows package in your private user folder. Run Connect-Endpoint.cmd and enter your one-time enrollment code. Then run Install-Endpoint.cmd and start the normal Agent. Existing endpoints must migrate their original identity; do not re-enroll. No private key or enrollment code is included.\n')
    from .deployment import prepare_connection
    prepare_connection(Store(root / 'control.sqlite3'),root / 'Endpoint-Connection.zip','setup',rotate=True)
    from .endpoint_package import server_installer
    endpoint_installer = server_installer(exe, root / 'Endpoint-Connection.zip')
    executable = str(exe).replace('%', '%%')
    batch = ('@echo off\r\nchcp 65001 >nul\r\nsetlocal DisableDelayedExpansion\r\n'
             f'"{executable}" serve --config "%~dp0server.json" --open-console\r\npause\r\n')
    write(root / 'Start-Management.cmd', batch.encode('utf-8'))
    maintenance_launcher(root,exe)
    remote_launcher(root,exe)
    return {'config': str(config), 'start': str(root / 'Start-Management.cmd'),
            'console': f'http://127.0.0.1:{console_port}', 'endpoint': connection['server'],
            'connection_bundle': str(root / 'Endpoint-Connection.zip'),
            'endpoint_package': str(endpoint_installer) if endpoint_installer else None,
            'imported_existing_database': bool(source)}




def maintenance_launcher(root,executable):
    executable=Path(executable)
    if not getattr(sys,'frozen',False) and executable.name.lower().startswith('python'):return
    target=str(executable).replace('%','%%')
    batch=('@echo off\r\nchcp 65001 >nul\r\nsetlocal DisableDelayedExpansion\r\n'
           'echo 請先關閉管理中心。本工具會備份、搬移歷史日誌、驗證並壓縮主庫。\r\n'
           'echo 不刪除邏輯事件；完成後請重新執行 Start-Management.cmd。\r\n'
           f'"{target}" optimize-storage --config "%~dp0server.json"\r\npause\r\n')
    path=Path(root)/'Optimize-Storage.cmd'
    from .event_storage import ordinary
    ordinary(path).write_text(batch,encoding='utf-8',newline='')


def remote_launcher(root,executable):
    viewer=Path(executable).parent/'_internal/GuardDeskRemote.exe'
    if not viewer.is_file():return
    target=str(viewer).replace('%','%%')
    settings=load(Path(root)/'server.json')
    console='http://127.0.0.1:'+str(settings['local_console_port'])
    batch='@echo off\r\nchcp 65001 >nul\r\nsetlocal DisableDelayedExpansion\r\nstart "" "'+target+'" --server '+console+'\r\n'
    Path(root,'Start-Remote.cmd').write_text(batch,encoding='utf-8',newline='')


def wizard(root=None):
    print('GuardDesk 管理中心簡易部署：僅 MIS 在 Server 本機登入。\n不安裝全機信任憑證、不修改防火牆或 Defender。')
    root = root or input('資料目錄完整路徑（新目錄或空資料夾，例如 E:\\GuardDeskData）: ').strip().strip('"')
    state = destination_state(root)
    if state == 'installed':
        settings = load(Path(root) / 'server.json')
        print('此目錄已有管理中心，保留原資料、帳號及憑證，不重新初始化。')
        print('請雙擊原啟動檔：\n' + str(Path(root) / 'Start-Management.cmd'))
        print(f"Server 本機管理：http://127.0.0.1:{settings['local_console_port']}")
        exe = Path(sys.executable) if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[1] / 'dist/GuardDesk/GuardDesk.exe'
        from .deployment import prepare_connection
        from .endpoint_package import server_installer
        connection = Path(root)/'Endpoint-Connection.zip'
        prepare_connection(Store(Path(root)/'control.sqlite3'), connection, 'setup')
        installer = server_installer(exe, connection)
        remote_launcher(root,exe)
        if installer: print('端點請使用完整安裝包：' + str(installer))
        return
    if state == 'empty': print('已確認為空資料夾，將只替此資料夾設定私人存取權限。')
    address = input('Server 固定內網 IPv4 或 DNS 名稱: ').strip()
    server_name(address)
    source = input('舊中心搬移快照完整路徑（全新建立請直接 Enter）: ').strip().strip('"') or None
    if source and not Path(source).is_file(): raise ValueError('找不到舊中心搬移快照')
    native=None if source else native_settings(address)
    if native is not None and not native['console_ipv4']:
        address_input=input('在中心本機使用 MIS 原生遠端的固定內網 IPv4: ').strip()
        native=native_settings(address,[address_input])
    username = password = None
    if not source:
        username = input('MIS 管理帳號 [mis]: ').strip() or 'mis'
        password = getpass.getpass('MIS 密碼（不可空白）: ')
        if password != getpass.getpass('再輸入一次密碼: '): raise ValueError('兩次密碼不一致')
    exe = Path(sys.executable) if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[1] / 'dist/GuardDesk/GuardDesk.exe'
    print('正在建立受保護目錄、資料庫與端點連線憑證……', flush=True)
    result = create(root, address, username, password, source, exe,
                    native_console_ipv4=native['console_ipv4'] if native else None)
    print('完成。雙擊啟動檔，會開啟 Server 本機管理畫面：\n' + result['start'])
    print('本機管理：' + result['console'])
    if result['endpoint_package']: print('端點完整安裝包：' + result['endpoint_package'] + '\n將此 ZIP 完整解壓後雙擊 Setup-Endpoint.cmd；不需輸入 IP 或註冊碼。')
    else: print('連線設定包（不能單獨安裝）：' + result['connection_bundle'] + '\n請由管理畫面下載完整端點安裝包。')
    print('僅需依公司流程放行端點網段的 TCP 8787；8788 不開放網路。\n目前為前景啟動，視窗關閉即停止；開機排程需另由 MIS 設定。')

# Compatibility exports for existing center callers.
from .endpoint_files import secure_directory, read_connection
