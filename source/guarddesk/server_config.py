"""Location-independent Server settings and preflight; no ACL/policy changes."""
import ctypes
import datetime
import json
import os
import shutil
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path


def local_database(path):
    path = Path(path).resolve()
    if str(path).startswith(('\\\\', '//')):
        raise ValueError('管理中心資料庫必須位於本機固定磁碟，不支援 UNC／網路共用')
    if os.name == 'nt':
        get_type = ctypes.windll.kernel32.GetDriveTypeW
        get_type.argtypes = [ctypes.c_wchar_p]
        get_type.restype = ctypes.c_uint
        if get_type(path.anchor) != 3:
            raise ValueError('管理中心資料庫必須位於本機固定磁碟')
    return path


def load(path):
    path = Path(path).resolve(strict=True)
    with path.open('rb') as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('Server 設定檔過大')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Server 設定欄位重複：' + key)
            result[key] = value
        return result
    settings = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique)
    required = {'db', 'host', 'port', 'cert', 'key'}
    if not isinstance(settings, dict) or not required <= set(settings) or set(settings) - required - {'local_console_port','remote_native','remote_endpoint'}:
        raise ValueError('Server 設定需含 db、host、port、cert、key；可另設 local_console_port')
    if not isinstance(settings['host'], str) or not settings['host'].strip():
        raise ValueError('Server host 不正確')
    if type(settings['port']) is not int or not 1 <= settings['port'] <= 65535:
        raise ValueError('Server port 必須為 1–65535')
    if 'local_console_port' in settings and (type(settings['local_console_port']) is not int or
            not 1 <= settings['local_console_port'] <= 65535 or settings['local_console_port'] == settings['port']):
        raise ValueError('本機管理埠需為 1–65535，且與端點埠不同')
    for key in ('db', 'cert', 'key'):
        value = settings[key]
        if not isinstance(value, str) or not value.strip():
            raise ValueError('Server 路徑不得為空：' + key)
        settings[key] = (path.parent / value).resolve()
    settings['db'] = local_database(settings['db'])
    if len({path, settings['db'], settings['cert'], settings['key']}) != 4:
        raise ValueError('設定、資料庫、憑證及私鑰必須使用不同檔案')
    if 'remote_native' in settings:
        from .remote_preview_config import parse
        settings['remote_native']=parse(settings['remote_native'],path)
    if 'remote_endpoint' in settings:
        from .endpoint_source import parse
        settings['remote_endpoint']=parse(settings['remote_endpoint'],path)
    return settings


def check(settings):
    from .server import tls_context
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    tls_context(settings['host'], settings['cert'], settings['key'])
    certificate = x509.load_pem_x509_certificate(settings['cert'].read_bytes())
    now = datetime.datetime.now(datetime.timezone.utc)
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise ValueError('Server TLS 憑證尚未生效或已過期')
    database = local_database(settings['db'])
    if not database.is_file():
        raise ValueError('找不到既有資料庫；先用 add-user 初始化或搬入 server-backup --migration 快照，不自動建立空白資料庫')
    # No schema migration or writes to company tables during a check.
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=15)) as db:
        if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
            raise ValueError('資料庫完整性檢查失敗')
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'users', 'devices', 'policies'} <= tables or not ({'events','events_legacy'} & tables):
            raise ValueError('不是 GuardDesk 管理中心資料庫')
        roles = dict(db.execute('SELECT role,count(*) FROM users GROUP BY role'))
        if not roles.get('admin'):
            raise ValueError('資料庫尚無管理員，請先使用 add-user 建立')
        from .event_storage import enabled,day_file
        daily=enabled(db)
        counts={'devices':db.execute('SELECT count(*) FROM devices').fetchone()[0]}
        if daily:
            counts['events']=db.execute('SELECT count(*) FROM events_legacy').fetchone()[0]+db.execute('SELECT count(*) FROM event_catalog').fetchone()[0]
            for day, in db.execute('SELECT day FROM event_storage_daily ORDER BY day'):
                if db.execute('SELECT 1 FROM event_catalog WHERE day=? AND stored=1 LIMIT 1',(day,)).fetchone() and not day_file(database,day).is_file():
                    raise ValueError('事件日檔缺失；請還原主庫對應的 AuditData 備份')
        else:counts['events']=db.execute('SELECT count(*) FROM events').fetchone()[0]
    # Opening without writing checks Windows DACLs too (os.access does not).
    with database.open('r+b'):
        pass
    # Disposable DB verifies directory/WAL creation, never mutates the live DB.
    with tempfile.TemporaryDirectory(prefix='guarddesk-preflight-', dir=database.parent) as scratch:
        with closing(sqlite3.connect(str(Path(scratch) / 'probe.sqlite3'))) as probe:
            if probe.execute('PRAGMA journal_mode=WAL').fetchone()[0] != 'wal':
                raise ValueError('資料目錄不支援 SQLite WAL')
            probe.execute('CREATE TABLE probe (value INTEGER)')
            probe.execute('INSERT INTO probe VALUES (1)')
            probe.commit()
    free = shutil.disk_usage(database.parent).free
    if free < 100 * 1024 * 1024:
        raise ValueError('資料庫磁碟可用空間不足 100 MiB，請先處理容量')
    return {'passed': True, 'db': str(database), 'roles': roles, **counts,
            'disk_free_bytes': free, 'tls_minimum': '1.2',
            'certificate_sha256': certificate.fingerprint(hashes.SHA256()).hex(),
            'certificate_expires': certificate.not_valid_after_utc.isoformat(),
            'checks': ['existing_database', 'sqlite_quick_check', 'admin_exists',
                       'directory_wal_write', 'local_fixed_disk', 'certificate_key_match', 'certificate_dates'],
            'requires_site_acceptance': ['DNS/SAN and client CA trust', 'folder ACL and service account',
                                         'firewall connectivity', 'Server reboot and company Defender policy']}


def start(settings):
    """Bind all listeners before running; release the first if the second fails."""
    from .server import serve
    check(settings)
    from .remote_preview_config import prepare,apply
    native=prepare(settings.get('remote_native'))
    endpoint_source=settings.get('remote_endpoint')
    if endpoint_source is not None:
        from .endpoint_source import inspect
        inspect(endpoint_source)
    split = 'local_console_port' in settings
    endpoint = serve(settings['db'], settings['host'], settings['port'], settings['cert'], settings['key'],
                     surface='agent' if split else 'all',endpoint_source=endpoint_source)
    servers = [endpoint]
    try:
        apply(endpoint,native)
        if split:
            servers.append(serve(settings['db'], '127.0.0.1', settings['local_console_port'],
                                 surface='console', shared=endpoint))
        return servers
    except BaseException:
        endpoint.server_close()
        raise
