import csv
import io
import json
import logging
import math
import secrets
import ssl
import sys
import sqlite3
import threading
import time
import tempfile
import zipfile
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from .policy import validate_policy,agent_policy_wire
from .store import Store, canonical, digest, password_matches, validate_password
from . import __version__
from . import management
from . import native_usb
from . import remote
from . import removal
from . import deployment
from . import updates
from . import software
from . import audit_reports,audit_archive,pagination,policy_progress

STATIC = Path(__file__).with_name("static")
_CURSOR_LOCK=threading.Lock()
LOG = logging.getLogger("guarddesk")


class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def string(body, key, maximum=200):
    value = body.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise APIError(400, f"{key} 欄位不正確")
    return value.strip()


class Server(ThreadingHTTPServer):
    daemon_threads = False
    max_request_threads = 64

    def __init__(self, address, store, tls=False, context=None, surface='all', shared=None,endpoint_source=None):
        self.endpoint_source=shared.endpoint_source if shared else endpoint_source
        self.surface = surface
        self.context = context
        self.request_slots = threading.BoundedSemaphore(self.max_request_threads)
        self.store, self.tls = store, tls
        if shared:self.store.share_ingestion(shared.store)
        from .event_storage import DayWriter
        self.storage_writer=DayWriter();self.store.storage_writer=self.storage_writer
        self.attempts, self.attempt_lock = {}, threading.Lock()
        self.remote_memory=shared.remote_memory if shared else {}
        self.remote_lock=shared.remote_lock if shared else threading.Lock()
        self.remote_native_presence=shared.remote_native_presence if shared else {}
        self.remote_native_preview=shared.remote_native_preview if shared else False
        self.remote_native_owned_loopback=shared.remote_native_owned_loopback if shared else False
        self.remote_native_console_ipv4=list(shared.remote_native_console_ipv4) if shared else []
        self.remote_native_relay_authority=shared.remote_native_relay_authority if shared else None
        from .update_notify import Signals
        self.update_signals=shared.update_signals if shared else Signals()
        self.remote_stop=threading.Event()
        self.remote_thread=threading.Thread(target=self.remote_cleanup,daemon=True)
        self.package_lock = shared.package_lock if shared else threading.Lock()
        self.browser_publication_slots=shared.browser_publication_slots if shared else threading.BoundedSemaphore(2)
        self.event_search_slots=shared.event_search_slots if shared else threading.BoundedSemaphore(2)
        from .audit_search import Registry
        from .audit_search_index import Worker
        self.event_search_registry=shared.event_search_registry if shared else Registry()
        self.owns_search_index=shared is None
        from .bundled_release import Publisher
        self.bundled_release=shared.bundled_release if shared else Publisher(store,self.package_lock,manual_endpoint=self.endpoint_source is not None)
        super().__init__(address, Handler)
        self.search_index=shared.search_index if shared else Worker(store)
        self.audit_service=shared.audit_service if shared else audit_reports.AuditService(store)
        from .mail_reports import MailWorker
        self.owns_mail_worker=shared is None
        self.mail_worker=shared.mail_worker if shared else MailWorker(store)
        from .endpoint_purge import Worker as PurgeWorker
        self.owns_purge_worker=shared is None
        self.purge_worker=shared.purge_worker if shared else PurgeWorker(store)
        self.remote_thread.start()
        if shared is None:self.bundled_release.start()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(15)
        if self.context:
            try:
                # Handshake occurs in a request thread, never blocking accept().
                connection = self.context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
            except BaseException:
                connection.close()
                raise
        return connection, address

    def handle_error(self, request, client_address):
        if isinstance(sys.exception(), (ssl.SSLError, ConnectionError)):
            LOG.debug('HTTP/TLS peer disconnected or rejected the handshake')
        else:
            super().handle_error(request, client_address)

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()

    def remote_cleanup(self):
        while not self.remote_stop.wait(2):
            try:
                with self.store.connect() as db:
                    db.execute('BEGIN IMMEDIATE');remote.sweep(self,db)
            except sqlite3.Error:pass

    def server_close(self):
        if getattr(self,'owns_purge_worker',False):self.purge_worker.close()
        if getattr(self,'owns_search_index',False):self.search_index.close()
        if getattr(self,'owns_mail_worker',False):self.mail_worker.close()
        if hasattr(self,'audit_service'):self.audit_service.close()
        self.bundled_release.close()
        self.update_signals.close()
        self.remote_stop.set()
        if self.remote_thread.is_alive(): self.remote_thread.join(20)
        with self.remote_lock:self.remote_memory.clear()
        super().server_close()
        if hasattr(self,'audit_service'):
            # The offline lease must outlive every DB worker, including a
            # backup still winding down after its initial cooperative timeout.
            self.audit_service.index_thread.join()
            self.audit_service.archive.thread.join()
        if getattr(self,'owns_mail_worker',False) and self.mail_worker.thread.is_alive():self.mail_worker.thread.join()
        if getattr(self,'owns_search_index',False) and self.search_index.thread.is_alive():self.search_index.thread.join()
        self.storage_writer.close()
        if getattr(self,'database_lease',None):self.database_lease.close();self.database_lease=None


class Handler(BaseHTTPRequestHandler):
    server_version = "GuardDesk/" + __version__

    def log_message(self, *args):
        pass  # Never log cookies, bodies, enrollment tokens or credentials.

    def send(self, status, value, content_type="application/json; charset=utf-8", headers=None):
        data = value if isinstance(value, bytes) else canonical(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for key, val in (headers or {}).items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        if self.headers.get("Transfer-Encoding"):
            raise APIError(400, "不支援分塊請求")
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise APIError(400, "請求長度不正確")
        # Only consented desktop frames need a larger bounded JSON envelope.
        from .remote_codec import CLARITY_BODY
        limit=CLARITY_BODY if urlsplit(self.path).path=='/api/agent/remote/update' else 1024*1024
        if size < 0 or size > limit:
            raise APIError(413, "請求過大")
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise APIError(415, "請使用 JSON")
        try:
            value = json.loads(self.rfile.read(size), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))
        except (ValueError, UnicodeError):
            raise APIError(400, "JSON 格式錯誤")
        if not isinstance(value, dict):
            raise APIError(400, "請傳送 JSON 物件")
        return value

    def check_host(self):
        # Reject hostile DNS names on loopback, including DNS rebinding attempts.
        host = self.headers.get("Host", "")
        parsed = urlsplit("//" + host)
        if self.server.server_address[0] in ("127.0.0.1", "localhost") and parsed.hostname not in ("127.0.0.1", "localhost"):
            raise APIError(403, "Host 不允許")
        origin = self.headers.get("Origin")
        if origin:
            expected = ("https" if self.server.tls else "http") + "://" + host
            if origin != expected:
                raise APIError(403, "來源不允許")

    def session(self, db, mutate=False, admin=False, support=False):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
            token = cookies["gd_mis" if support else "gd_session"].value
        except (KeyError, ValueError):
            raise APIError(401, "請先登入")
        row = db.execute("SELECT s.*,u.role FROM sessions s JOIN users u ON u.username=s.username WHERE s.token=? AND s.expires>?", (('mis:' if support else '')+digest(token), time.time())).fetchone()
        if not row:
            raise APIError(401, "登入已到期")
        if mutate and not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), row["csrf"]):
            raise APIError(403, "操作驗證失敗，請重新登入")
        if admin and row["role"] != "admin":
            raise APIError(403, "需要管理員權限")
        if support and row['role'] not in ('admin','support'):
            raise APIError(403,'此帳號未授權使用 MIS 遠端協助')
        return row

    def login(self, db, body, support=False):
        username=string(body,'username',80);password=validate_password(body.get('password'))
        now,client=time.time(),self.client_address[0]
        with self.server.attempt_lock:
            self.server.attempts={k:v for k,v in self.server.attempts.items() if v[-1]>now-60}
            attempts=[t for t in self.server.attempts.get(client,[]) if t>now-60]
            if len(attempts)>=8:raise APIError(429,'嘗試次數過多，請一分鐘後再試')
            self.server.attempts[client]=attempts+[now]
        user=db.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        if not user or not password_matches(password,user['password']):raise APIError(401,'帳號或密碼錯誤')
        if support and user['role'] not in ('admin','support'):raise APIError(403,'此帳號未授權使用 MIS 遠端協助')
        token,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(24)
        db.execute('DELETE FROM sessions WHERE expires<?',(now,))
        lifetime=3600 if support else 28800
        db.execute('INSERT INTO sessions VALUES (?,?,?,?)',(('mis:' if support else '')+digest(token),username,csrf,now+lifetime))
        Store.event(db,'console','remote.operator_login' if support else 'admin.login','info',{'actor':username})
        cookie=('gd_mis=' if support else 'gd_session=')+token+'; HttpOnly; SameSite=Strict; Path='+('/api/support' if support else '/')+'; Max-Age='+str(lifetime)+('; Secure' if self.server.tls else '')
        return {'username':username,'role':'support' if support else user['role'],'csrf':csrf}, {'Set-Cookie':cookie}, 'application/json; charset=utf-8'

    def agent(self, db):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise APIError(401, "端點認證失敗")
        row = db.execute("SELECT * FROM devices WHERE token=? AND revoked=0", (digest(auth[7:]),)).fetchone()
        if not row:
            raise APIError(401, "端點認證失敗或已撤銷")
        return row

    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def handle_request(self, method):
        self.connection.settimeout(15)
        path=''
        try:
            self.check_host()
            path = urlsplit(self.path).path
            if path.startswith('/api/support/'):
                from .mis_support import route
                body=self.body() if method=='POST' else {}
                with self.server.store.connect() as db:
                    db.execute('BEGIN IMMEDIATE')
                    result,headers,mime=route(self,db,method,path,body,urlsplit(self.path).query)
                return self.send(200,result,mime,headers)
            if self.server.surface == 'agent' and path != '/api/health' and not path.startswith('/api/agent/') and not (method=='GET' and path.startswith('/browser-extension/')):
                raise APIError(403, '此連接埠僅供端點連線，管理畫面請在 Server 本機開啟')
            if self.server.surface == 'console' and path.startswith('/api/agent/'):
                raise APIError(403, '端點請使用 HTTPS 連接埠')
            if method == "GET" and path in ("/", "/app.js", "/management.js", "/audit_ui.js", "/audit_reports_ui.js", "/remote_ui.js", "/updates_ui.js", "/software_ui.js", "/improvements_ui.js", "/custom_settings_ui.js", "/custom_library_ui.js", "/category_library_ui.js", "/mail_reports_ui.js", "/style.css"):
                filename,mime=('index.html','text/html; charset=utf-8') if path=='/' else (path[1:],'text/css; charset=utf-8' if path.endswith('.css') else 'text/javascript; charset=utf-8')
                return self.send(200, (STATIC / filename).read_bytes(), mime)
            if method == "GET" and path == "/api/health":
                return self.send(200, {"status": "ok", "version": __version__})
            if method=='GET' and path.startswith('/browser-extension/'):
                return self.extension_public_file(path)
            if path=='/api/browser-publication' and method in ('GET','POST') or path=='/api/browser-publication/create' and method=='POST':
                return self.extension_publication(method,create=path.endswith('/create'))
            if method=='POST' and path=='/api/software/import':return self.import_software()
            if method=='GET' and path=='/api/agent/software/download':return self.download_software()
            if method=='POST' and path=='/api/updates/import':return self.import_update()
            if method=='GET' and path=='/api/agent/updates/download':return self.download_update()
            if method=='GET' and path=='/api/audit/exports/download':return self.download_audit_export()
            if method=='GET' and path=='/api/mail-reports/preview':return self.preview_mail_report()
            if method=='POST' and path=='/api/agent/updates/wait':return self.wait_update()
            if method == 'POST' and path == '/api/endpoint-package':
                self.body()
                return self.send_endpoint_package()
            if method=='POST' and path in ('/api/mis-support-package','/api/mis-support-executable'):
                body=self.body()
                if body:raise APIError(400,'MIS 工具下載不接受額外參數')
                with self.server.store.connect() as db:
                    user=self.session(db,mutate=True,admin=True)
                from .mis_support import package
                from .mis_onefile import executable
                from .endpoint_package import application_directory
                if not self.server.package_lock.acquire(blocking=False):raise APIError(429,'套件製作中，請稍後重試')
                single=path.endswith('executable')
                try:blob=(executable if single else package)(self.server.store.path.resolve().parent,application_directory())
                finally:self.server.package_lock.release()
                with self.server.store.connect() as db:Store.event(db,'console','remote.operator_package_download','info',{'actor':user['username'],'format':'exe' if single else 'zip'})
                return self.send(200,blob,'application/octet-stream' if single else 'application/zip',{'Content-Disposition':'attachment; filename="GuardDesk-MIS-Remote-'+__version__+('.exe' if single else '.zip')+'"'})
            if method=='POST' and path=='/api/browser-deployment-package':
                self.body()
                with self.server.store.connect() as db:
                    self.session(db,mutate=True,admin=True)
                from .browser_deployment import artifact
                return self.send(200,artifact(),'application/zip',{'Content-Disposition':'attachment; filename="GuardDesk-Browser-Enterprise.zip"'})
            if path == '/api/deployment' and method == 'GET':
                return self.deployment_action('status', {})
            if path=='/api/audit/search/cancel' and method=='POST':
                body=self.body()
                if set(body)!={'request_id'}:raise APIError(400,'搜尋取消欄位不正確')
                with self.server.store.connect() as db:
                    user=self.session(db,mutate=True)
                    if user['role']=='support':raise APIError(403,'需要稽核查詢權限')
                    self.server.event_search_registry.cancel(user['token'],body['request_id'])
                return self.send(200,{'ok':True})
            if path in ('/api/deployment/rotate','/api/deployment/revoke') and method == 'POST':
                return self.deployment_action(path.rsplit('/',1)[-1], self.body())
            body = self.body() if method == "POST" else {}
            with self.server.store.connect(event_ingest=method=='POST' and path=='/api/agent/events') as db:
                # Remote GETs renew leases and sweep expired sessions. Acquire
                # the writer lease before reading; deferred read -> write can
                # fail immediately with SQLITE_BUSY during video/input overlap.
                if method == "POST" or path.startswith('/api/remote/'):
                    db.execute("BEGIN IMMEDIATE")
                else:db.execute('BEGIN')
                result, headers, mime = self.route(db, method, path, body)
            if method=='POST' and path in ('/api/updates/jobs','/api/updates/cancel','/api/updates/cancel-waiting','/api/updates/notify','/api/agent/updates/status'):
                self.update_changed(path,body,result)
            self.send(200, result, mime, headers)
        except deployment.DeploymentError as exc:
            self.send(409, {'error':str(exc)})
        except (APIError,management.ManagementError,remote.RemoteError,audit_reports.AuditError) as exc:
            self.send(exc.status, {"error": exc.message})
        except sqlite3.IntegrityError:
            self.send(409,{'error':'名稱或指派已存在，或仍被其他資料使用'})
        except (ValueError, TypeError, OverflowError) as exc:
            message=str(exc)[:240] if path.startswith(('/api/custom-settings','/api/browser-publication')) and isinstance(exc,ValueError) else '輸入欄位不正確'
            self.send(400, {"error":message})
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError):
            pass
        except Exception:
            LOG.exception("request failed")
            self.send(500, {"error": "伺服器處理失敗，請查看本機紀錄"})

    def extension_public_file(self,path):
        from .browser_publication import PUBLIC_PREFIX,public_file
        # Public browser update downloads have no Agent bearer. This narrow
        # allowlist is the only exception on the TLS agent listener.
        import re
        name=path[len(PUBLIC_PREFIX):]
        if not re.fullmatch(r'updates\.xml|guarddesk-[0-9]+\.[0-9]+\.[0-9]+\.crx',name):raise APIError(404,'找不到擴充發布檔')
        if self.server.surface=='console' or not self.server.tls:raise APIError(403,'擴充發布需使用 HTTPS 端點連接埠')
        if not self.server.browser_publication_slots.acquire(blocking=False):raise APIError(429,'擴充下載忙碌，稍後重試')
        try:
            try:payload,mime=public_file(self.server.store.path.resolve().parent,name)
            except FileNotFoundError:raise APIError(404,'尚未設定擴充發布')
            return self.send(200,payload,mime,{'Cache-Control':'no-cache'})
        finally:self.server.browser_publication_slots.release()

    def extension_publication(self,method,create=False):
        from . import browser_publication as publication
        from .source_permissions import SourcePermissionError
        with self.server.store.connect() as db:actor=self.session(db,mutate=method=='POST',admin=True)['username']
        root=self.server.store.path.resolve().parent
        if method=='GET':
            result=publication.status(root)
            prepared=self.server.bundled_release.snapshot()
            fallback={'status':'preparing' if getattr(self.server.bundled_release,'source',None) else 'not_packaged'}
            if prepared.get('status')=='failed':fallback={'status':'blocked_by_release_preparation','code':prepared.get('code','preparation_failed')}
            elif prepared.get('status')=='stopped':fallback={'status':'stopped'}
            result['automatic_preparation']=prepared.get('browser_publication',fallback)
            if (root/'Endpoint-Connection.zip').is_file():
                from .endpoint_package import public_connection
                manifest,_=public_connection(root/'Endpoint-Connection.zip')
                result['suggested_base_url']=json.loads(manifest)['server'].rstrip('/')+'/browser-extension/'
            return self.send(200,result)
        if self.headers.get('X-GuardDesk-Authorize')!='browser-publication':raise APIError(400,'請確認匯入企業擴充發布套件')
        if create:
            body=self.body()
            if set(body)!={'base_url','confirm_company_identity'} or body['confirm_company_identity'] is not True:raise APIError(400,'請確認建立並保管固定的公司擴充身分')
        else:
            length=self.headers.get('Content-Length','')
            if self.headers.get('Transfer-Encoding') or not length.isdecimal() or not 0<int(length)<=publication.MAX_BUNDLE:raise APIError(413,'發布 ZIP 不能超過 2 MiB')
        if not self.server.package_lock.acquire(blocking=False):raise APIError(429,'其他安裝包作業進行中')
        try:
            try:
                if create:result=publication.create_managed(root,body['base_url'])
                else:
                    payload=self.rfile.read(int(length))
                    if len(payload)!=int(length):raise APIError(400,'發布包未接收完整')
                    result=publication.install(root,payload)
            except (zipfile.BadZipFile,KeyError) as exc:raise APIError(400,'發布包格式不正確') from exc
            except SourcePermissionError as exc:raise APIError(409,'Server 資料目錄可由其他帳戶改寫；尚未使用簽署金鑰，請 MIS 先核對資料目錄 ACL') from exc
            except PermissionError as exc:raise APIError(409,'公司擴充金鑰權限不符或存取遭拒；已保留原身分，請 MIS 核對 Server 資料目錄與 BrowserSigner 權限') from exc
            with self.server.store.connect() as db:Store.event(db,'console','admin.browser_publication','info',{'actor':actor,'generation':result['generation'],'extension_version':result['extension_version'],'extension_id':result['extension_id'],'managed_identity':create})
            return self.send(200,result)
        finally:self.server.package_lock.release()

    def preview_mail_report(self):
        from . import mail_reports
        query=parse_qs(urlsplit(self.path).query)
        day=mail_reports.report_day(query.get('day',[''])[0])
        with self.server.store.connect() as db:
            db.execute('BEGIN')
            self.session(db,admin=True)
            data=mail_reports.snapshot(db,day)
        # Rendering occurs after releasing the read snapshot and outside the
        # writer lock. At most two simultaneous chart renderers per server.
        if not self.server.mail_worker.preview_slots.acquire(blocking=False):raise APIError(429,'預覽產生中，請稍後再試')
        try:
            images=mail_reports.charts(data)
            self.send(200,{'html':mail_reports.render(data,images,preview=True),'day':day,'total':data['total'],'devices':len(data['rows'])})
        finally:self.server.mail_worker.preview_slots.release()

    def download_audit_export(self):
        params=parse_qs(urlsplit(self.path).query);jid=params.get('id',[''])[0]
        if not __import__('re').fullmatch('[0-9a-f]{32}',jid):raise APIError(400,'備份識別碼不正確')
        with self.server.store.connect() as db:
            user=self.session(db)
            if user['role']!='admin':raise APIError(403,'僅 MIS 管理員可下載備份')
            row=db.execute('SELECT state,bytes FROM audit_exports WHERE id=?',(jid,)).fetchone()
            if not row:raise APIError(404,'找不到備份')
            if row['state']!='completed':raise APIError(409,'備份尚未完成驗證')
            expected=row['bytes']
        path=audit_archive.ordinary(self.server.audit_service.archive.root/jid/'archive.zip')
        with path.open('rb') as stream:
            if __import__('os').fstat(stream.fileno()).st_size!=expected:raise APIError(409,'備份檔案大小不符')
            with self.server.store.connect() as db:
                db.execute('BEGIN IMMEDIATE');user=self.session(db)
                if user['role']!='admin':raise APIError(403,'僅 MIS 管理員可下載備份')
                Store.event(db,'console','audit.export_download_requested','info',{'actor':user['username'],'job_id':jid,'bytes':expected})
            self.send_response(200);self.send_header('Content-Type','application/zip');self.send_header('Content-Length',str(expected));self.send_header('Content-Disposition',f'attachment; filename="GuardDesk-Audit-{jid}.zip"');self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.end_headers()
            while chunk:=stream.read(65536):self.wfile.write(chunk)

    def wait_update(self):
        body=self.body()
        if set(body)-{'role','cursor'}:raise APIError(400,'通知欄位不正確')
        # Authenticate then close SQLite before blocking. Never hold a writer
        # transaction or remote lock for a notification connection.
        with self.server.store.connect() as db:device=dict(self.agent(db))
        result=self.server.update_signals.wait(device['id'],body.get('role'),body.get('cursor'))
        with self.server.store.connect() as db:self.agent(db)  # revoke while waiting
        return self.send(200,result)

    def update_changed(self,path,body,result):
        ids=result.get('job_ids',[]) if path in ('/api/updates/jobs','/api/updates/cancel-waiting') else [body.get('job_id')]
        with self.server.store.connect() as db:
            devices=[row[0] for jid in ids for row in db.execute('SELECT device_id FROM update_jobs WHERE id=?',(jid,))]
        if devices:self.server.update_signals.notify(devices)

    def send_endpoint_package(self):
        with self.server.store.connect() as db:
            user = self.session(db, mutate=True, admin=True)
            actor = user['username']
        from .endpoint_package import application_directory, build
        from .server_setup import secure_directory
        root = self.server.store.path.resolve().parent
        connection = root / 'Endpoint-Connection.zip'
        if not connection.is_file(): raise APIError(409, '找不到 Server 原產生的 Endpoint-Connection.zip，請先由 MIS 核對部署資料目錄')
        # Bound concurrent generation; no general ZIP/path upload API.
        if not self.server.package_lock.acquire(blocking=False): raise APIError(429, '安裝包製作中，請稍後重試')
        target = None
        try:
            selected=self.server.endpoint_source
            version=selected['version'] if selected is not None else __version__
            try:
                if selected is not None:
                    from .endpoint_source import inspect
                    source=inspect(selected)
                else:source=application_directory()
            except (OSError,ValueError) as exc:raise APIError(409,'遠端專用端點成品未通過核對；請核對設定與原成品，不會改用中心執行包') from exc
            directory = Path(tempfile.mkdtemp(prefix='guarddesk-endpoint-', dir=root))
            # mkdtemp creates an empty folder; establish private ACL before output.
            secure_directory(directory, allow_empty=True)
            target = directory / f'GuardDesk-Endpoint-{version}.zip'
            from .source_permissions import SourcePermissionError
            try:deployment.prepare_connection(self.server.store, connection, actor)
            except SourcePermissionError as exc:raise APIError(409,'擴充發布金鑰的私人目錄權限檢查未通過；請 MIS 核對資料目錄 ACL（'+exc.reason+'），不會自動放寬權限') from exc
            try: build(source, connection, target,version=version,manifest_sha256=selected['manifest_sha256'] if selected is not None else None)
            except ValueError as exc: raise APIError(409, str(exc)[:400]) from exc
            if target.stat().st_size > 64 * 1024 * 1024: raise APIError(409, '安裝包超過 64 MiB，請 MIS 核對程式目錄')
            with self.server.store.connect() as db:
                Store.event(db, 'console', 'admin.endpoint_package', 'info', {'actor': actor, 'version': version,'dedicated_endpoint':selected is not None})
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Length', str(target.stat().st_size))
            self.send_header('Content-Disposition', f'attachment; filename="GuardDesk-Endpoint-{version}.zip"')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            with target.open('rb') as stream:
                while chunk := stream.read(65536): self.wfile.write(chunk)
        finally:
            if target: target.unlink(missing_ok=True)
            if 'directory' in locals():
                try: directory.rmdir()
                except OSError: pass
            self.server.package_lock.release()

    def import_software(self):
        from .software_contract import MAX_PACKAGE,GIB
        from .server_setup import secure_directory
        import shutil
        with self.server.store.connect() as db:
            actor=self.session(db,mutate=True,admin=True)['username'];limit=software.limits(db)['package_bytes']
        if self.server.endpoint_source is not None:raise APIError(409,'獨立遠端測試中心不提供軟體派送')
        if self.headers.get('X-GuardDesk-Authorize')!='install-msi-machine' or self.headers.get('Content-Type')!='application/x-msi':raise APIError(400,'只接受明確授權的 MSI 上傳')
        length=self.headers.get('Content-Length','');budget=self.headers.get('X-Install-Bytes','')
        if not length.isdecimal() or not 0<int(length)<=limit or self.headers.get('Transfer-Encoding'):raise APIError(413,'MSI 超過目前軟體庫單包配額')
        if not budget.isdecimal() or not int(length)<=int(budget)<=256*GIB:raise APIError(400,'請填寫安裝所需空間預算')
        if not self.server.package_lock.acquire(blocking=False):raise APIError(429,'其他安裝包工作進行中')
        directory=None
        try:
            root=self.server.store.path.resolve().parent
            if shutil.disk_usage(root).free<int(length)+GIB:raise APIError(409,'上傳磁碟空間不足')
            directory=Path(tempfile.mkdtemp(prefix='msi-upload-',dir=root));secure_directory(directory,allow_empty=True)
            source=directory/'incoming.msi';remaining=int(length)
            with source.open('xb') as stream:
                while remaining:
                    data=self.rfile.read(min(65536,remaining))
                    if not data:raise APIError(400,'MSI 上傳中斷')
                    stream.write(data);remaining-=len(data)
            try:result=software.add_package(self.server.store,source,actor,int(budget))
            except (OSError,ValueError) as exc:
                from .native_browser_identity import IdentityError
                if isinstance(exc,IdentityError):raise APIError(400,'MSI 發行者簽章無法驗證；保留公司防護，請確認套件來源與憑證信任') from None
                if isinstance(exc,ValueError):raise APIError(400,str(exc)[:240]) from None
                raise APIError(400,'Windows Installer 無法讀取此 MSI，請確認是完整的全機安裝包') from None
            return self.send(200,result)
        finally:
            if directory:
                (directory/'incoming.msi').unlink(missing_ok=True);directory.rmdir()
            self.server.package_lock.release()

    def download_software(self):
        import re
        from .update_packages import plain
        jid=parse_qs(urlsplit(self.path).query).get('job_id',[''])[0]
        with self.server.store.connect() as db:
            device=self.agent(db);job=software.valid(db,device,jid)
            if job['state']!='downloading' or job['expires']<=time.time():raise APIError(409,'軟體工作不可下載')
            m=json.loads(db.execute('SELECT manifest FROM software_packages WHERE id=?',(job['package_id'],)).fetchone()[0])
        path=plain(software.repository(self.server.store)/(m['sha256']+'.msi'))
        offset=0;requested=self.headers.get('Range')
        if requested:
            match=re.fullmatch(r'bytes=(\d{1,12})-',requested)
            if not match or not 0<=int(match[1])<m['bytes']:raise APIError(416,'MSI 續傳範圍不正確')
            offset=int(match[1])
        with path.open('rb') as source:
            if path.stat().st_size!=m['bytes']:raise APIError(409,'MSI 檔案大小不符')
            self.send_response(206 if requested else 200)
            self.send_header('Content-Type','application/x-msi');self.send_header('Content-Length',str(m['bytes']-offset));self.send_header('Cache-Control','no-store')
            if requested:self.send_header('Content-Range',f"bytes {offset}-{m['bytes']-1}/{m['bytes']}")
            self.end_headers();source.seek(offset)
            while chunk:=source.read(65536):self.wfile.write(chunk)

    def import_update(self):
        with self.server.store.connect() as db:actor=self.session(db,mutate=True,admin=True)['username']
        if self.server.endpoint_source is not None:raise APIError(409,'獨立遠端測試中心僅提供指定安裝包，尚未開放集中更新')
        if self.headers.get('X-GuardDesk-Authorize')!='update-release':raise APIError(400,'請確認匯入端點可執行更新')
        from .update_packages import MAX_ZIP
        length=self.headers.get('Content-Length','')
        if not length.isdecimal() or not 0<int(length)<=MAX_ZIP or self.headers.get('Transfer-Encoding'):raise APIError(413,'請直接上傳不超過 64 MiB 的完整發布 ZIP')
        if not self.server.package_lock.acquire(blocking=False):raise APIError(429,'其他安裝包作業進行中，請稍後重試')
        directory=None
        try:
            from .server_setup import secure_directory
            directory=Path(tempfile.mkdtemp(prefix='update-import-',dir=self.server.store.path.resolve().parent))
            secure_directory(directory,allow_empty=True);source=directory/'incoming.zip'
            remaining=int(length)
            with source.open('xb') as output:
                while remaining:
                    data=self.rfile.read(min(65536,remaining))
                    if not data:raise APIError(400,'發布 ZIP 上傳中斷')
                    output.write(data);remaining-=len(data)
            result=updates.add_release(self.server.store,source,directory,actor)
            return self.send(200,result)
        finally:
            if directory:
                for name in ('incoming.zip','package.tmp'):(directory/name).unlink(missing_ok=True)
                directory.rmdir()
            self.server.package_lock.release()

    def download_update(self):
        params=parse_qs(urlsplit(self.path).query);jid=params.get('job_id',[''])[0]
        import re
        if not re.fullmatch('[0-9a-f]{32}',jid):raise APIError(400,'更新工作識別碼不正確')
        with self.server.store.connect() as db:
            device=self.agent(db);job=updates.valid_job(db,device,jid)
            row=db.execute('SELECT envelope FROM update_releases WHERE id=?',(job['release_id'],)).fetchone()
            manifest=json.loads(row[0])['payload']
        from .update_packages import plain
        path=plain(updates.repository(self.server.store)/(job['release_id']+'.zip'))
        if not path.is_file() or path.stat().st_size!=manifest['bytes']:raise APIError(409,'發布檔案遺失或大小不符')
        self.send_response(200);self.send_header('Content-Type','application/zip');self.send_header('Content-Length',str(manifest['bytes']));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.end_headers()
        with path.open('rb') as source:
            while chunk:=source.read(65536):self.wfile.write(chunk)

    def deployment_action(self, action, body):
        with self.server.store.connect() as db:
            user = self.session(db, mutate=action!='status', admin=True)
            actor = user['username']
            if action == 'status': return self.send(200, deployment.status(db))
        if not isinstance(body,dict) or body.get('confirm') != action: raise APIError(400,'請確認部署碼操作')
        if not self.server.package_lock.acquire(blocking=False): raise APIError(429,'安裝包製作中，請稍後重試')
        try:
            if action == 'rotate':
                connection = self.server.store.path.resolve().parent / 'Endpoint-Connection.zip'
                if not connection.is_file(): raise APIError(409,'找不到原 Endpoint-Connection.zip，請 MIS 核對資料目錄')
                deployment.prepare_connection(self.server.store,connection,actor,rotate=True)
            else:
                with self.server.store.connect() as db:
                    db.execute('BEGIN IMMEDIATE')
                    current = deployment.status(db)
                    db.execute('UPDATE deployment_codes SET revoked=1 WHERE revoked=0')
                    Store.event(db,'console','deployment.revoked','info',{'actor':actor,'code_id':current['code']['id'] if current['code'] else None})
            with self.server.store.connect() as db: result = deployment.status(db)
            return self.send(200, result)
        finally: self.server.package_lock.release()

    def route(self, db, method, path, body):
        headers, mime = {}, "application/json; charset=utf-8"
        if method == "POST" and path == "/api/login":
            return self.login(db,body)
        if method=='POST' and path=='/api/removal-result':
            from . import removal_full
            auth=self.headers.get('Authorization','')
            return removal_full.result(db,auth[7:] if auth.startswith('Bearer ') else '',body),headers,mime
        if method == "POST" and path == "/api/agent/enroll":
            token, name = string(body, "token", 200), string(body, "name", 120)
            department = string(body, "department", 120)
            enrollment = db.execute("SELECT * FROM enrollments WHERE token=? AND used=0 AND expires>?", (digest(token), time.time())).fetchone()
            shared = deployment.consume(db, token) if not enrollment else None
            if not enrollment and not shared:
                raise APIError(401, "註冊碼無效、過期或已停用；共用安裝包請向 MIS 取得新版")
            device_id, agent_token = secrets.token_hex(12), secrets.token_urlsafe(32)
            if enrollment: db.execute("UPDATE enrollments SET used=1 WHERE token=?", (digest(token),))
            db.execute("INSERT INTO devices(id,token,name,department,last_seen,enrolled_at,last_address) VALUES (?,?,?,?,?,?,?)", (device_id, digest(agent_token), name, department, time.time(),time.time(),self.client_address[0]))
            Store.event(db, device_id, "device.enrolled", "info", {"name": name, "department": department,'enrollment_source':'deployment' if shared else 'single_use','deployment_id':shared})
            return {"device_id": device_id, "token": agent_token, "policy": agent_policy_wire(management.ControlPlane(db).bundle({'id':device_id,'name':name,'group_id':None,'inventory':{}}))}, headers, mime
        if method == "POST" and path.startswith("/api/agent/"):
            device = self.agent(db)
            if path in ('/api/agent/software/poll','/api/agent/software/authorize','/api/agent/software/result','/api/agent/software/state'):
                return software.agent_route(self.server.store,db,device,path,body),headers,mime
            if path=='/api/agent/uninstall/prepare-files':
                from . import removal_full
                return removal_full.prepare(db,device,body),headers,mime
            if path=='/api/agent/uninstall/files-error':
                from . import removal_full
                return removal_full.preparation_error(db,device,body),headers,mime
            if path in ('/api/agent/custom-settings','/api/agent/custom-status','/api/agent/custom-action/authorize','/api/agent/custom-action/complete'):
                from . import custom_settings as custom
                from . import custom_library
                if path.endswith('/authorize'):
                    protocol=body.get('protocol',1)
                    if type(protocol) is not int or protocol not in (1,2):raise APIError(409,'自訂設定協定不相容')
                    request={k:v for k,v in body.items() if k!='protocol'}
                    packet=custom_library.resolve(db,dict(device)) if protocol==2 else None
                    return custom.authorize_action(db,dict(device),request,packet),headers,mime
                if path.endswith('/complete'):
                    if set(body)!={'token'} or not isinstance(body['token'],str):raise ValueError('動作回報格式不正確')
                    db.execute('DELETE FROM custom_action_leases WHERE device_id=? AND token=?',(device['id'],body['token']))
                    return {'ok':True},headers,mime
                if path.endswith('custom-status'):
                    return custom.accept_status(db,dict(device),body),headers,mime
                if set(body)!={'protocol'} or type(body.get('protocol')) is not int:raise APIError(400,'自訂設定協定欄位不正確')
                if body.get('protocol')==custom_library.PROTOCOL:
                    return {**custom_library.resolve(db,dict(device)),'busy':custom.busy(db,device['id'])},headers,mime
                if body.get('protocol')!=custom.PROTOCOL:raise APIError(409,'自訂設定協定不相容')
                return {**custom.resolve(db,dict(device)),'busy':custom.busy(db,device['id'])},headers,mime
            if path in ('/api/agent/updater/prepare','/api/agent/updater/complete','/api/agent/updater/observed'):
                from .updater_maintenance import route
                return route(self.server.store,db,device,path,body),headers,mime
            if path in ('/api/agent/updates/poll','/api/agent/updates/status','/api/agent/updates/diagnostic'):return updates.agent_route(self.server.store,db,device,path,body),headers,mime
            if path in ('/api/agent/uninstall/poll','/api/agent/uninstall/status'):return removal.agent_route(db,device,path,body),headers,mime
            if path.startswith('/api/agent/remote/'):
                return remote.agent_route(self.server,db,device,path,body),headers,mime
            if path=='/api/agent/extended-policy':
                from .browser_dispatch import projection
                from .browser_trust import projection as trust_projection
                return {**agent_policy_wire({'device_id':device['id'],'body':management.ControlPlane(db).resolve(dict(device))['body']}),'browser_dispatch':projection(self.server.store.path.resolve().parent),'browser_trust':trust_projection(self.server.store.path.resolve().parent)},headers,mime
            if path=='/api/agent/extended-status':
                if len(canonical(body))>4000:raise APIError(400,'收集器狀態過大')
                old=db.execute('SELECT body FROM extended_status WHERE device_id=?',(device['id'],)).fetchone()
                if not old or json.loads(old[0]).get('status')!=body.get('status'):Store.event(db,device['id'],'agent.extended_status','warning' if body.get('status')=='failed' else 'info',body)
                db.execute('INSERT OR REPLACE INTO extended_status VALUES (?,?,?)',(device['id'],canonical(body),time.time()))
                return {'ok':True},headers,mime
            if path=='/api/agent/native-usb-policy':return native_usb.policy_packet(db,device),headers,mime
            if path=='/api/agent/native-usb-status':return native_usb.accept_status(db,device,body),headers,mime
            if path == "/api/agent/heartbeat":
                inventory, ack = body.get("inventory", {}), body.get("policy_version", 0)
                fingerprint=body.get('policy_fingerprint','')
                if not isinstance(inventory, dict) or len(canonical(inventory)) > 64000 or type(ack) is not int or not 0 <= ack <= 9223372036854775807 or not isinstance(fingerprint,str) or (fingerprint and (len(fingerprint)!=64 or any(c not in '0123456789abcdef' for c in fingerprint))):
                    raise APIError(400, "心跳欄位不正確")
                current=management.ControlPlane(db).bundle({**dict(device),'inventory':inventory})
                db.execute("UPDATE devices SET last_seen=?,policy_version=?,policy_fingerprint=?,inventory=?,last_address=? WHERE id=?", (time.time(), ack,fingerprint, canonical(inventory),self.client_address[0], device["id"]))
                if ack != device["policy_version"] or fingerprint!=device['policy_fingerprint']:
                    Store.event(db, device["id"], "policy.applied", "info", {"version": ack,'fingerprint':fingerprint,'meaning':'received_not_proof_of_enforcement'})
                from .browser_dispatch import projection
                from .browser_trust import projection as trust_projection
                return {"policy": agent_policy_wire(current), "server_time": time.time(),'browser_dispatch':projection(self.server.store.path.resolve().parent),'browser_trust':trust_projection(self.server.store.path.resolve().parent)}, headers, mime
            if path == "/api/agent/events":
                events = body.get("events")
                if not isinstance(events, list) or len(events) > 100:
                    raise APIError(400, "每批最多 100 筆事件")
                accepted = []
                from .file_exclusions import excluded_activity,excluded_internal_health_activity,excluded_installer_activity
                from .application_exclusions import excluded_application
                from .file_access import excluded_event as excluded_file_access
                # Resolve the authenticated computer's current policy once per
                # bounded batch, including inherited group/device overrides.
                collection_policy=management.ControlPlane(db).resolve(dict(device))['body']
                exclusions=collection_policy['file_audit']['exclude_paths']
                application_exclusions=collection_policy['application_audit_exclusions']
                for e in events:
                    if not isinstance(e, dict):
                        raise APIError(400, "事件格式不正確")
                    eid, kind = string(e, "event_id", 100), string(e, "kind", 80)
                    severity, details, occurred = e.get("severity"), e.get("details"), e.get("occurred")
                    if not kind.startswith(("file.", "export.", "agent.", "vault.", "web.", "network.", "usb.", "application.")) or severity not in ("info", "warning", "critical") or not isinstance(details, dict) or len(canonical(details)) > 16000:
                        raise APIError(400, "事件欄位不正確")
                    if type(occurred) not in (int, float) or not math.isfinite(occurred) or not 0 <= occurred <= 253402300799:
                        raise APIError(400, "事件時間不正確")
                    if occurred>time.time()+300:
                        details={**details,'clock_warning':'agent_timestamp_in_future'}
                    # Acknowledge legacy agents so they can drain their outbox;
                    # excluded events are not appended to the immutable log.
                    if kind != 'file.modified' and not excluded_internal_health_activity(kind,severity,details) and not excluded_installer_activity(kind,severity,details) and not excluded_activity(kind,details,exclusions) and not excluded_application(kind,severity,details,application_exclusions) and not excluded_file_access(kind,severity,details,exclusions):
                        Store.event(db, device["id"], kind, severity, details, eid, occurred)
                    accepted.append(eid)
                return {"accepted": accepted}, headers, mime
            raise APIError(404, "找不到端點 API")
        user = self.session(db, mutate=method == "POST", admin=method == "POST" and path != "/api/logout" and not path.startswith('/api/remote/'))
        if path.startswith('/api/mail-reports'):
            if user['role']!='admin':raise APIError(403,'僅 MIS 管理員可設定與查看郵件報表')
            from . import mail_reports
            if method=='GET' and path=='/api/mail-reports':return {**mail_reports.catalog(db),'worker_error':self.server.mail_worker.error},headers,mime
            if method=='POST' and path=='/api/mail-reports/config':
                if body.get('client_secret') and not self.server.tls:
                    import ipaddress
                    if not ipaddress.ip_address(self.client_address[0]).is_loopback:raise APIError(403,'密鑰只能透過 HTTPS 或 Server 本機設定')
                return mail_reports.save(db,body,user['username']),headers,mime
            if method=='POST' and path=='/api/mail-reports/send':return mail_reports.enqueue(db,body,user['username']),headers,mime
            raise APIError(404,'找不到每日郵件報表操作')
        if path.startswith('/api/categories'):
            if user['role']=='support':raise APIError(403,'支援帳號不能查看分類')
            from .category_library import route as category_route
            return category_route(db,method,path,body,user['username'],parse_qs(urlsplit(self.path).query)),headers,mime
        if path.startswith('/api/custom-settings'):
            if user['role']=='support':raise APIError(403,'支援帳號不能查看自訂設定')
            from . import custom_settings as custom
            query=parse_qs(urlsplit(self.path).query)
            if method=='GET' and path=='/api/custom-settings':return custom.catalog(db),headers,mime
            if method=='POST' and path=='/api/custom-settings/preview':return custom.preview(db,body),headers,mime
            if method=='POST' and path=='/api/custom-settings/publish':return custom.publish(db,body,user['username']),headers,mime
            if method=='GET' and path=='/api/custom-settings/effective':
                d=db.execute('SELECT * FROM devices WHERE id=? AND revoked=0',(query.get('device_id',[''])[0],)).fetchone()
                if not d:raise APIError(404,'找不到有效端點')
                return custom.resolve(db,dict(d)),headers,mime
            if method=='GET' and path=='/api/custom-settings/history':
                scope,target=custom.scope_input(db,{'scope':query.get('scope',[''])[0],'target':query.get('target',[''])[0]})
                rows=[{**dict(r),'body':json.loads(r['body'])} for r in db.execute('SELECT * FROM custom_settings_history WHERE scope=? AND target=? ORDER BY revision DESC LIMIT 50',(scope,target))]
                return {'versions':rows},headers,mime
            raise APIError(404,'找不到自訂設定操作')
        if path.startswith('/api/custom-library'):
            if user['role']=='support':raise APIError(403,'支援帳號不能查看自訂設定')
            from . import custom_library
            query=parse_qs(urlsplit(self.path).query)
            if method=='GET' and path=='/api/custom-library':return custom_library.catalog(db),headers,mime
            if method=='GET' and path=='/api/custom-library/effective':return custom_library.target_view(db,query.get('scope',[''])[0],query.get('target',[''])[0]),headers,mime
            if method=='GET' and path=='/api/custom-library/history':return custom_library.history(db,query.get('id',[''])[0]),headers,mime
            if method=='POST' and path=='/api/custom-library/preview':return custom_library.preview(db,body),headers,mime
            if method=='POST' and path=='/api/custom-library/publish':return custom_library.publish(db,body,user['username']),headers,mime
            raise APIError(404,'找不到自訂設定庫操作')
        if path.startswith('/api/audit/'):
            if user['role']=='support':raise APIError(403,'支援帳號不能查看稽核資料')
            if path.startswith('/api/audit/storage'):
                from . import event_storage
                if method=='GET' and path=='/api/audit/storage':
                    return {**event_storage.status(db,self.server.store.path),'migration':getattr(self.server,'storage_migration',None)},headers,mime
                if user['role']!='admin':raise APIError(403,'僅 MIS 可啟用分日儲存')
                if method=='POST' and path=='/api/audit/storage/enable':
                    if body.get('confirm')!='enable_daily':raise APIError(400,'請確認啟用分日儲存')
                    with _CURSOR_LOCK:
                        job=getattr(self.server,'storage_migration',None)
                        if job and job['state']=='working':raise APIError(409,'分日儲存啟用中')
                        job={'state':'working','started':time.time()};self.server.storage_migration=job
                        server=self.server;actor=user['username']
                        def activate_storage():
                            try:
                                with server.store.connect() as connection:
                                    result=event_storage.enable(connection,server.store.path)
                                    Store.event(connection,'console','audit.daily_storage_enabled','warning',{'actor':actor,**result})
                                job.update(state='completed',result=result)
                            except Exception:
                                LOG.exception('daily storage activation failed')
                                job.update(state='failed',error='啟用失敗；原資料保留，請檢查目錄權限、可用磁碟及 Server 日誌')
                        threading.Thread(target=activate_storage,name='GuardDesk-StorageActivation',daemon=True).start()
                    return {'state':'working'},headers,mime
            if method=='GET' and path=='/api/audit/summary':return audit_reports.summary(db,parse_qs(urlsplit(self.path).query),self.server.audit_service.error),headers,mime
            if user['role']!='admin':raise APIError(403,'僅 MIS 管理員可管理備份')
            if method=='GET' and path=='/api/audit/exports':return audit_archive.export_catalog(db,self.server.audit_service.archive.root),headers,mime
            if method=='POST' and path=='/api/audit/exports':return audit_archive.create_job(db,user['username'],body),headers,mime
            if method=='POST' and path=='/api/audit/exports/cancel':return audit_archive.cancel_job(db,user['username'],body.get('id')),headers,mime
            raise APIError(404,'找不到稽核總表／備份功能')
        if path.startswith('/api/software'):
            user=self.session(db,mutate=method=='POST',admin=True)
            if method=='GET' and path=='/api/software':return software.catalog(db),headers,mime
            if method=='POST' and path=='/api/software/jobs':return software.create_jobs(db,user,body),headers,mime
            if method=='POST' and path=='/api/software/cancel':return software.cancel(db,user,body),headers,mime
            if method=='POST' and path=='/api/software/limits':return software.set_limits(db,user,body),headers,mime
            if method=='POST' and path=='/api/software/delete':return software.delete_package(self.server.store,db,user,body),headers,mime
            if method=='POST' and path=='/api/software/close-review':return software.close_review(db,user,body),headers,mime
        if path.startswith('/api/updates'):
            if user['role']!='admin':raise APIError(403,'僅 MIS 管理員可管理 Agent 更新')
            if self.server.endpoint_source is not None and method=='POST' and path in ('/api/updates/jobs','/api/updates/notify','/api/updates/bundled/prepare'):
                raise APIError(409,'獨立遠端測試中心僅提供指定安裝包，尚未開放集中更新')
            if method=='GET' and path=='/api/updates':return updates.catalog(db,self.server.update_signals,self.server.bundled_release.snapshot(),parse_qs(urlsplit(self.path).query)),headers,mime
            if path in ('/api/updates/cancel-waiting/preview','/api/updates/cancel-waiting'):
                from . import update_progress
                if method=='POST' and path=='/api/updates/cancel-waiting':return update_progress.cancel_waiting(db,user,body),headers,mime
                if method=='GET' and path=='/api/updates/cancel-waiting/preview':
                    releases=db.execute('SELECT id,version FROM update_releases').fetchall()
                    latest=max(releases,key=lambda r:updates.packages.version(r['version']))['id'] if releases else None
                    filters=update_progress.parameters(db,parse_qs(urlsplit(self.path).query),latest)
                    return update_progress.preview(db,filters),headers,mime
            if method=='POST' and path=='/api/updates/bundled/prepare':
                if body:raise APIError(400,'準備隨附版本不接受額外欄位')
                if self.server.bundled_release.start():Store.event(db,'console','update.bundled_release_retry_requested','info',{'actor':user['username'],'version':__version__})
                return self.server.bundled_release.snapshot(),headers,mime
            if method=='POST' and path=='/api/updates/jobs':return updates.create_jobs(db,user,body),headers,mime
            if method=='POST' and path=='/api/updates/cancel':return updates.cancel(db,user,body),headers,mime
            if method=='POST' and path=='/api/updates/notify':return updates.notify(db,user,body,self.server.update_signals),headers,mime
            raise APIError(404,'找不到更新功能')
        if path.startswith('/api/remote/'):return remote.route(self.server,db,{**dict(user),'_remote_address':self.client_address[0]},method,path,body,urlsplit(self.path).query),headers,mime
        if user['role']=='support' and path not in ('/api/me','/api/logout'):raise APIError(403,'此帳號僅授權遠端協助')
        if path.startswith('/api/devices/purge'):
            from . import endpoint_purge
            if user['role']!='admin':raise APIError(403,'需要管理員權限')
            if method=='GET' and path=='/api/devices/purge/retire-preview':return endpoint_purge.retire_preview(db,user,parse_qs(urlsplit(self.path).query).get('device_id',[''])[0]),headers,mime
            if method=='POST' and path=='/api/devices/purge/retire':return endpoint_purge.retire_request(db,user,body,self.server),headers,mime
            if method=='GET' and path=='/api/devices/purge/preview':return endpoint_purge.preview(db,user,parse_qs(urlsplit(self.path).query).get('device_id',[''])[0]),headers,mime
            if method=='GET' and path=='/api/devices/purge':return endpoint_purge.catalog(db,user),headers,mime
            if method=='POST' and path=='/api/devices/purge':return endpoint_purge.request(db,user,body),headers,mime
            if method=='POST' and path=='/api/devices/purge/retry':
                return endpoint_purge.retry(db,user,body),headers,mime
            raise APIError(404,'找不到端點資料清除功能')
        if method=='POST' and path=='/api/devices/uninstall':
            job=removal.request(db,user,body)
            for session in db.execute("SELECT * FROM remote_sessions WHERE device_id=? AND status IN ('requested','active')",(job['device_id'],)).fetchall():remote.close(self.server,db,session,'endpoint_uninstall')
            return job,headers,mime
        if method == "GET" and path == "/api/me":
            return {"username": user["username"], "role": user["role"], "csrf": user["csrf"]}, headers, mime
        if method == "POST" and path == "/api/logout":
            db.execute("DELETE FROM sessions WHERE token=?", (user["token"],))
            headers["Set-Cookie"] = "gd_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            return {"ok": True}, headers, mime
        if method=='GET' and path=='/api/fleet':
            from . import fleet
            return fleet.page(db,management.ControlPlane(db),parse_qs(urlsplit(self.path).query)),headers,mime
        if method == "GET" and path == "/api/state":
            from . import fleet
            now=time.time();plane=management.ControlPlane(db)
            devices=fleet.catalog(db,plane)
            if parse_qs(urlsplit(self.path).query).get('compact')==['1']:devices=[fleet.compact(d) for d in devices]
            from .event_storage import overview_stats
            stats = None if parse_qs(urlsplit(self.path).query).get('stats')==['0'] else overview_stats(db,now)
            return {"devices": devices, "stats": stats, "policy": Store.policy(db), "server_time": now,**plane.catalog(devices)}, headers, mime
        if method=='GET' and path=='/api/device-detail':
            params=parse_qs(urlsplit(self.path).query);device_id=params.get('device_id',[''])[0]
            row=db.execute('SELECT id,name,department,last_seen,policy_version,policy_fingerprint,revoked,inventory,group_id,management_revision,last_address,enrolled_at FROM devices WHERE id=?',(device_id,)).fetchone()
            if not row:raise APIError(404,'找不到端點')
            device=dict(row);device['inventory']=json.loads(device['inventory'])
            device['status']='revoked' if device['revoked'] else 'online' if time.time()-device['last_seen']<90 else 'offline'
            plane=management.ControlPlane(db);effective=plane.bundle(device)
            device['native_usb']=native_usb.snapshot(db,device['id'],effective['body']['usb_mode'])
            ext=db.execute('SELECT body,received FROM extended_status WHERE device_id=?',(device['id'],)).fetchone()
            device['extended_status']={**json.loads(ext['body']),'received':ext['received']} if ext else None
            from .document_audit import readiness
            from .custom_library import resolve as resolve_custom
            device['document_audit']=readiness(device,effective['body'],documents=resolve_custom(db,device)['documents'])
            device['uninstall']=removal.latest(db,device['id'])
            selected_user=params.get('principal',[''])[0]
            preview=plane.resolve(device,selected_user) if selected_user else effective
            device['policy_received']=bool(device['policy_version']==effective['version'] and device['policy_fingerprint']==effective['fingerprint'])
            device['policy_progress']=policy_progress.progress(device,effective)
            # Detail is a bounded device/policy read. Audit history and activity
            # aggregates belong to their dedicated, paginated query screens.
            return {'device':device,'effective_policy':effective,'preview_policy':preview},headers,mime
        if path.startswith(('/api/groups','/api/policy-sets','/api/assignments','/api/devices/move')):
            return management.route(db,method,path,body,user['username'],urlsplit(self.path).query),headers,mime
        if method == "GET" and path in ("/api/events", "/api/events.csv"):
            query = parse_qs(urlsplit(self.path).query)
            term = query.get("q", [""])[0][:200]
            from . import audit_sort
            sort=query.get('sort',['id'])[0];direction=query.get('direction',['desc'])[0]
            try:audit_sort.validate(sort,direction)
            except ValueError as exc:raise APIError(400,str(exc))
            anchor=None
            severity = query.get("severity", [""])[0]
            device_id = query.get("device", [""])[0]
            category=query.get('category',[''])[0];kind=query.get('kind',[''])[0]
            categories={'applications':'application.','web':'web.','uploads':'web.upload_','files':'file.','remote':'remote.','documents':None}
            if category and category not in categories:raise APIError(400,'日誌分類不正確')
            start=query.get('start',[''])[0];end=query.get('end',[''])[0]
            start=float(start) if start else 0;end=float(end) if end else 253402300799
            if not math.isfinite(start) or not math.isfinite(end) or start>end:raise APIError(400,'時間範圍不正確')
            limit = min(max(int(query.get("limit", ["50"])[0]), 1), 5000 if path.endswith("csv") else 200)
            offset = max(0, int(query.get("offset", ["0"])[0]))
            # Omit absent filters instead of LIKE '%%' over every JSON payload
            # and OR predicates that prevent device/kind index selection.
            clauses=[];values=[]
            if severity:clauses.append('e.severity=?');values.append(severity)
            if device_id:clauses.append('e.device_id=?');values.append(device_id)
            group_id=query.get('group',[''])[0]
            if group_id:
                plane=management.ControlPlane(db)
                if group_id not in plane.groups:raise APIError(400,'群組不存在')
                children=[gid for gid in plane.groups if group_id in [g['id'] for g in plane.chain(gid)]]
                clauses.append('e.device_id IN (SELECT id FROM devices WHERE group_id IN ('+','.join('?' for _ in children)+'))');values.extend(children)

            if category:
                if category=='documents':clauses.append("e.family IN ('file','uploads')")
                else:
                    clauses.append('e.family=?');values.append({'applications':'application','web':'web','uploads':'uploads','files':'file','remote':'remote'}[category])
            if category=='web':clauses.append("NOT (e.kind>='web.upload_' AND e.kind<'web.upload`')")
            if kind:clauses.append('e.kind=?');values.append(kind)
            if start:clauses.append('e.occurred>=?');values.append(start)
            if end<253402300799:clauses.append('e.occurred<?' if query.get('end_exclusive',[''])[0]=='1' else 'e.occurred<=?');values.append(end)
            person_join=''
            if query.get('person_filter',[''])[0]=='1' or 'file_action' in query:
                actions=audit_reports.action_filter(query.get('file_action',['changes'])[0])
                person_join=' JOIN audit_file_index ai ON ai.event_row=e.id '
                clauses.append('ai.action IN ('+','.join('?' for _ in actions)+')');values.extend(actions)
                if query.get('person_filter',[''])[0]=='1':
                    account=query.get('person',[''])[0]
                    if len(account)>512:raise APIError(400,'帳號過長')
                    clauses.append('ai.person=?');values.append(account.casefold())
            cursor_mode=query.get('cursor_mode',[''])[0]=='1' and not path.endswith('csv')
            cursor_key=getattr(self.server,'event_cursor_key',None)
            if cursor_key is None:
                with _CURSOR_LOCK:
                    if not hasattr(self.server,'event_cursor_key'):self.server.event_cursor_key=secrets.token_bytes(32)
                    cursor_key=self.server.event_cursor_key
            identity=dict(query)
            if sort=='device':
                # Names are mutable. Expire the snapshot instead of silently
                # skipping/duplicating rows after an administrator renames a PC.
                identity['_device_names']=[digest(canonical([tuple(r) for r in db.execute('SELECT id,name FROM devices ORDER BY id')]))]
            filter_id=pagination.filter_identity(identity)
            if cursor_mode:
                token=query.get('cursor',[''])[0]
                if token:
                    try:snapshot,before=pagination.decode(cursor_key,token,user['token'],filter_id)
                    except ValueError:raise APIError(400,'查詢游標無效或已過期，請按搜尋重新查詢')
                else:
                    from .event_storage import head
                    snapshot=head(db)[0];before=snapshot+1
                clauses.append('e.id<=?');values.append(snapshot)
                if sort=='id' and direction=='desc':clauses.append('e.id<?');values.append(before)
                elif before!=snapshot+1:anchor=before
            clause='WHERE '+' AND '.join(clauses) if clauses else ''
            values=tuple(values)
            if term or sort!='id' or direction!='desc':
                from . import audit_search
                from . import audit_search_index
                narrow=bool(start and 0<end-start<=31*86400)
                index_ready,index_state=audit_search_index.ready(db,clause,values,person_join,narrow) if term else (True,{})
                sort_ready,sort_state=audit_sort.ready(db,clause,values,person_join,narrow) if sort in audit_sort.FIELDS else (True,{})
                if not sort_ready:index_state=sort_state
                request_id=query.get('request_id',[''])[0]
                if request_id and (len(request_id)!=32 or any(c not in '0123456789abcdef' for c in request_id)):raise APIError(400,'搜尋識別碼不正確')
                if not sort_ready or (request_id and not index_ready):
                    self.server.search_index.request()
                    if path.endswith('csv'):raise APIError(409,'排序／搜尋索引仍在背景準備，請先完成畫面查詢後再匯出')
                    return {'search_pending':True,'search_index':{**index_state,'error':self.server.search_index.error},'search_cursor':pagination.encode(cursor_key,user['token'],filter_id,snapshot,before) if cursor_mode else None},headers,mime
                registry=self.server.event_search_registry;cancel=None
                if request_id:
                    try:cancel=registry.start(user['token'],request_id)
                    except audit_search.SearchDuplicate:raise APIError(429,'相同搜尋已在處理，請勿重複送出') from None
                if not self.server.event_search_slots.acquire(blocking=False):
                    if cancel:registry.finish(user['token'],request_id,cancel)
                    raise APIError(429,'目前已有較大的查詢／排序，請稍後重試；其他畫面仍可使用。')
                try:
                    identifiers,total=audit_search.identifiers(db,clause,values,person_join,term,limit+1 if cursor_mode else limit,0 if cursor_mode else offset,not cursor_mode and not path.endswith('csv'),30 if path.endswith('csv') else 10,time_filtered=narrow,cancel=cancel,indexed=index_ready,sort=sort,direction=direction,anchor=anchor)
                except ValueError as exc:raise APIError(400,str(exc)) from None
                except audit_search.SearchTimeout:raise APIError(408,'查詢／排序超過時間限制，請縮小日期、指定端點或操作後重試；未回傳不完整結果。') from None
                except audit_search.SearchCancelled:raise APIError(409,'搜尋已取消，請重新查詢') from None
                finally:
                    self.server.event_search_slots.release()
                    if cancel:registry.finish(user['token'],request_id,cancel)
            else:
                count_from='event_headers e'+person_join
                total=None if cursor_mode else db.execute('SELECT count(*) FROM '+count_from+' '+clause,values).fetchone()[0]
                identifiers=[r[0] for r in db.execute('SELECT e.id FROM event_headers e LEFT JOIN devices d ON e.device_id=d.id '+person_join+clause+' ORDER BY e.id DESC LIMIT ? OFFSET ?',values+((limit+1 if cursor_mode else limit),0 if cursor_mode else offset))]
            rows=[dict(db.execute("SELECT e.*,COALESCE(d.name,'管理中心') AS device_name FROM events e LEFT JOIN devices d ON e.device_id=d.id WHERE e.id=?",(eid,)).fetchone()) for eid in identifiers]
            has_more=cursor_mode and len(rows)>limit
            if cursor_mode:rows=rows[:limit]
            for row in rows:
                row["details"] = json.loads(row["details"])
            if path.endswith("csv"):
                output = io.StringIO(newline="")
                writer = csv.writer(output)
                writer.writerow(["id", "device", "kind", "severity", "occurred_unix", "received_unix", "user", "process", "source_path", "destination_path", "url", "title", "details", "hash"])
                def safe(v):
                    v = str(v)
                    return "'" + v if v.lstrip().startswith(("=", "+", "-", "@")) else v
                for row in rows:
                    d=row['details']
                    writer.writerow([safe(v) for v in (row["id"], row["device_name"], row["kind"], row["severity"], row["occurred"], row["received"],d.get('user',d.get('operator','')),d.get('process',''),d.get('source_path',d.get('path','')),d.get('destination_path',''),d.get('url',''),d.get('title',''),canonical(d), row["hash"])])
                headers["Content-Disposition"] = 'attachment; filename="guarddesk-audit.csv"'
                return ("\ufeff" + output.getvalue()).encode("utf-8"), headers, "text/csv; charset=utf-8"
            return {"items": rows, "total": total, "offset": offset, "limit": limit, "has_more":has_more if cursor_mode else offset+len(rows)<total,"next_cursor":pagination.encode(cursor_key,user['token'],filter_id,snapshot,rows[-1]['id']) if cursor_mode and has_more else None,"snapshot":snapshot if cursor_mode else None}, headers, mime
        if method == "GET" and path == "/api/integrity":
            return self.server.store.verify(), headers, mime
        if method == "POST" and path == "/api/enrollments":
            token, expires = secrets.token_urlsafe(24), time.time() + 900
            db.execute("INSERT INTO enrollments(token,expires) VALUES (?,?)", (digest(token), expires))
            Store.event(db, "console", "enrollment.created", "info", {"actor": user["username"], "expires": expires})
            return {"token": token, "expires": expires}, headers, mime
        if method=='POST' and path=='/api/policy/preview':
            import copy
            from .policy_preview import compare_planes
            policy=validate_policy(body.get('body'));current=Store.policy(db)
            if type(body.get('base_version')) is not int or body['base_version']!=current['version']:raise APIError(409,'全域預設已變更')
            plane=management.ControlPlane(db);after=copy.copy(plane)
            after.baseline={**current,'body':policy,'version':current['version']+1}
            result=compare_planes(plane,after,management.devices_for_management(db),None,management.preview_offset(body),50)
            result['generation']=plane.version
            return result,headers,mime
        if method == "POST" and path == "/api/policy":
            if 'expected_generation' in body and body['expected_generation']!=management.generation(db):raise APIError(409,'繼承來源已變更，請重新預覽')
            policy = validate_policy(body.get("body"))
            current = Store.policy(db)
            if type(body.get("base_version")) is not int or body["base_version"] != current["version"]:
                raise APIError(409, "策略已被其他管理員修改，請重新整理")
            version = current["version"] + 1
            db.execute("INSERT INTO policies VALUES (?,?,?,?)", (version, canonical(policy), time.time(), user["username"]))
            management.validate_active_combinations(db)
            management.bump(db)
            Store.event(db, "console", "policy.published", "warning", {"actor": user["username"], "version": version, "body": policy})
            return Store.policy(db), headers, mime
        if method == "POST" and path == "/api/devices/revoke":
            device_id = string(body, "device_id", 100)
            pending=removal.latest(db,device_id)
            if pending and pending['status'] not in removal.TERMINAL:raise APIError(409,'移除工作尚未完成，請先保留端點憑證供日誌補送與結果回報')
            if not db.execute("SELECT id FROM devices WHERE id=? AND revoked=0", (device_id,)).fetchone():
                raise APIError(404, "找不到有效端點")
            db.execute("UPDATE devices SET revoked=1 WHERE id=?", (device_id,))
            Store.event(db, device_id, "device.revoked", "warning", {"actor": user["username"]})
            return {"ok": True}, headers, mime
        raise APIError(404, "找不到此功能")


def tls_context(host, cert=None, key=None):
    if bool(cert) != bool(key):
        raise ValueError('TLS 憑證與私鑰必須一起提供')
    if host not in ("127.0.0.1", "localhost") and not (cert and key):
        raise ValueError("非本機監聽必須提供 --cert 與 --key 啟用 TLS")
    if cert and key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        def unsupported_password():
            raise ValueError('無人值守 Server 不支援需互動密碼的 PEM 私鑰；請由 MIS 以受保護 ACL 部署公司核准私鑰')
        context.load_cert_chain(cert, key, password=unsupported_password)
        return context
    return None


def serve(db_path, host="127.0.0.1", port=8787, cert=None, key=None, surface='all', shared=None,endpoint_source=None):
    if surface not in ('all', 'agent', 'console'):
        raise ValueError('Server 介面類型不正確')
    if surface == 'console' and host not in ('127.0.0.1', 'localhost'):
        raise ValueError('本機管理介面僅能監聽 loopback')
    if surface == 'agent' and not (cert and key):
        raise ValueError('端點介面必須使用 TLS')
    # Invalid TLS fails before DB creation, listening or background tasks.
    context = tls_context(host, cert, key)
    from .server_config import local_database
    db_path = local_database(db_path)
    from .storage_maintenance import DatabaseLease
    lease=shared.database_lease.retain() if shared and getattr(shared,'database_lease',None) else DatabaseLease(db_path)
    try:
        server=Server((host, port), Store(db_path), tls=bool(context), context=context, surface=surface, shared=shared,endpoint_source=endpoint_source)
        server.database_lease=lease
        return server
    except BaseException:
        if lease:lease.close()
        raise
