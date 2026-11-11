"""Visible, opt-in folder audit agent and mediated file export."""
import hashlib
import json
import logging
import os
import platform
import secrets
import shutil
import socket
import sqlite3
import threading
import time
from contextlib import contextmanager
import urllib.error
import urllib.request
import ssl
import copy
from pathlib import Path
from urllib.parse import urlsplit
from .policy import MAX_FILE, evaluate, normalize_policy,decode_agent_policy
from .serialization import canonical
from . import __version__
from .identity import current_account,session_metadata
from .file_exclusions import excluded_internal_health_activity,excluded_installer_activity
from .transport_errors import CenterTransportError, network_error

LOG = logging.getLogger("guarddesk.agent")












def inventory(root,include_software=True):
    from .remote_trial import reject
    reject('Asset inventory')
    disk = shutil.disk_usage(root)
    result = {"hostname": socket.gethostname(), "os": platform.platform(), "architecture": platform.machine(),
              "python": platform.python_version(), "cpu_count": os.cpu_count(), "disk_total": disk.total, "disk_free": disk.free,
              "watch": str(root), "agent_version": __version__, "capabilities": ["folder_audit", "managed_export", "asset_inventory", "windows_security_audit_adapter", "usb_policy_adapter", "browser_native_host", "browser_history_readonly_v1", "upload_qos_adapter"],
              "software": [], "software_coverage": "unavailable"}
    result['capabilities'].append('remote_uninstall_v1')
    result['capabilities'].append('remote_remove_files_v1')
    if os.name == "nt" and include_software:
        import winreg
        names = set()
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for registry_path in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"):
                try:
                    with winreg.OpenKey(hive, registry_path) as key:
                        for index in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                with winreg.OpenKey(key, winreg.EnumKey(key, index)) as app:
                                    title = winreg.QueryValueEx(app, "DisplayName")[0]
                                    if isinstance(title, str):
                                        names.add(title[:160])
                            except OSError:
                                continue
                except OSError:
                    continue
        result["software"] = sorted(names)[:200]
        result["software_coverage"] = "registry_partial_200_max"
    result.update(session_metadata())
    return result


class Agent:
    def __init__(self, config):
        self.config_path = Path(config).resolve()
        self.config = json.loads(self.config_path.read_text(encoding="utf-8"))
        from .remote_trial_install import check_settings
        check_settings(self.config)
        self.audit_runtime=self.config_path.parent.parent if self.config_path.parent.name.lower()=='agent' else self.config_path.parent
        self.root = Path(self.config["watch"]).resolve()
        self.state = self.config_path.with_suffix(".sqlite3")
        self.feature_status={}
        self.monitor=None;self.security=None;self.proxy=None;self.browser_history=None
        self.native_handoff=None
        self.control_signature=None;self.next_controls=0
        self.assets={};self._next_software=0;self._next_inventory=0
        self._snapshot=None;self._policy_cache=None;self._policy_stamp=None;self._policy_checked=0
        self._policy_lock=threading.Lock()
        from .performance import ProcessSampler
        self._process_sampler=ProcessSampler()
        self._opener=None
        self._qos_verified=False
        with self.db() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS outbox(event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, signature TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS outbox_created ON outbox(created,event_id);
            CREATE TABLE IF NOT EXISTS outbox_priority(event_id TEXT PRIMARY KEY,created REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS outbox_priority_created ON outbox_priority(created,event_id);
            ''')
            # One-time compatibility backfill. Future host/collector writes add
            # priority entries in the same transaction as the durable event.
            if not db.execute("SELECT 1 FROM state WHERE key='outbox_priority_initialized'").fetchone():
                db.execute("INSERT OR IGNORE INTO outbox_priority SELECT event_id,created FROM outbox WHERE json_extract(payload,'$.kind') LIKE 'web.%' OR json_extract(payload,'$.kind') LIKE 'application.%' OR json_extract(payload,'$.severity')='critical'")
                db.execute("INSERT INTO state VALUES ('outbox_priority_initialized','1')")

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.state, timeout=15)
        try:
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('PRAGMA cache_size=-512')
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def call(self, path, body,timeout=10):
        from .remote_trial import enabled
        if enabled() and path not in {'/api/agent/heartbeat', '/api/agent/remote/poll',
                '/api/agent/remote/update','/api/agent/remote/native',
                '/api/agent/uninstall/poll','/api/agent/uninstall/status'}:
            raise PermissionError('Non-remote endpoint route disabled in trial')
        if self.config.get('machine_session'):
            from .machine_agent_windows import request as machine_request
            session=self.config['machine_session']
            return machine_request(path,body,timeout=timeout,parent=session['parent'],generation=session['generation'])
        if self._opener is None:self._opener=transport(self.config['server'],self.config.get('ca'))
        return request(self.config["server"], path, body, self.config["token"], self.config.get("ca"),opener=self._opener,timeout=timeout)

    @contextmanager
    def wal_session(self):
        # Keep a read-only, idle connection open during a long-running worker.
        # Otherwise every short queue transaction closes the last connection,
        # forcing a WAL checkpoint and extra synchronous database writes.
        with self.db() as anchor:
            anchor.execute('SELECT key FROM state LIMIT 1').fetchall()
            yield

    def queue(self, kind, details, severity="info", db=None, occurred=None, event_id=None):
        from .remote_trial import reject
        reject('Audit event queue')
        # Product collection scope: retain historical records, but never queue
        # new content/attribute-change events from any collector.
        if kind == 'file.modified':return None
        if excluded_internal_health_activity(kind,severity,details):return None
        if excluded_installer_activity(kind,severity,details):return None
        eid = event_id or secrets.token_hex(16)
        payload = {"event_id": eid, "kind": kind, "severity": severity, "details": details, "occurred": time.time() if occurred is None else occurred}
        if db is not None:
            db.execute("INSERT OR IGNORE INTO outbox VALUES (?,?,?)", (eid, canonical(payload), time.time()))
            if kind.startswith(('web.','application.')) or severity=='critical':db.execute('INSERT OR IGNORE INTO outbox_priority VALUES (?,?)',(eid,time.time()))
        else:
            with self.db() as connection:
                connection.execute("INSERT OR IGNORE INTO outbox VALUES (?,?,?)", (eid, canonical(payload), time.time()))
                if kind.startswith(('web.','application.')) or severity=='critical':connection.execute('INSERT OR IGNORE INTO outbox_priority VALUES (?,?)',(eid,time.time()))
        return eid

    def cached_policy(self):
        # Native host and main Agent use separate processes. Check the WAL timestamp,
        # retaining a bounded immutable-by-convention snapshot between reads.
        with self._policy_lock:
            stamp=[]
            for path in (self.state,Path(str(self.state)+'-wal')):
                try:s=path.stat();stamp.append((s.st_mtime_ns,s.st_size))
                except FileNotFoundError:stamp.append(None)
            now=time.monotonic()
            if self._policy_cache is None or stamp!=self._policy_stamp or now-self._policy_checked>=2:
                with self.db() as db:saved=db.execute("SELECT value FROM state WHERE key='policy'").fetchone()
                packet=json.loads(saved[0]) if saved else {'version':0,'body':{}}
                packet=decode_agent_policy(packet)
                self._policy_cache=packet;self._policy_stamp=stamp;self._policy_checked=now
            return copy.deepcopy(self._policy_cache)

    def queue_status(self):
        with self.db() as db:
            count,oldest=db.execute('SELECT count(*),min(created) FROM outbox').fetchone()
        return {'pending':count,'oldest_pending':oldest,'database_bytes':self.state.stat().st_size,
                'disk_free':shutil.disk_usage(self.state.parent).free}

    def policy_for_user(self,account):
        packet=self.cached_policy()
        selected=packet.get('user_policies',{}).get(account.casefold(),packet)
        selected['body']=normalize_policy(selected['body'])
        return selected

    def heartbeat(self, refresh_inventory=True):
        from .remote_trial import reject
        reject('Standard heartbeat/inventory')
        with self.db() as db:
            saved = db.execute("SELECT value FROM state WHERE key='policy'").fetchone()
        old=json.loads(saved[0]) if saved else {}
        ack = old.get('version',0)
        now=time.monotonic()
        if refresh_inventory and (not self.assets or now>=self._next_inventory):
            full=not self.assets or now>=self._next_software
            assets=inventory(self.root) if full else inventory(self.root,include_software=False)
            if not full:
                assets['software']=self.assets.get('software',[])
                assets['software_coverage']=self.assets.get('software_coverage','unavailable')
            else:self._next_software=now+900
            self._next_inventory=now+60
            self.assets=assets
        assets=copy.deepcopy(self.assets)
        from .document_audit import browser_status
        self.feature_status['document_upload']=browser_status(self,self.cached_policy()['body']['browser_audit'])
        if self.native_handoff is not None:
            self.feature_status['native_file_handoff']=self.native_handoff.snapshot()
        self.feature_status.setdefault('performance',{}).update(self._process_sampler.sample())
        assets['collectors']=self.feature_status
        assets['outbox']=self.queue_status()
        result = self.call("/api/agent/heartbeat", {"policy_version": ack, "policy_fingerprint":old.get('fingerprint',''), "inventory": assets})
        decoded=decode_agent_policy(result['policy'])
        with self.db() as db:
            if canonical(old)!=canonical(result['policy']):db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)", (canonical(result["policy"]),))
        with self._policy_lock:self._policy_cache=None
        self.assets = assets
        if getattr(self,'_installed_desktop_browser_dispatch',False):
            from .browser_dispatch import sync
            self.feature_status['browser_deployment']=sync(self,result.get('browser_dispatch'),enabled=decoded['body']['browser_audit'])
        return decoded

    def collect_native(self,policy):
        from .remote_trial import reject
        reject('Native audit collectors')
        if self.config.get('machine_session'):
            # The SYSTEM companion owns directory/security collection once per
            # computer. User sessions supply browser/user-desktop sources only.
            self.feature_status['directory_notifications']={'status':'machine_worker_owned'}
            self.feature_status['security_log']={'status':'machine_worker_owned'}
            return
        from .windows_controls import WindowsControls
        controls=WindowsControls(self)
        body=policy['body']
        from .custom_client import effective_body,build_number
        from .custom_settings import compatibility_modules
        exceptions=compatibility_modules(effective_body(self),build_number())
        skip_directory='directory_notifications' in exceptions
        if skip_directory and self.monitor:self.monitor.close();self.monitor=None
        if os.name=='nt' and body['file_audit']['enabled'] and not skip_directory:
            from .windows_watch import DirectoryMonitor
            if self.monitor and self.monitor.policy['file_audit']!=body['file_audit']:
                self.monitor.close();self.monitor=None
            if not self.monitor and not skip_directory:
                self.monitor=DirectoryMonitor(self,body)
                self.feature_status['directory_notifications']=self.monitor.start()
        signature=canonical({k:body[k] for k in ('usb_mode','file_audit','upload_rules')})
        if signature!=self.control_signature or time.monotonic()>=self.next_controls:
            previous=self.feature_status.get('windows')
            self.feature_status['windows']=controls.apply(body)
            if previous!=self.feature_status['windows']:
                self.queue('agent.controls_status',self.feature_status['windows'],'warning' if self.feature_status['windows'].get('status') in ('requires_admin','not_installed','partial','failed') else 'info')
            self.control_signature=signature;self.next_controls=time.monotonic()+60
            with self.db() as db:
                db.execute("INSERT OR REPLACE INTO state VALUES ('feature_status',?)",(canonical(self.feature_status),))
        if controls.installed and body['file_audit']['enabled'] and os.name=='nt':
            if self._snapshot:self._snapshot.close();self._snapshot=None
            from .windows_events import SecurityCollector
            from .windows_watch import DirectoryMonitor
            if self.monitor and self.monitor.policy['file_audit']!=body['file_audit']:
                self.monitor.close();self.monitor=None
            if not self.monitor and not skip_directory:
                self.monitor=DirectoryMonitor(self,body)
                self.feature_status['directory_notifications']=self.monitor.start()
            try:
                if not self.security:self.security=SecurityCollector(self)
                security_body={**body,'_custom_skip_security_files':'security_file_events' in exceptions}
                if 'process_events' in exceptions:security_body['application_audit']=False
                self.feature_status['security_log']={'status':'collecting',**self.security.poll(security_body)}
            except OSError as exc:
                message=str(exc)[:500]
                if self.feature_status.get('security_log',{}).get('error')!=message:
                    self.queue('agent.audit_unavailable',{'error':message},'critical')
                self.feature_status['security_log']={'status':'failed','error':message}
        else:
            if self.monitor and not body['file_audit']['enabled']:self.monitor.close();self.monitor=None
            self.feature_status['security_log']={'status':'disabled' if not body['file_audit']['enabled'] else 'not_installed'}
            if body['file_audit']['enabled'] and not skip_directory:self.scan(exclude_paths=body['file_audit']['exclude_paths'])
            elif self._snapshot:self._snapshot.close();self._snapshot=None
        if self.config.get('proxy_enabled') and not self.proxy:
            from .upload_proxy import GuardProxy
            try:
                self.proxy=GuardProxy(('127.0.0.1',int(self.config.get('proxy_port',17879))),self)
                threading.Thread(target=self.proxy.serve_forever,daemon=True).start()
                self.feature_status['website_proxy']={'status':'listening','port':self.proxy.server_address[1]}
            except OSError as exc:
                self.feature_status['website_proxy']={'status':'failed','error':str(exc)[:500]}

    def close_collectors(self):
        if self.native_handoff is not None:
            self.native_handoff.close()
        if self.browser_history:self.browser_history.close();self.browser_history=None
        if self._snapshot:self._snapshot.close();self._snapshot=None
        if self.monitor:self.monitor.close();self.monitor=None
        if self.proxy:self.proxy.close();self.proxy=None

    def flush(self,max_batches=20,require_empty=True,pause=0,stop=None):
        sent=0
        for _ in range(max_batches):
            if stop is not None and stop.is_set():break
            with self.db() as db:
                rows=[];size=0
                priority=[];priority_bytes=0
                for row in db.execute('SELECT o.event_id,o.payload FROM outbox_priority p JOIN outbox o ON o.event_id=p.event_id ORDER BY p.created,p.event_id LIMIT 25'):
                    length=len(row[1].encode('utf-8'))
                    if priority and priority_bytes+length>65536:break
                    priority.append(row);priority_bytes+=length
                ordinary=list(db.execute('SELECT event_id,payload FROM outbox ORDER BY created,event_id LIMIT 100'))
                seen=set()
                for row in priority+ordinary:
                    if row[0] in seen:continue
                    length=len(row[1].encode('utf-8'))
                    if rows and size+length>262144:break
                    rows.append(row);seen.add(row[0]);size+=length
                    if len(rows)>=100:break
            if not rows:
                return {'sent':sent,'pending':False}
            result = self.call("/api/agent/events", {"events": [json.loads(row[1]) for row in rows]})
            expected = {row[0] for row in rows}
            accepted = result.get("accepted", [])
            if set(accepted) != expected:
                raise ConnectionError("管理中心未完整確認事件")
            with self.db() as db:
                db.executemany("DELETE FROM outbox WHERE event_id=?", [(eid,) for eid in accepted])
                db.executemany('DELETE FROM outbox_priority WHERE event_id=?',[(eid,) for eid in accepted])
            sent+=len(accepted)
            if pause and stop is not None:
                if stop.wait(pause):break
            elif pause:time.sleep(pause)
        with self.db() as db:
            pending=bool(db.execute("SELECT 1 FROM outbox LIMIT 1").fetchone())
            if pending and require_empty:
                raise ConnectionError("事件積壓尚未送完，請稍後重試")
        return {'sent':sent,'pending':pending}

    def scan(self,max_entries=200,time_budget=.05,exclude_paths=None):
        from .remote_trial import reject
        reject('Folder scanning')
        if not self.root.is_dir():
            raise ValueError("監看資料夾不存在；保留既有盤點，不回報刪除")
        from .snapshot import Snapshot
        paths=list(self.cached_policy()['body']['file_audit']['exclude_paths'] if exclude_paths is None else exclude_paths)
        if self._snapshot and self._snapshot.exclude_paths!=paths:
            self._snapshot.close();self._snapshot=None
        if not self._snapshot:self._snapshot=Snapshot(self,paths)
        result=self._snapshot.step(max_entries,time_budget)
        if not result['in_progress']:self._snapshot.close();self._snapshot=None
        self.feature_status['fallback_snapshot']=result
        return result

    def export(self, source, target):
        # Always consult the server: offline/revoked endpoints cannot export via this command.
        self.heartbeat()
        policy = self.policy_for_user(current_account())
        source, target = Path(source).resolve(), Path(target).absolute()
        if not source.is_relative_to(self.root) or not source.is_file():
            raise ValueError("來源必須在監看資料夾內")
        if source.stat().st_size > MAX_FILE:
            self.queue("export.blocked", {"path": str(source.relative_to(self.root)), "reasons": ["pilot_10mb_limit"]}, "warning")
            self.flush()
            raise PermissionError("試用版受控外發單檔上限 10 MB")
        # Read once, evaluate and write the exact same bytes to avoid content-change races.
        with source.open("rb") as stream:
            data = stream.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise PermissionError("檔案讀取時超過上限")
        result = evaluate(policy["body"], source.name, data)
        detail = {"path": str(source.relative_to(self.root)), "target": target.name, "policy_version": policy["version"],
                  "user":current_account(),
                  "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "reasons": result["reasons"]}
        if not result["allowed"]:
            self.queue("export.blocked", detail, "critical")
            self.flush()
            raise PermissionError("策略已阻擋外發：" + ", ".join(result["reasons"]))
        self.queue("export.requested", detail, "warning" if result["matched"] else "info")
        self.flush()
        try:
            with target.open("xb") as stream:
                stream.write(data)
        except OSError:
            self.queue("export.failed", detail, "warning")
            raise
        self.queue("export.completed", detail, "warning" if result["matched"] else "info")
        try:
            self.flush()
        except ConnectionError:
            LOG.warning("外發已完成；完成紀錄保留於本機待補送")
        return result

    def run(self, stop, interval=5):
        from .remote_trial import reject
        reject('Desktop collector')
        from .performance import background_work
        from .decommission import saved
        managed_remote=getattr(self,'_managed_remote',None)
        marker=saved(self)
        if marker and managed_remote:
            managed_remote.stop.set();managed_remote.local_stop.set();managed_remote.close_indicator()
        if marker and marker['phase']=='done':self.decommissioned=True;return
        self.remote_stop=managed_remote.stop if managed_remote else threading.Event()
        if managed_remote:self.remote=managed_remote
        from .custom_client import CustomClient
        custom=None
        if os.name=='nt':
            try:custom=CustomClient(self,stop).start()
            except (OSError,ValueError,sqlite3.Error):self.feature_status['custom_settings']={'state':'invalid_custom_cache'}
        if not managed_remote and os.name=='nt' and self.config.get('remote_enabled',True) and not saved(self):
            from .remote_windows import RemoteAgent
            self.remote=RemoteAgent(self,self.remote_stop,stop);self.remote.start()
        with background_work() as scheduling,self.wal_session():
            self.feature_status['performance']={**scheduling,'scan_entries':200,'scan_budget_ms':50,'software_refresh_seconds':900,'inventory_refresh_seconds':60,'flush_batches':8,'flush_batch_events':100}
            try:self._run_background(stop,interval)
            finally:
                if custom:custom.close()
                if not managed_remote:
                    self.remote_stop.set()
                    if hasattr(self,'remote'):self.remote.local_stop.set();self.remote.close_indicator()

    def _run_background(self,stop,interval):
        LOG.info("Agent 啟動，讀取已安裝的收集器與離線策略；按 Ctrl+C 可停止")
        from .native_handoff_runtime import NativeHandoffRuntime
        self.native_handoff=NativeHandoffRuntime(self)
        if os.name=='nt':
            from .browser_history import BrowserHistory
            self.browser_history=BrowserHistory(self)
            self.browser_history.start()
        from .decommission import saved
        if not saved(self):self.queue("agent.started", {"watch": str(self.root)})
        next_heartbeat = 0
        next_runtime_health=0
        next_network=0;retry=5
        try:
            while not stop.is_set():
                from .decommission import main_step,saved
                try:
                    if time.monotonic()>=next_network and main_step(self):return
                except (OSError,ConnectionError,ValueError):pass
                if saved(self):
                    self.feature_status['native_file_handoff']=self.native_handoff.step(self.cached_policy())
                    stop.wait(interval);continue
                try:
                    policy=self.cached_policy()
                    self.feature_status['native_file_handoff']=self.native_handoff.step(policy)
                    self.collect_native(policy)
                except (OSError,ValueError):LOG.exception('收集器執行失敗；本機 outbox 保留')
                if self.config.get('update_key') and time.monotonic()>=next_runtime_health:
                    from .update_client import save
                    save(self.config_path.parent/'runtime-health.json',{'version':__version__,'time':time.time(),'device_id':self.config['device_id']})
                    next_runtime_health=time.monotonic()+30
                try:
                    if time.monotonic()<next_network:
                        stop.wait(min(interval,.25) if self._snapshot else interval);continue
                    if time.monotonic() >= next_heartbeat:
                        self.heartbeat()
                        next_heartbeat = time.monotonic() + 30
                    self.flush(max_batches=8,require_empty=False,pause=.05,stop=stop)
                    retry=5;next_network=0
                except (ConnectionError,OSError,ValueError):
                    LOG.warning('管理中心不可用；依最後策略運作，紀錄保留本機待補送')
                    next_network=time.monotonic()+retry;retry=min(retry*2,60)
                stop.wait(min(interval,.25) if self._snapshot else interval)
        finally:self.close_collectors()

# Compatibility imports for the standard Agent API.
from .endpoint_transport import NoRedirect, transport, request, private_write, enroll
