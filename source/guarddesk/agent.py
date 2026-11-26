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
from .audit_collection import uploads_enabled

from .policy import MAX_FILE, evaluate, normalize_policy,decode_agent_policy
from .serialization import canonical
from . import __version__
from .identity import current_account,session_metadata
from .file_exclusions import excluded_internal_health_activity,excluded_installer_activity
from .document_writes import excluded_unconfirmed_write
from .transport_errors import CenterTransportError, network_error
from . import event_upload, document_saves

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
        self._inventory_upload=InventoryUpload()
        self._qos_verified=False
        self._upload_schedule = None
        with self.db() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS outbox(event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, signature TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS outbox_created ON outbox(created,event_id);
            CREATE TABLE IF NOT EXISTS outbox_priority(event_id TEXT PRIMARY KEY,created REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS outbox_priority_created ON outbox_priority(created,event_id);
            ''' + event_upload.SCHEMA + document_saves.SCHEMA)
            # One-time compatibility backfill. Future host/collector writes add
            # priority entries in the same transaction as the durable event.
            if not db.execute("SELECT 1 FROM state WHERE key='outbox_priority_initialized'").fetchone():
                db.execute("INSERT OR IGNORE INTO outbox_priority SELECT event_id,created FROM outbox WHERE json_extract(payload,'$.kind') LIKE 'web.%' OR json_extract(payload,'$.kind') LIKE 'application.%' OR json_extract(payload,'$.severity')='critical'")
                db.execute("INSERT INTO state VALUES ('outbox_priority_initialized','1')")
            idle=db.execute("SELECT value FROM state WHERE key='heartbeat_only'").fetchone()
            self.idle_revision=int(idle[0]) if idle else 0
        self._next_mode_check=0

    def set_idle_revision(self, revision, db):
        if type(revision) is not int or revision < 0:
            raise ValueError('端點心跳模式版本不正確')
        if self.idle_revision == revision:return
        if revision:
            db.execute("INSERT OR REPLACE INTO state VALUES ('heartbeat_only',?)",(str(revision),))
            db.execute("DELETE FROM state WHERE key='custom_packet_v1'")
            self.custom_packet=None
        else:
            db.execute("DELETE FROM state WHERE key='heartbeat_only'")
            db.execute("INSERT OR REPLACE INTO state VALUES ('resume_since',?)",(str(time.time()),))
            db.execute("INSERT OR REPLACE INTO state VALUES ('snapshot_rebaseline','1')")
            db.execute("DELETE FROM state WHERE key IN ('security_cursor','browser_history_session','snapshot_last_failure') OR key LIKE 'applocker_cursor_%'")
        self.idle_revision=revision

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
        if path != '/api/agent/heartbeat':
            # Other processes (including the independent updater) share this agent DB.
            now=time.monotonic()
            if now>=self._next_mode_check:
                with self.db() as db:
                    idle=db.execute("SELECT value FROM state WHERE key='heartbeat_only'").fetchone()
                self.idle_revision=int(idle[0]) if idle else 0
                self._next_mode_check=now+2
            if self.idle_revision:
                raise ConnectionError('端點目前只回報心跳')
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
        def post(data):
            return request(self.config["server"], path, data, self.config["token"], self.config.get("ca"),opener=self._opener,timeout=timeout)
        if path=='/api/agent/heartbeat' and isinstance(body.get('inventory'),dict) and 'software' in body['inventory']:
            return self._inventory_upload.send(post,body)
        return post(body)

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
        if kind=='web.upload_gap' and isinstance(details,dict) and details.get('reason')=='request_body_unavailable':return None
        if kind in ('web.navigation','web.page_title') and isinstance(details,dict) and details.get('source')=='browser_extension':return None
        # Product collection scope: retain historical records, but never queue
        # new content/attribute-change events from any collector.
        if kind == 'file.modified':return None
        if excluded_unconfirmed_write(kind,severity,details):return None
        if excluded_internal_health_activity(kind,severity,details):return None
        if excluded_installer_activity(kind,severity,details):return None
        identity = None
        if isinstance(details, dict) and '_save_object' in details:
            details = dict(details)
            identity = details.pop('_save_object')
        eid = event_id or secrets.token_hex(16)
        payload = {"event_id": eid, "kind": kind, "severity": severity, "details": details, "occurred": time.time() if occurred is None else occurred}

        def insert(connection):
            if connection.execute("SELECT 1 FROM state WHERE key='heartbeat_only'").fetchone():return None
            if occurred is not None:
                since=connection.execute("SELECT value FROM state WHERE key='resume_since'").fetchone()
                if since and occurred<float(since[0]):return None
            stamp = time.time()
            added = connection.execute("INSERT OR IGNORE INTO outbox VALUES (?,?,?)", (eid, canonical(payload), stamp))
            if added.rowcount and document_saves.candidate(kind, severity, details, identity):
                ref = identity or (details.get('file_id'), None)
                document_saves.track(connection, eid, ref, stamp, kind, details['path'])
            if kind.startswith(('web.','application.')) or severity=='critical':
                connection.execute('INSERT OR IGNORE INTO outbox_priority VALUES (?,?)',(eid, stamp))
            return eid

        if db is not None:
            return insert(db)
        with self.db() as connection:
            return insert(connection)

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
                with self.db() as db:values=dict(db.execute("SELECT key,value FROM state WHERE key IN ('policy','heartbeat_only')"))
                if 'heartbeat_only' in values:
                    from .policy import heartbeat_policy
                    packet=heartbeat_policy(int(values['heartbeat_only']))
                else:
                    packet=json.loads(values['policy']) if 'policy' in values else {'version':0,'body':{}}
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
        if old.get('heartbeat_only') or self.idle_revision:
            result=self.call('/api/agent/heartbeat',{'idle_heartbeat':True,'inventory':{}})
            return self.receive_policy(old,result,{})
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
        self.feature_status['document_upload']=browser_status(self,uploads_enabled(self.policy_for_user(current_account())['body']))
        if self.native_handoff is not None:
            self.feature_status['native_file_handoff']=self.native_handoff.snapshot()
        self.feature_status.setdefault('performance',{}).update(self._process_sampler.sample())
        assets['collectors']=self.feature_status
        assets['outbox']=self.queue_status()
        result = self.call("/api/agent/heartbeat", {"policy_version": ack, "policy_fingerprint":old.get('fingerprint',''), "inventory": assets})
        return self.receive_policy(old,result,assets)

    def receive_policy(self,old,result,assets):
        decoded=decode_agent_policy(result['policy'])
        with self.db() as db:
            if canonical(old)!=canonical(result['policy']):db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)", (canonical(result["policy"]),))
            self.set_idle_revision(decoded.get('heartbeat_only',0),db)
        with self._policy_lock:self._policy_cache=None
        self.assets = {} if self.idle_revision else assets
        if getattr(self,'_installed_desktop_browser_dispatch',False):
            from .browser_dispatch import sync
            self.feature_status['browser_deployment']=sync(self,result.get('browser_dispatch'),enabled=uploads_enabled(decoded['body']) or any(uploads_enabled(p['body']) for p in decoded.get('user_policies', {}).values()))
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
        with self.db() as db:
            if not db.execute('SELECT 1 FROM outbox LIMIT 1').fetchone():
                return {'sent':0,'pending':False}
        with event_upload.sender(self.state, wait=require_empty) as acquired:
            if not acquired:
                return {'sent':0,'pending':True}
            return self._flush_batches(max_batches,require_empty,pause,stop)

    def _flush_batches(self,max_batches,require_empty,pause,stop):
        sent=0
        for _ in range(max_batches):
            if stop is not None and stop.is_set():break
            with self.db() as db:
                if db.execute("SELECT 1 FROM state WHERE key='heartbeat_only'").fetchone():
                    return {'sent':sent,'pending':bool(db.execute('SELECT 1 FROM outbox LIMIT 1').fetchone())}
                document_saves.settle(db, force=require_empty)
            with self.db() as db:
                if db.execute("SELECT 1 FROM state WHERE key='heartbeat_only'").fetchone():
                    return {'sent':sent,'pending':bool(db.execute('SELECT 1 FROM outbox LIMIT 1').fetchone())}
                rows=[];size=0
                priority=[];priority_bytes=0
                urgent = list(db.execute(f'SELECT event_id,payload FROM outbox WHERE {event_upload.URGENT} ORDER BY created,event_id LIMIT 12'))
                preferred = db.execute('SELECT o.event_id,o.payload FROM outbox_priority p JOIN outbox o ON o.event_id=p.event_id ORDER BY p.created,p.event_id LIMIT 25')
                preferred_ids = set()
                for row in urgent + list(preferred):
                    if row[0] in preferred_ids:continue
                    length=len(row[1].encode('utf-8'))
                    if priority and priority_bytes+length>65536:break
                    priority.append(row);priority_bytes+=length
                    preferred_ids.add(row[0])
                    if len(priority)>=25:break
                ordinary=list(db.execute('SELECT event_id,payload FROM outbox WHERE event_id NOT IN '
                                         '(SELECT event_id FROM document_save_pending) ORDER BY created,event_id LIMIT 100'))
                seen=set()
                for row in priority+ordinary:
                    if row[0] in seen:continue
                    length=len(row[1].encode('utf-8'))
                    if rows and size+length>262144:break
                    rows.append(row);seen.add(row[0]);size+=length
                    if len(rows)>=100:break
                if not rows:
                    pending = bool(db.execute('SELECT 1 FROM outbox LIMIT 1').fetchone())
                    if pending and require_empty:
                        continue
                    return {'sent':sent,'pending':pending}
                outgoing, keys, local_keys = event_upload.prepare(db, rows, self.config.get('device_id'))
            expected = {event['event_id'] for event in outgoing}
            confirmed = set()
            if outgoing:
                result = self.call("/api/agent/events", {"events": outgoing})
                accepted = result.get('accepted') if isinstance(result, dict) else None
                if (not isinstance(accepted,list) or len(accepted)>len(expected)
                        or not all(isinstance(eid,str) for eid in accepted)):
                    raise ConnectionError("管理中心事件回覆格式不正確")
                confirmed=set(accepted)
                if len(confirmed)!=len(accepted) or not confirmed.issubset(expected):
                    raise ConnectionError("管理中心事件回覆包含未知或重複識別碼")
            waiting=expected-confirmed
            # A local copy may share an outgoing ID or have a receipt from an earlier batch.
            local_ids=[(eid,) for eid,key in local_keys.items() if keys[key] not in waiting]
            with self.db() as db:
                event_upload.confirm(db, keys, confirmed)
                db.executemany("DELETE FROM outbox WHERE event_id=?", local_ids)
                db.executemany('DELETE FROM outbox_priority WHERE event_id=?', local_ids)
            sent+=len(confirmed)
            if waiting:
                raise ConnectionError("管理中心未完整確認事件")
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
        if self.idle_revision:
            with source.open('rb') as original, target.open('xb') as output:
                shutil.copyfileobj(original,output)
            return {'allowed':True,'matched':False,'reasons':[],'mode':'monitor'}
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
            self.feature_status['performance']={**scheduling,'scan_entries':200,'scan_budget_ms':50,'software_refresh_seconds':900,'inventory_refresh_seconds':60,'flush_batches':1,'flush_batch_events':100,'upload_interval_seconds':[event_upload.NORMAL_MIN,event_upload.NORMAL_MAX]}
            try:self._run_background(stop,interval)
            finally:
                if custom:custom.close()
                if not managed_remote:
                    self.remote_stop.set()
                    if hasattr(self,'remote'):self.remote.local_stop.set();self.remote.close_indicator()

    def upload_if_due(self, stop=None):
        if getattr(self,'idle_revision',0):return
        if self._upload_schedule is None:
            self._upload_schedule = event_upload.UploadSchedule()
        self._upload_schedule.poll(self, stop)

    def _link_step(self,stop,heartbeat_gate,next_heartbeat):
        """One bounded center round; returns the next heartbeat deadline.

        The reason is a fixed scalar for the next successful heartbeat and the
        local log. It is never an exception text, URL, token or path.
        """
        from .transport_errors import link_state,link_retry_floor
        if time.monotonic()>=next_heartbeat and heartbeat_gate.ready():
            previous=self.feature_status.get('center_link') or {}
            try:
                self.heartbeat()
                next_heartbeat=time.monotonic()+30;heartbeat_gate.success()
                last=previous.get('state') if previous.get('state') not in (None,'connected') else previous.get('last_failure')
                self.feature_status['center_link']={'state':'connected',**({'last_failure':last} if last else {})}
            except (ConnectionError,OSError,ValueError) as exc:
                state=link_state(exc);heartbeat_gate.failure(link_retry_floor(state))
                if previous.get('state')!=state['state']:
                    LOG.warning('心跳未送達（%s）；依最後策略運作，紀錄保留本機待補送',state['state'])
                self.feature_status['center_link']=state
        self.upload_if_due(stop)
        return next_heartbeat

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
        # Separate lanes: a stuck upload must not stretch the heartbeat beyond
        # its normal 30 second cadence, and neither lane restarts the Agent.
        from .transport_errors import Backoff
        heartbeat_gate=Backoff(5,30)
        session_account = current_account().casefold()
        try:
            while not stop.is_set():
                if self.idle_revision:
                    quiet=self.cached_policy()
                    self.native_handoff.step(quiet)
                    if self.monitor:self.monitor.close();self.monitor=None
                    if self._snapshot:self._snapshot.close();self._snapshot=None
                    if self.proxy:self.proxy.close();self.proxy=None
                    self.security=None
                    if not self.config.get('machine_session') and os.name=='nt' and time.monotonic()>=self.next_controls:
                        from .windows_controls import WindowsControls
                        controls=WindowsControls(self)
                        if controls.installed:
                            from .policy import heartbeat_policy
                            neutral=decode_agent_policy(heartbeat_policy(self.idle_revision))['body']
                            try:self.feature_status['windows']=controls.apply(neutral)
                            except (OSError,ValueError):self.feature_status['windows']={'status':'restore_pending'}
                        self.next_controls=time.monotonic()+60
                    self.control_signature=None
                    next_heartbeat=self._link_step(stop,heartbeat_gate,next_heartbeat)
                    stop.wait(interval)
                    continue
                from .decommission import main_step,saved
                try:
                    if heartbeat_gate.ready() and main_step(self):return
                except (OSError,ConnectionError,ValueError):pass
                if saved(self):
                    self.feature_status['native_file_handoff']=self.native_handoff.step(self.cached_policy())
                    stop.wait(interval);continue
                try:
                    policy=self.cached_policy()
                    session_policy = policy.get('user_policies', {}).get(session_account, policy)
                    self.feature_status['native_file_handoff']=self.native_handoff.step(session_policy)
                    self.collect_native(policy)
                except (OSError,ValueError):LOG.exception('收集器執行失敗；本機 outbox 保留')
                if self.config.get('update_key') and time.monotonic()>=next_runtime_health:
                    from .update_client import save
                    save(self.config_path.parent/'runtime-health.json',{'version':__version__,'time':time.time(),'device_id':self.config['device_id']})
                    next_runtime_health=time.monotonic()+30
                next_heartbeat=self._link_step(stop,heartbeat_gate,next_heartbeat)
                stop.wait(min(interval,.25) if self._snapshot else interval)
        finally:self.close_collectors()

# Compatibility imports for the standard Agent API.
from .endpoint_transport import InventoryUpload, NoRedirect, transport, request, private_write, enroll
