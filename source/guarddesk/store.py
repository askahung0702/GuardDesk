import hashlib
import hmac
import json
import secrets
import sqlite3
import time
import threading
from contextlib import contextmanager
from pathlib import Path
from .policy import normalize_policy






def event_hash_valid(row):
    """SQLite REAL can return an original integer timestamp as a float.

    Accept only identical numeric values in either historical serialization;
    never rewrite original audit hashes or event content.
    """
    record={k:row[k] for k in ('event_id','device_id','kind','severity','occurred','received')}
    record['details']=json.loads(row['details']) if isinstance(row['details'],str) else row['details']
    occurred=[record['occurred']];received=[record['received']]
    for values in (occurred,received):
        if isinstance(values[0],float) and values[0].is_integer():values.append(int(values[0]))
    return any(row['hash']==digest(row['prev_hash']+canonical({**record,'occurred':a,'received':b})) for a in occurred for b in received)


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + ":" + hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def password_matches(password, encoded):
    return hmac.compare_digest(password_hash(password, encoded.split(":")[0]), encoded)


def validate_password(password):
    # User-selected policy: no minimum length or character composition rules.
    # The upper bound limits input/resource use; preserve the exact password.
    if not isinstance(password, str) or not password.strip():
        raise ValueError('密碼不可空白')
    if len(password) > 1024:
        raise ValueError('密碼輸入過長（上限 1024 字）')
    return password


class IngestActivity:
    """Process-local priority hint; durable index coverage lives in SQLite."""
    def __init__(self):
        self.wakeup=threading.Event();self.active=threading.Event()
        self.lock=threading.Lock();self.count=0


class ReaderActivity:
    def __init__(self):
        self.lock=threading.Lock();self.sequence=0;self.live=set();self.cutoffs={}

    @contextmanager
    def lease(self):
        with self.lock:
            self.sequence+=1;token=self.sequence;self.live.add(token)
        try:yield
        finally:
            with self.lock:self.live.discard(token)

    def awaiting_old_readers(self,job):
        with self.lock:
            cutoff=self.cutoffs.setdefault(job,self.sequence)
            return any(token<=cutoff for token in self.live)


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self._storage_lock=threading.Lock()
        self.lifecycle_lock=threading.RLock()
        self.readers=ReaderActivity()
        self._ingest=IngestActivity()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            schema='''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL, csrf TEXT NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS enrollments (token TEXT PRIMARY KEY, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS deployment_codes(id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, created REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, uses INTEGER NOT NULL DEFAULT 0);
            CREATE UNIQUE INDEX IF NOT EXISTS deployment_one_active ON deployment_codes(revoked) WHERE revoked=0;
            CREATE TABLE IF NOT EXISTS update_releases(id TEXT PRIMARY KEY,version TEXT NOT NULL,envelope TEXT NOT NULL,created REAL NOT NULL,actor TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS update_release_scope(release_id TEXT PRIMARY KEY,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS update_job_preparations(job_id TEXT PRIMARY KEY REFERENCES update_jobs(id),body TEXT NOT NULL,received REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS update_jobs(id TEXT PRIMARY KEY,device_id TEXT NOT NULL REFERENCES devices(id),release_id TEXT NOT NULL REFERENCES update_releases(id),actor TEXT NOT NULL,created REAL NOT NULL,not_before REAL NOT NULL,expires REAL NOT NULL,allow_downgrade INTEGER NOT NULL,status TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS update_jobs_device ON update_jobs(device_id,created);
            CREATE INDEX IF NOT EXISTS update_jobs_created ON update_jobs(created DESC,id DESC);
            CREATE INDEX IF NOT EXISTS update_jobs_status_created ON update_jobs(status,created DESC,id DESC);
            CREATE INDEX IF NOT EXISTS update_jobs_release_created ON update_jobs(release_id,created DESC,id DESC);
            CREATE TABLE IF NOT EXISTS update_status(job_id TEXT NOT NULL REFERENCES update_jobs(id),role TEXT NOT NULL,state TEXT NOT NULL,version TEXT NOT NULL,error TEXT NOT NULL,received REAL NOT NULL,PRIMARY KEY(job_id,role));
            CREATE TABLE IF NOT EXISTS update_presence(device_id TEXT NOT NULL REFERENCES devices(id),role TEXT NOT NULL,version TEXT NOT NULL,received REAL NOT NULL,broker_version TEXT NOT NULL DEFAULT '',PRIMARY KEY(device_id,role));
            CREATE TABLE IF NOT EXISTS update_diagnostics(device_id TEXT NOT NULL REFERENCES devices(id),role TEXT NOT NULL,code TEXT NOT NULL,version TEXT NOT NULL,received REAL NOT NULL,PRIMARY KEY(device_id,role));
            CREATE TABLE IF NOT EXISTS updater_refresh(device_id TEXT PRIMARY KEY REFERENCES devices(id),id TEXT NOT NULL,job_id TEXT NOT NULL,version TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
                department TEXT NOT NULL, last_seen REAL NOT NULL, policy_version INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0, inventory TEXT NOT NULL DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS policies (version INTEGER PRIMARY KEY, body TEXT NOT NULL, created REAL NOT NULL, actor TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
                device_id TEXT NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL, occurred REAL NOT NULL,
                received REAL NOT NULL, details TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_device ON events(device_id, id);
            CREATE INDEX IF NOT EXISTS events_kind ON events(kind, id);
            CREATE INDEX IF NOT EXISTS events_severity_received ON events(severity,received);
            CREATE INDEX IF NOT EXISTS events_occurred ON events(occurred,id);
            CREATE INDEX IF NOT EXISTS events_received ON events(received,id);
            CREATE TABLE IF NOT EXISTS audit_rollup_meta(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
            INSERT OR IGNORE INTO audit_rollup_meta VALUES ('cursor',0);
            CREATE TABLE IF NOT EXISTS audit_daily(day TEXT NOT NULL,device_id TEXT NOT NULL,person TEXT NOT NULL,label TEXT NOT NULL,action TEXT NOT NULL,severity TEXT NOT NULL,n INTEGER NOT NULL,last_occurred REAL NOT NULL,PRIMARY KEY(day,device_id,person,action,severity));
            CREATE INDEX IF NOT EXISTS audit_daily_person ON audit_daily(person,day);
            CREATE TABLE IF NOT EXISTS audit_file_index(event_row INTEGER PRIMARY KEY,person TEXT NOT NULL,action TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS audit_file_person ON audit_file_index(person,event_row);
            CREATE TABLE IF NOT EXISTS audit_exports(id TEXT PRIMARY KEY,actor TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,state TEXT NOT NULL,parameters TEXT NOT NULL,snapshot_id INTEGER NOT NULL,snapshot_head TEXT NOT NULL,rows INTEGER NOT NULL DEFAULT 0,bytes INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',zip_sha256 TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS native_usb_status(device_id TEXT PRIMARY KEY REFERENCES devices(id),body TEXT NOT NULL,received REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS extended_status(device_id TEXT PRIMARY KEY REFERENCES devices(id),body TEXT NOT NULL,received REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS endpoint_removals(id TEXT PRIMARY KEY,device_id TEXT NOT NULL REFERENCES devices(id),actor TEXT NOT NULL,reason TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,status TEXT NOT NULL,main TEXT NOT NULL,native TEXT NOT NULL,error TEXT NOT NULL DEFAULT '');
            CREATE INDEX IF NOT EXISTS removal_device ON endpoint_removals(device_id,created);
            CREATE TABLE IF NOT EXISTS endpoint_file_removals(job_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,phase TEXT NOT NULL DEFAULT 'queued',token_hash TEXT NOT NULL DEFAULT '',updated REAL NOT NULL,report_until REAL NOT NULL DEFAULT 0,error_code TEXT NOT NULL DEFAULT '',winerror INTEGER,helper_cleanup TEXT NOT NULL DEFAULT 'not_scheduled');
            CREATE INDEX IF NOT EXISTS file_removal_device ON endpoint_file_removals(device_id);
            CREATE TABLE IF NOT EXISTS remote_grants(username TEXT NOT NULL REFERENCES users(username),device_id TEXT NOT NULL REFERENCES devices(id),can_control INTEGER NOT NULL,expires REAL NOT NULL,PRIMARY KEY(username,device_id));
            CREATE TABLE IF NOT EXISTS remote_all_grants(username TEXT PRIMARY KEY REFERENCES users(username),can_control INTEGER NOT NULL,expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS remote_presence(device_id TEXT PRIMARY KEY,account TEXT NOT NULL,ready INTEGER NOT NULL,received REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS remote_readiness(device_id TEXT PRIMARY KEY,reason TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS remote_capabilities(device_id TEXT PRIMARY KEY,protocol INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS remote_admin_grants(username TEXT NOT NULL,device_id TEXT NOT NULL,enabled INTEGER NOT NULL,PRIMARY KEY(username,device_id));
            CREATE TABLE IF NOT EXISTS remote_admin_sessions(session_id TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS remote_sessions(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,operator TEXT NOT NULL,login_token TEXT NOT NULL,status TEXT NOT NULL,mode TEXT NOT NULL,reason TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,viewer_seen REAL NOT NULL,agent_seen REAL NOT NULL,ended_reason TEXT NOT NULL DEFAULT '');
            '''
            from .event_storage import enabled
            if enabled(db):schema=schema.replace('CREATE TABLE IF NOT EXISTS events (','CREATE TABLE IF NOT EXISTS events_legacy (').replace(' ON events(',' ON events_legacy(')
            db.executescript(schema)
            from .software import SCHEMA as software_schema
            db.executescript(software_schema)
            from .policy_defaults import server_policy
            db.execute("INSERT OR IGNORE INTO policies VALUES (1,?,?,?)", (canonical(server_policy()), time.time(), "system"))
            db.executescript('''
            CREATE TABLE IF NOT EXISTS endpoint_groups(id TEXT PRIMARY KEY,name TEXT NOT NULL,parent_id TEXT REFERENCES endpoint_groups(id),revision INTEGER NOT NULL,created REAL NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS group_sibling_name ON endpoint_groups(COALESCE(parent_id,''),name COLLATE NOCASE);
            CREATE TABLE IF NOT EXISTS policy_sets(id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT NOT NULL,revision INTEGER NOT NULL,enabled INTEGER NOT NULL,archived INTEGER NOT NULL DEFAULT 0,overrides TEXT NOT NULL,created REAL NOT NULL,actor TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS policy_set_name ON policy_sets(name COLLATE NOCASE) WHERE archived=0;
            CREATE TABLE IF NOT EXISTS policy_set_versions(set_id TEXT NOT NULL REFERENCES policy_sets(id),revision INTEGER NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,enabled INTEGER NOT NULL,overrides TEXT NOT NULL,created REAL NOT NULL,actor TEXT NOT NULL,PRIMARY KEY(set_id,revision));
            CREATE TABLE IF NOT EXISTS policy_assignments(id TEXT PRIMARY KEY,set_id TEXT NOT NULL REFERENCES policy_sets(id),target_type TEXT NOT NULL,target_id TEXT NOT NULL,priority INTEGER NOT NULL,enabled INTEGER NOT NULL,revision INTEGER NOT NULL,created REAL NOT NULL,actor TEXT NOT NULL,UNIQUE(set_id,target_type,target_id));
            CREATE TABLE IF NOT EXISTS control_meta(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
            INSERT OR IGNORE INTO control_meta SELECT 'generation',MAX(version) FROM policies;
            ''')
            for table in ('policy_sets', 'policy_set_versions'):
                if 'operations' not in {r[1] for r in db.execute('PRAGMA table_info('+table+')')}:
                    db.execute("ALTER TABLE "+table+" ADD COLUMN operations TEXT NOT NULL DEFAULT '[]'")
            from .event_storage import install_schema
            install_schema(db)
            from .audit_search_index import install as install_search
            install_search(db)
            from .custom_settings import install as install_custom
            install_custom(db)
            from .custom_library import install as install_custom_library
            install_custom_library(db)
            from .category_library import install as install_categories
            install_categories(db)
            from .mail_reports import install as install_mail_reports
            install_mail_reports(db)
            from .endpoint_purge import install as install_purge
            install_purge(db)
            columns={r[1] for r in db.execute('PRAGMA table_info(devices)')}
            if 'zip_sha256' not in {r[1] for r in db.execute('PRAGMA table_info(audit_exports)')}:db.execute("ALTER TABLE audit_exports ADD COLUMN zip_sha256 TEXT NOT NULL DEFAULT ''")
            for name,definition in [('group_id','TEXT REFERENCES endpoint_groups(id)'),('management_revision','INTEGER NOT NULL DEFAULT 1'),('policy_fingerprint',"TEXT NOT NULL DEFAULT ''"),('last_address',"TEXT NOT NULL DEFAULT ''"),('enrolled_at','REAL NOT NULL DEFAULT 0')]:
                if name not in columns:db.execute('ALTER TABLE devices ADD COLUMN '+name+' '+definition)
            # Serialize the once-only default merge with other initializers.
            # Keep the schema installation independent of policy publication.
            db.commit();db.execute('BEGIN IMMEDIATE')
            from .policy_defaults import migrate
            migrate(db)

    @contextmanager
    def connect(self, *, event_ingest=False, flush_events=True):
        # Admission is marked BEFORE opening SQLite / waiting for its writer.
        # The indexer yields to queued uploads as well as the current writer.
        if event_ingest:
            with self._ingest.lock:
                self._ingest.count+=1;self.ingest_active.set()
        try:
            with self._connect(flush_events=flush_events) as db:yield db
        finally:
            if event_ingest:
                with self._ingest.lock:
                    self._ingest.count-=1
                    if not self._ingest.count:self.ingest_active.clear()
                self.index_wakeup.set()

    @property
    def ingest_active(self):return self._ingest.active

    @property
    def index_wakeup(self):return self._ingest.wakeup

    def share_ingestion(self,other):
        # Console and HTTPS listeners own separate Store/DayWriter objects.
        # Share ONLY this priority hint when their database is the same.
        if self.path.resolve()!=other.path.resolve():raise ValueError('收件協調必須使用同一資料庫')
        self._ingest=other._ingest
        self.lifecycle_lock=other.lifecycle_lock
        self._storage_lock=other._storage_lock
        self.readers=other.readers

    @contextmanager
    def _connect(self, *, flush_events=True):
        with self.readers.lease():
            with self._open(flush_events=flush_events) as db:yield db

    @contextmanager
    def _open(self, *, flush_events=True):
        from .event_storage import EventConnection,Reader,flush,decode_id
        db = sqlite3.connect(self.path, timeout=15, factory=EventConnection)
        db.row_factory = sqlite3.Row;db.guarddesk_store=self
        reader=Reader(db,self.path);db.create_function('event_value',2,reader.value);db.create_function('event_identifier',1,decode_id,deterministic=True)
        committed=False
        try:
            db.execute("PRAGMA foreign_keys=ON")
            yield db
            db.commit();committed=True
        except BaseException:
            db.rollback()
            raise
        finally:
            reader.close();db.close()
            if committed and flush_events:flush(self)

    def add_user(self, username, password, role="admin"):
        validate_password(password)
        if not username.strip() or len(username) > 80 or role not in ("admin", "auditor", "support"):
            raise ValueError("帳號不可空白；角色為 admin、auditor 或 support")
        with self.connect() as db:
            db.execute("INSERT INTO users VALUES (?,?,?)", (username, password_hash(password), role))

    @staticmethod
    def policy(db):
        row = db.execute("SELECT * FROM policies ORDER BY version DESC LIMIT 1").fetchone()
        return {"version": row["version"], "body": normalize_policy(json.loads(row["body"])), "created": row["created"], "actor": row["actor"]}

    @staticmethod
    def event(db, device_id, kind, severity, details, event_id=None, occurred=None):
        if db.execute('SELECT 1 FROM endpoint_purges WHERE device_id=?',(device_id,)).fetchone():
            raise ValueError('此端點已要求永久刪除，拒絕新增資料')
        event_id = event_id or secrets.token_hex(16)
        from .event_storage import enabled,append
        if getattr(db,'guarddesk_store',None) is not None and enabled(db):
            return append(db,device_id,kind,severity,details,event_id,occurred)
        previous = db.execute("SELECT device_id FROM events WHERE event_id=?", (event_id,)).fetchone()
        if previous:
            if previous["device_id"] != device_id:
                raise ValueError("事件識別碼衝突")
            return
        from .event_storage import head
        previous_hash = head(db)[1]
        received = time.time()
        record = {"event_id": event_id, "device_id": device_id, "kind": kind, "severity": severity,
                  "occurred": occurred if occurred is not None else received, "received": received, "details": details}
        row_hash = digest(previous_hash + canonical(record))
        db.execute("INSERT INTO events(event_id,device_id,kind,severity,occurred,received,details,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?)",
                   (event_id, device_id, kind, severity, record["occurred"], received, canonical(details), previous_hash, row_hash))

    def verify(self):
        try:return self._verify_events()
        except (sqlite3.Error,ValueError,OSError):return {'valid':False,'checked':0,'error':'事件日檔缺失、封裝損壞或儲存無法讀取；請檢查日誌與還原備份'}

    def _verify_events(self):
        with self.connect() as db:
            previous = "0" * 64
            count = 0
            deleted=0
            for row in db.execute("SELECT id,prev_hash,hash,0 erased FROM events UNION ALL SELECT id,prev_hash,hash,1 FROM event_deletions ORDER BY id"):
                if row['erased']:
                    if row['prev_hash']!=previous:return {'valid':False,'checked':count,'broken_at':row['id']}
                    previous=row['hash'];deleted+=1;continue
                row=db.execute('SELECT * FROM events WHERE id=?',(row['id'],)).fetchone()
                record = {k: row[k] for k in ("event_id", "device_id", "kind", "severity", "occurred", "received")}
                record["details"] = json.loads(row["details"])
                if row["prev_hash"] != previous or not event_hash_valid(row):
                    return {"valid": False, "checked": count, "broken_at": row["id"]}
                previous = row["hash"]
                count += 1
            return {"valid": True, "checked": count, "head": previous,'authorized_deleted':deleted,
                    'scope':'remaining_event_hashes_and_chain_links_with_authorized_deletions' if deleted else 'complete_chain'}

from .serialization import canonical, digest
