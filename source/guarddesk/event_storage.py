"""Opt-in daily payloads with a transactional catalog and durable staging.

The control database commits the complete compressed event before acknowledgement.
Day files are replayable copies; catalog finalization happens only after their
commit. All readers use the same events view, including legacy rows and staging.
"""
import collections
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import time
import zlib

MAX_EVENT=2*1024*1024
MAX_PENDING=64*1024*1024
DAY=re.compile(r'\d{8}\Z')
FIELDS=('event_id','device_id','kind','severity','occurred','received')
ROW_DICTIONARY=b'{"event_id":"","device_id":"","kind":"","severity":"info","occurred":,"received":,"details":"","prev_hash":"","hash":"","id":,source_path,destination_path,process,process_id,parent_process_id,user,source,title,url,path,file.created,file.deleted,file.moved,file.opened,application.started,application.stopped,web.navigation,C:\\Users\\,C:\\Windows\\,browser_history'
SEVERITIES=('info','warning','critical')
FAMILY_SQL="CASE WHEN kind>='web.upload_' AND kind<'web.upload`' THEN 'uploads' ELSE substr(kind,1,instr(kind,'.')-1) END"
HEADER_FIELDS='id,event_id,device_id,kind,severity,occurred,received,hash'


def family(kind):return 'uploads' if kind.startswith('web.upload_') else kind.split('.')[0]


def head(db):
    """Two primary-key seeks, never MAX over the payload UNION view."""
    erased=db.execute('SELECT id,hash FROM event_deletions ORDER BY id DESC LIMIT 1').fetchone() if db.execute("SELECT 1 FROM sqlite_master WHERE name='event_deletions'").fetchone() else None
    if not enabled(db):
        row=db.execute('SELECT id,hash FROM events ORDER BY id DESC LIMIT 1').fetchone()
        return max([tuple(r) for r in (row,erased) if r],default=(0,'0'*64),key=lambda r:r[0])
    old=db.execute('SELECT id,hash FROM events_legacy ORDER BY id DESC LIMIT 1').fetchone()
    new=db.execute('SELECT id,lower(hex(hash)) FROM event_catalog ORDER BY id DESC LIMIT 1').fetchone()
    return max([tuple(r) for r in (old,new,erased) if r],default=(0,'0'*64),key=lambda r:r[0])


def overview_stats(db,now):
    active=enabled(db);legacy='events_legacy' if active else 'events'
    result={'events':db.execute('SELECT count(*) FROM '+legacy).fetchone()[0],
            'alerts_today':db.execute("SELECT count(*) FROM "+legacy+" WHERE severity IN ('warning','critical') AND received>?",(now-86400,)).fetchone()[0],
            'blocked':db.execute("SELECT count(*) FROM "+legacy+" WHERE kind='export.blocked'").fetchone()[0]}
    if active:
        result['events']+=db.execute('SELECT COALESCE(sum(rows),0) FROM event_storage_daily').fetchone()[0]
        result['alerts_today']+=db.execute('SELECT count(*) FROM event_catalog WHERE severity IN (1,2) AND received>?',(now-86400,)).fetchone()[0]
        result['blocked']+=db.execute("SELECT count(*) FROM event_catalog WHERE kind=(SELECT id FROM event_terms WHERE category='kind' AND value='export.blocked')").fetchone()[0]
    return result


def install_headers(db):
    """Covering metadata paths isolate lists/statistics from event payloads."""
    legacy='events_legacy' if enabled(db) else 'events'
    expression='CAST(('+FAMILY_SQL+') AS TEXT)'
    for name,columns in (('audit_family_id',expression+',id'),('audit_family_device_id',expression+',device_id,id')):
        definition='CREATE INDEX '+name+' ON '+legacy+'('+columns+')'
        old=db.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name=?",(name,)).fetchone()
        if not old or old[0].replace('"'+legacy+'"',legacy)!=definition:
            if old:db.execute('DROP INDEX '+name)
            db.execute(definition)
    sql='SELECT '+HEADER_FIELDS+','+expression+' AS family FROM '+legacy
    if enabled(db):
        sql+=''' UNION ALL SELECT c.id,CAST(event_identifier(c.event_id) AS TEXT),d.value,k.value,
          CAST(CASE c.severity WHEN 0 THEN 'info' WHEN 1 THEN 'warning' ELSE 'critical' END AS TEXT),
          c.occurred,c.received,CAST(lower(hex(c.hash)) AS TEXT),c.family
          FROM event_catalog c JOIN event_terms d ON d.id=c.device_id JOIN event_terms k ON k.id=c.kind'''
    definition='CREATE VIEW event_headers AS '+sql
    old=db.execute("SELECT sql FROM sqlite_master WHERE name='event_headers' AND type='view'").fetchone()
    if not old or old[0]!=definition:
        db.execute('DROP VIEW IF EXISTS event_headers')
        db.execute(definition)
    # Narrow date searches must seek by occurred time before sorting metadata.
    # Otherwise ORDER BY id can walk a million same-device historical headers
    # even though none are in today's range. This view contains no payloads.
    timed_sql='SELECT '+HEADER_FIELDS+','+expression+' AS family FROM '+legacy+' INDEXED BY events_occurred'
    if enabled(db):
        timed_sql+=''' UNION ALL SELECT c.id,CAST(event_identifier(c.event_id) AS TEXT),d.value,k.value,
          CAST(CASE c.severity WHEN 0 THEN 'info' WHEN 1 THEN 'warning' ELSE 'critical' END AS TEXT),
          c.occurred,c.received,CAST(lower(hex(c.hash)) AS TEXT),c.family
          FROM event_catalog c INDEXED BY event_catalog_occurred JOIN event_terms d ON d.id=c.device_id JOIN event_terms k ON k.id=c.kind'''
    definition='CREATE VIEW event_headers_time AS '+timed_sql
    old=db.execute("SELECT sql FROM sqlite_master WHERE name='event_headers_time' AND type='view'").fetchone()
    if not old or old[0]!=definition:
        db.execute('DROP VIEW IF EXISTS event_headers_time');db.execute(definition)

def encode_id(value):
    return b'0'+bytes.fromhex(value) if re.fullmatch('[0-9a-f]{32}',value) else b'1'+value.encode('utf-8')

def decode_id(value):
    if not isinstance(value,bytes) or not value:raise ValueError('事件識別索引損壞')
    if value[:1]==b'0':return value[1:].hex()
    if value[:1]==b'1':return value[1:].decode('utf-8')
    raise ValueError('事件識別索引格式不正確')


class EventConnection(sqlite3.Connection):
    pass


def ordinary(path):
    path=Path(os.path.abspath(path))
    for item in (path,*path.parents):
        if os.path.lexists(item) and (item.is_symlink() or getattr(item.lstat(),'st_file_attributes',0)&0x400):
            raise ValueError('事件儲存路徑不可經過 junction／符號連結')
    return path


def private_folder(path):
    path=ordinary(path)
    if not path.exists():
        from .server_setup import secure_directory
        try:secure_directory(path)
        except FileExistsError:pass
    if not path.is_dir():raise ValueError('事件儲存目錄不是一般資料夾')
    return path


def storage_root(control):
    control=Path(control)
    return control.parent/('AuditData' if control.name=='control.sqlite3' else control.name+'.AuditData')


def day_file(control,day,create=False):
    if not isinstance(day,str) or not DAY.fullmatch(day):raise ValueError('事件日期索引不正確')
    dt.datetime.strptime(day,'%Y%m%d')
    folder=storage_root(control)
    for part in (None,day[:6],day):
        if part:folder=folder/part
        if create:private_folder(folder)
        else:ordinary(folder)
    return ordinary(folder/'events.sqlite3')


def install_schema(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS server_options(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS event_terms(id INTEGER PRIMARY KEY,category TEXT NOT NULL,value TEXT NOT NULL,UNIQUE(category,value));
    CREATE TABLE IF NOT EXISTS event_catalog(id INTEGER PRIMARY KEY,event_id BLOB UNIQUE NOT NULL,
      device_id INTEGER NOT NULL REFERENCES event_terms(id),kind INTEGER NOT NULL REFERENCES event_terms(id),severity INTEGER NOT NULL,occurred REAL NOT NULL,
      received REAL NOT NULL,day TEXT NOT NULL,hash BLOB NOT NULL,stored INTEGER NOT NULL DEFAULT 0,payload_bytes INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS event_terms_value ON event_terms(value,id);
    CREATE INDEX IF NOT EXISTS event_catalog_device ON event_catalog(device_id,id);
    CREATE INDEX IF NOT EXISTS event_catalog_kind ON event_catalog(kind,id);
    CREATE INDEX IF NOT EXISTS event_catalog_occurred ON event_catalog(occurred,id);
    CREATE INDEX IF NOT EXISTS event_catalog_received ON event_catalog(received,id);
    CREATE INDEX IF NOT EXISTS event_catalog_severity ON event_catalog(severity,received);
    CREATE INDEX IF NOT EXISTS event_catalog_day ON event_catalog(day,id);
    CREATE TABLE IF NOT EXISTS event_pending(id INTEGER PRIMARY KEY REFERENCES event_catalog(id),payload BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS event_storage_daily(day TEXT PRIMARY KEY,rows INTEGER NOT NULL,payload_bytes INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS event_storage_sources(day TEXT NOT NULL,device_id INTEGER NOT NULL,kind INTEGER NOT NULL,rows INTEGER NOT NULL,payload_bytes INTEGER NOT NULL,PRIMARY KEY(day,device_id,kind));
    ''')
    if 'payload_bytes' not in {r[1] for r in db.execute('PRAGMA table_info(event_catalog)')}:db.execute('ALTER TABLE event_catalog ADD COLUMN payload_bytes INTEGER NOT NULL DEFAULT 0')
    if 'family' not in {r[1] for r in db.execute('PRAGMA table_info(event_catalog)')}:
        db.execute("ALTER TABLE event_catalog ADD COLUMN family TEXT NOT NULL DEFAULT ''")
    # Also recover a crash after ALTER but before the backfill commit.
    db.execute("UPDATE event_catalog SET family=(SELECT "+FAMILY_SQL.replace('kind','value')+" FROM event_terms WHERE id=event_catalog.kind) WHERE family='' AND kind IN (SELECT id FROM event_terms WHERE category='kind' AND instr(value,'.')>0)")
    db.execute('CREATE INDEX IF NOT EXISTS event_catalog_family_id ON event_catalog(family,id)')
    db.execute('CREATE INDEX IF NOT EXISTS event_catalog_family_device_id ON event_catalog(family,device_id,id)')
    install_headers(db)


def enabled(db):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='server_options'").fetchone():return False
    row=db.execute("SELECT value FROM server_options WHERE key='event_storage'").fetchone()
    return bool(row and row[0]=='daily-v1')


def pack(row):
    from .serialization import canonical
    raw=canonical(row).encode('utf-8')
    if len(raw)>MAX_EVENT:raise ValueError('事件超過分日儲存上限')
    # Metadata/hash are already durable in the same catalog transaction.
    # Keep the original details and chain link without storing a second copy
    # of all random IDs, timestamps and hashes in every compressed payload.
    compressor=zlib.compressobj(1,zdict=ROW_DICTIONARY)
    return b'GDE2'+bytes.fromhex(row['prev_hash'])+compressor.compress(row['details'].encode('utf-8'))+compressor.flush()


def unpack(payload):
    if len(payload)>MAX_EVENT:raise ValueError('事件封裝過大')
    compact=payload.startswith(b'GDE2')
    if compact and len(payload)<37:raise ValueError('事件封裝損壞')
    dictionary=compact or payload.startswith(b'GDE1')
    decoder=zlib.decompressobj(zdict=ROW_DICTIONARY) if dictionary else zlib.decompressobj()
    raw=decoder.decompress(payload[36:] if compact else payload[4:] if dictionary else payload,MAX_EVENT+1)
    if len(raw)>MAX_EVENT or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError('事件封裝損壞或超過上限')
    value=json.loads(raw)
    if not isinstance(value,dict):raise ValueError('事件封裝結構不正確')
    if compact:return {'details':raw.decode('utf-8'),'prev_hash':payload[4:36].hex(),'_catalog':True}
    return value


class Reader:
    def __init__(self,db,path):
        self.db,self.path=db,Path(path)
        self.handles=collections.OrderedDict();self.rows=collections.OrderedDict();self.bytes=0

    def value(self,identifier,field):
        if type(identifier) is not int or field not in ('details','prev_hash'):raise ValueError('事件欄位不正確')
        if identifier in self.rows:
            row,size=self.rows.pop(identifier);self.rows[identifier]=(row,size)
            return row[field]
        meta=self.db.execute('SELECT c.*,d.value AS device_name,k.value AS kind_name FROM event_catalog c JOIN event_terms d ON d.id=c.device_id JOIN event_terms k ON k.id=c.kind WHERE c.id=?',(identifier,)).fetchone()
        if meta:
            meta=dict(meta);meta.update(event_id=decode_id(meta['event_id']),device_id=meta['device_name'],kind=meta['kind_name'],severity=SEVERITIES[meta['severity']],hash=meta['hash'].hex())
        if not meta:raise ValueError('事件索引遺失')
        pending=self.db.execute('SELECT payload FROM event_pending WHERE id=?',(identifier,)).fetchone() if not meta['stored'] else None
        if pending:payload=pending[0]
        else:
            day=meta['day']
            if day not in self.handles:
                path=day_file(self.path,day)
                if not path.is_file():raise ValueError('事件日檔缺失，請還原對應備份')
                con=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2)
                con.execute('PRAGMA query_only=ON');self.handles[day]=con
                if len(self.handles)>2:self.handles.popitem(last=False)[1].close()
            con=self.handles.pop(day);self.handles[day]=con
            record=con.execute('SELECT payload FROM events WHERE id=?',(identifier,)).fetchone()
            if not record:raise ValueError('事件日檔不完整')
            payload=record[0]
        row=unpack(payload)
        if row.pop('_catalog',False):row={**{k:meta[k] for k in (*FIELDS,'hash')},'id':identifier,**row}
        from .store import event_hash_valid
        if row.get('id')!=identifier or any(row.get(k)!=meta[k] for k in (*FIELDS,'hash')) or not event_hash_valid(row):
            raise ValueError('事件封裝與索引或雜湊不符')
        size=len(row.get('details',''))+len(payload)+512
        while self.rows and (len(self.rows)>=64 or self.bytes+size>4*1024*1024):
            _,(_,old)=self.rows.popitem(last=False);self.bytes-=old
        self.rows[identifier]=(row,size);self.bytes+=size
        return row[field]

    def close(self):
        for con in self.handles.values():con.close()
        self.handles.clear();self.rows.clear()


def enable(db,control,snapshot_backup=True):
    from .endpoint_purge import active
    if active(db):raise ValueError('端點資料清除中，完成後再切換儲存模式')
    if enabled(db):return {'enabled':True,'already_enabled':True}
    if db.in_transaction:raise ValueError('目前有資料異動，請稍後重新啟用分日儲存')
    # Hold the writer reservation before a second, read-only connection takes
    # the pre-migration backup. WAL readers remain allowed; no own uncommitted
    # changes exist at this point.
    db.execute('BEGIN IMMEDIATE')
    required=db.execute('PRAGMA page_count').fetchone()[0]*db.execute('PRAGMA page_size').fetchone()[0]+512*1024*1024
    if shutil.disk_usage(Path(control).parent).free<required:raise ValueError('快照空間不足，原資料保留')
    folder=private_folder(Path(control).parent/'StorageBackups')
    backup=ordinary(folder/('before-daily-'+secrets.token_hex(8)+'.sqlite3'))
    if snapshot_backup:
        with backup.open('xb'):pass
        source=sqlite3.connect(Path(control).resolve().as_uri()+'?mode=ro',uri=True,timeout=5)
        target=sqlite3.connect(backup)
        try:source.backup(target,pages=256,sleep=.01)
        finally:source.close();target.close()
    db.execute('ALTER TABLE events RENAME TO events_legacy')
    # Explicit matching affinities allow SQLite MERGE/ID seeks; otherwise the
    # UNION coroutine expands every compressed payload before LIMIT.
    db.execute('''CREATE VIEW events AS SELECT * FROM events_legacy UNION ALL
      SELECT c.id,CAST(event_identifier(c.event_id) AS TEXT) AS event_id,d.value AS device_id,k.value AS kind,
        CAST(CASE c.severity WHEN 0 THEN 'info' WHEN 1 THEN 'warning' WHEN 2 THEN 'critical' END AS TEXT) AS severity,c.occurred,c.received,
        CAST(event_value(c.id,'details') AS TEXT) AS details,CAST(event_value(c.id,'prev_hash') AS TEXT) AS prev_hash,CAST(lower(hex(c.hash)) AS TEXT) AS hash
      FROM event_catalog c JOIN event_terms d ON d.id=c.device_id JOIN event_terms k ON k.id=c.kind''')
    db.execute("INSERT OR REPLACE INTO server_options VALUES ('event_storage','daily-v1')")
    install_headers(db)
    return {'enabled':True,'backup':backup.name if snapshot_backup else '', 'legacy_preserved':True}


def append(db,device_id,kind,severity,details,event_id,occurred):
    from .serialization import canonical,digest
    old=db.execute('SELECT t.value FROM event_catalog c JOIN event_terms t ON t.id=c.device_id WHERE c.event_id=?',(encode_id(event_id),)).fetchone()
    if not old:old=db.execute('SELECT device_id FROM events_legacy WHERE event_id=?',(event_id,)).fetchone()
    if old:
        if old[0]!=device_id:raise ValueError('事件識別碼衝突')
        return
    # A single SQLite write transaction serializes ID allocation and chain head.
    db.execute("UPDATE server_options SET value=value WHERE key='event_storage'")
    last,previous=head(db);identifier=last+1
    received=time.time();day=dt.datetime.fromtimestamp(received,dt.timezone(dt.timedelta(hours=8))).strftime('%Y%m%d')
    logical={'event_id':event_id,'device_id':device_id,'kind':kind,'severity':severity,
             'occurred':occurred if occurred is not None else received,'received':received,'details':details}
    row={**logical,'id':identifier,'details':canonical(details),'prev_hash':previous,'hash':digest(previous+canonical(logical))}
    payload=pack(row)
    pending=db.execute('SELECT COALESCE(sum(length(payload)),0) FROM event_pending').fetchone()[0]
    if pending+len(payload)>MAX_PENDING:raise ValueError('事件日檔待寫佇列已滿，請檢查磁碟；端點需保留日誌重試')
    def term(category,value):
        db.execute('INSERT OR IGNORE INTO event_terms(category,value) VALUES (?,?)',(category,value))
        return db.execute('SELECT id FROM event_terms WHERE category=? AND value=?',(category,value)).fetchone()[0]
    device_key=term('device',device_id);kind_key=term('kind',kind)
    db.execute('INSERT INTO event_catalog(id,event_id,device_id,kind,severity,occurred,received,day,hash,payload_bytes,family) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
               (identifier,encode_id(event_id),device_key,kind_key,SEVERITIES.index(severity),row['occurred'],received,day,bytes.fromhex(row['hash']),len(payload),family(kind)))
    db.execute('INSERT INTO event_pending VALUES (?,?)',(identifier,payload))
    db.execute('INSERT INTO event_storage_daily VALUES (?,1,?) ON CONFLICT(day) DO UPDATE SET rows=rows+1,payload_bytes=payload_bytes+excluded.payload_bytes',(day,len(payload)))
    db.execute('INSERT INTO event_storage_sources VALUES (?,?,?,1,?) ON CONFLICT(day,device_id,kind) DO UPDATE SET rows=rows+1,payload_bytes=payload_bytes+excluded.payload_bytes',(day,device_key,kind_key,len(payload)))


def finalize(control, rows):
    with control:
        for row in rows:
            control.execute('UPDATE event_catalog SET stored=1 WHERE id=?',(row['id'],))
            control.execute('DELETE FROM event_pending WHERE id=?',(row['id'],))


class DayWriter:
    """At most two WAL writers, serialized by the Store flush lock."""
    def __init__(self):self.handles=collections.OrderedDict()
    def connection(self,control,day):
        if day in self.handles:
            con=self.handles.pop(day);self.handles[day]=con;return con
        path=day_file(control,day,create=True)
        for suffix in ('-wal','-shm'):ordinary(str(path)+suffix)
        con=sqlite3.connect(path,timeout=2,check_same_thread=False)
        try:
            con.execute('PRAGMA journal_mode=WAL');con.execute('PRAGMA synchronous=FULL')
            con.execute('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,payload BLOB NOT NULL)')
        except BaseException:con.close();raise
        self.handles[day]=con
        if len(self.handles)>2:self.handles.popitem(last=False)[1].close()
        return con
    def close(self):
        for con in self.handles.values():
            try:con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            except sqlite3.Error:pass
            finally:con.close()
        self.handles.clear()


def flush(store):
    if not store._storage_lock.acquire(blocking=False):return
    control=None
    try:
        control=sqlite3.connect(store.path,timeout=2);control.row_factory=sqlite3.Row
        if not enabled(control):return
        batch=[];size=0
        writer=getattr(store,'storage_writer',None)
        for row in control.execute('SELECT p.id,p.payload,c.day FROM event_pending p JOIN event_catalog c ON c.id=p.id ORDER BY p.id LIMIT ?',(2048 if writer else 128,)):
            batch.append(dict(row));size+=len(row['payload'])
            if size>=2*1024*1024:break
        groups=collections.defaultdict(list)
        for row in batch:groups[row['day']].append(row)
        for day,rows in groups.items():
            path=day_file(store.path,day,create=True) if not writer else None
            con=writer.connection(store.path,day) if writer else sqlite3.connect(path,timeout=2)
            try:
                con.execute('PRAGMA synchronous=FULL')
                con.execute('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,payload BLOB NOT NULL)')
                for row in rows:
                    old=con.execute('SELECT payload FROM events WHERE id=?',(row['id'],)).fetchone()
                    if old and old[0]!=row['payload']:raise ValueError('既有日檔事件不符，停止寫入並保留待寫資料')
                    con.execute('INSERT OR IGNORE INTO events VALUES (?,?)',(row['id'],row['payload']))
                con.commit()
            except BaseException:con.rollback();raise
            finally:
                if not writer:con.close()
            # The daily commit precedes catalog finalization. A crash between
            # them simply replays identical IDs/payloads on the next request.
            finalize(control, rows)
        if batch:
            with control:control.execute("DELETE FROM server_options WHERE key='event_storage_error'")
    except (OSError,ValueError,sqlite3.Error) as exc:
        # Full staged data remains committed. Backpressure prevents unbounded
        # growth; the management status exposes pending rows and this reason.
        if control:
            try:
                with control:control.execute("INSERT OR REPLACE INTO server_options VALUES ('event_storage_error',?)",(str(exc)[:250],))
            except sqlite3.Error:pass
    finally:
        if control:control.close()
        store._storage_lock.release()


def status(db,control):
    active=enabled(db)
    pending=db.execute('SELECT count(*),COALESCE(sum(length(payload)),0) FROM event_pending').fetchone()
    error=db.execute("SELECT value FROM server_options WHERE key='event_storage_error'").fetchone()
    days=[dict(row) for row in db.execute('SELECT day,rows,payload_bytes FROM event_storage_daily ORDER BY day DESC LIMIT 366')]
    pending_days={r[0]:r[1] for r in db.execute('SELECT c.day,count(*) FROM event_pending p JOIN event_catalog c ON c.id=p.id GROUP BY c.day')}
    for row in days:
        row['pending']=pending_days.get(row['day'],0)
        path=day_file(control,row['day']);row['bytes']=path.stat().st_size if path.is_file() else None
        wal=ordinary(str(path)+'-wal');row['wal_bytes']=wal.stat().st_size if wal.is_file() else 0
        row['state']='pending' if row['pending']==row['rows'] else 'online' if path.is_file() else 'missing'
    sources=[dict(row) for row in db.execute('SELECT c.day,t.value AS device_id,COALESCE(d.name,t.value) AS device_name,k.value AS kind,c.rows,c.payload_bytes FROM event_storage_sources c JOIN event_terms t ON t.id=c.device_id JOIN event_terms k ON k.id=c.kind LEFT JOIN devices d ON d.id=t.value WHERE c.day=(SELECT max(day) FROM event_storage_daily) ORDER BY c.rows DESC LIMIT 100')]
    categories={r['name']:r['type'] for r in db.execute("SELECT name,type FROM sqlite_master WHERE type IN ('table','index') AND (name LIKE 'event_%' OR name LIKE 'events%')")}
    backup_root=ordinary(Path(control).parent/'StorageBackups')
    backup_bytes=sum(p.stat().st_size for p in list(backup_root.glob('before-*.sqlite3'))[:1000] if ordinary(p).is_file()) if backup_root.is_dir() else 0
    legacy_table='events_legacy' if active else 'events'
    legacy_rows=db.execute('SELECT count(*) FROM '+legacy_table).fetchone()[0]
    return {'sources':sources,'mode':'daily-v1' if active else 'legacy','pending_rows':pending[0],'pending_bytes':pending[1],
            'error':error[0] if error else '', 'days':days,'legacy_preserved':True,
            'backup_bytes':backup_bytes,'legacy_rows':legacy_rows,'reusable_control_bytes':db.execute('PRAGMA freelist_count').fetchone()[0]*db.execute('PRAGMA page_size').fetchone()[0],
            'optimizer':'Optimize-Storage.cmd','control_event_objects':categories,'index_bytes':None,'index_note':'事件索引與統計包含在主資料庫大小；本 SQLite 未提供個別物件實體頁量測',
            'control_bytes':Path(control).stat().st_size,'wal_bytes':Path(str(control)+'-wal').stat().st_size if Path(str(control)+'-wal').exists() else 0}


def snapshot_days(source,target):
    """Copy only days referenced by the already-consistent control snapshot.

    Daily rows are append-only, so extra later rows in a day snapshot are not
    referenced by the frozen catalog. Pending rows are in the control snapshot.
    Never overwrite an existing destination day directory.
    """
    from contextlib import closing
    with closing(sqlite3.connect(Path(target).resolve().as_uri()+'?mode=ro',uri=True)) as control:
        if not enabled(control):return []
        days=[r[0] for r in control.execute('SELECT DISTINCT day FROM event_catalog WHERE stored=1 ORDER BY day')]
    if len(days)>36600:raise ValueError('分日備份超過支援的日期數')
    if os.path.lexists(storage_root(target)):raise ValueError('備份事件目錄已存在，保留原檔未覆寫')
    result=[]
    for day in days:
        original=day_file(source,day);destination=day_file(target,day,create=True)
        if not original.is_file():raise ValueError('來源事件日檔缺失，未完成備份')
        required=original.stat().st_size+64*1024*1024
        if shutil.disk_usage(destination.parent).free<required:raise ValueError('事件日檔備份空間不足，原資料保留')
        with destination.open('xb'):pass
        with closing(sqlite3.connect(original.as_uri()+'?mode=ro',uri=True,timeout=5)) as a,closing(sqlite3.connect(destination)) as b:
            a.backup(b,pages=128,sleep=.01)
            if b.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('事件日檔備份完整性檢查失敗')
        with destination.open('rb') as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
        result.append({'day':day,'sha256':sha,'bytes':destination.stat().st_size})
    return result
