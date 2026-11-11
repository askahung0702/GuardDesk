"""Offline, backed-up, resumable event migration. Never drops logical history."""
import datetime as dt
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import time
import threading
from contextlib import closing
from . import event_storage as storage


class DatabaseLease:
    """OS file lock shared by Server lifetime and the offline optimizer."""
    def __init__(self,path):
        self.stream=None
        self.users=1;self.lock=threading.Lock()
        path=storage.ordinary(str(storage.ordinary(path))+'.server-lock')
        path.parent.mkdir(parents=True,exist_ok=True)
        stream=path.open('a+b')
        try:
            if path.stat().st_size==0:stream.write(b'0');stream.flush()
            stream.seek(0)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except (OSError,PermissionError):
            stream.close();raise ValueError('管理中心或最佳化程序正在使用此資料庫；請先停止管理中心再執行最佳化') from None
        self.stream=stream

    def retain(self):
        with self.lock:self.users+=1
        return self

    def close(self):
        with self.lock:
            self.users-=1
            if self.users>0:return
        if self.stream:
            stream,self.stream=self.stream,None
            stream.seek(0)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(),fcntl.LOCK_UN)
            stream.close()

    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def migrate_batch(store,limit=2048):
    """Catalog + durable payload + legacy removal in one bounded transaction."""
    from .store import event_hash_valid
    from collections import Counter
    with store.connect() as db:
        if not storage.enabled(db):raise ValueError('請先啟用分日儲存')
        db.execute('BEGIN IMMEDIATE');batch=[];size=0
        for row in db.execute('SELECT * FROM events_legacy ORDER BY id LIMIT ?',(min(2048,max(1,limit)),)):
            row=dict(row)
            if not event_hash_valid(row):raise ValueError('歷史事件雜湊不符，停止搬移並保留備份及尚未搬移資料')
            payload=storage.pack(row);size+=len(payload)+len(row['details'].encode('utf-8'));batch.append((row,payload))
            if size>=2*1024*1024:break
        if not batch:return 0
        pending=db.execute('SELECT COALESCE(sum(length(payload)),0) FROM event_pending').fetchone()[0]
        if pending+sum(len(p) for _,p in batch)>storage.MAX_PENDING:raise ValueError('日檔待寫佇列已滿，停止搬移；可修復磁碟後重試')
        terms={};catalog=[];days=Counter();sources=Counter();day_counts=Counter();source_counts=Counter()
        def term(category,value):
            key=(category,value)
            if key not in terms:
                db.execute('INSERT OR IGNORE INTO event_terms(category,value) VALUES (?,?)',key)
                terms[key]=db.execute('SELECT id FROM event_terms WHERE category=? AND value=?',key).fetchone()[0]
            return terms[key]
        for row,payload in batch:
            device=term('device',row['device_id']);kind=term('kind',row['kind'])
            day=dt.datetime.fromtimestamp(row['received'],dt.timezone(dt.timedelta(hours=8))).strftime('%Y%m%d')
            catalog.append((row['id'],storage.encode_id(row['event_id']),device,kind,storage.SEVERITIES.index(row['severity']),row['occurred'],row['received'],day,bytes.fromhex(row['hash']),len(payload),storage.family(row['kind'])))
            days[day]+=len(payload);day_counts[day]+=1;sources[(day,device,kind)]+=len(payload);source_counts[(day,device,kind)]+=1
        # Unique constraints reject conflicting IDs without removing originals.
        db.executemany('INSERT INTO event_catalog(id,event_id,device_id,kind,severity,occurred,received,day,hash,payload_bytes,family) VALUES (?,?,?,?,?,?,?,?,?,?,?)',catalog)
        db.executemany('INSERT INTO event_pending VALUES (?,?)',[(r['id'],p) for r,p in batch])
        db.executemany('INSERT INTO event_storage_daily VALUES (?,?,?) ON CONFLICT(day) DO UPDATE SET rows=rows+excluded.rows,payload_bytes=payload_bytes+excluded.payload_bytes',[(day,day_counts[day],size) for day,size in days.items()])
        db.executemany('INSERT INTO event_storage_sources VALUES (?,?,?,?,?) ON CONFLICT(day,device_id,kind) DO UPDATE SET rows=rows+excluded.rows,payload_bytes=payload_bytes+excluded.payload_bytes',[(*key,source_counts[key],size) for key,size in sources.items()])
        db.executemany('DELETE FROM events_legacy WHERE id=?',[(r['id'],) for r,_ in batch])
    drain(store)
    return len(batch)


def drain(store):
    while True:
        # A plain read avoids triggering an implicit flush in Store.connect.
        db=sqlite3.connect(store.path)
        try:before=db.execute('SELECT count(*) FROM event_pending').fetchone()[0]
        finally:db.close()
        if not before:return
        storage.flush(store)
        db=sqlite3.connect(store.path)
        try:after=db.execute('SELECT count(*) FROM event_pending').fetchone()[0]
        finally:db.close()
        if after>=before:raise ValueError('日檔寫入未完成；完整待寫資料仍保存在主庫，請檢查磁碟與權限後重試')


def optimize(path,progress=None):
    from .server_config import local_database
    from .server_backup import snapshot
    from .store import Store
    path=local_database(storage.ordinary(path))
    if not path.is_file():raise ValueError('管理中心資料庫不存在')
    started=time.monotonic()
    with DatabaseLease(path):
        before=path.stat().st_size
        db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
        try:
            daily=storage.enabled(db)
            day_bytes=sum(storage.day_file(path,r[0]).stat().st_size for r in db.execute('SELECT DISTINCT day FROM event_catalog WHERE stored=1')) if daily else 0
        finally:db.close()
        if shutil.disk_usage(path.parent).free<before*3+day_bytes*2+512*1024*1024:raise ValueError('備份、日檔及主庫壓縮所需空間不足，未變更資料')
        backup_root=storage.private_folder(path.parent/'StorageBackups')
        backup=backup_root/('before-optimize-'+secrets.token_hex(8)+'.sqlite3')
        if progress:progress({'phase':'backup','control_bytes':before})
        saved=snapshot(path,backup)
        store=Store(path)
        with store.connect() as db:
            if not storage.enabled(db):storage.enable(db,path,snapshot_backup=False)
            count=db.execute('SELECT count(*) FROM events_legacy').fetchone()[0]
        moved=0
        with closing(sqlite3.connect(path)):
            store.storage_writer=storage.DayWriter()
            try:
                moved,verified=_complete_migration(store,count,progress)
            finally:
                store.storage_writer.close();store.storage_writer=None
        if not verified['valid']:raise ValueError('搬移後稽核鏈驗證失敗；保留所有資料及搬移前備份，未壓縮主庫')
        if progress:progress({'phase':'compact','checked':verified['checked']})
        db=sqlite3.connect(path,timeout=2)
        try:
            db.execute('PRAGMA wal_checkpoint(TRUNCATE)');db.execute('VACUUM');db.execute('PRAGMA optimize')
            if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('壓縮後資料庫檢查失敗，請保留備份並調查')
            days=[storage.day_file(path,r[0]) for r in db.execute('SELECT day FROM event_storage_daily ORDER BY day')]
        finally:db.close()
        result={'passed':True,'moved':moved,'events':verified['checked'],'head':verified['head'],
                'before_control_bytes':before,'control_bytes':path.stat().st_size,'day_bytes':sum(p.stat().st_size for p in days),
                'backup':saved,'elapsed_seconds':round(time.monotonic()-started,2),'history_preserved':True}
        report=storage.ordinary(path.parent/('storage-optimization-'+secrets.token_hex(8)+'.json'))
        with report.open('x',encoding='utf-8') as stream:json.dump(result,stream,ensure_ascii=False,indent=2)
        return result


def _complete_migration(store,count,progress):
    moved=0;last_report=0
    drain(store)
    while n:=migrate_batch(store):
        moved+=n
        if progress and (moved-last_report>=12800 or moved>=count):
            progress({'phase':'migrate','moved':moved,'total':count});last_report=moved
    drain(store)
    from .audit_reports import index_batch
    if progress:progress({'phase':'summary_index'})
    while index_batch(store):pass
    if progress:progress({'phase':'verify','moved':moved})
    return moved,store.verify()
