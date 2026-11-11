"""Bounded, date-partitioned audit export. Never deletes source events."""
import csv
import datetime as dt
import gzip
import hashlib
import json
import os
import re
import shutil
import sqlite3
import threading
import time
import zipfile
from pathlib import Path,PurePosixPath
from .audit_reports import AuditError,dates,day_bounds,TAIPEI
from .performance import background_work
from .store import Store,canonical,event_hash_valid

MAX_PART_ROWS=50000
MAX_PART_BYTES=32*1024*1024
MAX_EXPORT_BYTES=64*1024**3


def ordinary(path):
    path=Path(os.path.abspath(path))
    for p in (path,*path.parents):
        if os.path.lexists(p) and (p.is_symlink() or getattr(p.lstat(),'st_file_attributes',0)&0x400):raise AuditError(409,'備份路徑不可經過 junction 或符號連結')
    return path


def private_folder(path):
    path=ordinary(path)
    if not path.exists():
        from .server_setup import secure_directory
        secure_directory(path)
    if not path.is_dir():raise AuditError(409,'備份目錄不是一般資料夾')
    return path


def sha_file(path):
    digest=hashlib.sha256()
    with ordinary(path).open('rb') as f:
        while chunk:=f.read(65536):digest.update(chunk)
    return digest.hexdigest()


def manifest_write(path,value):
    data=(canonical(value)+'\n').encode('utf-8')
    with ordinary(path).open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())


def safe_csv(value):
    value=str(value if value is not None else '')
    return "'"+value if value.lstrip().startswith(('=','+','-','@')) else value


def local_time(value):
    try:return dt.datetime.fromtimestamp(value,TAIPEI).isoformat()
    except (OverflowError,ValueError,OSError):return '超出日期顯示範圍'


def export_catalog(db,root):
    rows=[]
    for r in db.execute('SELECT * FROM audit_exports ORDER BY created DESC LIMIT 50'):
        row=dict(r);row['parameters']=json.loads(row['parameters']);row['folder']=str(root/row['id']);rows.append(row)
    database=Path(db.execute('PRAGMA database_list').fetchone()[2])
    def size(path):
        try:return path.stat().st_size
        except OSError:return 0
    return {'jobs':rows,'root':str(root),'source_preserved':True,'database_bytes':size(database),'wal_bytes':size(Path(str(database)+'-wal')),'archive_bytes':db.execute("SELECT COALESCE(sum(bytes),0) FROM audit_exports WHERE state='completed'").fetchone()[0]}


def create_job(db,actor,body):
    from .endpoint_purge import active
    if active(db):raise AuditError(409,'端點資料清除中，完成後再建立匯出')
    if set(body)-{'start','end','basis','csv'}:raise AuditError(400,'匯出欄位不正確')
    first,last=dates(body.get('start'),body.get('end'));basis=body.get('basis','occurred');with_csv=body.get('csv',True)
    if basis not in ('occurred','received') or type(with_csv) is not bool:raise AuditError(400,'匯出時間基準或格式不正確')
    if db.execute("SELECT count(*) FROM audit_exports WHERE state IN ('queued','running','cancelling')").fetchone()[0]>=3:raise AuditError(429,'已有 3 筆匯出工作，請等待或取消')
    import secrets
    jid=secrets.token_hex(16);now=time.time();head=db.execute('SELECT id,hash FROM events ORDER BY id DESC LIMIT 1').fetchone()
    params={'start':first.isoformat(),'end':last.isoformat(),'basis':basis,'csv':with_csv}
    db.execute('INSERT INTO audit_exports(id,actor,created,updated,state,parameters,snapshot_id,snapshot_head) VALUES (?,?,?,?,?,?,?,?)',(jid,actor,now,now,'queued',canonical(params),head['id'] if head else 0,head['hash'] if head else '0'*64))
    Store.event(db,'console','audit.export_requested','info',{'actor':actor,'job_id':jid,**params,'source_preserved':True})
    return {'id':jid,'state':'queued','source_preserved':True}


def cancel_job(db,actor,jid):
    if not isinstance(jid,str) or not re.fullmatch('[0-9a-f]{32}',jid):raise AuditError(400,'匯出工作識別碼不正確')
    row=db.execute('SELECT state FROM audit_exports WHERE id=?',(jid,)).fetchone()
    if not row:raise AuditError(404,'找不到匯出工作')
    if row['state'] not in ('queued','running','cancelling'):raise AuditError(409,'工作已結束')
    db.execute("UPDATE audit_exports SET state=?,updated=? WHERE id=?",('cancelled' if row['state']=='queued' else 'cancelling',time.time(),jid))
    Store.event(db,'console','audit.export_cancelled','info',{'actor':actor,'job_id':jid})
    return {'ok':True}


def verify_directory(directory,stop=None):
    root=ordinary(directory);manifest_path=ordinary(root/'manifest.json')
    if manifest_path.stat().st_size>8*1024*1024:raise AuditError(409,'備份清單過大')
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    if not isinstance(manifest,dict) or manifest.get('format')!=1 or manifest.get('complete') is not True or not isinstance(manifest.get('files'),list) or len(manifest['files'])>20000:raise AuditError(409,'備份清單不完整或格式不正確')
    if type(manifest.get('rows')) is not int or not 0<=manifest['rows']<=10**10 or type(manifest.get('snapshot_id')) is not int or not 0<=manifest['snapshot_id']<=2**63-1:raise AuditError(409,'備份筆數或事件界線不正確')
    rows=0;seen=set()
    for entry in manifest['files']:
        if not isinstance(entry,dict) or type(entry.get('bytes')) is not int or not 0<=entry['bytes']<=MAX_EXPORT_BYTES or not isinstance(entry.get('sha256'),str) or not re.fullmatch('[0-9a-f]{64}',entry['sha256']):raise AuditError(409,'備份檔案清單不正確')
        name=entry.get('path','')
        if not isinstance(name,str) or not re.fullmatch(r'\d{6}/\d{8}/(?:events-\d{8}-\d{4}\.(?:jsonl\.gz|csv)|manifest-day\.json)',name) or name in seen:raise AuditError(409,'備份檔名不正確')
        seen.add(name);path=ordinary(root/PurePosixPath(name))
        if not path.is_file() or path.stat().st_size!=entry['bytes'] or sha_file(path)!=entry['sha256']:raise AuditError(409,'備份檔案缺少或 SHA-256 不符')
        if name.endswith('.jsonl.gz'):
            if type(entry.get('rows')) is not int or not 0<=entry['rows']<=MAX_PART_ROWS:raise AuditError(409,'分檔筆數不正確')
            count=0
            with gzip.open(path,'rb') as stream:
                while line:=stream.readline(1024*1024+1):
                    if count%128==0 and stop and stop():raise AuditError(409,'工作已中止')
                    if len(line)>1024*1024 or not line.endswith(b'\n'):raise AuditError(409,'事件資料超過驗證上限')
                    row=json.loads(line)
                    try:valid=isinstance(row,dict) and event_hash_valid(row)
                    except (KeyError,TypeError,ValueError):valid=False
                    if not valid:raise AuditError(409,'原始事件雜湊驗證失敗')
                    count+=1
                    if count>entry['rows']:raise AuditError(409,'備份事件數量不符')
            if count!=entry['rows']:raise AuditError(409,'備份事件數量不符')
            rows+=count
    if rows!=manifest['rows']:raise AuditError(409,'備份總筆數不符')
    return {'valid':True,'files':len(seen),'rows':rows,'snapshot_id':manifest['snapshot_id'],'scope':'file_sha256_and_each_exported_event_hash_not_complete_database_chain'}


class ArchiveWorker:
    def __init__(self,store):
        self.store=store;self.root=store.path.parent/'AuditArchives';self.stop=threading.Event();self.wake=threading.Event();self.pending_failure=None
        with store.connect() as db:db.execute("UPDATE audit_exports SET state='interrupted',error='Server 重啟；原資料保留，請重新建立匯出工作',updated=? WHERE state IN ('running','cancelling')",(time.time(),))
        self.thread=threading.Thread(target=self._run,daemon=True,name='GuardDesk-AuditExport');self.thread.start()

    def close(self):
        self.stop.set();self.wake.set()
        if self.thread.is_alive():self.thread.join(3)

    def _run(self):
        with background_work():
            while not self.stop.is_set():
                try:
                    if self.pending_failure:
                        self._record_failure(*self.pending_failure);self.pending_failure=None
                    with self.store.connect() as db:
                        db.execute('BEGIN IMMEDIATE');row=db.execute("SELECT * FROM audit_exports WHERE state='queued' ORDER BY created LIMIT 1").fetchone()
                        job=dict(row) if row else None
                        if job:db.execute("UPDATE audit_exports SET state='running',updated=? WHERE id=?",(time.time(),job['id']))
                    if job:
                        try:
                            result=self.export(job)
                            with self.store.connect() as db:
                                if db.execute('SELECT state FROM audit_exports WHERE id=?',(job['id'],)).fetchone()[0]=='cancelling':raise AuditError(409,'工作已取消')
                                db.execute("UPDATE audit_exports SET state='completed',rows=?,bytes=?,zip_sha256=?,updated=? WHERE id=?",(result['rows'],result['bytes'],result['zip_sha256'],time.time(),job['id']))
                                Store.event(db,'console','audit.export_completed','info',{'actor':job['actor'],'job_id':job['id'],'rows':result['rows'],'source_preserved':True,'verification':result['verification']})
                        except (OSError,ValueError,KeyError,TypeError,OverflowError,RecursionError,sqlite3.Error,AuditError,zipfile.BadZipFile) as exc:
                            error=exc.message if isinstance(exc,AuditError) else '匯出失敗；請檢查磁碟空間、權限、原始事件及本機紀錄'
                            self.pending_failure=(job,error)
                            self._record_failure(job,error);self.pending_failure=None
                        continue
                except sqlite3.Error:pass
                self.wake.wait(2);self.wake.clear()

    def _record_failure(self,job,error):
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE');current=db.execute('SELECT state FROM audit_exports WHERE id=?',(job['id'],)).fetchone()[0]
            state='interrupted' if self.stop.is_set() else 'cancelled' if current=='cancelling' else 'failed'
            db.execute('UPDATE audit_exports SET state=?,error=?,updated=? WHERE id=?',(state,error,time.time(),job['id']))
            Store.event(db,'console','audit.export_failed','warning',{'actor':job['actor'],'job_id':job['id'],'state':state,'error':error})

    def cancelled(self,jid):
        if self.stop.is_set():return True
        with self.store.connect() as db:return db.execute('SELECT state FROM audit_exports WHERE id=?',(jid,)).fetchone()[0]=='cancelling'

    def export(self,job):
        private_folder(self.root);target=self.root/job['id']
        if os.path.lexists(target):raise AuditError(409,'此工作已有資料夾，保留原檔，請建立新工作')
        private_folder(target);params=json.loads(job['parameters']);first,last=dates(params['start'],params['end']);basis=params['basis']
        if basis not in ('occurred','received'):raise AuditError(400,'匯出基準不正確')
        files=[];total=0;disk_bytes=0;day=first
        while day<=last:
            if self.cancelled(job['id']):raise AuditError(409,'工作已中止')
            month=private_folder(target/day.strftime('%Y%m'));folder=private_folder(month/day.strftime('%Y%m%d'))
            lo,hi=day_bounds(day);cursor_time=lo;cursor_id=0;part=0;day_rows=0;day_files=[]
            output=None;csv_stream=None;raw=None;part_rows=0;part_bytes=0
            def finish():
                nonlocal output,csv_stream,raw,disk_bytes
                if output is None:return
                output.close();raw.flush();os.fsync(raw.fileno());raw.close()
                if csv_stream:csv_stream.flush();os.fsync(csv_stream.fileno());csv_stream.close()
                for path in [json_path]+([csv_path] if params['csv'] else []):
                    entry={'path':path.relative_to(target).as_posix(),'bytes':path.stat().st_size,'sha256':sha_file(path),'rows':part_rows}
                    files.append(entry);day_files.append(entry);disk_bytes+=entry['bytes']
                output=None;csv_stream=None;raw=None
            try:
                while True:
                    if self.cancelled(job['id']):raise AuditError(409,'工作已中止')
                    if shutil.disk_usage(target).free<512*1024*1024 or disk_bytes>MAX_EXPORT_BYTES:raise AuditError(409,'備份空間不足或本次超過 64 GiB，請縮小日期區間')
                    with self.store.connect() as db:
                        batch=[dict(r) for r in db.execute('SELECT e.*,COALESCE(d.name,\'管理中心／已移除端點\') device_name FROM events e LEFT JOIN devices d ON e.device_id=d.id WHERE e.'+basis+'>=? AND e.'+basis+'<? AND e.id<=? AND (e.'+basis+'>? OR (e.'+basis+'=? AND e.id>?)) ORDER BY e.'+basis+',e.id LIMIT 128',(lo,hi,job['snapshot_id'],cursor_time,cursor_time,cursor_id))]
                    if not batch:break
                    for row in batch:
                        if not event_hash_valid(row):raise AuditError(409,'原始事件雜湊不符；停止匯出，原資料保留')
                        row['details']=json.loads(row['details']);data=(canonical(row)+'\n').encode('utf-8')
                        if len(data)>1024*1024:raise AuditError(409,'單筆事件過大，請 MIS 檢查原始事件')
                        if output is None:
                            part+=1
                            if part>9999:raise AuditError(409,'每日分檔數超過上限，請縮小區間')
                            stem=f'events-{day:%Y%m%d}-{part:04d}';json_path=folder/(stem+'.jsonl.gz');csv_path=folder/(stem+'.csv')
                            raw=json_path.open('xb');output=gzip.GzipFile(filename='',mode='wb',compresslevel=1,fileobj=raw,mtime=0);part_rows=0;part_bytes=0
                            if params['csv']:
                                csv_stream=csv_path.open('x',encoding='utf-8-sig',newline='');writer=csv.writer(csv_stream);writer.writerow(['id','event_id','發生時間（台北）','接收時間（台北）','端點','使用者','操作','完整來源路徑','目的地','網址','完整事件','prev_hash','hash'])
                        output.write(data)
                        if csv_stream:
                            d=row['details'] if isinstance(row['details'],dict) else {};writer.writerow([safe_csv(v) for v in [row['id'],row['event_id'],local_time(row['occurred']),local_time(row['received']),row['device_name'],d.get('user',d.get('actor','')),row['kind'],d.get('source_path',d.get('path','')),d.get('destination_path',''),d.get('url',''),canonical(row['details']),row['prev_hash'],row['hash']]])
                        part_rows+=1;part_bytes+=len(data);total+=1;day_rows+=1
                        cursor_time=row[basis];cursor_id=row['id']
                        if part_rows>=MAX_PART_ROWS or part_bytes>=MAX_PART_BYTES:finish()
                    with self.store.connect() as db:db.execute('UPDATE audit_exports SET rows=?,bytes=?,updated=? WHERE id=?',(total,disk_bytes,time.time(),job['id']))
                    if self.stop.wait(.01):raise AuditError(409,'Server 正在停止')
                finish()
            finally:
                if output:output.close()
                if raw and not raw.closed:raw.close()
                if csv_stream and not csv_stream.closed:csv_stream.close()
            path=folder/'manifest-day.json';manifest_write(path,{'date':day.isoformat(),'rows':day_rows,'files':day_files,'snapshot_id':job['snapshot_id']})
            files.append({'path':path.relative_to(target).as_posix(),'bytes':path.stat().st_size,'sha256':sha_file(path)})
            if len(files)>20000:raise AuditError(409,'分檔數超過上限，請縮小區間')
            day+=dt.timedelta(days=1)
        manifest={'format':1,'complete':True,'created':time.time(),'timezone':'Asia/Taipei','parameters':params,'rows':total,'files':files,'snapshot_id':job['snapshot_id'],'snapshot_head':job['snapshot_head'],'source_preserved':True,
                  'integrity_scope':'each_exported_row_hash_and_file_sha256; partial_date_range_is_not_complete_database_chain',
                  'late_arrivals':'Events received after snapshot_id are excluded, including older occurred dates; rerun export to include them'}
        manifest_write(target/'manifest.json',manifest)
        verification=verify_directory(target,lambda:self.cancelled(job['id']))
        # Keep ingestion space available while writing the additional ZIP.
        # Deflate can expand incompressible CSV slightly; reserve generously.
        estimated_zip=sum(entry['bytes'] for entry in files)*1.02+1024*1024
        if shutil.disk_usage(target).free<estimated_zip+512*1024*1024:raise AuditError(409,'建立 ZIP 空間不足，保留原始日誌與已匯出分檔，請縮小區間')
        pending=ordinary(target/'archive.zip.partial')
        with zipfile.ZipFile(pending,'x',allowZip64=True,compresslevel=1) as archive:
            for entry in [*files,{'path':'manifest.json'}]:
                if self.cancelled(job['id']):raise AuditError(409,'工作已中止')
                path=ordinary(target/PurePosixPath(entry['path']))
                info=zipfile.ZipInfo.from_file(path,entry['path']);info.compress_type=zipfile.ZIP_STORED if str(path).endswith('.gz') else zipfile.ZIP_DEFLATED
                info._compresslevel=1  # Same pinned CPython level as ZipFile.write.
                with path.open('rb') as source,archive.open(info,'w',force_zip64=True) as output:
                    copied=0
                    while chunk:=source.read(65536):
                        output.write(chunk);copied+=len(chunk)
                        if copied>=1024*1024:
                            if self.cancelled(job['id']):raise AuditError(409,'工作已中止')
                            if shutil.disk_usage(target).free<512*1024*1024:raise AuditError(409,'ZIP 寫入期間可用空間不足，停止備份並保留原始日誌')
                            copied=0
        os.replace(pending,target/'archive.zip')
        return {'rows':total,'bytes':(target/'archive.zip').stat().st_size,'zip_sha256':sha_file(target/'archive.zip'),'verification':verification}
