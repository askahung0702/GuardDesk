"""Explicit, resumable deletion of one retired endpoint's live center data.

Exports / external backups are deliberately outside this operation. Hash links
survive without event payloads so deleting one endpoint never rewrites a sibling's
evidence. Deletion is irreversible; this is not a remote uninstall command.
"""
import functools
import json
import logging
import re
import secrets
import sqlite3
import threading
import time
from .management import ManagementError
from .store import Store, canonical

BATCH=64
EXCLUSIONS=['既有匯出 ZIP、寄出的報表、StorageBackups 與外部備份',
            '端點本機程式與檔案（另執行解除安裝／清除）',
            '管理操作稽核及不含原文的事件雜湊鏈結（仍保留刪除身分／操作者）']


def install(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS endpoint_purges(id TEXT PRIMARY KEY,device_id TEXT NOT NULL UNIQUE,
      actor TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,state TEXT NOT NULL,
      phase TEXT NOT NULL,removed INTEGER NOT NULL DEFAULT 0,cursor INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '');
    CREATE INDEX IF NOT EXISTS endpoint_purges_state ON endpoint_purges(state,created);
    CREATE TABLE IF NOT EXISTS event_deletions(id INTEGER PRIMARY KEY,prev_hash TEXT NOT NULL,hash TEXT NOT NULL,purge_id TEXT NOT NULL REFERENCES endpoint_purges(id));
    CREATE TABLE IF NOT EXISTS endpoint_purge_days(event_row INTEGER PRIMARY KEY,day TEXT NOT NULL,purge_id TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS endpoint_purge_days_job ON endpoint_purge_days(purge_id,event_row);
    CREATE TABLE IF NOT EXISTS endpoint_purge_values(job_id TEXT NOT NULL,value_id INTEGER NOT NULL,keep INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(job_id,value_id));
    CREATE INDEX IF NOT EXISTS endpoint_purge_values_id ON endpoint_purge_values(value_id,keep);
    ''')
    if 'row_cursor' not in {r[1] for r in db.execute('PRAGMA table_info(endpoint_purges)')}:
        db.execute('ALTER TABLE endpoint_purges ADD COLUMN row_cursor INTEGER NOT NULL DEFAULT 0')
    # Serialize with every writer, including a request authenticated before
    # revocation and configuration saved while an earlier phase was running.
    # These schema-only guards do not scan old event or metadata rows.
    guarded={t:'device_id' for t in ('update_jobs','update_presence','update_diagnostics','updater_refresh',
        'native_usb_status','extended_status','endpoint_removals','remote_grants','remote_presence','remote_readiness',
        'remote_capabilities','remote_admin_grants','remote_sessions','custom_status','custom_action_leases','custom_executions','audit_daily')}
    guarded['devices']='id'
    guarded['endpoint_file_removals']='device_id'
    guarded['software_jobs']='device_id'
    guarded['software_presence']='device_id'
    for table,column in guarded.items():
        for operation in ('INSERT','UPDATE'):
            db.execute('CREATE TRIGGER IF NOT EXISTS purge_guard_'+table+'_'+operation+' BEFORE '+operation+' ON '+table+
                ' WHEN EXISTS(SELECT 1 FROM endpoint_purges WHERE device_id=NEW.'+column+
                ") BEGIN SELECT RAISE(ABORT,'endpoint_data_permanently_retired'); END")
    for table in ('policy_assignments','custom_bindings','custom_settings','custom_settings_history','custom_legacy_imports','custom_migration_notes'):
        kind,target=('target_type','target_id') if table in ('policy_assignments','custom_bindings') else ('scope','target')
        for operation in ('INSERT','UPDATE'):
            db.execute('CREATE TRIGGER IF NOT EXISTS purge_guard_'+table+'_'+operation+' BEFORE '+operation+' ON '+table+
                " WHEN NEW."+kind+"='device' AND EXISTS(SELECT 1 FROM endpoint_purges WHERE device_id=NEW."+target+
                ") BEGIN SELECT RAISE(ABORT,'endpoint_data_permanently_retired'); END")


def serialized(function):
    """Derived read/compute/write batches cannot resurrect a deleted event."""
    @functools.wraps(function)
    def call(store,*args,**kwargs):
        with store.lifecycle_lock:return function(store,*args,**kwargs)
    return call


def active(db):
    return db.execute("SELECT 1 FROM endpoint_purges WHERE state<>'completed' LIMIT 1").fetchone() is not None


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{24}',value):
        raise ManagementError(400,'端點識別碼不正確')
    return value


def eligible(db,did):
    device=db.execute('SELECT id,name,revoked FROM devices WHERE id=?',(did,)).fetchone()
    if not device:raise ManagementError(404,'找不到端點')
    from .removal import latest,TERMINAL
    removal=latest(db,did)
    if removal and removal['status'] not in TERMINAL:raise ManagementError(409,'請先完成解除安裝，不能刪除尚待端點回報的身分')
    if not device['revoked'] and (not removal or removal['status']!='completed'):
        raise ManagementError(409,'請先完成遠端解除安裝，或確認已在本機移除後撤銷憑證')
    now=time.time()
    checks=[("SELECT 1 FROM update_jobs WHERE device_id=? AND status='pending' AND expires>?",(did,now)),
            ("SELECT 1 FROM updater_refresh WHERE device_id=? AND state='active' AND expires>?",(did,now)),
            ('SELECT 1 FROM custom_action_leases WHERE device_id=? AND expires>?',(did,now)),
            ("SELECT 1 FROM remote_sessions WHERE device_id=? AND status IN ('requested','active')",(did,)),
            ("SELECT 1 FROM audit_exports WHERE state IN ('queued','running','cancelling') LIMIT 1",())]
    if any(db.execute(sql,args).fetchone() for sql,args in checks):
        raise ManagementError(409,'尚有更新、維護、遠端協助或匯出工作，請先完成或取消')
    return device


def preview(db,user,did):
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    did=identifier(did);d=eligible(db,did)
    # No all-history count / payload query on the request thread.
    return {'device_id':did,'name':d['name'],'deletes':['端點身分與憑證、資產、狀態及授權',
        '此端點的日誌原文、搜尋／排序索引與總表', '此端點的策略指派、自訂設定、更新與移除紀錄'],
        'retains':EXCLUSIONS,'irreversible':True,'history_counted':False}


def retire_preview(db,user,did):
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    did=identifier(did)
    device=db.execute('SELECT id,name FROM devices WHERE id=?',(did,)).fetchone()
    if not device:raise ManagementError(404,'找不到端點')
    return {'device_id':did,'name':device['name'],'retains':EXCLUSIONS,'irreversible':True,
            'waits_for_uninstall':False,'uninstall_verified':False,'can_queue':True}


def retire_request(db,user,body,server):
    """Explicit admin abandonment of endpoint reporting, not fake uninstall."""
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    if (set(body)!={'device_id','confirm_name','acknowledge_scope','acknowledge_no_uninstall'}
        or body.get('acknowledge_scope') is not True or body.get('acknowledge_no_uninstall') is not True):
        raise ManagementError(400,'請確認刪除範圍，並確認不等待解除安裝／未補送資料')
    did=identifier(body.get('device_id'))
    if not db.in_transaction:db.execute('BEGIN IMMEDIATE')
    old=db.execute('SELECT * FROM endpoint_purges WHERE device_id=?',(did,)).fetchone()
    if old:return public(old)
    device=retire_preview(db,user,did)
    if body.get('confirm_name')!=device['name']:raise ManagementError(400,'請輸入完整端點名稱確認')
    # End center remote sessions BEFORE installing the tombstone triggers.
    # Revoking credentials never pretends to stop an already running OS action.
    from . import remote
    for row in db.execute("SELECT * FROM remote_sessions WHERE device_id=? AND status IN ('requested','active')",(did,)).fetchall():
        remote.close(server,db,row,'administrator_retired_endpoint')
    busy=active(db) or db.execute("SELECT 1 FROM audit_exports WHERE state IN ('queued','running','cancelling') LIMIT 1").fetchone()
    state='queued' if busy else 'running';jid=secrets.token_hex(16);now=time.time()
    db.execute('UPDATE devices SET revoked=1 WHERE id=?',(did,))
    db.execute('INSERT INTO endpoint_purges(id,device_id,actor,created,updated,state,phase) VALUES(?,?,?,?,?,?,?)',
               (jid,did,user['username'],now,now,state,'events'))
    Store.event(db,'console','device.retired_without_uninstall','warning',{'actor':user['username'],'device_id':did,
        'device_name':device['name'],'job_id':jid,'uninstall_verified':False,'pending_reports_abandoned':True,
        'local_actions_stopped':False,'cleanup_state':state,'retains':EXCLUSIONS})
    return public(db.execute('SELECT * FROM endpoint_purges WHERE id=?',(jid,)).fetchone())


def request(db,user,body):
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    if set(body)!={'device_id','confirm_name','acknowledge_scope'} or body.get('acknowledge_scope') is not True:
        raise ManagementError(400,'請確認永久刪除範圍及保留項目')
    did=identifier(body.get('device_id'))
    if not db.in_transaction:db.execute('BEGIN IMMEDIATE')
    old=db.execute('SELECT * FROM endpoint_purges WHERE device_id=?',(did,)).fetchone()
    if old:return public(old)
    d=eligible(db,did)
    if body.get('confirm_name')!=d['name']:raise ManagementError(400,'請輸入完整端點名稱確認')
    if active(db):raise ManagementError(409,'已有端點資料清除中，完成後再操作下一台')
    jid=secrets.token_hex(16);now=time.time()
    db.execute('UPDATE devices SET revoked=1 WHERE id=?',(did,))
    db.execute('INSERT INTO endpoint_purges(id,device_id,actor,created,updated,state,phase) VALUES(?,?,?,?,?,?,?)',
               (jid,did,user['username'],now,now,'running','events'))
    Store.event(db,'console','device.purge_requested','warning',{'actor':user['username'],'device_id':did,
        'device_name':d['name'],'job_id':jid,'retains':EXCLUSIONS})
    return public(db.execute('SELECT * FROM endpoint_purges WHERE id=?',(jid,)).fetchone())


def public(row):
    return {k:row[k] for k in ('id','device_id','created','updated','state','phase','removed','error')}


def catalog(db,user):
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    return {'jobs':[public(r) for r in db.execute('SELECT * FROM endpoint_purges ORDER BY created DESC LIMIT 20')],
            'retains':EXCLUSIONS}


def retry(db,user,body):
    if user['role']!='admin':raise ManagementError(403,'需要管理員權限')
    jid=body.get('id')
    if set(body)!={'id'} or not isinstance(jid,str) or not re.fullmatch('[0-9a-f]{32}',jid):raise ManagementError(400,'工作識別碼不正確')
    row=db.execute('SELECT state FROM endpoint_purges WHERE id=?',(jid,)).fetchone()
    if not row:raise ManagementError(404,'找不到清除工作')
    if row['state']!='paused':raise ManagementError(409,'工作未暫停，不需重試')
    db.execute("UPDATE endpoint_purges SET state='running',error='',updated=? WHERE id=?",(time.time(),jid))
    Store.event(db,'console','device.purge_resumed','warning',{'actor':user['username'],'job_id':jid})
    return {'ok':True}


def remove_indexes(db,job,rows):
    from .audit_search_index import grams
    from .audit_sort import FIELDS
    searched=sorted_rows=0
    for row in rows:
        eid=row['id']
        search=db.execute('SELECT document_id FROM audit_search_rows WHERE id=?',(eid,)).fetchone()
        searched+=int(search is not None)
        db.execute('DELETE FROM audit_search_rows WHERE id=?',(eid,))
        if search and search[0] and not db.execute('SELECT 1 FROM audit_search_rows WHERE document_id=? LIMIT 1',(search[0],)).fetchone():
            tokens=grams(row['details'])
            if tokens is None:raise ValueError('搜尋索引與原文不一致，停止刪除')
            db.execute("INSERT INTO audit_search_grams(audit_search_grams,rowid,grams) VALUES('delete',?,?)",(search[0],tokens))
            db.execute('DELETE FROM audit_search_documents WHERE id=?',(search[0],))
        sort=db.execute('SELECT '+','.join(FIELDS)+' FROM audit_sort_rows WHERE id=?',(eid,)).fetchone()
        sorted_rows+=int(sort is not None)
        if sort:db.executemany('INSERT OR IGNORE INTO endpoint_purge_values(job_id,value_id) VALUES(?,?)',[(job['id'],v) for v in set(sort)])
        db.execute('DELETE FROM audit_sort_rows WHERE id=?',(eid,))
        db.execute('DELETE FROM audit_file_index WHERE event_row=?',(eid,))
    for table,n in (('audit_search_state',searched),('audit_sort_state',sorted_rows)):
        db.execute('UPDATE '+table+' SET indexed_rows=max(0,indexed_rows-?)',(n,))


def event_batch(db,job):
    from .event_storage import enabled
    daily=enabled(db);legacy='events_legacy' if daily else 'events'
    ids=[r[0] for r in db.execute('SELECT id FROM '+legacy+' WHERE device_id=? ORDER BY id LIMIT ?',(job['device_id'],BATCH))]
    modern=False
    if not ids and daily:
        ids=[r[0] for r in db.execute("SELECT id FROM event_catalog WHERE device_id=(SELECT id FROM event_terms WHERE category='device' AND value=?) ORDER BY id LIMIT ?",(job['device_id'],BATCH))]
        modern=True
    if not ids:return False
    rows=[];size=0
    for eid in ids:
        r=dict(db.execute('SELECT * FROM events WHERE id=?',(eid,)).fetchone());rows.append(r);size+=len(r['details'])
        if size>=512*1024:break
    remove_indexes(db,job,rows)
    for row in rows:
        eid=row['id']
        from .store import event_hash_valid
        if not event_hash_valid(row):raise ValueError('原事件雜湊不符，停止刪除並保留剩餘資料')
        db.execute('INSERT INTO event_deletions VALUES(?,?,?,?)',(eid,row['prev_hash'],row['hash'],job['id']))
        if modern:
            meta=db.execute('SELECT * FROM event_catalog WHERE id=?',(eid,)).fetchone()
            # Durable physical cleanup intent in the SAME control transaction.
            # A restart never loses the day/ID after removing its catalog entry.
            db.execute('INSERT INTO endpoint_purge_days VALUES(?,?,?)',(eid,meta['day'],job['id']))
            db.execute('DELETE FROM event_pending WHERE id=?',(eid,))
            db.execute('DELETE FROM event_catalog WHERE id=?',(eid,))
            db.execute('UPDATE event_storage_daily SET rows=rows-1,payload_bytes=max(0,payload_bytes-?) WHERE day=?',(meta['payload_bytes'],meta['day']))
            db.execute('UPDATE event_storage_sources SET rows=rows-1,payload_bytes=max(0,payload_bytes-?) WHERE day=? AND device_id=? AND kind=?',
                       (meta['payload_bytes'],meta['day'],meta['device_id'],meta['kind']))
        else:db.execute('DELETE FROM '+legacy+' WHERE id=?',(eid,))
    db.execute('UPDATE endpoint_purges SET removed=removed+? WHERE id=?',(len(rows),job['id']))
    return True


def day_batch(store,job):
    from .event_storage import day_file,ordinary
    # Connections opened before catalog deletion can still see a WAL snapshot
    # referencing these payloads. Let them finish without blocking new readers.
    if store.readers.awaiting_old_readers(job['id']):return True
    with store.connect(flush_events=False) as db:
        first=db.execute('SELECT day FROM endpoint_purge_days WHERE purge_id=? ORDER BY event_row LIMIT 1',(job['id'],)).fetchone()
        if not first:return False
        rows=list(db.execute('SELECT event_row FROM endpoint_purge_days WHERE purge_id=? AND day=? ORDER BY event_row LIMIT ?',(job['id'],first[0],BATCH)))
    path=day_file(store.path,first[0])
    # Pending payloads may never have reached the day file. A missing file is
    # safe here: the full original was validated before catalog removal.
    if path.exists():
        for suffix in ('-wal','-shm'):ordinary(str(path)+suffix)
        con=sqlite3.connect(path.as_uri()+'?mode=rw',uri=True,timeout=1)
        try:
            with con:
                con.execute('PRAGMA secure_delete=ON')
                con.executemany('DELETE FROM events WHERE id=?',[(r[0],) for r in rows])
        finally:con.close()
    with store.connect(flush_events=False) as db:
        db.executemany('DELETE FROM endpoint_purge_days WHERE event_row=?',[(r[0],) for r in rows])
    return True


def relation_batch(db,job):
    """Whitelisted predicates only; one table / <=256 rows per commit."""
    did=job['device_id']
    # Child rows precede the parent jobs / sessions / devices.
    tables=[('update_status','EXISTS(SELECT 1 FROM update_jobs p WHERE p.id=update_status.job_id AND p.device_id=?)'),
        ('update_job_preparations','EXISTS(SELECT 1 FROM update_jobs p WHERE p.id=update_job_preparations.job_id AND p.device_id=?)'),
        ('remote_admin_sessions','EXISTS(SELECT 1 FROM remote_sessions p WHERE p.id=remote_admin_sessions.session_id AND p.device_id=?)')]
    tables += [(t,'device_id=?') for t in ('update_jobs','update_presence','update_diagnostics','updater_refresh',
        'native_usb_status','extended_status','endpoint_removals','remote_grants','remote_presence','remote_readiness',
        'remote_capabilities','remote_admin_grants','remote_sessions','custom_status','custom_action_leases','custom_executions','audit_daily')]
    tables += [(t,"target_type='device' AND target_id=?") for t in ('policy_assignments','custom_bindings')]
    tables += [(t,"scope='device' AND target=?") for t in ('custom_settings','custom_settings_history','custom_legacy_imports','custom_migration_notes')]
    # Append: existing persisted purge cursors must retain their table positions.
    tables += [('endpoint_file_removals','device_id=?')]
    tables += [('software_jobs','device_id=?'),('software_presence','device_id=?')]
    position=job['cursor']
    if position>=len(tables):return False
    table,where=tables[position]
    # Advance through at most 256 metadata rows, even when device_id has no
    # index. Repeated misses must not rescan an entire multi-year table.
    rows=list(db.execute('SELECT rowid FROM '+table+' WHERE rowid>? ORDER BY rowid LIMIT 256',(job['row_cursor'],)))
    if rows:
        db.execute('DELETE FROM '+table+' NOT INDEXED WHERE rowid>? AND rowid<=? AND '+where,(job['row_cursor'],rows[-1][0],did))
        db.execute('UPDATE endpoint_purges SET row_cursor=? WHERE id=?',(rows[-1][0],job['id']))
    else:db.execute('UPDATE endpoint_purges SET cursor=cursor+1,row_cursor=0 WHERE id=?',(job['id'],))
    return True


def sort_scan(db,job):
    from .audit_sort import FIELDS
    rows=list(db.execute('SELECT id,'+','.join(FIELDS)+' FROM audit_sort_rows WHERE id>? ORDER BY id LIMIT 512',(job['cursor'],)))
    for row in rows:
        db.executemany('UPDATE endpoint_purge_values SET keep=1 WHERE job_id=? AND value_id=?',[(job['id'],v) for v in set(tuple(row)[1:])])
    if rows:db.execute('UPDATE endpoint_purges SET cursor=? WHERE id=?',(rows[-1]['id'],job['id']))
    return bool(rows)


def sort_cleanup(db,job):
    rows=list(db.execute('SELECT value_id,keep FROM endpoint_purge_values WHERE job_id=? LIMIT 256',(job['id'],)))
    for row in rows:
        if not row['keep']:db.execute('DELETE FROM audit_sort_values WHERE id=?',(row['value_id'],))
        db.execute('DELETE FROM endpoint_purge_values WHERE job_id=? AND value_id=?',(job['id'],row['value_id']))
    return bool(rows)


def step(store):
    # Both listeners share these locks; order matches daily flush (storage ->
    # SQLite). flush_events=False avoids recursively taking the storage lock.
    with store.lifecycle_lock,store._storage_lock:
        with store.connect(flush_events=False) as db:
            db.execute('PRAGMA busy_timeout=250');db.execute('PRAGMA secure_delete=ON');db.execute('BEGIN IMMEDIATE')
            row=db.execute("SELECT * FROM endpoint_purges WHERE state='running' ORDER BY created LIMIT 1").fetchone()
            if not row:
                # A paused predecessor remains first until its cause is fixed.
                if db.execute("SELECT 1 FROM endpoint_purges WHERE state='paused' LIMIT 1").fetchone():return False
                if db.execute("SELECT 1 FROM audit_exports WHERE state IN ('queued','running','cancelling') LIMIT 1").fetchone():return False
                row=db.execute("SELECT * FROM endpoint_purges WHERE state='queued' ORDER BY created,rowid LIMIT 1").fetchone()
                if not row:return False
                db.execute("UPDATE endpoint_purges SET state='running',updated=? WHERE id=?",(time.time(),row['id']))
                row=db.execute('SELECT * FROM endpoint_purges WHERE id=?',(row['id'],)).fetchone()
            job=dict(row)
            # Do not run while an older pending export can still read history.
            if db.execute("SELECT 1 FROM audit_exports WHERE state IN ('queued','running','cancelling') LIMIT 1").fetchone():return False
            phase=job['phase'];more=True
            if phase=='events':
                more=event_batch(db,job);next_phase='days'
            elif phase=='days':next_phase='relations';more=False
            elif phase=='relations':more=relation_batch(db,job);next_phase='sort_scan'
            elif phase=='sort_scan':more=sort_scan(db,job);next_phase='sort_cleanup'
            elif phase=='sort_cleanup':more=sort_cleanup(db,job);next_phase='finish'
            elif phase=='finish':
                did=job['device_id']
                db.execute('DELETE FROM devices WHERE id=?',(did,))
                # Dictionaries shared with another endpoint are retained.
                db.execute("DELETE FROM event_storage_sources WHERE device_id=(SELECT id FROM event_terms WHERE category='device' AND value=?) AND rows=0",(did,))
                db.execute("DELETE FROM event_terms WHERE category='device' AND value=? AND NOT EXISTS(SELECT 1 FROM event_catalog WHERE device_id=event_terms.id)",(did,))
                db.execute("UPDATE endpoint_purges SET state='completed',error='',updated=? WHERE id=?",(time.time(),job['id']))
                with store.readers.lock:store.readers.cutoffs.pop(job['id'],None)
                Store.event(db,'console','device.purge_completed','warning',{'actor':job['actor'],'device_id':did,'job_id':job['id'],
                    'events_deleted':job['removed'],'scope':'live_center_logical_deletion','retains':EXCLUSIONS})
            else:raise ValueError('未知清除階段')
            if not more and phase!='days':db.execute('UPDATE endpoint_purges SET phase=?,cursor=0 WHERE id=?',(next_phase,job['id']))
            db.execute("UPDATE endpoint_purges SET updated=?,error='' WHERE id=?",(time.time(),job['id']))
        if phase=='days':
            if not day_batch(store,job):
                with store.connect(flush_events=False) as db:db.execute("UPDATE endpoint_purges SET phase='relations',cursor=0 WHERE id=?",(job['id'],))
    return True


class Worker:
    def __init__(self,store):
        self.store=store;self.stop=threading.Event()
        self.thread=threading.Thread(target=self.run,daemon=True,name='GuardDesk-EndpointPurge');self.thread.start()
    def run(self):
        from .performance import background_work
        with background_work():
            while not self.stop.is_set():
                try:changed=step(self.store)
                except (sqlite3.Error,OSError,ValueError) as exc:
                    if isinstance(exc,sqlite3.Error) and getattr(exc,'sqlite_errorcode',0)&255 in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED):
                        self.stop.wait(1);continue
                    logging.getLogger('guarddesk').exception('Endpoint purge paused; durable progress retained')
                    with self.store.connect(flush_events=False) as db:
                        db.execute("UPDATE endpoint_purges SET state='paused',error='清除暫停；已完成的刪除不會還原，請檢查 Server 紀錄後重試',updated=? WHERE state='running'",(time.time(),))
                    changed=False
                self.stop.wait(.1 if changed else 2)
    def close(self):
        self.stop.set();self.thread.join()
