"""Rebuildable display keys; immutable evidence is never used as a sort workspace.

Only the cooperative background worker decodes history. Repeated full strings
share dictionary entries. Coverage advances in the same transaction as rows.
"""
import json
import shutil
import time
from .event_storage import head
from .endpoint_purge import serialized

FIELDS=('process','path','destination','user','browser','title','url','upload_path')
METADATA={'id':'e.id','occurred':'e.occurred','received':'e.received',
          'device':"COALESCE(d.name,'管理中心') COLLATE NOCASE",'kind':'e.kind COLLATE NOCASE'}

def validate(field,direction):
    if field not in (*METADATA,*FIELDS) or direction not in ('asc','desc'):
        raise ValueError('排序欄位或方向不正確')

def install(db):
    db.execute('CREATE TABLE IF NOT EXISTS audit_sort_values(id INTEGER PRIMARY KEY,value TEXT NOT NULL COLLATE NOCASE UNIQUE)')
    db.execute('CREATE TABLE IF NOT EXISTS audit_sort_rows(id INTEGER PRIMARY KEY,'+','.join(f+' INTEGER NOT NULL' for f in FIELDS)+')')
    db.execute('CREATE TABLE IF NOT EXISTS audit_sort_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),low_id INTEGER NOT NULL,high_id INTEGER NOT NULL,indexed_rows INTEGER NOT NULL)')
    if not db.execute('SELECT 1 FROM audit_sort_state').fetchone():
        last=head(db)[0];db.execute('INSERT INTO audit_sort_state VALUES(1,?,?,0)',(last+1,last))

def state(db):return dict(db.execute('SELECT low_id,high_id,indexed_rows FROM audit_sort_state WHERE singleton=1').fetchone())

def ready(db,clause,values,person_join='',time_filtered=False):
    value=state(db);source='event_headers_time' if time_filtered else 'event_headers'
    suffix=(' AND ' if clause else 'WHERE ')+'(e.id<? OR e.id>?)'
    missing=db.execute('SELECT 1 FROM '+source+' e '+person_join+clause+suffix+' LIMIT 1',tuple(values)+(value['low_id'],value['high_id'])).fetchone()
    return not missing,{**value,'purpose':'sort'}

def keys(raw):
    d=json.loads(raw)
    if not isinstance(d,dict):return ('',)*len(FIELDS)
    def text(*names):
        v=next((d.get(n) for n in names if d.get(n)),'')
        return v if isinstance(v,str) else ''
    # New 0.4.56 candidates have no native path. Their displayed filename is
    # also their document sort key; preexisting event projections stay intact.
    path=text('source_path','path','file_name','url') if d.get('correlation')=='page_body_metadata_candidate' else text('source_path','path','url')
    destination=text('site_origin') if d.get('evidence') in ('receiver_accepted_drop','browser_file_attached') else text('destination_path','title')
    return (text('process'),path,destination,
            text('user'),text('browser'),text('title'),text('url'),text('source_path','file_name'))

@serialized
def index_batch(store,stop=None,*,cooperative=False):
    if (stop and stop.is_set()) or (cooperative and store.ingest_active.is_set()):return False
    if shutil.disk_usage(store.path.parent).free<256*1024*1024:raise OSError('排序索引空間不足，請保留至少 256 MiB 可用空間')
    with store.connect(flush_events=False) as db:
        before=state(db);forward=before['high_id']<head(db)[0];limit=100 if cooperative else 500
        sql=f'SELECT id,details FROM events WHERE id>? ORDER BY id LIMIT {limit}' if forward else f'SELECT id,details FROM events WHERE id<? ORDER BY id DESC LIMIT {limit}'
        records=[];size=0;started=time.monotonic()
        for row in db.execute(sql,(before['high_id'] if forward else before['low_id'],)):
            if (stop and stop.is_set()) or (cooperative and store.ingest_active.is_set()):return False
            records.append((row['id'],keys(row['details'])));size+=len(row['details'])
            if size>=2*1024*1024 or (cooperative and time.monotonic()-started>=.05):break
    if not records and (forward or before['low_id']==0):return False
    if (stop and stop.is_set()) or (cooperative and store.ingest_active.is_set()):return False
    with store.connect(flush_events=False) as db:
        db.execute('PRAGMA busy_timeout='+('25' if cooperative else '250'));db.execute('BEGIN IMMEDIATE')
        if state(db)!=before:return True
        written=[];started=time.monotonic()
        for identifier,texts in records:
            if stop and stop.is_set():db.rollback();return False
            if cooperative and store.ingest_active.is_set():break
            ids=[]
            for text in texts:
                found=db.execute('SELECT id FROM audit_sort_values WHERE value=?',(text,)).fetchone()
                ids.append(found[0] if found else db.execute('INSERT INTO audit_sort_values(value) VALUES(?)',(text,)).lastrowid)
            # A purge scans old references incrementally. A concurrent backfill
            # may insert lower IDs after that cursor, so mark fresh references.
            db.executemany('UPDATE endpoint_purge_values SET keep=1 WHERE value_id=?',[(v,) for v in set(ids)])
            db.execute('INSERT INTO audit_sort_rows VALUES('+','.join('?' for _ in range(9))+')',(identifier,*ids));written.append(identifier)
            if cooperative and time.monotonic()-started>=.025:break
        low=before['low_id'];high=before['high_id']
        if forward:
            if written:high=written[-1]
        elif written:low=written[-1]
        elif not records:low=0
        db.execute('UPDATE audit_sort_state SET low_id=?,high_id=?,indexed_rows=indexed_rows+? WHERE singleton=1',(low,high,len(written)))
    return bool(written) or low!=before['low_id']

def order(db,field,direction,anchor=None):
    """Whitelisted SQL only. URLs carry an authenticated event ID, never keys."""
    validate(field,direction)
    join='';expression=METADATA.get(field)
    if field in FIELDS:
        join=' JOIN audit_sort_rows sk ON sk.id=e.id JOIN audit_sort_values sv ON sv.id=sk.'+field+' '
        expression='sv.value COLLATE NOCASE'
    seek='';params=()
    if anchor is not None:
        row=db.execute('SELECT '+expression+' FROM event_headers e LEFT JOIN devices d ON d.id=e.device_id '+join+' WHERE e.id=?',(anchor,)).fetchone()
        if row is None:raise ValueError('排序游標資料已變更，請重新搜尋')
        op='>' if direction=='asc' else '<'
        seek=f'({expression}{op}? OR ({expression}=? AND e.id{op}?))';params=(row[0],row[0],anchor)
    return join,seek,params,expression+' '+direction+',e.id '+direction
