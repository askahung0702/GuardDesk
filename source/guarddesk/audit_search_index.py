"""Derived, contentless substring candidates; exact LIKE still checks evidence.

Documents share identical sets of ASCII-folded Unicode uni/bigrams. This keeps
repeated process events from storing identical postings once per event. Neither
original details nor positions are copied. Oversized inputs always remain
candidates, rather than being silently truncated out of searches.
"""
import hashlib
import logging
import re
import shutil
import sqlite3
import threading
import time
from .event_storage import head
from .performance import background_work
from .endpoint_purge import serialized

FOLD=str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')

def grams(text):
    if len(text)>65536:return None
    text=text.translate(FOLD);tokens=set()
    for i,c in enumerate(text):
        tokens.add('u'+format(ord(c),'06x'))
        if i:tokens.add('b'+format(ord(text[i-1]),'06x')+format(ord(c),'06x'))
        if len(tokens)>8192:return None
    return ' '.join(sorted(tokens))

def match(term):
    # SQLite LIKE stops at NUL and treats %/_ as wildcards, with no ESCAPE.
    parts=re.split('[%_]',term.split('\0',1)[0].translate(FOLD));tokens=set()
    for part in parts:
        if len(part)==1:tokens.add('u'+format(ord(part),'06x'))
        for a,b in zip(part,part[1:]):tokens.add('b'+format(ord(a),'06x')+format(ord(b),'06x'))
    # A subset is a safe prefilter. Keep query compilation bounded.
    return ' AND '.join(sorted(tokens)[:64])

def install(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS audit_search_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),low_id INTEGER NOT NULL,high_id INTEGER NOT NULL,indexed_rows INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_search_documents(id INTEGER PRIMARY KEY,fingerprint BLOB UNIQUE NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_search_rows(id INTEGER PRIMARY KEY,document_id INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS audit_search_document_rows ON audit_search_rows(document_id,id);
    CREATE VIRTUAL TABLE IF NOT EXISTS audit_search_grams USING fts5(grams,content='',detail=none,columnsize=0,tokenize='ascii');
    ''')
    if not db.execute('SELECT 1 FROM audit_search_state').fetchone():
        last=head(db)[0];db.execute('INSERT INTO audit_search_state VALUES(1,?,?,0)',(last+1,last))
    from . import audit_sort
    audit_sort.install(db)

def state(db):return dict(db.execute('SELECT low_id,high_id,indexed_rows FROM audit_search_state WHERE singleton=1').fetchone())

def ready(db,clause,values,person_join='',time_filtered=False):
    value=state(db);source='event_headers_time' if time_filtered else 'event_headers'
    suffix=(' AND ' if clause else 'WHERE ')+'(e.id<? OR e.id>?)'
    missing=db.execute('SELECT 1 FROM '+source+' e '+person_join+clause+suffix+' LIMIT 1',tuple(values)+(value['low_id'],value['high_id'])).fetchone()
    return not missing,value

@serialized
def index_batch(store,stop=None,tail_only=False,*,cooperative=False):
    if stop and stop.is_set():return False
    if cooperative and store.ingest_active.is_set():return False
    if shutil.disk_usage(store.path.parent).free<256*1024*1024:raise OSError('搜尋索引空間不足，請保留至少 256 MiB 可用空間')
    # Index connections must not drain daily event staging as a side effect.
    # Receipt owns durability/flush; derived work is independently retryable.
    with store.connect(flush_events=False) as db:
        before=state(db);last=head(db)[0];forward=before['high_id']<last
        if tail_only and not forward:return False
        limit=100 if cooperative else 500
        sql=f'SELECT id,details FROM events WHERE id>? ORDER BY id LIMIT {limit}' if forward else f'SELECT id,details FROM events WHERE id<? ORDER BY id DESC LIMIT {limit}'
        records=[];size=0;started=time.monotonic()
        for row in db.execute(sql,(before['high_id'] if forward else before['low_id'],)):
            if stop and stop.is_set():return False
            if cooperative and store.ingest_active.is_set():return False
            records.append((row['id'],grams(row['details'])));size+=len(row['details'])
            if size>=2*1024*1024:break
            if cooperative and time.monotonic()-started>=.05:break
    if not records and (forward or before['low_id']==0):return False
    if stop and stop.is_set():return False
    if cooperative and store.ingest_active.is_set():return False
    with store.connect(flush_events=False) as db:
        db.execute('PRAGMA busy_timeout='+('25' if cooperative else '250'));db.execute('BEGIN IMMEDIATE')
        if state(db)!=before:return True
        written=[];started=time.monotonic()
        for identifier,tokens in records:
            if stop and stop.is_set():db.rollback();return False
            if cooperative and store.ingest_active.is_set():break
            document=0
            if tokens is not None:
                fingerprint=hashlib.sha256(tokens.encode('ascii')).digest()
                found=db.execute('SELECT id FROM audit_search_documents WHERE fingerprint=?',(fingerprint,)).fetchone()
                if found:document=found[0]
                else:
                    document=db.execute('INSERT INTO audit_search_documents(fingerprint) VALUES(?)',(fingerprint,)).lastrowid
                    db.execute('INSERT INTO audit_search_grams(rowid,grams) VALUES(?,?)',(document,tokens))
            db.execute('INSERT INTO audit_search_rows VALUES(?,?)',(identifier,document))
            written.append(identifier)
            if cooperative and time.monotonic()-started>=.025:break
        # Only the COMMITTED prefix is covered, including yield mid-batch.
        low=before['low_id'];high=before['high_id']
        if forward:
            if written:high=written[-1]
        elif written:low=written[-1]
        elif not records:low=0
        db.execute('UPDATE audit_search_state SET low_id=?,high_id=?,indexed_rows=indexed_rows+? WHERE singleton=1',(low,high,len(written)))
    return bool(written) or low!=before['low_id']

class Worker:
    def __init__(self,store):
        self.store=store;self.stop=threading.Event();self.error='';self.request_until=0
        self.thread=threading.Thread(target=self.run,daemon=True,name='GuardDesk-SearchIndex');self.thread.start()
    def request(self):
        self.request_until=time.monotonic()+3;self.store.index_wakeup.set()
    def run(self):
        with background_work():
            keeper=sqlite3.connect(self.store.path,timeout=2)
            try:
                while not self.stop.is_set():
                    self.store.index_wakeup.clear()
                    if self.store.ingest_active.is_set():
                        self.stop.wait(.1);continue
                    try:
                        changed=index_batch(self.store,self.stop,cooperative=True)
                        from . import audit_sort
                        changed=audit_sort.index_batch(self.store,self.stop,cooperative=True) or changed
                        self.error=''
                    except (sqlite3.Error,ValueError,OSError) as exc:
                        if getattr(exc,'sqlite_errorcode',0)&255 in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED):
                            self.stop.wait(1);continue
                        if not self.error:logging.getLogger('guarddesk').exception('Search index update temporarily failed')
                        changed=False;self.error='搜尋索引暫時無法更新，請檢查儲存空間與管理中心紀錄'
                    # Automatic from first receipt/startup, even with no query.
                    # Short slices and a mandatory quiet gap bound shared I/O.
                    # Wakeups shorten idle sleep, never the post-write throttle.
                    if changed:self.stop.wait(.05 if time.monotonic()<self.request_until else .1)
                    else:self.store.index_wakeup.wait(1)
            finally:keeper.close()
    def close(self):
        self.stop.set()
        self.store.index_wakeup.set()
        if self.thread.is_alive():self.thread.join(3)
