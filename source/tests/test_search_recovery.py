"""Sparse substring candidates, rebuild coverage, cancellation and isolation."""
import sqlite3,threading,time,unittest,urllib.error
from contextlib import contextmanager
from urllib.parse import urlencode
from unittest.mock import patch
import test_system
from guarddesk import audit_search,audit_search_index as index,event_storage as storage
from guarddesk.store import Store

class SearchRecoveryTest(unittest.TestCase):
    def setUp(self):
        test_system.SystemTest.setUp(self);self.server.search_index.close()
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent
    def build(self):
        while index.index_batch(self.store):pass
    def test_sparse_missing_unicode_short_wildcard_and_injection_equal_like(self):
        _,did,_=self.make_agent()
        with self.store.connect() as db:
            for i in range(60):Store.event(db,did,'file.deleted','info',{'path':f'C:\\Owned\\{i}.docx','note':['報告','耀','AÄß😀xy','26C0018',"\" AND * OR' "][i%5]},f'legacy-recover-{i}')
        with self.store.connect() as db:storage.enable(db,self.store.path,snapshot_backup=False)
        with self.store.connect() as db:
            for i in range(60):Store.event(db,did,'application.started','info',{'path':'26C0018' if i==2 else 'ordinary','process':'cmd.exe'},f'daily-recover-{i}')
        self.build()
        for term in ('26c0018','not-present','報告','耀','😀','ä','Ä','ß','a%xy','a_xy','%','_',"\" AND * OR'",'cmd','path','26\x00ignored'):
            pattern='%'+term+'%'
            with self.store.connect() as db:
                expected=[r[0] for r in db.execute("SELECT e.id FROM events e LEFT JOIN devices d ON d.id=e.device_id WHERE e.device_id=? AND (e.kind LIKE ? OR e.details LIKE ? OR COALESCE(d.name,'') LIKE ?) ORDER BY e.id DESC",(did,pattern,pattern,pattern))]
                ready,_=index.ready(db,'WHERE e.device_id=?',(did,));self.assertTrue(ready)
                result,total=audit_search.identifiers(db,'WHERE e.device_id=?',(did,),'',term,500,count=True,indexed=True)
            self.assertEqual(result,expected,term);self.assertEqual(total,len(expected))
    def test_repeat_docs_share_index_and_oversize_fallback_remains_searchable(self):
        _,did,_=self.make_agent()
        with self.store.connect() as db:
            for i in range(100):Store.event(db,did,'application.started','info',{'process':'ordinary.exe'},f'repeated-{i}')
            Store.event(db,did,'file.deleted','info',{'path':'RARE-OVERSIZE','padding':'x'*70000},'large-recover')
        self.build()
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(DISTINCT document_id) FROM audit_search_rows WHERE id IN (SELECT id FROM event_headers WHERE kind=?)',('application.started',)).fetchone()[0],1)
            result,_=audit_search.identifiers(db,'WHERE e.device_id=?',(did,),'','RARE-OVERSIZE',50,indexed=True)
            self.assertEqual(len(result),1)
            self.assertEqual(db.execute('SELECT document_id FROM audit_search_rows WHERE id=?',result).fetchone()[0],0)
    def test_recent_first_backfill_resume_and_new_tail_coverage_are_atomic(self):
        _,did,_=self.make_agent()
        with self.store.connect() as db:
            for i in range(700):Store.event(db,did,'file.deleted','info',{'path':'owned'},f'coverage-{i}')
        # Simulate upgrading a populated old control DB: no evidence changed.
        with self.store.connect() as db:
            high=storage.head(db)[0];db.execute('DELETE FROM audit_search_rows');db.execute('DELETE FROM audit_search_documents');db.execute("INSERT INTO audit_search_grams(audit_search_grams) VALUES('delete-all')");db.execute('UPDATE audit_search_state SET low_id=?,high_id=?,indexed_rows=0',(high+1,high));before=storage.head(db)
        self.assertTrue(index.index_batch(self.store))
        with self.store.connect() as db:
            s=index.state(db);self.assertEqual(s['high_id'],high);self.assertGreater(s['low_id'],1)
            self.assertTrue(index.ready(db,'WHERE e.id>=?',(s['low_id'],))[0]);self.assertFalse(index.ready(db,'',())[0])
        restarted=Store(self.store.path);self.assertTrue(index.index_batch(restarted));self.build()
        with self.store.connect() as db:
            self.assertTrue(index.ready(db,'',())[0]);self.assertEqual(storage.head(db),before)
            Store.event(db,did,'file.deleted','info',{'path':'new-tail'},'coverage-tail')
        with self.store.connect() as db:self.assertFalse(index.ready(db,'',())[0])
        self.build()
        with self.store.connect() as db:self.assertTrue(index.ready(db,'',())[0])
    def test_pending_search_does_not_scan_payload_and_plain_list_still_works(self):
        _,did,_=self.make_agent();request='1'*32
        with patch.object(audit_search,'identifiers',side_effect=AssertionError('pending must not run a scan')):
            result=self.api('/api/events?'+urlencode({'q':'rare','request_id':request,'cursor_mode':1}))
        self.assertTrue(result['search_pending']);self.assertNotIn('items',result)
        self.assertTrue(self.api('/api/events?cursor_mode=1')['items'])
        with self.store.connect() as db:Store.event(db,'new-owned','file.deleted','info',{'path':'rare-after-wait'},'new-during-pending')
        self.build();self.assertEqual(self.api('/api/events?'+urlencode({'q':'rare','request_id':request,'cursor_mode':1,'cursor':result['search_cursor']}))['items'],[])
        self.assertEqual(len(self.api('/api/events?'+urlencode({'q':'rare','request_id':'7'*32,'cursor_mode':1}))['items']),1)
    def test_actual_running_search_cancel_is_session_scoped_and_releases_slot(self):
        self.make_agent();self.build();began=threading.Event();result=[];request='2'*32
        def slow(*args,**kwargs):
            began.set();self.assertTrue(kwargs['cancel'].wait(3));raise audit_search.SearchCancelled()
        def fetch():
            try:self.api('/api/events?'+urlencode({'q':'owned','request_id':request,'cursor_mode':1}))
            except urllib.error.HTTPError as exc:result.append(exc.code);exc.close()
        with patch.object(audit_search,'identifiers',side_effect=slow):
            thread=threading.Thread(target=fetch);thread.start();self.assertTrue(began.wait(2))
            self.api('/api/audit/search/cancel',{'request_id':request});thread.join(3)
        self.assertEqual(result,[409]);self.assertEqual(self.server.event_search_registry.active,{})
        self.assertTrue(self.server.event_search_slots.acquire(False));self.server.event_search_slots.release()
        self.server.event_search_slots.acquire();self.server.event_search_slots.acquire()
        try:
            with self.assertRaises(urllib.error.HTTPError) as busy:self.api('/api/events?'+urlencode({'q':'owned','request_id':'8'*32,'cursor_mode':1}))
            self.assertEqual(busy.exception.code,429);busy.exception.close();self.assertEqual(self.server.event_search_registry.active,{})
        finally:self.server.event_search_slots.release();self.server.event_search_slots.release()
        cancelled=threading.Event();cancelled.set()
        with self.store.connect() as db:
            with self.assertRaises(audit_search.SearchCancelled):audit_search.identifiers(db,'',(),'','owned',50,cancel=cancelled)
            self.assertEqual(db.execute('SELECT 1').fetchone()[0],1)
        with self.assertRaises(urllib.error.HTTPError) as exc:self.api('/api/audit/search/cancel',{'request_id':request},csrf=False)
        self.assertEqual(exc.exception.code,403);exc.exception.close()
        registry=audit_search.Registry();a=registry.start('user-a','3'*32);registry.cancel('user-b','3'*32);self.assertFalse(a.is_set())
        b=registry.start('user-a','4'*32);self.assertTrue(a.is_set());self.assertFalse(b.is_set())
    def test_request_identity_does_not_invalidate_cursor_but_filters_still_do(self):
        _,did,_=self.make_agent()
        with self.store.connect() as db:
            for i in range(8):Store.event(db,did,'file.deleted','info',{'path':'owned'},f'cursor-recover-{i}')
        self.build();q={'q':'owned','cursor_mode':1,'limit':3,'device':did,'request_id':'5'*32}
        first=self.api('/api/events?'+urlencode(q));second=self.api('/api/events?'+urlencode({**q,'request_id':'6'*32,'cursor':first['next_cursor']}))
        self.assertFalse({r['id'] for r in first['items']}&{r['id'] for r in second['items']})
        with self.assertRaises(urllib.error.HTTPError) as exc:self.api('/api/events?'+urlencode({**q,'q':'other','cursor':first['next_cursor']}))
        self.assertEqual(exc.exception.code,400);exc.exception.close()
    def test_background_index_runs_without_query_and_stops_cleanly(self):
        ran=threading.Event()
        def batch(*args,**kwargs):ran.set();return True
        with patch.object(index,'index_batch',side_effect=batch):
            worker=index.Worker(self.store)
            try:self.assertTrue(ran.wait(2))
            finally:worker.close()
        self.assertFalse(worker.thread.is_alive())
    def test_failed_index_commit_rolls_back_postings_mapping_and_progress(self):
        _,did,_=self.make_agent()
        with self.store.connect() as db:
            Store.event(db,did,'file.deleted','info',{'path':'atomic-owned-document'},'atomic-index-fixture');before=storage.head(db);state=index.state(db)
        original=self.store.connect
        class Connection:
            def __init__(self,db):self.db=db
            def execute(self,sql,*args):
                if sql.startswith('UPDATE audit_search_state'):raise OSError('owned simulated commit boundary failure')
                return self.db.execute(sql,*args)
        @contextmanager
        def fail_commit(**kwargs):
            with original(**kwargs) as db:yield Connection(db)
        with patch.object(self.store,'connect',side_effect=fail_commit):
            with self.assertRaises(OSError):index.index_batch(self.store)
        with original() as db:
            self.assertEqual(index.state(db),state);self.assertEqual(storage.head(db),before)
            self.assertEqual(db.execute('SELECT count(*) FROM audit_search_rows').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM audit_search_documents').fetchone()[0],0)
            self.assertFalse(db.execute('SELECT rowid FROM audit_search_grams WHERE audit_search_grams MATCH ?',(index.match('atomic'),)).fetchall())
        self.build()
        with original() as db:self.assertTrue(index.ready(db,'',())[0]);self.assertEqual(storage.head(db),before)
    def test_startup_backfills_history_and_first_new_tail_without_query(self):
        _,did,_=self.make_agent()
        with self.store.connect() as db:
            for i in range(600):Store.event(db,did,'file.deleted','info',{'path':'tail-owned'},f'tail-owned-{i}')
            high=storage.head(db)[0];db.execute('UPDATE audit_search_state SET low_id=?,high_id=?,indexed_rows=0',(high+1,high))
        worker=index.Worker(self.store)
        try:
            deadline=time.monotonic()+6
            while time.monotonic()<deadline:
                with self.store.connect() as db:ready,_=index.ready(db,'',())
                if ready:break
                time.sleep(.05)
            self.assertTrue(ready)
            with self.store.connect(event_ingest=True) as db:
                Store.event(db,did,'file.deleted','info',{'path':'fresh-without-query'},'new-tail-maintenance')
            deadline=time.monotonic()+4
            while time.monotonic()<deadline:
                with self.store.connect() as db:current=index.state(db);last=storage.head(db)[0]
                if current['high_id']==last:break
                time.sleep(.05)
            self.assertEqual(current['high_id'],last)
            with self.store.connect() as db:self.assertTrue(index.ready(db,'',())[0])
        finally:worker.close()
        busy=sqlite3.OperationalError('owned contention fixture');busy.sqlite_errorcode=sqlite3.SQLITE_BUSY;ran=threading.Event()
        def contended(*args,**kwargs):ran.set();raise busy
        with patch.object(index,'index_batch',side_effect=contended):
            worker=index.Worker(self.store)
            try:worker.request();self.assertTrue(ran.wait(2));time.sleep(.1);self.assertEqual(worker.error,'')
            finally:worker.close()

if __name__=='__main__':unittest.main()
