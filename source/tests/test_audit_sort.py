"""Global ordering over immutable mixed-storage evidence, not current-page sort."""
import csv,io,json,sqlite3,time,unittest
import urllib.error
from contextlib import contextmanager
from urllib.parse import urlencode
from unittest.mock import patch
import test_system
from guarddesk import audit_sort,audit_search,audit_search_index,event_storage as storage
from guarddesk.store import Store

class AuditSortTest(unittest.TestCase):
    def setUp(self):
        test_system.SystemTest.setUp(self);self.server.search_index.close()
        self.server.audit_service.stop.set();self.server.audit_service.index_thread.join(3)
        _,self.did,_=self.make_agent();self.now=time.time()-100
        for phase in range(2):
            with self.store.connect() as db:
                if phase:storage.enable(db,self.store.path,snapshot_backup=False)
                for i in range(65):
                    n=phase*65+i
                    d={'source_path':['',r'C:\Owned\乙.docx',r'C:\Owned\a.docx',r'C:\Owned\A.docx'][n%4],
                       'path':r'C:\Owned\fallback.docx','process':['','brave.exe','LINE.exe'][n%3],
                       'user':['','EXAMPLE\\乙','EXAMPLE\\dev'][n%3],'destination_path':['','D:\\目的地','C:\\Target'][n%3],
                       'browser':['Edge','Chrome'][n%2],'title':['','會議','Alpha'][n%3],'url':'https://example.com/'+str(n%7),'file_name':str(n)}
                    Store.event(db,self.did,'file.created' if n%2 else 'file.deleted','info',d,'sort-'+str(n),self.now+(n*17)%130)
        self.query={'device':self.did,'category':'files','cursor_mode':1,'limit':13,'start':self.now-1,'end':self.now+131}
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def build(self):
        for _ in range(20):
            if not audit_sort.index_batch(self.store):break
        with self.store.connect() as db:self.assertTrue(audit_sort.ready(db,'',())[0])
    def all_pages(self,q):
        first=self.api('/api/events?'+urlencode(q));rows=list(first['items']);snapshot=first['snapshot']
        while first['has_more']:
            first=self.api('/api/events?'+urlencode({**q,'cursor':first['next_cursor']}));rows+=first['items'];self.assertEqual(first['snapshot'],snapshot)
        self.assertEqual(len({r['id'] for r in rows}),len(rows));return rows

    def test_all_columns_both_directions_global_order_and_original_chain(self):
        before=self.store.verify();self.build()
        with self.store.connect() as db:
            original=[dict(r) for r in db.execute("SELECT * FROM events WHERE device_id=? AND kind IN ('file.created','file.deleted')",(self.did,))]
        for field in (*audit_sort.METADATA,*audit_sort.FIELDS):
            def value(row):
                if field in audit_sort.FIELDS:return audit_sort.keys(row['details'])[audit_sort.FIELDS.index(field)].translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'))
                if field=='device':return 'test-endpoint'
                return row[field]
            for direction in ('asc','desc'):
                expected=[r['id'] for r in sorted(original,key=lambda r:(value(r),r['id']),reverse=direction=='desc')]
                actual=self.all_pages({**self.query,'sort':field,'direction':direction})
                self.assertEqual([r['id'] for r in actual],expected,(field,direction))
        self.assertEqual(self.store.verify(),before)

    def test_pending_is_not_empty_and_csv_refuses_unprepared_keys(self):
        q={**self.query,'sort':'path','direction':'asc'}
        r=self.api('/api/events?'+urlencode(q));self.assertTrue(r['search_pending']);self.assertEqual(r['search_index']['purpose'],'sort');self.assertNotIn('items',r)
        with self.assertRaises(urllib.error.HTTPError) as exc:self.api('/api/events.csv?'+urlencode(q))
        self.assertEqual(exc.exception.code,409);exc.exception.close()
        self.build();self.assertEqual(len(self.all_pages(q)),130)

    def test_snapshot_new_arrival_and_sort_tamper_rejected(self):
        self.build();q={**self.query,'sort':'path','direction':'asc'};first=self.api('/api/events?'+urlencode(q));ids=[r['id'] for r in first['items']]
        with self.store.connect() as db:Store.event(db,self.did,'file.deleted','info',{'path':'000-first'},'after-sort-snapshot',self.now)
        # New rows outside the snapshot do not require waiting for index catch-up.
        token=first['next_cursor']
        for change in ({'sort':'process'},{'direction':'desc'},{'q':'changed'}):
            with self.assertRaises(urllib.error.HTTPError) as exc:self.api('/api/events?'+urlencode({**q,**change,'cursor':token}))
            self.assertEqual(exc.exception.code,400);exc.exception.close()
        while first['has_more']:
            first=self.api('/api/events?'+urlencode({**q,'cursor':first['next_cursor']}));ids += [r['id'] for r in first['items']]
        self.assertEqual(len(ids),130);self.assertEqual(len(set(ids)),130)

    def test_device_rename_invalidates_cursor_instead_of_duplicate_rows(self):
        q={**self.query,'sort':'device'};first=self.api('/api/events?'+urlencode(q))
        with self.store.connect() as db:db.execute('UPDATE devices SET name=? WHERE id=?',('renamed',self.did))
        with self.assertRaises(urllib.error.HTTPError) as exc:self.api('/api/events?'+urlencode({**q,'cursor':first['next_cursor']}))
        self.assertEqual(exc.exception.code,400);exc.exception.close()

    def test_distinct_computers_and_category_filter_remain_global(self):
        with self.store.connect() as db:
            db.execute("INSERT INTO devices(id,token,name,department,last_seen) VALUES('owned-second','fixture-token','AA-PC','Owned',?)",(self.now,))
            Store.event(db,'owned-second','file.deleted','info',{'path':'Owned second'},'second-file',self.now)
            Store.event(db,'owned-second','web.navigation','info',{'url':'https://example.com'},'second-web',self.now)
        q={k:v for k,v in self.query.items() if k!='device'}
        rows=self.all_pages({**q,'sort':'device','direction':'asc'})
        self.assertEqual(len(rows),131);self.assertEqual(rows[0]['device_name'],'AA-PC')
        self.assertTrue(all(r['kind'].startswith('file.') for r in rows))

    def test_sort_identifiers_reads_no_original_payload_and_long_keys_not_truncated(self):
        with self.store.connect() as db:
            for i in (2,1):Store.event(db,self.did,'file.deleted','info',{'path':'C:\\'+('長'*9000)+str(i)},'long-key-'+str(i),self.now)
        self.build()
        with patch.object(storage.Reader,'value',side_effect=AssertionError('sorting must not decompress evidence')):
            with self.store.connect() as db:
                ids,_=audit_search.identifiers(db,"WHERE e.device_id=? AND e.family='file'",(self.did,),'','',500,sort='path',direction='asc')
                self.assertEqual(len(ids),132)
        with self.store.connect() as db:
            long_ids=[r[0] for r in db.execute("SELECT id FROM events WHERE event_id IN ('long-key-1','long-key-2') ORDER BY event_id")]
        self.assertEqual([x for x in ids if x in long_ids],long_ids)

    def test_csv_order_same_as_global_pages_and_keyword_scope_preserved(self):
        self.build()
        while audit_search_index.index_batch(self.store):pass
        q={**self.query,'q':'Owned','sort':'path','direction':'asc'}
        expected=[r['id'] for r in self.all_pages(q)]
        data=self.api('/api/events.csv?'+urlencode({**q,'limit':5000})).decode('utf-8-sig')
        self.assertEqual([int(r['id']) for r in csv.DictReader(io.StringIO(data))],expected)

    def test_sql_input_cancel_deadline_and_capacity_release(self):
        for extra in ({'sort':'path;DROP TABLE devices'},{'direction':'asc;--'}):
            with self.assertRaises(urllib.error.HTTPError) as exc:self.api('/api/events?'+urlencode({**self.query,**extra}))
            self.assertEqual(exc.exception.code,400);exc.exception.close()
        self.build();import threading
        cancel=threading.Event();cancel.set()
        with self.store.connect() as db:
            with self.assertRaises(audit_search.SearchCancelled):audit_search.identifiers(db,'',(),'','',51,sort='path',cancel=cancel)
            with self.assertRaises(audit_search.SearchTimeout):audit_search.identifiers(db,'',(),'','',51,sort='path',seconds=-1)
            self.assertEqual(db.execute('SELECT 1').fetchone()[0],1)
        with patch.object(audit_search,'identifiers',side_effect=audit_search.SearchTimeout):
            with self.assertRaises(urllib.error.HTTPError) as exc:self.api('/api/events?'+urlencode({**self.query,'sort':'occurred'}))
            self.assertEqual(exc.exception.code,408);exc.exception.close()
        slots=self.server.event_search_slots;self.assertTrue(slots.acquire(False));self.assertTrue(slots.acquire(False));slots.release();slots.release()

    def test_ingestion_priority_disk_failure_and_restart_coverage(self):
        before=self.store.verify()
        with self.store.connect(event_ingest=True),patch.object(audit_sort,'keys',side_effect=AssertionError('ingestion first')):
            self.assertFalse(audit_sort.index_batch(self.store,cooperative=True))
        with patch.object(audit_sort.shutil,'disk_usage',return_value=type('Disk',(),{'free':0})()):
            with self.assertRaises(OSError):audit_sort.index_batch(self.store)
        # Failed preparation changes no coverage or mappings; reopening resumes.
        with patch.object(audit_sort,'keys',side_effect=ValueError('owned failure')):
            with self.assertRaises(ValueError):audit_sort.index_batch(self.store)
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM audit_sort_rows').fetchone()[0],0)
        self.store=Store(self.db);self.build();self.assertEqual(self.store.verify(),before)

    def test_extractor_missing_nontext_and_full_fallbacks(self):
        self.assertEqual(audit_sort.keys('{}'),('',)*8)
        self.assertEqual(audit_sort.keys('[]'),('',)*8)
        self.assertEqual(audit_sort.keys(json.dumps({'path':{'x':1},'process':42})),('',)*8)
        values=audit_sort.keys(json.dumps({'path':'fallback','url':'url','file_name':'name','title':'標題'}))
        self.assertEqual(values[1],'fallback');self.assertEqual(values[2],'標題');self.assertEqual(values[-1],'name')

    def test_mid_write_ingestion_commits_only_contiguous_prefix_and_restarts(self):
        original=self.store.connect;active=self.store.ingest_active
        class Proxy:
            def __init__(self,db):self.db=db
            def execute(self,sql,*args):
                result=self.db.execute(sql,*args)
                if sql.startswith('INSERT INTO audit_sort_rows'):active.set()
                return result
            def __getattr__(self,name):return getattr(self.db,name)
        @contextmanager
        def connection(**kwargs):
            with original(**kwargs) as db:yield Proxy(db)
        for backwards in (False,True):
            with original() as db:
                db.execute('DELETE FROM audit_sort_rows');db.execute('DELETE FROM audit_sort_values')
                last=storage.head(db)[0]
                db.execute('UPDATE audit_sort_state SET low_id=?,high_id=?,indexed_rows=0',(last+1 if backwards else 1,last if backwards else 0))
            with patch.object(self.store,'connect',connection):self.assertTrue(audit_sort.index_batch(self.store,cooperative=True))
            active.clear()
            with original() as db:
                value=audit_sort.state(db);rows=[r[0] for r in db.execute('SELECT id FROM audit_sort_rows')]
                self.assertEqual(len(rows),1);self.assertEqual(value['indexed_rows'],1)
                self.assertEqual(value['low_id'] if backwards else value['high_id'],rows[0])
            self.build()

    def test_mid_transaction_failure_rolls_back_dictionary_rows_and_progress(self):
        # Keep a real nonempty baseline. Startup can legitimately prepare one
        # row before the fixture stops background indexing; rollback must retain
        # that data, rather than assuming every test database begins empty.
        self.assertTrue(audit_sort.index_batch(self.store,cooperative=True))
        original=self.store.connect
        class Proxy:
            def __init__(self,db):self.db=db
            def execute(self,sql,*args):
                result=self.db.execute(sql,*args)
                if sql.startswith('INSERT INTO audit_sort_rows'):raise sqlite3.OperationalError('owned disk write failure')
                return result
            def __getattr__(self,name):return getattr(self.db,name)
        @contextmanager
        def connection(**kwargs):
            with original(**kwargs) as db:yield Proxy(db)
        with original() as db:
            before=audit_sort.state(db)
            rows_before=[tuple(r) for r in db.execute('SELECT * FROM audit_sort_rows ORDER BY id')]
            values_before=[tuple(r) for r in db.execute('SELECT * FROM audit_sort_values ORDER BY id')]
            self.assertTrue(rows_before)
        with patch.object(self.store,'connect',connection):
            with self.assertRaises(sqlite3.OperationalError):audit_sort.index_batch(self.store)
        with original() as db:
            self.assertEqual(audit_sort.state(db),before)
            self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM audit_sort_rows ORDER BY id')],rows_before)
            self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM audit_sort_values ORDER BY id')],values_before)
        self.build();self.assertTrue(self.store.verify()['valid'])

    def test_default_refresh_without_replacement_nonce_does_not_cancel_other_tab(self):
        import threading
        self.build()
        while audit_search_index.index_batch(self.store):pass
        started=threading.Event();release=threading.Event();errors=[];original=audit_search.identifiers
        def observed(*args,**kwargs):
            if args[4]=='owned-slow-tab':
                started.set()
                if not release.wait(3):raise AssertionError('owned blocked query was not released')
                if kwargs['cancel'].is_set():raise audit_search.SearchCancelled()
                return [],None
            return original(*args,**kwargs)
        def manual_query():
            try:self.api('/api/events?'+urlencode({**self.query,'q':'owned-slow-tab','request_id':'1'*32,'sort':'occurred'}))
            except Exception as exc:errors.append(str(exc))
        with patch.object(audit_search,'identifiers',side_effect=observed):
            thread=threading.Thread(target=manual_query);thread.start()
            try:
                self.assertTrue(started.wait(2))
                # The client sends no replacement nonce for automatic refresh.
                self.api('/api/events?'+urlencode({**self.query,'sort':'occurred'}))
                active=list(self.server.event_search_registry.active.values())
                self.assertEqual(len(active),1);self.assertFalse(active[0].is_set())
            finally:release.set();thread.join(4)
        self.assertFalse(errors,errors)

if __name__=='__main__':unittest.main()
