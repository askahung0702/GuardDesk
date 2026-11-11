"""Search scopes payload reads before substring matching, including daily data."""
import json,time,unittest
import urllib.error
from urllib.parse import urlencode
from unittest.mock import patch
import test_system
from guarddesk import event_storage as storage,audit_search
from guarddesk.store import Store

class ScopedSearchTest(unittest.TestCase):
    def setUp(self):
        test_system.SystemTest.setUp(self);self.server.search_index.close()
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent
    def test_keyword_search_never_reads_payloads_outside_metadata_filters(self):
        _,did,_=self.make_agent();now=time.time()-100
        self.server.audit_service.stop.set();self.server.audit_service.index_thread.join(3)
        with self.store.connect() as db:storage.enable(db,self.store.path)
        with self.store.connect() as db:
            for i in range(90):
                Store.event(db,did if i%3 else 'other','web.navigation' if i%3==1 else 'file.deleted','info',{'path':r'C:\\Owned\\26C0018.docx'},f'outside-{i}',now-86400 if i%3==2 else now)
            for i in range(7):Store.event(db,did,'file.deleted','info',{'path':r'C:\\Owned\\26C0018.docx'},f'inside-{i}',now)
        allowed=set()
        with self.store.connect() as db:allowed={r[0] for r in db.execute('SELECT id FROM event_headers WHERE device_id=? AND family=? AND occurred>=? AND occurred<?',(did,'file',now-1,now+1))}
        calls=[];original=storage.Reader.value
        def observed(reader,identifier,field):calls.append(identifier);return original(reader,identifier,field)
        q={'q':'26C0018','device':did,'category':'files','kind':'file.deleted','start':now-1,'end':now+1,'end_exclusive':1,'cursor_mode':1,'limit':2}
        with patch.object(storage.Reader,'value',observed):result=self.api('/api/events?'+urlencode(q))
        self.assertEqual(len(result['items']),2);self.assertTrue(result['has_more'])
        self.assertTrue(set(calls)<=allowed,(sorted(set(calls)-allowed),len(calls)))
        self.assertLessEqual(len(set(calls)),3,'cursor search should stop after one page plus a lookahead')
    def test_mixed_storage_same_sql_like_semantics_counts_offsets_and_cursor_pages(self):
        _,did,_=self.make_agent();now=time.time()-10
        self.server.audit_service.stop.set();self.server.audit_service.index_thread.join(3)
        for phase in range(2):
            with self.store.connect() as db:
                if phase:storage.enable(db,self.store.path)
                for i in range(15):Store.event(db,did,'file.deleted','warning' if i%2 else 'info',{'path':r'C:\Owned\26C0018\報告-'+str(i)+'.docx'},f'mixed-{phase}-{i}',now)
        for term in ('26c0018','報告','%','_','file.deleted',"' OR 1=1 --"):
            clause='WHERE e.device_id=?';values=(did,);pattern='%'+term+'%'
            with self.store.connect() as db:
                expected=[r[0] for r in db.execute("SELECT e.id FROM events e LEFT JOIN devices d ON d.id=e.device_id WHERE e.device_id=? AND (e.kind LIKE ? OR e.details LIKE ? OR COALESCE(d.name,'') LIKE ?) ORDER BY e.id DESC",values+(pattern,)*3)]
                result,total=audit_search.identifiers(db,clause,values,'',term,7,3,True)
            self.assertEqual(total,len(expected));self.assertEqual(result,expected[3:10])
        q={'q':'26C0018','device':did,'category':'files','cursor_mode':1,'limit':7}
        first=self.api('/api/events?'+urlencode(q));ids=[r['id'] for r in first['items']]
        with self.store.connect() as db:Store.event(db,did,'file.deleted','info',{'path':'26C0018-new-after-snapshot'},'later',now)
        while first['has_more']:
            first=self.api('/api/events?'+urlencode({**q,'cursor':first['next_cursor']}));ids.extend(r['id'] for r in first['items'])
        self.assertEqual(len(ids),30);self.assertEqual(len(set(ids)),30);self.assertEqual(ids,sorted(ids,reverse=True))
        csv=self.api('/api/events.csv?'+urlencode({'q':'報告','device':did})).decode('utf-8-sig')
        self.assertEqual(len(csv.splitlines()),31);self.assertNotIn('new-after-snapshot',csv)
    def test_metadata_only_term_does_not_read_payload_during_identifier_search(self):
        _,did,_=self.make_agent()
        with self.store.connect() as db:
            storage.enable(db,self.store.path)
            for i in range(8):Store.event(db,did,'file.deleted','info',{'path':'owned'},f'meta-{i}')
        with patch.object(storage.Reader,'value',side_effect=AssertionError('metadata match must not decompress payload')):
            with self.store.connect() as db:
                ids,total=audit_search.identifiers(db,'WHERE e.device_id=?',(did,),'','file.deleted',3)
        self.assertEqual(len(ids),3);self.assertIsNone(total)
    def test_time_header_view_seeks_both_storage_time_indexes_without_payload_reads(self):
        _,did,_=self.make_agent()
        with self.store.connect() as db:
            storage.enable(db,self.store.path)
            with patch.object(storage.Reader,'value',side_effect=AssertionError('headers must not read payloads')):
                plan=' '.join(r[3] for r in db.execute('EXPLAIN QUERY PLAN SELECT id FROM event_headers_time WHERE occurred>=? AND occurred<? ORDER BY id DESC',(1,2)))
            self.assertIn('events_occurred',plan);self.assertIn('event_catalog_occurred',plan)
            self.assertIn('occurred>? AND occurred<?',plan)
    def test_timeout_never_returns_partial_results_and_clears_progress_handler(self):
        _,did,_=self.make_agent()
        with self.store.connect() as db:
            with self.assertRaises(audit_search.SearchTimeout):audit_search.identifiers(db,'WHERE e.device_id=?',(did,),'','missing',3,seconds=0)
            self.assertEqual(db.execute('SELECT 1').fetchone()[0],1)
    def test_search_capacity_timeout_response_and_release_leave_other_pages_available(self):
        _,did,_=self.make_agent();slots=self.server.event_search_slots
        slots.acquire();slots.acquire()
        try:
            with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/events?q=owned')
            self.assertEqual(error.exception.code,429);error.exception.close()
            self.assertIsNone(self.api('/api/state?compact=1&stats=0')['stats'])
        finally:slots.release();slots.release()
        with patch.object(audit_search,'identifiers',side_effect=audit_search.SearchTimeout):
            with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/events?q=owned')
            self.assertEqual(error.exception.code,408);error.exception.close()
        self.assertEqual(self.api('/api/events?q=missing&cursor_mode=1')['items'],[])

if __name__=='__main__':unittest.main()
