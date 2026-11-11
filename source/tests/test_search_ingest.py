"""Collection stays durable and idempotent while derived indexing yields/fails."""
import sqlite3,threading,time,unittest
from contextlib import contextmanager
from unittest.mock import patch
import test_system
from guarddesk import audit_search_index as index,event_storage as storage
from guarddesk.agent import request
from guarddesk.store import Store

class SearchIngestTest(unittest.TestCase):
    def setUp(self):
        test_system.SystemTest.setUp(self);self.server.search_index.close()
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def test_receipt_survives_index_failure_and_restart_recovers_without_query(self):
        agent,did,_=self.make_agent();store=self.server.store
        with store.connect() as db:storage.enable(db,store.path,snapshot_backup=False)
        with store.connect() as db:token=agent.config['token'];before=storage.head(db)[0]
        failed=threading.Event()
        def failure(*args,**kwargs):failed.set();raise OSError('owned index disk reserve fixture')
        body={'events':[{'event_id':f'owned-ingest-{i}','kind':'file.deleted','severity':'info','details':{'path':f'C:\\Owned\\{i}.txt'},'occurred':time.time()} for i in range(30)]}
        with patch.object(index,'index_batch',side_effect=failure):
            worker=index.Worker(store)
            try:
                self.assertTrue(failed.wait(2))
                for _ in range(2):
                    reply=request(self.url,'/api/agent/events',body,token)
                    self.assertEqual(len(reply['accepted']),30)
                self.assertTrue(worker.error);self.assertFalse(store.ingest_active.is_set())
            finally:worker.close()
        with store.connect() as db:
            self.assertEqual(storage.head(db)[0],before+30)
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE device_id=? AND kind='file.deleted'",(did,)).fetchone()[0],30)
        worker=index.Worker(Store(store.path))
        try:
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                with store.connect() as db:ready,_=index.ready(db,'',())
                if ready:break
                time.sleep(.05)
            self.assertTrue(ready);self.assertTrue(store.verify()['valid'])
        finally:worker.close()

    def test_queued_ingestion_yields_without_reading_payload_and_cleans_exception(self):
        with self.store.connect() as db:Store.event(db,'owned','file.deleted','info',{'path':'owned'},'owned-priority')
        with self.store.connect(event_ingest=True):
            with patch.object(index,'grams',side_effect=AssertionError('must yield before payload work')):
                self.assertFalse(index.index_batch(self.store,cooperative=True))
            with self.assertRaises(ValueError):
                with self.store.connect(event_ingest=True):raise ValueError('owned failure')
            self.assertTrue(self.store.ingest_active.is_set())
        self.assertFalse(self.store.ingest_active.is_set());self.assertTrue(self.store.index_wakeup.is_set())
        self.assertTrue(index.index_batch(self.store,cooperative=True))

    def test_upload_arrival_mid_write_commits_only_prefix_in_both_directions(self):
        with self.store.connect() as db:
            for i in range(8):Store.event(db,'owned','file.deleted','info',{'path':f'owned-{i}'},f'owned-slice-{i}')
        original=self.store.connect;active=self.store.ingest_active
        with original() as db:total=storage.head(db)[0]
        class Connection:
            def __init__(self,db):self.db=db
            def execute(self,sql,*args):
                result=self.db.execute(sql,*args)
                if sql.startswith('INSERT INTO audit_search_rows'):active.set()
                return result
        @contextmanager
        def arriving(**kwargs):
            with original(**kwargs) as db:yield Connection(db)
        for backwards in (False,True):
            with original() as db:
                db.execute('DELETE FROM audit_search_rows');db.execute('DELETE FROM audit_search_documents');db.execute("INSERT INTO audit_search_grams(audit_search_grams) VALUES('delete-all')")
                db.execute('UPDATE audit_search_state SET low_id=?,high_id=?,indexed_rows=0',(total+1,total) if backwards else (1,0));before=storage.head(db)
            with patch.object(self.store,'connect',side_effect=arriving):self.assertTrue(index.index_batch(self.store,cooperative=True))
            active.clear()
            with original() as db:
                s=index.state(db);self.assertEqual(s['indexed_rows'],1)
                self.assertEqual(s['low_id'] if backwards else s['high_id'],total if backwards else 1)
                self.assertFalse(index.ready(db,'',())[0]);self.assertEqual(storage.head(db),before)
            while index.index_batch(self.store,cooperative=True):pass
            with original() as db:self.assertTrue(index.ready(db,'',())[0]);self.assertEqual(db.execute('SELECT count(*) FROM audit_search_rows').fetchone()[0],total)

    def test_index_connections_never_drain_event_staging(self):
        with self.store.connect() as db:Store.event(db,'owned','file.deleted','info',{'path':'owned'},'owned-no-flush')
        with patch.object(storage,'flush',side_effect=AssertionError('index must not flush receipt staging')):
            self.assertTrue(index.index_batch(self.store,cooperative=True))

    def test_disk_reserve_rolls_back_index_without_changing_source(self):
        with self.store.connect() as db:Store.event(db,'owned','file.deleted','info',{'path':'owned'},'owned-low-disk');before=storage.head(db);state=index.state(db)
        with patch.object(index.shutil,'disk_usage',return_value=type('Usage',(),{'free':255*1024*1024})()):
            with self.assertRaises(OSError):index.index_batch(self.store,cooperative=True)
        with self.store.connect() as db:self.assertEqual(storage.head(db),before);self.assertEqual(index.state(db),state)

    def test_https_listener_shares_receipt_priority_with_console_indexer(self):
        from guarddesk.server import serve
        from test_server_deployment import certificate
        cert,key=certificate(self.root/'owned-tls')
        listener=serve(self.db,port=0,cert=cert,key=key,surface='agent',shared=self.server)
        try:
            self.assertIsNot(listener.store,self.server.store)
            self.assertIs(listener.search_index,self.server.search_index)
            with listener.store.connect(event_ingest=True):
                with self.server.store.connect(event_ingest=True):pass
                self.assertTrue(self.server.store.ingest_active.is_set())
                self.assertFalse(index.index_batch(self.server.store,cooperative=True))
            self.assertFalse(self.server.store.ingest_active.is_set())
            self.assertTrue(self.server.store.index_wakeup.is_set())
        finally:listener.server_close()

if __name__=='__main__':unittest.main()
