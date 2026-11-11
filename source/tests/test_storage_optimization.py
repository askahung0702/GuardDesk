"""Owned databases only: lossless migration, read isolation and offline lease."""
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import test_system
from guarddesk.store import Store
from guarddesk import event_storage as storage
from guarddesk.storage_maintenance import DatabaseLease,migrate_batch,optimize


class OptimizationTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.store=Store(self.root/'control.sqlite3')
    def tearDown(self):self.tmp.cleanup()
    def seed(self,n=8):
        with self.store.connect() as db:
            for i in range(n):Store.event(db,'fixture','file.deleted','info',{'path':f'C:\\Owned\\{i}.docx','padding':'fixture '*100},f'old-{i}',1700000000+i)
    def original(self):
        with self.store.connect() as db:return [dict(r) for r in db.execute('SELECT * FROM events ORDER BY id')]

    def test_full_optimize_backup_rows_hashes_and_resume(self):
        self.seed(260);before=self.original();result=optimize(self.store.path)
        self.assertTrue(result['passed']);self.assertEqual(result['moved'],260)
        self.assertEqual(self.original(),before);self.assertTrue(self.store.verify()['valid'])
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM events_legacy').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM event_catalog').fetchone()[0],260)
        backup=Store(result['backup']['path'])
        with backup.connect() as db:self.assertEqual([dict(r) for r in db.execute('SELECT * FROM events ORDER BY id')],before)
        self.assertEqual(optimize(self.store.path)['moved'],0)

    def test_failed_daily_write_preserves_durable_payload_and_restart_continues(self):
        self.seed(260);before=self.original()
        with self.store.connect() as db:storage.enable(db,self.store.path)
        with patch('guarddesk.event_storage.day_file',side_effect=OSError('owned disk failure')):
            with self.assertRaises(ValueError):migrate_batch(self.store,limit=128)
        self.assertEqual(self.original(),before)
        # Partial migration leaves low catalog IDs and higher legacy IDs.
        # New online arrivals must use the highest of both, including its hash.
        with self.store.connect() as db:Store.event(db,'fixture','web.navigation','info',{'url':'https://example.invalid/'},'after-crash')
        with self.store.connect() as db:self.assertEqual(db.execute("SELECT id FROM events WHERE event_id='after-crash'").fetchone()[0],261)
        self.assertTrue(self.store.verify()['valid'])
        self.assertEqual(optimize(self.store.path)['moved'],132)
        self.assertEqual(self.original()[:260],before)

    def test_corrupt_history_stops_without_deleting_or_compacting(self):
        self.seed()
        with self.store.connect() as db:db.execute("UPDATE events SET details='{}' WHERE id=3")
        with self.assertRaisesRegex(ValueError,'雜湊'):optimize(self.store.path)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM events_legacy').fetchone()[0],8)
            self.assertEqual(db.execute('SELECT count(*) FROM event_catalog').fetchone()[0],0)
        self.assertTrue(list((self.root/'StorageBackups').glob('before-optimize-*.sqlite3')))

    def test_lease_denies_other_server_and_optimizer_and_releases(self):
        self.seed()
        with DatabaseLease(self.store.path):
            with self.assertRaises(ValueError):DatabaseLease(self.store.path)
            with self.assertRaises(ValueError):optimize(self.store.path)
        with DatabaseLease(self.store.path) as lease:
            retained=lease.retain();retained.close()
            with self.assertRaises(ValueError):DatabaseLease(self.store.path)
        with DatabaseLease(self.store.path):pass

    def test_insufficient_space_and_header_reads_do_not_open_payloads(self):
        self.seed()
        with patch('guarddesk.storage_maintenance.shutil.disk_usage',return_value=type('Disk',(),{'free':0})()):
            with self.assertRaises(ValueError):optimize(self.store.path)
        self.assertFalse((self.root/'StorageBackups').exists())
        with self.store.connect() as db:storage.enable(db,self.store.path)
        while migrate_batch(self.store):pass
        with patch.object(storage.Reader,'value',side_effect=AssertionError('metadata must not read payload')):
            with self.store.connect() as db:
                self.assertEqual(storage.head(db)[0],8)
                self.assertEqual(db.execute("SELECT count(*) FROM event_headers WHERE family='file'").fetchone()[0],8)
                self.assertEqual(db.execute("SELECT id FROM event_headers WHERE family='file' ORDER BY id DESC LIMIT 1").fetchone()[0],8)

    def test_header_backfill_recovers_and_reopening_store_does_not_rewrite(self):
        self.seed()
        with self.store.connect() as db:storage.enable(db,self.store.path)
        while migrate_batch(self.store):pass
        with self.store.connect() as db:db.execute("UPDATE event_catalog SET family=''")
        Store(self.store.path)
        with self.store.connect() as db:self.assertEqual(db.execute("SELECT count(*) FROM event_headers WHERE family='file'").fetchone()[0],8)
        before=self.store.path.read_bytes();Store(self.store.path)
        self.assertEqual(self.store.path.read_bytes(),before)

    def test_cached_wal_writers_bound_handles_and_backup_contains_committed_rows(self):
        from guarddesk.server_backup import snapshot
        self.store.storage_writer=storage.DayWriter()
        try:
            with self.store.connect() as db:storage.enable(db,self.store.path)
            for i in range(4):
                with patch('guarddesk.event_storage.time.time',return_value=1700000000+i*86400):
                    with self.store.connect() as db:Store.event(db,'fixture','file.deleted','info',{'path':'owned'},f'wal-{i}')
                self.assertLessEqual(len(self.store.storage_writer.handles),2)
            target=self.root/'wal-backup.sqlite3';result=snapshot(self.store.path,target)
            self.assertEqual(len(result['event_day_files']),4);self.assertTrue(Store(target).verify()['valid'])
        finally:self.store.storage_writer.close();self.store.storage_writer=None

    def test_overview_uses_indexed_headers_and_counts_mixed_storage_exactly(self):
        now=1700000000
        for phase in range(2):
            if phase:
                with self.store.connect() as db:storage.enable(db,self.store.path)
            for name,kind,received in [('expired','agent.audit_gap',now-90000),('recent','agent.audit_gap',now),('blocked','export.blocked',now)]:
                with patch('guarddesk.store.time.time',return_value=received):
                    with self.store.connect() as db:Store.event(db,'fixture',kind,'warning',{},f'{phase}-{name}')
        with patch.object(storage.Reader,'value',side_effect=AssertionError('overview must not hydrate payload')):
            with self.store.connect() as db:self.assertEqual(storage.overview_stats(db,now),{'events':6,'alerts_today':4,'blocked':2})

    def test_metadata_keyset_plan_merges_index_seeks_without_global_sort(self):
        self.seed()
        with self.store.connect() as db:storage.enable(db,self.store.path)
        while migrate_batch(self.store):pass
        with self.store.connect() as db:
            for sql in ('SELECT id,kind FROM event_headers WHERE id>1 ORDER BY id LIMIT 5',
                        "SELECT id FROM event_headers WHERE family='file' ORDER BY id DESC LIMIT 5"):
                plan=' '.join(r[3] for r in db.execute('EXPLAIN QUERY PLAN '+sql))
                self.assertIn('MERGE (UNION ALL)',plan);self.assertNotIn('TEMP B-TREE',plan)


class FastAuditAPITest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def test_daily_list_only_reads_page_payloads_and_state_omits_stats(self):
        _,did,_=self.make_agent()
        with self.store.connect() as db:
            storage.enable(db,self.store.path)
            for i in range(90):Store.event(db,did,'file.deleted','info',{'path':f'C:\\Owned\\{i}.docx'},f'page-{i}')
        self.server.audit_service.stop.set();self.server.audit_service.index_thread.join(3)
        # The persistent search/sort worker is separate from the archive worker.
        # Finish its fixture index before counting only this HTTP page's payload
        # reads; otherwise background work races this global Reader probe.
        self.server.search_index.close()
        from guarddesk import audit_search_index
        while audit_search_index.index_batch(self.store):pass
        calls=[];original=storage.Reader.value
        def observed(reader,identifier,field):calls.append(identifier);return original(reader,identifier,field)
        with patch.object(storage.Reader,'value',observed):
            rows=self.api('/api/events?category=files&cursor_mode=1&limit=10')
            self.assertEqual(len(rows['items']),10);self.assertTrue(rows['has_more'])
            self.assertLessEqual(len(set(calls)),11)
            s=self.api('/api/state?compact=1&stats=0');self.assertIsNone(s['stats'])
        self.assertEqual(self.api('/api/events?category=files&q=Owned&limit=2')['total'],90)

    def test_running_server_rejects_offline_optimizer(self):
        with self.assertRaisesRegex(ValueError,'停止'):optimize(self.store.path)

    def test_server_close_keeps_lease_until_last_worker_finishes(self):
        self.server.audit_service.stop.set();self.server.audit_service.index_thread.join(3)
        self.server.audit_service.archive.close()
        release=threading.Event();worker=threading.Thread(target=release.wait,daemon=True);worker.start()
        self.server.audit_service.archive.thread=worker
        with patch.object(self.server.audit_service,'close'):
            self.server.shutdown();closer=threading.Thread(target=self.server.server_close);closer.start()
            try:
                time.sleep(.1)
                with self.assertRaises(ValueError):DatabaseLease(self.store.path)
                self.assertTrue(closer.is_alive())
            finally:release.set();closer.join(5)
        self.assertFalse(closer.is_alive())
        with DatabaseLease(self.store.path):pass


if __name__=='__main__':unittest.main()
