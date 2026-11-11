import contextlib
import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from guarddesk import event_storage as storage
from guarddesk.store import Store
from guarddesk.server_backup import snapshot


class DailyEventStorageTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.store=Store(self.root/'control.sqlite3')

    def tearDown(self):self.temp.cleanup()

    def enable(self):
        with self.store.connect() as db:return storage.enable(db,self.store.path)

    def add(self,eid='event',when=None,device='fixture'):
        with self.store.connect() as db:Store.event(db,device,'file.moved','info',{'source_path':r'C:\Owned\before.txt','destination_path':r'D:\Owned\after.txt'},eid,when)

    def test_legacy_preserved_daily_queries_hashes_and_restart(self):
        self.add('legacy',123);before=self.store.verify();self.enable();self.add('daily',456)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM events_legacy').fetchone()[0],1)
            rows=list(db.execute('SELECT * FROM events ORDER BY id'));self.assertEqual(len(rows),2)
            self.assertEqual(rows[0]['hash'],before['head'])
            self.assertEqual(json.loads(rows[1]['details'])['destination_path'],r'D:\Owned\after.txt')
            day=db.execute('SELECT day FROM event_catalog').fetchone()[0]
            self.assertTrue(storage.day_file(self.store.path,day).is_file())
            self.assertEqual(db.execute('SELECT count(*) FROM event_pending').fetchone()[0],0)
        self.assertTrue(Store(self.store.path).verify()['valid'])

    def test_received_day_boundary_and_late_occurred_events(self):
        self.enable()
        midnight=dt.datetime(2026,10,20,tzinfo=dt.timezone(dt.timedelta(hours=8))).timestamp()
        with patch('guarddesk.event_storage.time.time',return_value=midnight-.1):self.add('yesterday',1)
        with patch('guarddesk.event_storage.time.time',return_value=midnight+.1):self.add('today',1)
        with self.store.connect() as db:
            self.assertEqual([r[0] for r in db.execute('SELECT day FROM event_catalog ORDER BY id')],['20261019','20261020'])
            self.assertEqual(db.execute('SELECT count(*) FROM events WHERE occurred=1').fetchone()[0],2)
        self.assertTrue(self.store.verify()['valid'])

    def test_pending_failure_restart_and_idempotent_replay(self):
        self.enable()
        with patch('guarddesk.event_storage.day_file',side_effect=OSError('owned simulated disk error')):self.add()
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM event_pending').fetchone()[0],1)
            self.assertEqual(json.loads(db.execute('SELECT details FROM events').fetchone()[0])['source_path'],r'C:\Owned\before.txt')
        self.add() # Replayed event ID is acknowledged without another event.
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM event_pending').fetchone()[0],0)
        self.assertTrue(self.store.verify()['valid'])

    def test_cross_device_duplicate_and_transaction_rollback(self):
        self.enable();self.add()
        with self.assertRaises(ValueError):self.add(device='other-device')
        with self.assertRaises(RuntimeError):
            with self.store.connect() as db:
                Store.event(db,'fixture','file.deleted','info',{},'rolled-back')
                raise RuntimeError('owned rollback')
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0],1)

    def test_missing_or_modified_day_fails_instead_of_returning_empty(self):
        self.enable();self.add()
        with self.store.connect() as db:day=db.execute('SELECT day FROM event_catalog').fetchone()[0]
        path=storage.day_file(self.store.path,day)
        with contextlib.closing(sqlite3.connect(path)) as con:
            con.execute("UPDATE events SET payload=x'00'");con.commit()
        self.assertFalse(self.store.verify()['valid'])
        path.unlink()
        with self.store.connect() as db:self.assertEqual(storage.status(db,self.store.path)['days'][0]['state'],'missing')

    def test_consistent_backup_copies_days_and_can_restore(self):
        self.add('legacy');self.enable();self.add('daily')
        target=self.root/'backup.sqlite3';result=snapshot(self.store.path,target)
        self.assertEqual(len(result['event_day_files']),1)
        restored=Store(target);self.assertTrue(restored.verify()['valid'])
        with restored.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0],2)

    def test_pending_bound_and_blob_expansion_bound(self):
        self.enable()
        with patch('guarddesk.event_storage.MAX_PENDING',10):
            with self.assertRaises(ValueError):self.add()
        import zlib
        with self.assertRaises(ValueError):storage.unpack(zlib.compress(b'X'*(storage.MAX_EVENT+1)))
        self.assertTrue(self.store.verify()['valid'])

    def test_path_rejection_and_activation_backup_preserves_original(self):
        self.add('legacy');result=self.enable()
        backup=self.root/'StorageBackups'/result['backup']
        with contextlib.closing(sqlite3.connect(backup)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0],1)
            self.assertEqual(db.execute("SELECT type FROM sqlite_master WHERE name='events'").fetchone()[0],'table')
        with self.assertRaises(ValueError):storage.day_file(self.store.path,'../../escape')

    def test_crash_after_day_commit_replays_without_loss_or_duplicates(self):
        self.enable()
        with patch('guarddesk.event_storage.finalize',side_effect=sqlite3.OperationalError('owned crash before catalog commit')):
            self.add('committed-day')
            with self.store.connect() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM event_pending').fetchone()[0],1)
                day=db.execute('SELECT day FROM event_catalog').fetchone()[0]
            with contextlib.closing(sqlite3.connect(storage.day_file(self.store.path,day))) as con:
                self.assertEqual(con.execute('SELECT count(*) FROM events').fetchone()[0],1)
        restored=Store(self.store.path)
        self.assertTrue(restored.verify()['valid'])
        with restored.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM event_pending').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0],1)

    def test_dictionary_codec_and_compact_catalog_preserve_exact_values(self):
        self.enable()
        identifier='0123456789abcdef0123456789abcdef'
        with self.store.connect() as db:
            Store.event(db,'fixture','web.navigation','warning',{'url':'https://example.invalid/測試?key=1','path':r'C:\Owned\很長的檔名.docx'},identifier,123)
        with self.store.connect() as db:
            row=dict(db.execute('SELECT * FROM events').fetchone())
            self.assertEqual(row['event_id'],identifier)
            self.assertIn('很長的檔名',row['details'])
            self.assertEqual(db.execute('SELECT length(event_id),length(hash) FROM event_catalog').fetchone()[:],(17,32))
        self.assertTrue(self.store.verify()['valid'])

    def test_cursor_limit_does_not_expand_unselected_day_payloads(self):
        self.enable()
        with self.store.connect() as db:
            for i in range(240):Store.event(db,'fixture','file.deleted','info',{'path':str(i)},'bounded-page-'+str(i))
        with self.store.connect() as db:
            calls=[]
            db.create_function('event_value',2,lambda identifier,field:calls.append((identifier,field)) or '{}')
            rows=list(db.execute('SELECT id,details FROM events WHERE id<? ORDER BY id DESC LIMIT 50',(230,)))
            self.assertEqual(len(rows),50)
            self.assertLessEqual(len(calls),52)
            plan=' '.join(str(r[3]) for r in db.execute('EXPLAIN QUERY PLAN SELECT id,details FROM events WHERE id<? ORDER BY id DESC LIMIT 50',(230,)))
            self.assertIn('MERGE',plan)
