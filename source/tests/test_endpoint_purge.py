import json
import secrets
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from guarddesk.store import Store,canonical
from guarddesk import endpoint_purge as purge
from guarddesk import audit_search_index,audit_sort,audit_reports,event_storage
from guarddesk.management import ManagementError


class PurgeTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'control.sqlite3')
        self.a='a'*24;self.b='b'*24;self.user={'username':'admin','role':'admin'}
        with self.store.connect() as db:
            for did in (self.a,self.b):db.execute('INSERT INTO devices(id,token,name,department,last_seen,revoked) VALUES(?,?,?,?,?,1)',(did,did,'same-name','IT',0))

    def queue(self):
        with self.store.connect() as db:return purge.request(db,self.user,{'device_id':self.a,'confirm_name':'same-name','acknowledge_scope':True})

    def drain(self,limit=1000):
        for _ in range(limit):
            if not purge.step(self.store):return
        self.fail('purge did not finish')

    def seed(self,n=9):
        with self.store.connect() as db:
            for i in range(n):
                Store.event(db,self.a if i%2==0 else self.b,'file.opened','info',{'path':'private-only-A' if i%2==0 else 'private-only-B','user':'shared-person'},occurred=time.time())
        while audit_search_index.index_batch(self.store):pass
        while audit_sort.index_batch(self.store):pass
        while audit_reports.index_batch(self.store):pass

    def test_legacy_full_relations_chain_sibling_and_sort_dictionaries(self):
        self.seed()
        with self.store.connect() as db:
            before=[dict(r) for r in db.execute('SELECT * FROM events WHERE device_id=?',(self.b,))]
            for did in (self.a,self.b):
                db.execute('INSERT INTO custom_settings VALUES(?,?,?,?,?,?)',('device',did,1,'{}','admin',0))
                db.execute('INSERT INTO custom_settings_history VALUES(?,?,?,?,?,?)',('device',did,1,'{}','admin',0))
                db.execute('INSERT INTO native_usb_status VALUES(?,?,?)',(did,'{}',0))
                db.execute('INSERT INTO remote_presence VALUES(?,?,?,?)',(did,'fixture',0,0))
                db.execute('INSERT INTO remote_admin_grants VALUES(?,?,?)',('admin',did,1))
            db.execute("INSERT INTO custom_settings VALUES('global','',1,'{}','admin',0)")
            # Child references must be removed before their parent.
            db.execute("INSERT INTO update_releases VALUES('release','0.4.69','{}',0,'admin')")
            db.execute("INSERT INTO update_jobs VALUES('job',?,'release','admin',0,0,1,0,'completed')",(self.a,))
            db.execute("INSERT INTO update_status VALUES('job','main','ready','0.4.69','',0)")
            db.execute("INSERT INTO update_job_preparations VALUES('job','{}',0)")
        self.queue();self.drain()
        with self.store.connect() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM devices WHERE id=?',(self.a,)).fetchone())
            self.assertEqual([dict(r) for r in db.execute('SELECT * FROM events WHERE device_id=?',(self.b,))],before)
            self.assertEqual(db.execute('SELECT count(*) FROM events WHERE device_id=?',(self.a,)).fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM event_deletions').fetchone()[0],5)
            for table in ('native_usb_status','remote_presence','remote_admin_grants','audit_daily'):
                self.assertIsNone(db.execute('SELECT 1 FROM '+table+' WHERE device_id=?',(self.a,)).fetchone())
                self.assertIsNotNone(db.execute('SELECT 1 FROM '+table+' WHERE device_id=?',(self.b,)).fetchone())
            self.assertEqual(db.execute('SELECT count(*) FROM custom_settings').fetchone()[0],2)
            self.assertEqual(db.execute('SELECT count(*) FROM update_jobs').fetchone()[0],0)
            self.assertIsNotNone(db.execute("SELECT 1 FROM update_releases WHERE id='release'").fetchone())
            self.assertIsNone(db.execute("SELECT 1 FROM audit_sort_values WHERE value='private-only-A'").fetchone())
            self.assertIsNotNone(db.execute("SELECT 1 FROM audit_sort_values WHERE value='private-only-B'").fetchone())
            self.assertIsNotNone(db.execute("SELECT 1 FROM audit_sort_values WHERE value='shared-person'").fetchone())
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])
            with self.assertRaises(ValueError):Store.event(db,self.a,'file.opened','info',{})
            Store.event(db,self.b,'file.opened','info',{'after':'purge'})
        result=self.store.verify();self.assertTrue(result['valid']);self.assertEqual(result['authorized_deleted'],5)

    def test_daily_physical_resume_after_catalog_commit_and_pending(self):
        with self.store.connect() as db:event_storage.enable(db,self.store.path,snapshot_backup=False)
        self.seed(11)
        self.queue()
        purge.step(self.store) # catalog removal + durable day IDs
        with self.store.connect(flush_events=False) as db:
            intent=list(db.execute('SELECT * FROM endpoint_purge_days'))
            self.assertEqual(len(intent),6)
        # Model power loss after a daily commit but before its cleanup receipt.
        for r in intent:
            with closing(sqlite3.connect(event_storage.day_file(self.store.path,r['day']))) as daily:
                with daily:daily.execute('DELETE FROM events WHERE id=?',(r['event_row'],))
        # Reopen Store exactly as Server startup; no lost in-memory cursor.
        self.store=Store(self.store.path)
        self.drain()
        event_storage.flush(self.store)
        for r in intent:
            with closing(sqlite3.connect(event_storage.day_file(self.store.path,r['day']))) as daily:
                self.assertIsNone(daily.execute('SELECT 1 FROM events WHERE id=?',(r['event_row'],)).fetchone())
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM event_pending').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM endpoint_purge_days').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT sum(rows) FROM event_storage_daily').fetchone()[0],db.execute('SELECT count(*) FROM event_catalog').fetchone()[0])
        self.assertTrue(self.store.verify()['valid'])

    def test_preview_no_history_read_and_guards(self):
        with self.store.connect() as db:
            queries=[];db.set_trace_callback(queries.append)
            p=purge.preview(db,self.user,self.a)
            self.assertFalse(p['history_counted'])
            self.assertFalse(any('FROM events' in q or 'FROM event_catalog' in q for q in queries))
            for body in ({'device_id':'../x','confirm_name':'same-name','acknowledge_scope':True},
                         {'device_id':self.a,'confirm_name':'bad','acknowledge_scope':True},
                         {'device_id':self.a,'confirm_name':'same-name','acknowledge_scope':False}):
                with self.assertRaises(ManagementError):purge.request(db,self.user,body)
            with self.assertRaises(ManagementError):purge.preview(db,{'role':'auditor'},self.a)
            db.execute('UPDATE devices SET revoked=0 WHERE id=?',(self.a,))
            with self.assertRaises(ManagementError):purge.preview(db,self.user,self.a)

    def test_completed_uninstall_allowed_and_immediate_credential_revocation(self):
        with self.store.connect() as db:
            db.execute('UPDATE devices SET revoked=0 WHERE id=?',(self.a,))
            db.execute("INSERT INTO endpoint_removals VALUES('uninstall',?,'admin','fixture',0,99999999999,'completed','ready','ready','')",(self.a,))
        job=self.queue()
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT revoked FROM devices WHERE id=?',(self.a,)).fetchone()[0],1)
        self.assertEqual(self.queue()['id'],job['id'])

    def test_late_metadata_writes_blocked_and_rollup_skips_retired_rows(self):
        with self.store.connect() as db:
            for _ in range(3):Store.event(db,self.a,'file.opened','info',{'path':'retiring'})
            Store.event(db,self.b,'file.opened','info',{'path':'sibling'})
        self.queue()
        for sql,args in [('UPDATE devices SET revoked=0 WHERE id=?',(self.a,)),
                         ('INSERT INTO custom_status VALUES(?,?,?,?)',(self.a,'main','{}',0)),
                         ("INSERT INTO custom_settings VALUES('device',?,1,'{}','admin',0)",(self.a,))]:
            with self.assertRaises(sqlite3.IntegrityError):
                with self.store.connect() as db:db.execute(sql,args)
        while audit_reports.index_batch(self.store):pass
        with self.store.connect() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM audit_daily WHERE device_id=?',(self.a,)).fetchone())
            self.assertIsNotNone(db.execute('SELECT 1 FROM audit_daily WHERE device_id=?',(self.b,)).fetchone())
        self.drain()

    def test_busy_leases_uninstall_remote_and_exports_refused(self):
        cases=[("INSERT INTO custom_action_leases VALUES(?,'token',?)",(self.a,time.time()+100),'custom_action_leases'),
               ("INSERT INTO updater_refresh VALUES(?,'id','job','0.4.69',0,?,'active')",(self.a,time.time()+100),'updater_refresh'),
               ("INSERT INTO endpoint_removals VALUES('uninstall',?,'admin','test',0,99999999999,'running','ready','pending','')",(self.a,),'endpoint_removals'),
               ("INSERT INTO remote_sessions VALUES('remote',?,'admin','token','active','view','',0,0,0,0,'')",(self.a,),'remote_sessions')]
        for sql,args,table in cases:
            with self.store.connect() as db:
                db.execute(sql,args)
                with self.assertRaises(ManagementError):purge.preview(db,self.user,self.a)
                db.execute('DELETE FROM '+table)
        self.queue()
        from guarddesk.audit_archive import create_job,AuditError
        with self.store.connect() as db:
            with self.assertRaises(AuditError):create_job(db,'admin',{'start':'2026-10-30','end':'2026-10-30'})
            with self.assertRaises(ValueError):event_storage.enable(db,self.store.path,False)

    def test_corrupt_event_rolls_back_batch_and_is_not_fabricated_success(self):
        self.seed()
        with self.store.connect() as db:db.execute("UPDATE events SET hash=? WHERE device_id=?",('0'*64,self.a))
        self.queue()
        with self.assertRaises(ValueError):purge.step(self.store)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM event_deletions').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM events WHERE device_id=?',(self.a,)).fetchone()[0],5)

    def test_sort_backfill_during_gc_preserves_new_reference(self):
        self.seed();self.queue()
        # Stop at completed full scan, then insert a late sort reference just
        # as real backfill can do with an old, previously unindexed ID.
        for _ in range(200):
            purge.step(self.store)
            with self.store.connect() as db:
                phase=db.execute('SELECT phase FROM endpoint_purges').fetchone()[0]
            if phase=='sort_cleanup':break
        with self.store.connect() as db:
            value=db.execute("SELECT id FROM audit_sort_values WHERE value='private-only-A'").fetchone()[0]
            ids=(value,)*8
            db.execute('INSERT INTO audit_sort_rows VALUES('+','.join('?'*9)+')',(999999,*ids))
            db.executemany('UPDATE endpoint_purge_values SET keep=1 WHERE value_id=?',[(v,) for v in set(ids)])
        self.drain()
        with self.store.connect() as db:self.assertIsNotNone(db.execute('SELECT 1 FROM audit_sort_values WHERE id=?',(value,)).fetchone())

    def test_large_history_seeks_and_bounded_transaction(self):
        # 100,000 unrelated rows must not be decoded or counted for preview
        # or the first delete slice. Preserve a real chained target event.
        with self.store.connect() as db:
            db.executemany('INSERT INTO events(event_id,device_id,kind,severity,occurred,received,details,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?)',
                ((f'bulk-{i}',self.b,'application.started','info',0,0,'{}','0'*64,'0'*64) for i in range(100000)))
            for i in range(130):Store.event(db,self.a,'file.opened','info',{'path':'owned-fixture'})
            plan=[r[3] for r in db.execute('EXPLAIN QUERY PLAN SELECT id FROM events WHERE device_id=? ORDER BY id LIMIT ?',(self.a,purge.BATCH))]
            self.assertTrue(any('events_device' in x and 'SEARCH' in x for x in plan))
        self.queue()
        with patch.object(event_storage.Reader,'value',side_effect=AssertionError('legacy must not decode daily payload')):
            self.assertTrue(purge.step(self.store))
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT removed FROM endpoint_purges').fetchone()[0],purge.BATCH)
            self.assertEqual(db.execute('SELECT count(*) FROM events WHERE device_id=?',(self.b,)).fetchone()[0],100000)

    def test_unflushed_daily_payload_and_crash_after_day_commit(self):
        with self.store.connect() as db:event_storage.enable(db,self.store.path,snapshot_backup=False)
        with self.store.connect(flush_events=False) as db:
            for i in range(3):Store.event(db,self.a,'file.opened','info',{'path':'pending-only'})
        with patch('guarddesk.event_storage.flush'):
            self.queue();self.drain()
        with self.store.connect(flush_events=False) as db:
            self.assertIsNone(db.execute('SELECT 1 FROM events WHERE device_id=?',(self.a,)).fetchone())
            self.assertIsNone(db.execute('SELECT 1 FROM endpoint_purge_days').fetchone())
            self.assertEqual(db.execute('SELECT removed FROM endpoint_purges').fetchone()[0],3)

    def test_old_daily_reader_drains_before_physical_delete(self):
        with self.store.connect() as db:event_storage.enable(db,self.store.path,snapshot_backup=False)
        self.seed(3)
        with self.store.connect(flush_events=False) as reader:
            reader.execute('BEGIN')
            eid=reader.execute('SELECT id FROM events WHERE device_id=? LIMIT 1',(self.a,)).fetchone()[0]
            self.queue();purge.step(self.store);purge.step(self.store);purge.step(self.store)
            # Previously opened snapshot still reads its referenced day data.
            self.assertIsNotNone(reader.execute('SELECT details FROM events WHERE id=?',(eid,)).fetchone())
            with self.store.connect() as db:self.assertEqual(db.execute('SELECT phase FROM endpoint_purges').fetchone()[0],'days')
        self.drain()
        self.assertTrue(self.store.verify()['valid'])

    def test_pause_retry_and_center_backup_guard(self):
        self.seed();job=self.queue();purge.step(self.store)
        from guarddesk.server_backup import snapshot
        with self.assertRaises(ValueError):snapshot(self.store.path,self.store.path.parent/'not-valid.sqlite3')
        with self.store.connect() as db:db.execute("UPDATE endpoint_purges SET state='paused'")
        self.assertFalse(purge.step(self.store))
        with self.store.connect() as db:
            purge.retry(db,self.user,{'id':job['id']})
            with self.assertRaises(ManagementError):purge.retry(db,self.user,{'id':job['id']})
        self.drain()
        copy=self.store.path.parent/'after-cleanup.sqlite3'
        self.assertTrue(snapshot(self.store.path,copy)['source_modified'] is False)


class PurgeHTTPTest(unittest.TestCase):
    def setUp(self):
        import test_system
        test_system.SystemTest.setUp(self)
        # Deterministic inspection of the HTTP response before background work.
        self.server.purge_worker.close()
    def tearDown(self):
        import test_system
        test_system.SystemTest.tearDown(self)
    def api(self,*args,**kwargs):
        import test_system
        return test_system.SystemTest.api(self,*args,**kwargs)
    def test_real_http_csrf_reader_revoke_delete_and_fresh_enroll(self):
        import test_system
        agent,did,_=test_system.SystemTest.make_agent(self)
        with self.store.connect() as db:
            db.execute("INSERT INTO endpoint_removals VALUES('owned-remove',?,'admin','fixture',0,99999999999,'completed','ready','ready','')",(did,))
        body={'device_id':did,'confirm_name':'test-endpoint','acknowledge_scope':True}
        with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/devices/purge',body,csrf=False)
        self.assertEqual(error.exception.code,403)
        self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        for path in ('/api/devices/purge','/api/devices/purge/preview?device_id='+did):
            with self.assertRaises(urllib.error.HTTPError) as error:self.api(path)
            self.assertEqual(error.exception.code,403)
        with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/devices/purge',body)
        self.assertEqual(error.exception.code,403)
        self.csrf=self.api('/api/login',{'username':'admin','password':self.password})['csrf']
        self.assertEqual(self.api('/api/devices/purge/preview?device_id='+did)['device_id'],did)
        job=self.api('/api/devices/purge',body)
        self.assertEqual(job['state'],'running')
        with self.assertRaises(ConnectionError):agent.heartbeat()
        for _ in range(200):
            if not purge.step(self.server.store):break
        else:self.fail('HTTP purge not finished')
        self.assertNotIn(did,[d['id'] for d in self.api('/api/state')['devices']])
        with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/device-detail?device_id='+did)
        self.assertEqual(error.exception.code,404)
        self.assertEqual(self.api('/api/devices/purge')['jobs'][0]['state'],'completed')
        from guarddesk.agent import enroll
        code=self.api('/api/enrollments',{})['token']
        fresh=enroll(self.root/'fresh-agent/config.json',self.url,code,self.watch,name='test-endpoint')
        self.assertNotEqual(fresh,did)
        self.assertTrue(self.server.store.verify()['valid'])


if __name__=='__main__':unittest.main()
