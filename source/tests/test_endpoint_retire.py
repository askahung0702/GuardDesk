"""Explicit retirement without fake uninstall, queued serial center deletion."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import threading
from types import SimpleNamespace
import unittest
import urllib.error
from guarddesk import endpoint_purge as purge,event_storage
from guarddesk.management import ManagementError
from guarddesk.store import Store
import test_endpoint_purge as purge_tests


class RetireTest(unittest.TestCase):
    setUp=purge_tests.PurgeTest.setUp
    seed=purge_tests.PurgeTest.seed
    drain=purge_tests.PurgeTest.drain

    def server(self):return SimpleNamespace(remote_lock=threading.RLock(),remote_memory={})
    def body(self,did=None):return {'device_id':did or self.a,'confirm_name':'same-name','acknowledge_scope':True,'acknowledge_no_uninstall':True}
    def retire(self,did=None):
        with self.store.connect() as db:return purge.retire_request(db,self.user,self.body(did),self.server())
    def pending(self,state='failed',did=None):
        did=did or self.a
        with self.store.connect() as db:
            db.execute('UPDATE devices SET revoked=0 WHERE id=?',(did,))
            db.execute("INSERT INTO endpoint_removals VALUES(?,?,?,'fixture',0,99999999999,?,'pending','pending','original failure')",('remove-'+did,did,'admin',state))

    def test_sealed_72_reproduces_failed_uninstall_preview_block(self):
        import types
        from PyInstaller.archive.readers import CArchiveReader
        repository=Path(os.environ.get('GUARDDESK_REPOSITORY_ROOT',Path(__file__).resolve().parents[1]))
        path=repository/'dist/archive/releases/GuardDesk-Center-0.4.72-internal.zip'
        # Use the exact archived source-matching executable already sealed.
        exe=repository/'runtime/center72-src/dist/GuardDesk/GuardDesk.exe'
        self.assertTrue(path.is_file());code=CArchiveReader(str(exe)).open_embedded_archive('PYZ.pyz').extract('guarddesk.endpoint_purge')
        old=types.ModuleType('guarddesk.owned_old_purge');old.__package__='guarddesk';exec(code,old.__dict__)
        self.pending()
        with self.store.connect() as db:
            with self.assertRaisesRegex(ManagementError,'請先完成解除安裝'):old.preview(db,self.user,self.a)
            self.assertEqual(db.execute('SELECT revoked FROM devices WHERE id=?',(self.a,)).fetchone()[0],0)
        self.assertEqual(self.retire()['state'],'running')

    def test_direct_retirement_without_uninstall_revoke_and_no_fake_completion(self):
        self.pending()
        job=self.retire()
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT revoked FROM devices WHERE id=?',(self.a,)).fetchone()[0],1)
            row=db.execute('SELECT status,error FROM endpoint_removals WHERE device_id=?',(self.a,)).fetchone()
            self.assertEqual(tuple(row),('failed','original failure'))
            event=db.execute("SELECT details FROM events WHERE kind='device.retired_without_uninstall'").fetchone()[0]
            value=json.loads(event);self.assertFalse(value['uninstall_verified']);self.assertFalse(value['local_actions_stopped'])
        self.assertEqual(self.retire()['id'],job['id'])

    def test_roles_confirmation_name_and_ack_are_required_before_revocation(self):
        self.pending()
        cases=[{**self.body(),'confirm_name':'wrong'},{**self.body(),'acknowledge_scope':False},
               {**self.body(),'acknowledge_no_uninstall':False},{**self.body(),'acknowledge_no_uninstall':1},
               {**self.body(),'arbitrary_path':'C:\\'}]
        for body in cases:
            with self.store.connect() as db:
                with self.assertRaises(ManagementError):purge.retire_request(db,self.user,body,self.server())
                self.assertEqual(db.execute('SELECT revoked FROM devices WHERE id=?',(self.a,)).fetchone()[0],0)
        with self.store.connect() as db:
            with self.assertRaises(ManagementError):purge.retire_request(db,{'username':'reader','role':'auditor'},self.body(),self.server())
            with self.assertRaises(ManagementError):purge.retire_preview(db,{'role':'support'},self.a)

    def test_all_incomplete_removal_states_can_be_retired_without_claiming_done(self):
        for i,state in enumerate(('queued','running','failed','expired')):
            did=chr(ord('c')+i)*24
            with self.store.connect() as db:db.execute('INSERT INTO devices(id,token,name,department,last_seen,revoked) VALUES(?,?,?,?,?,0)',(did,did,'same-name','IT',0))
            self.pending(state,did);self.retire(did)
            with self.store.connect() as db:self.assertEqual(db.execute('SELECT status FROM endpoint_removals WHERE device_id=?',(did,)).fetchone()[0],state)

    def test_active_remote_is_closed_before_retirement_guard_is_installed(self):
        self.pending();server=self.server();server.remote_memory['session']={'input_batches':3}
        with self.store.connect() as db:
            db.execute("INSERT INTO remote_sessions VALUES('session',?,'admin','owned-login','active','view','',0,99999999999,0,0,'')",(self.a,))
            purge.retire_request(db,self.user,self.body(),server)
            row=db.execute("SELECT status,ended_reason FROM remote_sessions WHERE id='session'").fetchone()
            self.assertEqual(tuple(row),('closed','administrator_retired_endpoint'))
        self.assertNotIn('session',server.remote_memory)

    def test_inflight_center_jobs_do_not_require_late_endpoint_reports(self):
        import time
        self.pending()
        with self.store.connect() as db:
            db.execute("INSERT INTO update_releases VALUES('release','0.4.69','{}',0,'admin')")
            db.execute("INSERT INTO update_jobs VALUES('job',?,'release','admin',0,?,1,0,'pending')",(self.a,time.time()+100))
            db.execute("INSERT INTO updater_refresh VALUES(?,'id','job','0.4.69',0,?,'active')",(self.a,time.time()+100))
            db.execute('INSERT INTO custom_action_leases VALUES(?,?,?)',(self.a,'owned-lease',time.time()+100))
        self.assertEqual(self.retire()['state'],'running')
        self.drain()
        with self.store.connect() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM devices WHERE id=?',(self.a,)).fetchone())
            self.assertIsNotNone(db.execute('SELECT 1 FROM devices WHERE id=?',(self.b,)).fetchone())

    def test_queued_retirement_immediate_revoke_pause_and_automatic_following(self):
        self.seed();a=self.retire();self.pending(did=self.b);b=self.retire(self.b)
        self.assertEqual(b['state'],'queued')
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT revoked FROM devices WHERE id=?',(self.b,)).fetchone()[0],1)
            db.execute("UPDATE endpoint_purges SET state='paused' WHERE id=?",(a['id'],))
        self.assertFalse(purge.step(self.store))
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT state FROM endpoint_purges WHERE id=?',(b['id'],)).fetchone()[0],'queued')
            purge.retry(db,self.user,{'id':a['id']})
        self.store=Store(self.store.path);self.drain()
        with self.store.connect() as db:
            self.assertEqual([r[0] for r in db.execute('SELECT state FROM endpoint_purges')],['completed','completed'])
            self.assertEqual(db.execute('SELECT count(*) FROM devices').fetchone()[0],0)
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])
        self.assertTrue(self.store.verify()['valid'])

    def test_queued_daily_cleanup_preserves_same_name_third_endpoint_and_restarts(self):
        with self.store.connect() as db:event_storage.enable(db,self.store.path,snapshot_backup=False)
        self.seed();c='c'*24
        with self.store.connect() as db:
            db.execute('INSERT INTO devices(id,token,name,department,last_seen,revoked) VALUES(?,?,?,?,?,0)',(c,c,'same-name','IT',0))
            Store.event(db,c,'file.opened','info',{'path':'KEEP THIRD'})
        self.retire();self.retire(self.b);purge.step(self.store)
        self.store=Store(self.store.path);self.drain();event_storage.flush(self.store)
        with self.store.connect() as db:
            rows=list(db.execute('SELECT device_id,details FROM events WHERE device_id=?',(c,)))
            self.assertEqual(len(rows),1);self.assertIn('KEEP THIRD',rows[0]['details'])
            self.assertEqual([r[0] for r in db.execute('SELECT id FROM devices')],[c])
            self.assertFalse(db.execute('SELECT 1 FROM endpoint_purge_days').fetchone())
        self.assertTrue(self.store.verify()['valid'])

    def test_two_concurrent_admin_requests_have_only_one_running_worker_job(self):
        barrier=threading.Barrier(2);results=[];errors=[]
        def submit(did):
            try:barrier.wait(10);results.append(self.retire(did))
            except Exception as exc:errors.append(type(exc).__name__+':'+str(exc))
        threads=[threading.Thread(target=submit,args=(did,)) for did in (self.a,self.b)]
        for t in threads:t.start()
        for t in threads:t.join(15)
        self.assertFalse(any(t.is_alive() for t in threads));self.assertEqual(errors,[])
        self.assertEqual(sorted(r['state'] for r in results),['queued','running'])

    def test_queued_identity_blocks_late_writes(self):
        self.retire();self.retire(self.b)
        for sql,args in [('UPDATE devices SET revoked=0 WHERE id=?',(self.b,)),
                         ('INSERT INTO custom_status VALUES(?,?,?,?)',(self.b,'main','{}',0)),
                         ("UPDATE endpoint_removals SET status='completed' WHERE device_id=?",(self.b,))]:
            if 'endpoint_removals' in sql:continue
            with self.assertRaises(sqlite3.IntegrityError):
                with self.store.connect() as db:db.execute(sql,args)

    def test_preview_is_metadata_only_and_standard_deletion_keeps_old_gate(self):
        self.pending()
        with self.store.connect() as db:
            queries=[];db.set_trace_callback(queries.append)
            value=purge.retire_preview(db,self.user,self.a)
            self.assertFalse(value['uninstall_verified']);self.assertFalse(value['waits_for_uninstall'])
            self.assertFalse(any('FROM events' in q or 'FROM event_catalog' in q for q in queries))
            with self.assertRaises(ManagementError):purge.preview(db,self.user,self.a)


class RetireHTTPTest(unittest.TestCase):
    def setUp(self):
        import test_system
        test_system.SystemTest.setUp(self);self.server.purge_worker.close()
    def tearDown(self):
        import test_system
        test_system.SystemTest.tearDown(self)
    def api(self,*args,**kwargs):
        import test_system
        return test_system.SystemTest.api(self,*args,**kwargs)
    def test_real_http_csrf_reader_refusal_immediate_old_agent_rejection_and_fresh_identity(self):
        import test_system
        agent,did,_=test_system.SystemTest.make_agent(self)
        with self.store.connect() as db:
            db.execute("INSERT INTO endpoint_removals VALUES('stuck',?,'admin','fixture',0,99999999999,'failed','pending','pending','old failure')",(did,))
        body={'device_id':did,'confirm_name':'test-endpoint','acknowledge_scope':True,'acknowledge_no_uninstall':True}
        with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/devices/purge/retire',body,csrf=False)
        self.assertEqual(error.exception.code,403)
        self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/devices/purge/retire',body)
        self.assertEqual(error.exception.code,403)
        self.csrf=self.api('/api/login',{'username':'admin','password':self.password})['csrf']
        self.assertFalse(self.api('/api/devices/purge/retire-preview?device_id='+did)['uninstall_verified'])
        self.assertEqual(self.api('/api/devices/purge/retire',body)['state'],'running')
        with self.assertRaises(ConnectionError):agent.heartbeat()
        for _ in range(250):
            if not purge.step(self.server.store):break
        else:self.fail('retired data cleanup did not finish')
        self.assertNotIn(did,[d['id'] for d in self.api('/api/state')['devices']])
        from guarddesk.agent import enroll
        code=self.api('/api/enrollments',{})['token']
        fresh=enroll(self.root/'new-after-retire/config.json',self.url,code,self.watch,name='test-endpoint')
        self.assertNotEqual(fresh,did)


if __name__=='__main__':unittest.main()
