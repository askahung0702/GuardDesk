"""Owned data and handler streams only. No management center or endpoint launch."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from guarddesk import release_scope, update_dispatch, update_progress, update_retention, updates
from guarddesk.management import ManagementError
from guarddesk.server import Handler
from guarddesk.store import Store
from guarddesk.update_packages import signer, public_key, verify


class DispatchTest(unittest.TestCase):
    def setUp(self):
        owned=tempfile.TemporaryDirectory()
        self.addCleanup(owned.cleanup)
        self.store=Store(Path(owned.name)/'owned.db')
        self.user={'username':'owned-mis'}
        self._guard=patch('socketserver.TCPServer.__init__',side_effect=AssertionError('No local center'))
        self._guard.start()
        self.addCleanup(self._guard.stop)
        self.version='0.4.117'
        self.now=time.time()

    def release(self,db,target=None,*,file=False):
        target=target or self.version
        data=(target+' owned payload').encode()
        rid=hashlib.sha256(data).hexdigest()
        db.execute('INSERT INTO update_releases VALUES (?,?,?,?,?)',
                   (rid,target,json.dumps({'payload':{'bytes':len(data)}}),self.now,'owned'))
        scope=release_scope.profile(target,{'format':1,'version':target,'scope':'endpoint',
            'components':list(release_scope.COMPONENTS),'min_compatible_agent':'0.4.12','required_updater':'0.4.69'})
        db.execute('INSERT INTO update_release_scope VALUES (?,?)',(rid,json.dumps(scope)))
        if file:
            folder=self.store.path.parent/'update-packages'
            folder.mkdir(exist_ok=True)
            (folder/(rid+'.zip')).write_bytes(data)
        return rid

    def device(self,db,n,online=False):
        did=f'{n:024x}'
        db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',
                   (did,f'owned-{n}',f'Owned-{n}','Owned',self.now if online else self.now-1000))
        return did

    def poll(self,db,did,broker='0.4.117',resume=False):
        body={'role':'native','version':'0.4.116'}
        if broker is not None:body['broker_version']=broker
        if resume:body['resume_protocol']=True
        return updates.agent_route(self.store,db,{'id':did},'/poll',body)

    def report(self,db,did,jid,state,version='0.4.116',role='native'):
        return updates.agent_route(self.store,db,{'id':did},'/status',
                                   {'job_id':jid,'role':role,'state':state,'version':version})

    def confirm(self,db,preview,ready_only=False):
        return updates.create_jobs(db,self.user,{'confirm':'deploy','preview_id':preview['preview_id'],'ready_only':ready_only})

    def test_component_reports_update_progress_without_appending_audit_events(self):
        with self.store.connect() as db:
            rid=self.release(db)
            did=self.device(db,1,online=True)
            self.poll(db,did)
            kind='update.component_status'
            Store.event(db,did,kind,'info',{'state':'healthy'},event_id='historical-status')
            jid=updates.create_jobs(db,self.user,{'confirm':'deploy','release_id':rid,'device_ids':[did]})['job_ids'][0]
            self.report(db,did,jid,'applying')
            self.report(db,did,jid,'healthy',self.version)
            failure={'job_id':jid,'role':'main','version':'0.4.116','state':'failed','error':'health_check_failed'}
            for _ in range(2):
                result=updates.agent_route(self.store,db,{'id':did},'/api/agent/updates/status',failure)
                self.assertTrue(result['ok'])
            job=updates.catalog(db)['jobs'][0]
            self.assertEqual(job['status'],'failed')
            self.assertEqual(job['components']['native']['state'],'healthy')
            self.assertEqual(job['components']['main']['error'],failure['error'])
            history=db.execute('SELECT event_id FROM events WHERE kind=?',(kind,)).fetchall()
            self.assertEqual([row['event_id'] for row in history],['historical-status'])

    def test_broker_status_cannot_erase_or_refresh_a_version_report(self):
        with self.store.connect() as db:
            rid=self.release(db);did=self.device(db,1,online=True)
            self.poll(db,did)
            before=tuple(db.execute('SELECT version,received FROM update_broker_presence WHERE device_id=?',(did,)).fetchone())
            job=updates.create_jobs(db,self.user,{'confirm':'deploy','device_ids':[did],'release_id':rid})['job_ids'][0]
            with patch('time.time',return_value=before[1]+89):
                self.report(db,did,job,'healthy',self.version)
                self.report(db,did,job,'healthy',self.version,'main')
                stale=db.execute('SELECT version,received FROM update_broker_presence WHERE device_id=?',(did,)).fetchone()
                self.assertEqual(tuple(stale),before)
                self.assertEqual(db.execute("SELECT broker_version FROM update_presence WHERE role='native'").fetchone()[0],self.version)
            self.assertEqual(update_dispatch.broker_state(db,did,'0.4.69',before[1]+90),'waiting')
            self.poll(db,did)
            self.assertEqual(update_dispatch.broker_state(db,did,'0.4.69',time.time()),'ready')

    def test_mixed_batch_reserves_one_offline_and_rechecks_broker_and_slots_on_reconnect(self):
        with self.store.connect() as db:
            rid=self.release(db)
            ids=[self.device(db,n) for n in range(4)]
            for did in ids[:3]:self.poll(db,did)
            draft=update_dispatch.preview(db,self.user,{'release_id':rid,'all_endpoints':True})
            self.assertEqual([r['state'] for r in draft['targets']],['ready','ready','ready','waiting'])
            reply=self.confirm(db,draft)
            jids=reply['job_ids']
            self.assertEqual((reply['scheduled'],reply['reserved']),(3,1))
            self.assertEqual(self.confirm(db,draft),reply)
            self.assertEqual(db.execute('SELECT count(*) FROM update_jobs').fetchone()[0],4)
            with self.assertRaises(ManagementError):updates.valid_job(db,{'id':ids[3]},jids[3])
            self.assertIsNotNone(self.poll(db,ids[0])['job'])
            self.assertIsNotNone(self.poll(db,ids[1])['job'])
            self.assertEqual(self.poll(db,ids[2])['waiting_for'],'batch_slot')
            self.assertEqual(self.poll(db,ids[3],'0.4.68')['waiting_for'],'needs_check')
            self.assertEqual(self.poll(db,ids[3],None)['waiting_for'],'waiting')
            self.assertEqual(self.poll(db,ids[3])['waiting_for'],'batch_slot')
            self.assertEqual(db.execute('SELECT status FROM update_jobs WHERE id=?',(jids[3],)).fetchone()[0],'reserved')
            self.report(db,ids[0],jids[0],'waiting')
            packet=self.poll(db,ids[3],resume=True)['job']
            key=public_key(signer(self.store.path.parent))
            self.assertEqual(verify(packet,key)['transfer_role'],'native')
            self.assertEqual(db.execute('SELECT status FROM update_jobs WHERE id=?',(jids[3],)).fetchone()[0],'pending')

    def test_two_hundred_device_snapshot_and_revocation_before_confirmation(self):
        with self.store.connect() as db:
            rid=self.release(db)
            ids=[self.device(db,n) for n in range(200)]
            draft=update_dispatch.preview(db,self.user,{'release_id':rid,'all_endpoints':True})
            after=self.device(db,200)
            db.execute('UPDATE devices SET revoked=1 WHERE id=?',(ids[-1],))
            reply=self.confirm(db,draft)
            self.assertEqual((reply['reserved'],reply['skipped']),(199,1))
            self.assertEqual(set(r[0] for r in db.execute('SELECT device_id FROM update_jobs')),set(ids[:-1]))
            self.assertNotIn(after,set(r[0] for r in db.execute('SELECT device_id FROM update_jobs')))

    def test_preview_ready_only_and_cancel_or_expire_reservations(self):
        with self.store.connect() as db:
            rid=self.release(db);ready=self.device(db,1);offline=self.device(db,2);later=self.device(db,3)
            self.poll(db,ready)
            ready_preview=update_dispatch.preview(db,self.user,{'release_id':rid,'device_ids':[ready,offline]})
            only=self.confirm(db,ready_preview,ready_only=True)
            self.assertEqual((only['scheduled'],only['reserved'],only['skipped']),(1,0,1))
            saved=self.confirm(db,update_dispatch.preview(db,self.user,{'release_id':rid,'device_ids':[offline,later]}))
            a,b=saved['job_ids']
            self.assertEqual(update_progress.cancel_waiting(db,self.user,{'job_ids':[a],'confirm':'cancel_waiting'})['cancelled'],1)
            db.execute('UPDATE update_jobs SET expires=? WHERE id=?',(self.now-1,b))
            self.assertIsNone(self.poll(db,offline)['job'])
            self.assertIsNone(self.poll(db,later)['job'])

    def test_switch_result_received_after_expiry_does_not_restart_or_reopen_job(self):
        from guarddesk import custom_settings,remote,software,removal
        with self.store.connect() as db:
            rid=self.release(db);did=self.device(db,1);self.poll(db,did)
            job=updates.create_jobs(db,self.user,{'confirm':'deploy','release_id':rid,'device_ids':[did]})['job_ids'][0]
            self.poll(db,did)
            self.report(db,did,job,'applying')
            self.report(db,did,job,'waiting')
            self.assertEqual(updates.component(db,job,'native')['state'],'applying')
            with self.assertRaises(ManagementError):updates.cancel(db,self.user,{'job_id':job})
            db.execute('UPDATE update_jobs SET expires=? WHERE id=?',(self.now-1,job))
            self.assertTrue(software.conflicting(db,did))
            self.assertTrue(custom_settings.busy(db,did))
            self.assertTrue(remote.update_busy(db,did,time.time()))
            with self.assertRaises(ManagementError) as denied:
                removal.request(db,{**self.user,'role':'admin'},{'device_id':did,'confirm_name':'Owned-1','reason':'owned test'})
            self.assertEqual(denied.exception.status,409)
            running=updates.catalog(db,params={'state':['running']})
            self.assertEqual([j['delivery']['code'] for j in running['jobs']],['awaiting_result'])
            self.assertIsNone(self.poll(db,did)['job'])
            self.assertTrue(self.report(db,did,job,'healthy',self.version)['ok'])
            self.assertFalse(software.conflicting(db,did))
            self.assertFalse(custom_settings.busy(db,did))
            self.assertFalse(remote.update_busy(db,did,time.time()))
            self.assertTrue(self.report(db,did,job,'healthy',self.version)['terminal'])
            with self.assertRaises(ManagementError):self.report(db,did,job,'rolled_back','0.4.116')
            self.assertEqual(updates.component(db,job,'native')['state'],'healthy')

    def test_retention_keeps_referenced_old_binary_but_not_new_jobs_or_preview(self):
        with self.store.connect() as db:
            first=self.release(db,'0.4.99',file=True);did=self.device(db,1)
            reservation=self.confirm(db,update_dispatch.preview(db,self.user,{'release_id':first,'all_endpoints':True}))['job_ids'][0]
            for revision in (102,108,113,116,117):self.release(db,f'0.4.{revision}',file=True)
            self.assertEqual([r['version'] for r in update_retention.available(db,self.store)],
                             ['0.4.117','0.4.116','0.4.113','0.4.108','0.4.102'])
            with self.assertRaises(ManagementError):
                update_dispatch.preview(db,self.user,{'release_id':first,'all_endpoints':True})
        folder=self.store.path.parent/'update-packages'
        self.assertEqual(update_retention.cleanup(self.store),0)
        self.assertTrue((folder/(first+'.zip')).is_file())
        with self.store.connect() as db:
            self.assertIsNotNone(self.poll(db,did)['job'])
            _,_,_,lease=updates.begin_download(db,{'id':did},reservation,'native',None)
            updates.cancel(db,self.user,{'job_id':reservation})
        self.assertEqual(update_retention.cleanup(self.store),0)
        with self.store.connect() as db:updates.finish_download(db,lease,False)
        self.assertEqual(update_retention.cleanup(self.store),1)
        self.assertFalse((folder/(first+'.zip')).exists())
        with self.store.connect() as db:
            catalog=updates.catalog(db,store=self.store)
            self.assertEqual((len(catalog['releases']),len(catalog['history_releases'])),(5,6))
            self.assertEqual(catalog['jobs'][0]['version'],'0.4.99')

    def test_broker_maintenance_observes_only_explicit_native_version_reports(self):
        from guarddesk import updater_maintenance
        with self.store.connect() as db:
            rid=self.release(db)
            did=self.device(db,1)
            with patch('time.time',return_value=self.now):
                self.poll(db,did)
            job=self.confirm(db,update_dispatch.preview(db,self.user,{'release_id':rid,'device_ids':[did]}))['job_ids'][0]
            with patch('time.time',return_value=self.now+70):
                self.poll(db,did,None)
                self.poll(db,did)
                self.report(db,did,job,'verifying')
            with patch('time.time',return_value=self.now+170):
                self.report(db,did,job,'verifying')
                observed=updater_maintenance.route(self.store,db,{'id':did},'/observed',{})
                self.assertEqual(observed['presence'],{'broker_version':self.version,'received':self.now+70})

    def test_damaged_new_package_cannot_displace_a_good_fifth_release(self):
        with self.store.connect() as db:
            ids=[self.release(db,f'0.4.{v}',file=True) for v in range(112,118)]
        folder=self.store.path.parent/'update-packages'
        damaged=folder/(ids[-1]+'.zip')
        original=damaged.read_bytes()
        damaged.write_bytes(original[:-1])
        with self.store.connect() as db:
            self.assertEqual([r['id'] for r in update_retention.available(db,self.store)],ids[-2::-1])
        self.assertEqual(update_retention.cleanup(self.store),0)
        damaged.write_bytes(b'x'*len(original))
        self.assertEqual(update_retention.cleanup(self.store),0)
        with self.store.connect() as db:
            self.assertEqual([r['id'] for r in update_retention.available(db,self.store)],ids[-2::-1])
        self.assertTrue((folder/(ids[0]+'.zip')).is_file())
        damaged.write_bytes(original)
        self.assertEqual(update_retention.cleanup(self.store),1)

    def test_migration_requires_a_new_broker_observation_on_destination(self):
        import sqlite3
        from contextlib import closing
        from guarddesk.server_backup import snapshot
        with self.store.connect() as db:
            did=self.device(db,1)
            self.poll(db,did)
        destination=self.store.path.parent/'migration.db'
        snapshot(self.store.path,destination,migration=True)
        with closing(sqlite3.connect(destination)) as copy:
            self.assertEqual(copy.execute('SELECT count(*) FROM update_broker_presence').fetchone()[0],0)
        with self.store.connect() as db:
            self.assertEqual(update_dispatch.broker_state(db,did,'0.4.69',time.time()),'ready')

    def test_simultaneous_reconnects_and_duplicate_confirmation_at_full_selection_limit(self):
        from concurrent.futures import ThreadPoolExecutor
        with self.store.connect() as db:
            rid=self.release(db)
            ids=[self.device(db,n) for n in range(1000)]
            draft=update_dispatch.preview(db,self.user,{'release_id':rid,'all_endpoints':True})
        def confirm(_):
            with self.store.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                return self.confirm(db,draft)
        def reconnect(did):
            with self.store.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                return self.poll(db,did)
        with ThreadPoolExecutor(max_workers=8) as pool:
            first,second=pool.map(confirm,range(2))
            self.assertEqual(first,second)
            self.assertEqual(first['reserved'],1000)
            replies=list(pool.map(reconnect,ids[:200]))
        self.assertEqual(sum(bool(reply['job']) for reply in replies),2)
        self.assertEqual(sum(reply.get('waiting_for')=='batch_slot' for reply in replies),198)

    def test_real_download_handler_range_preserves_identity_and_limits(self):
        with self.store.connect() as db:
            rid=self.release(db,file=True);did=self.device(db,1);other=self.device(db,2)
            self.poll(db,did)
            jid=updates.create_jobs(db,self.user,{'confirm':'deploy','device_ids':[did],'release_id':rid})['job_ids'][0]
            self.poll(db,did)
            with self.assertRaises(ManagementError):updates.begin_download(db,{'id':other},jid,'native','bytes=2-')
            with self.assertRaises(ManagementError) as invalid:updates.begin_download(db,{'id':did},jid,'native','bytes=2-3')
            self.assertEqual(invalid.exception.status,416)
        headers={}
        handler=Handler.__new__(Handler)
        handler.server=SimpleNamespace(store=self.store)
        handler.path='/api/agent/updates/download?job_id='+jid+'&role=native'
        handler.headers={'Range':'bytes=2-'}
        handler.agent=lambda db:{'id':did}
        handler.wfile=io.BytesIO()
        handler.send_response=lambda status:headers.update(status=status)
        handler.send_header=headers.__setitem__
        handler.end_headers=lambda:None
        handler.download_update()
        content=(self.version+' owned payload').encode()
        self.assertEqual(headers['status'],206)
        self.assertEqual(headers['Content-Range'],f'bytes 2-{len(content)-1}/{len(content)}')
        self.assertEqual(handler.wfile.getvalue(),content[2:])
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM update_downloads').fetchone()[0],0)
