"""Exercise the normal console, authenticated ingestion and Agent boundaries without a listener."""
import shutil
import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from guarddesk.agent import Agent, private_write
from guarddesk.management import ManagementError
from guarddesk.native_usb import UsbWorker
from guarddesk.policy import DEFAULT_POLICY, decode_agent_policy, heartbeat_policy
from guarddesk.policy_progress import offline_days
from guarddesk.server import APIError, Handler
from guarddesk.store import Store, digest


class HeartbeatModeTest(unittest.TestCase):
    did = 'a'*24

    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.store=Store(self.root/'center.db')
        self.handler=Handler.__new__(Handler)
        self.handler.headers={'Cookie':'gd_session=fixture','X-CSRF-Token':'csrf','Authorization':'Bearer agent'}
        self.handler.server=SimpleNamespace(store=self.store)
        self.handler.client_address=('test',0)
        with self.store.connect() as db:
            db.execute("INSERT INTO users VALUES ('admin','unused','admin')")
            db.execute("INSERT INTO sessions VALUES (?,'admin','csrf',?)",(digest('fixture'),time.time()+86400))
            db.execute("INSERT INTO devices(id,name,department,token,last_seen,inventory) VALUES (?,'PC','IT',?,?,?)",
                       (self.did,digest('agent'),time.time()-3*86400,'{"asset":"kept"}'))

    def route(self,db,path,body):
        self.handler.path=path
        return self.handler.route(db,'POST',path,body)[0]

    def toggle(self,db,enabled,revision):
        return self.route(db,'/api/devices/heartbeat-mode',{'device_id':self.did,'enabled':enabled,'revision':revision})

    def test_console_actions_and_click(self):
        node=shutil.which('node')
        self.assertIsNotNone(node)
        subprocess.run([node,str(Path(__file__).with_suffix('.cjs'))],check=True,timeout=20)

    def test_software_inventory_sent_once_and_refreshed_on_center_mismatch(self):
        from guarddesk.serialization import canonical
        config=self.root/'client.json'
        private_write(config,{'watch':str(self.root),'device_id':self.did,'server':'http://127.0.0.1:1','token':'agent'})
        client=Agent(config)
        software=['Example Application '+str(n) for n in range(200)]
        sent=[]
        with self.store.connect() as db:
            def transport(server,path,body,*args,**kwargs):
                sent.append(body)
                return self.route(db,path,body)
            with patch('guarddesk.agent.request',side_effect=transport):
                def beat(names,free,host='NEW-PC'):
                    return client.call('/api/agent/heartbeat',{'inventory':{'software':names,'disk_free':free,'hostname':host}})
                beat(software,10,'PC');beat(software,20)
                self.assertIsNone(sent[-1]['inventory'])
                self.assertLess(len(canonical(sent[-1])),len(canonical(sent[0]))//5)
                self.assertEqual(json.loads(db.execute('SELECT inventory FROM devices').fetchone()[0]),
                                 {'software':software,'disk_free':20,'hostname':'NEW-PC'})
                self.assertEqual(db.execute('SELECT name,registered_name FROM devices').fetchone()[:],('NEW-PC','PC'))
                db.execute("UPDATE devices SET inventory='{}'")
                beat(software,30)
                self.assertIsNone(sent[-2]['inventory'])
                self.assertEqual(sent[-1]['inventory']['software'],software)
                changed=software+['New application']
                beat(changed,40)
                self.assertEqual(sent[-1]['inventory']['software'],changed)
                beat([],50)
                self.assertEqual(json.loads(db.execute('SELECT inventory FROM devices').fetchone()[0])['software'],[])
                beat(changed,60)
                self.toggle(db,True,0)
                self.assertTrue(beat(changed,70)['policy']['heartbeat_only'])
                self.assertEqual(json.loads(db.execute('SELECT inventory FROM devices').fetchone()[0])['disk_free'],60)

    def test_old_center_always_gets_full_inventory_and_downgrade_recovers(self):
        from guarddesk.endpoint_transport import InventoryUpload, software_reference
        from guarddesk.transport_errors import CenterTransportError
        body={'inventory':{'software':['x'*150,'y'*150]}}
        upload=InventoryUpload()
        old=Mock(return_value={'policy':{}})
        upload.send(old,body);upload.send(old,body)
        self.assertTrue(all(c.args[0]['inventory']==body['inventory'] for c in old.call_args_list))
        upload.send(lambda b:{'software_ack':software_reference(body['inventory'])},body)
        downgraded=Mock(side_effect=[CenterTransportError('http',http_status=400),{'policy':{}}])
        upload.send(downgraded,body)
        self.assertEqual([c.args[0]['inventory'] for c in downgraded.call_args_list],[None,body['inventory']])

    def test_windows_rename_from_existing_database_changes_display_and_preserves_links(self):
        with self.store.connect() as db:
            # The old center already accepted a heartbeat after Windows was renamed.
            db.execute("UPDATE devices SET name='原註冊名稱',inventory=? WHERE id=?",
                       (json.dumps({'hostname':'NEW-PC'}),self.did))
            db.execute("INSERT INTO endpoint_groups VALUES ('ops','Operations',NULL,1,?)",(time.time(),))
            db.execute("UPDATE devices SET group_id='ops' WHERE id=?",(self.did,))
            db.execute("INSERT INTO remote_grants VALUES ('admin',?,1,?)",(self.did,time.time()+600))
            Store.event(db,self.did,'file.created','info',{'path':'fixture'},event_id='before-rename')
            before = db.execute("SELECT * FROM events WHERE event_id='before-rename'").fetchone()
            db.execute('ALTER TABLE devices DROP COLUMN registered_name')
        migrated = Store(self.store.path)
        self.handler.server.store = migrated
        self.handler.server.remote_memory = {}
        self.store = migrated
        with self.store.connect() as db:
            packet = self.route(db,'/api/agent/heartbeat',{'inventory':{'hostname':'NEW-PC'}})
            self.route(db,'/api/agent/heartbeat',{'inventory':{'hostname':'new-pc'}})
            device = db.execute('SELECT * FROM devices WHERE id=?',(self.did,)).fetchone()
            self.assertEqual((device['name'],device['registered_name'],device['token'],device['group_id']),
                             ('NEW-PC','原註冊名稱',digest('agent'),'ops'))
            self.assertEqual(packet['policy']['group_path'],['Operations'])
            self.assertEqual(db.execute("SELECT * FROM events WHERE event_id='before-rename'").fetchone(),before)
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE kind='device.hostname_changed'").fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM devices').fetchone()[0],1)
            def get(path):
                self.handler.path = path
                return self.handler.route(db,'GET',path.split('?',1)[0],{})[0]
            from urllib.parse import quote
            for query in ('NEW-PC',quote('原註冊名稱')):
                item = get('/api/fleet?q='+query)['items'][0]
                self.assertEqual((item['id'],item['name']),(self.did,'NEW-PC'))
            remote = get('/api/remote/catalog')
            self.assertEqual(remote['devices'][0]['name'],'NEW-PC')
            self.assertEqual(remote['devices'][0]['registered_name'],'原註冊名稱')
            self.assertEqual(remote['grants'][0]['device_id'],self.did)

    def test_hostname_validation_collisions_and_heartbeat_only(self):
        with self.store.connect() as db:
            db.execute("INSERT INTO devices(id,name,department,token,last_seen) VALUES (?,'SHARED','IT',?,?)",
                       ('b'*24,digest('other'),time.time()))
            for invalid in (None,True,'','invalid name','<b>','\ud800','x'*121):
                with self.subTest(invalid=invalid):
                    self.route(db,'/api/agent/heartbeat',{'inventory':{'hostname':invalid}})
                    self.assertEqual(db.execute('SELECT name FROM devices WHERE id=?',(self.did,)).fetchone()[0],'PC')
            self.toggle(db,True,0)
            self.route(db,'/api/agent/heartbeat',{'inventory':{'hostname':'SHARED'}})
            self.assertEqual(db.execute('SELECT name FROM devices WHERE id=?',(self.did,)).fetchone()[0],'PC')
            self.toggle(db,False,1)
            self.route(db,'/api/agent/heartbeat',{'idle_heartbeat':True,'inventory':{'hostname':'SHARED'}})
            self.assertEqual(db.execute('SELECT name FROM devices WHERE id=?',(self.did,)).fetchone()[0],'PC')
            self.route(db,'/api/agent/heartbeat',{'inventory':{'hostname':'SHARED'}})
            names = [tuple(row) for row in db.execute("SELECT id,name FROM devices ORDER BY id")]
            self.assertEqual(names,[(self.did,'SHARED'),('b'*24,'SHARED')])

    def test_switch_preserves_identity_history_policy_and_filters_late_uploads(self):
        def event(eid,when):
            return {'event_id':eid,'kind':'file.created','severity':'info','details':{'path':'file'},'occurred':when}
        with self.store.connect() as db:
            self.toggle(db,True,0)
            rev=db.execute('SELECT mode_revision FROM devices').fetchone()[0]
            before,during=event('before',time.time()-10),event('during',time.time())
            result=self.route(db,'/api/agent/heartbeat',{'inventory':{'software':['should not be saved']}})
            quiet=decode_agent_policy(result['policy'])
            self.assertFalse(quiet['body']['file_audit']['enabled'])
            self.assertFalse(quiet['body']['application_control']['enabled'])
            self.assertEqual(self.route(db,'/api/agent/native-usb-policy',{})['usb_mode'],'allow')
            self.assertEqual(self.route(db,'/api/agent/custom-settings',{'protocol':2})['documents']['rules'],[])
            self.route(db,'/api/agent/heartbeat',{'native_idle_revision':rev})
            self.route(db,'/api/agent/extended-status',{'status':'failed'})
            self.assertEqual(self.route(db,'/api/agent/events',{'events':[before,during]})['accepted'],['during'])
            d=dict(db.execute('SELECT * FROM devices').fetchone())
            self.assertEqual((d['id'],d['token'],d['inventory'],d['mode_ack']),(self.did,digest('agent'),'{"asset":"kept"}',rev))
            self.assertEqual(d['last_offline_seconds']//86400,3)
            self.assertEqual(offline_days(d),0)
            self.assertEqual(offline_days(d, d['last_seen']+2*86400),2)
            self.assertIsNone(db.execute('SELECT 1 FROM extended_status').fetchone())
            current=Store.policy(db)
            updated={**current['body'],'usb_mode':'read_only'}
            self.route(db,'/api/policy',{'body':updated,'base_version':current['version']})
            self.assertEqual(self.route(db,'/api/agent/native-usb-policy',{})['usb_mode'],'allow')
            self.toggle(db,False,rev)
            packet=self.route(db,'/api/agent/extended-policy',{})
            self.assertEqual(packet['mode_revision'],rev+1)
            self.route(db,'/api/agent/extended-status',{'status':'configured','mode_revision':rev})
            self.assertEqual(db.execute('SELECT mode_ack FROM devices').fetchone()[0],0)
            self.route(db,'/api/agent/extended-status',{'status':'configured','mode_revision':rev+1})
            self.assertEqual(db.execute('SELECT mode_ack FROM devices').fetchone()[0],rev+1)
            restored=self.route(db,'/api/agent/heartbeat',{'idle_heartbeat':True,'inventory':{}})
            self.assertTrue(decode_agent_policy(restored['policy'])['body']['file_audit']['enabled'])
            self.assertEqual(decode_agent_policy(restored['policy'])['body']['usb_mode'],'read_only')
            after=event('after',time.time())
            self.route(db,'/api/agent/events',{'events':[before,during,after]})
            self.assertEqual({r[0] for r in db.execute("SELECT event_id FROM events WHERE kind='file.created'")},{'before','after'})
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE kind='device.heartbeat_mode'").fetchone()[0],2)

    def test_role_csrf_stale_tab_revocation_and_retirement(self):
        with self.store.connect() as db:
            self.handler.headers['X-CSRF-Token']='wrong'
            with self.assertRaises(APIError):self.toggle(db,True,0)
            self.handler.headers['X-CSRF-Token']='csrf'
            db.execute("UPDATE users SET role='auditor'")
            with self.assertRaises(APIError):self.toggle(db,True,0)
            db.execute("UPDATE users SET role='admin'")
            self.toggle(db,True,0)
            with self.assertRaises(ManagementError):self.toggle(db,False,0)
            db.execute('UPDATE devices SET revoked=1')
            with self.assertRaises(ManagementError):self.toggle(db,False,1)
            with self.assertRaises(APIError):self.route(db,'/api/agent/heartbeat',{})
            db.execute('DELETE FROM devices')
            self.assertFalse(db.execute('SELECT 1 FROM heartbeat_only_periods').fetchone())

    def test_agent_remembers_mode_across_restart_and_keeps_pre_pause_queue(self):
        path=self.root/'agent.json'
        private_write(path,{'watch':str(self.root),'device_id':self.did})
        agent=Agent(path)
        agent.queue('file.created',{'path':'before'},event_id='before')
        agent.receive_policy({}, {'policy':heartbeat_policy(1)}, {})
        agent=Agent(path)
        self.assertEqual(agent.idle_revision,1)
        self.assertIsNone(agent.queue('agent.audit_gap',{'reason':'ignored'},'critical'))
        with patch.object(agent,'call',side_effect=AssertionError('paused sender used transport')):
            self.assertEqual(agent.flush(),{'sent':0,'pending':True})
        with patch.object(agent,'call',return_value={'policy':{'version':1,'body':DEFAULT_POLICY}}) as call:
            agent.heartbeat()
            call.assert_called_once_with('/api/agent/heartbeat',{'idle_heartbeat':True,'inventory':{}})
        self.assertIsNone(agent.queue('file.created',{},occurred=time.time()-60))
        self.assertEqual(agent.queue('file.created',{},event_id='after'),'after')
        with agent.db() as db:self.assertEqual(dict(db.execute('SELECT event_id,1 FROM outbox')),{'before':1,'after':1})

    def test_native_ack_only_after_owned_controls_restored_and_retries_conflict(self):
        path=self.root/'agent.json'
        private_write(path,{'watch':str(self.root),'device_id':self.did})
        worker=UsbWorker.__new__(UsbWorker)
        worker.agent=Agent(path)
        with worker.agent.db() as db:worker.agent.set_idle_revision(1,db)
        worker.custom=None
        worker.controls=SimpleNamespace(installed=False)
        companion=Mock()
        companion.restore.side_effect=[OSError('company policy conflict'),None]
        worker.restore=Mock()
        with patch.object(worker.agent,'call',side_effect=[{'policy':heartbeat_policy(1)},
                        {'policy':heartbeat_policy(1)},{'heartbeat_only':False}]) as call:
            worker.idle_cycle(companion)
            self.assertEqual(call.call_args.args[1],{'native_idle_revision':0})
            worker.idle_cycle(companion)
            self.assertEqual(call.call_args.args[1],{'native_idle_revision':1})
            worker.idle_cycle(companion)
        self.assertEqual(companion.restore.call_count,2)
        self.assertEqual(worker.agent.idle_revision,0)
