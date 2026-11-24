"""Exercise the normal console, authenticated ingestion and Agent boundaries without a listener."""
import shutil
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
