"""Global remote metadata/lifetime and real isolated consent API, no screen capture."""
import copy
import json
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
import test_machine_agent
import test_system
import test_updates
from guarddesk.machine_agent_session import RemoteBridge,serve_session
from guarddesk.remote_readiness import label


class GlobalRouterTest(test_machine_agent.MachineFixture):
    def test_existing_removal_marker_stops_borrowed_remote_before_early_return(self):
        remote=SimpleNamespace(stop=threading.Event(),local_stop=threading.Event(),close_indicator=Mock())
        self.agent._managed_remote=remote
        with self.agent.db() as db:
            db.execute("INSERT INTO state VALUES ('removal_job',?)",(json.dumps({'id':'owned-removal','phase':'done'}),))
        self.agent.run(threading.Event())
        self.assertTrue(remote.stop.is_set());self.assertTrue(remote.local_stop.is_set())
        remote.close_indicator.assert_called_once();self.assertTrue(self.agent.decommissioned)

    def test_remote_bootstrap_without_private_profile_or_policy_contains_no_secret(self):
        self.agent.machine_session_policy=None
        result=self.dispatch('/local/remote-bootstrap',{})
        self.assertEqual(result['session'],1);self.assertEqual(result['sid'],self.states[1]['sid'])
        self.assertEqual(result['device_id'],self.agent.config['device_id'])
        self.assertNotIn('MACHINE-SECRET',json.dumps(result));self.assertNotIn('config',result)
        with self.assertRaises(OSError):self.dispatch('/local/bootstrap',{})
        with self.assertRaises(PermissionError):self.router.dispatch({'path':'/local/remote-bootstrap','body':{}})
        with self.assertRaises(ValueError):self.dispatch('/local/remote-bootstrap',{'path':'arbitrary'})

    def test_idle_A_does_not_replace_new_B_readiness_or_receive_old_consent(self):
        self.states[2]['active']=False
        self.dispatch('/api/agent/remote/poll',{'ready':True})
        self.router.end_session(1,10)
        self.states[1]['active']=False;self.states[2]['active']=True
        self.dispatch('/api/agent/remote/poll',{'ready':True,'account':'forged'},2)
        self.assertEqual(self.calls[-1][1]['account'],'EXAMPLE\\B')
        before=len(self.calls);self.dispatch('/api/agent/remote/poll',{'ready':True},1)
        self.assertEqual(len(self.calls),before)
        with self.assertRaises(PermissionError):self.dispatch('/api/agent/remote/update',{'session_id':'remote1','action':'approve'},1)

    def test_all_locked_reports_false_and_multiple_desktops_keep_safety(self):
        for value in self.states.values():value['locked']=True
        self.dispatch('/api/agent/remote/poll',{'ready':True})
        self.assertFalse(self.calls[-1][1]['ready']);self.assertEqual(self.calls[-1][1]['readiness'],'locked_or_disconnected')
        for value in self.states.values():value['locked']=False
        self.dispatch('/api/agent/remote/poll',{'ready':True})
        self.assertEqual(self.calls[-1][1]['readiness'],'multiple_interactive_sessions')


class SessionLifetimeTest(unittest.TestCase):
    def setUp(self):
        self.stop=threading.Event();self.packet=dict(parent=100,session=2,sid='S-1-5-21-22',logon=10,
            generation='a'*32,device_id='b'*24,enabled=True)
        self.events=[];owner=self
        class Remote:
            def __init__(self,bridge,stop,parent_stop):self.bridge=bridge;self.stop=stop;self.parent_stop=parent_stop;self.local_stop=threading.Event()
            def start(self):owner.events.append('remote_started')
            def close_indicator(self):owner.events.append('remote_closed')
            def call(self,path,body):return self.bridge.call('/api/agent/remote/'+path,body)
        self.factory=Remote
        self.bootstrap={k:self.packet[k] for k in ('parent','session','sid','logon','generation')}
        self.request=Mock(return_value=self.bootstrap)

    def test_remote_bridge_fixed_routes_parent_generation_no_credentials(self):
        bridge=RemoteBridge(self.packet,self.request)
        bridge.call('/api/agent/remote/poll',{'ready':True},timeout=2)
        self.request.assert_called_once_with('/api/agent/remote/poll',{'ready':True},timeout=2,parent=100,generation='a'*32)
        for path in ('/api/agent/events','/api/agent/updates/poll','https://other.test'):
            with self.assertRaises(PermissionError):bridge.call(path,{})

    def test_remote_starts_before_profile_failure_and_remains_until_parent_stop(self):
        def prepare(*args):
            self.assertIn('remote_started',self.events)
            self.events.append('private_profile_failed');self.stop.set();raise OSError('owned private profile failure')
        with patch('guarddesk.machine_agent_session.prepare',side_effect=prepare):
            serve_session(self.packet,2,self.stop,self.request,self.factory,retry_seconds=.001)
        self.assertEqual(self.events,['remote_started','private_profile_failed','remote_closed'])

    def test_profile_retry_does_not_start_duplicate_remote_or_reenroll(self):
        def prepare(*args):
            self.events.append('prepare')
            if self.events.count('prepare')==1:raise OSError('owned first preparation failure')
            return Path('owned/config.json')
        def run(*args,**kwargs):
            self.assertTrue(kwargs['managed_session']);self.assertIsInstance(kwargs['managed_remote'],self.factory)
            self.events.append('collector_started');self.stop.set()
        with patch('guarddesk.machine_agent_session.prepare',side_effect=prepare),patch('guarddesk.desktop_agent.run',side_effect=run):
            serve_session(self.packet,2,self.stop,self.request,self.factory,retry_seconds=.001)
        self.assertEqual(self.events.count('remote_started'),1);self.assertEqual(self.events.count('prepare'),2)

    def test_collector_exit_does_not_end_remote_parent_lifetime(self):
        def run(*args,**kwargs):
            self.events.append('collector')
            args[1].set()  # desktop collector owns its own stop only
            if self.events.count('collector')==2:self.stop.set()
        with patch('guarddesk.machine_agent_session.prepare',return_value=Path('owned/config.json')),patch('guarddesk.desktop_agent.run',side_effect=run):
            serve_session(self.packet,2,self.stop,self.request,self.factory,retry_seconds=.001)
        self.assertEqual(self.events.count('collector'),2);self.assertEqual(self.events.count('remote_started'),1)

    def test_changed_logon_stops_without_preparing_other_user_profile(self):
        self.bootstrap['logon']=99
        with patch('guarddesk.machine_agent_session.prepare',side_effect=AssertionError('wrong logon')):
            serve_session(self.packet,2,self.stop,self.request,self.factory,retry_seconds=.001)
        self.assertTrue(self.stop.is_set());self.assertIn('remote_closed',self.events)

    def test_disabled_remote_reports_false_but_collectors_continue(self):
        self.packet['enabled']=False
        def run(*args,**kwargs):self.stop.set()
        with patch('guarddesk.machine_agent_session.prepare',return_value=Path('owned/config.json')),patch('guarddesk.desktop_agent.run',side_effect=run):
            serve_session(self.packet,2,self.stop,self.request,self.factory,retry_seconds=.001)
        self.assertNotIn('remote_started',self.events)
        self.assertEqual(self.request.call_args_list[0].args[1]['readiness'],'disabled')

    def test_disabled_remote_network_error_does_not_stop_general_collectors(self):
        self.packet['enabled']=False
        def request(path,*args,**kwargs):
            if path.endswith('/remote/poll'):raise OSError('owned network failure')
            return self.bootstrap
        def run(*args,**kwargs):self.events.append('collector');self.stop.set()
        with patch('guarddesk.machine_agent_session.prepare',return_value=Path('owned/config.json')),patch('guarddesk.desktop_agent.run',side_effect=run):
            serve_session(self.packet,2,self.stop,request,self.factory,retry_seconds=.001)
        self.assertIn('collector',self.events);self.assertNotIn('remote_started',self.events)


class ReadinessServerTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp;tearDown=test_system.SystemTest.tearDown;api=test_system.SystemTest.api
    make_agent=test_updates.UpdateServerTest.make_agent

    def test_online_heartbeat_does_not_claim_desktop_ready(self):
        agent,did,_=self.make_agent();agent.heartbeat(False)
        device=next(d for d in self.api('/api/remote/catalog')['devices'] if d['id']==did)
        self.assertFalse(device['ready']);self.assertEqual(device['readiness'],'no_desktop_report')
        agent.call('/api/agent/remote/poll',{'account':'EXAMPLE\\B','ready':False,'protocol':3,'readiness':'locked_or_disconnected'})
        device=next(d for d in self.api('/api/remote/catalog')['devices'] if d['id']==did)
        self.assertEqual(device['readiness'],'locked_or_disconnected')

    def test_legacy_current_metadata_and_stale_presence_are_compatible(self):
        agent,did,_=self.make_agent()
        agent.call('/api/agent/remote/poll',{'account':'EXAMPLE\\A','ready':True,'protocol':3})
        with self.store.connect() as db:
            # Same four-column shape is still usable by an actual old Server.
            self.assertEqual(len(db.execute('SELECT * FROM remote_presence LIMIT 1').fetchone()),4)
            db.execute('UPDATE remote_presence SET received=? WHERE device_id=?',(time.time()-30,did))
        device=next(d for d in self.api('/api/remote/catalog')['devices'] if d['id']==did)
        self.assertFalse(device['ready']);self.assertEqual(device['readiness'],'no_desktop_report')

    def test_false_readiness_has_bounded_reason_and_cannot_enable_remote(self):
        agent,did,_=self.make_agent()
        with self.assertRaises(ConnectionError):agent.call('/api/agent/remote/poll',{'account':'EXAMPLE\\B','ready':False,'protocol':3,'readiness':'x'*10000})
        agent.call('/api/agent/remote/poll',{'account':'EXAMPLE\\B','ready':False,'protocol':3,'readiness':'elevated_context'})
        self.api('/api/remote/grant',{'username':'admin','device_id':did,'can_control':True,'enabled':True,'days':1})
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/remote/request',{'device_id':did,'mode':'view','reason':''})
        self.assertEqual(denied.exception.code,409)

    def test_native_MIS_label_explains_readiness_without_changing_control_gate(self):
        self.assertEqual(label({'protocol':3,'ready':False,'readiness':'no_desktop_report'}),'尚未收到登入桌面回報')
        self.assertEqual(label({'protocol':3,'ready':False,'readiness':'untrusted'}),'登入桌面尚未就緒')
        self.assertEqual(label({'protocol':3,'ready':True,'readiness':'disabled'}),'可連線')


if __name__=='__main__':unittest.main()
