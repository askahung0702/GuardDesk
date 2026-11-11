"""Synthetic A/B logons and private queues; never install/modify company Agent."""
import copy
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
from guarddesk.agent import Agent
from guarddesk.machine_agent import Router,Supervisor,PIPE
from guarddesk.machine_agent_session import prepare
from guarddesk.policy import DEFAULT_POLICY


class MachineFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);watch=self.root/'watch';watch.mkdir()
        self.config=self.root/'config.json'
        self.config.write_text(json.dumps({'server':'https://center.example.test:8787','device_id':'a'*24,
            'token':'MACHINE-SECRET-NEVER-LEAVE-BROKER','watch':str(watch),'update_key':'fixture-public-key'}))
        self.agent=Agent(self.config)
        self.states={1:{'sid':'S-1-5-21-11','account':'EXAMPLE\\A','logon':10,'active':True,'locked':False},
                     2:{'sid':'S-1-5-21-22','account':'EXAMPLE\\B','logon':20,'active':True,'locked':False}}
        self.calls=[]
        def call(path,body):
            self.calls.append((path,copy.deepcopy(body)))
            if path.endswith('/heartbeat'):return {'policy':{'version':1,'body':copy.deepcopy(DEFAULT_POLICY)}}
            if path.endswith('/events'):return {'accepted':[e['event_id'] for e in body['events']]}
            if path.endswith('/poll') and '/remote/' in path:return {'session':{'id':'remote1','status':'requested'},'desktop_protocol':2}
            return {'ok':True,'status':'active'}
        self.router=Router(self.agent,lambda:self.states,call)

    def peer(self,sid):return {'session':sid,'sid':self.states[sid]['sid'],'logon':self.states[sid]['logon']}
    def dispatch(self,path,body,sid=1):return self.router.dispatch({'path':path,'body':body},self.peer(sid))


class MachineAgentTest(MachineFixture):
    def test_public_status_and_bootstrap_never_disclose_machine_token(self):
        public=self.router.dispatch({'path':'/local/status','body':{}})
        self.assertEqual(public['device_id'],'a'*24)
        bootstrap=self.dispatch('/local/bootstrap',{})
        self.assertNotIn('token',bootstrap['config'])
        self.assertNotIn('MACHINE-SECRET',json.dumps([public,bootstrap]))
        self.assertEqual(bootstrap['session'],1)
        self.assertEqual(self.calls,[])

    def test_sessions_cannot_invoke_system_updates_management_or_arbitrary_urls(self):
        for path in ('/api/agent/native-usb-policy','/api/agent/updates/poll','/api/agent/updater/prepare',
                     '/api/agent/custom-action/authorize','/api/agent/extended-policy','/api/users','https://evil.test/'):
            with self.subTest(path=path),self.assertRaises(PermissionError):self.dispatch(path,{})
        for path,body in [('/api/agent/custom-status',{'role':'native'}),('/api/agent/uninstall/poll',{'role':'native'})]:
            with self.assertRaises(PermissionError):self.dispatch(path,body)
        self.assertEqual(self.calls,[])

    def test_peer_sid_and_logon_cannot_be_replaced_by_json(self):
        peer=self.peer(1)
        peer['sid']=self.states[2]['sid']
        with self.assertRaises(PermissionError):self.router.dispatch({'path':'/api/agent/heartbeat','body':{}},peer)
        peer=self.peer(1);self.states[1]['logon']=30
        with self.assertRaises(PermissionError):self.router.dispatch({'path':'/local/bootstrap','body':{}},peer)
        with self.assertRaises(PermissionError):self.router.dispatch({'path':'/local/bootstrap','body':{}},None)

    def test_A_B_events_same_device_and_real_account_separate_queues_offline(self):
        configs=[]
        with patch('guarddesk.desktop_agent.client_root',return_value=self.root/'empty-user'):
            for sid in (1,2):
                packet=self.dispatch('/local/bootstrap',{},sid)
                path=prepare(packet,sid,root=self.root/str(sid)/'agent/config.json')
                configs.append(path)
                agent=Agent(path)
                self.assertEqual(agent.config['token'],'')
                self.assertEqual(agent.config['machine_session']['pipe'],PIPE)
                eid=agent.queue('web.navigation',{'url':'https://example.test/','user':'forged'})
                with patch('guarddesk.machine_agent_windows.request',side_effect=ConnectionError('offline')):
                    with self.assertRaises(ConnectionError):agent.flush()
                self.assertEqual(agent.queue_status()['pending'],1)
                def route(path,body,**kwargs):return self.dispatch(path,body,sid)
                with patch('guarddesk.machine_agent_windows.request',side_effect=route):agent.flush()
                self.assertEqual(agent.queue_status()['pending'],0)
                sent=self.calls[-1][1]['events'][0]
                self.assertEqual(sent['event_id'],eid)
                self.assertEqual(sent['details']['user'],self.states[sid]['account'])
        self.assertNotEqual(configs[0],configs[1])
        self.assertEqual(Agent(configs[0]).config['device_id'],Agent(configs[1]).config['device_id'])

    def test_session_never_starts_own_directory_security_or_system_control(self):
        self.agent.config['machine_session']={'parent':123}
        with patch('guarddesk.windows_controls.WindowsControls',side_effect=AssertionError('system control')):
            self.agent.collect_native({'body':copy.deepcopy(DEFAULT_POLICY)})
        self.assertEqual(self.agent.feature_status['security_log']['status'],'machine_worker_owned')

    def test_reporting_session_does_not_invent_unknown_filesystem_actor(self):
        self.dispatch('/api/agent/events',{'events':[{'event_id':'unknown-actor','kind':'file.created','details':{'user':None}}]})
        details=self.calls[-1][1]['events'][0]['details']
        self.assertIsNone(details['user']);self.assertEqual(details['reporting_account'],'EXAMPLE\\A')

    def test_old_desktop_launcher_delegates_without_starting_second_collector(self):
        from guarddesk.desktop_agent import run
        machine={'device_id':'a'*24,'server':self.agent.config['server'],'scope':'machine'}
        with patch('guarddesk.machine_agent_session.discover',return_value=machine),patch('guarddesk.desktop_agent.instance',side_effect=AssertionError('duplicate collector')):
            run(self.config,threading.Event())

    def test_heartbeat_preserves_computer_and_exposes_both_sessions(self):
        self.dispatch('/api/agent/heartbeat',{'inventory':{'agent_account':'forged','agent_version':'0.4.64'}})
        inventory=self.calls[-1][1]['inventory']
        self.assertEqual(inventory['agent_account'],'EXAMPLE\\A')
        self.assertEqual([s['user'] for s in inventory['machine_agent']['sessions']],['EXAMPLE\\A','EXAMPLE\\B'])

    def test_remote_consent_and_frames_never_transfer_to_B_or_reused_session(self):
        self.states[2]['active']=False
        self.assertTrue(self.dispatch('/api/agent/remote/poll',{'ready':True})['session'])
        self.assertIsNone(self.dispatch('/api/agent/remote/poll',{'ready':True},2)['session'])
        with self.assertRaises(PermissionError):self.dispatch('/api/agent/remote/update',{'session_id':'remote1','action':'approve'},2)
        self.states[1]['locked']=True
        response=self.dispatch('/api/agent/remote/update',{'session_id':'remote1','action':'frame'})
        self.assertEqual(response['status'],'closed')
        self.assertEqual(self.calls[-1][1],{'session_id':'remote1','action':'stop'})
        self.states[1]['locked']=False;self.dispatch('/api/agent/remote/poll',{'ready':True})
        self.states[1]['logon']=99
        with self.assertRaises(PermissionError):self.dispatch('/api/agent/remote/update',{'session_id':'remote1','action':'approve'})

    def test_logout_closes_remote_before_new_user_poll(self):
        self.states[2]['active']=False
        self.dispatch('/api/agent/remote/poll',{'ready':True})
        self.router.end_session(1,10)
        self.assertEqual(self.calls[-1],('/api/agent/remote/update',{'session_id':'remote1','action':'stop'}))

    def test_two_active_desktops_do_not_silently_choose_a_remote_user(self):
        result=self.dispatch('/api/agent/remote/poll',{'ready':True})
        self.assertEqual(result['reason'],'multiple_interactive_sessions')
        self.assertIsNone(result['session'])
        self.assertFalse(self.calls[-1][1]['ready'])

    def test_legacy_migration_preserves_outbox_cursor_and_identity_without_token_in_new_config(self):
        user=self.root/'legacy-user';legacy=user/'runtime/agent/config.json';legacy.parent.mkdir(parents=True)
        legacy.write_bytes(self.config.read_bytes());old=Agent(legacy)
        old.queue('web.navigation',{'fixture':True},event_id='legacy-fixed-id')
        with old.db() as db:db.execute("INSERT INTO state VALUES ('browser_cursor','1234')")
        original=legacy.read_bytes();packet=self.dispatch('/local/bootstrap',{})
        with (patch('guarddesk.desktop_agent.client_root',return_value=user),patch('guarddesk.desktop_agent.stop_running') as stop,
             patch('guarddesk.browser_host.unregister_owned'),patch('guarddesk.endpoint_setup.remove_autostart_for_config')):
            result=prepare(packet,1,root=self.root/'new/agent/config.json')
        stop.assert_called_once_with(legacy)
        new=Agent(result)
        self.assertEqual(new.queue_status()['pending'],1)
        self.assertEqual(old.queue_status()['pending'],1)
        self.assertEqual(legacy.read_bytes(),original)
        self.assertEqual((legacy.parent/'pre-machine-config.json').read_bytes(),original)
        with new.db() as db:self.assertEqual(db.execute("SELECT value FROM state WHERE key='browser_cursor'").fetchone()[0],'1234')
        self.assertEqual(new.config['token'],'')

    def test_conflicting_user_identity_fails_without_stopping_original(self):
        user=self.root/'conflict';legacy=user/'runtime/agent/config.json';legacy.parent.mkdir(parents=True)
        settings=json.loads(self.config.read_text());settings['device_id']='b'*24;legacy.write_text(json.dumps(settings))
        with patch('guarddesk.desktop_agent.client_root',return_value=user),patch('guarddesk.desktop_agent.stop_running') as stop:
            with self.assertRaises(ValueError):prepare(self.dispatch('/local/bootstrap',{}),1,root=self.root/'blocked/agent/config.json')
        stop.assert_not_called()

    def test_legacy_native_host_pointer_is_replaced_by_machine_session_registration(self):
        import sys
        from guarddesk import browser_host
        from test_browser_deployment_lifecycle import FakeRegistry
        user=self.root/'host-user';legacy=user/'runtime/agent/config.json';legacy.parent.mkdir(parents=True)
        legacy.write_bytes(self.config.read_bytes());Agent(legacy)
        exe=self.root/'GuardDesk.exe';exe.write_bytes(b'owned fixture, not executed')
        registry=FakeRegistry();packet=self.dispatch('/local/bootstrap',{})
        with (patch.dict(sys.modules,winreg=registry),patch('guarddesk.desktop_agent.client_root',return_value=user),
              patch('guarddesk.desktop_agent.stop_running'),patch('guarddesk.endpoint_setup.remove_autostart_for_config'),
              patch.object(sys,'frozen',True,create=True),patch.object(sys,'executable',str(exe))):
            browser_host.register(legacy,exe,enable_proxy=False)
            new=prepare(packet,1,root=user/'runtime/machine-agent'/('a'*24)/'1/agent/config.json')
            self.assertNotIn('AgentConfig',registry.keys[r'Software\GuardDesk'])
            with patch('guarddesk.browser_host.installed_user_host',return_value=True):
                result=browser_host.ensure_user_host(new)
            self.assertEqual(result['status'],'registered_awaiting_extension')
            self.assertEqual(registry.keys[r'Software\GuardDesk']['AgentConfig'],str(new.resolve()))

    def test_same_computer_installer_from_B_does_not_enroll_again(self):
        from guarddesk.endpoint_setup import install
        ca=self.root/'ca.pem';ca.write_bytes(b'public-ca')
        import hashlib
        machine={**self.router.dispatch({'path':'/local/status','body':{}}),'ca_sha256':hashlib.sha256(ca.read_bytes()).hexdigest()}
        with (patch('guarddesk.endpoint_setup.read_connection',return_value=(machine['server'],ca)),
             patch('guarddesk.machine_agent_session.discover',return_value=machine),
             patch('guarddesk.endpoint_setup.client_root',return_value=self.root/'owned-unenrolled-account'),
             patch('guarddesk.endpoint_setup.enroll') as enroll):
            result=install(self.root/'connection.json')
        self.assertEqual(result['autostart'],'all_user_sessions');enroll.assert_not_called()

    def test_one_user_cannot_complete_other_users_uninstall_cleanup(self):
        profiles={s['sid']:{'removal_ready':None} for s in self.states.values()}
        with self.agent.db() as db:db.execute("INSERT INTO state VALUES ('machine_profiles',?)",(json.dumps(profiles),))
        self.router.removal={'id':'removal-job'}
        self.dispatch('/api/agent/uninstall/status',{'role':'main','job_id':'removal-job','state':'ready'})
        self.assertEqual(self.calls[-1][1]['state'],'failed')
        self.dispatch('/api/agent/uninstall/status',{'role':'main','job_id':'removal-job','state':'ready'},2)
        self.assertEqual(self.calls[-1][1]['state'],'ready')


class SupervisorTest(MachineFixture):
    def test_unexpected_thread_failure_closes_ipc_and_stops_parent_with_diagnostic(self):
        supervisor,platform=self.supervisor()
        listener=Mock();platform.listen=Mock(return_value=listener)
        supervisor.tick=Mock(side_effect=ModuleNotFoundError('PRIVATE_EXCEPTION_TEXT'))
        supervisor.start();supervisor.thread.join(5)
        self.assertFalse(supervisor.thread.is_alive());self.assertTrue(supervisor.stop.is_set())
        listener.close.assert_called_once()
        self.assertEqual(supervisor.fatal_error['operation'],'supervisor_thread')
        path=self.agent.config_path.parent/'machine-startup-failure.json'
        value=json.loads(path.read_text())
        self.assertEqual(value['type'],'ModuleNotFoundError');self.assertNotIn('PRIVATE',path.read_text())
    def supervisor(self):
        platform=SimpleNamespace(sessions=Mock(return_value=self.states),launch=Mock(side_effect=lambda *a:SimpleNamespace(alive=lambda:True,close=Mock())))
        return Supervisor(self.agent,threading.Event(),platform),platform

    def tick(self,supervisor):supervisor.next_scan=0;supervisor.tick()

    def test_logon_fast_switch_logout_and_reboot_keep_one_machine_identity(self):
        supervisor,platform=self.supervisor();self.tick(supervisor)
        self.assertEqual(platform.launch.call_count,2)
        self.states[1]['active']=False;self.tick(supervisor)
        self.assertEqual(platform.launch.call_count,2)
        child=supervisor.children[1];self.states.pop(1);self.tick(supervisor)
        child.close.assert_called_once()
        self.assertEqual(set(supervisor.children),{2})
        reboot,platform=self.supervisor();self.tick(reboot)
        self.assertEqual(set(reboot.children),{2});self.assertEqual(reboot.agent.config['device_id'],'a'*24)

    def test_failed_query_keeps_existing_children_and_launch_failure_backs_off(self):
        supervisor,platform=self.supervisor();self.tick(supervisor)
        platform.sessions.side_effect=OSError('WTS unavailable');self.tick(supervisor)
        self.assertEqual(len(supervisor.children),2)
        platform.sessions.side_effect=None;platform.launch.side_effect=OSError('denied')
        self.states[3]={**self.states[2],'sid':'S-1-5-21-33','logon':30}
        self.tick(supervisor);count=platform.launch.call_count;self.tick(supervisor)
        self.assertEqual(platform.launch.call_count,count)
        self.assertEqual(supervisor.snapshot()['errors'],2)

    def test_more_than_eight_sessions_fail_closed_without_starting_partial_set(self):
        supervisor,platform=self.supervisor();platform.sessions.return_value={i:{**self.states[1]} for i in range(1,10)}
        self.tick(supervisor);platform.launch.assert_not_called();self.assertEqual(supervisor.snapshot()['errors'],1)

    def test_install_or_update_transaction_does_not_launch_migration_early(self):
        supervisor,platform=self.supervisor();platform.can_launch=lambda:False
        self.tick(supervisor);platform.launch.assert_not_called()
        platform.can_launch=lambda:True;self.tick(supervisor)
        self.assertEqual(platform.launch.call_count,2)

    def test_antimalware_launch_rejection_latches_without_retries_or_other_session_launch(self):
        for code in (225,226):
            with self.subTest(code=code):
                supervisor,platform=self.supervisor()
                error=OSError('owned AV rejection');error.winerror=code
                platform.launch.side_effect=error
                self.tick(supervisor)
                self.assertEqual(platform.launch.call_count,1)
                self.assertTrue(supervisor.local_process_diagnostics()['launch_blocked_antimalware'])
                supervisor.retry.clear();self.tick(supervisor)
                self.assertEqual(platform.launch.call_count,1)
                self.assertEqual(supervisor.last_error['winerror'],code)

    def test_antimalware_launch_rejection_preserves_existing_child(self):
        supervisor,platform=self.supervisor();self.tick(supervisor)
        child=supervisor.children[1]
        self.states[3]={**self.states[2],'sid':'S-1-5-21-33','logon':30}
        error=OSError('owned AV rejection');error.winerror=225;platform.launch.side_effect=error
        self.tick(supervisor)
        self.assertIs(supervisor.children[1],child);child.close.assert_not_called()

    def test_access_denied_remains_bounded_retry_not_antimalware_latch(self):
        supervisor,platform=self.supervisor()
        error=OSError('owned access denied');error.winerror=5;platform.launch.side_effect=error
        self.tick(supervisor)
        self.assertFalse(supervisor.launch_blocked_antimalware)
        before=platform.launch.call_count;self.tick(supervisor)
        self.assertEqual(platform.launch.call_count,before)
        supervisor.retry.clear();self.tick(supervisor)
        self.assertGreater(platform.launch.call_count,before)


class MachineUpdateHandoffTest(unittest.TestCase):
    import test_system as fixtures
    setUp=fixtures.SystemTest.setUp
    tearDown=fixtures.SystemTest.tearDown
    api=fixtures.SystemTest.api
    make_agent=fixtures.SystemTest.make_agent

    def test_old_user_updater_cannot_race_machine_handoff(self):
        agent,did,_=self.make_agent()
        with self.store.connect() as db:
            db.execute('INSERT INTO extended_status VALUES (?,?,?)',(did,json.dumps({'machine_agent':{'scope':'machine','version':'0.4.64'}}),time.time()))
        result=agent.call('/api/agent/updates/poll',{'role':'main','version':'0.4.63'})
        self.assertEqual(result['waiting_for'],'machine_agent_handoff')
        result=agent.call('/api/agent/updates/poll',{'role':'main','version':'0.4.64','machine_scope':True})
        self.assertNotEqual(result.get('waiting_for'),'machine_agent_handoff')
