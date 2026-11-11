"""Remote-only compile profile; synthetic transport/WTS only, no OS control."""
import contextlib
import copy
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from guarddesk import remote_trial
from guarddesk.agent import Agent
from guarddesk.machine_agent import Router, Supervisor


class TrialTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.path=self.root/'config.json'
        self.path.write_text(json.dumps({'server':'https://owned.test','token':'fixture-secret','device_id':'a'*24,
            'watch':str(self.root),'install_profile':remote_trial.PROFILE,'remote_native_preview':True}))
        self.enabled=patch.object(remote_trial,'ENABLED',True);self.enabled.start();self.addCleanup(self.enabled.stop)
        self.agent=Agent(self.path)

    def test_default_profile_is_compile_constant_and_not_config_selected(self):
        with patch.object(remote_trial,'ENABLED',False):
            self.assertFalse(remote_trial.enabled());remote_trial.command_allowed('agent')
        for value in ({},{'remote_trial':True},{'install_profile':'standard'}):
            with self.assertRaises(PermissionError):remote_trial.require_profile(value)

    def test_collection_and_control_cli_and_update_entries_are_rejected(self):
        for command in ('agent','desktop-agent','update-service','apply-user-update','browser-host',
                'browser-install','browser-policy','browser-trust','windows-install','export','app-file-info'):
            with self.assertRaises(PermissionError):remote_trial.command_allowed(command)
        for command in ('usb-worker','usb-install','machine-session','endpoint-uninstall',
                'serve','server-setup','server-check','add-user','remote-viewer'):
            remote_trial.command_allowed(command)
        from guarddesk.native_usb import UsbWorker
        from guarddesk.desktop_agent import run as desktop
        from guarddesk.update_client import UserPoller,apply_user
        from guarddesk.update_native import run as updater
        from guarddesk.updater_refresh import start
        from guarddesk.agent import inventory
        functions=[lambda:UsbWorker(self.path),lambda:desktop(self.path,threading.Event()),
            lambda:UserPoller(self.agent,threading.Event()),lambda:apply_user(self.path,'x'),
            lambda:updater(self.path,threading.Event()),lambda:start(self.agent,threading.Event()),
            lambda:inventory(self.root),lambda:self.agent.run(threading.Event()),self.agent.heartbeat,
            lambda:self.agent.collect_native({'body':{}}),self.agent.scan,
            lambda:self.agent.queue('file.created',{})]
        for function in functions:
            with self.assertRaises(PermissionError):function()

    def test_actual_elevation_and_wts_child_argv_are_allowed(self):
        # Inspect actual source argument lists, never invoke ShellExecuteEx,
        # CreateProcessAsUser, UAC, or any desktop process in this regression.
        import ast
        import inspect
        from guarddesk import usb_install,machine_agent_windows
        elevate=ast.parse(inspect.getsource(usb_install.elevate))
        assignment=next(node for node in ast.walk(elevate) if isinstance(node,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id=='arguments' for t in node.targets))
        self.assertIsInstance(assignment.value,ast.List)
        actual=assignment.value.elts
        self.assertEqual(ast.literal_eval(actual[0]),'endpoint-native-install')
        self.assertEqual([ast.literal_eval(actual[i]) for i in (1,3,5)],
                         ['--config','--action','--diagnostic-pipe'])
        remote_trial.command_allowed(ast.literal_eval(actual[0]))
        import textwrap
        launch=ast.parse(textwrap.dedent(inspect.getsource(machine_agent_windows.Platform.launch)))
        call=next(node for node in ast.walk(launch) if isinstance(node,ast.Call)
                  and isinstance(node.func,ast.Attribute) and node.func.attr=='list2cmdline')
        self.assertIsInstance(call.args[0],ast.List)
        command=ast.literal_eval(call.args[0].elts[1])
        self.assertEqual(command,'machine-session');remote_trial.command_allowed(command)
        self.assertEqual(ast.literal_eval(call.args[0].elts[2]),'--parent')
        for rejected in ('endpoint-native-install-extra','machine-session-extra','update-service'):
            with self.assertRaises(PermissionError):remote_trial.command_allowed(rejected)

    def test_minimal_heartbeat_ignores_standard_policy_and_never_inventories(self):
        self.agent.call=Mock(return_value={'policy':{'body':{'application_audit':True,'browser_audit':True}}})
        with patch('guarddesk.agent.inventory',side_effect=AssertionError('inventory called')):
            remote_trial.heartbeat(self.agent)
        payload=self.agent.call.call_args.args[1]['inventory']
        self.assertEqual(payload['software'],[])
        self.assertNotIn('watch',payload);self.assertNotIn('disk_total',payload)
        self.assertEqual(payload['install_profile'],remote_trial.PROFILE)
        self.assertNotIn('policy',self.agent.assets)

    def test_native_diagnostics_distinguish_ended_and_stale_contexts(self):
        sample={'state':'active','phase':'native_transport','media':{'age_ms':12},'worker':{'age_ms':24}}
        launcher=SimpleNamespace(snapshot=lambda:{'contexts':[sample]})
        def snapshot():return remote_trial.native_diagnostics(launcher=launcher)['contexts'][0]
        self.assertTrue(snapshot()['fresh']);self.assertEqual(snapshot()['state'],'active')
        sample['media']['age_ms']=823359
        self.assertFalse(snapshot()['fresh'])
        sample['media']['age_ms']=12;sample['state']='ended'
        self.assertFalse(snapshot()['fresh']);self.assertEqual(snapshot()['state'],'ended')
        sample['state']='PRIVATE';self.assertNotIn('state',snapshot());self.assertFalse(snapshot()['fresh'])

    def test_native_failure_heartbeat_is_bounded_and_excludes_session_identity(self):
        error={'phase':'native_reserve','error_type':'OSError','native_code':1627,
               'diagnostic':'broker_image_trust:native_broker_rejected','private':'PRIVATE_TOKEN'}
        launcher=SimpleNamespace(snapshot=lambda:{'last_failure':error,
            'contexts':[{'id':'PRIVATE_SESSION','account':'PRIVATE_ACCOUNT','phase':'native_launch','error':error}]*20})
        supervisor=SimpleNamespace(platform=SimpleNamespace(native_launcher=launcher))
        self.agent.call=Mock(return_value={});remote_trial.heartbeat(self.agent,supervisor)
        sent=self.agent.call.call_args.args[1]['inventory']['collectors']['remote_only_trial']['native_remote']
        self.assertEqual(len(sent['contexts']),4);self.assertEqual(sent['last_failure']['native_code'],1627)
        self.assertNotIn('PRIVATE',json.dumps(sent))
        self.assertEqual(self.agent.call.call_args.args[0],'/api/agent/heartbeat')

    def test_startup_failure_and_handoff_are_bounded_and_not_user_spoofed(self):
        raw={'sessions':2,'helpers':0,'errors':3,'account':'PRIVATE_ACCOUNT','pid':1234,
             'last_error':{'operation':'launch','type':'PermissionError','winerror':1314,'message':'PRIVATE_TOKEN'},
             'handoff':{'status':'waiting','code':'journal_in_progress','path':'PRIVATE_PATH'}}
        supervisor=SimpleNamespace(snapshot=lambda:raw)
        self.agent.call=Mock(return_value={});remote_trial.heartbeat(self.agent,supervisor)
        sent=self.agent.call.call_args.args[1]['inventory']['collectors']['remote_only_trial']['session_startup']
        self.assertEqual(sent['last_error'],{'operation':'launch','error_type':'PermissionError','winerror':1314})
        self.assertEqual(sent['handoff'],{'status':'waiting','code':'journal_in_progress'})
        self.assertNotIn('PRIVATE',json.dumps(sent));self.assertNotIn('pid',sent)
        self.agent.feature_status['machine_agent']=raw
        state={1:{'sid':'S-1-5-21-11','account':'OWNED\\A','logon':10,'active':True}}
        call=Mock(return_value={});router=Router(self.agent,lambda:state,call)
        router.dispatch({'path':'/api/agent/heartbeat','body':{'inventory':{'collectors':{'remote_only_trial':{'session_startup':'SPOOF'}}}}},
                        {'session':1,'sid':state[1]['sid'],'logon':10})
        self.assertEqual(call.call_args.args[1]['inventory']['collectors']['remote_only_trial']['session_startup'],sent)
        self.assertNotIn('SPOOF',json.dumps(call.call_args.args[1]))
        malformed=remote_trial.session_diagnostics({'sessions':True,'helpers':-1,'errors':2**33,
            'last_error':{'operation':'PRIVATE','type':'PRIVATE','winerror':True},'handoff':{'status':'PRIVATE','code':'PRIVATE'}})
        self.assertIsNone(malformed)

    def test_media_diagnostics_reach_protected_router_heartbeat_without_private_fields(self):
        state={1:{'sid':'S-1-5-21-11','account':'OWNED\\A','logon':10,'active':True}}
        peer={'session':1,'sid':state[1]['sid'],'logon':10};call=Mock(return_value={})
        router=Router(self.agent,lambda:state,call)
        media={'peer_connected':True,'channel_open':True,'codec_failed':False,'stale_slot':False,
               'capture_sequence':73,'encoded_frames':28,'age_ms':120,'sdp':'PRIVATE','pixels':'PRIVATE'}
        worker=dict(stage=3,api=106,error=0x887a0022,polls=1,acquired=0,published=0,resets=1,age_ms=1,
            input_received=9,input_accepted=7,input_rejected=2,input_stale=1,moves_coalesced=5,
            queue_high_water=3,queue_age_max_ms=48,command_max_ms=17,pixels='PRIVATE',path='PRIVATE')
        router.native_launcher=SimpleNamespace(snapshot=lambda:{'contexts':[{'phase':'native_transport','media':media,'worker':worker}]})
        router.dispatch({'path':'/api/agent/heartbeat','body':{'inventory':{'collectors':{'remote_only_trial':{'native_remote':'SPOOF'}}}}},peer)
        sent=call.call_args.args[1]['inventory']['collectors']['remote_only_trial']['native_remote']
        self.assertEqual(sent['contexts'][0]['media'],{k:v for k,v in media.items() if k not in ('sdp','pixels')})
        self.assertEqual(sent['contexts'][0]['worker'],{k:v for k,v in worker.items() if k not in ('pixels','path')})
        self.assertNotIn('PRIVATE',json.dumps(sent));self.assertNotIn('SPOOF',json.dumps(sent))
        media.update(peer_connected=1,capture_sequence=True,encoded_frames=-1,age_ms=2**65)
        result=remote_trial.native_diagnostics(launcher=router.native_launcher)['contexts'][0]['media']
        for key in ('peer_connected','capture_sequence','encoded_frames','age_ms'):self.assertNotIn(key,result)
        worker.update(stage=True,error=-1,polls=2**32)
        result=remote_trial.native_diagnostics(launcher=router.native_launcher)['contexts'][0]['worker']
        for key in ('stage','error','polls'):self.assertNotIn(key,result)

    def test_router_rejects_collection_and_sanitizes_untrusted_heartbeat(self):
        state={1:{'sid':'S-1-5-21-11','account':'OWNED\\A','logon':10,'active':True}}
        peer={'session':1,'sid':state[1]['sid'],'logon':10};call=Mock(return_value={})
        router=Router(self.agent,lambda:state,call)
        for path in ('/local/bootstrap','/api/agent/events','/api/agent/custom-settings','/api/agent/custom-status'):
            with self.assertRaises(PermissionError):router.dispatch({'path':path,'body':{}},peer)
        router.dispatch({'path':'/api/agent/heartbeat','body':{'inventory':{'software':['PRIVATE APP'],'watch':'PRIVATE'}}},peer)
        sent=call.call_args.args[1]['inventory']
        self.assertEqual(sent['software'],[]);self.assertNotIn('watch',sent)
        protected={'phase':'native_reserve','error_type':'OSError','native_code':1627}
        router.native_launcher=SimpleNamespace(snapshot=lambda:{'last_failure':protected,'contexts':[]})
        router.dispatch({'path':'/api/agent/heartbeat','body':{'inventory':{'collectors':{'remote_only_trial':{'native_remote':'SPOOF'}}}}},peer)
        diagnostic=call.call_args.args[1]['inventory']['collectors']['remote_only_trial']['native_remote']
        self.assertEqual(diagnostic['last_failure'],protected)
        self.assertNotIn('SPOOF',json.dumps(diagnostic))
        public=router.dispatch({'path':'/local/status','body':{}})
        self.assertEqual(public['install_profile'],remote_trial.PROFILE)
        for path in ('/api/agent/native-usb-policy','/api/agent/extended-policy','/api/agent/updates/poll','/api/agent/events'):
            with self.assertRaises(PermissionError):self.agent.call(path,{})

    def test_supervisor_never_starts_policy_monitor_or_update(self):
        self.agent.machine_session_policy={'body':{'file_audit':{'enabled':True}}}
        supervisor=Supervisor(self.agent,threading.Event(),platform=SimpleNamespace())
        with patch('guarddesk.windows_watch.DirectoryMonitor',side_effect=AssertionError('monitor')):
            supervisor.sync_collectors()
        self.agent.call=Mock(side_effect=AssertionError('update call'))
        supervisor.ready={};supervisor.report_main_update()
        self.assertIsNone(supervisor.monitor)

    def test_existing_control_or_outbox_is_not_adopted(self):
        remote_trial.no_control_ledgers(self.agent)
        (self.root/'applications').mkdir()
        with self.assertRaises(PermissionError):remote_trial.no_control_ledgers(self.agent)
        (self.root/'applications').rmdir()
        with self.agent.db() as db:db.execute('INSERT INTO outbox VALUES (?,?,?)',('owned','{}',0))
        with self.assertRaises(PermissionError):remote_trial.no_control_ledgers(self.agent)

    def test_trial_enrollment_profile_is_in_first_atomic_config_write(self):
        from guarddesk.agent import enroll
        target=self.root/'new.json';watch=self.root/'watch';watch.mkdir()
        with patch('guarddesk.endpoint_transport.request',return_value={'device_id':'b'*24,'token':'owned-token'}):
            enroll(target,'https://owned.test','one-time',watch)
        self.assertEqual(json.loads(target.read_text())['install_profile'],remote_trial.PROFILE)

    def test_session_has_readiness_and_remote_but_never_profile_collectors(self):
        from guarddesk.machine_agent_session import serve_session
        stop=threading.Event();status=self.root/'session/agent/config.json';status.parent.mkdir(parents=True)
        bootstrap={'device_id':'a'*24,'session':1,'parent':100,'generation':'owned','enabled':True}
        remote=SimpleNamespace(start=Mock(),local_stop=threading.Event(),close_indicator=Mock())
        requests=[]
        def request(path,body,**kwargs):
            requests.append((path,copy.deepcopy(body)))
            if path.endswith('/uninstall/poll'):stop.set()
            return {}
        @contextlib.contextmanager
        def instance(path):yield True
        with patch('guarddesk.machine_agent_session.config_path',return_value=status),\
             patch('guarddesk.desktop_agent.instance',instance),\
             patch('guarddesk.machine_agent_session.prepare',side_effect=AssertionError('prepare collector')),\
             patch('guarddesk.desktop_agent.run',side_effect=AssertionError('desktop collector')):
            serve_session(bootstrap,1,stop,request,remote_factory=lambda *args:remote)
        self.assertTrue(remote.start.called);self.assertTrue(remote.local_stop.is_set())
        self.assertFalse(status.exists())
        ready=json.loads(status.with_name('desktop-status.json').read_text())
        self.assertEqual(ready['state'],'stopped');self.assertEqual(ready['install_profile'],remote_trial.PROFILE)
        self.assertTrue(any(path.endswith('/heartbeat') for path,body in requests))
        self.assertFalse(any('custom' in path or 'events' in path for path,body in requests))

    def test_worker_once_restore_and_loop_never_construct_control_workers(self):
        stop=threading.Event();supervisor=Mock();supervisor.start.return_value=supervisor
        local={'parent_pid':100,'helpers':[{'role':'machine_session_helper','pid':101,'session_id':6,'launch_observed_at':1.0}]}
        supervisor.local_process_diagnostics.return_value=local
        def step(worker):stop.set();return 'normal'
        with patch('guarddesk.machine_agent.eligible',return_value=True),\
             patch('guarddesk.windows_privilege.is_admin',return_value=True),\
             patch('guarddesk.windows_controls.WindowsControls',side_effect=AssertionError('controls')),\
             patch('guarddesk.application_control.ExtendedWorker',side_effect=AssertionError('extended')),\
             patch('guarddesk.custom_client.CustomClient',side_effect=AssertionError('custom')),\
             patch('guarddesk.remote_components.read_cohort',return_value={}),\
             patch('guarddesk.update_native.folder',return_value=self.root),\
             patch('guarddesk.remote_trial.heartbeat',return_value={}) as heartbeat,\
             patch('guarddesk.machine_agent.Supervisor',return_value=supervisor),\
             patch('guarddesk.decommission.native_step',side_effect=step),\
             patch('guarddesk.update_client.save') as save:
            self.assertEqual(remote_trial.worker(self.path,stop,once=True)['status'],'configured_remote_only')
            self.assertEqual(remote_trial.worker(self.path,stop,restore=True)['status'],'nothing_to_restore')
            remote_trial.worker(self.path,stop)
            supervisor.close.assert_called_once();self.assertEqual(heartbeat.call_count,2)
            health=[c.args[1] for c in save.call_args_list if c.args[0].name=='native-health.json']
            self.assertEqual(len(health),1);self.assertEqual(health[0]['process_diagnostics'],local)
            json.dumps(health[0])
        with patch('guarddesk.machine_agent.eligible',return_value=False),\
             patch('guarddesk.windows_privilege.is_admin',return_value=True):
            with self.assertRaises(PermissionError):remote_trial.worker(self.path,stop,once=True)

    def test_startup_failure_phase_survives_shutdown_without_credentials(self):
        for phase in ('construct_supervisor','start_supervisor','running'):
            with self.subTest(phase=phase):
                stop=threading.Event();supervisor=Mock();supervisor.start.return_value=supervisor
                supervisor.close.side_effect=stop.set
                failure=OSError('PRIVATE_TOKEN / arbitrary command')
                if phase=='start_supervisor':supervisor.start.side_effect=failure
                with patch('guarddesk.machine_agent.eligible',return_value=True),patch('guarddesk.windows_privilege.is_admin',return_value=True),patch('guarddesk.machine_agent.Supervisor',side_effect=failure if phase=='construct_supervisor' else None,return_value=supervisor),patch('guarddesk.decommission.native_step',side_effect=failure):
                    with self.assertRaises(OSError):remote_trial.worker(self.path,stop)
                body=json.loads((self.root/'native-startup.json').read_text())
                self.assertEqual(body['phase'],phase);self.assertEqual(body['state'],'failed')
                self.assertNotIn('PRIVATE_TOKEN',json.dumps(body));self.assertNotIn('command',json.dumps(body))

    def test_trial_and_standard_config_cannot_cross_start(self):
        with patch.object(remote_trial,'ENABLED',False):
            with self.assertRaises(ValueError):Agent(self.path)
        body=json.loads(self.path.read_text());body.pop('install_profile');self.path.write_text(json.dumps(body))
        with self.assertRaises(ValueError):Agent(self.path)

    def test_native_removal_never_restores_controls_or_requires_updater_task(self):
        from guarddesk.decommission import native_step
        self.agent.call=Mock(side_effect=lambda path,body:{'job':{'id':'owned-job','main':'ready','status':'running'}})
        worker=SimpleNamespace(agent=self.agent,extended_companion=None,restore=Mock(side_effect=AssertionError('restore')))
        with patch('guarddesk.decommission.remove_task') as remove,\
             patch('guarddesk.application_control.ExtendedWorker',side_effect=AssertionError('extended')),\
             patch('guarddesk.update_native.remove_broker_task',side_effect=AssertionError('updater')):
            self.assertEqual(native_step(worker),'done');remove.assert_called_once()
        worker.restore.assert_not_called()


if __name__=='__main__':unittest.main()
