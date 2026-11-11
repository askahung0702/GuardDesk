import copy
import datetime as dt
import json
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
import test_system
from guarddesk import custom_settings as custom
from guarddesk.custom_client import ScheduleEngine,check_packet,CustomClient
from guarddesk.custom_network import NetworkLease
from guarddesk.custom_software import publisher_xml
from guarddesk.policy import DEFAULT_POLICY,agent_policy_wire,decode_agent_policy
from guarddesk.store import canonical,digest


def schedule(**changes):
    return {'id':'scheduled-test','name':'Test','action':'shutdown','days':[1,2,3,4,5,6,7],'times':['22:00'],'delay_seconds':60,'allow_cancel':True,'defer_minutes':1,'idle_minutes':0,'message':'Test reminder',**changes}


def packet(device='test',body=None,busy=False):
    body=copy.deepcopy(custom.DEFAULT if body is None else body)
    return {'protocol':1,'device_id':device,'body':body,'fingerprint':digest(canonical(body)),'busy':busy}


class CustomSettingsApiTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def write(self,body,scope='global',target='',revision=0,**extra):
        draft={'scope':scope,'target':target,'revision':revision,'body':body,**extra}
        preview=self.api('/api/custom-settings/preview',draft)
        return self.api('/api/custom-settings/publish',{**draft,'expected_generation':preview['generation'],'expected_scope_generation':preview['scope_generation'],'confirm':'publish_custom'})

    def assert_http(self,code,fn):
        with self.assertRaises(urllib.error.HTTPError) as error:fn()
        self.assertEqual(error.exception.code,code)
        error.exception.close()

    def test_default_packet_and_legacy_policy_are_unchanged(self):
        agent,eid,_=self.make_agent();before=agent.heartbeat()
        p=agent.call('/api/agent/custom-settings',{'protocol':1})
        self.assertEqual(p['body'],custom.DEFAULT);self.assertEqual(p['device_id'],eid)
        self.write({'schedules':[schedule()]})
        after=agent.heartbeat()
        self.assertEqual(before['body'],after['body']);self.assertEqual(before['version'],after['version'])
        self.assertNotIn('custom_settings',agent_policy_wire(before)['body'])
        self.assertEqual(decode_agent_policy(agent_policy_wire(before))['body'],before['body'])

    def test_group_and_device_section_inheritance_and_empty_override(self):
        agent,eid,_=self.make_agent();parent=self.api('/api/groups',{'name':'Custom Parent'});child=self.api('/api/groups',{'name':'Custom Child','parent_id':parent['id']})
        device=self.api('/api/state')['devices'][0]
        self.api('/api/devices/move',{'device_id':eid,'group_id':child['id'],'revision':device['management_revision']})
        self.write({'schedules':[schedule()]});self.write({'compatibility':[{'module':'browser_history','min_build':0,'max_build':999999,'expires':time.time()+3600,'reason':'Issue'}]},'group',parent['id'])
        self.write({'schedules':[]},'device',eid)
        result=agent.call('/api/agent/custom-settings',{'protocol':1})
        self.assertEqual(result['body']['schedules'],[]);self.assertEqual(len(result['body']['compatibility']),1)
        self.assertEqual(result['sources']['compatibility']['target'],parent['id'])
        self.write({},'device',eid,1)
        self.assertEqual(len(agent.call('/api/agent/custom-settings',{'protocol':1})['body']['schedules']),1)

    def test_preview_is_read_only_and_stale_generation_rejected(self):
        self.make_agent();draft={'scope':'global','target':'','revision':0,'body':{'schedules':[schedule()]}}
        first=self.api('/api/custom-settings/preview',draft)
        self.assertEqual(first['affected_count'],1);self.assertEqual(self.api('/api/custom-settings')['profiles'],[])
        self.write({'software':[]},'global')
        self.assert_http(409,lambda:self.api('/api/custom-settings/publish',{**draft,'expected_generation':first['generation'],'confirm':'publish_custom'}))

    def test_history_restores_as_new_revision_and_network_ack_required(self):
        self.make_agent();self.write({'schedules':[schedule()]});self.write({'schedules':[]},revision=1)
        history=self.api('/api/custom-settings/history?scope=global')['versions']
        self.assertEqual([r['revision'] for r in history],[2,1]);self.write(history[1]['body'],revision=2)
        self.assertEqual(self.api('/api/custom-settings')['profiles'][0]['revision'],3)
        self.assert_http(400,lambda:self.write({'network':{'ipv6':'disable'}},revision=3))
        self.write({'network':{'ipv6':'prefer_ipv4'}},revision=3,network_ack=True)

    def test_roles_csrf_and_revoked_endpoint(self):
        agent,eid,_=self.make_agent();draft={'scope':'global','target':'','revision':0,'body':{}}
        self.assert_http(403,lambda:self.api('/api/custom-settings/preview',draft,csrf=False))
        self.api('/api/login',{'username':'reader','password':self.password})
        self.assertIn('profiles',self.api('/api/custom-settings'))
        self.assert_http(403,lambda:self.api('/api/custom-settings/preview',draft))
        self.csrf=self.api('/api/login',{'username':'admin','password':self.password})['csrf']
        self.api('/api/devices/revoke',{'device_id':eid})
        with self.assertRaises(ConnectionError):agent.call('/api/agent/custom-settings',{'protocol':1})

    def test_status_is_device_scoped_and_current_fingerprint_checked(self):
        agent,eid,_=self.make_agent();p=agent.call('/api/agent/custom-settings',{'protocol':1})
        report={'protocol':1,'role':'main','version':'0.4.37','fingerprint':p['fingerprint'],'report':{'state':'reported'}}
        agent.call('/api/agent/custom-status',report);agent.call('/api/agent/custom-status',report)
        result=self.api('/api/custom-settings');self.assertEqual(len(result['reports']),1);self.assertTrue(result['reports'][0]['matches_current'])
        self.write({'schedules':[schedule()]})
        self.assertFalse(self.api('/api/custom-settings')['reports'][0]['matches_current'])
        with self.store.connect() as db:self.assertEqual(db.execute("SELECT count(*) FROM events WHERE kind='agent.custom_status'").fetchone()[0],1)
        with self.assertRaises(ConnectionError):agent.call('/api/agent/custom-status',{**report,'device_id':'other'})

    def test_typed_schema_rejects_shell_commands_and_broad_software(self):
        for body in ({'command':'cmd.exe'},{'network':{'ipv6':'disable','shell':'anything'}},{'schedules':[schedule(action='run_script')]},{'schedules':[schedule(days=[[]])]},{'schedules':[schedule(times=[{}])]}):
            self.assert_http(400,lambda b=body:self.api('/api/custom-settings/preview',{'scope':'global','target':'','revision':0,'body':b}))
        rule={'name':'Too broad','collection':'Exe','publisher':'CN=*','product':'*','binary':'*','min_version':'0.0.0.0','max_version':'*'}
        with self.assertRaises(ValueError):custom.validate({**custom.DEFAULT,'software':[rule]})

    def test_atomic_action_lease_blocks_update_poll_and_holds_current_schedule(self):
        agent,eid,_=self.make_agent();now=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime('%H:%M')
        self.write({'schedules':[schedule(times=[now])]});p=agent.call('/api/agent/custom-settings',{'protocol':1})
        occurrence=custom.due_schedules(p['body'],time.time())[0][1]
        lease=agent.call('/api/agent/custom-action/authorize',{'fingerprint':p['fingerprint'],'rule_id':'scheduled-test','occurrence':occurrence})
        self.assertEqual(lease['action'],'shutdown')
        from guarddesk import removal
        from guarddesk.management import ManagementError
        with self.store.connect() as db:
            with self.assertRaisesRegex(ManagementError,'自訂動作'):removal.request(db,{'role':'admin','username':'admin'},{'device_id':eid,'confirm_name':'test-endpoint','reason':'Test'})
        r=agent.call('/api/agent/updates/poll',{'role':'native','version':'0.4.37'})
        self.assertIsNone(r['job']);self.assertEqual(r['waiting_for'],'custom_action')
        with self.assertRaises(ConnectionError):agent.call('/api/agent/custom-action/authorize',{'fingerprint':p['fingerprint'],'rule_id':'scheduled-test','occurrence':occurrence})
        agent.call('/api/agent/custom-action/complete',{'token':lease['token']})
        with self.store.connect() as db:self.assertFalse(custom.action_leased(db,eid))
        with self.assertRaises(ConnectionError):agent.call('/api/agent/custom-action/authorize',{'fingerprint':p['fingerprint'],'rule_id':'scheduled-test','occurrence':occurrence})

    def test_scope_change_after_preview_requires_new_preview(self):
        self.make_agent();draft={'scope':'global','target':'','revision':0,'body':{'schedules':[schedule()]}}
        result=self.api('/api/custom-settings/preview',draft)
        self.api('/api/groups',{'name':'Scope changed after preview'})
        self.assert_http(409,lambda:self.api('/api/custom-settings/publish',{**draft,'expected_generation':result['generation'],'expected_scope_generation':result['scope_generation'],'confirm':'publish_custom'}))

    def test_custom_group_requires_explicit_inheritance_before_deletion(self):
        group=self.api('/api/groups',{'name':'Custom settings group'})
        self.write({'schedules':[schedule()]},'group',group['id'])
        self.assert_http(409,lambda:self.api('/api/groups/delete',group))
        self.write({},'group',group['id'],1);self.api('/api/groups/delete',group)
        self.assertFalse(any(p['target']==group['id'] for p in self.api('/api/custom-settings')['profiles']))

    def test_compatibility_preserves_security_log_clear_alerts(self):
        from guarddesk.windows_events import SecurityCollector
        agent,_,_=self.make_agent();collector=SecurityCollector(agent,object())
        policy={**copy.deepcopy(DEFAULT_POLICY),'application_audit':False,'_custom_skip_security_files':True}
        with agent.db() as db:collector.ingest(db,{'event_id':1102,'record_id':123,'data':{},'occurred':time.time()},policy)
        with agent.db() as db:events=[json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox')]
        self.assertEqual(events[0]['kind'],'agent.audit_log_cleared');self.assertEqual(events[0]['severity'],'critical')


class FakeAgent:
    def __init__(self,path):
        self.config_path=path/'config.json';self.config={'device_id':'test'};self.path=path/'state.sqlite3';self.calls=[];self.events=[];self.feature_status={}
        with self.db() as db:db.execute('CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT)')
    @contextmanager
    def db(self):
        db=sqlite3.connect(self.path);db.row_factory=sqlite3.Row
        try:yield db;db.commit()
        finally:db.close()
    def queue(self,*args,**kwargs):self.events.append(args)
    def call(self,path,body):
        self.calls.append((path,body))
        if path.endswith('/authorize'):return {'token':'test-token','action':'shutdown'}
        if path.endswith('/custom-settings'):return packet()
        return {'ok':True}


class Actions:
    def __init__(self):self.answer='continue';self.executed=[];self.idle=100;self.boot=1000;self.people=[{'id':1,'user':'example','active':True}]
    def sessions(self):return self.people.copy()
    def prompt(self,*args):return self.answer
    def execute(self,*args):self.executed.append(args)
    def idle_minutes(self,*args):return self.idle
    def boot_age(self):return self.boot


class CustomRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.agent=FakeAgent(self.root);self.now=dt.datetime(2026,10,20,22,0,tzinfo=dt.timezone(dt.timedelta(hours=8))).timestamp();self.mono=1000.;self.stop=threading.Event();self.actions=Actions();self.p=packet(body={**copy.deepcopy(custom.DEFAULT),'schedules':[schedule()]})
        self.engine=ScheduleEngine(self.agent,self.actions,lambda:self.p,self.stop,clock=lambda:self.now,monotonic=lambda:self.mono)
    def tearDown(self):self.temp.cleanup()
    def start(self):
        self.engine.tick(self.p)
        for _ in range(30):
            if not self.engine.pending or self.engine.pending['responses']:break
            time.sleep(.01)
    def advance(self,seconds):self.now+=seconds;self.mono+=seconds
    def test_countdown_executes_once_and_restart_does_not_replay(self):
        self.start();self.assertEqual(self.actions.executed,[]);self.advance(61);self.engine.tick(self.p)
        self.assertEqual(len(self.actions.executed),1);self.assertIn('accepted',self.engine.report['state'])
        again=ScheduleEngine(self.agent,self.actions,lambda:self.p,self.stop,clock=lambda:self.now,monotonic=lambda:self.mono);again.tick(self.p)
        self.assertEqual(len(self.actions.executed),1)
    def test_cancel_never_executes(self):
        self.actions.answer='cancel';self.start();self.engine.tick(self.p);self.advance(120);self.engine.tick(self.p);self.assertEqual(self.actions.executed,[])
    def test_defer_is_bounded_to_one(self):
        self.actions.answer='defer';self.start();self.engine.tick(self.p);self.assertEqual(self.engine.report['state'],'deferred');self.advance(61);self.engine.tick(self.p)
        for _ in range(30):
            if self.engine.pending and self.engine.pending['responses']:break
            time.sleep(.01)
        self.engine.tick(self.p);self.assertIsNone(self.engine.pending);self.assertEqual(self.actions.executed,[])
    def test_busy_revocation_and_session_change_cancel(self):
        self.start();self.p={**self.p,'busy':True};self.advance(61);self.engine.tick(self.p);self.assertEqual(self.actions.executed,[])
    def test_session_identity_is_rechecked(self):
        self.start();self.actions.people=[{'id':1,'user':'changed','active':True}];self.advance(61);self.engine.tick(self.p);self.assertEqual(self.actions.executed,[])
    def test_reused_session_id_after_new_logon_cancels_old_notice(self):
        self.actions.people=[{'id':1,'user':'example','active':True,'logon':100}];self.start();self.actions.people=[{'id':1,'user':'example','active':True,'logon':200}]
        self.advance(61);self.engine.tick(self.p);self.assertEqual(self.actions.executed,[])
    def test_final_fetch_failure_or_policy_change_never_executes(self):
        self.start();self.engine.fetch=lambda:packet();self.advance(61);self.engine.tick(self.p);self.assertEqual(self.actions.executed,[])
    def test_stopping_clock_jump_and_new_boot_are_safe(self):
        self.start();self.stop.set();self.advance(61);self.engine.tick(self.p);self.assertEqual(self.actions.executed,[])
        self.stop.clear();self.engine.pending=None;self.actions.boot=0;self.engine.tick(self.p);self.assertIsNone(self.engine.pending)
    def test_clock_jump_cancels_before_any_windows_action(self):
        self.start();self.now+=120;self.engine.tick(self.p);self.assertEqual(self.actions.executed,[]);self.assertIsNone(self.engine.pending)
    def test_idle_does_not_masquerade_as_cancellable_message_text(self):
        self.p=packet(body={**copy.deepcopy(custom.DEFAULT),'schedules':[schedule(idle_minutes=10)]});self.actions.idle=0;self.start();self.assertIsNone(self.engine.pending);self.assertEqual(self.actions.executed,[])
    def test_taipei_time_independent_of_local_timezone_and_no_late_backfill(self):
        self.assertEqual(len(custom.due_schedules(self.p['body'],self.now)),1)
        self.assertEqual(custom.due_schedules(self.p['body'],self.now+61),[])
    def test_packet_identity_and_integrity(self):
        for p in ({**packet(),'device_id':'other'},{**packet(),'protocol':2},{**packet(),'fingerprint':'0'*64},{k:v for k,v in packet().items() if k!='body'}):
            with self.assertRaises(ValueError):check_packet(self.agent,p)
    def test_overlapping_schedules_including_sunday_midnight_are_rejected(self):
        for schedules in ([schedule(times=['22:00','22:01'])],[schedule(days=[7],times=['23:59']),schedule(id='other',days=[1],times=['00:00'])]):
            with self.assertRaises(ValueError):custom.validate({**custom.DEFAULT,'schedules':schedules})
    def test_expiring_compatibility_keeps_app_control_and_security_alerts(self):
        policy=copy.deepcopy(DEFAULT_POLICY);settings={**copy.deepcopy(custom.DEFAULT),'compatibility':[{'module':'process_events','min_build':100,'max_build':200,'expires':self.now+60,'reason':'Test'}]}
        with patch('guarddesk.custom_settings.time.time',return_value=self.now):result=custom.compatible_policy(policy,settings,150)
        self.assertFalse(result['application_audit']);self.assertEqual(result['application_control'],policy['application_control']);self.assertTrue(policy['application_audit'])
        self.assertEqual(custom.compatibility_modules(settings,150,self.now+61),set());self.assertEqual(custom.compatibility_modules(settings,99,self.now),set())
    def test_disabled_client_is_throttled_and_legacy_server_failure_does_not_touch_queue(self):
        client=CustomClient(self.agent,self.stop)
        for _ in range(10):client.cycle()
        self.assertEqual(sum(p.endswith('/custom-settings') for p,_ in self.agent.calls),1)
        self.assertEqual(sum(p.endswith('/custom-status') for p,_ in self.agent.calls),1)
        self.assertEqual(self.agent.events,[])
    def test_wrong_or_missing_native_identity_never_reaches_controls(self):
        from guarddesk.custom_windows import trusted_native,launch_session_action
        for identity in ('..','../../other','invalid',None):
            with self.assertRaises((ValueError,OSError)):trusted_native({'device_id':identity})
        with self.assertRaises(OSError):launch_session_action(1,'lock')
    def test_schedule_edits_do_not_reapply_existing_software_or_os_audit(self):
        from guarddesk.application_control import ExtendedWorker
        rule={'name':'Example','collection':'Exe','publisher':'CN=Example','product':'Example','binary':'*','min_version':'0.0.0.0','max_version':'*'}
        self.agent.custom_packet=packet(body={**copy.deepcopy(custom.DEFAULT),'software':[rule]})
        self.agent.call=lambda *args:{'device_id':'test','body':copy.deepcopy(DEFAULT_POLICY)}
        worker=ExtendedWorker(self.agent)
        with patch('guarddesk.custom_windows.trusted_native',return_value=self.root),patch('guarddesk.process_audit.configure',return_value={'process_audit_enabled':True}) as audit,patch('guarddesk.application_control.native_action',return_value={'application_control':'configured_requires_execution_test'}) as native,patch.object(worker,'poll'),patch.object(worker,'configure_documents'):
            worker.configure();self.agent.custom_packet['body']['schedules']=[schedule()];worker.configure()
            native.assert_called_once();audit.assert_called_once_with(worker.directory,True)
    def test_stop_after_fetch_prevents_any_native_effect(self):
        from unittest.mock import Mock
        client=CustomClient(self.agent,self.stop);client.native=True;client.network=Mock();client.scheduler=Mock()
        def fetch():client.local_stop.set();return packet()
        client.fetch=fetch;result=client.cycle()
        self.assertEqual(result['state'],'stopped');client.network.apply.assert_not_called();client.scheduler.tick.assert_not_called()
    def test_process_pause_keeps_security_source_and_restores_without_network(self):
        from unittest.mock import Mock
        from guarddesk.application_control import ExtendedWorker
        self.agent.custom_packet=packet(body={**copy.deepcopy(custom.DEFAULT),'compatibility':[{'module':'process_events','min_build':0,'max_build':999999,'expires':time.time()+3600,'reason':'Test'}]})
        self.agent.flush=lambda **kwargs:None
        worker=ExtendedWorker(self.agent);worker.policy=copy.deepcopy(DEFAULT_POLICY);worker.policy['file_audit']['enabled']=False;worker.collector=Mock();worker.collector.poll.return_value={'read':0}
        worker.poll();self.assertFalse(worker.collector.poll.call_args.args[0]['application_audit']);self.assertTrue(worker.policy['application_audit'])
        self.agent.custom_packet=packet();worker.poll();self.assertTrue(worker.collector.poll.call_args.args[0]['application_audit'])
    def test_cancel_is_final_even_if_journal_or_queue_write_fails(self):
        self.start()
        with patch.object(self.agent,'db',side_effect=sqlite3.OperationalError('busy')):
            with self.assertRaises(sqlite3.Error):self.engine.record('cancelled_offline')
        self.assertIsNone(self.engine.pending);self.assertEqual(self.actions.executed,[])
    def test_cache_write_failure_does_not_prevent_native_network_recovery(self):
        from unittest.mock import Mock
        client=CustomClient(self.agent,self.stop);client.native=True;client.network=Mock();client.network.path.exists.return_value=True;client.network.apply.return_value={'state':'restored_requires_restart'};client.scheduler=Mock();client.scheduler.pending=None
        client.fetch=Mock(side_effect=sqlite3.OperationalError('busy'));result=client.cycle()
        self.assertEqual(result['network']['state'],'restored_requires_restart');client.network.apply.assert_called_once_with('unchanged',False);client.scheduler.tick.assert_not_called()
    def test_shutdown_api_is_called_without_forcing_apps_closed(self):
        from contextlib import contextmanager
        from unittest.mock import Mock
        from guarddesk.custom_windows import execute
        @contextmanager
        def privilege():yield
        api=Mock();api.InitiateSystemShutdownExW.return_value=1
        with patch('guarddesk.custom_windows.enable_shutdown',side_effect=privilege),patch('guarddesk.custom_windows.ctypes.WinDLL',return_value=api):execute('shutdown',[1])
        args=api.InitiateSystemShutdownExW.call_args.args
        self.assertIs(args[3],False);self.assertIs(args[4],False)


class MemoryRegistry:
    def __init__(self,value=None):self.value=value;self.fail=False
    def read(self):return self.value
    def write(self,value):
        if self.fail:raise OSError('Simulated registry write failure')
        self.value=value


class NetworkAndSoftwareTest(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.now=1000;self.registry=MemoryRegistry();self.lease=NetworkLease(self.root/'network.json',self.registry,clock=lambda:self.now)
    def tearDown(self):self.temp.cleanup()
    def test_network_recovers_missing_original_and_nondefault_original(self):
        self.lease.apply('prefer_ipv4');self.assertEqual(self.registry.value,0x20);self.lease.restore();self.assertIsNone(self.registry.value)
        self.registry.value=0x10;self.lease.apply('disable');self.assertEqual(self.registry.value,0xff);self.lease.restore();self.assertEqual(self.registry.value,0x10)
    def test_offline_expiry_and_restart_restore_without_inferred_default(self):
        self.registry.value=0x40;self.lease.apply('disable');self.now+=301
        restarted=NetworkLease(self.lease.path,self.registry,clock=lambda:self.now);self.assertIn('restored',restarted.apply('disable',False)['state']);self.assertEqual(self.registry.value,0x40)
    def test_external_change_preserved_and_write_failure_recoverable(self):
        self.lease.apply('prefer_ipv4');self.registry.value=0x80;self.assertEqual(self.lease.restore()['state'],'conflict');self.assertEqual(self.registry.value,0x80)
    def test_failed_mode_change_keeps_a_recoverable_journal(self):
        self.registry.value=0x40;self.lease.apply('prefer_ipv4');self.registry.fail=True
        with self.assertRaises(OSError):self.lease.apply('disable')
        self.registry.fail=False;self.lease.restore();self.assertEqual(self.registry.value,0x40)
    def test_invalid_recovery_state_rejected_without_registry_write(self):
        self.lease.path.write_text('{"managed":true}',encoding='utf-8')
        with self.assertRaises(OSError):self.lease.restore()
        self.assertIsNone(self.registry.value)
    def test_company_network_policy_prevents_new_registry_setting(self):
        from guarddesk.custom_network import Registry
        registry=Registry();lease=NetworkLease(self.root/'company-network.json',registry)
        with patch.object(registry,'read',return_value=None),patch.object(registry,'write') as write,patch.object(registry,'policy_managed',return_value=True):
            self.assertEqual(lease.apply('disable')['state'],'conflict');write.assert_not_called()
        self.assertFalse(lease.path.exists())
    def test_publisher_rules_merge_with_existing_rules_and_appx_allow(self):
        control={'enabled':True,'mode':'denylist','block_msi':False,'rules':[{'name':'Existing','collection':'Exe','type':'path','value':r'*\old.exe'}]}
        rule={'name':'Example product','collection':'Exe','publisher':'CN=Example Corp, O=Example','product':'Example Product','binary':'*','min_version':'0.0.0.0','max_version':'*'}
        xml=publisher_xml(control,[rule,{**rule,'collection':'Msi'},{**rule,'collection':'Appx'}]);root=ET.fromstring(xml)
        self.assertEqual(root.find(".//FilePathRule[@Action='Deny']/Conditions/FilePathCondition").get('Path'),r'*\old.exe')
        self.assertEqual(len(root.findall(".//FilePublisherRule[@Action='Deny']")),3)
        self.assertIsNotNone(root.find("RuleCollection[@Type='Appx']/FilePublisherRule[@Action='Allow']"))
        self.assertEqual(publisher_xml(control,[rule]),publisher_xml(control,[rule]))
    def test_dangerous_publisher_rules_are_rejected(self):
        rule={'name':'Bad','collection':'Exe','publisher':'CN=Example','product':'Windows','binary':'*','min_version':'0.0.0.0','max_version':'*'}
        for r in (rule,{**rule,'product':'*'},{**rule,'product':'Example','publisher':'CN=*'},{**rule,'product':'Example','min_version':'1.0.0.0','max_version':'0.0.0.1'}):
            with self.assertRaises(ValueError):publisher_xml(copy.deepcopy(DEFAULT_POLICY['application_control']),[r])
    def test_custom_denial_does_not_enable_a_disabled_legacy_allowlist(self):
        disabled={'enabled':False,'mode':'allowlist','block_msi':True,'rules':[{'name':'Dormant allow','collection':'Exe','type':'path','value':r'*\dormant.exe'}]}
        rule={'name':'Example','collection':'Exe','publisher':'CN=Example','product':'Example','binary':'*','min_version':'0.0.0.0','max_version':'*'}
        root=ET.fromstring(publisher_xml(disabled,[rule]))
        paths=[n.get('Path') for n in root.findall(".//FilePathRule[@Action='Allow']/Conditions/FilePathCondition")]
        self.assertEqual(paths,['*','*']);self.assertNotIn(r'*\dormant.exe',paths)


if __name__=='__main__':unittest.main()
