"""Synthetic process identities, owned policies and local test endpoints only."""
import copy
import json
import time
import unittest
from unittest.mock import patch
import test_management
import test_endpoint_controls as fixtures
from guarddesk.application_exclusions import validate_exclusions,excluded_application
from guarddesk.policy import DEFAULT_POLICY,agent_policy_wire,decode_agent_policy
from guarddesk.windows_events import SecurityCollector
from guarddesk.store import Store
from guarddesk.application_control import ExtendedWorker


class ApplicationExclusionsTest(unittest.TestCase):
    def test_exact_name_full_path_case_and_extended_prefix(self):
        for path in (r'C:\Windows\System32\conhost.exe',r'D:\Tools\ConHost.EXE','conhost.exe'):
            self.assertTrue(excluded_application('application.started','info',{'path':path,'process':path},['conhost.exe']))
        rule=r'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
        for path in (rule,rule.upper(),'\\\\?\\'+rule):
            self.assertTrue(excluded_application('application.stopped','info',{'process':path},[rule]))
        for path in (r'C:\Temp\docker.exe',r'C:\Tools\mydocker.exe',r'C:\Tools\docker.exe.bak'):
            self.assertFalse(excluded_application('application.started','info',{'process':path},[rule]))
        self.assertFalse(excluded_application('application.started','info',{'process':'docker.exe'},[]))

    def test_alerts_other_events_unknown_and_conflicting_identity_remain(self):
        for kind in ('application.blocked','application.audit_would_block','agent.audit_gap','file.opened','web.upload_started','export.blocked'):
            self.assertFalse(excluded_application(kind,'info',{'path':'docker.exe'},['docker.exe']))
        for level in ('warning','critical'):
            self.assertFalse(excluded_application('application.started',level,{'path':'docker.exe'},['docker.exe']))
        for details in ({},{'process':123},{'process':'docker.exe','path':'other.exe'}):
            self.assertFalse(excluded_application('application.started','info',details,['docker.exe']))

    def test_validation_is_bounded_exact_and_no_command_or_glob(self):
        self.assertEqual(validate_exclusions(['docker.exe',r'C:\Tools\worker.com',r'\\server\share\worker.exe']),['docker.exe',r'C:\Tools\worker.com',r'\\server\share\worker.exe'])
        for rules in (None,'docker.exe',['docker.exe','DOCKER.EXE'],['*.exe'],[r'%TEMP%\x.exe'],['docker.exe --help'],[r'..\x.exe'],['C:docker.exe'],['C:\\Tools'],[' x.exe'],['bad\n.exe'],['a.exe']*101):
            with self.subTest(rules=rules),self.assertRaises(ValueError):validate_exclusions(rules)

    def test_wire_keeps_legacy_body_and_roundtrips_user_packets_without_mutation(self):
        body=copy.deepcopy(DEFAULT_POLICY);body['application_audit_exclusions']=['docker.exe']
        packet={'body':body,'fingerprint':'fixture','user_policies':{'acme\\alice':{'body':copy.deepcopy(body)}}};before=copy.deepcopy(packet)
        wire=agent_policy_wire(packet)
        self.assertEqual(packet,before)
        for p in (wire,wire['user_policies']['acme\\alice']):
            self.assertEqual(set(p['body']),set(DEFAULT_POLICY)-{'application_audit_exclusions','website_control','application_publishers'})
            self.assertEqual(p['audit_options']['application_exclusions'],['docker.exe'])
            self.assertEqual(p['target_controls']['website_control'],body['website_control'])
            self.assertEqual(p['target_controls']['application_publishers'],body['application_publishers'])
        self.assertEqual(decode_agent_policy(wire)['body'],body)
        self.assertEqual(decode_agent_policy({'body':{}})['body']['application_audit_exclusions'],[])
        with self.assertRaises(ValueError):decode_agent_policy({'body':{},'audit_options':{'shell':'cmd.exe'}})


class ApplicationSourceTest(unittest.TestCase):
    setUp=fixtures.EndpointTest.setUp
    tearDown=fixtures.EndpointTest.tearDown
    queued=fixtures.EndpointTest.queued

    def test_native_interactive_primary_does_not_duplicate_security_reads_or_lose_delete_and_warning(self):
        collector=SecurityCollector(self.agent,source=object())
        policy={**self.policy,'_native_interactive_open_primary':True}
        with self.agent.db() as db:
            collector.ingest(db,fixtures.event(1,4656),policy)
            collector.ingest(db,fixtures.event(2,4663),policy)
            collector.ingest(db,fixtures.event(3,4663,mask='0x10001'),policy)
            collector.ingest(db,fixtures.event(4,4660),policy)
            collector.ingest(db,fixtures.event(5,1102),policy)
        rows=self.queued()
        self.assertEqual([r['kind'] for r in rows],['file.delete_requested','file.deleted','agent.audit_log_cleared'])
        self.assertEqual(rows[1]['details']['path'],r'C:\Users\employee\report.txt')
        with self.agent.db() as db:collector.ingest(db,fixtures.event(6,4663),self.policy)
        self.assertEqual(self.queued()[-1]['kind'],'file.opened')

    def test_security_creation_and_termination_filtered_without_losing_other_actors(self):
        self.policy['application_audit_exclusions']=['conhost.exe','docker.exe']
        collector=SecurityCollector(self.agent,source=object())
        with self.agent.db() as db:
            for rid,eid,path in [(1,4688,r'C:\Windows\System32\conhost.exe'),(2,4689,r'C:\Tools\docker.exe'),(3,4688,r'C:\Tools\editor.exe')]:
                e=fixtures.event(rid,eid);e['data'].update(NewProcessName=path,ProcessName=path,NewProcessId='0x10')
                collector.ingest(db,e,self.policy)
            collector.ingest(db,fixtures.event(4,4663,path=r'C:\Docs\report.docx'),self.policy)
            collector.ingest(db,fixtures.event(5,1102),self.policy)
        self.assertEqual([r['kind'] for r in self.queued()],['application.started','file.opened','agent.audit_log_cleared'])
        self.assertEqual(self.queued()[0]['details']['user'],r'COMPANY\employee')

    def test_extended_worker_wire_decode_offline_policy_and_no_exclusion_triggered_os_change(self):
        body=copy.deepcopy(self.policy);body['application_audit_exclusions']=['docker.exe']
        from guarddesk.file_access import ALL_ACCESSES,INTERVAL,options
        body['file_audit']['exclude_paths']=[INTERVAL+'60',r'C:\Owned\excluded',ALL_ACCESSES]
        worker=ExtendedWorker(self.agent)
        with patch.object(self.agent,'call',side_effect=lambda *args:agent_policy_wire({'device_id':'test-device','body':body})),patch('guarddesk.process_audit.configure',return_value={'process_audit_enabled':True}) as configure,patch.object(worker,'poll'),patch.object(worker,'configure_documents'):
            worker.configure();body['application_audit_exclusions']=['conhost.exe'];worker.configure()
            configure.assert_called_once()
        self.assertEqual(worker.policy['application_audit_exclusions'],['conhost.exe'])
        with self.agent.db() as db:
            persisted=json.loads(db.execute("SELECT value FROM state WHERE key='extended_policy'").fetchone()[0])
            self.assertNotIn('application_audit_exclusions',persisted)
        offline=ExtendedWorker(self.agent);offline.status={}
        class Collector:
            def poll(self,policy):return {'observed_rules':policy['application_audit_exclusions']}
        offline.collector=Collector()
        with patch.object(self.agent,'flush'),patch.object(self.agent,'call'),patch.object(offline,'configure_documents'):
            report=offline.poll()
        self.assertEqual(report['process_audit']['observed_rules'],['conhost.exe'])
        self.assertEqual(offline.policy['file_audit']['exclude_paths'],body['file_audit']['exclude_paths'])
        self.assertEqual(options(offline.policy['file_audit']['exclude_paths'])['mode'],'all')
        self.assertEqual(options(offline.policy['file_audit']['exclude_paths'])['interaction_seconds'],60)
        # Removing explicit options is an atomic cache update, not an old
        # projection resurrected at the next offline start.
        body['file_audit']['exclude_paths']=[]
        with patch.object(self.agent,'call',return_value=agent_policy_wire({'device_id':'test-device','body':body})),patch('guarddesk.process_audit.configure'),patch.object(worker,'poll'),patch.object(worker,'configure_documents'):
            worker.configure()
        with self.agent.db() as db:self.assertIsNone(db.execute("SELECT value FROM state WHERE key='extended_file_access_options'").fetchone())


class ApplicationPolicyTest(unittest.TestCase):
    setUp=test_management.ManagementTest.setUp
    tearDown=test_management.ManagementTest.tearDown
    api=test_management.ManagementTest.api
    make_agent=test_management.ManagementTest.make_agent
    group=test_management.ManagementTest.group
    policy=test_management.ManagementTest.policy
    assign=test_management.ManagementTest.assign
    detail=test_management.ManagementTest.detail
    move=test_management.ManagementTest.move
    assert_status=test_management.ManagementTest.assert_status

    def test_group_filter_legacy_ack_security_history_replay_and_device_restore(self):
        agent,did,_=self.make_agent();group=self.group('MIS development');self.move(did,group['id'])
        control={**copy.deepcopy(DEFAULT_POLICY['application_control']),'enabled':True,'block_msi':True}
        protection=self.policy('Keep application protection',{'application_control':control});self.assign(protection,'group',group['id'])
        with self.store.connect() as db:
            Store.event(db,did,'application.started','info',{'process':'docker.exe'},'historical-docker')
            original=dict(db.execute("SELECT * FROM events WHERE event_id='historical-docker'").fetchone())
        p=self.policy('Process log exclusions',{'application_audit_exclusions':['conhost.exe','docker.exe']});self.assign(p,'group',group['id'])
        self.assertEqual(agent.heartbeat()['body']['application_audit_exclusions'],['conhost.exe','docker.exe'])
        self.assertEqual(agent.cached_policy()['body']['application_control'],control)
        agent.heartbeat()
        self.assertTrue(self.detail(did)['device']['policy_received'])
        with agent.db() as db:
            wire=json.loads(db.execute("SELECT value FROM state WHERE key='policy'").fetchone()[0]);self.assertNotIn('application_audit_exclusions',wire['body'])
        events=[{'event_id':eid,'kind':kind,'details':{'process':process},'severity':level,'occurred':time.time()} for eid,kind,level,process in [
            ('skip-start','application.started','info','docker.exe'),('skip-stop','application.stopped','info','conhost.exe'),
            ('keep-editor','application.started','info','editor.exe'),('keep-block','application.blocked','warning','docker.exe'),
            ('keep-alert','application.started','critical','docker.exe'),('keep-file','file.opened','info','docker.exe')]]
        for _ in range(2):self.assertEqual(agent.call('/api/agent/events',{'events':events})['accepted'],[e['event_id'] for e in events])
        with self.store.connect() as db:
            ids={r[0] for r in db.execute('SELECT event_id FROM events WHERE device_id=?',(did,))}
            self.assertNotIn('skip-start',ids);self.assertNotIn('skip-stop',ids)
            self.assertTrue({'keep-editor','keep-block','keep-alert','keep-file'}<=ids)
            self.assertEqual(dict(db.execute("SELECT * FROM events WHERE event_id='historical-docker'").fetchone()),original)
        # A device override restores this endpoint while the group keeps its list.
        restore=self.policy('Full process audit',{'application_audit_exclusions':[]});self.assign(restore,'device',did)
        self.assertEqual(agent.heartbeat()['body']['application_audit_exclusions'],[])
        agent.call('/api/agent/events',{'events':[{**events[0],'event_id':'restored-docker'}]})
        with self.store.connect() as db:self.assertIsNotNone(db.execute("SELECT id FROM events WHERE event_id='restored-docker'").fetchone())
        self.assertTrue(self.store.verify()['valid'])

    def test_validation_roles_csrf_and_no_implicit_user_or_group_exclusion(self):
        agent,did,_=self.make_agent();group=self.group('MIS')
        p=self.policy('Exclude process audit',{'application_audit_exclusions':['docker.exe']});self.assign(p,'group',group['id'])
        from guarddesk.policy_defaults import APPLICATIONS
        self.assertEqual(agent.heartbeat()['body']['application_audit_exclusions'],list(APPLICATIONS))
        self.assert_status(400,lambda:self.assign(p,'user',r'ACME\alice'))
        self.assert_status(400,lambda:self.policy('Bad pattern',{'application_audit_exclusions':['*.exe']}))
        self.assert_status(403,lambda:self.api('/api/policy-sets',{'name':'No CSRF','overrides':{'application_audit_exclusions':[]}},csrf=False))
        self.api('/api/logout',{});self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        self.assert_status(403,lambda:self.policy('Unauthorized',{'application_audit_exclusions':[]}))


if __name__=='__main__':unittest.main()
