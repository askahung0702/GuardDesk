"""Owned policies/SQLite and synthetic Windows records only; no center or trace."""
import copy
import json
import time
import unittest
from unittest.mock import patch
import test_endpoint_controls as fixtures
import test_policy_defaults as defaults_fixtures
from guarddesk.application_exclusions import directory_rule, excluded_application, validate_exclusions
from guarddesk.application_control import ExtendedWorker
from guarddesk.file_access import PROCESS, options
from guarddesk.management import ControlPlane
from guarddesk.policy import DEFAULT_POLICY, agent_policy_wire, decode_agent_policy
from guarddesk.policy_defaults import SYSTEM32, SYSTEM32_MARKER
from guarddesk.server import Handler, APIError, digest
from guarddesk.store import Store, canonical
from guarddesk.windows_events import SecurityCollector


class System32RulesTest(unittest.TestCase):
    def test_component_case_namespace_and_executable_boundaries(self):
        paths=[SYSTEM32+'svchost.exe',SYSTEM32.upper()+'CMD.EXE',
               SYSTEM32+r'WindowsPowerShell\v1.0\powershell.exe',SYSTEM32+'tool.com']
        paths += ['\\\\?\\'+paths[0], '\\??\\'+paths[0]]
        for path in paths:
            self.assertTrue(excluded_application('application.started','info',{'process':path},[SYSTEM32]),path)
            self.assertTrue(excluded_application('application.stopped','info',{'path':path,'process':path},[SYSTEM32]),path)
        for path in (r'C:\Windows\System32-old\cmd.exe',r'C:\Windows\SysWOW64\cmd.exe',
                     r'D:\Windows\System32\cmd.exe',r'C:\Tools\cmd.exe','cmd.exe',
                     SYSTEM32+'test.dll',SYSTEM32+'cmd.exe.bak',SYSTEM32+'file:cmd.exe',SYSTEM32+'*.exe',r'C:\Windows\System32\..\cmd.exe'):
            self.assertFalse(excluded_application('application.started','info',{'process':path},[SYSTEM32]),path)

    def test_alerts_documents_and_unknown_actors_remain(self):
        for kind in ('application.blocked','application.audit_would_block','agent.audit_gap','file.opened','file.deleted','web.upload_started'):
            self.assertFalse(excluded_application(kind,'info',{'process':SYSTEM32+'cmd.exe'},[SYSTEM32]))
        for severity in ('warning','critical'):
            self.assertFalse(excluded_application('application.started',severity,{'process':SYSTEM32+'cmd.exe'},[SYSTEM32]))
        for details in ({},{'process':None},{'process':1},{'process':SYSTEM32+'cmd.exe','path':r'C:\Tools\cmd.exe'}):
            self.assertFalse(excluded_application('application.started','info',details,[SYSTEM32]))

    def test_directory_syntax_is_explicit_and_read_process_options_stay_exact(self):
        self.assertEqual(validate_exclusions([SYSTEM32]),[SYSTEM32])
        for value in ('C:\\',r'\\server\share'+'\\',r'..\System32'+'\\',r'C:Windows\System32'+'\\',
                      r'C:\Windows\System32',r'C:\Windows\System32\*.exe',r'%WINDIR%\System32'+'\\',
                      r'C:\Windows\System32:other'+'\\',r'\\server\share\folder.exe'+'\\'):
            with self.subTest(value=value),self.assertRaises(ValueError):validate_exclusions([value])
        with self.assertRaises(ValueError):validate_exclusions([SYSTEM32,SYSTEM32.upper()])
        with self.assertRaises(ValueError):options([PROCESS+SYSTEM32])
        self.assertIsNone(directory_rule('cmd.exe'))

    def test_wire_preserves_order_nested_rules_and_strict_legacy_exact_list(self):
        body=copy.deepcopy(DEFAULT_POLICY);body['application_audit_exclusions']=['one.exe',SYSTEM32,'two.exe','D:\\Owned\\']
        packet={'body':body,'user_policies':{'owned\\user':{'body':copy.deepcopy(body)}}};before=copy.deepcopy(packet)
        wire=agent_policy_wire(packet)
        self.assertEqual(packet,before)
        for item in (wire,wire['user_policies']['owned\\user']):
            self.assertNotIn('application_audit_exclusions',item['body'])
            self.assertEqual(item['audit_options']['application_exclusions'],['one.exe','two.exe'])
            validate_exclusions(item['audit_options']['application_exclusions'],allow_directories=False)
            self.assertEqual(item['application_directory_options']['positions'],[1,3])
        self.assertEqual(decode_agent_policy(wire)['body'],body)
        self.assertEqual(decode_agent_policy(wire)['user_policies']['owned\\user']['body'],body)
        self.assertNotIn('application_directory_options',agent_policy_wire({'body':copy.deepcopy(DEFAULT_POLICY),
                                                                          'application_directory_options':{'stale':True}}))

    def test_bad_projection_cannot_inject_rules_or_overflow_legacy_list(self):
        body=copy.deepcopy(DEFAULT_POLICY);body['application_audit_exclusions']=[SYSTEM32]
        wire=agent_policy_wire({'body':body})
        for changes in ({'format':True},{'format':2},{'rules':['cmd.exe']},{'rules':['C:\\']},
                        {'positions':[True]},{'positions':[2]},{'positions':[-1]},{'positions':[]},
                        {'positions':[0,0],'rules':[SYSTEM32,SYSTEM32]},{'shell':'cmd.exe'}):
            packet=copy.deepcopy(wire);packet['application_directory_options'].update(changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):decode_agent_policy(packet)
        wire['audit_options']['application_exclusions']=[f'owned{i}.exe' for i in range(100)]
        with self.assertRaises(ValueError):decode_agent_policy(wire)


class System32DefaultsTest(unittest.TestCase):
    setUp=defaults_fixtures.PolicyDefaultsTest.setUp

    def old_center(self,rules):
        with self.store.connect() as db:
            db.execute('DELETE FROM control_meta WHERE key=?',(SYSTEM32_MARKER,))
            body=Store.policy(db)['body'];body['application_audit_exclusions']=rules
            db.execute('UPDATE policies SET body=? WHERE version=1',(canonical(body),))

    def test_existing_v1_center_adds_once_preserves_history_and_user_removal(self):
        self.old_center(['conhost.exe','docker.exe','owned.exe'])
        with self.store.connect() as db:
            Store.event(db,'owned','application.started','info',{'process':SYSTEM32+'cmd.exe'},'history')
            original=dict(db.execute("SELECT * FROM events WHERE event_id='history'").fetchone())
        Store(self.path);Store(self.path)
        with self.store.connect() as db:
            policy=Store.policy(db);self.assertEqual(policy['version'],2)
            self.assertEqual(policy['body']['application_audit_exclusions'],['conhost.exe','docker.exe','owned.exe',SYSTEM32])
            self.assertEqual(dict(db.execute("SELECT * FROM events WHERE event_id='history'").fetchone()),original)
            body=policy['body'];body['application_audit_exclusions'].remove(SYSTEM32)
            db.execute('UPDATE policies SET body=? WHERE version=2',(canonical(body),))
        Store(self.path)
        with self.store.connect() as db:self.assertNotIn(SYSTEM32,Store.policy(db)['body']['application_audit_exclusions'])
        self.assertTrue(self.store.verify()['valid'])

    def test_existing_explicit_empty_baseline_is_not_filled(self):
        self.old_center([]);Store(self.path);Store(self.path)
        with self.store.connect() as db:
            self.assertEqual(Store.policy(db)['body']['application_audit_exclusions'],[])
            self.assertEqual(Store.policy(db)['version'],1)
            self.assertIsNotNone(db.execute('SELECT value FROM control_meta WHERE key=?',(SYSTEM32_MARKER,)).fetchone())

    def test_scoped_empty_override_is_preserved(self):
        self.old_center(['conhost.exe','docker.exe'])
        with self.store.connect() as db:
            db.execute("INSERT INTO policy_sets(id,name,description,revision,enabled,archived,overrides,created,actor,operations) VALUES ('owned','Owned','',1,1,0,?,?,?,'[]')",(canonical({'application_audit_exclusions':[]}),time.time(),'owned'))
            db.execute("INSERT INTO policy_assignments VALUES ('owned','owned','global','',100,1,1,?,'owned')",(time.time(),))
        Store(self.path)
        with self.store.connect() as db:
            self.assertIn(SYSTEM32,Store.policy(db)['body']['application_audit_exclusions'])
            self.assertEqual(ControlPlane(db).resolve({'id':'owned','group_id':None})['body']['application_audit_exclusions'],[])
    def test_empty_group_capacity_preserves_complete_old_baseline(self):
        # An empty group's append would overflow 100 after the new default.
        self.old_center(['conhost.exe','docker.exe'])
        with self.store.connect() as db:
            db.execute('DELETE FROM policy_assignments');db.execute('DELETE FROM policy_sets')
            db.execute("INSERT INTO endpoint_groups VALUES ('empty','Empty',NULL,1,?)",(time.time(),))
            operations=[{'path':'application_audit_exclusions','op':'append','value':[f'owned{i}.exe' for i in range(98)]}]
            db.execute("INSERT INTO policy_sets(id,name,description,revision,enabled,archived,overrides,created,actor,operations) VALUES ('full','Full','',1,1,0,'{}',?,'owned',?)",(time.time(),canonical(operations)))
            db.execute("INSERT INTO policy_assignments VALUES ('full','full','group','empty',100,1,1,?,'owned')",(time.time(),))
            old=Store.policy(db)
        Store(self.path)
        with self.store.connect() as db:self.assertEqual(Store.policy(db),old)


class System32SourceTest(unittest.TestCase):
    setUp=fixtures.EndpointTest.setUp
    tearDown=fixtures.EndpointTest.tearDown
    queued=fixtures.EndpointTest.queued

    def test_security_source_suppresses_start_stop_only(self):
        self.policy['application_audit_exclusions']=[SYSTEM32]
        collector=SecurityCollector(self.agent,source=object())
        with self.agent.db() as db:
            for rid,eid,path in [(1,4688,SYSTEM32+'cmd.exe'),(2,4689,SYSTEM32+'cmd.exe'),
                                 (3,4688,r'C:\Tools\cmd.exe'),(4,4688,r'C:\Windows\SysWOW64\cmd.exe')]:
                item=fixtures.event(rid,eid);item['data'].update(NewProcessName=path,ProcessName=path,NewProcessId='0x10')
                collector.ingest(db,item,self.policy)
            item=fixtures.event(5,4663,path=r'C:\Docs\report.docx');item['data']['ProcessName']=SYSTEM32+'cmd.exe'
            collector.ingest(db,item,self.policy);collector.ingest(db,fixtures.event(6,1102),self.policy)
        self.assertEqual([r['kind'] for r in self.queued()],['application.started','application.started','file.opened','agent.audit_log_cleared'])

    def test_selected_stops_preserve_starts_and_source_queue(self):
        self.policy.update(application_stop_mode='selected', application_stop_programs=['writer.exe'])
        collector = SecurityCollector(self.agent, source=object())
        with self.agent.db() as db:
            for rid, eid, image in [(1,4688,'helper.exe'), (2,4689,'helper.exe'), (3,4689,'writer.exe')]:
                item = fixtures.event(rid, eid)
                item['data'].update(NewProcessName=image, ProcessName=image, NewProcessId='0x10')
                collector.ingest(db, item, self.policy)
        self.assertEqual([e['kind'] for e in self.queued()], ['application.started','application.stopped'])
        self.assertEqual(self.queued()[-1]['details']['process'], 'writer.exe')

    def test_native_cache_survives_offline_and_clears_without_restoring_stale_rule(self):
        body=copy.deepcopy(self.policy);body['application_audit_exclusions']=[SYSTEM32,'owned.exe']
        worker=ExtendedWorker(self.agent)
        with patch.object(self.agent,'call',return_value=agent_policy_wire({'device_id':'test-device','body':body})),patch('guarddesk.process_audit.configure',return_value={'process_audit_enabled':True}),patch.object(worker,'poll'),patch.object(worker,'configure_documents'):
            worker.configure()
        class Collector:
            def poll(self,policy):return {'rules':policy['application_audit_exclusions']}
        offline=ExtendedWorker(self.agent);offline.status={};offline.collector=Collector()
        with patch.object(self.agent,'flush'),patch.object(self.agent,'call'),patch.object(offline,'configure_documents'):
            self.assertEqual(offline.poll()['process_audit']['rules'],[SYSTEM32,'owned.exe'])
        body['application_audit_exclusions']=[]
        with patch.object(self.agent,'call',return_value=agent_policy_wire({'device_id':'test-device','body':body})),patch('guarddesk.process_audit.configure'),patch.object(worker,'poll'),patch.object(worker,'configure_documents'):
            worker.configure()
        with self.agent.db() as db:self.assertIsNone(db.execute("SELECT value FROM state WHERE key='extended_application_directory_options'").fetchone())
        offline=ExtendedWorker(self.agent);offline.status={};offline.collector=Collector()
        with patch.object(self.agent,'flush'),patch.object(self.agent,'call'),patch.object(offline,'configure_documents'):
            self.assertEqual(offline.poll()['process_audit']['rules'],[])


class System32IngestionTest(unittest.TestCase):
    setUp=defaults_fixtures.PolicyDefaultsTest.setUp

    def test_actual_authenticated_route_ack_replay_override_and_immutable_history(self):
        # Invoke the real route with a real owned SQLite DB, without constructing
        # any Server/HTTP listener or bypassing the Agent bearer check.
        handler=Handler.__new__(Handler);handler.headers={'Authorization':'Bearer owned-token'}
        with self.store.connect() as db:
            db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',
                       ('owned',digest('owned-token'),'Owned-PC','Owned',time.time()))
            Store.event(db,'owned','application.started','info',{'process':SYSTEM32+'cmd.exe'},'historical')
            historical=dict(db.execute("SELECT * FROM events WHERE event_id='historical'").fetchone())
            specs=[('skip-start','application.started','info',SYSTEM32+'cmd.exe'),
                   ('skip-stop','application.stopped','info',SYSTEM32+'cmd.exe'),
                   ('keep-outside','application.started','info',r'C:\Tools\cmd.exe'),
                   ('keep-warning','application.started','warning',SYSTEM32+'cmd.exe'),
                   ('keep-block','application.blocked','warning',SYSTEM32+'cmd.exe'),
                   ('keep-file','file.opened','info',SYSTEM32+'cmd.exe')]
            events=[{'event_id':eid,'kind':kind,'severity':severity,'details':{'process':process,'path':r'C:\Docs\report.docx'} if kind=='file.opened' else {'process':process},'occurred':time.time()} for eid,kind,severity,process in specs]
            for _ in range(2):
                reply,_,_=handler.route(db,'POST','/api/agent/events',{'events':events})
                self.assertEqual(reply['accepted'],[e['event_id'] for e in events])
            ids=[r[0] for r in db.execute("SELECT event_id FROM events WHERE device_id='owned'")]
            self.assertNotIn('skip-start',ids);self.assertNotIn('skip-stop',ids)
            self.assertEqual(ids.count('keep-outside'),1)
            self.assertTrue({'keep-warning','keep-block','keep-file'}<=set(ids))
            self.assertEqual(dict(db.execute("SELECT * FROM events WHERE event_id='historical'").fetchone()),historical)
            db.execute("INSERT INTO policy_sets(id,name,description,revision,enabled,archived,overrides,created,actor,operations) VALUES ('restore','Restore','',1,1,0,?,?,?,'[]')",(canonical({'application_audit_exclusions':[]}),time.time(),'owned'))
            db.execute("INSERT INTO policy_assignments VALUES ('restore','restore','device','owned',100,1,1,?,'owned')",(time.time(),))
            handler.route(db,'POST','/api/agent/events',{'events':[{**events[0],'event_id':'restored'}]})
            self.assertIsNotNone(db.execute("SELECT id FROM events WHERE event_id='restored'").fetchone())
            handler.headers={'Authorization':'Bearer wrong-token'}
            with self.assertRaises(APIError) as denied:handler.route(db,'POST','/api/agent/events',{'events':events})
            self.assertEqual(denied.exception.status,401)
            handler.headers={'Authorization':'Bearer owned-token'};db.execute("UPDATE devices SET revoked=1 WHERE id='owned'")
            with self.assertRaises(APIError):handler.route(db,'POST','/api/agent/events',{'events':events})
        self.assertTrue(self.store.verify()['valid'])
