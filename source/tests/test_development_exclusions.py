"""Owned synthetic paths/DB only. No real employee data or Windows policy edits."""
import copy
import json
import time
import unittest
from unittest.mock import patch
from pathlib import Path
import test_management
import test_endpoint_controls as fixtures
from guarddesk.file_exclusions import DEVELOPMENT_RULE,development_path,excluded,excluded_activity
from guarddesk.policy import DEFAULT_POLICY,validate_policy
from guarddesk.windows_events import SecurityCollector
from guarddesk.store import Store


class DevelopmentPathTest(unittest.TestCase):
    def test_opt_in_exact_boundaries_and_no_extension_guessing(self):
        for path in (r'C:\Dev\node_modules\x\a.js',r'D:\Repo\.git\objects\aa',
                     r'\\?\C:\Repo\.venv\Lib\a.py',r'C:\Users\dev\.nuget\packages\x\a.dll',
                     r'\\nas\source\repo\__pycache__\a.pyc',r'C:\Users\dev\AppData\Local\npm-cache\_logs\x'):
            with self.subTest(path=path):
                self.assertTrue(development_path(path));self.assertFalse(excluded(path))
                self.assertTrue(excluded(path,[DEVELOPMENT_RULE]))
        for path in (r'C:\Dev\src\main.py',r'C:\Dev\build\report.docx',r'C:\Dev\dist\a.zip',
                     r'C:\Docs\node_modules-report.xlsx',r'C:\Dev\my.git\a.txt',
                     r'C:\Users\dev\AppData\Local\business.docx',r'C:\Docs\main.js',
                     r'C:\Projects\.nuget-notes\brief.docx'):
            with self.subTest(path=path):self.assertFalse(excluded(path,[DEVELOPMENT_RULE]))
        policy=copy.deepcopy(DEFAULT_POLICY);policy['file_audit']['exclude_paths']=[DEVELOPMENT_RULE]
        self.assertIs(validate_policy(policy),policy)  # unchanged legacy wire schema

    def test_both_move_ends_required_and_security_events_preserved(self):
        cache=r'C:\Dev\node_modules\a.txt';doc=r'C:\Docs\a.txt';extra=[DEVELOPMENT_RULE]
        self.assertTrue(excluded_activity('file.created',{'path':cache},extra))
        for src,dst in ((cache,doc),(doc,cache)):
            self.assertFalse(excluded_activity('file.moved',{'path':src,'source_path':src,'destination_path':dst},extra))
        self.assertTrue(excluded_activity('file.renamed',{'path':cache,'source_path':cache,'destination_path':cache+'2'},extra))
        for details in ({'path':cache},{'source_path':cache,'destination_path':None},{'path':123}):
            self.assertFalse(excluded_activity('file.moved',details,extra))
        for kind in ('export.blocked','web.upload_completed','application.blocked','agent.audit_gap','file.security_alert'):
            self.assertFalse(excluded_activity(kind,{'path':cache},extra))
        self.assertTrue(excluded_activity('file.created',{'path':r'D:\Repo\main.py'},[r'D:\Repo']))
        self.assertFalse(excluded_activity('file.created',{'path':r'D:\Repository\main.py'},[r'D:\Repo']))


class DevelopmentSourceTest(unittest.TestCase):
    setUp=fixtures.EndpointTest.setUp
    tearDown=fixtures.EndpointTest.tearDown
    save_policy=fixtures.EndpointTest.save_policy
    queued=fixtures.EndpointTest.queued

    def test_security_skips_cache_and_keeps_document_actor_and_gap(self):
        self.policy['file_audit']['exclude_paths']=[DEVELOPMENT_RULE];collector=SecurityCollector(self.agent,source=object())
        with self.agent.db() as db:
            collector.ingest(db,fixtures.event(1,4656,path=r'C:\Dev\node_modules\x.js'),self.policy)
            collector.ingest(db,fixtures.event(2,4660),self.policy)
            collector.ingest(db,fixtures.event(3,4663,path=r'C:\Dev\src\main.py'),self.policy)
            collector.ingest(db,fixtures.event(4,1102),self.policy)
        rows=self.queued();self.assertEqual([r['kind'] for r in rows],['file.opened','agent.audit_log_cleared'])
        self.assertEqual(rows[0]['details']['user'],r'COMPANY\employee')

    def test_snapshot_prunes_without_reading_cache_and_no_fake_delete(self):
        folder=self.watch/'node_modules';folder.mkdir();cache=folder/'fixture.js';cache.write_text('fixture')
        doc=self.watch/'main.py';doc.write_text('fixture source')
        self.policy['file_audit']['exclude_paths']=[DEVELOPMENT_RULE];self.save_policy()
        with self.agent.db() as db:db.execute('INSERT INTO files VALUES (?,?)',('node_modules/old.js','{}'))
        original=Path.open;opened=[]
        def checked(path,*args,**kwargs):opened.append(path);return original(path,*args,**kwargs)
        with patch.object(Path,'open',checked):
            for _ in range(50):
                if not self.agent.scan(max_entries=2,time_budget=1)['in_progress']:break
            else:self.fail('unbounded scan')
        self.assertEqual(opened,[doc]);self.assertEqual([r['kind'] for r in self.queued()],['file.created'])


class DevelopmentAssignmentTest(unittest.TestCase):
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

    def test_group_server_legacy_ack_history_crossings_security_and_rollback(self):
        agent,did,_=self.make_agent();dev=self.group('MIS developers');self.move(did,dev['id'])
        with self.store.connect() as db:
            Store.event(db,did,'file.created','info',{'path':r'C:\Dev\node_modules\old.js'},'keep-history')
            original=dict(db.execute("SELECT * FROM events WHERE event_id='keep-history'").fetchone())
        p=self.policy('Skip development caches',{'file_audit':{**DEFAULT_POLICY['file_audit'],'exclude_paths':[DEVELOPMENT_RULE,r'D:\Projects']}})
        assignment=self.assign(p,'group',dev['id'])
        body=agent.heartbeat()['body'];self.assertIn(DEVELOPMENT_RULE,body['file_audit']['exclude_paths'])
        self.assertTrue(body['browser_audit']);self.assertTrue(body['application_audit'])
        self.assertEqual(body['application_control'],DEFAULT_POLICY['application_control'])
        cases=[('cache','file.created',{'path':r'C:\Dev\node_modules\x.js'}),
               ('project','file.opened',{'path':r'D:\Projects\main.py'}),
               ('doc','file.opened',{'path':r'C:\Docs\report.xlsx'}),
               ('cross','file.moved',{'path':r'C:\Dev\node_modules\x.js','source_path':r'C:\Dev\node_modules\x.js','destination_path':r'C:\Docs\x.js'}),
               ('security','application.blocked',{'path':r'C:\Dev\node_modules\x.exe'}),
               ('upload','web.upload_completed',{'path':r'C:\Dev\node_modules\x.js'}),
               ('web','web.navigation',{'url':'https://example.test/'}),
               ('app','application.started',{'process':r'C:\Dev\tool.exe'})]
        events=[{'event_id':eid,'kind':kind,'details':d,'severity':'info','occurred':time.time()} for eid,kind,d in cases]
        for _ in range(2):self.assertEqual(agent.call('/api/agent/events',{'events':events})['accepted'],[e['event_id'] for e in events])
        with self.store.connect() as db:
            found={r[0] for r in db.execute('SELECT event_id FROM events WHERE device_id=?',(did,))}
            self.assertNotIn('cache',found);self.assertNotIn('project',found)
            self.assertTrue({'doc','cross','security','upload','web','app'}<=found)
            self.assertEqual(dict(db.execute("SELECT * FROM events WHERE event_id='keep-history'").fetchone()),original)
        # Group removal restores collection for the same legacy Agent.
        self.move(did,None)
        restored={**events[0],'event_id':'restored-cache'}
        agent.call('/api/agent/events',{'events':[restored]})
        with self.store.connect() as db:self.assertIsNotNone(db.execute("SELECT id FROM events WHERE event_id='restored-cache'").fetchone())
        self.assertTrue(self.store.verify()['valid'])
        invalid={**restored,'occurred':'invalid'}
        with self.assertRaisesRegex(ConnectionError,'HTTP 400'):agent.call('/api/agent/events',{'events':[invalid]})

    def test_mis_only_and_not_implicitly_applied_to_people_or_other_groups(self):
        agent,did,_=self.make_agent();dev=self.group('MIS');other=self.group('Staff');self.move(did,other['id'])
        p=self.policy('Development exclusion',{'file_audit':{**DEFAULT_POLICY['file_audit'],'exclude_paths':[DEVELOPMENT_RULE]}})
        self.assign(p,'group',dev['id'])
        from guarddesk.policy_defaults import ROAMING
        self.assertEqual(agent.heartbeat()['body']['file_audit']['exclude_paths'],[ROAMING])
        self.assert_status(400,lambda:self.assign(p,'user',r'ACME\developer'))
        self.api('/api/logout',{});self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        self.assert_status(403,lambda:self.policy('Unauthorized',{'file_audit':DEFAULT_POLICY['file_audit']}))


if __name__=='__main__':unittest.main()
