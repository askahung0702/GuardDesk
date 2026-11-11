"""Synthetic multi-profile rules, no profile discovery or employee files."""
import copy
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch
import test_endpoint_controls as fixtures
import test_management
from guarddesk.file_exclusions import excluded,matches_extra,excluded_activity,user_path_template
from guarddesk.policy import DEFAULT_POLICY,validate_policy
from guarddesk.policy_operations import validate_operations
from guarddesk.store import Store,canonical
from guarddesk.windows_events import SecurityCollector
from guarddesk.windows_watch import DirectoryMonitor

RULE=r'C:\Users\{user}\workspace'


class UserPathRuleTest(unittest.TestCase):
    def test_single_directory_token_all_accounts_and_subtree_boundaries(self):
        for path in (r'C:\Users\dev\workspace',r'C:\Users\user1\workspace\src\main.py',
                     r'C:\Users\林小姐\workspace\a.docx',r'\\?\C:\Users\dev\workspace\a',
                     r'\??\C:\Users\dev\workspace\a',r'C:/USERS/dev/WORKSPACE/a',
                     r'C:\Users\dev\Documents\..\workspace\a'):
            with self.subTest(path=path):self.assertTrue(excluded(path,[RULE]))
        for path in (r'C:\Users\dev\workspace2\a',r'C:\Users\dev\Documents\workspace\a',
                     r'C:\Users\workspace\a',r'C:\Users\dev\workspace\..\Documents\a',
                     r'D:\Users\dev\workspace\a',r'\\nas\Users\DEV\workspace\a',
                     r'C:\Users\dev\nested\workspace\a',r'C:\Other\DEV\workspace\a'):
            with self.subTest(path=path):self.assertFalse(matches_extra(path,[RULE]))
        self.assertTrue(matches_extra(r'D:\Profiles\A\資料\Straße\a',[r'D:\Profiles\{USER}\資料\Straße']))
        self.assertTrue(matches_extra(r'C:\Users\dev\Documents\a',[r'C:\Users\{user}']))
        self.assertFalse(matches_extra(r'C:\Users',[r'C:\Users\{user}']))

    def test_invalid_token_shapes_fail_closed_and_policy_operations_validate(self):
        invalid=[r'{user}',r'C:\{user}\workspace',r'Users\{user}\workspace',r'C:Users\{user}',
                 r'C:\Users\prefix{user}\a',r'C:\Users\{user}\{user}',r'C:\Users\{user}\..',
                 r'C:\Users\{user}\a\..\b',r'C:\Users\{user}\*',r'C:\Users\{user}\%APPDATA%',
                 r'C:\Users\{user}\a?b',r'\\nas\share\{user}\a',r'C:\Users\\{user}\a']
        for rule in invalid:
            with self.subTest(rule=rule):
                self.assertIsNone(user_path_template(rule))
                self.assertFalse(matches_extra(r'C:\Users\dev\workspace\a',[rule]))
                p=copy.deepcopy(DEFAULT_POLICY);p['file_audit']['exclude_paths']=[rule]
                with self.assertRaisesRegex(ValueError,'使用者路徑'):validate_policy(p)
                with self.assertRaises(ValueError):validate_operations([{'path':'file_audit.exclude_paths','op':'append','value':[rule]}])
        p=copy.deepcopy(DEFAULT_POLICY);p['file_audit']['exclude_paths']=[RULE,r'D:\Fixed',r'C:\literal{braces}']
        self.assertIs(validate_policy(p),p)

    def test_moves_require_both_ends_and_non_file_audit_remains(self):
        a=r'C:\Users\dev\workspace\a';b=r'C:\Users\user1\workspace\b';doc=r'C:\Users\dev\Documents\a'
        self.assertTrue(excluded_activity('file.moved',{'source_path':a,'destination_path':b},[RULE]))
        for details in ({'path':a},{'source_path':a,'destination_path':doc},{'source_path':doc,'destination_path':a},{'path':doc,'source_path':a,'destination_path':b}):
            self.assertFalse(excluded_activity('file.moved',details,[RULE]))
        for kind in ('web.upload_completed','web.navigation','application.started','export.blocked','agent.audit_gap'):
            self.assertFalse(excluded_activity(kind,{'path':a},[RULE]))


class UserPathSourceTest(unittest.TestCase):
    setUp=fixtures.EndpointTest.setUp
    tearDown=fixtures.EndpointTest.tearDown
    save_policy=fixtures.EndpointTest.save_policy
    queued=fixtures.EndpointTest.queued

    def test_security_handle_pair_keeps_document_and_gap(self):
        self.policy['file_audit']['exclude_paths']=[RULE];collector=SecurityCollector(self.agent,source=object())
        with self.agent.db() as db:
            collector.ingest(db,fixtures.event(1,4656,path=r'C:\Users\user1\workspace\x.py'),self.policy)
            collector.ingest(db,fixtures.event(2,4660),self.policy)
            collector.ingest(db,fixtures.event(3,4663,path=r'C:\Users\user1\Documents\x.docx'),self.policy)
            collector.ingest(db,fixtures.event(4,1102),self.policy)
        self.assertEqual([r['kind'] for r in self.queued()],['file.opened','agent.audit_log_cleared'])

    def fixture_tree(self):
        for name in ('DEV','user1'):
            f=self.watch/'Users'/name/'workspace'/'x.py';f.parent.mkdir(parents=True);f.write_text('fixture')
        doc=self.watch/'Users/user1/workspace2/report.docx';doc.parent.mkdir(parents=True);doc.write_text('business fixture')
        self.policy['file_audit']['exclude_paths']=[str(self.watch/'Users'/'{user}'/'workspace')];self.save_policy()
        return doc

    def test_snapshot_skips_entire_subtree_without_reads_or_fake_deletes(self):
        doc=self.fixture_tree();opened=[];visited=[];original_open=Path.open;original_scan=os.scandir
        old='Users/DEV/workspace/missing.py'
        with self.agent.db() as db:db.execute('INSERT INTO files VALUES (?,?)',(old,'{}'))
        def read(p,*a,**kw):opened.append(p);return original_open(p,*a,**kw)
        def scan(p):visited.append(Path(p));return original_scan(p)
        with patch.object(Path,'open',read),patch('guarddesk.snapshot.os.scandir',side_effect=scan):
            for _ in range(60):
                if not self.agent.scan(max_entries=2,time_budget=1)['in_progress']:break
            else:self.fail('scan unbounded')
        self.assertEqual(opened,[doc]);self.assertFalse(any(p.name=='workspace' for p in visited))
        self.assertEqual([r['kind'] for r in self.queued()],['file.created'])
        with self.agent.db() as db:self.assertIsNone(db.execute('SELECT 1 FROM files WHERE path=?',(old,)).fetchone())

    @unittest.skipUnless(os.name=='nt','Windows directory API')
    def test_native_monitor_template_churn_and_crossing_move(self):
        doc=self.fixture_tree()
        monitor=DirectoryMonitor(self.agent,{**self.policy,'file_audit':{**self.policy['file_audit'],'scope':'managed'}})
        try:
            self.assertEqual(monitor.start()['active'],1);time.sleep(.1)
            for name in ('DEV','user1'):(self.watch/'Users'/name/'workspace'/'ignored.txt').write_text('ignored')
            created=doc.parent/'keep.docx';created.write_text('kept')
            source=self.watch/'Users/DEV/workspace/x.py';dest=doc.parent/'moved.py';os.replace(source,dest)
            deadline=time.monotonic()+4
            while time.monotonic()<deadline:
                rows=self.queued()
                if any(r['details'].get('destination_path')==str(dest) for r in rows) and any(r['details'].get('path')==str(created) for r in rows):break
                time.sleep(.05)
            rows=self.queued();self.assertFalse(any('ignored.txt' in r['details'].get('path','') for r in rows))
            self.assertTrue(any(r['details'].get('path')==str(created) for r in rows))
            self.assertTrue(any(r['details'].get('source_path')==str(source) and r['details'].get('destination_path')==str(dest) for r in rows))
        finally:monitor.close()


class UserPathServerTest(unittest.TestCase):
    setUp=test_management.ManagementTest.setUp
    tearDown=test_management.ManagementTest.tearDown
    api=test_management.ManagementTest.api
    make_agent=test_management.ManagementTest.make_agent
    policy=test_management.ManagementTest.policy
    assign=test_management.ManagementTest.assign
    assert_status=test_management.ManagementTest.assert_status

    def test_mis_assignment_legacy_ack_history_and_rule_removal(self):
        agent,did,_=self.make_agent()
        with self.store.connect() as db:
            Store.event(db,did,'file.created','info',{'path':r'C:\Users\dev\workspace\old.py'},'historic-user-path')
            original=dict(db.execute("SELECT * FROM events WHERE event_id='historic-user-path'").fetchone())
        p=self.policy('User workspace exclusion',{'file_audit':{**DEFAULT_POLICY['file_audit'],'exclude_paths':[RULE]}})
        self.assign(p,'device',did);self.assertIn(RULE,agent.heartbeat()['body']['file_audit']['exclude_paths'])
        a=r'C:\Users\dev\workspace\a';b=r'C:\Users\user1\workspace\b';d=r'C:\Users\user1\Documents\b'
        cases=[('skip-dev','file.created',{'path':a}),('skip-user1','file.opened',{'path':b}),
               ('skip-move','file.moved',{'source_path':a,'destination_path':b}),
               ('keep-cross','file.moved',{'source_path':a,'destination_path':d}),
               ('keep-doc','file.opened',{'path':d}),('keep-gap','agent.audit_gap',{'path':a}),
               ('keep-upload','web.upload_completed',{'path':a})]
        events=[{'event_id':eid,'kind':kind,'severity':'info','details':details,'occurred':time.time()} for eid,kind,details in cases]
        for _ in range(2):self.assertEqual(agent.call('/api/agent/events',{'events':events})['accepted'],[e['event_id'] for e in events])
        with self.store.connect() as db:
            for eid,_,_ in cases:self.assertEqual(db.execute('SELECT count(*) FROM events WHERE event_id=?',(eid,)).fetchone()[0],0 if eid.startswith('skip-') else 1)
            self.assertEqual(dict(db.execute("SELECT * FROM events WHERE event_id='historic-user-path'").fetchone()),original)
        self.assertTrue(self.store.verify()['valid'])
        self.api('/api/policy-sets',{'id':p['id'],'revision':p['revision'],'name':'Disabled user workspace exclusion','enabled':False,'overrides':{'file_audit':{**DEFAULT_POLICY['file_audit'],'exclude_paths':[RULE]}}})
        agent.call('/api/agent/events',{'events':[{**events[0],'event_id':'restored-user-path'}]})
        with self.store.connect() as db:self.assertIsNotNone(db.execute("SELECT 1 FROM events WHERE event_id='restored-user-path'").fetchone())
        self.assert_status(400,lambda:self.policy('bad',{'file_audit':{**DEFAULT_POLICY['file_audit'],'exclude_paths':[RULE+r'\..']}}))
        self.api('/api/logout',{});self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        self.assert_status(403,lambda:self.policy('reader forbidden',{'file_audit':{**DEFAULT_POLICY['file_audit'],'exclude_paths':[RULE]}}))


if __name__=='__main__':unittest.main()
