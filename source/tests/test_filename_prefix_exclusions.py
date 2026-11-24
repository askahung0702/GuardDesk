"""Offline policy/source boundaries; no center, profile discovery or install."""
import copy
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
import test_endpoint_controls as fixtures
from guarddesk.file_exclusions import TMP_FILE_RULE,FILENAME_PREFIX_RULE as PREFIX,filename_prefix_template,matches_extra,excluded_activity
from guarddesk.policy import DEFAULT_POLICY,validate_policy,agent_policy_wire,decode_agent_policy
from guarddesk.policy_operations import validate_operations,apply_operations
from guarddesk.file_access import ALL_ACCESSES,INTERVAL
from guarddesk.application_control import ExtendedWorker
from guarddesk.machine_agent import cached_machine_policy
from guarddesk.windows_events import SecurityCollector

RULE=PREFIX+r'C:\Users\{user}\.claude.json.tmp.*'

class PrefixRules(TestCase):
    def test_tmp_rules_match_only_the_leaf_and_preserve_alerts_and_uploads(self):
        rules=[TMP_FILE_RULE]
        for name in (r'C:\Reports\work.tmp',r'D:\a.TmP',r'\\nas\share\.tmp',r'C:\x.tmp:stream'):
            self.assertTrue(matches_extra(name,rules))
        for name in (r'C:\work.tmp\report.xlsx',r'C:\a.tmp.123',r'C:\report.txt:note.tmp'):
            self.assertFalse(matches_extra(name,rules))
        self.assertFalse(matches_extra(r'C:\work.tmp',rules,directory=True))
        self.assertFalse(matches_extra(r'C:\a.tmp',['*.tmp']))
        policy=apply_operations(copy.deepcopy(DEFAULT_POLICY),[{'path':'file_audit.exclude_paths','op':'append','value':rules}])
        self.assertEqual(decode_agent_policy(agent_policy_wire({'body':policy}))['body'],policy)
        with self.assertRaises(ValueError):
            validate_operations([{'path':'file_audit.exclude_paths','op':'set','value':['@guarddesk:tmp-files:v2']}])
        details={'path':r'C:\read.TMP'}
        for kind in ('web.upload_started','file.web_handoff','export.blocked','application.started'):
            self.assertFalse(excluded_activity(kind,details,rules))
        self.assertFalse(excluded_activity('file.written',details,rules,'critical'))
        self.assertTrue(excluded_activity('file.deleted',{**details,'source':'fallback_snapshot'},rules,'warning'))
        self.assertFalse(excluded_activity('file.moved',{**details,'source_path':details['path'],'destination_path':r'C:\saved.txt'},rules))

    def test_random_suffix_profiles_normalization_and_directory_boundaries(self):
        for path in (r'C:\Users\dev\.claude.json.tmp.1234.567890',r'C:\Users\user1\.claude.json.tmp.1',r'\\?\C:\Users\dev\.claude.json.tmp.9',r'C:/USERS/dev/.CLAUDE.JSON.TMP.1',r'C:\Users\dev\.claude.json.tmp.dir\child'):
            with self.subTest(path=path):self.assertTrue(matches_extra(path,[RULE]))
        for path in (r'C:\Users\dev\.claude.json',r'C:\Users\dev\.claude.json.tmpx.1',r'C:\Users\dev\nested\.claude.json.tmp.1',r'C:\Users\dev\.claude.json.tmp.1\..\keep.docx',r'D:\Users\dev\.claude.json.tmp.1',r'\\nas\Users\dev\.claude.json.tmp.1'):
            with self.subTest(path=path):self.assertFalse(matches_extra(path,[RULE]))
        self.assertTrue(matches_extra(r'C:\Users\dev\.claude.json',[PREFIX+r'C:\Users\{user}\.*']))
        self.assertFalse(matches_extra(r'C:\Users\dev\report.docx',[PREFIX+r'C:\Users\{user}\.*']))

    def test_invalid_rules_rejected_at_policy_and_append_boundary(self):
        self.assertIsNone(filename_prefix_template(PREFIX+'C:\\'+'a'*10000+'*'))
        bad=[r'C:\Users\{user}\*',r'C:\Users\*\tmp*',r'C:\Users\{user}\a*b*',r'C:\Users\{user}\a?*',r'C:\Users\{user}\..\a*',r'C:\{user}\a*',r'C:\Users\{user}\{user}*',r'C:\Users\{user}\%TEMP%*',r'\\server\share\tmp*',r'C:tmp*',r'C:\Users\\dev\tmp*',r'C:\Users\dev\a:stream*',r'C:\Users\dev\tmp',r'C:\Users\dev\tmp*\child',r'C:\Users\dev.\tmp*']
        for value in [PREFIX+p for p in bad]+['@guarddesk:filename-prefix:v2:C:\\tmp*']:
            with self.subTest(value=value):
                self.assertIsNone(filename_prefix_template(value))
                p=copy.deepcopy(DEFAULT_POLICY);p['file_audit']['exclude_paths']=[value]
                with self.assertRaises(ValueError):validate_policy(p)
                with self.assertRaises(ValueError):validate_operations([{'path':'file_audit.exclude_paths','op':'append','value':[value]}])

    def test_plain_paths_and_legacy_stars_never_gain_prefix_meaning(self):
        self.assertFalse(matches_extra(r'C:\Users\dev\.claude.json.tmp.1',[r'C:\Users\dev\.claude.json.tmp.*']))
        self.assertFalse(matches_extra(r'C:\Users\dev\.claude.json.tmp.1',[r'C:\Users\dev\.claude.json.tmp.']))
        self.assertTrue(matches_extra(r'C:\Users\dev\.claude\cache',[r'C:\Users\{user}\.claude']))
        p=apply_operations(copy.deepcopy(DEFAULT_POLICY),[{'path':'file_audit.exclude_paths','op':'append','value':[RULE]}])
        self.assertIn(RULE,p['file_audit']['exclude_paths'])

    def test_moves_uploads_and_security_preserved(self):
        a=r'C:\Users\dev\.claude.json.tmp.1';b=r'C:\Users\dev\.claude.json.tmp.2';final=r'C:\Users\dev\.claude.json'
        self.assertTrue(excluded_activity('file.renamed',{'source_path':a,'destination_path':b},[RULE]))
        self.assertFalse(excluded_activity('file.renamed',{'source_path':a,'destination_path':final},[RULE]))
        self.assertFalse(excluded_activity('file.moved',{'path':a},[RULE]))
        for kind in ('web.upload_completed','application.started','agent.audit_gap','export.blocked'):
            self.assertFalse(excluded_activity(kind,{'path':a},[RULE]))

    def test_wire_preserves_order_and_legacy_body_and_nested_accounts(self):
        p=copy.deepcopy(DEFAULT_POLICY);paths=[RULE,INTERVAL+'60',r'C:\Fixed',PREFIX+r'D:\Temp\name*',ALL_ACCESSES]
        p['file_audit']['exclude_paths']=paths
        packet={'body':p,'user_policies':{'owned':{'body':copy.deepcopy(p)}}};wire=agent_policy_wire(packet)
        self.assertEqual(wire['body']['file_audit']['exclude_paths'],[r'C:\Fixed'])
        decoded=decode_agent_policy(wire)
        self.assertEqual(decoded['body'],p)
        self.assertEqual(decoded['user_policies']['owned']['body'],p)
        self.assertEqual(agent_policy_wire(decode_agent_policy(wire)),wire)
        for changed in ({'format':2},{'positions':[4,0]},{'positions':[0,99]},{'rules':['bad']},{'positions':[True,3]}):
            bad=copy.deepcopy(wire);bad['filename_prefix_options'].update(changed)
            with self.subTest(changed=changed),self.assertRaises(ValueError):decode_agent_policy(bad)

class PrefixSource(TestCase):
    setUp=fixtures.EndpointTest.setUp
    tearDown=fixtures.EndpointTest.tearDown
    queued=fixtures.EndpointTest.queued
    save_policy=fixtures.EndpointTest.save_policy

    def test_tmp_snapshot_keeps_business_files_below_tmp_named_directory(self):
        from guarddesk.document_scope import permits
        self.policy['file_audit']['exclude_paths']=[TMP_FILE_RULE];self.save_policy()
        folder=self.watch/'work.tmp';folder.mkdir()
        doc=folder/'notes.txt';doc.write_text('fixture')
        scratch=folder/'cache.TMP';scratch.write_text('scratch')
        self.assertFalse(permits(str(scratch),self.policy['file_audit'],self.watch))
        self.assertTrue(permits(str(doc),self.policy['file_audit'],self.watch))
        opened=[];original=Path.open
        def read(path,*a,**kw):opened.append(path);return original(path,*a,**kw)
        with patch.object(Path,'open',read):
            for _ in range(30):
                if not self.agent.scan(max_entries=2,time_budget=1)['in_progress']:break
        self.assertEqual(opened,[doc])
        self.assertEqual([r['details']['path'] for r in self.queued()],[str(doc)])

    def test_tmp_offline_rows_filtered_before_transport_after_policy_change(self):
        from guarddesk.agent import Agent
        path=r'C:\scratch.TMP'
        self.agent.queue('file.created',{'path':path},event_id='old')
        self.agent.queue('file.rename_to',{'destination_path':path},event_id='destination-only')
        self.agent.queue('file.deleted',{'path':path,'source':'fallback_snapshot'},'warning',event_id='delete')
        self.agent.queue('file.renamed',{'path':path,'source_path':path,'destination_path':r'C:\report.xlsx'},event_id='cross')
        self.agent.queue('web.upload_started',{'path':path,'source':'browser_webrequest'},event_id='upload')
        self.agent.queue('file.written',{'path':path},'warning',event_id='alert')
        self.policy['file_audit']['exclude_paths']=[TMP_FILE_RULE]
        # The machine collector stores the legacy-compatible body separately.
        with self.agent.db() as db:
            db.execute("INSERT OR REPLACE INTO state VALUES ('extended_policy',?)",(json.dumps(agent_policy_wire({'body':self.policy})['body']),))
        sent=[]
        def accept(route,body):
            ids=[row['event_id'] for row in body['events']];sent.extend(ids);return {'accepted':ids}
        agent=Agent(self.config)
        with patch.object(agent,'call',accept):
            self.assertFalse(agent.flush()['pending'])
        self.assertCountEqual(sent,['cross','upload','alert'])
        self.policy['file_audit']['exclude_paths']=[];self.save_policy()
        agent.queue('file.created',{'path':path},event_id='enabled-again')
        with patch.object(agent,'call',accept):agent.flush()
        self.assertIn('enabled-again',sent)

    def test_older_agent_tmp_activity_acknowledged_before_center_storage(self):
        from guarddesk.server import Handler
        from guarddesk.store import Store,digest
        store=Store(self.config.parent/'center-fixture.sqlite3')
        handler=Handler.__new__(Handler)
        handler.headers={'Authorization':'Bearer fixture'}
        path=r'C:\Reports\draft.TMP'
        def record(eid,kind,**details):
            return {'event_id':eid,'occurred':100,'kind':kind,'severity':'info','details':{'path':path,**details}}
        events=[record('temp','file.created'),record('cross','file.renamed',source_path=path,destination_path=r'C:\Reports\final.txt'),
                record('upload','file.web_handoff'),{**record('alert','file.deleted'),'severity':'critical'}]
        with store.connect() as db:
            db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',
                       ('fixture',digest('fixture'),'Owned','Owned',100))
            Store.event(db,'fixture','file.created','info',{'path':path},'historical',99)
            policy=Store.policy(db)
            policy['body']['file_audit']['exclude_paths'].append(TMP_FILE_RULE)
            db.execute('INSERT INTO policies VALUES (?,?,?,?)',(policy['version']+1,json.dumps(policy['body']),100,'fixture'))
            for _ in range(2):
                ack,_,_=handler.route(db,'POST','/api/agent/events',{'events':events})
                self.assertEqual(ack['accepted'],[row['event_id'] for row in events])
            self.assertCountEqual([r[0] for r in db.execute("SELECT event_id FROM events WHERE device_id='fixture'")],
                                  ['historical','cross','upload','alert'])
        self.assertTrue(store.verify()['valid'])

    def test_snapshot_prunes_prefix_directory_and_files_before_content_reads(self):
        self.policy['file_audit']['exclude_paths']=[PREFIX+str(self.watch/'.claude.json.tmp.*')];self.save_policy()
        (self.watch/'.claude.json.tmp.1').write_text('ignored')
        directory=self.watch/'.claude.json.tmp.dir';directory.mkdir();(directory/'child').write_text('ignored')
        doc=self.watch/'report.docx';doc.write_text('owned fixture')
        opened=[];original=Path.open
        def read(path,*a,**kw):opened.append(path);return original(path,*a,**kw)
        with patch.object(Path,'open',read):
            for _ in range(30):
                if not self.agent.scan(max_entries=2,time_budget=1)['in_progress']:break
            else:self.fail('unbounded snapshot')
        self.assertEqual(opened,[doc])
        self.assertEqual([r['kind'] for r in self.queued()],['file.created'])

    def test_security_source_stops_temp_activity_but_keeps_business_and_gap(self):
        self.policy['file_audit']['exclude_paths']=[RULE];collector=SecurityCollector(self.agent,source=object())
        with self.agent.db() as db:
            for rid,path in ((1,r'C:\Users\dev\.claude.json.tmp.1'),(2,r'C:\Users\dev\report.docx')):
                collector.ingest(db,fixtures.event(rid,4663,path=path),self.policy)
            collector.ingest(db,fixtures.event(3,1102),self.policy)
        self.assertEqual([r['kind'] for r in self.queued()],['file.opened','agent.audit_log_cleared'])

    def test_extended_cache_roundtrip_clear_and_machine_offline(self):
        p=copy.deepcopy(DEFAULT_POLICY);p['browser_audit']=False;p['file_audit']['exclude_paths']=[INTERVAL+'60',RULE,ALL_ACCESSES]
        worker=ExtendedWorker(self.agent,start_documents=False)
        p.update(browser_audit=False, browser_upload_mode='enabled', application_stop_mode='selected', application_stop_programs=['editor.exe'])
        def configure():
            with patch.object(self.agent,'call',return_value=agent_policy_wire({'device_id':'test-device','body':p})),patch('guarddesk.process_audit.configure',return_value={}),patch('guarddesk.browser_dispatch.sync',return_value={}),patch.object(worker,'poll'),patch.object(worker,'configure_documents'):
                worker.configure()
        configure()
        self.assertEqual(decode_agent_policy(cached_machine_policy(self.agent))['body'],p)
        offline=ExtendedWorker(self.agent,start_documents=False)
        with patch.object(self.agent,'call'),patch.object(self.agent,'flush'),patch.object(offline,'configure_documents'):offline.poll()
        self.assertEqual(offline.policy,p)
        p['file_audit']['exclude_paths']=[];configure()
        self.assertNotIn('filename_prefix_options',cached_machine_policy(self.agent))
        self.assertEqual(decode_agent_policy(cached_machine_policy(self.agent))['body'],p)
