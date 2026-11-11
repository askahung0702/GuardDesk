"""Owned health-file fixtures only; never change the installed broker or tasks."""
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch
import test_endpoint_controls as fixtures
import test_management
from guarddesk.file_exclusions import FILE_ACTIVITY_KINDS,excluded,internal_health_path,excluded_internal_health_activity
from guarddesk.store import Store,canonical
from guarddesk.windows_events import SecurityCollector
from guarddesk.windows_watch import DirectoryMonitor

BASE='C:\\ProgramData\\GuardDeskPilot\\USBControl\\'+'a'*24+'\\'
HEALTH=BASE+'broker-health.json'
TEMP=BASE+'broker-health.new'
DOC=r'C:\Users\fixture\Documents\broker-health.json'


class HealthPathTest(unittest.TestCase):
    def test_update_capacity_diagnostics_are_exact_and_alerts_remain(self):
        for path in (BASE+'updates\\last-update-failure-native.json',BASE+'updates\\last-update-failure-main.new',BASE+'updates\\'+'b'*32+'\\cache-receipt.json'):
            self.assertTrue(internal_health_path(path))
            self.assertTrue(excluded_internal_health_activity('file.created','info',{'path':path}))
            self.assertFalse(excluded_internal_health_activity('file.created','warning',{'path':path}))
            self.assertFalse(excluded_internal_health_activity('file.moved','info',{'source_path':path,'destination_path':DOC}))
        self.assertFalse(internal_health_path(BASE+'updates\\business\\cache-receipt.json'))
        self.assertFalse(internal_health_path(r'C:\Users\fixture\Documents\last-update-failure-native.json'))

    def test_website_control_journals_are_exact_not_business_basenames(self):
        for name in ('website-policy-chrome.json','website-policy-edge.new','website-policy.lock'):
            self.assertTrue(internal_health_path(BASE+name))
            self.assertFalse(internal_health_path(r'C:\Users\fixture\Documents'+'\\'+name))
            self.assertFalse(excluded_internal_health_activity('file.created','warning',{'path':BASE+name}))
        self.assertFalse(internal_health_path(BASE+'website-policy-unknown.json'))
    def test_exact_paths_case_normalization_and_volume(self):
        for path in (HEALTH,TEMP,HEALTH.upper(),HEALTH.replace('\\','/'),'\\\\?\\'+HEALTH,'\\??\\'+TEMP,'D'+HEALTH[1:],BASE+'child\\..\\broker-health.json'):
            with self.subTest(path=path):self.assertTrue(internal_health_path(path));self.assertTrue(excluded(path))
        for path in (DOC,BASE+'config.json',BASE+'updater-state.json',BASE+'broker-health.json.bak',
                     BASE+'child\\broker-health.json',HEALTH.replace('USBControl','USBControls'),
                     HEALTH.replace('a'*24,'a'*23),HEALTH.replace('a'*24,'g'*24),
                     '\\\\server\\ProgramData\\GuardDeskPilot\\USBControl\\'+'a'*24+r'\broker-health.json',None,123,''):
            with self.subTest(path=path):self.assertFalse(internal_health_path(path))

    def test_relocated_local_programdata_requires_exact_root(self):
        with patch.dict(os.environ,{'ProgramData':r'E:\CompanyData'}):
            self.assertTrue(internal_health_path(HEALTH.replace(r'C:\ProgramData',r'E:\CompanyData')))
            self.assertFalse(internal_health_path(HEALTH.replace(r'C:\ProgramData',r'E:\OtherData')))

    def test_information_only_all_file_actions_and_complete_moves(self):
        for kind in FILE_ACTIVITY_KINDS:
            details={'path':HEALTH,'source_path':TEMP,'destination_path':HEALTH}
            self.assertTrue(excluded_internal_health_activity(kind,'info',details))
            for level in ('warning','critical'):self.assertFalse(excluded_internal_health_activity(kind,level,details))
        for kind in ('agent.audit_gap','agent.audit_log_cleared','update.failed','usb.blocked','file.security_alert','web.upload_completed'):
            self.assertFalse(excluded_internal_health_activity(kind,'info',{'path':HEALTH}))
        for kind in ('file.renamed','file.moved'):
            for details in ({'path':HEALTH},{'source_path':TEMP,'destination_path':None},
                            {'source_path':TEMP,'destination_path':DOC},
                            {'source_path':DOC,'destination_path':HEALTH},
                            {'path':DOC,'source_path':TEMP,'destination_path':HEALTH}):
                self.assertFalse(excluded_internal_health_activity(kind,'info',details))


class HealthSourceTest(unittest.TestCase):
    setUp=fixtures.EndpointTest.setUp
    tearDown=fixtures.EndpointTest.tearDown
    queued=fixtures.EndpointTest.queued
    save_policy=fixtures.EndpointTest.save_policy

    def test_queue_keeps_alerts_documents_and_preexisting_outbox(self):
        old={'event_id':'preexisting','kind':'file.created','severity':'info','occurred':time.time(),'details':{'path':HEALTH}}
        with self.agent.db() as db:db.execute('INSERT INTO outbox VALUES (?,?,?)',('preexisting',canonical(old),time.time()))
        self.assertIsNone(self.agent.queue('file.created',{'path':HEALTH}))
        for kind,level,path in (('file.deleted','warning',HEALTH),('agent.audit_gap','critical',HEALTH),('file.created','info',DOC)):
            self.assertIsNotNone(self.agent.queue(kind,{'path':path},level))
        self.assertEqual(self.queued()[0],old);self.assertEqual(len(self.queued()),4)

    def test_security_handle_marker_no_false_unresolved_delete(self):
        collector=SecurityCollector(self.agent,source=object())
        with self.agent.db() as db:
            collector.ingest(db,fixtures.event(1,4656,path=HEALTH),self.policy)
            self.assertEqual(json.loads(db.execute('SELECT payload FROM audit_handles').fetchone()[0]),{'_excluded':True})
            collector.ingest(db,fixtures.event(2,4663,path=HEALTH),self.policy)
            collector.ingest(db,fixtures.event(3,4660),self.policy)
            collector.ingest(db,fixtures.event(4,4660),self.policy)
            collector.ingest(db,fixtures.event(5,4663,path=DOC),self.policy)
            collector.ingest(db,fixtures.event(6,1102),self.policy)
        self.assertEqual([r['kind'] for r in self.queued()],['agent.audit_unresolved_delete','file.opened','agent.audit_log_cleared'])

    def test_snapshot_never_reads_health_and_prunes_baseline_without_fake_delete(self):
        data=self.watch/'programdata';health=data/'GuardDeskPilot/USBControl'/('a'*24)/'broker-health.json'
        health.parent.mkdir(parents=True);health.write_text('health fixture')
        doc=self.watch/'broker-health.json';doc.write_text('business fixture')
        relative=str(health.relative_to(self.watch))
        with self.agent.db() as db:db.execute('INSERT INTO files VALUES (?,?)',(relative,'{}'))
        opened=[];original=Path.open
        def checked(path,*args,**kwargs):opened.append(path);return original(path,*args,**kwargs)
        with patch.dict(os.environ,{'ProgramData':str(data)}),patch.object(Path,'open',checked):
            for _ in range(50):
                if not self.agent.scan(max_entries=2,time_budget=1)['in_progress']:break
            else:self.fail('unbounded scan')
        self.assertEqual(opened,[doc]);self.assertEqual([r['kind'] for r in self.queued()],['file.created'])
        with self.agent.db() as db:self.assertIsNone(db.execute('SELECT 1 FROM files WHERE path=?',(relative,)).fetchone())
        self.assertTrue(health.exists())

    @unittest.skipUnless(os.name=='nt','Windows directory API')
    def test_real_directory_health_atomic_replacement_keeps_documents_and_crossings(self):
        data=self.watch/'programdata';folder=data/'GuardDeskPilot/USBControl'/('a'*24);folder.mkdir(parents=True)
        health=folder/'broker-health.json';temp=folder/'broker-health.new';doc=self.watch/'business.docx'
        with patch.dict(os.environ,{'ProgramData':str(data)}):
            monitor=DirectoryMonitor(self.agent,{**self.policy,'file_audit':{**self.policy['file_audit'],'scope':'managed'}})
            try:
                self.assertEqual(monitor.start()['active'],1);time.sleep(.1)
                for _ in range(5):temp.write_text('health fixture');os.replace(temp,health)
                doc.write_text('business fixture')
                deadline=time.monotonic()+4
                while time.monotonic()<deadline:
                    if any(r['details'].get('path')==str(doc) for r in self.queued()):break
                    time.sleep(.05)
                rows=self.queued();self.assertTrue(any(r['details'].get('path')==str(doc) for r in rows))
                self.assertFalse(any('broker-health.' in r['details'].get('path','') for r in rows))
                self.assertTrue(health.exists())
                crossing=self.watch/'exported-health.json';os.replace(health,crossing)
                deadline=time.monotonic()+4
                while time.monotonic()<deadline:
                    if any(r['details'].get('destination_path')==str(crossing) for r in self.queued()):break
                    time.sleep(.05)
                self.assertTrue(any(r['details'].get('source_path')==str(health) and r['details'].get('destination_path')==str(crossing) for r in self.queued()))
            finally:monitor.close()


class HealthServerTest(unittest.TestCase):
    setUp=test_management.ManagementTest.setUp
    tearDown=test_management.ManagementTest.tearDown
    api=test_management.ManagementTest.api
    make_agent=test_management.ManagementTest.make_agent

    def test_legacy_ack_replay_alerts_crossings_and_original_hashes(self):
        agent,did,_=self.make_agent()
        with self.store.connect() as db:
            Store.event(db,did,'file.created','info',{'path':HEALTH},'historic-health')
            original=dict(db.execute("SELECT * FROM events WHERE event_id='historic-health'").fetchone())
        cases=[('skip-health','file.deleted','info',{'path':HEALTH}),
               ('skip-rename','file.renamed','info',{'source_path':TEMP,'destination_path':HEALTH}),
               ('keep-warning','file.deleted','warning',{'path':HEALTH}),
               ('keep-gap','agent.audit_gap','critical',{'path':HEALTH}),
               ('keep-doc','file.created','info',{'path':DOC}),
               ('keep-cross','file.moved','info',{'source_path':HEALTH,'destination_path':DOC}),
               ('keep-incomplete','file.renamed','info',{'path':HEALTH})]
        events=[{'event_id':eid,'kind':kind,'severity':level,'details':d,'occurred':time.time()} for eid,kind,level,d in cases]
        for _ in range(2):self.assertEqual(agent.call('/api/agent/events',{'events':events})['accepted'],[e['event_id'] for e in events])
        with self.store.connect() as db:
            for eid,_,_,_ in cases:self.assertEqual(db.execute('SELECT count(*) FROM events WHERE event_id=?',(eid,)).fetchone()[0],0 if eid.startswith('skip-') else 1)
            self.assertEqual(dict(db.execute("SELECT * FROM events WHERE event_id='historic-health'").fetchone()),original)
        self.assertTrue(self.store.verify()['valid'])
        # Actual endpoint heartbeat still works and stays separately observable.
        self.assertIn('body',agent.heartbeat())


if __name__=='__main__':unittest.main()
