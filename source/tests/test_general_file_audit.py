import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from unittest.mock import Mock
from contextlib import nullcontext
from guarddesk.document_scope import paths,permits
from guarddesk.document_io import ReadObserver,CopyCorrelator
from guarddesk.document_worker import DocumentWorker
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.document_settings import packet
from test_document_native import queue_fixture


class Trace:
    def __init__(self):self.active=False;self.events=[];self.stats={'consumer_result':0,'dropped':0}
    def start_policy(self,policy,watch,runtime=None):self.policy=copy.deepcopy(policy);self.watch=watch;self.active=True
    def stop(self):self.active=False
    def poll(self):events=self.events;self.events=[];return events


class GeneralFileAuditTest(unittest.TestCase):
    def test_successful_open_fallback_and_read_share_one_observation(self):
        records=[];clock=[0];observer=ReadObserver(lambda d,t:records.append(d),clock=lambda:clock[0])
        event={'path':r'C:\Owned\mapped.txt','pid':123,'op':'open','bytes':0,'status':0,'open_id':1}
        observer.feed(event);observer.tick();self.assertFalse(records)
        clock[0]=1;observer.tick()
        self.assertEqual(records[0]['evidence'],'completed_native_open');self.assertFalse(records[0]['read_confirmed'])
        self.assertNotIn('read_bytes',records[0]);self.assertFalse(records[0]['human_read_confirmed'])
        observer.feed({**event,'op':'read','bytes':64});self.assertEqual(len(records),1)
        observer.feed({**event,'open_id':2});observer.feed({**event,'open_id':2,'op':'read','bytes':64})
        clock[0]=3;observer.tick();self.assertEqual(len(records),2)
        self.assertEqual(records[1]['evidence'],'completed_native_read')
        observer.feed({**event,'status':5,'open_id':3});observer.feed({**event,'pid':0,'open_id':3})
        observer.gap();clock[0]=5;observer.tick();self.assertEqual(len(records),2)

    def test_pending_opens_are_bounded_and_gaps_do_not_invent_copy(self):
        records=[];observer=ReadObserver(lambda d,t:records.append(d),clock=lambda:0)
        event={'path':r'C:\Owned\mapped.txt','pid':123,'op':'open','bytes':0,'status':0}
        for i in range(5000):observer.feed({**event,'open_id':i})
        self.assertEqual(len(observer.pending),4096);self.assertEqual(observer.pending_overflow,904)
        copies=[];copy=CopyCorrelator(lambda d,t:copies.append(d))
        copy.feed(event);copy.feed({**event,'op':'write','bytes':12,'offset':0,'path':r'C:\Owned\copy.txt'})
        self.assertFalse(copies)

    def test_process_identity_checks_birth_time_and_bounds_queries(self):
        from guarddesk.document_process import ProcessResolver
        resolver=ProcessResolver();image={'born':10,'queried':30,'image':r'C:\Windows\notepad.exe'}
        with patch.object(resolver,'query',return_value=image) as query,patch('guarddesk.document_process.time.time',return_value=30),patch('guarddesk.document_process.time.monotonic',return_value=100):
            self.assertEqual(resolver.resolve({'pid':123,'occurred':20})['process'],image['image'])
            self.assertEqual(resolver.resolve({'pid':123,'occurred':21})['process'],image['image']);self.assertEqual(query.call_count,1)
            self.assertNotIn('process',resolver.resolve({'pid':123,'occurred':9}))
            self.assertNotIn('process',resolver.resolve({'pid':123,'occurred':31}))
            for i in range(100):resolver.resolve({'pid':i+1000,'occurred':20})
            self.assertEqual(query.call_count,64)

    def test_extended_worker_starts_general_companion_once_with_empty_named_rules(self):
        from guarddesk.application_control import ExtendedWorker
        with tempfile.TemporaryDirectory() as d:
            agent=SimpleNamespace(config_path=Path(d)/'config.json',custom_packet=None)
            worker=ExtendedWorker(agent);worker.policy=copy.deepcopy(DEFAULT_POLICY)
            child=SimpleNamespace(policy=None)
            factory=Mock();factory.return_value.start.return_value=child
            with patch('guarddesk.document_worker.DocumentWorker',factory):
                worker.configure_documents();worker.configure_documents()
            factory.assert_called_once();self.assertIs(child.policy,worker.policy)

    def test_google_drive_guid_volume_and_unknown_fixed_drive_do_not_stop_other_volumes(self):
        import ctypes
        from guarddesk.document_io import NativeTrace
        from guarddesk.document_scope import local_device
        guid=r'\Device\Volume{042dcf0d-1a8b-3c45-87b7-1a3469d2a54b}'
        self.assertTrue(local_device(guid));self.assertFalse(local_device(r'\Device\Mup\server\share'))
        targets={'C:':r'\Device\HarddiskVolume3','D:':guid,'E:':r'\Device\OtherVirtualDisk'}
        def query(drive,buffer,size):buffer.value=targets[drive];return len(buffer.value)+1
        kernel=SimpleNamespace(QueryDosDeviceW=Mock(side_effect=query),GetDriveTypeW=Mock(return_value=3))
        trace=object.__new__(NativeTrace);trace.active=False;trace.api=SimpleNamespace(gd_trace_start_filtered=Mock(return_value=0))
        with patch.object(ctypes,'WinDLL',return_value=kernel),patch('guarddesk.process_audit.security_privilege',return_value=nullcontext()):
            trace._start_paths(['C:\\','D:\\','E:\\'],skip_unsupported=True)
        self.assertTrue(trace.active);self.assertEqual(trace.unsupported_volumes,1)
        self.assertEqual(trace.api.gd_trace_start_filtered.call_args.args[1],2)
        self.assertIn((guid,'D:'),trace.mappings)

    def test_general_scope_and_shared_exclusions_require_no_named_documents(self):
        policy={'enabled':True,'scope':'all_local','exclude_paths':[r'C:\Users\{user}\AppData']}
        self.assertEqual(paths(policy,'unused',drives=['C:\\','D:\\']),['C:\\','D:\\'])
        self.assertFalse(permits(r'C:\Users\alice\AppData\x.txt',policy,r'C:\Owned'))
        self.assertTrue(permits(r'C:\Users\alice\Documents\x.txt',policy,r'C:\Owned'))
        policy['scope']='managed'
        self.assertFalse(permits(r'D:\Other\x.txt',policy,r'C:\Owned'))
        self.assertTrue(permits(r'C:\Owned\x.txt',policy,r'C:\Owned'))
        policy['enabled']=False;self.assertEqual(paths(policy,r'C:\Owned'),[])

    def test_read_buffers_deduplicate_but_immediate_new_open_is_retained(self):
        events=[];clock=[0];observer=ReadObserver(lambda d,t:events.append(d),clock=lambda:clock[0])
        event={'path':r'C:\Owned\x.txt','pid':123,'op':'read','bytes':12,'status':0,'open_id':1}
        for i in range(20):observer.feed(event)
        observer.feed({**event,'open_id':2})
        self.assertEqual(len(events),2)
        observer.feed({**event,'status':5,'open_id':3});observer.feed({**event,'pid':0});observer.feed({**event,'bytes':0})
        self.assertEqual(len(events),2)
        clock[0]=60;observer.feed(event);self.assertEqual(len(events),2)
        self.assertFalse(events[0]['human_read_confirmed']);self.assertIsNone(events[0]['user'])
        for i in range(5000):observer.feed({**event,'open_id':i+10})
        self.assertLessEqual(len(observer.seen),4096)

    def worker(self,root,rules=None):
        agent=SimpleNamespace(root=root,config_path=root/'config.json',audit_runtime=root/'internal',config={'audit_watch':r'C:\Owned'},custom_packet={'documents':packet(rules or []),'body':{},'busy':False})
        queue_fixture(agent,root)
        worker=DocumentWorker(agent,root);worker.policy=copy.deepcopy(DEFAULT_POLICY);worker.policy['file_audit']['scope']='managed';worker.trusted=True
        # These fixtures isolate scope/type/queue behavior. Session correlation
        # and the real local-pipe boundary have separate interaction tests.
        worker.context=Mock();worker.context.channels={};worker.context.status.return_value={'fresh_samples':1}
        worker.access_filter.context=None
        return worker

    def test_empty_named_rule_collects_reads_and_preserves_base_exclusions(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);worker=self.worker(root)
            worker.policy['file_audit']['exclude_paths']=[r'C:\Owned\excluded']
            with patch('guarddesk.document_io.NativeTrace',Trace),patch('guarddesk.document_sacl.Manager',side_effect=AssertionError('General policy must not create SACL')):
                worker.cycle();self.assertTrue(worker.trace.active)
                base={'pid':123,'tid':10,'op':'read','bytes':1024,'offset':0,'status':0,'open_id':1}
                worker.trace.events=[{**base,'path':r'C:\Owned\x.txt'},{**base,'path':r'C:\Owned\excluded\secret.txt'},{**base,'path':r'D:\Outside\x.txt'}]
                worker.cycle()
                with worker.agent.db() as db:rows=[json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox')]
                self.assertEqual([r['kind'] for r in rows],['file.opened'])
                self.assertEqual(worker.status()['read']['status'],'collecting_native_reads')
                self.assertFalse((root/'document-sacl.sqlite3').exists())
                trace=worker.trace;worker.policy['file_audit']['enabled']=False;worker.cycle()
                self.assertFalse(trace.active);self.assertEqual(worker.status()['read']['status'],'disabled')

    def test_worker_queues_completed_open_without_fabricating_read_or_copy(self):
        with tempfile.TemporaryDirectory() as d:
            worker=self.worker(Path(d));clock=[0]
            with patch('guarddesk.document_io.NativeTrace',Trace):
                worker.cycle();worker.reader.clock=lambda:clock[0]
                worker.trace.events=[{'path':r'C:\Owned\mapped.txt','pid':123,'tid':10,'op':'open','bytes':0,'status':0,'open_id':1,'non_directory_confirmed':True}]
                worker.cycle();clock[0]=2;worker.cycle()
                with worker.agent.db() as db:rows=[json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox')]
                self.assertEqual([r['kind'] for r in rows],['file.opened'])
                self.assertEqual(rows[0]['details']['evidence'],'completed_native_open')
                self.assertFalse(rows[0]['details']['read_confirmed']);self.assertNotIn('read_bytes',rows[0]['details'])
                self.assertEqual(worker.status()['read']['open_observations'],1)

    def test_changing_exclusions_restarts_native_filter_and_paused_policy_stops_trace(self):
        with tempfile.TemporaryDirectory() as d:
            worker=self.worker(Path(d))
            with patch('guarddesk.document_io.NativeTrace',Trace):
                worker.cycle();old=worker.trace
                worker.policy['file_audit']['exclude_paths']=[r'C:\Owned\newly-excluded'];worker.cycle()
                self.assertFalse(old.active);self.assertEqual(worker.trace.policy['exclude_paths'],[r'C:\Owned\newly-excluded'])
                with patch('guarddesk.custom_settings.compatibility_modules',return_value=['security_file_events']):worker.cycle()
                self.assertIsNone(worker.trace);self.assertEqual(worker.status()['read']['status'],'compatibility_paused')

    def test_worker_filters_background_and_directories_but_keeps_interactive_empty_file(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            worker=self.worker(Path(d));clock=[0]
            def identity(event):
                return {'process_identity_status':'creation_time_checked','process_session_id':0 if event['pid']==9000 else 1,'process':r'C:\Apps\editor.exe'}
            with patch('guarddesk.document_io.NativeTrace',Trace),patch('guarddesk.document_process.ProcessResolver.resolve',side_effect=identity),patch('guarddesk.file_access.attributes',return_value=0x10):
                worker.cycle();worker.reader.clock=lambda:clock[0]
                base={'tid':10,'op':'open','bytes':0,'status':0}
                worker.trace.events=[{**base,'pid':9000,'open_id':1,'path':r'C:\Owned\service.txt'},
                    {**base,'pid':9001,'open_id':2,'path':r'C:\Owned\DOCUME~1'},
                    {**base,'pid':os.getpid(),'open_id':3,'path':r'C:\Owned\self.txt'},
                    {**base,'pid':9001,'open_id':4,'path':r'C:\Owned\empty.txt','non_directory_confirmed':True}]
                worker.cycle();clock[0]=2;worker.cycle()
                with worker.agent.db() as db:rows=[json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox')]
                self.assertEqual([r['details']['path'] for r in rows],[r'C:\Owned\empty.txt'])
                self.assertFalse(rows[0]['details']['read_confirmed'])
                self.assertEqual(worker.status()['read']['filtered_access'],{'noninteractive_service':1,'directory':1,'collector_self':1})

    def test_native_gap_discards_mixed_batch_and_persists_gap_instead_of_false_copy(self):
        with tempfile.TemporaryDirectory() as d:
            worker=self.worker(Path(d))
            with patch('guarddesk.document_io.NativeTrace',Trace):
                worker.cycle()
                event={'path':r'C:\Owned\source.txt','pid':123,'op':'read','bytes':32,'offset':0,'status':0,'open_id':1}
                worker.trace.events=[event,{**event,'op':'write','path':r'C:\Owned\target.txt'}]
                worker.trace.stats['dropped']=1;worker.cycle()
                with worker.agent.db() as db:rows=[json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox')]
                self.assertEqual([r['kind'] for r in rows],['agent.audit_gap'])


if __name__=='__main__':unittest.main()
