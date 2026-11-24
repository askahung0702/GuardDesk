"""Completed-write simulation and real offline admission; no HTTP/ETW/Office."""
import copy
import datetime as dt
import json
import time
import unittest
from unittest.mock import patch
import test_endpoint_controls as fixtures
import test_policy_defaults as db_fixtures
from guarddesk import document_writes as writes, audit_reports
from guarddesk.document_io import ReadObserver, CopyCorrelator, NativeTrace
from guarddesk.document_worker import DocumentWorker
from guarddesk.file_access import ALL_ACCESSES, PROCESS, excluded_event
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.policy_defaults import SYSTEM32
from guarddesk.server import Handler, digest
from guarddesk.store import Store, canonical


class Resolver:
    def resolve(self,event):
        return {'process':r'C:\Office\WINWORD.EXE','process_created':900,
                'process_session_id':1,'process_identity_status':'creation_time_checked'}


def io(**changes):
    return {'op':'write','status':0,'pid':123,'open_id':1,'bytes':1024,'offset':0,
            'path':r'C:\Docs\report.docx','occurred':1000,'non_directory_confirmed':True,**changes}


class WriteBurstTest(unittest.TestCase):
    def setUp(self):
        self.now=0;self.events=[];self.loss=[]
        self.writer=writes.WriteObserver(lambda d,t:self.events.append((dict(d),t)),
                                        resolver=Resolver(),overflow=self.loss.append,clock=lambda:self.now)

    def test_in_place_buffers_become_one_write_activity_without_content_or_human_claim(self):
        for _ in range(1000):self.writer.feed(io(content='must never be copied'))
        self.writer.tick();self.assertEqual(self.events,[])
        self.now=3;self.writer.tick()
        self.assertEqual(len(self.events),1);details,_=self.events[0]
        self.assertEqual(details['written_bytes'],1024*1000)
        self.assertEqual(details['observed_write_ranges'],1000)
        self.assertEqual(details['process'],r'C:\Office\WINWORD.EXE')
        self.assertIsNone(details['user']);self.assertNotIn('content',details)
        self.assertFalse(details['human_save_confirmed']);self.assertFalse(details['disk_flush_confirmed'])

    def test_failed_empty_unknown_open_and_attribute_events_never_become_writes(self):
        for change in ({'op':'open'},{'op':'read'},{'op':'close'},{'status':259},{'status':True},
                       {'bytes':0},{'bytes':True},{'bytes':-1},{'pid':-1},{'pid':True},
                       {'open_id':0},{'open_id':True},{'path':'relative.docx'}):self.writer.feed(io(**change))
        self.writer.tick(force=True);self.assertEqual(self.events,[])

    def test_quiet_and_maximum_windows_preserve_later_save_activity(self):
        self.writer.feed(io());self.now=1;self.writer.feed(io())
        self.now=3;self.writer.feed(io(occurred=1003))
        self.assertEqual(len(self.events),1)
        for stamp in range(4,14):self.now=stamp;self.writer.feed(io(occurred=1000+stamp))
        self.assertEqual(len(self.events),2)
        self.assertEqual(self.events[1][0]['aggregation_end'],'maximum_window')
        self.writer.tick(force=True);self.assertEqual(len(self.events),3)

    def test_process_file_open_lifetimes_and_trace_gap_do_not_cross_merge(self):
        for change in ({},{'open_id':2},{'pid':124},{'path':r'C:\Docs\other.docx'}):self.writer.feed(io(**change))
        self.writer.gap();self.assertEqual(len(self.events),4)
        self.assertTrue(all(d['collection_interrupted'] for d,_ in self.events))
        self.writer.feed(io());self.now=3;self.writer.tick()
        self.assertFalse(self.events[-1][0]['collection_interrupted'])

    def test_pending_bound_reports_loss_without_a_fixed_minute_quota(self):
        for n in range(writes.MAX_PENDING+10):self.writer.feed(io(path=fr'C:\Docs\file{n}.docx'))
        self.assertLessEqual(len(self.writer.pending),writes.MAX_PENDING)
        self.now=3;self.writer.tick()
        self.assertEqual(len(self.events),writes.MAX_PENDING)
        self.assertEqual(self.loss,[])
        self.now=61;self.writer.tick()
        self.assertEqual(sum(self.loss),10)
        self.writer.feed(io(path=r'C:\Docs\new.docx'));self.now=64;self.writer.tick()
        self.assertEqual(len(self.events),writes.MAX_PENDING+1)

    def test_successful_eof_to_zero_and_overwrite_are_activity_without_fake_byte_count(self):
        self.writer.feed(io(op='set_end_of_file',file_size=0))
        self.writer.feed(io(op='overwrite'))
        self.writer.tick(force=True)
        details,_=self.events[0]
        self.assertEqual(details['written_bytes'],0)
        self.assertEqual(details['size_updates'],1);self.assertEqual(details['file_size_after'],0)
        self.assertEqual(details['overwrite_opens'],1)
        self.assertEqual(details['observed_write_ranges'],0)

    def test_writes_without_confirmed_process_never_enter_the_burst_buffer(self):
        for op in ('write','overwrite','set_end_of_file'):
            for pid in (0,4):self.writer.feed(io(op=op,pid=pid,file_size=0))
        for evidence in ({'process_identity_status':'unavailable_or_process_replaced'},
                         {'process_identity_status':'query_budget_reached'},
                         {'process_identity_status':'creation_time_checked','process_session_id':1},
                         {'process_identity_status':'not_resolved','process':r'C:\Apps\writer.exe'}):
            with patch.object(self.writer.resolver,'resolve',return_value=evidence):
                self.writer.feed(io())
        self.assertEqual(len(self.writer.pending),0)
        self.writer.feed(io())
        self.writer.tick(force=True)
        self.assertEqual(len(self.events),1)
        self.assertEqual(self.events[0][0]['process'],r'C:\Office\WINWORD.EXE')
        self.assertIsNone(self.events[0][0]['user'])

    def test_kernel_size_requests_and_ntfs_metadata_do_not_become_writes(self):
        for pid in (0,4):
            self.writer.feed(io(pid=pid,op='set_end_of_file',file_size=3211264,path=r'C:\Apps\example.exe'))
        for path in ('C:\\$Extend\\',r'D:\$EXTEND\$UsnJrnl:$J',r'D:\$Mft::$DATA'):
            self.writer.feed(io(path=path))
        self.writer.tick(force=True)
        self.assertEqual(self.events,[])
        for path in (r'C:\Apps\example.exe',r'C:\Docs\$Extend\report',r'C:\$Extend-notes.txt'):
            self.writer.feed(io(path=path))
        self.writer.tick(force=True)
        self.assertEqual(len(self.events),3)

    def test_admission_filter_cannot_allocate_a_pending_write(self):
        self.writer.admit=lambda d,t:False
        self.writer.feed(io());self.writer.tick(force=True)
        self.assertEqual(len(self.writer.pending),0);self.assertEqual(self.events,[])

    def test_data_bytes_alone_do_not_prove_a_regular_file(self):
        for kind, path in (('directory',r'C:\Users\fixture\AppData'),(None,r'C:\Users\fixture\unresolved')):
            with patch('guarddesk.hidden_files.resolver') as resolve:
                resolve.return_value.file_type.return_value=kind
                self.writer.feed(io(path=path,non_directory_confirmed=False))
        self.assertEqual(self.writer.status()['write_without_file_type_evidence'],2)
        with patch('guarddesk.hidden_files.resolver') as resolve:
            resolve.return_value.file_type.return_value='directory'
            self.writer.feed(io(path=r'C:\Users\fixture:stream'))
        self.writer.feed(io(path=r'C:\Users\fixture\README'))
        self.writer.tick(force=True)
        self.assertEqual([d['path'] for d,_ in self.events],[r'C:\Users\fixture\README'])
        self.assertEqual(self.events[0][0]['object_type_evidence'],'native_non_directory_option')

    def test_full_active_map_does_not_rescan_every_pending_burst_per_new_record(self):
        for n in range(writes.MAX_PENDING):self.writer.feed(io(path=fr'C:\Docs\active{n}.docx'))
        with patch.object(self.writer,'tick',wraps=self.writer.tick) as tick:
            for n in range(1000):self.writer.feed(io(path=fr'C:\Docs\overflow{n}.docx'))
            self.assertEqual(tick.call_count,0)
        self.assertEqual(self.writer.capacity_lost,1000)


class WriteWorkerTest(unittest.TestCase):
    setUp=fixtures.EndpointTest.setUp
    tearDown=fixtures.EndpointTest.tearDown
    queued=fixtures.EndpointTest.queued

    def worker(self):
        worker=DocumentWorker(self.agent,self.root/'owned-document-state')
        worker.policy=copy.deepcopy(DEFAULT_POLICY)
        worker.policy['file_audit']['exclude_paths']=[ALL_ACCESSES]
        worker.writer.resolver=Resolver()
        return worker

    def test_actual_worker_cycle_routes_in_place_write_to_durable_outbox(self):
        worker=self.worker();clock=[0];worker.writer.clock=lambda:clock[0]
        class Trace:
            stats={'consumer_result':0,'dropped':0,'completed':1,'schema_unresolved':0}
            def __init__(self):self.events=[io(pid=4),io()]
            def poll(self):result=self.events;self.events=[];return result
        worker.trace=Trace();worker.trusted=True
        # The real watch is config-defined; retain its exact signature.
        worker.trace_signature=repr((worker.policy['file_audit'],self.agent.config.get('audit_watch',str(self.agent.root)),True))
        worker.reader=ReadObserver(worker.emit_read);worker.correlator=CopyCorrelator(worker.emit)
        worker.cycle();clock[0]=3;worker.cycle()
        rows=self.queued();self.assertEqual([r['kind'] for r in rows],['file.written'])
        self.assertEqual(rows[0]['details']['path'],r'C:\Docs\report.docx')
        self.assertEqual(rows[0]['details']['written_bytes'],1024)

    def test_exclusion_and_disabled_policy_rechecked_before_emission(self):
        for disabled in (False,True):
            worker=self.worker();worker.writer.feed(io())
            if disabled:worker.policy['file_audit']['enabled']=False
            else:worker.policy['file_audit']['exclude_paths'].append(r'C:\Docs')
            worker.writer.tick(force=True);worker.candidate_queue.flush()
        self.assertEqual(self.queued(),[])

    def test_read_process_and_system32_start_stop_filters_do_not_hide_writes(self):
        worker=self.worker();worker.policy['application_audit_exclusions']=[SYSTEM32]
        class SystemResolver(Resolver):
            def resolve(self,event):return {**super().resolve(event),'process':SYSTEM32+'cmd.exe'}
        worker.writer.resolver=SystemResolver()
        worker.writer.feed(io());worker.writer.tick(force=True);worker.candidate_queue.flush()
        self.assertEqual(len(self.queued()),1)
        worker=self.worker();worker.policy['file_audit']['exclude_paths'].append(PROCESS+'WINWORD.EXE')
        worker.writer.feed(io());worker.writer.tick(force=True);worker.candidate_queue.flush()
        self.assertEqual(len(self.queued()),2)
        self.assertFalse(excluded_event('file.written','info',{'process':r'C:\Office\WINWORD.EXE','process_identity_status':'creation_time_checked'},[PROCESS+'WINWORD.EXE']))
        self.assertFalse(excluded_event('file.written','info',{'process':r'C:\Office\WINWORD.EXE'},[PROCESS+'WINWORD.EXE']))
        self.assertFalse(excluded_event('file.written','warning',{'process':r'C:\Office\WINWORD.EXE'},[PROCESS+'WINWORD.EXE']))

    def test_default_interactive_read_mode_does_not_filter_background_write(self):
        worker=self.worker();worker.policy['file_audit']['exclude_paths']=[]
        with patch.object(worker.access_filter.context,'classify',side_effect=AssertionError('read context must not gate writes')):
            worker.writer.feed(io());worker.writer.tick(force=True)
        self.assertEqual(len(worker.candidate_queue.buffer),1)

    def test_any_extension_and_no_extension_from_service_are_retained(self):
        worker=self.worker();worker.policy['file_audit']['exclude_paths']=[]
        class ServiceResolver(Resolver):
            def resolve(self,event):return {**super().resolve(event),'process':r'C:\Tools\worker.exe','process_session_id':0}
        worker.writer.resolver=ServiceResolver()
        paths=[r'C:\Docs\data'+extension for extension in ('.txt','.csv','.xlsx','.pdf','.png','.zip','.db','.json','.bin','')]
        for path in paths:worker.writer.feed(io(path=path))
        worker.writer.tick(force=True);worker.candidate_queue.flush()
        self.assertEqual({r['details']['path'] for r in self.queued()},set(paths))


class WriteIngestionTest(unittest.TestCase):
    setUp=db_fixtures.PolicyDefaultsTest.setUp

    def test_actual_route_ack_filters_replay_and_incremental_report_action(self):
        handler=Handler.__new__(Handler);handler.headers={'Authorization':'Bearer owned-token'}
        with self.store.connect() as db:
            db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',
                       ('owned',digest('owned-token'),'Owned-PC','Owned',time.time()))
            body=Store.policy(db)['body'];body['file_audit']['exclude_paths'].append(r'C:\Excluded')
            db.execute('UPDATE policies SET body=? WHERE version=1',(canonical(body),))
            Store.event(db,'owned','file.modified','info',{'path':r'C:\Docs\report.docx'},'history')
            historical=dict(db.execute("SELECT * FROM events WHERE event_id='history'").fetchone())
            events=[{'event_id':eid,'kind':kind,'severity':'info','occurred':time.time(),'details':{'path':path}}
                    for eid,kind,path in [('write','file.written',r'C:\Docs\report.docx'),
                                          ('excluded','file.written',r'C:\Excluded\report.docx'),
                                          ('modified','file.modified',r'C:\Docs\report.docx')]]
            for _ in range(2):
                reply,_,_=handler.route(db,'POST','/api/agent/events',{'events':events})
                self.assertEqual(reply['accepted'],['write','excluded','modified'])
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE event_id='write'").fetchone()[0],1)
            self.assertIsNone(db.execute("SELECT id FROM events WHERE event_id IN ('excluded','modified')").fetchone())
            self.assertEqual(dict(db.execute("SELECT * FROM events WHERE event_id='history'").fetchone()),historical)
        audit_reports.index_batch(self.store)
        day=dt.datetime.now(audit_reports.TAIPEI).date().isoformat()
        with self.store.connect() as db:
            summary=audit_reports.summary(db,{'start':[day],'end':[day],'action':['written'],'group_by':['device']})
            self.assertEqual(summary['total'],1)
        self.assertTrue(self.store.verify()['valid'])


class NativeWriteDecodeTest(unittest.TestCase):
    def test_real_abi_adapter_routes_zero_eof_and_overwrite_without_positive_bytes(self):
        trace=NativeTrace.__new__(NativeTrace);trace.mappings=[(r'\Device\HarddiskVolume123','C:')]
        class API:
            def gd_trace_poll(self,data,count,stats):
                for i,op in enumerate((69,65537)):
                    data[i].op=op|0x20000;data[i].bytes=0;data[i].pid=123;data[i].open_id=1
                    data[i].status=0;data[i].path=r'\Device\HarddiskVolume123\Docs\empty.txt'
                    data[i].time=116444736000000000+1000*10000000
                return 2
            def gd_trace_aux_stats(self,stats,count):return 0
        trace.api=API();events=trace.poll()
        self.assertEqual([e['op'] for e in events],['set_end_of_file','overwrite'])
        self.assertTrue(all(e['non_directory_confirmed'] for e in events))
        self.assertEqual(events[0]['file_size'],0);self.assertEqual(events[0]['bytes'],0)
        observed=[];writer=writes.WriteObserver(lambda d,t:observed.append(d),resolver=Resolver())
        for event in events:writer.feed(event)
        writer.tick(force=True)
        self.assertEqual(len(observed),1);self.assertEqual(observed[0]['file_size_after'],0)
        self.assertEqual(observed[0]['overwrite_opens'],1)
