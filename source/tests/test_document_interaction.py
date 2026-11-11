import collections
import copy
import ctypes
import json
import os
import subprocess
import sys
import time
import types
import unittest
import zipfile
from ctypes import wintypes as w
from pathlib import Path
from unittest.mock import patch,Mock
from guarddesk import document_context as context,file_access as access
from guarddesk.document_io import ReadObserver
from guarddesk.policy import DEFAULT_POLICY,agent_policy_wire,decode_agent_policy,normalize_policy


class InteractionTest(unittest.TestCase):
    def setUp(self):
        self.now=1000
        self.c=context.Context();self.c.states={1:{'active':True,'locked':False,'logon':10,'time':1000}}
        self.value={'session':1,'time':1000,'idle_ms':1000,'input_tick':100,'foreground_pid':123,'desktop':True}
        self.c.samples={1:collections.deque([dict(self.value)],maxlen=20)}
        self.details={'path':r'C:\Owned\empty.txt','process_id':123,'process_created':900,'process_session_id':1,'process_identity_status':'creation_time_checked','object_type':'file'}
    def classify(self,details=None):
        with patch('guarddesk.document_context.time.time',return_value=self.now):return self.c.classify(details or self.details,1000,30)
    def test_idle_locked_disconnected_foreground_and_session_separation(self):
        self.assertEqual(self.classify()[1]['interaction'],'recent_input_foreground')
        for change in ({'idle_ms':31000},{'foreground_pid':999},{'desktop':False},{'time':990}):
            self.c.samples[1]=[self.value|change];self.assertIsNotNone(self.classify()[0])
        self.c.samples[1]=[self.value]
        for changes in ({'locked':True},{'active':False},{'time':900}):
            self.c.states[1].update(changes);self.assertIsNotNone(self.classify()[0]);self.c.states[1]={'active':True,'locked':False,'logon':10,'time':1000}
        self.assertIsNotNone(self.classify(self.details|{'process_session_id':2})[0])
    def test_pid_reuse_unknown_metadata_and_future_samples_not_claimed_interactive(self):
        for changes in ({'process_created':1001},{'process_identity_status':'unavailable_or_process_replaced'},{'process_created':None}):
            self.assertIsNotNone(self.classify(self.details|changes)[0])
        self.c.samples[1]=[self.value|{'time':1002,'idle_ms':1000}];self.assertIsNotNone(self.classify()[0])
    def test_delayed_window_can_match_prior_input_but_never_later_input(self):
        self.c.samples[1]=[self.value|{'foreground_pid':999}]
        self.assertEqual(self.classify()[0],'foreground_not_observed')
        self.c.samples[1].append(self.value|{'time':1003,'idle_ms':4000})
        self.assertIsNone(self.classify()[0])
        self.c.samples[1]=[self.value|{'time':1003,'idle_ms':1000}]
        self.assertIsNotNone(self.classify()[0])
    def test_worker_deferred_context_is_bounded_and_delayed_foreground_is_delivered(self):
        import tempfile
        from test_general_file_audit import GeneralFileAuditTest
        with tempfile.TemporaryDirectory() as temporary:
            worker=GeneralFileAuditTest().worker(Path(temporary));worker.access_filter.context=self.c
            self.c.samples[1]=[self.value|{'foreground_pid':999}]
            with patch('guarddesk.document_context.time.time',return_value=1000):
                worker.emit_read(dict(self.details),1000);self.assertEqual(len(worker.pending_access),1)
                self.c.samples[1].append(self.value|{'time':1002,'idle_ms':3000})
                worker.drain_access();self.assertFalse(worker.pending_access);self.assertEqual(len(worker.candidate_queue.buffer),1)
                self.c.samples.clear()
                for i in range(300):worker.emit_read(self.details|{'path':'C:\\Owned\\'+str(i),'native_open_id':i},1000)
                self.assertEqual(len(worker.pending_access),256);self.assertEqual(worker.candidate_queue.overflow,44)
                expired=max(v[0] for v in worker.pending_access.values())+10
                with patch('guarddesk.document_worker.time.monotonic',return_value=expired):
                    for _ in range(8):worker.drain_access()
                self.assertFalse(worker.pending_access)
    def test_frames_reject_types_extra_fields_stale_large_and_other_session(self):
        self.assertTrue(context.valid_sample(self.value,1,1000))
        for change in ({'time':float('nan')},{'idle_ms':True},{'idle_ms':-1},{'input_tick':2**32},{'session':2},{'foreground_pid':'123'},{'desktop':1},{'time':996},{'time':1002},{'keys':'secret'}):
            self.assertFalse(context.valid_sample(self.value|change,1,1000))
    def test_source_filter_drops_background_and_keeps_empty_file_without_content_io(self):
        f=access.Filter(self.c)
        with patch('guarddesk.document_context.time.time',return_value=1000),patch('guarddesk.file_access.attributes',side_effect=AssertionError('known file must not query')):
            d=dict(self.details);self.assertIsNone(f.check(d,[],1000));self.assertEqual(d['interaction'],'recent_input_foreground')
            self.c.samples[1]=[self.value|{'idle_ms':60000}]
            self.assertEqual(f.check(dict(self.details),[],1000),'background_or_idle')
            self.assertIsNone(f.check(dict(self.details),[access.ALL_ACCESSES],1000))
    def test_cache_boundaries_and_no_blanket_appdata_or_business_filename_exclusion(self):
        cases=[(r'C:\Users\user1\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper',''),
               (r'C:\Users\dev\Desktop\KKTIX\edge_profile\Default\History1',r'C:\Apps\msedge.exe')]
        for path,image in cases:
            self.assertEqual(access.reason({'path':path,'process':image},[]),'known_background_cache')
            for kind in ('file.deleted','file.created','web.upload_started','file.copy_candidate'):
                self.assertFalse(access.excluded_event(kind,'info',{'path':path,'process':image},[]))
            self.assertFalse(access.excluded_event('file.opened','warning',{'path':path,'process':image},[]))
        for path in (r'C:\Business\History1',r'C:\Users\dev\AppData\Business\report.txt',r'C:\Business\Themes\document.txt'):
            self.assertIsNone(access.reason({'path':path,'process':r'C:\Apps\msedge.exe'},[]))
    def test_lifetime_no_minute_repeat_close_reopen_and_pending_empty_close(self):
        emitted=[];clock=[0];reader=ReadObserver(lambda d,t:emitted.append(d),clock=lambda:clock[0])
        event={'pid':123,'path':r'C:\Owned\empty.txt','open_id':1,'op':'read','bytes':1,'status':0}
        reader.feed(event);clock[0]=3600;reader.tick();reader.feed(event);self.assertEqual(len(emitted),1)
        reader.feed(event|{'op':'close'});reader.feed(event|{'open_id':2});self.assertEqual(len(emitted),2)
        reader.feed(event|{'open_id':3,'op':'open','bytes':0});reader.feed(event|{'open_id':3,'op':'close'})
        self.assertEqual(len(emitted),3);self.assertEqual(emitted[-1]['evidence'],'completed_native_open')
        self.assertFalse(emitted[-1]['read_confirmed']);reader.gap();self.assertFalse(reader.seen)
    def test_logical_merge_preserves_new_input_process_birth_and_different_files(self):
        reducer=access.OpenReducer()
        def item(**changes):return self.details|{'_interaction_key':(1,10,100)}|changes
        self.assertTrue(reducer.admit(item()));self.assertFalse(reducer.admit(item()))
        self.assertTrue(reducer.admit(item(_interaction_key=(1,10,101))))
        self.assertTrue(reducer.admit(item(process_created=901)))
        self.assertTrue(reducer.admit(item(path=r'C:\Owned\another.txt')))
        for i in range(5000):reducer.admit(item(path=str(i)))
        self.assertLessEqual(len(reducer.seen),4096);reducer.gap();self.assertTrue(reducer.admit(item()))
    def test_option_validation_roundtrip_and_invalid_intervals(self):
        policy=copy.deepcopy(DEFAULT_POLICY);policy['file_audit']['exclude_paths']=[access.INTERVAL+'60',r'C:\Excluded',access.ALL_ACCESSES,access.PROCESS+'background.exe']
        wire=agent_policy_wire({'body':policy});self.assertEqual(decode_agent_policy(wire)['body'],policy)
        self.assertNotIn(access.ALL_ACCESSES,wire['body']['file_audit']['exclude_paths'])
        for rule in (access.INTERVAL+'0',access.INTERVAL+'601',access.INTERVAL+'5.1',access.INTERVAL+'030',access.INTERVAL+'３０'):
            policy['file_audit']['exclude_paths']=[rule]
            with self.assertRaises(ValueError):normalize_policy(policy)
        for change in ({'format':True},{'positions':[100,0]},{'rules':['bad']},{'positions':[True,2]}):
            with self.assertRaises(ValueError):decode_agent_policy(wire|{'file_access_options':wire['file_access_options']|change})
    @unittest.skipUnless((Path(__file__).resolve().parents[1]/'dist/GuardDesk-0.4.53-source.zip').is_file(),'Requires sealed 0.4.53 source archive; legacy policy/file_access unchanged in this release; not replaced with a fake legacy decoder')
    def test_real_legacy_053_decoder(self):
        policy=copy.deepcopy(DEFAULT_POLICY);policy['file_audit']['exclude_paths']=[access.INTERVAL+'60',r'C:\Excluded',access.ALL_ACCESSES,access.PROCESS+'background.exe']
        wire=agent_policy_wire({'body':policy})
        root=Path(__file__).resolve().parents[1]
        with zipfile.ZipFile(root/'dist/GuardDesk-0.4.53-source.zip') as archive:
            legacy_access=types.ModuleType('guarddesk.file_access');legacy_access.__package__='guarddesk'
            exec(compile(archive.read('guarddesk/file_access.py'),'sealed-053-file-access.py','exec'),legacy_access.__dict__)
            legacy_policy=types.ModuleType('guarddesk.legacy_policy');legacy_policy.__package__='guarddesk'
            exec(compile(archive.read('guarddesk/policy.py'),'sealed-053-policy.py','exec'),legacy_policy.__dict__)
            with patch.dict(sys.modules,{'guarddesk.file_access':legacy_access}):
                old=legacy_policy.decode_agent_policy(wire)['body']
                self.assertEqual(old['file_audit']['exclude_paths'],[r'C:\Excluded',access.PROCESS+'background.exe'])

    def test_context_poll_bounds_closes_locked_and_retries_failed_helpers(self):
        channel=Mock();channel.poll.return_value=[self.value]
        states={1:{'active':True,'locked':False,'logon':10,'time':1000}}
        with patch('guarddesk.document_context.session_states',return_value=states),patch('guarddesk.document_context.launch',return_value=channel) as launch,patch('guarddesk.document_context.time.time',return_value=1000),patch('guarddesk.document_context.time.monotonic',return_value=100):
            c=context.Context();c.poll();self.assertEqual(c.status()['fresh_samples'],1);launch.assert_called_once()
            c.next_scan=0;states[1]['locked']=True;c.poll();channel.close.assert_called_once();self.assertFalse(c.channels)
            self.assertNotIn(1,c.retry)
            c.next_scan=0;states[1]['locked']=False;c.poll();self.assertEqual(launch.call_count,2)
            c.close();self.assertFalse(c.retry);self.assertFalse(c.channels)
        with patch('guarddesk.document_context.session_states',side_effect=OSError('unavailable')):
            c=context.Context();c.poll();self.assertFalse(c.states);self.assertEqual(c.errors,1)
    def test_actual_worker_filter_reducer_and_queue_keep_reopen_and_drop_idle(self):
        import tempfile
        from test_general_file_audit import GeneralFileAuditTest,Trace
        with tempfile.TemporaryDirectory() as temporary:
            worker=GeneralFileAuditTest().worker(Path(temporary));worker.context=self.c;worker.access_filter.context=self.c
            identity={k:v for k,v in self.details.items() if k not in ('path','process_id','object_type')}
            event={'path':self.details['path'],'pid':123,'op':'open','open_id':1,'status':0,'bytes':0,'occurred':1000,'non_directory_confirmed':True}
            with patch('guarddesk.document_io.NativeTrace',Trace),patch('guarddesk.document_process.ProcessResolver.resolve',return_value=identity),patch.object(self.c,'poll'),patch('guarddesk.document_context.time.time',return_value=1000):
                worker.cycle()
                worker.trace.events=[event,event|{'op':'close'},event|{'open_id':2},event|{'op':'close','open_id':2}];worker.cycle()
                self.c.samples[1]=[self.value|{'input_tick':101}]
                worker.trace.events=[event|{'open_id':3},event|{'op':'close','open_id':3}];worker.cycle()
                self.c.samples[1]=[self.value|{'input_tick':102,'idle_ms':60000}]
                worker.trace.events=[event|{'open_id':4},event|{'op':'close','open_id':4}];worker.cycle()
                with worker.agent.db() as db:rows=[json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox')]
                self.assertEqual(len(rows),2);self.assertEqual(worker.open_reducer.merged,1)
                self.assertEqual(worker.filtered_access,{'background_or_idle':1})
                self.assertTrue(all(r['details']['interaction']=='recent_input_foreground' and '_interaction_key' not in r['details'] for r in rows))
                self.assertEqual(worker.status()['read']['filter_minimum_version'],'0.4.54')


@unittest.skipUnless(os.name=='nt','Windows session/pipe fixture')
class WindowsContextTest(unittest.TestCase):
    def test_own_session_helper_stream_identity_and_cleanup(self):
        api=context.kernel_api();adv=ctypes.WinDLL('advapi32',use_last_error=True);token=w.HANDLE()
        api.GetCurrentProcess.restype=w.HANDLE
        adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)]
        self.assertTrue(adv.OpenProcessToken(api.GetCurrentProcess(),8,ctypes.byref(token)))
        try:channel=context.Channel(context.token_sid(token))
        finally:api.CloseHandle(token)
        child=None
        try:
            # Windows venv python.exe is a redirector with a different child
            # PID. Exercise the real pipe-writer PID without loosening the
            # product's same-handle/PID identity check.
            environment=os.environ.copy();environment['PYTHONPATH']=os.pathsep.join(p for p in sys.path if p)
            child=subprocess.Popen([getattr(sys,'_base_executable',sys.executable),str(Path(__file__).resolve().parents[1]/'app.py'),'document-session-context','--pipe',channel.pipe,'--parent',str(os.getpid())],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=environment)
            api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
            channel.process=api.OpenProcess(0x100001,False,child.pid);channel.pid=child.pid
            self.assertTrue(channel.process)
            records=[];deadline=time.monotonic()+8
            while time.monotonic()<deadline and not records:
                records.extend(channel.poll());time.sleep(.1)
            if not records and child.poll() is not None:self.fail(child.stderr.read(4000).decode(errors='replace'))
            self.assertTrue(records);self.assertTrue(context.valid_sample(records[-1],records[-1]['session'],time.time()))
            self.assertEqual(set(records[-1]),{'session','time','idle_ms','input_tick','foreground_pid','desktop'})
        finally:
            channel.close()
            if child:
                child.wait(timeout=5);child.stderr.close()
