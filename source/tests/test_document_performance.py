"""Work retained under cached policy, reused buffers and background scheduling."""
import ctypes
import os
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from guarddesk.document_io import NativeTrace
from guarddesk.document_worker import DocumentWorker
from guarddesk import file_access as access,document_context as context


class DocumentPerformanceTest(unittest.TestCase):
    def test_filter_reuses_validated_policy_but_applies_mutations_and_clear(self):
        f=access.Filter();rules=[access.PROCESS+'background.exe']
        item={'path':r'C:\Owned\empty.txt','process_id':123456,'process':r'C:\Apps\background.exe',
              'process_identity_status':'creation_time_checked','process_session_id':1,'object_type':'file'}
        with patch('guarddesk.file_access.options',wraps=access.options) as parse:
            for _ in range(100):self.assertEqual(f.check(dict(item),rules),'excluded_process')
            self.assertEqual(parse.call_count,1)
            rules[:]=[access.ALL_ACCESSES,access.INTERVAL+'60']
            self.assertIsNone(f.check(dict(item),rules));self.assertEqual(f.settings['mode'],'all')
            rules.clear();self.assertIsNone(f.check(dict(item),rules));self.assertEqual(f.settings['mode'],'interactive')
            self.assertEqual(parse.call_count,3)
            rules.append(access.INTERVAL+'invalid')
            with self.assertRaises(ValueError):f.check(dict(item),rules)
            self.assertEqual(f.rules_snapshot,());rules.clear();self.assertIsNone(f.check(dict(item),rules))

    def test_reused_native_buffer_never_replays_old_slots_and_copies_output(self):
        trace=object.__new__(NativeTrace);trace.mappings=[(r'\Device\HarddiskVolume3','C:')]
        calls=[];counts=iter((2,0,1,257))
        def poll(data,size,stats):
            calls.append(ctypes.addressof(data));count=next(counts)
            if count and count<=256:
                for i in range(count):
                    data[i].path=r'\Device\HarddiskVolume3\file'+str(len(calls))+str(i)+'.txt'
                    data[i].op=67;data[i].pid=100;data[i].bytes=1
            for i in range(4):stats[i]=0
            return count
        def aux(data,size):data[0]=0;data[1]=0;return 0
        trace.api=SimpleNamespace(gd_trace_poll=poll,gd_trace_aux_stats=aux)
        first=trace.poll();self.assertEqual(len(first),2);self.assertEqual(trace.poll(),[])
        third=trace.poll();self.assertEqual(len(third),1)
        self.assertEqual(first[0]['path'],r'C:\file10.txt');self.assertEqual(third[0]['path'],r'C:\file30.txt')
        self.assertEqual(len(set(calls)),1)
        with self.assertRaises(OSError):trace.poll()

    @unittest.skipUnless(os.name=='nt','actual Windows thread priority')
    def test_companion_really_runs_below_normal_without_changing_caller(self):
        from ctypes import wintypes as w
        api=ctypes.WinDLL('kernel32');api.GetCurrentThread.restype=w.HANDLE
        api.GetThreadPriority.argtypes=[w.HANDLE];api.GetThreadPriority.restype=ctypes.c_int
        caller=api.GetThreadPriority(api.GetCurrentThread());priorities=[]
        worker=object.__new__(DocumentWorker)
        worker._run=lambda:priorities.append(api.GetThreadPriority(api.GetCurrentThread()))
        thread=threading.Thread(target=worker.run);thread.start();thread.join(5)
        self.assertFalse(thread.is_alive());self.assertTrue(priorities);self.assertLessEqual(priorities[0],-1)
        self.assertEqual(api.GetThreadPriority(api.GetCurrentThread()),caller)

    def test_slow_session_launch_does_not_make_fresh_frames_future_dated(self):
        clock=[1000.0];c=context.Context();channel=Mock()
        value={'session':1,'time':1002.0,'idle_ms':0,'input_tick':10,'foreground_pid':123,'desktop':True}
        channel.poll.return_value=[value]
        def launch(sid):clock[0]=1002.0;return channel
        states={1:{'active':True,'locked':False,'logon':10,'time':1000.0}}
        with patch('guarddesk.document_context.time.time',side_effect=lambda:clock[0]),patch('guarddesk.document_context.session_states',return_value=states),patch('guarddesk.document_context.launch',side_effect=launch):
            c.poll();self.assertEqual(c.errors,0);self.assertEqual(c.samples[1][-1],value)
        c.close();channel.close.assert_called_once()


if __name__=='__main__':unittest.main()
