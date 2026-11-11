"""Owned Router/launcher fixtures only; no center, IPC, desktop or OS input."""
import unittest
import threading
import struct
from types import SimpleNamespace
from unittest.mock import patch,Mock
from guarddesk.transport_errors import network_error
import test_remote_native_broker as fixtures
from guarddesk.remote_windows import RemoteAgent


class NativeObserverTest(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.NativeRouterTest()
        self.router=self.fixture.make()
        self.fixture.poll(self.router)
        self.fixture.request(self.router,'update',{'session_id':fixtures.SID,'action':'approve'})

    def watch(self):
        return self.fixture.request(self.router,'update',{'session_id':fixtures.SID,'action':'admin_watch'})

    def test_indicator_watch_does_not_make_second_center_heartbeat(self):
        before=len(self.fixture.calls)
        for _ in range(100):self.assertEqual(self.watch()['status'],'active')
        self.assertEqual(len(self.fixture.calls),before)

    def test_center_timeout_in_observer_cannot_revoke_live_native_job(self):
        with patch.object(self.router,'_remote_call',side_effect=network_error(TimeoutError())):
            self.assertEqual(self.watch()['status'],'active')
        self.assertNotIn(fixtures.SID,self.fixture.launcher.revoked)

    def test_native_job_end_still_closes_observer(self):
        self.fixture.launcher.revoke(fixtures.SID)
        self.assertEqual(self.watch()['status'],'closed')

    def test_local_stop_revokes_before_unavailable_center(self):
        with patch.object(self.router,'_remote_call',side_effect=network_error(TimeoutError())):
            with self.assertRaises(OSError):
                self.fixture.request(self.router,'update',{'session_id':fixtures.SID,'action':'stop'})
        self.assertIn(fixtures.SID,self.fixture.launcher.revoked)
        with self.assertRaises(PermissionError):self.watch()

    def test_locked_or_changed_logon_cannot_observe_old_active_session(self):
        self.fixture.states[6]['locked']=True
        self.assertEqual(self.watch()['status'],'closed')
        self.assertIn(fixtures.SID,self.fixture.launcher.revoked)

    def test_local_observation_cannot_keep_expired_native_authority_alive(self):
        library=fixtures.Library();job=fixtures.NativeBrokerTest().job(library)
        job.reserve();job.apply(1000,fixtures.reply());job.phase='native_transport'
        launcher=fixtures.Launcher(SimpleNamespace(),library=library)
        launcher.entries[fixtures.SID]=job;self.router.native_launcher=launcher
        before=job.deadline
        for _ in range(10):
            self.assertEqual(self.watch()['native_lifecycle']['lease_remaining_ms'],5000)
        self.assertEqual(job.deadline,before)
        library.now=before
        job.run() # Actual coordinator expiry path, fake native/HTTP only.
        self.assertTrue(job.done.is_set())
        self.assertEqual(job.error['diagnostic'],'native_short_lease_expired')
        self.assertEqual(self.watch()['status'],'closed')


class IndicatorGenerationTest(unittest.TestCase):
    def test_delayed_old_dialog_exit_cannot_stop_new_session(self):
        worker=RemoteAgent(SimpleNamespace(),threading.Event())
        targets=[]
        class Thread:
            def __init__(self,*,target,daemon):targets.append(target)
            def start(self):pass
        old=worker.local_stop
        with patch('guarddesk.remote_windows.threading.Thread',Thread), \
             patch('guarddesk.remote_windows.ctypes.windll',SimpleNamespace(user32=SimpleNamespace(MessageBoxW=lambda *args:1)),create=True):
            worker.show_indicator(fixtures.REQUEST)
            worker.local_stop=threading.Event()
            targets[0]() # old MessageBox finishes after the replacement starts
        self.assertTrue(old.is_set())
        self.assertFalse(worker.local_stop.is_set())

    def test_delayed_legacy_input_thread_cleanup_is_bound_to_original_session(self):
        worker=RemoteAgent(SimpleNamespace(),threading.Event())
        worker.show_indicator=Mock();worker.close_indicator=Mock()
        worker.call=Mock(return_value={'status':'closed'})
        targets=[];inputs=SimpleNamespace(send=Mock(),release=Mock())
        class Flag:
            def __init__(self):self.flag=False
            def set(self):self.flag=True
            def is_set(self):return self.flag
            def wait(self,*args):return self.flag # controlled delayed thread
        class Thread:
            def __init__(self,*,target,name,daemon):targets.append(target)
            def start(self):pass
        with patch('guarddesk.remote_windows.threading.Thread',Thread), \
             patch('guarddesk.remote_windows.threading.Event',Flag), \
             patch('guarddesk.remote_windows.Input',return_value=inputs), \
             patch('guarddesk.remote_windows.jpeg_frame',return_value={'jpeg':'owned'}):
            worker.assist({**fixtures.REQUEST,'transport':'legacy_images','viewer':'desktop'})
        old=worker.local_stop;worker.local_stop=threading.Event()
        targets[0]() # finally from the old input thread runs after replacement
        self.assertTrue(old.is_set());self.assertFalse(worker.local_stop.is_set())
        inputs.send.assert_not_called()


class NativeLifecycleTest(unittest.TestCase):
    def test_observed_phase_is_not_authority_and_stale_media_not_streaming(self):
        library=fixtures.Library();job=fixtures.NativeBrokerTest().job(library)
        self.assertEqual(job.lifecycle_snapshot(),{'state':'starting','lease_remaining_ms':0,'transient_retries':0})
        self.assertFalse(job.granted);self.assertEqual(library.commands,[])
        job.phase='native_transport'
        self.assertEqual(job.lifecycle_snapshot()['state'],'negotiating')
        job.reserve();job.apply(1000,fixtures.reply())
        packet=fixtures.media_packet(6,fixtures.SID,1,struct.pack('<IIII',1,3,2,1))
        job.receive(packet)
        self.assertEqual(job.lifecycle_snapshot()['state'],'streaming')
        before=job.deadline;library.now+=2100
        self.assertEqual(job.lifecycle_snapshot()['state'],'negotiating')
        self.assertEqual(job.deadline,before)
        job.recovering=True
        self.assertEqual(job.lifecycle_snapshot()['state'],'recovering')
        job.stop();self.assertEqual(job.lifecycle_snapshot()['state'],'stopping')
        job.done.set();self.assertEqual(job.lifecycle_snapshot()['state'],'ended')

    def test_teardown_error_cannot_overwrite_first_failure(self):
        job=fixtures.NativeBrokerTest().job()
        job.record_failure('native_signaling',network_error(TimeoutError('secret')))
        original=dict(job.error)
        late=threading.Thread(target=job.record_failure,args=('native_transport',OSError('secret teardown')))
        late.start();late.join(1)
        self.assertEqual(job.error,original)
        self.assertEqual(job.error['diagnostic'],'center_temporary_network')
        self.assertNotIn('secret',str(job.error))

    def test_center_diagnostic_filters_lifecycle_values_and_secrets(self):
        from guarddesk.remote_trial import native_diagnostics
        launcher=SimpleNamespace(snapshot=lambda:{'contexts':[{'lifecycle':{
            'state':'recovering','lease_remaining_ms':5001,'transient_retries':True,
            'credentials':'secret','pixels':'secret'}}]})
        value=native_diagnostics(launcher=launcher)['contexts'][0]['lifecycle']
        self.assertEqual(value,{'state':'recovering'})
        self.assertNotIn('secret',str(value))


if __name__=='__main__':unittest.main()
