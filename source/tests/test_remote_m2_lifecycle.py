"""Owned synthetic sessions and local unnamed events; no desktop/input/install."""
import ctypes
from ctypes import wintypes as w
from pathlib import Path
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from guarddesk.remote_admin_windows import Desktop, Launcher, DesktopTransition, uac_foreground
from guarddesk.remote_client import ViewerEngine
from test_remote_admin import AdminServerTest
import test_native_remote


class PresentedEpochTest(AdminServerTest):
    def test_late_frame_cannot_restore_a_retired_desktop_epoch(self):
        client,agent,did,session,nonce=self.prepare_admin()
        def frame(epoch,generation):
            return agent.call('/api/agent/remote/update',dict(session_id=session['id'],action='frame',
                admin_nonce=nonce,desktop_epoch=epoch,desktop_generation=generation,desktop='default',frame=test_native_remote.frame()))
        frame('a'*32,1);frame('b'*32,2)
        self.assertTrue(frame('a'*32,1)['resync'])
        self.assertEqual(client.call('/api/remote/session?id='+session['id'])['desktop_epoch'],'b'*32)
        self.endpoint(agent,session,nonce,'admin_pause',epoch='b'*32)
        self.assertTrue(frame('b'*32,2)['resync'])
        self.assertNotIn('frame',client.call('/api/remote/session?id='+session['id']))
        frame('c'*32,3)
        self.assertEqual(client.call('/api/remote/session?id='+session['id'])['desktop_epoch'],'c'*32)

    def test_no_control_before_render_ack_and_no_old_ack_after_transition(self):
        client,agent,did,session,nonce=self.prepare_admin()
        def frame(epoch):
            generation=self._desktop_generations.setdefault(epoch,len(self._desktop_generations)+1)
            agent.call('/api/agent/remote/update',dict(session_id=session['id'],action='frame',
                admin_nonce=nonce,desktop_epoch=epoch,desktop_generation=generation,desktop='default',frame=test_native_remote.frame()))
        def key(epoch):
            return client.call('/api/remote/input',dict(session_id=session['id'],desktop_epoch=epoch,
                actions=[dict(type='key',key=65,down=True)]))
        def ack(epoch,seq):
            return client.call('/api/remote/presented',dict(session_id=session['id'],desktop_epoch=epoch,frame_seq=seq))['accepted']
        frame('a'*32)
        self.assertEqual(key('a'*32)['accepted'],0)
        self.assertFalse(ack('a'*32,999))
        self.assertTrue(ack('a'*32,1));self.assertEqual(key('a'*32)['accepted'],1)
        frame('b'*32)
        self.assertFalse(ack('a'*32,1));self.assertFalse(ack('b'*32,1))
        self.assertEqual(key('b'*32)['accepted'],0)
        self.assertTrue(ack('b'*32,2));self.assertEqual(key('b'*32)['accepted'],1)
        self.assertEqual(len(self.endpoint(agent,session,nonce,'commands',epoch='b'*32)['commands']),1)


class LocalLeaseTest(unittest.TestCase):
    def test_interactive_child_does_not_inherit_background_task_priority(self):
        from contextlib import nullcontext
        from pathlib import Path
        from guarddesk.remote_admin_windows import spawn_system_session
        api=Mock();api.GetCurrentProcess.return_value=1;adv=Mock()
        def source(handle,access,out):out._obj.value=2;return True
        def token(source,access,attrs,level,kind,out):out._obj.value=3;return True
        def create(*args):args[-1]._obj.process=123;args[-1]._obj.thread=124;return True
        adv.OpenProcessToken.side_effect=source;adv.DuplicateTokenEx.side_effect=token
        adv.CreateProcessAsUserW.side_effect=create
        with patch('guarddesk.remote_admin_windows.identity',return_value=(api,None)),patch('guarddesk.remote_admin_windows.ctypes.WinDLL',return_value=adv),patch('guarddesk.remote_admin_windows.session_privilege',side_effect=lambda:nullcontext()):
            child=spawn_system_session(Path('C:/owned-fixture/GuardDesk.exe'),['remote-admin-session'],2)
        flags=adv.CreateProcessAsUserW.call_args.args[6]
        self.assertEqual(flags,0x08000020);child.close()

    def test_ticket_path_failure_releases_the_launch_reservation(self):
        from types import SimpleNamespace
        launcher=Launcher(SimpleNamespace(config={'device_id':'a'*24}))
        sid='b'*32;launcher.reserve(sid)
        with patch('guarddesk.machine_agent.eligible',return_value=True),patch('guarddesk.remote_admin_windows.identity',return_value=(None,(0,1))),patch('guarddesk.remote_admin_windows.ticket_path',side_effect=ValueError('owned invalid ticket path')):
            with self.assertRaises(ValueError):launcher.launch({'id':sid},{},{},{})
        self.assertEqual(launcher.children,{})

    def test_monotonic_lease_cannot_be_extended_by_wall_clock_rollback(self):
        desktop=object.__new__(Desktop)
        with patch('guarddesk.remote_admin_windows.time.monotonic',return_value=100):desktop.authorize()
        with patch('guarddesk.remote_admin_windows.time.monotonic',return_value=104.99):desktop.check_authorization()
        with patch('guarddesk.remote_admin_windows.time.monotonic',return_value=105),self.assertRaises(PermissionError):
            desktop.check_authorization()
        with patch('guarddesk.remote_admin_windows.time.monotonic',return_value=106),self.assertRaises(PermissionError):
            desktop.authorize(100)

    def test_held_key_state_from_previous_epoch_is_never_replayed_on_new_desktop(self):
        from guarddesk.remote_windows import Input
        epoch=['old'];inputs=Input(guard=lambda:True,epoch=lambda:epoch[0])
        inputs.keys={65};inputs.buttons={'left'};inputs.held_epoch='old'
        epoch[0]='new'
        with patch.object(inputs,'send') as send:inputs.release()
        send.assert_not_called();self.assertEqual(inputs.keys,set());self.assertEqual(inputs.buttons,set())

    def test_unrendered_network_epoch_never_enables_viewer_input(self):
        client=Mock();engine=ViewerEngine(client,dict(id='a'*32,status='active',mode='control',admin_control=True,desktop_epoch='b'*32))
        engine.fresh_until=time.monotonic()+5
        engine.latest=(dict(status='active',desktop_epoch='b'*32),None)
        engine.take()
        self.assertFalse(engine.send(dict(type='key',key=65,down=True)))
        engine.presented('b'*32,1);client.call.return_value={'accepted':True}
        with patch.object(engine.stop_event,'wait',side_effect=[False,True]):engine.send_inputs()
        self.assertEqual(engine.displayed_epoch,'b'*32)
        self.assertTrue(engine.send(dict(type='key',key=65,down=True)))

    def test_revocation_event_precedes_any_network_or_worker_shutdown_wait(self):
        launcher=Launcher(None);sid='a'*32;launcher.reserve(sid)
        event=launcher.kernel.CreateEventW(None,True,False,None)
        self.assertTrue(event)
        with launcher.lock:launcher.children[sid]['event']=event
        launcher.revoke(sid)
        kernel=ctypes.WinDLL('kernel32');kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD]
        self.assertEqual(kernel.WaitForSingleObject(event,0),0)
        launcher.stop(sid);self.assertEqual(launcher.children,{})

    def test_child_cancel_handle_observes_signal_but_cannot_reset_or_signal_event(self):
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.GetCurrentProcess.restype=w.HANDLE
        kernel.CreateEventW.argtypes=[w.LPVOID,w.BOOL,w.BOOL,w.LPCWSTR];kernel.CreateEventW.restype=w.HANDLE
        kernel.DuplicateHandle.argtypes=[w.HANDLE,w.HANDLE,w.HANDLE,ctypes.POINTER(w.HANDLE),w.DWORD,w.BOOL,w.DWORD]
        kernel.SetEvent.argtypes=kernel.ResetEvent.argtypes=[w.HANDLE]
        kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];kernel.CloseHandle.argtypes=[w.HANDLE]
        original=kernel.CreateEventW(None,True,False,None);readonly=w.HANDLE()
        self.assertTrue(original)
        try:
            process=kernel.GetCurrentProcess()
            self.assertTrue(kernel.DuplicateHandle(process,original,process,ctypes.byref(readonly),0x100000,False,0))
            self.assertFalse(kernel.SetEvent(readonly));self.assertEqual(ctypes.get_last_error(),5)
            self.assertTrue(kernel.SetEvent(original));self.assertEqual(kernel.WaitForSingleObject(readonly,0),0)
            self.assertFalse(kernel.ResetEvent(readonly));self.assertEqual(ctypes.get_last_error(),5)
        finally:
            if readonly:kernel.CloseHandle(readonly)
            kernel.CloseHandle(original)

    def test_cancelled_reservation_cannot_launch_even_if_approval_arrives_late(self):
        launcher=Launcher(None);sid='a'*32;launcher.reserve(sid);launcher.revoke(sid)
        agent=SimpleNamespace(config={'device_id':'b'*24})
        launcher.agent=agent
        with patch('guarddesk.machine_agent.eligible',return_value=True),patch('guarddesk.remote_admin_windows.identity',return_value=(Mock(),(1,2,0,'owned'))),self.assertRaises(PermissionError):
            launcher.launch(dict(id=sid),{}, {}, {})
        launcher.stop(sid)

    def test_secure_desktop_name_without_verified_uac_foreground_is_refused(self):
        # Synthetic API metadata only. Never inspect the operator's foreground.
        user=Mock();user.GetForegroundWindow.return_value=77
        def pid(hwnd,p):ctypes.cast(p,ctypes.POINTER(w.DWORD)).contents.value=99;return 1
        user.GetWindowThreadProcessId.side_effect=pid
        api=Mock();api.OpenProcess.return_value=88;api.WaitForSingleObject.return_value=258
        def directory(buffer,size):buffer.value='C:\\Windows\\System32';return len(buffer.value)
        api.GetSystemDirectoryW.side_effect=directory
        lease=dict(session=3,expires=1000)
        valid=(99,int((500+11644473600)*1e7),3,'C:\\Windows\\System32\\consent.exe')
        with patch('guarddesk.native_browser_identity._windows',return_value=api),patch('guarddesk.native_browser_identity._snapshot',return_value=valid),patch('guarddesk.native_browser_identity.protected_browser_image'),patch('guarddesk.native_browser_identity.signed_publisher',return_value='Microsoft Corporation'):
            proof=uac_foreground(user,lease,None);self.assertEqual(proof[0],99)
        for metadata in ((99,valid[1],4,valid[3]),(99,valid[1],3,'C:\\Users\\owned\\consent.exe'),(99,1,3,valid[3])):
            with patch('guarddesk.native_browser_identity._windows',return_value=api),patch('guarddesk.native_browser_identity._snapshot',return_value=metadata),self.assertRaises(DesktopTransition):
                uac_foreground(user,lease,None)


if __name__=='__main__':unittest.main()
