"""Owned consent-loop regressions: no MessageBox, network, capture or OS input."""
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from guarddesk.remote_windows import RemoteAgent

REQUEST = dict(id='a'*32, status='requested', operator='owned', reason='',
               mode='control', admin_control=True, transport='native_webrtc')


class LoopStop(threading.Event):
    def __init__(self):
        super().__init__();self.rounds=0
    def wait(self,timeout=None):
        self.rounds+=1
        if self.rounds>=4:self.set()
        return self.is_set()


class ConsentOnceTest(unittest.TestCase):
    def worker(self,approved=True,update_error=True,withdrawn=False):
        calls=[];polls=0
        def call(path,body,**kwargs):
            nonlocal polls
            calls.append((path,dict(body)))
            if path.endswith('/poll'):
                polls+=1
                return {'session':None if withdrawn and polls>1 else dict(REQUEST)}
            if body.get('action') in ('approve','deny'):
                if update_error:raise ConnectionError('owned unavailable transport')
                return {'status':'closed'}
            return {'status':'closed'}
        worker=RemoteAgent(SimpleNamespace(call=call),LoopStop())
        worker.consent=Mock(return_value=approved)
        worker.assist=Mock();worker.admin_watch=Mock()
        return worker,calls

    def run_owned(self,worker):
        with patch('guarddesk.identity.current_account',return_value='OWNED\\user'), \
             patch('guarddesk.windows_privilege.is_admin',return_value=False), \
             patch('guarddesk.remote_windows.interactive_desktop',return_value=True), \
             patch('guarddesk.remote_windows.ctypes.windll',SimpleNamespace(user32=Mock())):
            worker.run()

    def test_approve_rpc_failure_never_reopens_same_consent(self):
        worker,calls=self.worker();self.run_owned(worker)
        self.assertEqual(worker.consent.call_count,1)
        self.assertEqual(sum(b.get('action')=='approve' for _,b in calls),1)
        worker.assist.assert_not_called();worker.admin_watch.assert_not_called()

    def test_deny_rpc_failure_never_reopens_same_consent(self):
        worker,calls=self.worker(approved=False);self.run_owned(worker)
        self.assertEqual(worker.consent.call_count,1)
        self.assertEqual(sum(b.get('action')=='deny' for _,b in calls),1)
        worker.assist.assert_not_called();worker.admin_watch.assert_not_called()

    def test_inactive_ack_does_not_reopen_or_start_capture(self):
        worker,calls=self.worker(update_error=False);self.run_owned(worker)
        self.assertEqual(worker.consent.call_count,1)
        worker.assist.assert_not_called();worker.admin_watch.assert_not_called()

    def test_withdrawn_during_dialog_is_not_approved(self):
        worker,calls=self.worker(update_error=False,withdrawn=True);self.run_owned(worker)
        self.assertFalse(any(b.get('action')=='approve' for _,b in calls))
        worker.assist.assert_not_called();worker.admin_watch.assert_not_called()

    def test_active_ack_starts_native_watch_once(self):
        worker,calls=self.worker(update_error=False)
        def transport(path,body,**kwargs):
            calls.append((path,dict(body)))
            return {'session':dict(REQUEST)} if path.endswith('/poll') else {'status':'active'}
        worker.agent.call=transport;self.run_owned(worker)
        worker.consent.assert_called_once();worker.admin_watch.assert_called_once_with(REQUEST)
        worker.assist.assert_not_called()

    def test_failed_reply_has_fixed_metadata_and_bounded_stop(self):
        worker,calls=self.worker();self.run_owned(worker)
        self.assertEqual(worker.consent_error,{'stage':'approve','error_type':'ConnectionError','winerror':None})
        self.assertEqual(sum(b.get('action')=='stop' for _,b in calls),1)

    def test_new_request_can_prompt_after_previous_failure(self):
        worker,calls=self.worker()
        with patch('guarddesk.remote_windows.interactive_desktop',return_value=True):
            worker.handle_request(REQUEST,'OWNED\\user')
            worker.handle_request({**REQUEST,'id':'b'*32},'OWNED\\user')
        self.assertEqual(worker.consent.call_count,2)

    def test_consent_history_is_bounded_and_expired_entries_are_pruned(self):
        worker,calls=self.worker();worker.consent_attempts={str(i):float('inf') for i in range(128)}
        worker.handle_request(REQUEST,'OWNED\\user');worker.consent.assert_not_called()
        self.assertEqual(len(worker.consent_attempts),128)
        worker.consent_attempts={str(i):0 for i in range(128)}
        with patch('guarddesk.remote_windows.interactive_desktop',return_value=True):worker.handle_request(REQUEST,'OWNED\\user')
        worker.consent.assert_called_once();self.assertEqual(len(worker.consent_attempts),1)

    def test_mode_change_after_dialog_cannot_receive_consent(self):
        worker,calls=self.worker(update_error=False)
        worker.agent.call=lambda path,body,**kwargs:{'session':{**REQUEST,'admin_control':False}}
        with patch('guarddesk.remote_windows.interactive_desktop',return_value=True):worker.handle_request(REQUEST,'OWNED\\user')
        self.assertEqual(worker.consent_error['error_type'],'RequestChanged')
        worker.assist.assert_not_called();worker.admin_watch.assert_not_called()


if __name__=='__main__':unittest.main()
