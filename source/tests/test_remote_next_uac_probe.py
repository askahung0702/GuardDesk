"""Owned RunAs harness boundary tests; no UAC, credentials or physical input."""
import ctypes
import json
import tempfile
from pathlib import Path
import unittest
from contextlib import ExitStack
from unittest.mock import Mock,patch
from tools import remote_next_uac_probe as probe
from tools.uac_prompt_identity import guard_proof,Variant

class RunAsGateTests(unittest.TestCase):
    def setUp(self):
        self.proof=dict(matched=True,hwnd=101,pid=22,created=123456,session=2,checked_at=100.)
        self.expected=dict(hwnd=101,pid=22,created=123456,session=2,now=101.)
    def test_fresh_same_window_and_lifetime_allowed(self):
        self.assertTrue(guard_proof(self.proof,**self.expected))
    def test_foreign_window_process_logon_and_reused_pid_rejected(self):
        for key in ('hwnd','pid','created','session'):
            with self.subTest(key=key):self.assertFalse(guard_proof(self.proof,**{**self.expected,key:999}))
    def test_stale_future_and_missing_match_rejected(self):
        for change in ({'matched':False},{'checked_at':90},{'checked_at':102},{'checked_at':'100'},{'checked_at':float('nan')}):
            with self.subTest(change=change):self.assertFalse(guard_proof({**self.proof,**change},**self.expected))
    def test_variant_matches_windows_x64_abi(self):
        self.assertEqual(ctypes.sizeof(Variant),24 if ctypes.sizeof(ctypes.c_void_p)==8 else 16)
    def test_requester_must_be_unelevated(self):
        with patch('guarddesk.windows_controls.is_admin',return_value=True),patch.object(probe.ctypes,'WinDLL') as shell:
            with self.assertRaises(PermissionError):probe.prompt(Path('unused'))
            shell.assert_not_called()
    def test_requester_waits_for_ready_in_same_session(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'ready.json').write_text(json.dumps(dict(ready=True,session=3)))
            with patch('guarddesk.windows_controls.is_admin',return_value=False),patch.object(probe,'active_session_check',return_value=2),patch.object(probe.ctypes,'WinDLL') as shell:
                with self.assertRaises(PermissionError):probe.prompt(root)
                shell.assert_not_called()
    def test_true_runas_cancel_is_required_not_process_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'ready.json').write_text(json.dumps(dict(ready=True,session=2)))
            api=Mock();api.ShellExecuteW.return_value=5
            with patch('guarddesk.windows_controls.is_admin',return_value=False),patch.object(probe,'active_session_check',return_value=2),patch('guarddesk.update_native.protected_tree'),patch.object(probe.ctypes,'WinDLL',return_value=api),patch.object(probe.ctypes,'get_last_error',return_value=1223),patch('builtins.print') as output:
                probe.prompt(root)
                self.assertEqual(api.ShellExecuteW.call_args.args[1],'runas')
                self.assertEqual(api.ShellExecuteW.call_args.args[3],'--elevation-target')
                self.assertTrue(json.loads(output.call_args.args[0])['cancelled'])
    def test_accidental_approval_target_has_no_privileged_work(self):
        with patch.object(probe.sys,'argv',['owned.exe','--elevation-target']),patch.object(probe,'setup') as setup,patch.object(probe,'worker') as worker,patch('builtins.print'):
            self.assertEqual(probe.main(),0);setup.assert_not_called();worker.assert_not_called()

class WorkerBoundaryTests(unittest.TestCase):
    def run_owned(self,matched=True,changed=False,timeout=False):
        with tempfile.TemporaryDirectory() as temp,ExitStack() as stack:
            root=Path(temp);(root/'launch.json').write_text(json.dumps(dict(session=2,logon=10,parent=5,expires=9999999999,started=0)))
            desktop=Mock();desktop.name='default';desktop.api.OpenDesktopW.return_value=0
            sequence=iter(('default','winlogon','default'))
            def select():desktop.name=next(sequence)
            desktop.select.side_effect=select
            api=Mock();api.OpenProcess.return_value=123
            current=dict(hwnd=101,pid=22,created=123,session=2)
            proof=dict(**current,matched=matched,checked_at=probe.time.time())
            output=Mock(returncode=0,stdout=json.dumps(proof).encode())
            records={};sent=[]
            class OwnedInput:
                def __init__(self,guard,**kwargs):self.guard=guard
                def send(self,action):self.guard();sent.append(action)
                def release(self):pass
            def capture(*args,**kwargs):kwargs['_desktop_guard']();return 8,8,8,bytes(range(64))
            stack.enter_context(patch('guarddesk.remote_admin_windows.identity',return_value=(api,(1,1,2))))
            stack.enter_context(patch('guarddesk.remote_admin_windows.Desktop',return_value=desktop))
            stack.enter_context(patch('guarddesk.remote_windows.Input',OwnedInput))
            capture_mock=stack.enter_context(patch('guarddesk.remote_windows.capture_bgr',side_effect=capture))
            stack.enter_context(patch.object(probe,'own_ui_context',return_value={}))
            stack.enter_context(patch.object(probe,'foreground_identity',return_value={**current,'pid':99} if changed else current))
            run=stack.enter_context(patch.object(probe.subprocess,'run',return_value=output))
            if timeout:run.side_effect=probe.subprocess.TimeoutExpired('owned-identity',5)
            stack.enter_context(patch.object(probe.time,'sleep'))
            stack.enter_context(patch.object(probe,'record',side_effect=lambda root,name,value:records.update({name:dict(value)})))
            stack.enter_context(patch('guarddesk.context_permissions.grant_read_execute'))
            if changed:
                with self.assertRaises(PermissionError):probe.worker(root)
            else:probe.worker(root)
            return records['result'],sent,capture_mock.call_count
    def test_matched_prompt_capture_escape_and_return(self):
        result,sent,captures=self.run_owned()
        self.assertTrue(result['passed']);self.assertEqual(captures,1)
        self.assertEqual(sent,[dict(type='key',key=27,down=True),dict(type='key',key=27,down=False)])
    def test_foreign_prompt_never_captured_or_cancelled(self):
        result,sent,captures=self.run_owned(matched=False)
        self.assertFalse(result['passed']);self.assertFalse(sent);self.assertEqual(captures,0)
    def test_identity_timeout_never_captured_or_cancelled(self):
        result,sent,captures=self.run_owned(timeout=True)
        self.assertTrue(result['identity_timeout_or_invalid']);self.assertFalse(sent);self.assertEqual(captures,0)
    def test_foreground_race_rejected_before_capture(self):
        result,sent,captures=self.run_owned(changed=True)
        self.assertFalse(result['passed']);self.assertFalse(sent);self.assertEqual(captures,0)

if __name__=='__main__':unittest.main()
