from guarddesk import remote_installer_entry
"""Exercise real entry dispatch with imports trapped before any OS side effect."""
import importlib.abc
import io
import json
import contextlib
import runpy
import sys
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock,patch
from guarddesk import remote_trial,remote_endpoint_entry


class RefuseImport(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname in ('guarddesk.browser_host','guarddesk.document_context','guarddesk.__main__'):
            raise AssertionError('Forbidden role imported: '+fullname)


class RemoteEndpointEntryTest(unittest.TestCase):
    def test_non_trial_build_refused_before_cli(self):
        with patch.object(remote_trial,'ENABLED',False),self.assertRaises(PermissionError):
            remote_endpoint_entry.main(['component-info'])

    def test_endpoint_denies_center_viewer_collectors_and_implicit_browser_roles(self):
        with patch.object(remote_trial,'ENABLED',True):
            for command in ('serve','add-user','server-setup','remote-viewer','agent','browser-host',
                            'document-session-context','chrome-extension://owned','update-service','--help'):
                with self.subTest(command=command),self.assertRaises(PermissionError):
                    remote_endpoint_entry.main([command])

    def test_component_info_needs_no_shared_cli_or_os_dispatch(self):
        finder=RefuseImport();sys.meta_path.insert(0,finder)
        self.addCleanup(sys.meta_path.remove,finder)
        cli=ModuleType('guarddesk.__main__');cli.main=Mock(side_effect=AssertionError('shared CLI'))
        output=io.StringIO();before=sys.argv
        with patch.object(remote_trial,'ENABLED',True),patch.dict(sys.modules,{'guarddesk.__main__':cli}),contextlib.redirect_stdout(output):
            remote_endpoint_entry.main(['component-info'])
        self.assertEqual(json.loads(output.getvalue())['build_role'],'remote-endpoint')
        self.assertIs(sys.argv,before);cli.main.assert_not_called()

    def test_installer_legacy_extended_flag_only_calls_remote_worker(self):
        with patch.object(remote_trial,'ENABLED',True),patch.object(remote_trial,'worker',return_value={'status':'owned'}) as worker,patch('signal.signal'),contextlib.redirect_stdout(io.StringIO()):
            remote_endpoint_entry.main(['usb-worker','--extended','--config','owned.json','--once'])
        self.assertEqual(worker.call_args.args[0],'owned.json')
        self.assertEqual(worker.call_args.kwargs,{'once':True,'restore':False})

    def test_all_mutating_dispatch_uses_existing_fixed_role_functions(self):
        cases=[('endpoint-setup',['--connection','owned.json'],'guarddesk.endpoint_setup','install',('owned.json',)),
               ('endpoint-uninstall',[],'guarddesk.endpoint_setup','uninstall',()),
               ('usb-install',['--config','owned.json','--action','Status'],'guarddesk.usb_install','install',('owned.json','Status')),
               ('machine-session',['--parent','123'],'guarddesk.machine_agent_session','run',(123,)),
               ('remote-admin-session',['--device-id','owned','--session-id','fixed'],'guarddesk.remote_admin_windows','run',('owned','fixed'))]
        for command,args,module,name,expected in cases:
            fake=ModuleType(module);callback=Mock(return_value={});setattr(fake,name,callback)
            with self.subTest(command=command),patch.object(remote_trial,'ENABLED',True),patch.dict(sys.modules,{module:fake}),patch('signal.signal'),contextlib.redirect_stdout(io.StringIO()):
                (remote_installer_entry if command in remote_installer_entry.INSTALLER_COMMANDS else remote_endpoint_entry).main([command,*args])
                self.assertEqual(callback.call_args.args[:len(expected)],expected)
                self.assertEqual(callback.call_count,1)

    def test_native_helper_exit_is_preserved(self):
        fake=ModuleType('guarddesk.usb_install');fake.helper=Mock(return_value=17)
        with patch.object(remote_trial,'ENABLED',True),patch.dict(sys.modules,{'guarddesk.usb_install':fake}),patch('signal.signal'),self.assertRaises(SystemExit) as exc:
            remote_installer_entry.main(['endpoint-native-install','--config','owned','--action','Status','--diagnostic-pipe','fixed'])
        self.assertEqual(exc.exception.code,17);fake.helper.assert_called_once_with('owned','Status','fixed')

    def test_invalid_arguments_refused_before_role_import_or_signal(self):
        with patch.object(remote_trial,'ENABLED',True),patch('signal.signal') as signal,contextlib.redirect_stderr(io.StringIO()):
            for args in (['component-info','--config','unexpected'],['machine-session'],
                         ['machine-session','--parent','not-int'],['usb-install','--act','Install'],
                         ['endpoint-native-install','--lab01-remote-test']):
                with self.subTest(args=args),self.assertRaises(SystemExit) as exc:(remote_installer_entry if args[0] in remote_installer_entry.INSTALLER_COMMANDS else remote_endpoint_entry).main(args)
                self.assertEqual(exc.exception.code,2)
            signal.assert_not_called()

    def test_existing_trial_app_blocks_special_roles_before_import(self):
        # Remove cached targets so the fresh import trap detects any regression.
        names=('guarddesk.browser_host','guarddesk.document_context','guarddesk.__main__')
        saved={name:sys.modules.pop(name) for name in names if name in sys.modules}
        finder=RefuseImport();sys.meta_path.insert(0,finder)
        try:
            with patch.object(remote_trial,'ENABLED',True),patch.object(sys,'executable','GuardDesk.exe'):
                for command in ('chrome-extension://owned','document-session-context'):
                    with patch.object(sys,'argv',['GuardDesk.exe',command]),self.assertRaises(SystemExit) as result:
                        runpy.run_path(str(Path(__file__).resolve().parents[1]/'app.py'),run_name='__main__')
                    self.assertIn('unavailable in remote-only trial',str(result.exception))
        finally:
            sys.meta_path.remove(finder);sys.modules.update(saved)
