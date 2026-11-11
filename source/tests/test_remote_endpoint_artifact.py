"""Profile inventory and shared helper extraction regression boundaries."""
import ast
import importlib.abc
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk import endpoint_package,remote_trial

ROOT=Path(__file__).resolve().parents[1]

class EndpointArtifactTest(unittest.TestCase):
    def test_endpoint_scope_does_not_advertise_center_or_updater(self):
        from tools.remote_endpoint_artifact import deployment_scope
        from guarddesk import __version__
        scope=deployment_scope(__version__)
        self.assertEqual(scope['components'],['native','main'])
        self.assertIsNone(scope['required_updater'])
        from guarddesk.release_scope import profile
        self.assertIn('server',profile(__version__)['components'])
        self.assertIn('updater',profile(__version__)['components'])

    def test_inventory_rejects_center_code_scripts_and_missing_broker(self):
        from tools.remote_endpoint_artifact import check_inventory
        modules={'guarddesk.remote_endpoint_entry','guarddesk.remote_trial','guarddesk.endpoint_files',
                 'guarddesk.remote_endpoint_state','guarddesk.endpoint_transport','guarddesk.windows_privilege',
                 'guarddesk.remote_service_worker','guarddesk.machine_agent',
                 'guarddesk.machine_agent_session','guarddesk.remote_native_broker'}
        check_inventory(modules,['GuardDesk.exe','GuardDeskAgent.exe'])
        with self.assertRaises(ValueError):check_inventory(modules|{'guarddesk.server'},[])
        with self.assertRaises(ValueError):check_inventory(modules-{'guarddesk.remote_native_broker'},[])
        for name in ('_internal/guarddesk/static/index.html','_internal/guarddesk/windows/controls.ps1',
                     '_internal/browser-extension/manifest.json','_internal/GuardDeskMIS.exe',
                     '_internal/remote/GuardDeskMisNative.dll','unexpected.PS1'):
            with self.subTest(name=name),self.assertRaises(ValueError):check_inventory(modules,[name])

    def test_standard_still_requires_control_scripts(self):
        with patch.object(remote_trial,'ENABLED',False):
            self.assertEqual(endpoint_package.required_files(),endpoint_package.REQUIRED)
            self.assertIn('_internal/guarddesk/windows/controls.ps1',endpoint_package.required_files())

    def test_compiled_trial_requires_native_cohort_instead_of_scripts(self):
        with patch.object(remote_trial,'ENABLED',True):
            files=endpoint_package.required_files()
        self.assertFalse(any(name.endswith('.ps1') for name in files))
        self.assertIn('_internal/remote/remote-cohort.json',files)
        self.assertIn('_internal/remote/GuardDeskRemoteWorker.exe',files)
        self.assertNotIn('_internal/remote/GuardDeskMisNative.dll',files)
        self.assertIn('_internal/agent-release.json',files)

    def test_shared_helpers_are_compatibility_exports(self):
        from guarddesk import endpoint_files,server_setup
        self.assertIs(server_setup.read_connection,endpoint_files.read_connection)
        self.assertIs(server_setup.secure_directory,endpoint_files.secure_directory)

    def test_fresh_endpoint_import_without_center_modules(self):
        code='''
import importlib.abc,sys
class Refuse(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname in {'guarddesk.__main__','guarddesk.server','guarddesk.server_setup','guarddesk.server_config','guarddesk.server_backup'}:raise AssertionError(fullname)
sys.meta_path.insert(0,Refuse())
from guarddesk import endpoint_setup,remote_endpoint_entry,remote_trial,machine_agent_session
remote_trial.ENABLED=True
remote_endpoint_entry.main(['component-info'])
'''
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=ROOT,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['build_role'],'remote-endpoint')
