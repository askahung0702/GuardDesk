"""Trial installer boundaries, using existing synthetic transaction fixtures."""
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from guarddesk import remote_trial,remote_trial_install as scope,native_installer
import test_native_installer as fixtures


class TrialInstallTests(unittest.TestCase):
    def fixture(self):
        fixture=fixtures.NativeInstallerTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def trial_settings(self,fixture):
        fixture.settings['install_profile']=scope.PROFILE
        fixture.config.write_text(json.dumps(fixture.settings))

    def test_trial_installs_only_native_and_removes_its_task(self):
        f=self.fixture();self.trial_settings(f)
        with patch.object(remote_trial,'ENABLED',True):
            result=f.run_install()
            self.assertEqual(result['status'],'installer_completed')
            self.assertEqual(list(f.ops.tasks),['GuardDesk-USBControl-'+'a'*24])
            self.assertFalse((f.program/'Updater').exists())
            saved=json.loads(f.protected.read_text())
            self.assertTrue(saved['remote_native_preview'])
            self.assertEqual(saved['install_profile'],scope.PROFILE)
            self.assertEqual([e[1] for e in f.ops.events if e[0]=='health'],['native-health.json'])
            commands=[e[1][0] for e in f.ops.events if e[0]=='invoke']
            self.assertEqual(commands,['usb-worker'])
            self.assertEqual(f.run_install('Uninstall')['status'],'removed')
            self.assertEqual(f.ops.tasks,{})

    def test_standard_and_trial_cannot_adopt_each_other(self):
        for enabled,marker in ((True,None),(False,scope.PROFILE)):
            f=self.fixture()
            if marker:self.trial_settings(f)
            with patch.object(remote_trial,'ENABLED',enabled),self.assertRaises(ValueError):f.run_install()
            self.assertFalse(f.program.exists());self.assertEqual(f.ops.events,[])

    def test_existing_standard_program_preserved(self):
        f=self.fixture();f.old_install();self.trial_settings(f)
        before=f.protected.read_bytes()
        with patch.object(remote_trial,'ENABLED',True),self.assertRaises(OSError):f.run_install()
        self.assertEqual(before,f.protected.read_bytes());self.assertEqual(f.ops.events,[])

    def test_browser_or_proxy_refused_before_writes(self):
        for key in ('browser_deployment','browser_deployment_authorization','browser_trust','proxy_enabled'):
            with self.subTest(key=key),patch.object(remote_trial,'ENABLED',True):
                with self.assertRaises(ValueError):scope.check_settings({'install_profile':scope.PROFILE,key:True})

    def test_connection_browser_trust_rejected(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(remote_trial,'ENABLED',True):
            root=Path(temp);scope.check_connection({},root)
            with self.assertRaises(ValueError):scope.check_connection({'browser_deployment':{'enabled':True}},root)
            (root/'browser-trust.json').write_text('{}')
            with self.assertRaises(ValueError):scope.check_connection({},root)

    def test_default_trial_policy_disables_collection_and_controls(self):
        from guarddesk.policy_defaults import server_policy
        from guarddesk.policy import DEFAULT_POLICY
        before=json.dumps(DEFAULT_POLICY,sort_keys=True)
        with patch.object(remote_trial,'ENABLED',True):
            policy=server_policy()
            self.assertFalse(policy['file_audit']['enabled'])
            for key in ('browser_audit','application_audit','allow_export'):self.assertFalse(policy[key])
            self.assertFalse(policy['website_control']['enabled'])
            self.assertFalse(policy['application_control']['enabled'])
            self.assertEqual(policy['upload_rules'],[])
        self.assertEqual(json.dumps(DEFAULT_POLICY,sort_keys=True),before)
        self.assertTrue(server_policy()['file_audit']['enabled'])

    def test_trial_package_has_matching_uninstall_and_no_browser_instructions(self):
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w') as archive:scope.package_notes(archive,b'fixture setup')
        with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive:
            self.assertEqual(set(archive.namelist()),{'Setup-Endpoint.cmd','Repair-Remote-Test.cmd','Uninstall-Remote-Test.cmd','README-Remote-Test.txt'})
            self.assertIn(b'endpoint-uninstall',archive.read('Uninstall-Remote-Test.cmd'))
            self.assertNotIn(b'ExecutionPolicy',archive.read('Uninstall-Remote-Test.cmd'))
            repair=archive.read('Repair-Remote-Test.cmd')
            self.assertIn(b'usb-install --config',repair)
            self.assertIn(b'--action Install',repair)
            self.assertNotIn(b'endpoint-setup',repair)
            self.assertNotIn(b'endpoint-uninstall',repair)
            self.assertNotIn(b'ExecutionPolicy',repair)

    def test_existing_trial_repair_preserves_identity_and_only_native_task(self):
        f=self.fixture();self.trial_settings(f)
        with patch.object(remote_trial,'ENABLED',True):
            f.run_install();before=json.loads(f.protected.read_text())
            f.ops.events.clear();f.run_install()
            after=json.loads(f.protected.read_text())
        for key in ('device_id','server','token','update_key','install_profile'):
            self.assertEqual(before.get(key),after.get(key))
        self.assertEqual(list(f.ops.tasks),['GuardDesk-USBControl-'+'a'*24])
        self.assertFalse((f.program/'Updater').exists())

    def test_trial_server_never_imports_company_backup(self):
        from guarddesk.server_setup import create
        with patch.object(remote_trial,'ENABLED',True),self.assertRaises(ValueError):
            create('unused','192.168.1.1',source='company-backup.sqlite3')
