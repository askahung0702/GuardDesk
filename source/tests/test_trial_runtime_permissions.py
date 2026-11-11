"""Trial runtime must verify permissions; only the installer may add RX."""
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
from guarddesk import context_permissions as cp,remote_trial
import test_native_installer as fixtures
from guarddesk.source_permissions import WindowsSecurity

class TrialRuntimePermissionTest(unittest.TestCase):
    def test_actual_acl_verification_is_read_only_and_rejects_missing_public_grant(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);native=root/'USBControl';native.mkdir();(native/'GuardDesk.exe').write_bytes(b'owned data only')
            entries=[root,native,native/'GuardDesk.exe'];security=WindowsSecurity()
            for path in entries:cp.grant_read_execute(path)
            before=[security.descriptor(p) for p in entries]
            with patch('guarddesk.update_native.folder',return_value=root),patch('guarddesk.update_native.protected_tree'),patch.object(cp,'grant_read_execute',side_effect=AssertionError('startup mutation')):
                self.assertEqual(cp.verify_installed_runtime()['changed'],0)
            self.assertEqual(before,[security.descriptor(p) for p in entries])
            # A protected descriptor fixture with no public RX must fail, never repair.
            with patch('guarddesk.update_native.folder',return_value=root),patch('guarddesk.update_native.protected_tree'),patch.object(WindowsSecurity,'descriptor',return_value=('S-1-5-18',[])),patch.object(cp,'grant_read_execute') as grant:
                with self.assertRaises(PermissionError):cp.verify_installed_runtime()
                grant.assert_not_called()

    def test_true_untrusted_owner_stage_refused_before_grant(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);stage=root/'USBControl.install-stage-0123456789abcdef';stage.mkdir();(stage/'GuardDesk.exe').write_bytes(b'owned')
            with patch('guarddesk.update_native.folder',return_value=root),patch('guarddesk.windows_privilege.is_admin',return_value=True),patch.object(cp,'grant_read_execute') as grant:
                with self.assertRaises(OSError):cp.prepare_staged_runtime(stage)
                grant.assert_not_called()
    def test_trial_startup_never_repairs_permissions_and_cache_requires_success(self):
        with patch.object(remote_trial,'ENABLED',True),patch.object(cp,'_ready',False),patch.object(cp,'repair_installed_runtime') as repair,patch.object(cp,'verify_installed_runtime',side_effect=[PermissionError('missing RX'),{}]) as verify:
            with self.assertRaises(PermissionError):cp.ensure_installed_runtime()
            cp.ensure_installed_runtime();cp.ensure_installed_runtime()
            self.assertEqual(verify.call_count,2);repair.assert_not_called()

    def test_standard_old_updater_compatibility_still_repairs(self):
        with patch.object(remote_trial,'ENABLED',False),patch.object(cp,'_ready',False),patch.object(cp,'repair_installed_runtime') as repair,patch.object(cp,'verify_installed_runtime') as verify:
            cp.ensure_installed_runtime();repair.assert_called_once();verify.assert_not_called()

    def test_staged_public_permissions_cannot_target_data_or_installed_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for target in (root/'USBControl',root/'Updater.install-stage-0123456789abcdef',root/'USBControl.install-stage-nothex',root/'data/USBControl.install-stage-0123456789abcdef'):
                with patch('guarddesk.update_native.folder',return_value=root),patch('guarddesk.windows_privilege.is_admin',return_value=True),patch.object(cp,'grant_read_execute') as grant:
                    with self.assertRaises(ValueError):cp.prepare_staged_runtime(target)
                    grant.assert_not_called()

    def test_trial_installer_prepares_stage_before_stopping_or_switching(self):
        f=fixtures.NativeInstallerTest();f.setUp();self.addCleanup(f.doCleanups)
        f.settings['install_profile']=remote_trial.PROFILE;f.config.write_text(__import__('json').dumps(f.settings))
        seen=[]
        def public(stage):
            self.assertTrue((stage/'GuardDesk.exe').is_file());self.assertFalse((f.program/'USBControl').exists())
            self.assertFalse(any(e[0] in ('stop','start','register') for e in f.ops.events));seen.append(stage)
        f.ops.public_runtime=public
        with patch.object(remote_trial,'ENABLED',True):f.run_install()
        self.assertEqual(len(seen),1);self.assertTrue(seen[0].name.startswith('USBControl.install-stage-'))

    def test_stage_permission_failure_preserves_existing_bytes_and_queue(self):
        f=fixtures.NativeInstallerTest();f.setUp();self.addCleanup(f.doCleanups)
        f.settings['install_profile']=remote_trial.PROFILE;f.config.write_text(__import__('json').dumps(f.settings))
        f.ops.public_runtime=lambda stage:None
        with patch.object(remote_trial,'ENABLED',True):f.run_install()
        exe=f.program/'USBControl/GuardDesk.exe';before=exe.read_bytes();config=f.protected.read_bytes()
        queue=f.protected.parent/'owned-queue-fixture.bin';queue.write_bytes(b'pending fixture data')
        f.ops.events.clear()
        def fail(stage):raise PermissionError('owned stage permission failure')
        f.ops.public_runtime=fail
        with patch.object(remote_trial,'ENABLED',True),self.assertRaises(OSError):f.run_install()
        self.assertEqual(exe.read_bytes(),before);self.assertEqual(f.protected.read_bytes(),config)
        self.assertEqual(queue.read_bytes(),b'pending fixture data')
        self.assertFalse(any(e[0] in ('stop','start','register','delete') for e in f.ops.events))

if __name__=='__main__':unittest.main()
