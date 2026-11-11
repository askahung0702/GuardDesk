"""Recovery never executes or restores Agent bytes; exercise partial commits."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import unittest
import uuid
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('recovery',HERE/'tools/recover_lab01_interrupted_install.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


class Ops:
    def __init__(self,root):
        self.program=root/'Program';self.data=root/'Data';self.calls=0;self.busy_at=0
        self.program.mkdir();self.data.mkdir()
    def security(self,path,ancestor=False):
        if not path.exists():raise FileNotFoundError(str(path))
    def quiescent(self):
        self.calls+=1
        if self.calls==self.busy_at:raise OSError('BUSY_FIXTURE')
    def mkdir(self,path):path.mkdir()
    def write_new(self,path,raw):
        with path.open('xb') as stream:stream.write(raw)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        workspace=HERE.parents[1]
        self.fixture=workspace/'runtime'/('recovery-case-'+uuid.uuid4().hex)
        self.fixture.mkdir();self.ops=Ops(self.fixture)
        self.root=self.ops.data/'USBControl'/r.DEVICE;self.root.mkdir(parents=True)
        self.config=self.root/'config.json'
        self.settings={'install_profile':r.PROFILE,'device_id':r.DEVICE,'token':'OWNED_TEST_SECRET','server':'https://owned.invalid'}
        self.config.write_text(json.dumps(self.settings))
        self.journal=self.root/'install-transaction.json';self.original=json.dumps(r.JOURNAL,indent=2).encode();self.journal.write_bytes(self.original)
        self.current=self.ops.program/'USBControl';self.current.mkdir();(self.current/'kept.dll').write_bytes(b'INCOMPLETE-ORIGINAL-BYTES')
        self.backup=self.ops.program/('USBControl.install-backup-'+r.TRANSACTION);self.backup.mkdir();(self.backup/'GuardDesk.exe').write_bytes(b'NEVER-EXECUTE-BACKUP')
        self.archive=self.root/('install-recovery-'+r.TRANSACTION)
        self.destination=self.ops.program/('USBControl.install-interrupted-'+r.TRANSACTION)
        (self.root/'queue').write_bytes(b'KEEP-QUEUE')
        self.initial=self.snapshot()
    def snapshot(self):return {str(p.relative_to(self.fixture)):p.read_bytes() for p in self.fixture.rglob('*') if p.is_file()}
    def unchanged(self):self.assertEqual(self.snapshot(),self.initial)
    def run_recovery(self,apply=True):return r.prepare(self.ops,apply)
    def test_check_does_not_mutate(self):
        self.assertEqual(self.run_recovery(False)['result'],'CHECK_PASSED_NO_CHANGES');self.unchanged()
    def test_prepare_retains_exact_journal_identity_queue_backup_and_damaged_tree(self):
        result=self.run_recovery()
        self.assertEqual(result['result'],'RECOVERY_PREPARED_NOT_INSTALLED')
        self.assertFalse(result['installed']);self.assertFalse(self.journal.exists());self.assertFalse(self.current.exists())
        self.assertEqual((self.archive/'install-transaction.json').read_bytes(),self.original)
        self.assertEqual((self.destination/'kept.dll').read_bytes(),b'INCOMPLETE-ORIGINAL-BYTES')
        for p in (self.config,self.root/'queue',self.backup/'GuardDesk.exe'):
            self.assertEqual(p.read_bytes(),self.initial[str(p.relative_to(self.fixture))])
        self.assertNotIn('OWNED_TEST_SECRET',json.dumps(result))
        self.assertNotIn('OWNED_TEST_SECRET',(self.archive/'plan.json').read_text())
    def test_repeat_is_idempotent(self):
        self.run_recovery();before=self.snapshot();self.run_recovery();self.assertEqual(before,self.snapshot())
    def test_current_executable_present_refused(self):
        (self.current/'GuardDesk.exe').write_bytes(b'DO-NOT-TOUCH');before=self.snapshot()
        with self.assertRaisesRegex(OSError,'INSTALLED_EXE_PRESENT'):self.run_recovery()
        self.assertEqual(before,self.snapshot())
    def test_wrong_identity_profile_settings_refused(self):
        for edit in ({'device_id':'b'*24},{'install_profile':'standard'},{'proxy_enabled':True},{'browser_trust':{'enabled':True}}):
            self.config.write_text(json.dumps({**self.settings,**edit}));before=self.snapshot()
            with self.assertRaises(OSError):self.run_recovery()
            self.assertEqual(before,self.snapshot())
    def test_unknown_transaction_refused(self):
        for edit in ({'id':'a'*16},{'phase':'initial_policy'},{'phase':'complete'},{'version':'0.4.85'}):
            self.journal.write_text(json.dumps({**r.JOURNAL,**edit}));before=self.snapshot()
            with self.assertRaisesRegex(OSError,'TRANSACTION_MISMATCH'):self.run_recovery()
            self.assertEqual(before,self.snapshot())
    def test_control_ledgers_refused(self):
        p=self.root/'windows/usb-original.json';p.parent.mkdir();p.write_text('{}');before=self.snapshot()
        with self.assertRaisesRegex(OSError,'CONTROL_RESTORE_REQUIRED'):self.run_recovery()
        self.assertEqual(before,self.snapshot())
    def test_updates_refused(self):
        p=self.root/'updates/transaction-native.json';p.parent.mkdir();p.write_text('{"phase":"starting"}');before=self.snapshot()
        with self.assertRaisesRegex(OSError,'UPDATE_TRANSACTION_PRESENT'):self.run_recovery()
        self.assertEqual(before,self.snapshot())
    def test_acl_failure_before_any_change(self):
        with patch.object(self.ops,'security',side_effect=PermissionError('fixture denied')):
            with self.assertRaises(PermissionError):self.run_recovery()
        self.unchanged()
    def test_busy_before_or_after_plan_never_moves_program(self):
        for step in (1,2):
            self.ops.calls=0;self.ops.busy_at=step
            with self.assertRaisesRegex(OSError,'BUSY'):self.run_recovery()
            self.assertTrue(self.current.exists());self.assertEqual(self.journal.read_bytes(),self.original)
    def test_busy_after_program_move_can_resume(self):
        self.ops.busy_at=3
        with self.assertRaisesRegex(OSError,'BUSY'):self.run_recovery()
        self.assertTrue(self.destination.exists());self.assertEqual(self.journal.read_bytes(),self.original)
        self.ops.busy_at=0;self.assertEqual(self.run_recovery()['result'],'RECOVERY_PREPARED_NOT_INSTALLED')
    def test_crash_before_or_after_each_rename_can_resume(self):
        original=os.rename
        def fail_after_move(source,dest):
            original(source,dest);raise OSError('simulated process crash')
        with patch.object(r.os,'rename',side_effect=fail_after_move):
            with self.assertRaisesRegex(OSError,'simulated'):self.run_recovery()
        self.assertTrue(self.destination.exists());self.assertTrue(self.journal.exists())
        with patch.object(r.os,'rename',side_effect=fail_after_move):
            with self.assertRaisesRegex(OSError,'simulated'):self.run_recovery()
        self.assertFalse(self.journal.exists());self.assertTrue((self.archive/'install-transaction.json').exists())
        self.assertEqual(self.run_recovery()['result'],'RECOVERY_PREPARED_NOT_INSTALLED')
    def test_foreign_archive_not_overwritten(self):
        self.destination.mkdir();(self.destination/'other').write_bytes(b'KEEP');before=self.snapshot()
        with self.assertRaises(OSError):self.run_recovery()
        self.assertEqual(before,self.snapshot())
    def test_config_change_after_plan_refused(self):
        original=self.ops.quiescent
        def mutate():
            original()
            if self.ops.calls==2:self.config.write_text(json.dumps({**self.settings,'token':'CHANGED'}))
        with patch.object(self.ops,'quiescent',side_effect=mutate):
            with self.assertRaisesRegex(OSError,'CONFIG_CHANGED'):self.run_recovery()
        self.assertTrue(self.current.exists());self.assertTrue(self.journal.exists())
    def test_hardlink_refused(self):
        os.link(self.config,self.root/'other-config-link')
        with self.assertRaisesRegex(OSError,'HARDLINK_REJECTED'):self.run_recovery()
    def test_real_windows_missing_path_and_untrusted_fixture_acl(self):
        with self.assertRaises(OSError):r.protected(self.fixture/'missing')
        with self.assertRaises(OSError):r.protected(self.current)
    def test_real_mutex_conflict(self):
        key='owned-fixture-'+uuid.uuid4().hex
        with r.mutex('recovery-test',key):
            with self.assertRaisesRegex(OSError,'MUTEX_BUSY'):
                with r.mutex('recovery-test',key):self.fail('must reject duplicate')
    def test_real_private_security_descriptor_shape(self):
        with r.private_attributes(True) as attributes:
            self.assertTrue(attributes.descriptor);self.assertFalse(attributes.inherit)
    def test_access_denied_is_never_missing(self):
        with patch.object(r,'plain',side_effect=PermissionError('fixture access denied')):
            with self.assertRaises(PermissionError):r.present(self.current/'GuardDesk.exe')
    def test_missing_plan_after_interruption_preserves_state(self):
        self.archive.mkdir();before=self.snapshot()
        with self.assertRaisesRegex(OSError,'RECOVERY_PLAN_MISMATCH'):self.run_recovery()
        self.assertEqual(before,self.snapshot())
    def test_unsafe_known_folder_parent_is_rejected_before_changes(self):
        original=self.ops.security
        def check(path,ancestor=False):
            if ancestor:raise OSError('UNTRUSTED_PARENT_FIXTURE')
            original(path)
        with patch.object(self.ops,'security',side_effect=check):
            with self.assertRaisesRegex(OSError,'UNTRUSTED_PARENT'):self.run_recovery()
        self.unchanged()
    def test_acl_refusal_exposes_fixed_path_and_ace_but_not_config_contents(self):
        error=r.PermissionReviewError('UNTRUSTED_WRITE',self.config,False,
                                      mask='0x001f01ff',trustee='S-1-5-21-1-2-3-1000')
        self.assertEqual(str(error),'UNTRUSTED_WRITE')
        self.assertEqual(error.permission_review['path'],str(self.config))
        self.assertNotIn('OWNED_TEST_SECRET',json.dumps(error.permission_review))
    def test_real_acl_rejection_contains_path(self):
        with self.assertRaises(r.PermissionReviewError) as caught:r.protected(self.current)
        self.assertEqual(caught.exception.permission_review['path'],str(self.current))


if __name__=='__main__':unittest.main()
