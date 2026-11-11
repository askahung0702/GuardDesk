import importlib.util
import json
from pathlib import Path
from unittest.mock import patch
from tests import test_interrupted_trial_recovery as shared

path=Path(__file__).resolve().parents[1]/'tools/recover_lab01_087_trial.py'
spec=importlib.util.spec_from_file_location('recovery087',path)
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class Recovery087Tests(shared.RecoveryTests):
    def setUp(self):
        self.recovery_patch=patch.object(shared,'r',r)
        self.recovery_patch.start();self.addCleanup(self.recovery_patch.stop)
        super().setUp()
        # Reproduce actual LAB01: no current-transaction backup after prior archive.
        self.backup.rename(self.ops.program/('USBControl.install-backup-'+r.PREVIOUS_TRANSACTION))
        self.backup=self.ops.program/('USBControl.install-backup-'+r.PREVIOUS_TRANSACTION)
        self.previous=self.ops.program/('USBControl.install-interrupted-'+r.PREVIOUS_TRANSACTION)
        self.previous.mkdir();(self.previous/'preserved.dll').write_bytes(b'KEEP-OLD-ARCHIVE')
        self.previous_state=self.root/('install-recovery-'+r.PREVIOUS_TRANSACTION)
        self.previous_state.mkdir()
        (self.previous_state/'install-transaction.json').write_text(json.dumps({**r.JOURNAL,'id':r.PREVIOUS_TRANSACTION}))
        self.settings['server']=r.SERVER
        self.config.write_text(json.dumps(self.settings))
        self.initial=self.snapshot()

    def test_previous_transaction_mismatch_preserves_everything(self):
        p=self.previous_state/'install-transaction.json';p.write_text('{}');before=self.snapshot()
        with self.assertRaisesRegex(OSError,'PREVIOUS_TRANSACTION_MISMATCH'):self.run_recovery()
        self.assertEqual(before,self.snapshot())

    def test_previous_archive_missing_is_not_new_install(self):
        self.previous.rename(self.previous.with_name('unrecognized-archive'));before=self.snapshot()
        with self.assertRaises(FileNotFoundError):self.run_recovery()
        self.assertEqual(before,self.snapshot())

    def test_server_mismatch_does_not_retarget(self):
        self.config.write_text(json.dumps({**self.settings,'server':'https://other.invalid'}));before=self.snapshot()
        with self.assertRaisesRegex(OSError,'TRIAL_SERVER_MISMATCH'):self.run_recovery()
        self.assertEqual(before,self.snapshot())

    def test_old_tool_rejects_new_journal(self):
        oldspec=importlib.util.spec_from_file_location('old',path.with_name('recover_lab01_interrupted_install.py'))
        old=importlib.util.module_from_spec(oldspec);oldspec.loader.exec_module(old)
        with self.assertRaisesRegex(OSError,'TRANSACTION_MISMATCH'):old.prepare(self.ops,True)
        self.unchanged()

    def test_archived_previous_bytes_untouched(self):
        self.run_recovery()
        for name,data in self.initial.items():
            if r.PREVIOUS_TRANSACTION in name:self.assertEqual((self.fixture/name).read_bytes(),data)
