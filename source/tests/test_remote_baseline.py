import copy
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from tools.remote_baseline import digest, verify


class BaselineRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stable = self.root / 'runtime/stable'
        (self.stable / 'guarddesk').mkdir(parents=True)
        (self.root / 'dist').mkdir()
        self.file = self.stable / 'guarddesk/fixture.py'
        self.file.write_bytes(b'owned=True\n')
        self.manifest = {'baseline': 'runtime/stable', 'archive': 'dist/original.zip',
                         'archive_sha256': '0' * 64, 'files': {'guarddesk/fixture.py': digest(self.file)}}
        self.snapshot = self.root / 'runtime/revalidated-source.zip'
        with zipfile.ZipFile(self.snapshot, 'w') as archive:
            archive.write(self.file, 'guarddesk/fixture.py')
        self.history = self.root / 'runtime/prior-product.json'
        self.history.write_text(json.dumps({'passed': True, 'capacity': {
            'baseline_zip_bytes': 1234, 'baseline_archive_expanded_bytes': 5678}}))
        self.record = {'format': 1, 'kind': 'internal_trial_source_revalidation',
                       'original_archive_available': False, 'deployable': False,
                       'original_manifest': copy.deepcopy(self.manifest),
                       'snapshot': 'runtime/revalidated-source.zip', 'snapshot_sha256': digest(self.snapshot),
                       'prior_product_receipt': 'runtime/prior-product.json',
                       'prior_product_receipt_sha256': digest(self.history)}

    def declare(self):
        receipt = self.root / 'runtime/revalidation.json'
        receipt.write_text(json.dumps(self.record))
        self.manifest['source_revalidation'] = {'receipt': 'runtime/revalidation.json', 'sha256': digest(receipt)}

    def test_missing_archive_requires_explicit_revalidation(self):
        with self.assertRaises(FileNotFoundError): verify(self.manifest, self.root)

    def test_source_snapshot_and_history_have_explicit_limits(self):
        self.declare()
        before, evidence = verify(self.manifest, self.root)
        self.assertEqual(before['guarddesk/fixture.py'], self.file.read_bytes())
        self.assertFalse(evidence['archive_available'])
        self.assertFalse(evidence['deployable'])
        self.assertEqual(evidence['capacity_basis'], 'historical_product_receipt_not_remeasured')
        self.assertEqual(evidence['expanded_bytes'], 5678)

    def test_changed_live_baseline_is_rejected(self):
        self.declare(); self.file.write_bytes(b'changed=True')
        with self.assertRaises(ValueError): verify(self.manifest, self.root)

    def test_changed_snapshot_or_receipt_or_history_is_rejected(self):
        for target in ('snapshot', 'receipt', 'history'):
            with self.subTest(target=target):
                self.declare()
                path = {'snapshot': self.snapshot, 'receipt': self.root / 'runtime/revalidation.json', 'history': self.history}[target]
                original = path.read_bytes(); path.write_bytes(original + b'changed')
                try:
                    with self.assertRaises(ValueError): verify(self.manifest, self.root)
                finally: path.write_bytes(original)

    def test_changed_original_cannot_be_hidden_by_revalidation(self):
        self.declare(); (self.root / 'dist/original.zip').write_bytes(b'wrong original')
        with self.assertRaises(ValueError): verify(self.manifest, self.root)

    def test_inventory_and_path_escape_are_rejected(self):
        with zipfile.ZipFile(self.snapshot, 'a') as archive: archive.writestr('../extra', b'owned')
        self.record['snapshot_sha256'] = digest(self.snapshot)
        self.declare()
        with self.assertRaises(ValueError): verify(self.manifest, self.root)
        self.manifest['source_revalidation']['receipt'] = 'dist/outside.json'
        (self.root / 'dist/outside.json').write_text('{}')
        with self.assertRaises(ValueError): verify(self.manifest, self.root)

    def test_claimed_recovery_or_formal_release_is_rejected(self):
        for name in ('original_archive_available', 'deployable'):
            with self.subTest(name=name):
                self.record[name] = True; self.declare()
                with self.assertRaises(ValueError): verify(self.manifest, self.root)
                self.record[name] = False

    def test_present_valid_original_is_measured_normally(self):
        original = self.root / 'dist/original.zip'
        with zipfile.ZipFile(original, 'w') as archive: archive.writestr('fixture', b'12345')
        self.manifest['archive_sha256'] = digest(original)
        _, evidence = verify(self.manifest, self.root)
        self.assertTrue(evidence['archive_available'])
        self.assertEqual(evidence['expanded_bytes'], 5)


if __name__ == '__main__': unittest.main()
