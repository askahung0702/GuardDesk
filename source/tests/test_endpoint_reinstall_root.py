"""Real filesystem reinstall boundary, no center, enrollment or installed Agent."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from guarddesk import endpoint_setup as setup


class StageReached(Exception):
    pass


class ReinstallRootTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'client'
        self.package = self.base / 'package'
        self.package.mkdir()
        self.connection = self.package / 'endpoint-connection.json'
        self.connection.write_text('{}')
        (self.package / 'update-trust.json').write_text('{}')

    def attempt(self):
        # Exercise the actual installer pre-stage path. OS directory protection
        # remains real; only public connection checks and later work are stubbed.
        with patch('guarddesk.windows_privilege.is_admin', return_value=False), \
             patch.object(setup, 'read_connection', return_value=('https://owned.test', 'unused')), \
             patch('guarddesk.update_packages.trust_file', return_value='owned-test-key'), \
             patch('guarddesk.remote_trial_install.check_connection'), \
             patch.object(setup, 'stage_application', side_effect=StageReached), \
             patch.object(setup, 'enroll', side_effect=AssertionError('No enrollment allowed')):
            setup._install(self.connection, self.root)

    def accepted(self):
        with self.assertRaises(StageReached):
            self.attempt()
        state = json.loads((self.root / 'endpoint-install.json').read_text())
        self.assertEqual(state['product'], 'GuardDeskEndpoint')
        self.assertEqual(state['phase'], 'created')

    def rejected(self):
        with self.assertRaises((ValueError, OSError)):
            self.attempt()
        self.assertFalse((self.root / 'endpoint-install.json').exists())

    def test_new_directory(self):
        self.accepted()

    def test_empty_existing_directory(self):
        self.root.mkdir()
        self.accepted()

    def test_empty_preserved_documents_after_removal(self):
        (self.root / 'PilotDocuments').mkdir(parents=True)
        self.accepted()

    def test_nonempty_documents_preserved(self):
        docs = self.root / 'PilotDocuments'
        docs.mkdir(parents=True)
        (docs / 'keep.txt').write_bytes(b'user-owned')
        self.rejected()
        self.assertEqual((docs / 'keep.txt').read_bytes(), b'user-owned')

    def test_documents_file_preserved(self):
        self.root.mkdir()
        (self.root / 'PilotDocuments').write_bytes(b'not-a-directory')
        self.rejected()
        self.assertEqual((self.root / 'PilotDocuments').read_bytes(), b'not-a-directory')

    def test_unknown_contents_preserved(self):
        self.root.mkdir()
        (self.root / 'unknown').write_bytes(b'keep')
        self.rejected()
        self.assertEqual((self.root / 'unknown').read_bytes(), b'keep')

    def test_old_identity_without_marker_not_reenrolled(self):
        config = self.root / 'runtime' / 'agent' / 'config.json'
        config.parent.mkdir(parents=True)
        config.write_bytes(b'old-identity')
        self.rejected()
        self.assertEqual(config.read_bytes(), b'old-identity')

    def test_existing_marker_not_overwritten(self):
        self.root.mkdir()
        marker = self.root / 'endpoint-install.json'
        marker.write_text(json.dumps({'product': 'GuardDeskEndpoint', 'phase': 'created',
                                     'config': str(self.root / 'runtime/agent/config.json')}))
        before = marker.read_bytes()
        self.accepted()
        self.assertEqual(marker.read_bytes(), before)

    def test_new_file_before_empty_root_recreation_preserved(self):
        self.root.mkdir()
        secure = setup.secure_directory
        def concurrent_file(path, **kwargs):
            (path / 'appeared.txt').write_bytes(b'keep-race')
            return secure(path, **kwargs)
        with patch.object(setup, 'secure_directory', side_effect=concurrent_file):
            self.rejected()
        self.assertEqual((self.root / 'appeared.txt').read_bytes(), b'keep-race')

    @unittest.skipUnless(os.name == 'nt', 'Windows junction boundary')
    def test_documents_junction_not_followed(self):
        self.root.mkdir()
        target = self.base / 'outside'
        target.mkdir()
        junction = self.root / 'PilotDocuments'
        made = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(junction), str(target)],
                              capture_output=True)
        self.assertEqual(made.returncode, 0, made.stderr)
        try:
            self.rejected()
            self.assertTrue(target.is_dir())
            self.assertTrue(junction.exists())
        finally:
            junction.rmdir()  # Remove only the owned junction, never its target.


if __name__ == '__main__':
    unittest.main()
