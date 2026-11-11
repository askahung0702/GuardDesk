"""Isolated Windows diagnostic: a free worker mutex is not process exit proof.

Uses a disposable child with its cwd in a disposable program directory. Never
opens installed endpoint configuration, tasks, policies, or company audit data.
This demonstrates a possible failure mechanism, not user1's proven root cause.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guarddesk.single_instance import machine_instance


@unittest.skipUnless(os.name == 'nt', 'Windows directory sharing semantics')
class SwitchRaceDiagnostic(unittest.TestCase):
    def test_free_mutex_with_live_directory_holder_blocks_switch(self):
        with tempfile.TemporaryDirectory(prefix='switch-race-', dir=ROOT/'runtime') as tmp:
            program = Path(tmp)
            native = program/'USBControl'
            stage = program/'USBControl.stage-test'
            native.mkdir()
            stage.mkdir()
            (native/'version.txt').write_text('old', encoding='utf-8')
            (stage/'version.txt').write_text('new', encoding='utf-8')
            device = uuid.uuid4().hex[:24]
            script = '''
import sys
from guarddesk.single_instance import machine_instance
with machine_instance('usb', sys.argv[1]):
    pass
print('mutex-released-process-alive', flush=True)
sys.stdin.readline()
'''
            env = {**os.environ, 'PYTHONPATH': str(ROOT)}
            child = subprocess.Popen([sys.executable, '-c', script, device],
                                     cwd=native, env=env, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(),
                                 'mutex-released-process-alive')
                # Reproduce the pre-fix primitive: mutex release alone, followed
                # by a single directory rename. The fixed stop/switch path has
                # separate acceptance tests in test_update_windows.py.
                with machine_instance('usb', device):
                    pass
                self.assertIsNone(child.poll())
                backup = program/'USBControl.backup'
                with self.assertRaises(OSError) as caught:
                    native.rename(backup)
                self.assertIn(caught.exception.winerror, (5, 32))
                self.assertTrue(native.is_dir())
                self.assertTrue(stage.is_dir())
                self.assertFalse(backup.exists())
                child.communicate('\n', timeout=10)
                self.assertEqual(child.returncode, 0)
                native.rename(backup)
                stage.rename(native)
                self.assertEqual((native/'version.txt').read_text(), 'new')
                self.assertEqual((backup/'version.txt').read_text(), 'old')
            finally:
                if child.poll() is None:
                    child.communicate('\n', timeout=10)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(SwitchRaceDiagnostic))
    print(json.dumps({'passed': result.wasSuccessful(),
                      'tests': result.testsRun,
                      'scope': 'isolated_windows_directory_holder',
                      'user1_root_cause_confirmed': False}))
    sys.exit(not result.wasSuccessful())
