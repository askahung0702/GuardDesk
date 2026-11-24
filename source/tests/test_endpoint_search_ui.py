"""Offline UI contract gate, including dispatch target and draft identity safety."""
import shutil
import subprocess
import unittest
from pathlib import Path


class EndpointSearchUITest(unittest.TestCase):
    def test_actual_ui_helpers_and_dispatch_handler(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node is required for the endpoint-search UI gate')
        result = subprocess.run(
            [node, str(Path(__file__).with_suffix('.cjs'))],
            capture_output=True, text=True, encoding='utf-8', timeout=40)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('"network_calls":0', result.stdout)


if __name__ == '__main__':
    unittest.main()
