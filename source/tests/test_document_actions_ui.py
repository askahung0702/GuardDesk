"""Offline action-menu gate; no management center or installed Agent."""
import shutil
import subprocess
import unittest
from pathlib import Path


class DocumentActionsUITest(unittest.TestCase):
    def test_actual_menu_render_query_and_toggle_preserve_history(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node is required for the document-action UI gate')
        result = subprocess.run([node, str(Path(__file__).with_suffix('.cjs'))],
                                capture_output=True, text=True, encoding='utf-8', timeout=40)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('"network_calls":0', result.stdout)
