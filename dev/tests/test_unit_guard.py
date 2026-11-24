"""The development runner must block a center before any TCP bind."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import run_unit


class CenterGuardTest(unittest.TestCase):
    def test_actual_HTTP_constructor_is_denied_before_binding(self):
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'source'))
        from http.server import HTTPServer,BaseHTTPRequestHandler
        with run_unit.center_start_guard() as attempts:
            with self.assertRaisesRegex(RuntimeError,'prohibited'):
                HTTPServer(('127.0.0.1',0),BaseHTTPRequestHandler)
        self.assertEqual(attempts,['HTTP_center_start_denied'])

    def test_inherited_center_fixture_is_explicitly_external_only(self):
        self.assertNotIn('test_machine_agent',run_unit.NAMES)
        self.assertNotIn('test_machine_agent.MachineUpdateHandoffTest',run_unit.NAMES)
        self.assertIn('test_machine_agent.MachineUpdateHandoffTest',run_unit.EXTERNAL_ONLY)


if __name__=='__main__':unittest.main()
