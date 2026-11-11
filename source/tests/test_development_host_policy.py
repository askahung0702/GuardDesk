"""Workflow guard checks only; never starts a listener, center or endpoint."""
import json,tempfile,unittest
from pathlib import Path
from tools.development_host_policy import require_center_test_host

class DevelopmentHostPolicyTest(unittest.TestCase):
    def test_explicit_development_retirement_rejects_before_creating_fixtures(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);marker=root/'DEVELOPMENT-HOST-POLICY.json'
            marker.write_text(json.dumps({'role':'development-workstation','local_management_center':'disabled'}),encoding='utf-8')
            with self.assertRaisesRegex(PermissionError,'User disabled local management centers'):require_center_test_host(root)
            self.assertEqual(list(root.iterdir()),[marker])
    def test_unknown_enable_value_cannot_restore_local_center(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);marker=root/'DEVELOPMENT-HOST-POLICY.json'
            for value in (None,False,'true','temporary','enabled-for-tests'):
                marker.write_text(json.dumps({'role':'development-workstation','local_management_center':value}),encoding='utf-8')
                with self.subTest(value=value),self.assertRaises(PermissionError):require_center_test_host(root)
    def test_server_checkout_without_development_marker_is_unaffected(self):
        with tempfile.TemporaryDirectory() as temp:self.assertIsNone(require_center_test_host(Path(temp)))
    def test_oversized_policy_does_not_start_any_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'DEVELOPMENT-HOST-POLICY.json').write_bytes(b' '*8193)
            with self.assertRaisesRegex(PermissionError,'Invalid development-host policy'):require_center_test_host(root)
