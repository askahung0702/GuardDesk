"""Retry only known transient Windows errors; preserve old file until success."""
import unittest
from unittest.mock import patch,call
from guarddesk.deployment import replace_with_retry


def locked(code):
    error=OSError('fixture lock');error.winerror=code;return error


class BundleReplaceTest(unittest.TestCase):
    def test_transient_error_retries_with_path_checks_and_no_delete(self):
        with patch('guarddesk.deployment.plain') as plain,patch('guarddesk.deployment.os.replace',side_effect=[locked(5),locked(32),None]) as replace,patch('guarddesk.deployment.time.sleep') as sleep,patch('guarddesk.deployment.time.monotonic',return_value=0):
            replace_with_retry('new','old')
            self.assertEqual(replace.call_count,3);self.assertEqual(sleep.call_count,2)
            self.assertEqual(plain.call_args_list,[call('new'),call('old')]*3)

    def test_persistent_denial_has_deadline_and_preserves_error(self):
        error=locked(5)
        with patch('guarddesk.deployment.plain'),patch('guarddesk.deployment.os.replace',side_effect=error) as replace,patch('guarddesk.deployment.time.sleep') as sleep,patch('guarddesk.deployment.time.monotonic',side_effect=[0,11]):
            with self.assertRaises(OSError) as result:replace_with_retry('new','old')
            self.assertIs(result.exception,error);self.assertEqual(replace.call_count,1);sleep.assert_not_called()

    def test_unrelated_errors_and_reparse_rejection_are_not_retried(self):
        with patch('guarddesk.deployment.plain'),patch('guarddesk.deployment.os.replace',side_effect=locked(112)) as replace,patch('guarddesk.deployment.time.sleep') as sleep:
            with self.assertRaises(OSError):replace_with_retry('new','old')
            self.assertEqual(replace.call_count,1);sleep.assert_not_called()
        with patch('guarddesk.deployment.plain',side_effect=ValueError('reparse')),patch('guarddesk.deployment.os.replace') as replace:
            with self.assertRaises(ValueError):replace_with_retry('new','old')
            replace.assert_not_called()
