"""The slim runtime's WTS dependency must execute without control modules."""
import unittest
from unittest.mock import patch
from guarddesk import document_context,windows_sessions


class ReadOnlySessionTest(unittest.TestCase):
    def test_metadata_path_works_when_control_module_is_unavailable(self):
        metadata={'locked':False,'logon':42,'idle':None}
        with patch.dict('sys.modules',{'guarddesk.custom_windows':None}),patch.object(windows_sessions,'session_information',return_value=metadata):
            self.assertEqual(document_context.user_session_states([]),{})
            values=document_context.user_session_states([(0,0),(1,0),(2,6)])
        self.assertEqual(set(values),{1});self.assertEqual(values[1]['logon'],42)

    def test_failed_session_remains_unknown_instead_of_verified_active(self):
        error=PermissionError('private');error.winerror=5
        with patch.object(windows_sessions,'session_information',side_effect=error):
            values=document_context.user_session_states([(1,0)])
        self.assertTrue(values[1]['query_failed']);self.assertEqual(values[1]['query_error']['winerror'],5)
        self.assertNotIn('private',str(values))
