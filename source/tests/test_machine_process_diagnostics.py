"""Owned metadata only; no SYSTEM launch, installed Agent, or Defender change."""
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from guarddesk.machine_agent import Supervisor,MAX_SESSIONS
from guarddesk.machine_agent_windows import Child

class ProcessDiagnosticsTests(unittest.TestCase):
    def supervisor(self,children):
        s=Supervisor.__new__(Supervisor);s.children=children
        return s

    def test_launched_handle_retains_pid_and_observation_time(self):
        api=Mock()
        with patch('guarddesk.machine_agent_windows.time.time',return_value=123.5):
            child=Child(api,123,7780)
        self.assertEqual((child.pid,child.launch_observed_at),(7780,123.5))
        self.assertEqual(api.mock_calls,[])
        child.close();child.close();api.CloseHandle.assert_called_once_with(123)

    def test_metadata_does_not_query_or_export_secrets(self):
        child=SimpleNamespace(pid=28208,launch_observed_at=123.5,token='SECRET',account='SECRET',alive=Mock(side_effect=AssertionError))
        s=self.supervisor({6:child});result=s.local_process_diagnostics()
        self.assertEqual(result['parent_pid'],os.getpid())
        self.assertEqual(result['helpers'],[{'role':'machine_session_helper','pid':28208,'session_id':6,'launch_observed_at':123.5}])
        self.assertNotIn('SECRET',json.dumps(result));child.alive.assert_not_called()
        self.assertTrue(result['observations_not_liveness_proof'])

    def test_capacity_bounded(self):
        s=self.supervisor({i:SimpleNamespace(pid=i+1,launch_observed_at=123.5) for i in range(50)})
        self.assertEqual(len(s.local_process_diagnostics()['helpers']),MAX_SESSIONS)

    def test_invalid_or_missing_metadata_is_not_fabricated(self):
        for pid in [None,0,-1,True,1.5,'28208',2**32]:
            with self.subTest(pid=pid):
                self.assertEqual(self.supervisor({6:SimpleNamespace(pid=pid,launch_observed_at=123)}).local_process_diagnostics()['helpers'],[])
        for stamp in [None,True,0,float('nan'),float('inf'),'secret']:
            with self.subTest(stamp=stamp):
                self.assertEqual(self.supervisor({6:SimpleNamespace(pid=1,launch_observed_at=stamp)}).local_process_diagnostics()['helpers'],[])

    def test_parent_heartbeat_snapshot_unchanged(self):
        s=self.supervisor({6:SimpleNamespace(pid=28208,launch_observed_at=123.5)})
        s.states={};s.errors=0;s.last_error=None;s.platform=SimpleNamespace()
        self.assertNotIn('28208',json.dumps(s.snapshot()))

    def test_child_replacement_reports_owned_current_observation(self):
        s=self.supervisor({6:SimpleNamespace(pid=100,launch_observed_at=10)})
        before=s.local_process_diagnostics()
        s.children[6]=SimpleNamespace(pid=101,launch_observed_at=20)
        self.assertEqual(before['helpers'][0]['pid'],100)
        self.assertEqual(s.local_process_diagnostics()['helpers'][0]['pid'],101)

if __name__=='__main__':unittest.main()
