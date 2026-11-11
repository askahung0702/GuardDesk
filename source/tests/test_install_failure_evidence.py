"""Reproduce lost startup/rollback evidence without touching installed Agents."""
import ctypes
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from guarddesk import native_installer as ni


class InstallEvidenceTest(unittest.TestCase):
    def test_trial_running_trace_is_evidence_not_health_success(self):
        from guarddesk import remote_trial
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);health=root/'native-health.json'
            (root/'native-startup.json').write_text(json.dumps({'version':'0.4.86','started':201,'phase':'running','state':'entered','pid':123,'token':'PRIVATE'}))
            with patch.object(remote_trial,'ENABLED',True),patch.object(ni.time,'monotonic',side_effect=[0,0,46]),patch.object(ni.time,'sleep'):
                with self.assertRaises(ni.InstallObservationError) as error:
                    ni.Windows().health(health,'0.4.86',root/'GuardDesk.exe',200)
            self.assertEqual(error.exception.evidence['health_state'],'missing')
            self.assertEqual(error.exception.evidence['startup']['phase'],'running')
            self.assertFalse(error.exception.evidence['pid_validated'])
            self.assertNotIn('PRIVATE',str(error.exception))

    def health_failure(self,value,exe_present=True):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'native-health.json';path.write_text(json.dumps(value))
            exe=root/'GuardDesk.exe'
            if exe_present:exe.write_bytes(b'not executed')
            with patch.object(ni.time,'monotonic',side_effect=[0,0,46]),patch.object(ni.time,'sleep'):
                with self.assertRaises(OSError) as error:ni.Windows().health(path,'0.4.86',exe,200)
            return error.exception

    def test_old_health_reports_observed_version_and_time_without_claiming_live_worker(self):
        error=self.health_failure({'version':'0.4.85','time':100,'pid':123})
        evidence=error.evidence
        self.assertEqual(evidence['observed_version'],'0.4.85')
        self.assertEqual(evidence['observed_time'],100)
        self.assertEqual(evidence['started'],200)
        self.assertEqual(evidence['health_state'],'version_mismatch')
        self.assertEqual(evidence['image_state'],'present_not_liveness_proof')
        self.assertFalse(evidence['pid_validated'])

    def test_missing_image_distinguished_from_stale_health(self):
        error=self.health_failure({'version':'0.4.85','time':100,'pid':123},False)
        self.assertEqual(error.evidence['image_state'],'missing')
        self.assertNotIn('Defender',str(error))

    def test_unknown_health_fields_and_untrusted_version_text_never_echoed(self):
        error=self.health_failure({'version':'SECRET\nBearer secret','time':100,'pid':123,'token':'PRIVATE_TOKEN','native_remote':{'text':'PRIVATE_SCREEN'}})
        for secret in ('SECRET','Bearer','PRIVATE_TOKEN','PRIVATE_SCREEN'):
            self.assertNotIn(secret,str(error));self.assertNotIn(secret,json.dumps(error.evidence))

    def test_current_version_with_old_time_is_not_ready(self):
        error=self.health_failure({'version':'0.4.86','time':100,'pid':123})
        self.assertEqual(error.evidence['health_state'],'stale_or_invalid_time')

    def test_invalid_pid_does_not_query_system_process(self):
        for pid in (True,0,-1,'123',2**33):
            with self.subTest(pid=pid),patch.object(ni,'health_image') as image:
                error=self.health_failure({'version':'0.4.86','time':201,'pid':pid})
                image.assert_not_called();self.assertEqual(error.evidence['health_state'],'invalid_pid')

    def test_stop_missing_exe_keeps_winerror_and_task_end_code(self):
        with patch.object(ni,'system_tool',return_value='schtasks.exe'),patch.object(ni.subprocess,'run',return_value=subprocess.CompletedProcess([],1)),patch.object(ni,'wait_image_unmapped',side_effect=ctypes.WinError(2)):
            with self.assertRaises(OSError) as error:ni.Windows().stop('GuardDesk-USBControl-'+'a'*24,Path('owned.exe'))
        self.assertEqual(error.exception.evidence['winerror'],2)
        self.assertEqual(error.exception.evidence['task_end_exit_code'],1)
        self.assertIn('missing',error.exception.evidence['state'])

    def test_failed_task_end_is_not_failure_if_exclusive_image_check_succeeds(self):
        with patch.object(ni,'system_tool',return_value='schtasks.exe'),patch.object(ni.subprocess,'run',return_value=subprocess.CompletedProcess([],1)),patch.object(ni,'wait_image_unmapped') as wait:
            ni.Windows().stop('fixed',Path('owned.exe'));wait.assert_called_once()

    def test_rollback_summary_does_not_echo_arbitrary_exception_text(self):
        summary=ni.failure_evidence('stop_native',OSError('secret-token'))
        self.assertNotIn('secret',json.dumps(summary))
        self.assertEqual(summary['operation'],'stop_native')

if __name__=='__main__':unittest.main()
