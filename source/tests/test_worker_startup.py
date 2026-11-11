import ctypes,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk.worker_startup import Trace,snapshot
from guarddesk import __version__

class StartupTraceTest(unittest.TestCase):
    def test_only_last_fixed_milestone_no_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);trace=Trace(root)
            self.assertTrue(trace.record('construct_supervisor'))
            exc=ctypes.WinError(5);exc.args=('PRIVATE_TOKEN password SECRET_COMMAND',)
            self.assertTrue(trace.record('start_supervisor',exc))
            value=json.loads(trace.path.read_text())
            self.assertEqual(value['winerror'],5);self.assertEqual(value['phase'],'start_supervisor')
            self.assertEqual(value['state'],'failed');self.assertLess(trace.path.stat().st_size,1024)
            self.assertNotIn('PRIVATE',trace.path.read_text());self.assertNotIn('password',trace.path.read_text())
            self.assertEqual([p.name for p in root.iterdir()],['native-startup.json'])

    def test_write_failure_does_not_mask_original_error(self):
        trace=Trace(Path('unused'))
        with patch('guarddesk.update_client.save',side_effect=PermissionError('denied')):
            self.assertFalse(trace.record('start_supervisor',OSError('original')))

    def test_unknown_phase_rejected_before_write(self):
        with patch('guarddesk.update_client.save') as save:
            with self.assertRaises(ValueError):Trace(Path('unused')).record('token=secret')
            save.assert_not_called()

    def test_installer_ignores_stale_trace_and_unknown_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'native-startup.json'
            self.assertEqual(snapshot(path,__version__,100),{'state':'missing'})
            value={'version':__version__,'started':99,'pid':123,'state':'failed','phase':'start_supervisor','token':'SECRET'}
            path.write_text(json.dumps(value))
            self.assertEqual(snapshot(path,__version__,100),{'state':'stale_or_other_version'})
            value['started']=101;path.write_text(json.dumps(value))
            result=snapshot(path,__version__,100)
            self.assertEqual(result['phase'],'start_supervisor');self.assertNotIn('SECRET',json.dumps(result))

if __name__=='__main__':unittest.main()
