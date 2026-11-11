import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk.process_audit import IDS,configure,normalized_flags,read_flags
from guarddesk.application_control import ExtendedWorker
from guarddesk.policy import DEFAULT_POLICY


class ProcessAuditTest(unittest.TestCase):
    def test_system_audit_flags_include_explicit_no_auditing(self):
        self.assertEqual([normalized_flags(value) for value in (0,1,2,3,4)],[0,1,2,3,0])
        with self.assertRaises(OSError):normalized_flags(8)

    def test_configure_preserves_failure_audit_and_restores_baseline(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);baseline={IDS[0]:2,IDS[1]:1};managed={IDS[0]:3,IDS[1]:1}
            with patch('guarddesk.process_audit.read_flags',side_effect=[baseline,managed]) as read,patch('guarddesk.process_audit.auditpol') as command:
                result=configure(directory,True)
                self.assertTrue(result['process_audit_enabled']);self.assertEqual(read.call_count,2)
                command.assert_called_once_with('/set','/subcategory:'+IDS[0],'/success:enable','/failure:enable')
            self.assertEqual(json.loads((directory/'process-audit-original.json').read_text()),baseline)
            with patch('guarddesk.process_audit.read_flags',side_effect=[managed,baseline]),patch('guarddesk.process_audit.auditpol') as command:
                configure(directory,False)
                command.assert_called_once_with('/set','/subcategory:'+IDS[0],'/success:disable','/failure:enable')
            self.assertFalse((directory/'process-audit-original.json').exists())

    def test_external_policy_change_and_bad_readback_preserve_backup(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);backup=directory/'process-audit-original.json';saved={key:0 for key in IDS};backup.write_text(json.dumps(saved))
            with patch('guarddesk.process_audit.read_flags',return_value={key:2 for key in IDS}),patch('guarddesk.process_audit.auditpol') as command:
                with self.assertRaisesRegex(OSError,'outside GuardDesk'):configure(directory,False)
                command.assert_not_called()
            with patch('guarddesk.process_audit.read_flags',side_effect=[saved,saved]),patch('guarddesk.process_audit.auditpol'):
                with self.assertRaisesRegex(OSError,'readback mismatch'):configure(directory,True)
            self.assertTrue(backup.exists())

    def test_existing_success_policy_is_verified_without_rewriting(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch('guarddesk.process_audit.read_flags',return_value={key:3 for key in IDS}),patch('guarddesk.process_audit.auditpol') as command:
                self.assertTrue(configure(Path(temp),True)['process_audit_enabled']);command.assert_not_called()

    def test_audit_only_worker_never_launches_powershell_and_caches_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            class Agent:
                config_path=Path(temp)/'config.json'
                config={'device_id':'test'}
                def call(self,*args):return {'device_id':'test','body':copy.deepcopy(DEFAULT_POLICY)}
                def db(self):raise AssertionError('database is replaced below')
            class Database:
                def __enter__(self):return self
                def __exit__(self,*args):pass
                def execute(self,*args):return self
                def fetchone(self):return None
            agent=Agent();agent.db=Database;worker=ExtendedWorker(agent)
            with patch('guarddesk.process_audit.configure',return_value={'process_audit_enabled':True}) as audit,patch('guarddesk.application_control.native_action',side_effect=AssertionError('PowerShell must not run')),patch.object(worker,'poll'),patch.object(worker,'configure_documents'):
                worker.configure();worker.configure()
                audit.assert_called_once();self.assertEqual(worker.status['status'],'configured')
                self.assertEqual(worker.status['application_control'],'disabled')


if __name__=='__main__':unittest.main()
