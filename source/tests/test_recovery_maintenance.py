import unittest
from unittest.mock import patch,Mock
from pathlib import Path
from guarddesk import remote_service
from tools.probe_recovery_maintenance import cases,fixture,rejected
from tools.offline_build_guard import guarded_main

class RecoveryMaintenanceTest(unittest.TestCase):
    def test_offline_build_rejects_caught_server_constructor_attempt(self):
        from http.server import HTTPServer,BaseHTTPRequestHandler
        @guarded_main
        def owned():
            try:HTTPServer(('127.0.0.1',0),BaseHTTPRequestHandler)
            except RuntimeError:pass
        with self.assertRaisesRegex(RuntimeError,'attempted to start'):owned()

    def test_offline_build_permits_readonly_probe(self):
        self.assertEqual(guarded_main(lambda:17)(),17)

    def test_disabled_service_read_start_and_safe_removal_boundaries(self):
        self.assertEqual(len(cases(remote_service)),8)

    def test_immediate_fence_readback_failure_is_not_accepted(self):
        service=fixture(remote_service,2);expected=service.query()
        service.api.ChangeServiceConfigW=lambda *args:True
        rejected(lambda:service.disable_for_recovery(expected))

    def test_already_disabled_fence_does_not_start_or_reconfigure(self):
        service=fixture(remote_service,4);service.disable_for_recovery(service.query())
        self.assertEqual(service.api.mutations,[])

    def test_query_does_not_make_disabled_service_startable(self):
        service=fixture(remote_service,4);expected=service.query()
        for _ in range(2):rejected(lambda:service.action(expected,'start'))
        self.assertEqual(service.api.mutations,[])

    def test_foreign_device_not_deleted_even_when_disabled(self):
        service=fixture(remote_service,4);expected={**service.query(),'device_id':'b'*24}
        rejected(lambda:service.action(expected,'delete'))
        self.assertEqual(service.api.mutations,[])

    def test_disabled_running_service_can_retire_after_final_ack(self):
        service=fixture(remote_service,4);service.retire_self(service.query())
        self.assertEqual(service.api.mutations,['delete'])

    def test_disabled_service_cannot_be_replaced_by_a_legacy_task(self):
        from guarddesk import native_installer
        service=fixture(remote_service,4)
        with patch.object(remote_service,'Service',return_value=service),patch.object(native_installer.Windows,'register') as register:
            ops=remote_service.platform();ops.expected=service.query()
            rejected(lambda:ops.register('GuardDesk-USBControl-'+'a'*24,'owned-original-xml',Path('owned')))
        register.assert_not_called();self.assertEqual(service.api.mutations,[])

    def test_native_update_refuses_rollback_before_touching_programs(self):
        from guarddesk import update_native
        adapter=update_native.NativeAdapter.__new__(update_native.NativeAdapter)
        adapter.service=fixture(remote_service,4);adapter.service_expected=adapter.service.query()
        adapter.stop=Mock();adapter.start=Mock()
        rejected(lambda:adapter.rollback({}))
        adapter.stop.assert_not_called();adapter.start.assert_not_called()

    def test_install_hold_keeps_new_maintenance_program_and_original_evidence(self):
        from test_remote_service import ServiceTransactionTest
        from guarddesk import native_installer
        case=ServiceTransactionTest();case.setUp()
        try:
            case.prepare(old=True);service=fixture(remote_service,4)
            with patch.object(remote_service,'Service',return_value=service):
                adapter=remote_service.platform();adapter.expected=service.query()
            case.ops.guard_recovery_rollback=adapter.guard_recovery_rollback
            case.ops.fail_new_health=True
            with self.assertRaises(native_installer.NativeInstallFailure) as failure:case.run_install()
            self.assertIn('recovery_hold',str(failure.exception))
            self.assertEqual((case.program/'USBControl/GuardDesk.exe').read_bytes(),(case.source/'GuardDesk.exe').read_bytes())
            self.assertTrue(list(case.program.glob('USBControl.install-backup-*')))
            self.assertFalse(any(event[0]=='delete' for event in case.ops.events))
            self.assertEqual((case.protected.parent/'offline-owned').read_bytes(),b'preserve')
        finally:case.doCleanups()
