"""Recovery security marker/exit behavior; no SCM, center or installed Agent."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import struct
import tempfile
import unittest

from guarddesk import service_recovery as recovery, machine_service


class RecoveryMarkerTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='guarddesk-hold-owned-');self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.did='a'*24;self.root=self.base/'USBControl'/self.did;self.root.mkdir(parents=True)
        self.agent=SimpleNamespace(config={'device_id':self.did},config_path=self.root/'config.json')
        p=patch('guarddesk.remote_service.Service');self.service=p.start().return_value;self.addCleanup(p.stop)
        for target,value in [('guarddesk.machine_service.ENABLED',True),('guarddesk.machine_agent.eligible',lambda _:True),
                             ('guarddesk.update_native.folder',lambda _:self.base),('guarddesk.update_native.protected_tree',lambda *a,**kw:None)]:
            p=patch(target,value);p.start();self.addCleanup(p.stop)
        def write(_,path,raw):path.write_bytes(raw)
        p=patch('guarddesk.protected_files.ProtectedFiles.write',write);p.start();self.addCleanup(p.stop)

    def test_first_security_reason_is_persisted_and_never_overwritten(self):
        self.assertTrue(recovery.persist_security_hold(self.agent,225))
        raw=(self.root/recovery.MARKER).read_bytes()
        self.assertEqual(struct.unpack('<4sI24s',raw),(b'GDS1',225,self.did.encode()))
        self.assertTrue(recovery.persist_security_hold(self.agent,226))
        self.assertEqual((self.root/recovery.MARKER).read_bytes(),raw)

    def test_os_fence_precedes_marker_and_failure_does_not_write(self):
        self.service.disable_for_recovery.side_effect=PermissionError('owned fence refusal')
        with self.assertRaises(PermissionError):recovery.persist_security_hold(self.agent,225)
        self.assertFalse((self.root/recovery.MARKER).exists())
        self.service.disable_for_recovery.side_effect=None
        def write(_,path,raw):
            self.service.disable_for_recovery.assert_called()
            path.write_bytes(raw)
        with patch('guarddesk.protected_files.ProtectedFiles.write',write):
            recovery.persist_security_hold(self.agent,225)

    def test_invalid_existing_state_is_preserved(self):
        path=self.root/recovery.MARKER
        for raw in [b'',b'bad'*20,recovery.marker_bytes('b'*24,225),struct.pack('<4sI24s',b'GDS1',5,self.did.encode())]:
            path.write_bytes(raw)
            with self.assertRaises(ValueError):recovery.persist_security_hold(self.agent,225)
            self.assertEqual(path.read_bytes(),raw)

    def test_non_security_error_and_wrong_config_do_not_write(self):
        with self.assertRaises(ValueError):recovery.persist_security_hold(self.agent,5)
        self.agent.config_path=self.root/'other.json'
        with self.assertRaises(PermissionError):recovery.persist_security_hold(self.agent,225)
        self.assertFalse((self.root/recovery.MARKER).exists())

    def test_uninstalled_or_disabled_source_does_not_touch_machine_state(self):
        with patch('guarddesk.machine_agent.eligible',return_value=False):
            self.assertFalse(recovery.persist_security_hold(self.agent,225))
        with patch('guarddesk.machine_service.ENABLED',False),patch('guarddesk.remote_trial.ENABLED',False):
            self.assertFalse(recovery.persist_security_hold(self.agent,225))
        self.assertFalse((self.root/recovery.MARKER).exists())

    def test_write_failure_propagates_without_fabricating_a_hold(self):
        with patch('guarddesk.protected_files.ProtectedFiles.write',side_effect=PermissionError('owned refusal')):
            with self.assertRaises(PermissionError):recovery.persist_security_hold(self.agent,225)
        self.assertFalse((self.root/recovery.MARKER).exists())

    def test_hardlink_marker_is_not_accepted(self):
        import os
        marker=self.root/recovery.MARKER;marker.write_bytes(recovery.marker_bytes(self.did,225))
        os.link(marker,self.root/'owned-alias.bin')
        with self.assertRaises(PermissionError):recovery.persist_security_hold(self.agent,225)


class WorkerExitTest(unittest.TestCase):
    def run_worker(self,operation):
        sessions=SimpleNamespace(fatal_error=({'operation':operation} if operation else None))
        worker=SimpleNamespace(agent=object(),machine_sessions=sessions,run=lambda *a,**kw:None)
        with patch.object(machine_service,'ENABLED',True),patch('guarddesk.remote_trial_install.check_settings'),\
             patch('guarddesk.native_installer.read_json',return_value={}),\
             patch('guarddesk.native_usb.UsbWorker',return_value=worker),patch('guarddesk.machine_agent.eligible',return_value=True):
            return machine_service.worker(Path('owned-not-read'),object())

    def test_normal_exit_does_not_become_a_restart(self):
        self.assertIsNone(self.run_worker(None))

    def test_supervisor_fatal_stop_is_not_a_successful_exit(self):
        with self.assertRaises(RuntimeError):self.run_worker('supervisor_thread')

    def test_unpersisted_security_hold_becomes_non_retryable_policy_exit(self):
        with self.assertRaises(SystemExit) as result:self.run_worker('persist_security_hold')
        self.assertEqual(result.exception.code,1260)


if __name__=='__main__':unittest.main()
