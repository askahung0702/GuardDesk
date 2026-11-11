"""Service transaction faults at existing identities; no actual service changes."""
import json
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk import remote_service as rs,remote_trial,native_installer as ni
import test_native_installer as fixture

class ServiceFixture(fixture.FakeWindows):
    body=staticmethod(lambda exe,config,role:rs.description(exe,config))
    def verify(self,raw,exe,config,role):
        if isinstance(raw,dict):rs.verify(raw,exe,config,role)
        else:ni.verify_task(raw,exe,config,role)
    def register(self,name,raw,directory):
        super().register(name,raw,directory)
        if getattr(self,'fail_create_once',False):
            self.fail_create_once=False;raise OSError('owned failure after service creation')
    def health(self,*args):
        if getattr(self,'fail_new_health',False):
            self.fail_new_health=False;raise OSError('owned new worker health failure')
        return super().health(*args)

class ServiceTransactionTest(unittest.TestCase):
    setUp=fixture.NativeInstallerTest.setUp
    run_install=fixture.NativeInstallerTest.run_install
    def prepare(self,old=False):
        self.ops=ServiceFixture()
        self.settings['install_profile']=remote_trial.PROFILE
        self.config.write_text(json.dumps(self.settings))
        enabled=patch.object(remote_trial,'ENABLED',True);enabled.start();self.addCleanup(enabled.stop)
        if old:
            root=self.protected.parent;root.mkdir(parents=True)
            self.protected.write_text(json.dumps(self.settings))
            (root/'offline-owned').write_bytes(b'preserve')
            target=self.program/'USBControl';target.mkdir(parents=True)
            (target/'GuardDesk.exe').write_bytes(b'old remote worker')
            self.ops.tasks['GuardDesk-USBControl-'+'a'*24]=ni.task_body(target/'GuardDesk.exe',self.protected,'native')
    def test_new_service_and_preserved_config(self):
        self.prepare();self.run_install()
        self.assertEqual(len(self.ops.tasks),1)
        self.assertEqual(next(iter(self.ops.tasks.values()))['kind'],'remote-service-v1')
        self.assertEqual(json.loads(self.protected.read_text())['token'],self.settings['token'])
    def test_legacy_task_migrates_without_registration_or_identity_reset(self):
        self.prepare(old=True);self.run_install()
        self.assertEqual(next(iter(self.ops.tasks.values()))['kind'],'remote-service-v1')
        self.assertEqual((self.protected.parent/'offline-owned').read_bytes(),b'preserve')
    def test_failed_service_create_and_health_restore_exact_old_task_and_bytes(self):
        for failure in ('fail_create_once','fail_new_health'):
            with self.subTest(failure=failure):
                # Each case gets its own isolated transaction tree.
                case=ServiceTransactionTest();case.setUp()
                try:
                    case.prepare(old=True);prior=dict(case.ops.tasks);config=case.protected.read_bytes()
                    setattr(case.ops,failure,True)
                    with self.assertRaises(ni.NativeInstallFailure):case.run_install()
                    self.assertEqual(case.ops.tasks,prior)
                    self.assertEqual(case.protected.read_bytes(),config)
                    self.assertEqual((case.program/'USBControl/GuardDesk.exe').read_bytes(),b'old remote worker')
                    self.assertEqual(json.loads((case.protected.parent/'install-transaction.json').read_text())['phase'],'rolled_back')
                finally:case.doCleanups()
    def test_stop_failure_never_replaces_old_program(self):
        self.prepare(old=True);prior=dict(self.ops.tasks);self.ops.fail_stop=True
        with self.assertRaises(ni.NativeInstallFailure):self.run_install()
        self.assertEqual(self.ops.tasks,prior)
        self.assertEqual((self.program/'USBControl/GuardDesk.exe').read_bytes(),b'old remote worker')
    def test_uninstall_service_retains_identity_and_files(self):
        self.prepare();self.run_install();before=self.protected.read_bytes()
        self.assertEqual(self.run_install('Uninstall')['status'],'removed')
        self.assertEqual(self.ops.tasks,{})
        self.assertEqual(self.protected.read_bytes(),before)
        self.assertTrue((self.program/'USBControl/GuardDesk.exe').exists())
    def test_foreign_service_identity_rejected_before_mutation(self):
        self.prepare(old=True)
        key=next(iter(self.ops.tasks));self.ops.tasks[key]={'kind':'remote-service-v1','device_id':'b'*24,'binary':'foreign'}
        with self.assertRaises(OSError):self.run_install()
        self.assertEqual(self.ops.events,[])

class RoleSeparationTest(unittest.TestCase):
    def test_shared_manifest_boundary_accepts_only_fixed_trial_artifacts(self):
        from guarddesk.update_packages import safe_name
        for enabled in (False,True):
            with patch.object(remote_trial,'ENABLED',enabled):
                for name in ('GuardDeskInstaller.exe','GuardDeskService.exe'):
                    if enabled:self.assertEqual(safe_name(name),name)
                    else:
                        with self.assertRaises(ValueError):safe_name(name)
                for name in ('installer.exe','GuardDeskService.exe/../bad','../GuardDeskInstaller.exe','GuardDeskService.exe:stream'):
                    with self.assertRaises(ValueError):safe_name(name)
    def test_real_windows_security_descriptors_reject_user_change_rights(self):
        import ctypes
        from ctypes import wintypes as w
        service=rs.Service();api=service.api;kernel=ctypes.WinDLL('kernel32')
        kernel.LocalFree.argtypes=[w.LPVOID]
        cases=[('O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLORC;;;AU)',True),
               ('O:BAD:P(A;;GA;;;SY)(A;;GA;;;WD)',False),
               ('O:WDD:P(A;;GA;;;SY)',False),('O:BA',False)]
        api.GetSecurityDescriptorLength.argtypes=[w.LPVOID];api.GetSecurityDescriptorLength.restype=w.DWORD
        for text,allowed in cases:
            descriptor=w.LPVOID()
            self.assertTrue(api.ConvertStringSecurityDescriptorToSecurityDescriptorW(text,1,ctypes.byref(descriptor),None))
            size=api.GetSecurityDescriptorLength(descriptor)
            def query(handle,flags,buffer,length,needed):
                ctypes.cast(needed,ctypes.POINTER(w.DWORD))[0]=size
                if not buffer:return False
                ctypes.memmove(buffer,descriptor,size);return True
            try:
                with self.subTest(descriptor=text),patch.object(api,'QueryServiceObjectSecurity',side_effect=query):
                    if allowed:service.protection(1)
                    else:
                        with self.assertRaises(PermissionError):service.protection(1)
            finally:kernel.LocalFree(descriptor)
    def test_installer_and_runtime_cannot_dispatch_each_others_authority(self):
        from guarddesk import remote_installer_entry as installer,remote_endpoint_entry as runtime
        with patch.object(remote_trial,'ENABLED',True):
            for command in installer.INSTALLER_COMMANDS-{'component-info'}:
                with self.assertRaises(PermissionError):runtime.main([command])
            for command in runtime.ENDPOINT_COMMANDS-{'component-info'}:
                with self.assertRaises(PermissionError):installer.main([command])
    def test_shared_plain_and_save_keep_original_compatibility_exports(self):
        from guarddesk import endpoint_setup,endpoint_files
        self.assertIs(endpoint_setup.plain,endpoint_files.plain)
        self.assertIs(endpoint_setup.save,endpoint_files.save)
    def test_service_description_has_no_user_supplied_command(self):
        exe=Path(r'C:\Program Files\GuardDeskPilot\USBControl\GuardDesk.exe')
        config=Path(r'C:\ProgramData\GuardDeskPilot\USBControl')/('a'*24)/'config.json'
        body=rs.description(exe,config);rs.verify(body,exe,config,'native')
        with self.assertRaises(OSError):rs.verify({**body,'binary':'cmd.exe'},exe,config,'native')
        with self.assertRaises(ValueError):rs.description(exe,config.parent.parent/'bad/config.json')

