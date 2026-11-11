"""Full service integration with real staging and fake SCM/task effects."""
import json,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from guarddesk import machine_service as ms,remote_trial,remote_service as rs,native_installer as ni
import test_native_installer as fixture

class FullServiceFixture(fixture.FakeWindows):
    @staticmethod
    def body(exe,config,role):return rs.description(exe,config) if role=='native' else ni.task_body(exe,config,role)
    @staticmethod
    def verify(raw,exe,config,role):
        if role=='native' and isinstance(raw,dict):return rs.verify(raw,exe,config,role)
        return ni.verify_task(raw,exe,config,role)

class FullServiceTransactionTest(unittest.TestCase):
    setUp=fixture.NativeInstallerTest.setUp
    run_install=fixture.NativeInstallerTest.run_install
    def prepare(self):
        flag=patch.object(ms,'ENABLED',True);flag.start();self.addCleanup(flag.stop)
        self.ops=FullServiceFixture();(self.source/'_internal/GuardDeskService.exe').write_bytes(b'owned service image')
        from guarddesk.endpoint_package import sha
        from guarddesk import __version__
        (self.source/'_internal/agent-release.json').write_text(json.dumps({'format':1,'version':__version__,
            'files':{p.relative_to(self.source).as_posix():sha(p) for p in self.source.rglob('*') if p.is_file() and p.name!='agent-release.json'}}))
    def test_new_full_install_keeps_updater_task_and_native_service_separate(self):
        self.prepare();self.run_install()
        native=self.ops.tasks['GuardDesk-USBControl-'+'a'*24];updater=self.ops.tasks['GuardDesk-AgentUpdater-'+'a'*24]
        self.assertEqual(native['kind'],'remote-service-v1');self.assertIn('_internal',native['binary'])
        ni.verify_task(updater,self.program/'Updater/GuardDesk.exe',self.protected,'updater')
        installed=json.loads((self.protected.parent/'installation.json').read_text())
        self.assertEqual(installed['lifecycle'],'native-service-v1');self.assertIsNone(installed['task'])
        self.assertNotIn('install_profile',json.loads(self.protected.read_text()))
        self.assertIs(json.loads(self.protected.read_text())['remote_native_preview'],True)
    def test_full_build_preserves_existing_explicit_native_opt_out(self):
        self.prepare();self.protected.parent.mkdir(parents=True);self.protected.write_text(json.dumps({**self.settings,'remote_native_preview':False}))
        self.run_install()
        self.assertIs(json.loads(self.protected.read_text())['remote_native_preview'],False)
    def test_missing_service_fails_before_any_installation_mutation(self):
        self.prepare();(self.source/'_internal/GuardDeskService.exe').unlink()
        with self.assertRaises(OSError):self.run_install()
        self.assertEqual(self.ops.events,[])
    def test_failed_native_health_restores_exact_prior_task_and_config(self):
        self.prepare();root=self.protected.parent;root.mkdir(parents=True);self.protected.write_text(json.dumps(self.settings));before=self.protected.read_bytes()
        native=self.program/'USBControl';native.mkdir(parents=True);(native/'GuardDesk.exe').write_bytes(b'owned old native')
        self.ops.tasks['GuardDesk-USBControl-'+'a'*24]=ni.task_body(native/'GuardDesk.exe',self.protected,'native')
        prior=dict(self.ops.tasks);self.ops.fail_health=True
        with self.assertRaises(ni.NativeInstallFailure):self.run_install()
        self.assertEqual(self.ops.tasks,prior);self.assertEqual(self.protected.read_bytes(),before)
        self.assertEqual((native/'GuardDesk.exe').read_bytes(),b'owned old native')

class FullServiceBoundaryTest(unittest.TestCase):
    def test_full_heartbeat_preserves_collectors_but_cannot_spoof_native_diagnostics(self):
        from test_remote_native_broker import NativeRouterTest,PEER
        case=NativeRouterTest();router=case.make()
        case.launcher.snapshot=lambda:{'contexts':[{'phase':'native_transport','worker':{'input_accepted':4,'pixels':'PRIVATE'}}]}
        body={'inventory':{'agent_version':'0.4.94','collectors':{'file_audit':{'state':'collecting'},'native_remote':'SPOOF'}}}
        with patch.object(ms,'ENABLED',True),patch.object(remote_trial,'ENABLED',False):
            router.dispatch({'path':'/api/agent/heartbeat','body':body},PEER)
        sent=case.calls[-1][1]['inventory']['collectors']
        self.assertEqual(sent['file_audit'],{'state':'collecting'})
        self.assertEqual(sent['native_remote']['contexts'][0]['worker'],{'input_accepted':4})
        self.assertNotIn('PRIVATE',str(sent));self.assertNotIn('SPOOF',str(sent))
    def test_updater_uses_fixed_service_or_verified_legacy_task_and_rejects_both(self):
        from types import SimpleNamespace
        from guarddesk.update_native import NativeAdapter
        import guarddesk.update_native as update
        adapter=NativeAdapter.__new__(NativeAdapter);adapter.native=Path('C:/owned/USBControl')
        adapter.agent=SimpleNamespace(config_path=Path('C:/owned/Data')/('a'*24)/'config.json')
        adapter.name='GuardDesk-USBControl-'+'a'*24
        service=Mock(spec=rs.Service)
        with patch.object(ms,'ENABLED',True),patch.object(rs,'Service',return_value=service),patch.object(ni.Windows,'names',return_value=set()),patch.object(update,'protected_tree'),patch.object(update,'task_command') as task:
            expected=rs.description(adapter.native/'GuardDesk.exe',adapter.agent.config_path)
            service.query.return_value=expected;adapter.start({},False)
            service.action.assert_called_once_with(expected,'start');task.assert_not_called()
            with patch.object(ni.Windows,'names',return_value={'\\'+adapter.name}):
                with self.assertRaises(OSError):adapter._validate_task()
            service.query.return_value={**expected,'device_id':'b'*24}
            with self.assertRaises(OSError):adapter._validate_task()
    def test_build_flag_and_remote_profile_are_independent(self):
        exe=Path('C:/owned/GuardDesk.exe')
        with patch.object(ms,'ENABLED',True),patch.object(remote_trial,'ENABLED',False):
            self.assertEqual(ms.image(exe),exe.parent/'_internal/GuardDeskService.exe')
            from guarddesk.endpoint_package import required_files,package_roots
            self.assertIn('_internal/GuardDeskService.exe',required_files());self.assertEqual(package_roots(),('GuardDesk.exe','GuardDeskAgent.exe'))
        with patch.object(ms,'ENABLED',False):
            with self.assertRaises(PermissionError):ms.worker(Path('absent'),Mock())
    def test_only_standard_profile_enters_full_control_worker(self):
        stop=Mock();worker=Mock()
        with patch.object(ms,'ENABLED',True),patch.object(remote_trial,'ENABLED',False),patch.object(ni,'read_json',return_value={'install_profile':'standard'}),patch('guarddesk.native_usb.UsbWorker',return_value=worker) as factory,patch('guarddesk.machine_agent.eligible',return_value=True):
            ms.worker(Path('owned'),stop);worker.run.assert_called_once_with(stop,extended=True)
        with patch.object(ms,'ENABLED',True),patch.object(remote_trial,'ENABLED',False),patch.object(ni,'read_json',return_value={'install_profile':remote_trial.PROFILE}),patch('guarddesk.native_usb.UsbWorker') as factory:
            with self.assertRaises(ValueError):ms.worker(Path('owned'),stop)
            factory.assert_not_called()
    def test_uninstalled_full_image_never_starts_controls(self):
        worker=Mock()
        with patch.object(ms,'ENABLED',True),patch.object(remote_trial,'ENABLED',False),patch.object(ni,'read_json',return_value={}),patch('guarddesk.native_usb.UsbWorker',return_value=worker),patch('guarddesk.machine_agent.eligible',return_value=False):
            with self.assertRaises(PermissionError):ms.worker(Path('owned'),Mock())
            worker.run.assert_not_called()
    def test_real_adapter_never_treats_updater_as_native_service(self):
        exe=Path('C:/owned/Updater/GuardDesk.exe');config=Path('C:/owned/Data')/('a'*24)/'config.json';name='GuardDesk-AgentUpdater-'+'a'*24
        service=Mock(spec=rs.Service);service.query.return_value={'device_id':'a'*24}
        with patch.object(rs,'Service',return_value=service),patch.object(ni.Windows,'query',return_value=b'updater xml') as query,patch.object(ni.Windows,'start') as start,patch.object(ni.Windows,'delete') as delete,patch.object(ni.Windows,'register') as register:
            ops=rs.platform();self.assertEqual(ops.query(name),b'updater xml');ops.start(name);ops.delete(name);ops.register(name,b'xml',Path('owned'))
            start.assert_called_once_with(name);delete.assert_called_once_with(name);register.assert_called_once()
            service.query.assert_not_called();service.action.assert_not_called()

if __name__=='__main__':unittest.main()
