"""Native installer transactions use owned fixture paths and fake OS controls."""
import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
import ctypes
import time
from contextlib import contextmanager
from unittest.mock import patch
import xml.etree.ElementTree as ET
from guarddesk import native_installer as ni, __version__
from guarddesk import usb_install as usb
from test_endpoint_setup import program


class InstallerHealthTest(unittest.TestCase):
    def test_accessible_image_does_not_enable_privilege(self):
        with patch.object(ni,'process_image',return_value=Path('owned.exe')),patch.object(ni,'system_query_scope') as scope:
            self.assertEqual(ni.health_image(123),Path('owned.exe'));scope.assert_not_called()
    def test_access_denied_retries_only_within_scope_and_always_unwinds(self):
        for result in (Path('owned.exe'),ctypes.WinError(5)):
            events=[]
            @contextmanager
            def scope():
                events.append('enter')
                try:yield
                finally:events.append('exit')
            with patch.object(ni,'process_image',side_effect=[ctypes.WinError(5),result]) as query,patch.object(ni,'system_query_scope',scope):
                if isinstance(result,Exception):
                    with self.assertRaises(PermissionError):ni.health_image(123)
                else:self.assertEqual(ni.health_image(123),result)
                self.assertEqual(query.call_args_list[0].args,(123,));self.assertEqual(query.call_args_list[1].args,(123,))
            self.assertEqual(events,['enter','exit'])
    def test_other_query_failure_never_uses_privilege(self):
        with patch.object(ni,'process_image',side_effect=ctypes.WinError(87)),patch.object(ni,'system_query_scope') as scope:
            with self.assertRaises(OSError):ni.health_image(123)
            scope.assert_not_called()
    def test_standard_user_cannot_enter_query_scope(self):
        with patch('guarddesk.windows_privilege.is_admin',return_value=False):
            with self.assertRaises(PermissionError):
                with ni.system_query_scope():self.fail('non-admin entered')
    def test_health_keeps_version_fresh_time_and_exact_image_requirements(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'native-health.json';path.write_text('{}');exe=Path(temp)/'GuardDesk.exe'
            for fields,image in [({'version':'old'},exe),({'time':99},exe),({'time':float('nan')},exe),({'time':float('inf')},exe),({},Path(temp)/'other.exe')]:
                value={'version':__version__,'time':100,'pid':123,**fields}
                with self.subTest(fields=fields,image=image),patch.object(ni,'read_json',return_value=value),patch.object(ni,'health_image',return_value=image),patch.object(ni.time,'monotonic',side_effect=[0,0,46]),patch.object(ni.time,'sleep'):
                    with self.assertRaises(OSError):ni.Windows().health(path,__version__,exe,100)
            with patch.object(ni,'read_json',return_value={'version':__version__,'time':100,'pid':123}),patch.object(ni,'health_image',return_value=exe):
                ni.Windows().health(path,__version__,exe,100)
    def test_health_reports_access_error_instead_of_silent_timeout(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'native-health.json';path.write_text('{}')
            with patch.object(ni,'read_json',return_value={'version':__version__,'time':100,'pid':123}),patch.object(ni,'health_image',side_effect=ctypes.WinError(5)),patch.object(ni.time,'monotonic',side_effect=[0,0,46]),patch.object(ni.time,'sleep'):
                with self.assertRaisesRegex(OSError,'Windows 5'):ni.Windows().health(path,__version__,Path(temp)/'GuardDesk.exe',100)
    def test_privilege_restore_failure_is_fatal_instead_of_retried(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'native-health.json';path.write_text('{}')
            with patch.object(ni,'read_json',return_value={'version':__version__,'time':100,'pid':123}),patch.object(ni,'health_image',side_effect=SystemExit('scope restoration failed')) as query:
                with self.assertRaises(SystemExit):ni.Windows().health(path,__version__,Path(temp)/'GuardDesk.exe',100)
                query.assert_called_once_with(123)


class FakeWindows:
    def __init__(self):
        self.tasks={};self.events=[];self.fail_once=False;self.fail_health=False;self.fail_stop=False;self.corrupt=False
    def protect(self,path,create=False):
        if create:path.mkdir(exist_ok=True)
        if self.corrupt and path.name=='GuardDeskAgent.exe':path.write_bytes(b'changed during copy');self.corrupt=False
    def tree(self,path):pass
    def public_runtime(self,path):self.events.append(('public_runtime',path))
    def names(self):return {'\\'+name for name in self.tasks}
    def query(self,name):return self.tasks[name]
    def stop(self,name,exe):
        self.events.append(('stop',name))
        if self.fail_stop:raise OSError('stop failed')
    def start(self,name):self.events.append(('start',name))
    def delete(self,name):self.events.append(('delete',name));self.tasks.pop(name,None)
    def register(self,name,raw,directory):self.events.append(('register',name));self.tasks[name]=raw
    def write(self,path,raw):path.write_bytes(raw)
    def invoke(self,exe,*args):
        self.events.append(('invoke',args))
        if args==('component-info',):return b'{"version":"0.4.19"}'
        if self.fail_once and '--once' in args:raise OSError('fixture initial policy failed')
        return b'{}'
    def health(self,path,version,exe,started):
        self.events.append(('health',path.name))
        if self.fail_health:raise OSError('fixture startup failed')


class NativeInstallerTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.program=self.root/'Program';self.data=self.root/'Data'
        self.source=program(self.root/'source');self.user=self.root/'User';self.user.mkdir()
        self.ca=self.user/'ca.pem';self.ca.write_text('PUBLIC CA FIXTURE ONLY')
        self.settings={'server':'https://fixture.invalid','token':'PRIVATE-FIXTURE','device_id':'a'*24,'watch':str(self.user/'Documents'),'ca':str(self.ca),'update_key':base64.b64encode(b'x'*32).decode()}
        self.config=self.user/'config.json';self.config.write_text(json.dumps(self.settings))
        self.ops=FakeWindows()
        def rename_fixture(source,target):
            # Preserve the production bounded sharing/access retry while the
            # fixture OS adapter supplies its own ACL boundary.
            from guarddesk import update_windows
            with patch('guarddesk.update_native.protected_tree'):
                return rename_protected(source,target)
        from guarddesk.update_windows import rename_protected
        self.patches=[patch.object(ni,'folder',side_effect=lambda id:self.program if id==38 else self.data),patch('guarddesk.windows_privilege.is_admin',return_value=True),patch('guarddesk.update_windows.rename_protected',side_effect=rename_fixture)]
        for p in self.patches:p.start();self.addCleanup(p.stop)
        self.protected=self.data/'USBControl'/('a'*24)/'config.json'
    def run_install(self,action='Install'):return ni.install(self.config,action,self.source,self.ops)
    def old_install(self):
        root=self.protected.parent;root.mkdir(parents=True)
        self.protected.write_text(json.dumps({**self.settings,'watch':'old-unused'}))
        (root/'company-ca.pem').write_text('OLD CA FIXTURE')
        (root/'offline-queue').write_bytes(b'preserve queue')
        for role,folder in [('native','USBControl'),('updater','Updater')]:
            target=self.program/folder;target.mkdir(parents=True,exist_ok=True);(target/'GuardDesk.exe').write_bytes(b'old '+role.encode())
            name=('GuardDesk-USBControl-' if role=='native' else 'GuardDesk-AgentUpdater-')+'a'*24
            self.ops.tasks[name]=ni.task_body(target/'GuardDesk.exe',self.protected,role)
    def test_success_uses_verified_complete_program_trees_and_fixed_tasks(self):
        result=self.run_install();self.assertEqual(result['status'],'installer_completed')
        self.assertEqual(len(self.ops.tasks),2)
        for role,name in [('native','USBControl'),('updater','Updater')]:
            target=self.program/name
            self.assertEqual(ni.source_files(target)[0],ni.source_files(self.source)[0])
        saved=json.loads(self.protected.read_text());self.assertEqual(saved['token'],self.settings['token']);self.assertEqual(saved['device_id'],self.settings['device_id'])
        self.assertEqual(json.loads((self.protected.parent/'install-transaction.json').read_text())['phase'],'complete')
        self.assertEqual([e[1] for e in self.ops.events if e[0]=='health'],['native-health.json','broker-health.json'])
    def browser_trust_fixture(self):
        from test_browser_trust import fixture_ca
        from guarddesk.browser_host import extension_id
        from guarddesk import browser_trust,browser_deployment,update_packages
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        anchor=Ed25519PrivateKey.generate();self.ca.write_bytes(fixture_ca())
        self.settings['update_key']=update_packages.public_key(anchor)
        browser={'extension_id':extension_id(),'chrome_update_url':self.settings['server']+'/browser-extension/updates.xml','edge_update_url':self.settings['server']+'/browser-extension/updates.xml'}
        self.settings.update(browser_deployment=browser,browser_deployment_authorization=browser_deployment.authorize(browser,anchor),browser_trust=browser_trust.authorize(self.settings['server'],self.ca.read_bytes(),anchor))
        self.config.write_text(json.dumps(self.settings))

    def test_browser_trust_same_elevated_transaction_precedes_native_start_and_policy(self):
        self.browser_trust_fixture();self.run_install()
        commands=[e[1] for e in self.ops.events if e[0]=='invoke']
        trust=('browser-trust','--config',self.protected,'--action','apply')
        policy=('browser-policy','--config',self.protected,'--action','apply')
        self.assertLess(commands.index(trust),commands.index(policy))
        self.assertLess(commands.index(trust),next(i for i,c in enumerate(commands) if '--once' in c))
        self.assertEqual(json.loads(self.protected.read_text())['browser_trust'],self.settings['browser_trust'])

    def test_browser_trust_rollback_only_restores_new_owned_ledger(self):
        self.browser_trust_fixture();invoke=self.ops.invoke
        def call(exe,*args):
            if args[0]=='browser-trust' and args[-1]=='apply':(self.protected.parent/'browser-trust-owned.json').write_text('{}')
            return invoke(exe,*args)
        self.ops.invoke=call;self.ops.fail_once=True
        with self.assertRaises(ni.NativeInstallFailure):self.run_install()
        commands=[e[1] for e in self.ops.events if e[0]=='invoke']
        self.assertIn(('browser-trust','--config',self.protected,'--action','restore'),commands)

    def test_browser_trust_wrong_ca_refused_before_any_privileged_changes(self):
        self.browser_trust_fixture()
        from test_browser_trust import fixture_ca
        self.ca.write_bytes(fixture_ca())
        with self.assertRaisesRegex(ValueError,'CA differs'):self.run_install()
        self.assertEqual(self.ops.events,[])
    def test_repair_retains_identity_queue_and_prior_binary_backups(self):
        self.old_install();result=self.run_install()
        self.assertEqual((self.protected.parent/'offline-queue').read_bytes(),b'preserve queue')
        self.assertEqual(len(result['backups_retained']),2)
        self.assertTrue(any((Path(p)/'GuardDesk.exe').read_bytes()==b'old native' for p in result['backups_retained']))
        self.assertEqual(json.loads(self.protected.read_text())['device_id'],'a'*24)
    def test_browser_deployment_inside_same_native_install_preserved_on_repair(self):
        from guarddesk.browser_host import extension_id
        browser={'extension_id':extension_id(),'chrome_update_url':'https://fixture.test:8787/browser-extension/updates.xml','edge_update_url':'https://fixture.test:8787/browser-extension/updates.xml'}
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from guarddesk.browser_deployment import authorize
        from guarddesk.update_packages import public_key
        anchor=Ed25519PrivateKey.generate();self.settings['update_key']=public_key(anchor)
        self.settings['browser_deployment']=browser;self.settings['browser_deployment_authorization']=authorize(browser,anchor);self.config.write_text(json.dumps(self.settings))
        correct=dict(self.settings);self.settings.pop('browser_deployment_authorization');self.config.write_text(json.dumps(self.settings))
        with self.assertRaisesRegex(ValueError,'授權簽章'):self.run_install()
        self.assertEqual(self.ops.events,[])
        self.settings=correct;self.config.write_text(json.dumps(self.settings));self.run_install()
        self.assertEqual(json.loads(self.protected.read_text())['browser_deployment'],browser)
        commands=[e[1] for e in self.ops.events if e[0]=='invoke']
        self.assertIn(('browser-policy','--config',self.protected,'--action','apply'),commands)
        # An older connection package must not silently erase an owned source.
        self.settings.pop('browser_deployment');self.config.write_text(json.dumps(self.settings));self.run_install()
        self.assertEqual(json.loads(self.protected.read_text())['browser_deployment'],browser)
        self.settings['browser_deployment']={**browser,'chrome_update_url':'https://changed.test/updates.xml'};self.config.write_text(json.dumps(self.settings))
        before=list(self.ops.events)
        with self.assertRaisesRegex(OSError,'部署來源'):self.run_install()
        self.assertEqual(self.ops.events,before)
    def test_initial_apply_failure_restores_previous_programs_settings_and_tasks(self):
        self.old_install();before=self.protected.read_bytes();tasks=dict(self.ops.tasks);self.ops.fail_once=True
        with self.assertRaises(OSError):self.run_install()
        self.assertEqual(self.protected.read_bytes(),before);self.assertEqual(self.ops.tasks,tasks)
        self.assertEqual((self.program/'USBControl/GuardDesk.exe').read_bytes(),b'old native')
        self.assertEqual((self.program/'Updater/GuardDesk.exe').read_bytes(),b'old updater')
        self.assertEqual(json.loads((self.protected.parent/'install-transaction.json').read_text())['phase'],'rolled_back')
    def test_new_install_health_failure_removes_new_tasks_and_attempts_restore(self):
        self.ops.fail_health=True
        with self.assertRaises(OSError):self.run_install()
        self.assertEqual(self.ops.tasks,{})
        self.assertTrue(any(e[0]=='invoke' and '--restore' in e[1] for e in self.ops.events))
        self.assertFalse((self.program/'USBControl').exists())
    def test_rollback_requires_old_worker_health_and_preserves_original_failure_stage(self):
        self.old_install();self.ops.fail_once=True;self.ops.fail_health=True
        with self.assertRaises(ni.NativeInstallFailure) as error:self.run_install()
        self.assertEqual(error.exception.stage,'initial_policy')
        self.assertIn('回復未確認完成',str(error.exception))
        self.assertNotIn(json.loads((self.protected.parent/'install-transaction.json').read_text())['phase'],('complete','rolled_back'))
        self.assertEqual((self.program/'USBControl/GuardDesk.exe').read_bytes(),b'old native')
    def test_successful_rollback_diagnostic_retains_original_failure_stage(self):
        self.old_install();self.ops.fail_once=True
        with self.assertRaises(ni.NativeInstallFailure) as error:self.run_install()
        self.assertEqual(error.exception.stage,'initial_policy')
        self.assertIn('GUARDDESK_STAGE=initial_policy',str(error.exception))
    def test_failed_stop_during_rollback_retains_new_program_and_journal(self):
        self.ops.fail_health=True;self.ops.fail_stop=True
        with self.assertRaises(ni.NativeInstallFailure) as error:self.run_install()
        self.assertEqual(error.exception.stage,'register_tasks',str(error.exception))
        self.assertEqual(error.exception.recovery_failures,[{'operation':'stop_or_delete_native','error_type':'OSError'}])
        self.assertIn('GUARDDESK_RECOVERY=',str(error.exception))
        self.assertTrue((self.program/'USBControl/GuardDesk.exe').exists())
        self.assertNotIn(json.loads((self.protected.parent/'install-transaction.json').read_text())['phase'],('complete','rolled_back'))
    def test_switch_failure_restores_both_directories(self):
        self.old_install();real=Path.rename
        def failed(source,target):
            if 'Updater.install-stage-' in source.name:raise OSError('fixture rename failure')
            return real(source,target)
        with patch('guarddesk.update_windows.rename_protected',side_effect=failed):
            with self.assertRaises(OSError):self.run_install()
        self.assertEqual((self.program/'USBControl/GuardDesk.exe').read_bytes(),b'old native')
        self.assertEqual((self.program/'Updater/GuardDesk.exe').read_bytes(),b'old updater')
    def test_corrupt_copy_does_not_stop_existing_workers(self):
        self.old_install();self.ops.corrupt=True
        with self.assertRaises(OSError):self.run_install()
        self.assertFalse(any(e[0]=='stop' for e in self.ops.events))
        self.assertEqual((self.program/'USBControl/GuardDesk.exe').read_bytes(),b'old native')
    def test_update_started_during_staging_is_not_overwritten(self):
        self.old_install();original=self.ops.tree
        def start_update(path):
            original(path)
            if '.install-stage-' in path.name:
                updates=self.protected.parent/'updates';updates.mkdir(exist_ok=True)
                (updates/'updater-refresh.json').write_text('{"phase":"switching"}')
        self.ops.tree=start_update
        with self.assertRaises(ni.NativeInstallFailure):self.run_install()
        self.assertFalse(any(e[0]=='stop' for e in self.ops.events))
        self.assertEqual((self.program/'USBControl/GuardDesk.exe').read_bytes(),b'old native')
        self.assertEqual((self.program/'Updater/GuardDesk.exe').read_bytes(),b'old updater')
    def test_update_started_while_stopping_prevents_program_switch(self):
        self.old_install();original=self.ops.stop
        def start_update(name,exe):
            original(name,exe)
            updates=self.protected.parent/'updates';updates.mkdir(exist_ok=True)
            (updates/'transaction-native.json').write_text('{"phase":"switching"}')
        self.ops.stop=start_update
        with self.assertRaises(ni.NativeInstallFailure) as error:self.run_install()
        self.assertEqual(error.exception.stage,'stopping')
        self.assertEqual((self.program/'USBControl/GuardDesk.exe').read_bytes(),b'old native')
        self.assertEqual((self.program/'Updater/GuardDesk.exe').read_bytes(),b'old updater')
    def test_other_device_or_wrong_task_identity_never_overwritten(self):
        for scenario in ('other','wrong'):
            with self.subTest(scenario=scenario):
                self.ops.tasks={}
                if scenario=='other':self.ops.tasks['guarddesk-usbcontrol-'+'b'*24]=b'unrelated'
                else:self.ops.tasks['GuardDesk-USBControl-'+'a'*24]=ni.task_body(self.program/'USBControl/GuardDesk.exe',self.user/'wrong-config.json','native')
                before=dict(self.ops.tasks)
                with self.assertRaises(OSError):self.run_install()
                self.assertEqual(self.ops.tasks,before);self.assertFalse(any(e[0]=='stop' for e in self.ops.events))
    def test_pending_transaction_key_change_and_identity_change_fail_before_stopping(self):
        self.old_install()
        for case in ('key','token','transaction'):
            old=copy.deepcopy(self.settings)
            if case=='key':old['update_key']=base64.b64encode(b'y'*32).decode()
            if case=='token':old['token']='OTHER-FIXTURE'
            self.protected.write_text(json.dumps(old))
            journal=self.protected.parent/'install-transaction.json'
            if case=='transaction':journal.write_text('{"phase":"switching"}')
            with self.assertRaises(OSError):self.run_install()
            self.assertFalse(any(e[0]=='stop' for e in self.ops.events))
            journal.unlink(missing_ok=True)
    def test_uninstall_restores_before_removing_tasks_and_retains_files(self):
        self.old_install();self.run_install('Uninstall')
        self.assertEqual(self.ops.tasks,{})
        self.assertEqual((self.protected.parent/'offline-queue').read_bytes(),b'preserve queue')
        invoke=next(i for i,e in enumerate(self.ops.events) if e[0]=='invoke')
        delete=next(i for i,e in enumerate(self.ops.events) if e[0]=='delete')
        self.assertLess(invoke,delete)
    def test_status_does_not_write_stop_or_enroll(self):
        self.old_install();self.ops.events=[];self.assertTrue(self.run_install('Status')['installed'])
        self.assertEqual(self.ops.events,[])
    def test_admin_guard_precedes_all_os_mutations(self):
        with patch('guarddesk.windows_privilege.is_admin',return_value=False):
            with self.assertRaises(PermissionError):self.run_install()
        self.assertFalse(self.program.exists());self.assertEqual(self.ops.events,[])
    def test_changed_source_missing_file_and_invalid_manifest_fail_before_os_changes(self):
        (self.source/'GuardDesk.exe').write_bytes(b'tampered')
        with self.assertRaises(ValueError):self.run_install()
        self.assertFalse(self.program.exists());self.assertEqual(self.ops.events,[])
    def test_native_entry_never_calls_legacy_powershell_installer(self):
        with patch('guarddesk.native_installer.install',return_value={'status':'installer_completed'}) as install,patch.object(usb,'run_script',side_effect=AssertionError('legacy script must not execute')):
            report=usb.run_native(self.config,'Install',self.source)
            self.assertEqual(report['exit_code'],0);install.assert_called_once()
    def test_transaction_does_not_depend_on_process_script_policy(self):
        with patch.dict(os.environ,{'PSExecutionPolicyPreference':'Restricted'}),patch.object(usb,'run_script',side_effect=AssertionError('PowerShell installer must not run')):
            self.assertEqual(self.run_install()['status'],'installer_completed')
    def test_task_xml_escapes_paths_and_rejects_weaker_identity_or_other_action(self):
        exe=self.user/'中文 & tools/GuardDesk.exe';cfg=self.user/'user & data/config.json'
        for role in ('native','updater'):
            raw=ni.task_body(exe,cfg,role);ni.verify_task(raw,exe,cfg,role)
            weakened=raw.decode('utf-16').replace('S-1-5-18','S-1-5-32-545').encode('utf-16')
            with self.assertRaises(OSError):ni.verify_task(weakened,exe,cfg,role)
            with self.assertRaises(OSError):ni.verify_task(raw,exe,self.user/'different.json',role)


@unittest.skipUnless(os.name=='nt','Windows executable image locks')
class InstallerImageLockTest(unittest.TestCase):
    def test_running_image_blocks_exclusive_access_and_same_name_elsewhere_is_ignored(self):
        import subprocess,time
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'fixture.cs';exe=root/'GuardDeskInstallerLockFixture.exe'
            source.write_text('using System; using System.Threading; class Program {static void Main(string[] a){Console.WriteLine("ready");Thread.Sleep(int.Parse(a[0]));}}')
            compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
            compiled=subprocess.run([str(compiler),'/nologo','/target:exe','/out:'+str(exe),str(source)],capture_output=True,timeout=30)
            self.assertEqual(compiled.returncode,0,compiled.stdout+compiled.stderr)
            other=root/'other';other.mkdir();other_exe=other/exe.name;other_exe.write_bytes(exe.read_bytes());original=exe.read_bytes()
            first=subprocess.Popen([str(exe),'700'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            second=subprocess.Popen([str(other_exe),'1800'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                self.assertEqual(first.stdout.readline().strip(),'ready');self.assertEqual(second.stdout.readline().strip(),'ready')
                with self.assertRaises(OSError):ni.wait_image_unmapped(exe,timeout=.05)
                ni.wait_image_unmapped(exe,timeout=3)
                self.assertIsNone(second.poll());self.assertEqual(exe.read_bytes(),original)
                with self.assertRaises(OSError):ni.wait_image_unmapped(other_exe,timeout=.05)
                second.wait(timeout=3);ni.wait_image_unmapped(other_exe,timeout=1)
            finally:
                for process in (first,second):
                    if process.poll() is None:process.terminate()
                    process.communicate(timeout=5)


if __name__=='__main__':unittest.main()
