"""No UAC, real install, SYSTEM tasks or company policies are changed."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from unittest.mock import patch
from guarddesk import __version__
from guarddesk import usb_install as usb
from guarddesk.endpoint_package import files, build, REQUIRED
import test_endpoint_setup as fixtures
from test_endpoint_setup import program


class InstallerDiagnosticsTest(unittest.TestCase):
    def test_policy_error_before_script_start_and_secret_redaction(self):
        report=usb.diagnostic(1,'not digitally signed. PSSecurityException secret-value Bearer bearer-value',{'token':'secret-value'})
        self.assertEqual(report['code'],'script_policy');self.assertEqual(report['stage'],'powershell_start')
        self.assertNotIn('secret-value',report['detail']);self.assertNotIn('bearer-value',report['detail'])
        self.assertNotIn('Install-Endpoint.ps1',str(usb.InstallError(report)))
        report=usb.diagnostic(1,'GUARDDESK_STAGE=protect_directories\nAccess is denied')
        self.assertEqual(report['code'],'access_denied');self.assertEqual(report['stage'],'protect_directories')
        self.assertEqual(usb.diagnostic(1,'CERTIFICATE_VERIFY_FAILED')['code'],'connection')
        self.assertLessEqual(len(usb.diagnostic(1,'z'*100000)['detail']),5000)

    def test_no_false_success_from_invalid_or_mismatched_result(self):
        good=usb.diagnostic(0,'complete');self.assertEqual(usb.validate_report(good,0),good)
        for report,code in [(None,0),({},0),({**good,'exit_code':1},0),({**good,'code':[]},0),({**good,'detail':'x'*5001},0),({**good,'code':'native_failed'},0),(good,1)]:
            with self.assertRaises(OSError):usb.validate_report(report,code)

    def test_non_admin_helper_never_opens_channel_or_runs_script(self):
        with patch('guarddesk.windows_privilege.is_admin',return_value=False),patch('guarddesk.installer_channel.connect') as connect,patch.object(usb,'run_script') as run:
            with self.assertRaises(PermissionError):usb.helper('not-read','Install','not-opened')
            connect.assert_not_called();run.assert_not_called()

    @unittest.skipUnless(os.name=='nt','Windows local diagnostic pipe')
    def test_helper_returns_fixed_source_result_over_real_pipe_without_installing(self):
        from guarddesk.installer_channel import Receiver
        with tempfile.TemporaryDirectory() as temp:
            config=Path(temp)/'config.json';config.write_text(json.dumps({'device_id':'d'*24,'token':'PRIVATE-FIXTURE'}))
            receiver=Receiver();self.addCleanup(receiver.close)
            report=usb.diagnostic(1,'Access is denied')
            with patch('guarddesk.windows_privilege.is_admin',return_value=True),patch.object(usb.sys,'frozen',True,create=True),patch.object(usb,'run_native',return_value=report) as run:
                self.assertEqual(usb.helper(config,'Install',receiver.name),1)
                self.assertEqual(run.call_args.args,(config.resolve(),'Install',Path(sys.executable).resolve().parent))
            self.assertEqual(receiver.poll(),report)

    def test_capture_early_error_and_large_output_uses_bounded_redacted_tail(self):
        with tempfile.TemporaryDirectory() as temp:
            config=Path(temp)/'config.json';config.write_text(json.dumps({'token':'VERY-PRIVATE-TOKEN'}))
            class Child:
                stdout=io.BytesIO(b'x'*100000+b'\nGUARDDESK_STAGE=initial_policy\nConnectionError VERY-PRIVATE-TOKEN')
                def wait(self):return 1
            with patch.object(usb.subprocess,'Popen',return_value=Child()) as start,patch.object(usb,'powershell_path',return_value=Path('powershell.exe')):
                report=usb.run_script(config,'Install',Path(temp))
            self.assertEqual(report['stage'],'initial_policy');self.assertEqual(report['code'],'connection')
            self.assertNotIn('VERY-PRIVATE-TOKEN',report['detail']);self.assertLess(len(report['detail']),5000)
            args=start.call_args.args[0];self.assertIn('-File',args);self.assertNotIn('-ExecutionPolicy',args)
            self.assertNotIn('VERY-PRIVATE-TOKEN',' '.join(args))

    @unittest.skipUnless(os.name=='nt','Windows pipe API')
    def test_real_local_pipe_roundtrip_after_client_exit_and_input_rejection(self):
        from guarddesk.installer_channel import Receiver,connect,send,pipe_name
        for name in ['C:\\result.json',r'\\remote\pipe\test',r'\\.\pipe\arbitrary','']:
            with self.assertRaises(ValueError):pipe_name(name)
        r=Receiver();self.addCleanup(r.close)
        self.assertIsNone(r.poll())
        result=usb.diagnostic(1,'GUARDDESK_STAGE=register_tasks\n排程錯誤')
        def writer():
            channel=connect(r.name)
            try:send(channel,result)
            finally:channel[0].CloseHandle(channel[1])
        thread=threading.Thread(target=writer);thread.start();thread.join(5)
        deadline=time.monotonic()+3;value=None
        while value is None and time.monotonic()<deadline:value=r.poll();time.sleep(.01)
        self.assertEqual(value,result)

    @unittest.skipUnless(os.name=='nt','Windows PowerShell 5.1')
    def test_actual_powershell_policy_failure_is_captured_without_running_script(self):
        # Tighten only this synthetic child process to Restricted; never bypass
        # or alter the user's/machine's execution policy or run our installer.
        with tempfile.TemporaryDirectory() as temp:
            script=Path(temp)/'fixture.ps1';script.write_bytes(b'\xef\xbb\xbfWrite-Output "SHOULD-NOT-EXECUTE"')
            config=Path(temp)/'config.json';config.write_text('{}')
            real_popen=subprocess.Popen
            def restricted(args,**kwargs):return real_popen([args[0],'-ExecutionPolicy','Restricted',*args[1:]],**kwargs)
            with patch.object(usb,'SCRIPT',script),patch.object(usb.subprocess,'Popen',side_effect=restricted):report=usb.run_script(config,'Install',Path(temp))
            self.assertNotEqual(report['exit_code'],0,report)
            self.assertEqual(report['code'],'script_policy',report)

    @unittest.skipUnless(os.name=='nt','Windows PowerShell 5.1')
    def test_worker_health_checks_version_time_and_exact_owned_pid(self):
        code=r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($env:GUARDDESK_INSTALL_TEST_SCRIPT,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
$node=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Wait-WorkerHealth'},$true)[0]
. ([scriptblock]::Create($node.Extent.Text.Replace('.AddSeconds(45)','.AddMilliseconds(10)')))
function Test-Path {param($LiteralPath) return $true}
function Assert-NoReparse {param($path)}
function Get-Item {param($LiteralPath) [pscustomobject]@{Length=100}}
function Get-Content {param($LiteralPath,[switch]$Raw,$Encoding) return $script:fixture}
function Get-InstalledWorkers {param($exe) [pscustomobject]@{ProcessId=123}}
function Start-Sleep {param($Milliseconds)}
$script:fixture='{"version":"test","time":100,"pid":123}'
Wait-WorkerHealth 'fixture.json' 'test' 'fixture.exe' 100
foreach($invalid in @('{"version":"old","time":100,"pid":123}','{"version":"test","time":99,"pid":123}','{"version":"test","time":100,"pid":456}')){
    $script:fixture=$invalid;$refused=$false
    try {Wait-WorkerHealth 'fixture.json' 'test' 'fixture.exe' 100} catch {$refused=$true}
    if(-not $refused){throw 'Invalid/stale/unowned health accepted'}
}
Write-Output 'health-check-passed'
'''
        env={**os.environ,'GUARDDESK_INSTALL_TEST_SCRIPT':str(usb.SCRIPT)}
        result=subprocess.run([str(usb.powershell_path()),'-NoLogo','-NoProfile','-NonInteractive','-Command',code],env=env,capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'));self.assertIn(b'health-check-passed',result.stdout)


class InstallerPackageValidationTest(unittest.TestCase):
    def test_missing_script_changed_runtime_and_mixed_version_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            for case in ('script','runtime','version'):
                source=program(Path(temp)/case)
                if case=='script':(source/'_internal/guarddesk/windows/install-usb.ps1').unlink()
                elif case=='runtime':(source/'_internal/runtime.dll').write_bytes(b'tampered')
                else:
                    path=source/'_internal/agent-release.json';data=json.loads(path.read_text());data['version']='0.4.19';path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):files(source)


class DownloadValidationTest(unittest.TestCase):
    setUp = fixtures.EndpointDownloadTest.setUp
    tearDown = fixtures.EndpointDownloadTest.tearDown
    api = fixtures.EndpointDownloadTest.api
    def test_download_rejects_incomplete_server_with_actionable_error(self):
        from guarddesk.server_setup import create
        created=create(self.root/'setup','guarddesk.test','mis','7',exe=sys.executable)
        (self.root/'Endpoint-Connection.zip').write_bytes(Path(created['connection_bundle']).read_bytes())
        source=program(self.root/'program');(source/'_internal/guarddesk/windows/install-usb.ps1').unlink()
        with patch('guarddesk.endpoint_package.application_directory',return_value=source):
            with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/endpoint-package',{})
        self.assertEqual(denied.exception.code,409)
        self.assertIn('Server',json.loads(denied.exception.read())['error'])
        self.assertFalse(list(self.root.glob('guarddesk-endpoint-*')))


if __name__=='__main__':unittest.main()
