import copy
import json
import os
import subprocess
import time
import unittest
from pathlib import Path
import urllib.error
from unittest.mock import patch
import test_system
from guarddesk.native_usb import UsbWorker,readback_matches
from guarddesk.windows_controls import WindowsControls
from guarddesk.single_instance import machine_instance


class NativeUsbTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent
    publish=test_system.SystemTest.publish

    def test_policy_follows_effective_device_assignment(self):
        agent,eid,_=self.make_agent()
        p=self.api('/api/policy-sets',{'name':'USB readonly','enabled':True,'overrides':{'usb_mode':'read_only'}})
        body={'set_id':p['id'],'target_type':'device','target_id':eid,'priority':100,'enabled':True}
        preview=self.api('/api/assignments/preview',body);self.api('/api/assignments',{**body,'expected_generation':preview['generation']})
        packet=agent.call('/api/agent/native-usb-policy',{})
        self.assertEqual(packet['usb_mode'],'read_only');self.assertEqual(set(packet),{'device_id','version','usb_mode'});self.assertEqual(packet['device_id'],eid)

    def test_status_is_independent_from_ordinary_agent_heartbeat(self):
        agent,eid,_=self.make_agent();self.publish(usb_mode='read_only')
        packet=agent.call('/api/agent/native-usb-policy',{})
        report={**packet,'status':'configured_replug_required','registry':{'Deny_Read':0,'Deny_Write':1},'worker_version':'test'}
        agent.call('/api/agent/native-usb-status',report);agent.call('/api/agent/native-usb-status',report)
        agent.feature_status={'windows':{'status':'not_installed'}};agent.heartbeat()
        device=self.api('/api/state')['devices'][0]
        self.assertEqual(device['inventory']['collectors']['windows']['status'],'not_installed')
        self.assertTrue(device['native_usb']['verified_readback']);self.assertTrue(device['native_usb']['fresh']);self.assertTrue(device['native_usb']['matches_policy'])
        events=self.api('/api/events?device='+eid)['items']
        self.assertEqual(sum(e['kind']=='usb.native_status' for e in events),1)
        self.publish(usb_mode='block');detail=self.api('/api/device-detail?device_id='+eid)
        self.assertFalse(detail['device']['native_usb']['matches_policy'])
        with self.store.connect() as db:db.execute('UPDATE native_usb_status SET received=?',(time.time()-121,))
        self.assertFalse(self.api('/api/state')['devices'][0]['native_usb']['fresh'])

    def test_report_validation_and_device_revocation(self):
        agent,eid,_=self.make_agent()
        for registry in [{'Deny_Write':True},{'Deny_Write':2},{'arbitrary':'bad'}]:
            with self.assertRaises(ConnectionError):agent.call('/api/agent/native-usb-status',{'version':1,'usb_mode':'read_only','status':'configured_replug_required','registry':registry})
        self.api('/api/devices/revoke',{'device_id':eid})
        with self.assertRaises(ConnectionError):agent.call('/api/agent/native-usb-policy',{})

    def test_worker_reuses_protected_cache_offline_without_default_allow(self):
        agent,eid,_=self.make_agent();self.publish(usb_mode='read_only');worker=UsbWorker(agent.config_path)
        with patch('guarddesk.native_usb.is_admin',return_value=True),patch.object(worker.controls,'apply_usb',return_value={'status':'configured_replug_required','registry':{'Deny_Read':0,'Deny_Write':1}}) as apply:
            worker.cycle(require_online=True)
            with patch.object(worker.agent,'call',side_effect=ConnectionError('offline')):report=worker.cycle()
            self.assertEqual(report['usb_mode'],'read_only');self.assertEqual(apply.call_args.args,('read_only',))
            with worker.agent.db() as db:db.execute("DELETE FROM state WHERE key='native_usb_policy'")
            apply.reset_mock()
            with patch.object(worker.agent,'call',side_effect=ConnectionError('offline')):
                with self.assertRaises(ConnectionError):worker.cycle()
            apply.assert_not_called()

    def test_non_admin_fails_before_fetch_or_apply(self):
        agent,_,_=self.make_agent();worker=UsbWorker(agent.config_path)
        with patch('guarddesk.native_usb.is_admin',return_value=False),patch.object(worker.agent,'call') as call:
            with self.assertRaises(PermissionError):worker.cycle()
            call.assert_not_called()

    def test_identity_mismatch_and_incorrect_readback_are_not_success(self):
        agent,eid,_=self.make_agent();worker=UsbWorker(agent.config_path)
        with patch('guarddesk.native_usb.is_admin',return_value=True),patch.object(worker.controls,'apply_usb') as apply:
            with patch.object(worker.agent,'call',return_value={'device_id':'wrong','version':1,'usb_mode':'read_only'}):
                with self.assertRaises(ValueError):worker.cycle(require_online=True)
            apply.assert_not_called()
        self.publish(usb_mode='read_only')
        with patch('guarddesk.native_usb.is_admin',return_value=True),patch.object(worker.controls,'apply_usb',return_value={'status':'configured_replug_required','registry':{'Deny_Read':0,'Deny_Write':0}}):
            report=worker.cycle(require_online=True)
        self.assertEqual(report['status'],'failed')
        status=self.api('/api/device-detail?device_id='+eid)['device']['native_usb']
        self.assertFalse(status['verified_readback']);self.assertEqual(status['status'],'failed')

    def test_company_denial_is_preserved_and_conflict_does_not_overwrite(self):
        agent,_,_=self.make_agent();controls=WindowsControls(agent);controls.directory.mkdir(parents=True)
        values={'Deny_Read':(1,4)}
        class Key:
            def __enter__(self):return self
            def __exit__(self,*args):pass
        class Registry:
            HKEY_LOCAL_MACHINE=1;KEY_SET_VALUE=2;KEY_QUERY_VALUE=4;REG_DWORD=4
            @staticmethod
            def OpenKey(*args):return Key()
            @staticmethod
            def CreateKeyEx(*args):return Key()
            @staticmethod
            def QueryValueEx(key,name):
                if name not in values:raise FileNotFoundError(name)
                return values[name]
            @staticmethod
            def SetValueEx(key,name,reserved,kind,value):values[name]=(value,kind)
            @staticmethod
            def DeleteValue(key,name):
                if name not in values:raise FileNotFoundError(name)
                del values[name]
        with patch.dict('sys.modules',{'winreg':Registry}):
            report=controls.apply_usb('read_only');self.assertEqual(report['registry'],{'Deny_Read':1,'Deny_Write':1})
            controls.apply_usb('allow');self.assertEqual(values,{'Deny_Read':(1,4)})
            controls.apply_usb('read_only');values['Deny_Write']=(0,4)
            with self.assertRaises(OSError):controls.apply_usb('read_only')
            self.assertEqual(values['Deny_Write'],(0,4))

    @unittest.skipUnless(os.name=='nt','Windows mutex')
    def test_machine_worker_singleton(self):
        with machine_instance('unit-usb',self.root.name):
            with self.assertRaises(OSError):
                with machine_instance('unit-usb',self.root.name):pass
        with machine_instance('unit-usb',self.root.name):pass


class InstallerShutdownTest(unittest.TestCase):
    @unittest.skipUnless(os.name=='nt','Windows PowerShell installer')
    def test_orphan_shutdown_preserves_other_commands_configs_and_reused_pids(self):
        # Load only the reviewed shutdown functions; never run the installer or
        # stop actual processes. Exercise Windows command-line matching in PS5.
        script=r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($env:GUARDDESK_INSTALL_TEST_SCRIPT,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Installer parse failed'}
foreach($name in @('Get-InstalledWorkers','Stop-InstalledWorker')){
    $node=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)[0]
    . ([scriptblock]::Create($node.Extent.Text))
}
$exe='C:\Program Files\GuardDeskPilot\USBControl\GuardDesk.exe'
$config='C:\ProgramData\GuardDeskPilot\USBControl\test\config.json'
function Reset-Worker([string]$command){
    $script:fake=@([pscustomobject]@{ExecutablePath=$exe;CommandLine=$command;CreationDate='one';ProcessId=123})
    $script:stopped=@();$script:reuse=$false;$script:natural=$false;$script:reads=0
}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction)
    if($Filter -like 'ProcessId=*' -and $script:reuse){
        $other=[pscustomobject]@{ExecutablePath=$exe;CommandLine=$script:fake[0].CommandLine;CreationDate='two';ProcessId=123}
        $script:fake=@();return $other
    }
    if($Filter -like 'Name=*' -and $script:natural){$script:reads++;if($script:reads -gt 1){$script:fake=@()}}
    return $script:fake
}
function Stop-Process {param($Id,[switch]$Force,$ErrorAction) $script:stopped+=@($Id);$script:fake=@()}
function Start-Sleep {param($Milliseconds)}
$worker='"'+$exe+'" usb-worker --extended --config "'+$config+'"'
Reset-Worker $worker;Stop-InstalledWorker $exe $config 0
if($script:stopped.Count -ne 1 -or $script:stopped[0] -ne 123){throw 'Owned orphan was not stopped'}
foreach($command in @(('"'+$exe+'" browser-host --config "'+$config+'"'),($worker.Replace($config,$config+'.other')))){
    Reset-Worker $command;$refused=$false
    try {Stop-InstalledWorker $exe $config 0} catch {$refused=$true}
    if(-not $refused -or $script:stopped.Count){throw 'Unrelated command/config was stopped'}
}
Reset-Worker $worker;$script:reuse=$true;Stop-InstalledWorker $exe $config 0
if($script:stopped.Count){throw 'Reused PID was stopped'}
Reset-Worker $worker;$script:natural=$true;Stop-InstalledWorker $exe $config
if($script:stopped.Count){throw 'Graceful exit was forcibly stopped'}
Write-Output 'installer-shutdown-passed'
'''
        installer=Path(__file__).resolve().parents[1]/'guarddesk/windows/install-usb.ps1'
        result=subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'),'-NoLogo','-NoProfile','-NonInteractive','-Command',script],env={**os.environ,'GUARDDESK_INSTALL_TEST_SCRIPT':str(installer)},capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8',errors='replace'))
        self.assertIn(b'installer-shutdown-passed',result.stdout)


if __name__=='__main__':unittest.main()
