import json
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk import browser_host
from guarddesk.application_control import ExtendedWorker


class Key:
    def __init__(self,values):self.values=values
    def __enter__(self):return self
    def __exit__(self,*args):pass


class FakeRegistry:
    HKEY_CURRENT_USER=1
    REG_SZ=1
    def __init__(self):self.keys={};self.writes=0
    def OpenKey(self,root,name):
        if name not in self.keys:raise FileNotFoundError(name)
        return Key(self.keys[name])
    def CreateKey(self,root,name):return Key(self.keys.setdefault(name,{}))
    def QueryValueEx(self,key,name):
        if name not in key.values:raise FileNotFoundError(name)
        return key.values[name],1
    def SetValueEx(self,key,name,reserved,kind,value):key.values[name]=value;self.writes+=1
    def DeleteKey(self,root,name):
        if name not in self.keys:raise FileNotFoundError(name)
        del self.keys[name]
    def DeleteValue(self,key,name):
        if name not in key.values:raise FileNotFoundError(name)
        del key.values[name]


class BrowserDeploymentLifecycleTest(unittest.TestCase):
    def installed(self,root):
        config=root/'runtime/agent/config.json';config.parent.mkdir(parents=True)
        app=root/'app/owned';app.mkdir(parents=True)
        (app/'GuardDesk.exe').write_bytes(b'owned fixture')
        (app/'GuardDeskAgent.exe').write_bytes(b'owned fixture')
        (root/'endpoint-install.json').write_text(json.dumps({'product':'GuardDeskEndpoint','config':str(config),'app':str(app)}))
        return config,app

    def test_user_startup_registers_host_without_enabling_proxy_and_updates_version_path(self):
        registry=FakeRegistry()
        with tempfile.TemporaryDirectory() as temp,patch.dict(sys.modules,winreg=registry),patch.object(sys,'frozen',True,create=True):
            root=Path(temp);config,app=self.installed(root);exe=app/'GuardDesk.exe'
            original={'proxy_enabled':False,'token':'owned-fixture'}
            config.write_text(json.dumps(original),encoding='utf-8');before=config.read_bytes()
            with patch.object(sys,'executable',str(app/'GuardDeskAgent.exe')):
                result=browser_host.ensure_user_host(config)
                self.assertEqual(result['status'],'registered_awaiting_extension')
                self.assertEqual(config.read_bytes(),before)
                manifest=config.parent/'com.guarddesk.agent.json';stamp=manifest.stat().st_mtime_ns
                browser_host.ensure_user_host(config)
                self.assertEqual(manifest.stat().st_mtime_ns,stamp)
                self.assertEqual(json.loads(manifest.read_text())['path'],str(exe.resolve()))
                browser_host.unregister_owned(config)
                self.assertFalse(any('NativeMessagingHosts' in key for key in registry.keys))

    def test_conflicting_enrollment_or_manifest_is_preserved(self):
        registry=FakeRegistry()
        with tempfile.TemporaryDirectory() as temp,patch.dict(sys.modules,winreg=registry),patch.object(sys,'frozen',True,create=True):
            root=Path(temp);config,app=self.installed(root);config.write_text('{}')
            registry.keys[r'Software\GuardDesk']={'AgentConfig':str(root/'another.json')}
            with patch.object(sys,'executable',str(app/'GuardDeskAgent.exe')),self.assertRaises(OSError):browser_host.ensure_user_host(config)
            self.assertEqual(registry.writes,0)
            registry.keys.clear()
            with patch.object(sys,'executable',str(app/'GuardDeskAgent.exe')):browser_host.ensure_user_host(config)
            chrome=r'Software\Google\Chrome\NativeMessagingHosts'+'\\'+browser_host.HOST_NAME
            registry.keys[chrome]['']=str(root/'external.json')
            before={k:v.copy() for k,v in registry.keys.items()}
            with self.assertRaises(OSError):browser_host.unregister_owned(config)
            self.assertEqual(before,registry.keys)
            with patch.object(sys,'executable',str(app/'GuardDeskAgent.exe')),self.assertRaises(OSError):browser_host.ensure_user_host(config)
            self.assertEqual(before,registry.keys)

    def test_uninstalled_frozen_probe_never_claims_real_user_registry(self):
        registry=FakeRegistry()
        with tempfile.TemporaryDirectory() as temp,patch.dict(sys.modules,winreg=registry),patch.object(sys,'frozen',True,create=True):
            root=Path(temp);config=root/'agent/config.json';config.parent.mkdir();config.write_text('{}')
            with patch.object(sys,'executable',str(root/'GuardDeskAgent.exe')):
                self.assertEqual(browser_host.ensure_user_host(config)['status'],'installation_not_selected')
            self.assertEqual(registry.keys,{});self.assertEqual(registry.writes,0)
            self.assertFalse((config.parent/'com.guarddesk.agent.json').exists())

    def test_old_application_or_mismatching_marker_does_not_claim_registration(self):
        registry=FakeRegistry()
        with tempfile.TemporaryDirectory() as temp,patch.dict(sys.modules,winreg=registry),patch.object(sys,'frozen',True,create=True):
            root=Path(temp);config,app=self.installed(root);config.write_text('{}')
            for bad in (root/'app/old/GuardDeskAgent.exe',root/'GuardDeskAgent.exe'):
                with patch.object(sys,'executable',str(bad)):
                    self.assertEqual(browser_host.ensure_user_host(config)['status'],'installation_not_selected')
            self.assertEqual(registry.writes,0)

    def test_native_restore_includes_only_owned_browser_journal(self):
        with tempfile.TemporaryDirectory() as temp:
            class Agent:config_path=Path(temp)/'config.json'
            worker=ExtendedWorker(Agent())
            with patch('guarddesk.process_audit.configure',return_value={'restored':True}),patch('guarddesk.browser_deployment.execute') as restore,patch('guarddesk.browser_deployment.Registry'):
                worker.restore();restore.assert_not_called()
                (Path(temp)/'browser-policy-owned.json').write_text('[]')
                worker.restore();self.assertEqual(restore.call_args.args[:3],(None,'restore',Path(temp)))

    def test_live_host_exits_after_reply_when_user_update_selects_new_host(self):
        with tempfile.TemporaryDirectory() as temp:
            class Agent:config_path=Path(temp)/'config.json'
            (Path(temp)/'com.guarddesk.agent.json').write_text(json.dumps({'path':str(Path(temp)/'new/GuardDesk.exe')}))
            target=io.BytesIO();source=io.BytesIO()
            browser_host.native_write(source,{'type':'status','request_id':'one'})
            browser_host.native_write(source,{'type':'status','request_id':'two'});source.seek(0)
            with patch.object(sys,'frozen',True,create=True),patch.object(sys,'executable',str(Path(temp)/'old/GuardDesk.exe')),patch('guarddesk.browser_host.handle_message',return_value={'ok':True}) as handler:
                browser_host.serve_messages(Agent(),source,target)
            self.assertEqual(handler.call_count,1)
            target.seek(0);self.assertEqual(browser_host.native_read(target)['request_id'],'one');self.assertIsNone(browser_host.native_read(target))


if __name__=='__main__':unittest.main()
