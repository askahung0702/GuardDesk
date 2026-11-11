import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from guarddesk import browser_dispatch as dispatch
from guarddesk.browser_deployment import authorize
from guarddesk.browser_host import extension_id
from guarddesk.update_packages import public_key


class BrowserDispatchTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.path=self.root/'config.json'
        self.key=Ed25519PrivateKey.generate()
        self.settings={'extension_id':extension_id(),'chrome_update_url':'https://server.test/browser-extension/updates.xml','edge_update_url':'https://server.test/browser-extension/updates.xml'}
        self.packet={'status':'published','settings':self.settings,'authorization':authorize(self.settings,self.key)}
        self.original={'device_id':'a'*24,'token':'owned-fixture-only','update_key':public_key(self.key),'audit_watch':'own-existing-root'}
        self.path.write_text(json.dumps(self.original),encoding='utf-8')
        self.agent=SimpleNamespace(config=copy.deepcopy(self.original),config_path=self.path,feature_status={})

    def test_verify_adopt_preserves_identity_outbox_settings_and_is_idempotent(self):
        body,changed=dispatch.adopt(self.agent,self.packet);self.assertTrue(changed);self.assertEqual(body,self.settings)
        current=json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual({k:current[k] for k in self.original},self.original)
        before=self.path.read_bytes();self.assertFalse(dispatch.adopt(self.agent,self.packet)[1]);self.assertEqual(before,self.path.read_bytes())

    def test_wrong_pin_tamper_source_change_and_race_leave_config_unchanged(self):
        for mutation in ('signature','pin','race','old_source'):
            a=copy.deepcopy(self.agent);packet=copy.deepcopy(self.packet)
            self.path.write_text(json.dumps(self.original),encoding='utf-8')
            if mutation=='signature':packet['settings']['edge_update_url']='https://different.test/updates.xml'
            if mutation=='pin':a.config['update_key']=public_key(Ed25519PrivateKey.generate())
            if mutation=='race':self.path.write_text(json.dumps({**self.original,'token':'changed-fixture'}),encoding='utf-8')
            if mutation=='old_source':a.config['browser_deployment']={**self.settings,'edge_update_url':'https://different.test/updates.xml'}
            before=self.path.read_bytes()
            with self.assertRaises((ValueError,OSError)):dispatch.adopt(a,packet)
            self.assertEqual(before,self.path.read_bytes())

    def test_absent_unpublished_disabled_and_wrong_runtime_have_no_side_effect(self):
        for packet,enabled,expected in ((None,True,'center_upgrade_required'),({'status':'publication_required'},True,'publication_required'),(self.packet,False,'audit_disabled')):
            with patch.object(dispatch,'adopt') as adopt:
                self.assertEqual(dispatch.sync(self.agent,packet,native=True,enabled=enabled)['status'],expected);adopt.assert_not_called()
        with patch('guarddesk.windows_privilege.is_admin',return_value=False),patch.object(dispatch,'adopt') as adopt:
            self.assertEqual(dispatch.sync(self.agent,self.packet,native=True)['status'],'deployment_failed');adopt.assert_not_called()

    def test_selected_user_host_refreshes_company_identity_without_proxy_or_profile_write(self):
        with patch('guarddesk.browser_host.installed_user_host',return_value=True),patch('guarddesk.browser_host.ensure_user_host',return_value={'status':'registered_awaiting_extension'}) as register:
            status=dispatch.sync(self.agent,self.packet);self.agent.feature_status['browser_deployment']=status
            self.assertEqual(status['status'],'host_ready_await_extension');self.assertFalse(status['browser_installation_verified'])
            self.assertEqual(dispatch.sync(self.agent,self.packet),status);register.assert_called_once_with(self.path)

    def test_unselected_smoke_cannot_take_over_live_host(self):
        with patch('guarddesk.browser_host.installed_user_host',return_value=False),patch.object(dispatch,'adopt') as adopt:
            self.assertEqual(dispatch.sync(self.agent,self.packet)['status'],'installation_not_selected');adopt.assert_not_called()

    def test_native_signed_adoption_additive_policy_retry_conflict_and_restore(self):
        from test_document_audit import RegistryFixture
        from guarddesk.browser_deployment import execute
        registry=RegistryFixture();baseline=copy.deepcopy(registry.values)
        exe=self.root/'USBControl/GuardDesk.exe'
        with patch('guarddesk.windows_privilege.is_admin',return_value=True),patch('sys.frozen',True,create=True),patch('sys.executable',str(exe)),patch('guarddesk.update_native.folder',return_value=self.root),patch('guarddesk.custom_windows.trusted_native',return_value=self.root),patch('guarddesk.update_native.protected_tree'),patch('guarddesk.browser_deployment.Registry',return_value=registry):
            state=dispatch.sync(self.agent,self.packet,native=True)
            self.assertEqual(state['status'],'policy_written_await_browser')
            self.assertFalse(state['browser_installation_verified'])
            self.assertTrue((self.root/'browser-policy-owned.json').is_file())
            self.assertEqual(dispatch.sync(self.agent,self.packet,native=True),state)
            for browser in ('chrome','edge'):
                self.assertEqual(registry.values[browser]['1'],baseline[browser]['1'])
                self.assertEqual(registry.values[browser]['2'],self.settings['extension_id']+';'+self.settings[browser+'_update_url'])
            registry.values['chrome']['2']='external-conflict'
            self.assertEqual(dispatch.sync(self.agent,self.packet,native=True)['status'],'deployment_failed')
            self.assertEqual(registry.values['chrome']['2'],'external-conflict')
            registry.values['chrome']['2']=self.settings['extension_id']+';'+self.settings['chrome_update_url']
            execute(None,'restore',self.root,registry)
            self.assertEqual(registry.values,baseline)

    def test_missing_publication_does_not_create_identity_and_bad_publication_does_not_break_heartbeat(self):
        self.assertEqual(dispatch.projection(self.root),{'status':'publication_required'})
        self.assertFalse((self.root/'update-signing').exists())
        with patch('guarddesk.browser_publication.selected',side_effect=ValueError('corrupt fixture')):
            self.assertEqual(dispatch.projection(self.root),{'status':'publication_unavailable'})

    def test_registry_identical_readback_never_rewrites_or_flushes_hive(self):
        from contextlib import nullcontext
        from guarddesk.browser_deployment import Registry
        state={'current':None,'writes':0,'flushes':0}
        def query(*args):
            if state['current'] is None:raise FileNotFoundError()
            return state['current'],1
        def write(*args):state['current']=args[-1];state['writes']+=1
        def flush(*args):state['flushes']+=1
        registry=object.__new__(Registry)
        registry.w=SimpleNamespace(HKEY_LOCAL_MACHINE=1,KEY_SET_VALUE=2,KEY_QUERY_VALUE=1,KEY_WOW64_64KEY=256,REG_SZ=1,
                                  CreateKeyEx=lambda *args:nullcontext('owned-key'),QueryValueEx=query,SetValueEx=write,FlushKey=flush)
        item={'key':'fixed-owned-key','name':'2','before':None,'after':'signed-value'}
        registry.write(item,'signed-value')
        self.assertEqual((state['writes'],state['flushes']),(1,1))
        for _ in range(100):registry.write(item,'signed-value')
        self.assertEqual((state['writes'],state['flushes']),(1,1))
        state['current']='external-value'
        with self.assertRaises(OSError):registry.write(item,'signed-value')
        self.assertEqual((state['writes'],state['flushes']),(1,1))


if __name__=='__main__':unittest.main()
