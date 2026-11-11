"""Protected-worker wiring with explicit OS boundaries mocked, never AppLocker."""
import copy
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager,ExitStack,closing
from pathlib import Path
from unittest.mock import patch,Mock
from guarddesk.application_control import ExtendedWorker
from guarddesk.policy import DEFAULT_POLICY,agent_policy_wire
from guarddesk.custom_settings import DEFAULT


class WorkerTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();root=Path(self.tmp.name)
        class Agent:
            def __init__(self):
                self.config_path=root/'config.json';self.config={'device_id':'a'*24};self.packet=None
            @contextmanager
            def db(self):
                with closing(sqlite3.connect(root/'state.db')) as db:
                    with db:yield db
            def call(self,path,body):return copy.deepcopy(self.packet)
        self.agent=Agent()
        with self.agent.db() as db:db.execute('CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT)')
        body=copy.deepcopy(DEFAULT_POLICY);body['browser_audit']=False
        self.agent.packet={'device_id':self.agent.config['device_id'],**agent_policy_wire({'body':body})}
        self.worker=ExtendedWorker(self.agent);self.worker.poll=Mock(return_value={});self.worker.configure_documents=Mock()
        self.stack=ExitStack()
        for name,kwargs in [('guarddesk.browser_dispatch.sync',{'return_value':{}}),('guarddesk.custom_client.load_custom',{'return_value':None}),('guarddesk.custom_client.effective_body',{'return_value':copy.deepcopy(DEFAULT)}),('guarddesk.process_audit.configure',{'return_value':{}}),('guarddesk.custom_windows.trusted_native',{'return_value':root})]:self.stack.enter_context(patch(name,**kwargs))
    def tearDown(self):self.stack.close();self.tmp.cleanup()
    def test_projection_saved_and_website_sync_is_change_driven_not_every_poll(self):
        self.agent.packet['target_controls']['website_control'].update(enabled=True,blocked=['example.com'])
        with patch('guarddesk.website_control.sync',return_value={'state':'reported_requires_browser_test','protocol':1}) as sync:
            self.worker.configure();self.worker.configure();self.assertEqual(sync.call_count,1)
        with self.agent.db() as db:self.assertIsNotNone(db.execute("SELECT value FROM state WHERE key='extended_target_controls'").fetchone())
    def test_old_server_omission_keeps_cached_control_and_does_not_restore(self):
        self.agent.packet['target_controls']['website_control'].update(enabled=True,blocked=['example.com'])
        with patch('guarddesk.website_control.sync',return_value={'state':'reported_requires_browser_test','protocol':1}) as sync:
            self.worker.configure();self.agent.packet.pop('target_controls');self.worker.configure()
            self.assertEqual(sync.call_count,1)
        self.assertTrue(self.worker.policy['website_control']['enabled'])
        self.assertEqual(self.worker.website_status['state'],'upstream_unsupported_cached_policy_preserved')
    def test_nonprotected_website_configuration_fails_and_is_throttled(self):
        self.agent.packet['target_controls']['website_control']['enabled']=True
        with patch('guarddesk.website_control.sync',side_effect=OSError('protected worker missing')) as sync:
            self.worker.configure();self.worker.configure();self.assertEqual(sync.call_count,1)
        self.assertEqual(self.worker.website_status['state'],'failed')
    def test_category_publisher_and_existing_custom_product_share_native_xml(self):
        item={'name':'New tool','collection':'Exe','publisher':'CN=Example','product':'New Tool','binary':'tool.exe','min_version':'0.0.0.0','max_version':'*'}
        settings=copy.deepcopy(DEFAULT);settings['software']=[{**item,'name':'Existing tool','product':'Existing Tool'}]
        self.agent.packet['target_controls']['application_publishers']=[item]
        self.agent.packet['target_controls']['application_control']['enabled']=True
        with patch('guarddesk.custom_client.effective_body',return_value=settings),patch('guarddesk.application_control.native_action',return_value={'application_control':'configured'}) as native:
            self.worker.configure()
            self.assertIn('New Tool',native.call_args.kwargs['xml']);self.assertIn('Existing Tool',native.call_args.kwargs['xml'])
            self.assertEqual(self.worker.custom_software_count,1)
            self.agent.packet.pop('target_controls');self.worker.configure()
            self.assertEqual(native.call_count,1)


if __name__=='__main__':unittest.main()
