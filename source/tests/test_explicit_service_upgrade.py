"""Explicit full-service bootstrap, not silent Setup takeover or reenrollment."""
import base64,hashlib,json,unittest
from unittest.mock import patch
from contextlib import ExitStack
from test_explicit_trial_upgrade import ExplicitTrialUpgradeTest
from guarddesk import endpoint_setup,endpoint_package


class ExplicitServiceUpgradeTest(ExplicitTrialUpgradeTest):
    def setUp(self):
        super().setUp()
        self.settings.pop('install_profile');self.config.write_text(json.dumps(self.settings))
        self.machine.pop('install_profile')

    def invoke(self,flag=True):
        with ExitStack() as stack:
            stack.enter_context(patch('guarddesk.remote_trial.ENABLED',False))
            stack.enter_context(patch('guarddesk.machine_service.ENABLED',True))
            stack.enter_context(patch.object(endpoint_setup,'__version__','0.4.101'))
            stack.enter_context(patch('guarddesk.machine_agent_session.discover',return_value=self.machine))
            stack.enter_context(patch.object(endpoint_setup,'client_root',return_value=self.user))
            stack.enter_context(patch.object(endpoint_setup,'read_connection',return_value=(self.settings['server'],self.ca)))
            install=stack.enter_context(patch.object(endpoint_setup,'_install',return_value={'status':'installed'}))
            enroll=stack.enter_context(patch.object(endpoint_setup,'enroll',side_effect=AssertionError('must not enroll')))
            before=self.config.read_bytes()
            try:result=endpoint_setup.install(self.root/'connection.json',upgrade_existing=flag)
            finally:
                enroll.assert_not_called();self.assertEqual(self.config.read_bytes(),before)
            return result,install

    def test_nontrial_and_custom_root_cannot_use_explicit_upgrade(self):
        with patch('guarddesk.remote_trial.ENABLED',False),patch('guarddesk.machine_service.ENABLED',False):
            with self.assertRaises(ValueError):endpoint_setup.install('unused',upgrade_existing=True)
        with patch('guarddesk.machine_service.ENABLED',True):
            with self.assertRaises(ValueError):endpoint_setup.install('unused',root=self.root,upgrade_existing=True)

    def test_same_version_is_unchanged_and_changed_center_or_CA_rejected(self):
        self.machine['version']='0.4.101'
        result,install=self.invoke();self.assertEqual(result['status'],'already_installed');install.assert_not_called()
        for key,value in [('server','https://wrong.invalid'),('ca_sha256','0'*64)]:
            prior=self.machine[key];self.machine[key]=value
            try:
                with self.assertRaises(ValueError):self.invoke()
            finally:self.machine[key]=prior

    def test_separate_CMD_has_opt_in_only_and_preserves_ordinary_setup(self):
        self.assertNotIn(b'--upgrade-existing',endpoint_package.SETUP)
        self.assertEqual(endpoint_package.UPGRADE.count(b'--upgrade-existing'),1)
        self.assertIn(b'GuardDesk\\GuardDesk.exe" endpoint-setup --upgrade-existing --connection',endpoint_package.UPGRADE)

    def test_real_staging_install_resume_preserves_identity_cursor_and_outbox(self):
        from guarddesk.agent import Agent
        from guarddesk import usb_install
        package=self.root/'package';program=package/'GuardDesk';program.mkdir(parents=True)
        with patch('guarddesk.machine_service.ENABLED',True):names=endpoint_package.required_files()
        hashes={}
        for name in names:
            path=program/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(('nonexecutable owned '+name).encode())
            hashes[name]=hashlib.sha256(path.read_bytes()).hexdigest()
        (package/'endpoint-files.json').write_text(json.dumps({'version':'0.4.101','files':hashes}))
        connection=package/'endpoint-connection.json';connection.write_text('{}')
        key=base64.b64encode(b'x'*32).decode()
        (package/'update-trust.json').write_text(json.dumps({'format':1,'public_key':key}))
        self.settings.update(watch=str(self.root),update_key=key)
        self.config.write_text(json.dumps(self.settings))
        (self.config.parent/'GuardDesk-CA.pem').write_bytes(self.ca.read_bytes())
        agent=Agent(self.config);agent.queue('file.created',{'owned':True})
        with agent.db() as db:db.execute("INSERT INTO state VALUES ('owned_cursor','KEEP')")
        native=[]
        def install_native(path,**kwargs):
            actual=json.loads(path.read_text());self.assertEqual(actual['device_id'],self.settings['device_id'])
            self.assertEqual(actual['token'],self.settings['token'])
            self.assertTrue((kwargs['source']/'GuardDesk.exe').is_file());native.append(True)
        with patch('guarddesk.remote_trial.ENABLED',False),patch('guarddesk.machine_service.ENABLED',True),patch.object(endpoint_setup,'__version__','0.4.101'),patch('guarddesk.machine_agent_session.discover',return_value=self.machine),patch.object(endpoint_setup,'client_root',return_value=self.user),patch.object(endpoint_setup,'read_connection',return_value=(self.settings['server'],self.ca)),patch('guarddesk.windows_privilege.is_admin',return_value=False),patch.object(endpoint_setup,'active',return_value=False),patch.object(endpoint_setup,'session_ready',side_effect=lambda *a:bool(native)),patch.object(endpoint_setup,'remove_autostart_for_config'),patch.object(usb_install,'install',side_effect=install_native),patch.object(endpoint_setup,'enroll',side_effect=AssertionError('must not enroll')):
            result=endpoint_setup.install(connection,upgrade_existing=True)
        self.assertEqual(result['status'],'installed');self.assertEqual(len(native),1)
        self.assertEqual(json.loads(self.config.read_text())['token'],self.settings['token'])
        self.assertEqual(agent.queue_status()['pending'],1)
        with agent.db() as db:self.assertEqual(db.execute("SELECT value FROM state WHERE key='owned_cursor'").fetchone()[0],'KEEP')
        self.assertEqual(json.loads(self.marker.read_text())['last_result'],'completed')
