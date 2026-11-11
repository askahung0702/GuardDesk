"""Only explicit trial update may replace a completed matching live install."""
import hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import ExitStack
from guarddesk import endpoint_setup,remote_trial

class ExplicitTrialUpgradeTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.user=self.root/'user';self.config=self.user/'runtime/agent/config.json';self.config.parent.mkdir(parents=True)
        self.ca=self.root/'ca.pem';self.ca.write_bytes(b'owned CA')
        self.settings={'device_id':'a'*24,'server':'https://owned.invalid','token':'OWNED_PRIVATE_TOKEN','install_profile':remote_trial.PROFILE}
        self.config.write_text(json.dumps(self.settings))
        self.marker=self.user/'endpoint-install.json';self.state={'product':'GuardDeskEndpoint','config':str(self.config),'last_result':'completed','phase':'ready'}
        self.marker.write_text(json.dumps(self.state))
        self.machine={'device_id':'a'*24,'server':self.settings['server'],'ca_sha256':hashlib.sha256(self.ca.read_bytes()).hexdigest(),'version':'0.4.91','install_profile':remote_trial.PROFILE,'status':'online'}

    def invoke(self,flag=True):
        with ExitStack() as stack:
            for target,value in [('guarddesk.remote_trial.ENABLED',True),('guarddesk.endpoint_setup.__version__','0.4.92')]:stack.enter_context(patch(target,value))
            stack.enter_context(patch('guarddesk.machine_agent_session.discover',return_value=self.machine))
            stack.enter_context(patch.object(endpoint_setup,'client_root',return_value=self.user))
            stack.enter_context(patch.object(endpoint_setup,'read_connection',return_value=(self.settings['server'],self.ca)))
            install=stack.enter_context(patch.object(endpoint_setup,'_install',return_value={'status':'installed'}))
            enroll=stack.enter_context(patch.object(endpoint_setup,'enroll',side_effect=AssertionError('must not enroll')))
            try:result=endpoint_setup.install(self.root/'connection.json',upgrade_existing=flag)
            finally:enroll.assert_not_called()
            return result,install

    def test_completed_live_explicit_update_uses_existing_install(self):
        result,install=self.invoke();self.assertEqual(result['status'],'installed');install.assert_called_once()

    def test_default_setup_keeps_completed_install_unchanged(self):
        result,install=self.invoke(False);self.assertEqual(result['status'],'already_installed');install.assert_not_called()

    def test_offline_completed_requires_review(self):
        self.machine['status']='supervisor_unavailable'
        with self.assertRaises(OSError):self.invoke()

    def test_offline_pending_keeps_original_resume_path(self):
        self.state['last_result']='incomplete_retry_same_installer';self.marker.write_text(json.dumps(self.state));self.machine['status']='supervisor_unavailable'
        result,install=self.invoke();self.assertEqual(result['status'],'installed');install.assert_called_once()

    def test_missing_identity_configuration_or_marker_never_registers(self):
        for missing in ('marker','config','machine'):
            with self.subTest(missing=missing):
                marker=self.marker.read_bytes();config=self.config.read_bytes();machine=self.machine
                if missing=='marker':self.marker.unlink()
                elif missing=='config':self.config.unlink()
                else:self.machine=None
                try:
                    with self.assertRaises(OSError):self.invoke()
                finally:self.marker.write_bytes(marker);self.config.write_bytes(config);self.machine=machine

    def test_wrong_identity_and_downgrade_are_rejected(self):
        for key,value in [('device_id','b'*24),('version','99.0.0')]:
            original=self.machine[key];self.machine[key]=value
            try:
                with self.assertRaises(OSError):self.invoke()
            finally:self.machine[key]=original

    def test_nontrial_and_custom_root_cannot_use_explicit_upgrade(self):
        with patch('guarddesk.remote_trial.ENABLED',False),patch('guarddesk.machine_service.ENABLED',False):
            with self.assertRaises(ValueError):endpoint_setup.install('unused',upgrade_existing=True)
        with patch('guarddesk.remote_trial.ENABLED',True):
            with self.assertRaises(ValueError):endpoint_setup.install('unused',root=self.root,upgrade_existing=True)
