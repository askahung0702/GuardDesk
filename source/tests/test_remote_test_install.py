"""LAB01 migration boundary fixtures; no installed endpoint or desktop access."""
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from guarddesk import remote_test_install as lab
from guarddesk import native_installer as ni
REAL_QUIESCENT=ni.assert_quiescent
import test_native_installer as installer_fixtures
import test_native_remote as remote_fixtures


class PreflightTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.config=Path(self.tmp.name)/'config.json';self.config.write_text('{}')
        self.marker={'device_id':'a'*24,'server':'https://original.invalid','version':'0.4.75','scope':'machine'}
        self.settings={**self.marker,'token':'fixture-only-secret','ca':'original.pem'}
        self.reply={'enabled':True,'wire':1,'version':'0.4.79','update_busy':False,'remote_busy':False}
        self.patches=[patch.object(lab,'existing',return_value=(self.marker,self.config)),
                      patch('guarddesk.update_native.protected_tree'),patch.object(ni,'assert_quiescent'),
                      patch('guarddesk.remote_components.read_cohort'),
                      patch('guarddesk.agent.request',return_value=self.reply)]
        self.mocks=[p.start() for p in self.patches]
        for p in self.patches:self.addCleanup(p.stop)
    def check(self):return lab.preflight(self.config,self.settings,Path(self.tmp.name))
    def test_preserves_identity_and_only_uses_original_authenticated_tls_destination(self):
        result=self.check();self.assertEqual(result['registration'],'preserved')
        self.mocks[-1].assert_called_once_with('https://original.invalid','/api/agent/remote/test-readiness',{},'fixture-only-secret','original.pem',timeout=5)
        self.assertNotIn('token',json.dumps(result));self.assertEqual(self.config.read_text(),'{}')
    def test_old_disabled_busy_or_incomplete_center_refused_before_transaction(self):
        for change in ({'version':'0.4.75'},{'enabled':False},{'update_busy':True},{'remote_busy':True},{'wire':2},{'remote_busy':None}):
            with self.subTest(change=change),patch('guarddesk.agent.request',return_value={**self.reply,**change}):
                with self.assertRaises(ValueError):self.check()
        self.marker['version']='99.0.0';self.mocks[-1].reset_mock()
        with self.assertRaisesRegex(ValueError,'newer'):self.check()
        self.mocks[-1].assert_not_called()
    def test_token_ca_or_center_failure_not_retried_or_retargeted(self):
        with patch('guarddesk.agent.request',side_effect=ConnectionError('TLS failed')) as call:
            with self.assertRaises(ConnectionError):self.check()
            self.assertEqual(call.call_count,1)
    def test_other_config_identity_or_trial_refused_without_network(self):
        for change in ({'device_id':'b'*24},{'server':'https://other.invalid'},{'install_profile':'remote-only-trial-v1'}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):lab.preflight(self.config,{**self.settings,**change},self.config.parent)
        with self.assertRaises(ValueError):lab.preflight(self.config.with_name('other.json'),self.settings,self.config.parent)
        self.mocks[-1].assert_not_called()
    def test_acl_or_interrupted_transaction_refused_without_network(self):
        for name in ('guarddesk.update_native.protected_tree','guarddesk.native_installer.assert_quiescent'):
            with patch(name,side_effect=OSError('fixture rejected')):
                with self.assertRaises(OSError):self.check()
        self.mocks[-1].assert_not_called()
    def test_host_and_trial_guards(self):
        for host,trial in (('DEV-01',False),('LAB01',True)):
            with patch.object(lab.platform,'node',return_value=host),patch('guarddesk.remote_trial.ENABLED',trial):
                with self.assertRaises(ValueError):lab.target()
        with patch.object(lab.platform,'node',return_value='lab01.example.invalid'),patch('guarddesk.remote_trial.ENABLED',False):lab.target()
    def test_staging_recheck_excludes_only_own_install_journal(self):
        journal=self.config.parent/'install-transaction.json'
        journal.write_text(json.dumps({'phase':'prepare_programs'}))
        with patch.object(ni,'assert_quiescent',side_effect=REAL_QUIESCENT):
            with self.assertRaises(OSError):self.check()
            lab.preflight(self.config,self.settings,self.config.parent,staging=True)
            updates=self.config.parent/'updates';updates.mkdir()
            (updates/'transaction-native.json').write_text(json.dumps({'phase':'downloading'}))
            with self.assertRaises(OSError):lab.preflight(self.config,self.settings,self.config.parent,staging=True)


class DiscoveryTest(unittest.TestCase):
    def test_standard_user_uses_existing_public_identity_without_reading_private_config(self):
        marker={'device_id':'a'*24,'server':'https://original.invalid','scope':'machine','version':'0.4.75'}
        with patch.object(lab,'target'),patch('guarddesk.machine_agent_session.discover',return_value=marker),patch('guarddesk.update_native.folder',return_value=Path('owned-fixture')):
            result,config=lab.existing()
        self.assertEqual(result,marker);self.assertEqual(config,Path('owned-fixture')/'USBControl'/('a'*24)/'config.json')


class UpgradeTest(unittest.TestCase):
    setUp=installer_fixtures.NativeInstallerTest.setUp
    old_install=installer_fixtures.NativeInstallerTest.old_install
    def test_check_only_never_walks_program_or_queue_trees_or_changes_tasks(self):
        self.old_install();before=self.protected.read_bytes()
        self.ops.tree=lambda path:(_ for _ in ()).throw(AssertionError('queue/program tree walk forbidden in read-only lab preflight'))
        with patch.object(lab,'preflight',return_value={'check_only':True}) as check:
            result=ni.install(self.protected,'Status',self.source,self.ops,remote_test=True)
        self.assertEqual(result,{'check_only':True});check.assert_called_once()
        self.assertEqual(self.ops.events,[]);self.assertEqual(self.protected.read_bytes(),before)
    def test_protected_config_repair_preserves_real_audit_scope_and_existing_optins(self):
        self.old_install()
        settings={**self.settings,'watch':'old-unused','audit_watch':'ORIGINAL_DOCUMENT_SCOPE','remote_admin_preview':True}
        self.protected.write_text(json.dumps(settings));before=(self.protected.parent/'offline-queue').read_bytes()
        ni.install(self.protected,'Install',self.source,self.ops)
        saved=json.loads(self.protected.read_text())
        self.assertEqual(saved['audit_watch'],'ORIGINAL_DOCUMENT_SCOPE');self.assertTrue(saved['remote_admin_preview'])
        self.assertEqual(saved['token'],settings['token']);self.assertEqual(saved['server'],settings['server'])
        self.assertEqual((self.protected.parent/'offline-queue').read_bytes(),before)
        self.assertNotIn('remote_native_preview',saved)
    def test_explicit_optin_rechecks_after_staging_and_preserves_queue(self):
        self.old_install();before=self.protected.read_bytes()
        with patch.object(lab,'preflight') as check:
            ni.install(self.protected,'Install',self.source,self.ops,remote_test=True)
        self.assertEqual(check.call_count,2)
        saved=json.loads(self.protected.read_text());self.assertTrue(saved['remote_native_preview'])
        self.assertEqual(saved['device_id'],json.loads(before)['device_id'])
        self.assertEqual((self.protected.parent/'offline-queue').read_bytes(),b'preserve queue')
    def test_center_becomes_busy_during_copy_no_existing_task_stopped(self):
        self.old_install();original=self.protected.read_bytes()
        with patch.object(lab,'preflight',side_effect=[None,ValueError('center became busy')]):
            with self.assertRaises(ni.NativeInstallFailure):ni.install(self.protected,'Install',self.source,self.ops,remote_test=True)
        self.assertFalse(any(e[0]=='stop' for e in self.ops.events))
        self.assertEqual(self.protected.read_bytes(),original)
    def test_initial_failure_restores_exact_config_optins_and_queue(self):
        self.old_install();original=self.protected.read_bytes();self.ops.fail_once=True
        with patch.object(lab,'preflight'):
            with self.assertRaises(ni.NativeInstallFailure):ni.install(self.protected,'Install',self.source,self.ops,remote_test=True)
        self.assertEqual(self.protected.read_bytes(),original)
        self.assertEqual((self.protected.parent/'offline-queue').read_bytes(),b'preserve queue')


class ReadinessHTTPTest(unittest.TestCase):
    api=remote_fixtures.NativeRemoteTest.api
    setUp=remote_fixtures.NativeRemoteTest.setUp
    tearDown=remote_fixtures.NativeRemoteTest.tearDown
    prepare=remote_fixtures.NativeRemoteTest.prepare
    def test_authenticated_check_does_not_create_session_or_change_presence(self):
        client,agent,did=self.prepare()
        with self.store.connect() as db:before=[tuple(row) for row in db.execute('SELECT * FROM remote_presence')]
        result=agent.call('/api/agent/remote/test-readiness',{})
        self.assertFalse(result['enabled']);self.assertFalse(result['update_busy']);self.assertFalse(result['remote_busy'])
        self.server.remote_native_preview=True
        self.assertTrue(agent.call('/api/agent/remote/test-readiness',{})['enabled'])
        with self.store.connect() as db:
            self.assertEqual(before,[tuple(row) for row in db.execute('SELECT * FROM remote_presence')])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM remote_sessions').fetchone()[0],0)
        with self.assertRaises(ConnectionError):agent.call('/api/agent/remote/test-readiness',{'approve':True})
        from guarddesk.agent import request
        with self.assertRaises(ConnectionError):request(self.url,'/api/agent/remote/test-readiness',{})
    def test_existing_pending_request_is_busy_not_approved_or_swept(self):
        client,agent,did=self.prepare();session=client.request(did,'view','fixture')
        self.assertTrue(agent.call('/api/agent/remote/test-readiness',{})['remote_busy'])
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT status FROM remote_sessions WHERE id=?',(session['id'],)).fetchone()[0],'requested')
    def test_scheduled_unclaimed_update_also_blocks_installation(self):
        client,agent,did=self.prepare();now=time.time()
        with self.store.connect() as db:
            db.execute('INSERT INTO update_releases VALUES (?,?,?,?,?)',('owned-release','0.4.79','{}',now,'admin'))
            db.execute('INSERT INTO update_jobs VALUES (?,?,?,?,?,?,?,?,?)',('owned-job',did,'owned-release','admin',now,now+3600,now+7200,0,'pending'))
        self.assertTrue(agent.call('/api/agent/remote/test-readiness',{})['update_busy'])
        with self.store.connect() as db:db.execute("UPDATE update_jobs SET status='cancelled' WHERE id='owned-job'")
        self.assertFalse(agent.call('/api/agent/remote/test-readiness',{})['update_busy'])
