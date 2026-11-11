"""Owned partial migration, registration conflict, and same-identity setup retry."""
import copy,json,sys,threading
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from guarddesk.agent import Agent
from guarddesk.machine_agent_session import prepare,cleanup_status
from test_machine_agent import MachineFixture
from test_browser_deployment_lifecycle import FakeRegistry


class MigrationResumeTest(MachineFixture):
    def test_offline_supervisor_only_resumes_matching_pending_same_or_newer_package(self):
        import hashlib
        from guarddesk.endpoint_setup import install
        user,legacy,old,target=self.fixtures();ca=self.root/'owned-offline-ca.pem';ca.write_bytes(b'owned-public-ca')
        original=legacy.read_bytes();marker=user/'endpoint-install.json'
        for label,version,pending,identity,allowed in [
            ('older','0.4.75',True,old.config['device_id'],True),
            ('same','0.4.76',True,old.config['device_id'],True),
            ('downgrade','0.4.77',True,old.config['device_id'],False),
            ('completed','0.4.75',False,old.config['device_id'],False),
            ('other','0.4.75',True,'b'*24,False)]:
            with self.subTest(label=label):
                marker.write_text(json.dumps({'product':'GuardDeskEndpoint','config':str(legacy),'last_result':'incomplete_retry_same_installer' if pending else 'completed'}))
                machine={'device_id':identity,'server':old.config['server'],'version':version,'status':'supervisor_unavailable','ca_sha256':hashlib.sha256(ca.read_bytes()).hexdigest()}
                with patch('guarddesk.endpoint_setup.__version__','0.4.76'),patch('guarddesk.endpoint_setup.client_root',return_value=user),patch('guarddesk.machine_agent_session.discover',return_value=machine),patch('guarddesk.endpoint_setup.read_connection',return_value=(machine['server'],ca)),patch('guarddesk.endpoint_setup._install',return_value={'resumed':True}) as resumed,patch('guarddesk.endpoint_setup.enroll') as enroll:
                    if allowed:self.assertEqual(install(self.root/'owned.json'),{'resumed':True});resumed.assert_called_once()
                    else:
                        with self.assertRaises(OSError):install(self.root/'owned.json')
                        resumed.assert_not_called()
                    enroll.assert_not_called()
                self.assertEqual(legacy.read_bytes(),original)
    def fixtures(self):
        user=self.root/'owned-user';legacy=user/'runtime/agent/config.json';legacy.parent.mkdir(parents=True)
        legacy.write_bytes(self.config.read_bytes());agent=Agent(legacy)
        agent.queue('web.navigation',{'owned':True},event_id='owned-original-event')
        with agent.db() as db:db.execute("INSERT INTO state VALUES ('browser_cursor','owned-cursor')")
        target=user/'runtime/machine-agent'/('a'*24)/'1/agent/config.json'
        return user,legacy,agent,target

    def test_host_conflict_does_not_strand_verified_queue_and_retry_never_recopies(self):
        user,legacy,old,target=self.fixtures();original=legacy.read_bytes();registry=FakeRegistry()
        registry.keys[r'Software\GuardDesk']={'AgentConfig':str(user/'owned-other-enrollment.json')}
        before=copy.deepcopy(registry.keys);packet=self.dispatch('/local/bootstrap',{})
        with patch.dict(sys.modules,winreg=registry),patch('guarddesk.desktop_agent.client_root',return_value=user),patch('guarddesk.desktop_agent.stop_running'),patch('guarddesk.endpoint_setup.remove_autostart_for_config'):
            prepare(packet,1,root=target);new=Agent(target)
            self.assertEqual(new.config['legacy_cleanup']['browser_host']['state'],'pending_review')
            self.assertEqual(new.config['token'],'');self.assertEqual(registry.keys,before)
            new.queue('web.navigation',{'after_migration':True},event_id='owned-new-event')
            prepare(packet,1,root=target)
        self.assertEqual(legacy.read_bytes(),original);self.assertEqual(old.queue_status()['pending'],1)
        self.assertEqual((legacy.parent/'pre-machine-config.json').read_bytes(),original)
        with new.db() as db:
            self.assertEqual({r[0] for r in db.execute('SELECT event_id FROM outbox')},{'owned-original-event','owned-new-event'})
            self.assertEqual(db.execute("SELECT value FROM state WHERE key='browser_cursor'").fetchone()[0],'owned-cursor')
        self.assertEqual(new.config['device_id'],old.config['device_id'])

    def test_startup_failure_preserves_marker_backup_and_publishes_session(self):
        user,legacy,old,target=self.fixtures();marker=user/'endpoint-install.json'
        marker.write_text(json.dumps({'product':'GuardDeskEndpoint','config':str(legacy)}));original=marker.read_bytes()
        with patch.dict(sys.modules,winreg=FakeRegistry()),patch('guarddesk.desktop_agent.client_root',return_value=user),patch('guarddesk.desktop_agent.stop_running'),patch('guarddesk.endpoint_setup.remove_autostart_for_config',side_effect=PermissionError('OWNED SECRET MUST NOT LEAVE')):
            prepare(self.dispatch('/local/bootstrap',{}),1,root=target)
        value=json.loads(target.read_text(encoding='utf-8'));self.assertEqual(value['legacy_cleanup']['autostart']['error_type'],'PermissionError')
        self.assertNotIn('OWNED SECRET',target.read_text(encoding='utf-8'));self.assertEqual((user/'pre-machine-install.json').read_bytes(),original)
        self.assertEqual(marker.read_bytes(),original);self.assertEqual(old.queue_status()['pending'],1)

    def test_unknown_existing_database_still_fails_before_registration_cleanup(self):
        import sqlite3
        user,legacy,old,target=self.fixtures();target.parent.mkdir(parents=True)
        with closing(sqlite3.connect(target.with_suffix('.sqlite3'))) as db:
            db.execute('CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT)');db.commit()
        original=target.with_suffix('.sqlite3').read_bytes()
        with patch('guarddesk.desktop_agent.client_root',return_value=user),patch('guarddesk.desktop_agent.stop_running'),patch('guarddesk.browser_host.unregister_owned') as cleanup:
            with self.assertRaisesRegex(OSError,'Incomplete session migration'):prepare(self.dispatch('/local/bootstrap',{}),1,root=target)
        cleanup.assert_not_called();self.assertFalse(target.exists());self.assertEqual(target.with_suffix('.sqlite3').read_bytes(),original)

    def test_proxy_and_identity_conflicts_remain_fatal(self):
        for mode in ('proxy','identity'):
            with self.subTest(mode=mode):
                user=self.root/mode;legacy=user/'runtime/agent/config.json';legacy.parent.mkdir(parents=True)
                body=json.loads(self.config.read_text(encoding='utf-8'));body.update({'proxy_enabled':True} if mode=='proxy' else {'device_id':'b'*24})
                legacy.write_text(json.dumps(body));original=legacy.read_bytes()
                with patch('guarddesk.desktop_agent.client_root',return_value=user),patch('guarddesk.desktop_agent.stop_running') as stop:
                    with self.assertRaises((OSError,ValueError)):prepare(self.dispatch('/local/bootstrap',{}),1,root=user/'new/config.json')
                stop.assert_not_called();self.assertEqual(legacy.read_bytes(),original)

    def test_pending_metadata_is_bounded_and_does_not_transmit_arbitrary_text(self):
        value={'browser_host':{'state':'pending_review','error_type':'PRIVATE_TOKEN','winerror':'PRIVATE_TOKEN','message':'PRIVATE_TOKEN'},
               'autostart':{'state':'pending_review','error_type':'PermissionError','winerror':5},'unexpected':'PRIVATE_TOKEN'}
        selected=cleanup_status(value);self.assertNotIn('PRIVATE_TOKEN',json.dumps(selected))
        self.assertEqual(selected['autostart']['winerror'],5);self.assertEqual(cleanup_status(['bad']),{})

    def test_running_session_reports_pending_cleanup_without_blocking_collector(self):
        from guarddesk.desktop_agent import run
        config=self.root/'managed/config.json';config.parent.mkdir()
        body=json.loads(self.config.read_text(encoding='utf-8'));body['machine_session']={'session':1}
        body['legacy_cleanup']={'browser_host':{'state':'pending_review','error_type':'OSError','winerror':None}}
        config.write_text(json.dumps(body));captured=[]
        with patch.object(Agent,'run',lambda a,stop:captured.append(a.feature_status)),patch('guarddesk.mis_support.ensure_agent_launcher'),patch('guarddesk.browser_host.ensure_user_host',return_value={'status':'failed_requires_review'}):
            run(config,threading.Event(),managed_session=True)
        self.assertEqual(captured[0]['legacy_migration_cleanup']['state'],'pending_review')
        self.assertEqual(captured[0]['browser_native_host']['status'],'failed_requires_review')

    def test_newer_installer_resumes_only_its_incomplete_enrollment_without_reenroll(self):
        from guarddesk.endpoint_setup import install
        import hashlib
        user,legacy,old,target=self.fixtures();ca=self.root/'owned-ca.pem';ca.write_bytes(b'owned-public-ca')
        marker=user/'endpoint-install.json';marker.write_text(json.dumps({'product':'GuardDeskEndpoint','config':str(legacy),'last_result':'incomplete_retry_same_installer'}))
        machine={'device_id':old.config['device_id'],'server':old.config['server'],'version':'0.4.75','ca_sha256':hashlib.sha256(ca.read_bytes()).hexdigest()}
        with patch('guarddesk.endpoint_setup.__version__','0.4.76'),patch('guarddesk.desktop_agent.client_root',return_value=user),patch('guarddesk.endpoint_setup.client_root',return_value=user),patch('guarddesk.machine_agent_session.discover',return_value=machine),patch('guarddesk.endpoint_setup.read_connection',return_value=(machine['server'],ca)),patch('guarddesk.endpoint_setup._install',return_value={'status':'owned resumed'}) as resumed,patch('guarddesk.endpoint_setup.enroll') as enroll:
            result=install(self.root/'owned-connection.json')
        self.assertEqual(result['status'],'owned resumed');resumed.assert_called_once();enroll.assert_not_called()

    def test_completed_or_other_account_installer_remains_non_enrolling(self):
        from guarddesk.endpoint_setup import install
        import hashlib
        ca=self.root/'owned-ca.pem';ca.write_bytes(b'owned-public-ca');user=self.root/'not-an-installed-profile'
        machine={'device_id':'a'*24,'server':self.agent.config['server'],'version':'0.4.75','ca_sha256':hashlib.sha256(ca.read_bytes()).hexdigest()}
        with patch('guarddesk.endpoint_setup.__version__','0.4.76'),patch('guarddesk.endpoint_setup.client_root',return_value=user),patch('guarddesk.machine_agent_session.discover',return_value=machine),patch('guarddesk.endpoint_setup.read_connection',return_value=(machine['server'],ca)),patch('guarddesk.endpoint_setup._install') as resumed,patch('guarddesk.endpoint_setup.enroll') as enroll:
            result=install(self.root/'owned-connection.json')
        self.assertEqual(result['status'],'already_installed');self.assertFalse(user.exists());resumed.assert_not_called();enroll.assert_not_called()

    def test_same_version_retry_must_not_claim_completed_while_collector_pending(self):
        from guarddesk.endpoint_setup import install
        from guarddesk.usb_install import InstallError
        import hashlib
        user,legacy,old,target=self.fixtures();ca=self.root/'owned-ca.pem';ca.write_bytes(b'owned-public-ca')
        marker=user/'endpoint-install.json';marker.write_text(json.dumps({'product':'GuardDeskEndpoint','config':str(legacy),'last_result':'incomplete_retry_same_installer'}))
        machine={'device_id':old.config['device_id'],'server':old.config['server'],'version':'0.4.76','ca_sha256':hashlib.sha256(ca.read_bytes()).hexdigest()}
        with patch('guarddesk.endpoint_setup.__version__','0.4.76'),patch('guarddesk.endpoint_setup.client_root',return_value=user),patch('guarddesk.machine_agent_session.discover',return_value=machine),patch('guarddesk.endpoint_setup.read_connection',return_value=(machine['server'],ca)),patch('guarddesk.endpoint_setup.session_ready',return_value=False),patch('guarddesk.endpoint_setup._install') as native:
            with self.assertRaises(InstallError) as raised:install(self.root/'owned-connection.json')
        self.assertEqual(raised.exception.report['stage'],'user_session');native.assert_not_called()
        self.assertEqual(json.loads((legacy.parent/'installation-diagnostic.json').read_text(encoding='utf-8'))['version'],'0.4.76')
        self.assertEqual(json.loads(marker.read_text(encoding='utf-8'))['last_result'],'incomplete_retry_same_installer')

    def test_readiness_rejects_old_status_and_requires_current_singleton(self):
        from guarddesk.endpoint_setup import session_ready
        path=self.root/'session-config.json';ready=path.with_name('desktop-status.json')
        ready.write_text(json.dumps({'state':'running','version':'0.4.75'}))
        with patch('guarddesk.machine_agent_session.config_path',return_value=path),patch('guarddesk.endpoint_setup.active',return_value=True):
            self.assertFalse(session_ready('a'*24,'0.4.76'))
        ready.write_text(json.dumps({'state':'running','version':'0.4.76'}))
        with patch('guarddesk.machine_agent_session.config_path',return_value=path),patch('guarddesk.endpoint_setup.active',return_value=False):
            self.assertFalse(session_ready('a'*24,'0.4.76'))
        with patch('guarddesk.machine_agent_session.config_path',return_value=path),patch('guarddesk.endpoint_setup.active',return_value=True):
            self.assertTrue(session_ready('a'*24,'0.4.76'))
