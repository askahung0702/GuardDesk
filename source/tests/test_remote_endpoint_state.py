"""Existing identity/SQLite boundaries, no installed paths or Windows mutation."""
import importlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
from guarddesk import remote_trial
from guarddesk.remote_endpoint_state import RemoteEndpointState, ROUTES


class RemoteStateTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.config=self.root/'config.json'
        self.config.write_text(json.dumps({'server':'https://owned.test','token':'owned-fixture',
            'device_id':'a'*24,'watch':str(self.root),'install_profile':remote_trial.PROFILE}))
        self.enabled=patch.object(remote_trial,'ENABLED',True)
        self.enabled.start();self.addCleanup(self.enabled.stop)

    def test_existing_identity_and_removal_resume_with_minimal_schema(self):
        from guarddesk.decommission import remember,saved
        before=self.config.read_bytes()
        state=RemoteEndpointState(self.config)
        remember(state,{'id':'owned-job'},'removed')
        with state.db() as db:
            db.execute("INSERT INTO state VALUES('machine_profiles','[]')")
            self.assertEqual({r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")},{'state','outbox'})
        again=RemoteEndpointState(self.config)
        self.assertEqual(saved(again),{'id':'owned-job','phase':'removed'})
        self.assertEqual(self.config.read_bytes(),before)
        self.assertEqual(again.flush(),{'sent':0,'pending':False})
        with again.wal_session(),again.db() as db:
            self.assertEqual(db.execute("SELECT value FROM state WHERE key='machine_profiles'").fetchone()[0],'[]')

    def test_existing_nonempty_audit_db_untouched_before_reject(self):
        path=self.config.with_suffix('.sqlite3')
        with closing(sqlite3.connect(path)) as db:
            db.execute('CREATE TABLE outbox(event_id TEXT PRIMARY KEY,payload TEXT,created REAL)')
            db.execute("INSERT INTO outbox VALUES('owned','{}',1)")
            db.commit()
        before=path.read_bytes()
        with self.assertRaises(PermissionError):RemoteEndpointState(self.config)
        self.assertEqual(path.read_bytes(),before)
        self.assertFalse(Path(str(path)+'-wal').exists())

    def test_control_file_rejected_without_creating_database(self):
        (self.root/'usb-original.json').write_text('{}')
        with self.assertRaises(PermissionError):RemoteEndpointState(self.config)
        self.assertFalse(self.config.with_suffix('.sqlite3').exists())

    def test_late_queue_never_uploaded_deleted_or_reported_empty(self):
        state=RemoteEndpointState(self.config)
        with state.db() as db:db.execute("INSERT INTO outbox VALUES('owned','{}',1)")
        with patch.object(state,'call',side_effect=AssertionError('network')):
            with self.assertRaises(PermissionError):state.flush(max_batches=8,require_empty=False)
        with state.db() as db:self.assertEqual(db.execute('SELECT event_id FROM outbox').fetchone(),('owned',))

    def test_profile_and_session_cannot_switch_roles(self):
        for extra in ({'install_profile':'standard'},{'machine_session':{'parent':1}}):
            settings=json.loads(self.config.read_text());settings.update(extra);self.config.write_text(json.dumps(settings))
            with self.assertRaises((PermissionError,ValueError)):RemoteEndpointState(self.config)
            self.assertFalse(self.config.with_suffix('.sqlite3').exists())
        with patch.object(remote_trial,'ENABLED',False),self.assertRaises(PermissionError):RemoteEndpointState(self.config)

    def test_route_allowlist_checked_before_transport(self):
        state=RemoteEndpointState(self.config)
        with patch('guarddesk.remote_endpoint_state.transport',return_value=object()) as transport,patch('guarddesk.remote_endpoint_state.request',return_value={}) as request:
            for path in ('/api/agent/events','/api/agent/enroll','/api/agent/updates/poll','/api/agent/custom-status'):
                with self.assertRaises(PermissionError):state.call(path,{})
            transport.assert_not_called();request.assert_not_called()
            for path in ROUTES:state.call(path,{},timeout=3)
            self.assertEqual(request.call_count,len(ROUTES));self.assertEqual(transport.call_count,1)
            self.assertEqual(request.call_args.kwargs['timeout'],3)

    def test_supervisor_does_not_load_legacy_policy(self):
        from guarddesk.machine_agent import Supervisor
        state=RemoteEndpointState(self.config)
        with state.db() as db:db.execute("INSERT INTO state VALUES('extended_policy','invalid retained legacy text')")
        with patch('guarddesk.machine_agent.cached_machine_policy',side_effect=AssertionError('policy')):
            supervisor=Supervisor(state,threading.Event(),platform=SimpleNamespace())
            supervisor.sync_collectors();supervisor.report_main_update()
        self.assertIsNone(supervisor.monitor)
        self.assertIsNone(state.machine_session_policy)

    def test_remote_worker_once_uses_minimal_state(self):
        with patch('guarddesk.windows_privilege.is_admin',return_value=True),patch('guarddesk.machine_agent.eligible',return_value=True),patch('guarddesk.update_native.folder',return_value=self.root),patch('guarddesk.remote_components.read_cohort'),patch('guarddesk.remote_endpoint_state.request',return_value={}),patch('guarddesk.remote_endpoint_state.transport',return_value=object()):
            result=remote_trial.worker(self.config,threading.Event(),once=True)
        self.assertEqual(result['status'],'configured_remote_only')

    def test_decommission_removal_ack_resumes_without_collectors(self):
        from guarddesk import decommission
        state=RemoteEndpointState(self.config)
        job={'id':'owned','main':'ready','status':'running'}
        state.call=Mock(side_effect=lambda path,body:{'job':job})
        with patch.object(decommission,'remove_task') as remove:
            self.assertEqual(decommission.native_step(SimpleNamespace(agent=state)), 'done')
            self.assertEqual(decommission.native_step(SimpleNamespace(agent=RemoteEndpointState(self.config))), 'done')
        remove.assert_called_once()

    def test_fresh_process_can_load_remote_roles_with_full_agent_absent(self):
        code='''
import importlib.abc,sys
class Absent(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname in {'guarddesk.agent','guarddesk.native_usb','guarddesk.application_control','guarddesk.windows_controls'}:raise AssertionError(fullname)
sys.meta_path.insert(0,Absent())
from guarddesk import remote_trial
remote_trial.ENABLED=True
from guarddesk import endpoint_setup,remote_endpoint_state,native_installer,usb_install
from guarddesk import machine_agent,machine_agent_windows,machine_agent_session,remote_admin_windows
'''
        result=subprocess.run([sys.executable,'-B','-c',code],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_compatibility_exports_preserve_serialization_and_transport(self):
        from guarddesk import agent,endpoint_transport,store,serialization,windows_controls,windows_privilege
        for name in ('request','transport','private_write','enroll','NoRedirect'):
            self.assertIs(getattr(agent,name),getattr(endpoint_transport,name))
        self.assertIs(store.canonical,serialization.canonical)
        self.assertIs(store.digest,serialization.digest)
        self.assertIs(windows_controls.is_admin,windows_privilege.is_admin)
