"""Isolated packages/identities. UAC, HKCU Run and production launch are mocked."""
import hashlib
import http.cookiejar
import io
import json
import tempfile
import time
import sys
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch

from guarddesk.endpoint_package import build, sha
from guarddesk.endpoint_setup import install, stage_application, autostart, remove_autostart_for_config
from guarddesk.server_setup import create, secure_directory
from guarddesk.agent import Agent
import test_system


def program(root):
    secure_directory(root)
    root = root / 'GuardDesk'
    root.mkdir()
    (root / '_internal').mkdir()
    for name in ('GuardDesk.exe', 'GuardDeskAgent.exe', '_internal/runtime.dll'):
        (root / name).write_bytes(('synthetic fixture ' + name).encode())
    scripts = root / '_internal/guarddesk/windows'; scripts.mkdir(parents=True)
    for name in ('install-usb.ps1', 'controls.ps1', 'applications.ps1'):
        (scripts / name).write_bytes(('synthetic non-executed fixture ' + name).encode())
    from guarddesk import __version__
    (root / '_internal/agent-release.json').write_text(json.dumps({'format': 1, 'version': __version__,
        'files': {p.relative_to(root).as_posix(): sha(p) for p in root.rglob('*') if p.is_file()}}))
    return root


class EndpointSetupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.server = create(self.root / 'server', 'guarddesk.test', 'mis', '7', exe=sys.executable)
        self.source = program(self.root / 'program')
        self.output = self.root / 'endpoint.zip'
        build(self.source, self.server['connection_bundle'], self.output)
        self.package = self.root / 'package'; self.package.mkdir()
        with zipfile.ZipFile(self.output) as z: z.extractall(self.package)

    def test_bundle_includes_only_public_connection_and_programs(self):
        (self.source / 'secret.key').write_text('PRIVATE KEY')  # Outside whitelisted application tree.
        with zipfile.ZipFile(self.output) as z:
            self.assertIn('Setup-Endpoint.cmd', z.namelist())
            self.assertNotIn('secret.key', z.namelist())
            self.assertNotIn(b'PRIVATE KEY', b''.join(z.read(n) for n in z.namelist()))
            files = json.loads(z.read('endpoint-files.json'))['files']
            from guarddesk.endpoint_package import REQUIRED
            self.assertTrue(REQUIRED <= files.keys())
            self.assertIn('不需要手動執行 PS1',z.read('README-Endpoint.txt').decode('utf-8'))
            for name, expected in files.items(): self.assertEqual(hashlib.sha256(z.read('GuardDesk/' + name)).hexdigest(), expected)
        (self.source / '_internal/secret.key').write_text('PRIVATE KEY')
        with self.assertRaises(ValueError): build(self.source, self.server['connection_bundle'], self.root/'blocked.zip')
        self.assertFalse((self.root/'blocked.zip').exists())

    def test_stage_hash_and_traversal_before_enrollment(self):
        destination = self.root / 'client'; destination.mkdir()
        app = stage_application(self.package, destination)
        self.assertEqual(sha(app/'GuardDeskAgent.exe'), sha(self.source/'GuardDeskAgent.exe'))
        (self.package/'GuardDesk/GuardDeskAgent.exe').write_bytes(b'changed')
        with self.assertRaises(ValueError): stage_application(self.package, destination)
        manifest = self.package/'endpoint-files.json'; data=json.loads(manifest.read_text())
        data['files']['../outside.exe'] = '0'*64; manifest.write_text(json.dumps(data))
        with self.assertRaises(ValueError): stage_application(self.package, destination)
        self.assertFalse((destination/'outside.exe').exists())

    def test_cancel_uac_then_retry_preserves_identity_queue_and_one_code(self):
        destination = self.root/'client'; connection=self.package/'endpoint-connection.json'
        calls=[]
        def enrollment(config, url, code, watch, ca):
            calls.append(code)
            config.write_text(json.dumps({'server':url,'token':'isolated-fixture-only','device_id':'a'*24,'watch':str(watch),'ca':ca}))
            Agent(config).queue('test.offline', {'fixture':True})
        def denied(config): raise PermissionError('fixture cancelled UAC')
        with patch('guarddesk.windows_privilege.is_admin',return_value=False), patch('guarddesk.endpoint_setup.enroll', side_effect=enrollment), patch('guarddesk.endpoint_setup.autostart') as startup:
            with self.assertRaises(PermissionError): install(connection, destination, lambda:self.fail('embedded shared code must not prompt'), denied)
            startup.assert_not_called()
            config=destination/'runtime/agent/config.json'; before=config.read_bytes()
            token=lambda:self.fail('retry must not ask for or consume another enrollment code')
            result=install(connection,destination,token,lambda cfg:None,lambda app,cfg:'running')
            self.assertEqual(result['status'],'installed')
            self.assertEqual(config.read_bytes(),before)
            self.assertEqual(calls,[json.loads(connection.read_text())['deployment_code']])
            startup.assert_called_once()
            self.assertNotIn('isolated-fixture-only',startup.call_args.args[1])
            self.assertTrue((destination/'Stop-Agent.cmd').is_file())
            self.assertEqual(Agent(config).queue_status()['pending'],1)
            self.assertEqual(json.loads((config.parent/'installation-diagnostic.json').read_text())['code'],'completed')
            remove_autostart_for_config(config)
            self.assertTrue(startup.call_args.kwargs['remove'])
            self.assertFalse(json.loads((destination/'endpoint-install.json').read_text())['autostart'])

    def test_running_agent_repair_preserves_queue_and_restarts_without_manual_stop(self):
        destination=self.root/'repair-client';connection=self.package/'endpoint-connection.json'
        def enrollment(config,url,code,watch,ca):
            config.write_text(json.dumps({'server':url,'token':'PRIVATE-FIXTURE','device_id':'b'*24,'watch':str(watch),'ca':ca}))
            Agent(config).queue('fixture.pending',{'safe':True})
        with patch('guarddesk.windows_privilege.is_admin',return_value=False),patch('guarddesk.endpoint_setup.enroll',side_effect=enrollment) as enroll_call,patch('guarddesk.endpoint_setup.autostart'),patch('guarddesk.endpoint_setup.active',return_value=False):
            install(connection,destination,native_install=lambda cfg:None,start_agent=lambda app,cfg:'running')
            config=destination/'runtime/agent/config.json';identity=config.read_bytes()
            with patch('guarddesk.endpoint_setup.active',return_value=True),patch('guarddesk.endpoint_setup.stop_running') as stop,patch('guarddesk.endpoint_setup.launch',return_value='running') as launch:
                install(connection,destination,native_install=lambda cfg:None)
                stop.assert_called_once_with(config);launch.assert_called_once()
            self.assertEqual(config.read_bytes(),identity);self.assertEqual(enroll_call.call_count,1)
            self.assertEqual(Agent(config).queue_status()['pending'],1)

    def test_native_failure_keeps_running_agent_and_saves_redacted_diagnostic(self):
        destination=self.root/'failure-client';connection=self.package/'endpoint-connection.json'
        def enrollment(config,url,code,watch,ca):
            config.write_text(json.dumps({'server':url,'token':'PRIVATE-FIXTURE','device_id':'c'*24,'watch':str(watch),'ca':ca}))
        with patch('guarddesk.windows_privilege.is_admin',return_value=False),patch('guarddesk.endpoint_setup.enroll',side_effect=enrollment),patch('guarddesk.endpoint_setup.autostart'),patch('guarddesk.endpoint_setup.active',return_value=False):
            install(connection,destination,native_install=lambda cfg:None,start_agent=lambda app,cfg:'running')
        def failed(cfg):raise OSError('Access is denied PRIVATE-FIXTURE')
        with patch('guarddesk.windows_privilege.is_admin',return_value=False),patch('guarddesk.endpoint_setup.active',return_value=True),patch('guarddesk.endpoint_setup.stop_running') as stop:
            with self.assertRaises(OSError):install(connection,destination,native_install=failed)
            stop.assert_not_called()
        report=json.loads((destination/'runtime/agent/installation-diagnostic.json').read_text())
        self.assertEqual(report['code'],'access_denied');self.assertNotIn('PRIVATE-FIXTURE',json.dumps(report))

    def test_existing_unknown_folder_and_modified_ca_preserved(self):
        destination=self.root/'unknown';destination.mkdir();(destination/'keep').write_text('keep')
        with patch('guarddesk.windows_privilege.is_admin',return_value=False):
            with self.assertRaises(ValueError): install(self.package/'endpoint-connection.json',destination)
        self.assertEqual((destination/'keep').read_text(),'keep')
        (self.package/'GuardDesk-CA.pem').write_text('tampered')
        with patch('guarddesk.windows_privilege.is_admin',return_value=False):
            with self.assertRaises(ValueError): install(self.package/'endpoint-connection.json',self.root/'untouched')
        self.assertFalse((self.root/'untouched').exists())

    def test_missing_update_key_rejected_before_enrollment_or_creating_runtime(self):
        (self.package/'update-trust.json').unlink()
        destination=self.root/'untouched-client'
        with patch('guarddesk.windows_privilege.is_admin',return_value=False),patch('guarddesk.endpoint_setup.enroll') as enroll_call:
            with self.assertRaises(ValueError):install(self.package/'endpoint-connection.json',destination)
            enroll_call.assert_not_called()
        self.assertFalse(destination.exists())

    def test_startup_conflicts_never_overwrite_existing_values(self):
        # No access to actual HKCU Run: replace every registry operation.
        import winreg
        from unittest.mock import MagicMock
        key=MagicMock(); key.__enter__.return_value=key
        with patch.object(winreg,'CreateKey',return_value=key), patch.object(winreg,'QueryValueEx',return_value=('unrelated.exe',winreg.REG_SZ)), patch.object(winreg,'SetValueEx') as set_value, patch.object(winreg,'DeleteValue') as delete:
            for remove in (False,True):
                with self.assertRaises(OSError): autostart('fixture','expected.exe',remove=remove)
            set_value.assert_not_called();delete.assert_not_called()


class EndpointDownloadTest(unittest.TestCase):
    setUp = test_system.SystemTest.setUp
    tearDown = test_system.SystemTest.tearDown
    api = test_system.SystemTest.api

    def test_admin_download_has_no_private_keys_and_denies_auditor(self):
        created=create(self.root/'setup','guarddesk.test','mis','7',exe=sys.executable)
        (self.root/'Endpoint-Connection.zip').write_bytes(Path(created['connection_bundle']).read_bytes())
        source=program(self.root/'program')
        with patch('guarddesk.endpoint_package.application_directory',return_value=source):
            raw=self.api('/api/endpoint-package',{})
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            self.assertIn('GuardDesk/GuardDeskAgent.exe',z.namelist())
            self.assertNotIn(b'PRIVATE KEY',b''.join(z.read(n) for n in z.namelist()))
        # The final HTTP byte reaches the client before the worker's finally block.
        deadline=time.monotonic()+3
        while list(self.root.glob('guarddesk-endpoint-*')) and time.monotonic()<deadline:time.sleep(.02)
        self.assertEqual(list(self.root.glob('guarddesk-endpoint-*')),[])
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE kind='admin.endpoint_package'").fetchone()[0],1)
        reader=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.api('/api/login',{'username':'reader','password':self.password},client=reader)
        with self.assertRaises(urllib.error.HTTPError) as denied: self.api('/api/endpoint-package',{},client=reader)
        self.assertEqual(denied.exception.code,403)
        with self.assertRaises(urllib.error.HTTPError) as anonymous:
            self.api('/api/endpoint-package',{},client=urllib.request.build_opener(urllib.request.ProxyHandler({})))
        self.assertEqual(anonymous.exception.code,401)

    def test_failed_build_cleans_private_temporary_folder_and_unlocks(self):
        (self.root/'Endpoint-Connection.zip').write_bytes(b'broken')
        source=program(self.root/'program')
        with patch('guarddesk.endpoint_package.application_directory',return_value=source):
            with self.assertRaises(urllib.error.HTTPError): self.api('/api/endpoint-package',{})
        self.assertEqual(list(self.root.glob('guarddesk-endpoint-*')),[])
        self.assertTrue(self.server.package_lock.acquire(blocking=False))
        self.server.package_lock.release()
