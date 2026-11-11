"""Actual authenticated HTTP download with a distinct synthetic endpoint runtime."""
import hashlib
import http.cookiejar
import io
import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch
from guarddesk import endpoint_source,remote_trial
from guarddesk.endpoint_package import sha
from guarddesk.endpoint_files import secure_directory
from guarddesk.remote_components import REMOTE_FILES,ENDPOINT_REMOTE_FILES,cohort_manifest
from guarddesk.server_setup import create
from tools.remote_endpoint_artifact import deployment_scope
import test_system


def artifact(root,version='0.4.99'):
    secure_directory(root)
    (root/'_internal/remote').mkdir(parents=True)
    for name in ('GuardDesk.exe','GuardDeskAgent.exe','GuardDeskInstaller.exe','GuardDeskService.exe',*('_internal/remote/'+n for n in ENDPOINT_REMOTE_FILES)):
        (root/name).write_bytes(('synthetic never executed '+name).encode())
    cohort=cohort_manifest({n:sha(root/'_internal/remote'/n) if n in ENDPOINT_REMOTE_FILES else '0'*64 for n in REMOTE_FILES},build_id='a'*64)
    (root/'_internal/remote/remote-cohort.json').write_text(json.dumps(cohort))
    (root/'_internal/remote-endpoint-build.json').write_text(json.dumps({'build_role':'remote-endpoint','install_profile':remote_trial.PROFILE,'version':version,'cohort_build_id':'a'*64}))
    from guarddesk.release_scope import METADATA
    (root/METADATA).write_text(json.dumps(deployment_scope(version)))
    (root/endpoint_source.MANIFEST).write_text(json.dumps({'format':1,'version':version,'files':{p.relative_to(root).as_posix():sha(p) for p in root.rglob('*') if p.is_file()}}))
    return {'path':root,'version':version,'manifest_sha256':sha(root/endpoint_source.MANIFEST),'cohort_build_id':'a'*64}


class EndpointSourceTest(unittest.TestCase):
    api=test_system.SystemTest.api
    tearDown=test_system.SystemTest.tearDown

    def setUp(self):
        test_system.SystemTest.setUp(self)
        enabled=patch.object(remote_trial,'ENABLED',True);enabled.start();self.addCleanup(enabled.stop)
        self.selection=artifact(self.root/'dedicated')
        self.server.endpoint_source=self.selection
        created=create(self.root/'setup','guarddesk.test','mis','7',exe=sys.executable)
        (self.root/'Endpoint-Connection.zip').write_bytes(Path(created['connection_bundle']).read_bytes())

    def test_download_uses_pinned_endpoint_version_not_center_version(self):
        with patch('guarddesk.endpoint_package.application_directory',side_effect=AssertionError('center fallback')):
            data=self.api('/api/endpoint-package',{})
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            outer=json.loads(archive.read('endpoint-files.json'))
            self.assertEqual(outer['version'],'0.4.99')
            self.assertEqual(hashlib.sha256(archive.read('GuardDesk/'+endpoint_source.MANIFEST)).hexdigest(),self.selection['manifest_sha256'])
            self.assertIn('0.4.99',archive.read('README-Remote-Test.txt').decode('utf-8-sig'))
            self.assertNotIn('GuardDesk/_internal/GuardDeskMIS.exe',archive.namelist())
            self.assertFalse(any(n.endswith('.ps1') for n in archive.namelist()))
            for name,digest in outer['files'].items():self.assertEqual(hashlib.sha256(archive.read('GuardDesk/'+name)).hexdigest(),digest)
        with self.store.connect() as db:
            row=db.execute("SELECT details FROM events WHERE kind='admin.endpoint_package'").fetchone()
            value=json.loads(row[0]);self.assertTrue(value['dedicated_endpoint']);self.assertEqual(value['version'],'0.4.99')

    def test_corrupt_pin_missing_file_and_changed_scope_never_fallback(self):
        original=self.selection['manifest_sha256']
        with patch('guarddesk.endpoint_package.application_directory',side_effect=AssertionError('center fallback')):
            for key,value in (('manifest_sha256','0'*64),('cohort_build_id','0'*64),('version','0.4.98')):
                prior=self.selection[key];self.selection[key]=value
                with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/endpoint-package',{})
                self.assertEqual(error.exception.code,409);self.selection[key]=prior
            (self.selection['path']/'GuardDesk.exe').write_bytes(b'changed')
            with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/endpoint-package',{})
            self.assertEqual(error.exception.code,409)
        self.assertEqual(self.selection['manifest_sha256'],original)

    def test_csrf_and_admin_remain_required(self):
        with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/endpoint-package',{},csrf=False)
        self.assertEqual(error.exception.code,403)
        client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.api('/api/login',{'username':'reader','password':self.password},client=client)
        with self.assertRaises(urllib.error.HTTPError) as error:self.api('/api/endpoint-package',{},client=client)
        self.assertEqual(error.exception.code,403)

    def test_trial_center_refuses_update_jobs_import_and_retry(self):
        for path in ('/api/updates/jobs','/api/updates/notify','/api/updates/bundled/prepare','/api/updates/import'):
            with self.subTest(path=path),self.assertRaises(urllib.error.HTTPError) as error:self.api(path,{})
            self.assertEqual(error.exception.code,409)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM update_jobs').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM update_releases').fetchone()[0],0)

    def test_source_setting_strict_and_cannot_enable_standard_center(self):
        raw={**self.selection,'path':'dedicated'}
        parsed=endpoint_source.parse(raw,self.root/'server.json')
        self.assertEqual(endpoint_source.inspect(parsed),self.selection['path'])
        for extra in ({'path':'\\\\server\\share'},{'path':''},{'shell':'anything'},{'manifest_sha256':'bad'}):
            with self.assertRaises(ValueError):endpoint_source.parse({**raw,**extra},self.root/'server.json')
        with patch.object(remote_trial,'ENABLED',False),self.assertRaises(ValueError):endpoint_source.parse(raw,self.root/'server.json')

    def test_manual_endpoint_never_publishes_full_center_as_update(self):
        from guarddesk.bundled_release import Publisher
        with patch.object(sys,'frozen',True,create=True):publisher=Publisher(self.store,threading.Lock(),manual_endpoint=True)
        self.assertFalse(publisher.start());self.assertIsNone(publisher.source)
        self.assertEqual(publisher.snapshot()['status'],'remote_trial_manual_only')
        self.assertFalse(publisher.snapshot()['automatic_dispatch'])
        publisher.close()

    def test_manifest_change_between_selection_and_packaging_is_rejected(self):
        from guarddesk.endpoint_package import build
        with self.assertRaisesRegex(ValueError,'manifest changed'):
            build(self.selection['path'],self.root/'Endpoint-Connection.zip',self.root/'blocked.zip',version='0.4.99',manifest_sha256='0'*64)
        self.assertFalse((self.root/'blocked.zip').exists())
