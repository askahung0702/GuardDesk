"""Installed-source registration only; no endpoints, code execution or deployment."""
import hashlib
import json
import os
import tempfile
import threading
import unittest
import time
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import patch
from guarddesk import __version__,bundled_release as bundled,update_packages as packages,updates
from guarddesk.server_setup import secure_directory
from guarddesk.store import Store
import test_system


class BundledServerTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp;tearDown=test_system.SystemTest.tearDown;api=test_system.SystemTest.api
    def test_retry_requires_admin_csrf_and_cannot_select_an_arbitrary_source(self):
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/updates/bundled/prepare',{},csrf=False)
        self.assertEqual(denied.exception.code,403)
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/updates/bundled/prepare',{'source':'other.exe'})
        self.assertEqual(denied.exception.code,400)
        self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        with self.assertRaises(urllib.error.HTTPError) as denied:self.api('/api/updates/bundled/prepare',{})
        self.assertEqual(denied.exception.code,403)
    def test_http_preparation_populates_catalog_without_upload_or_job(self):
        parent=secure_directory(self.root/'private-program');source=parent/'GuardDesk';source.mkdir();(source/'_internal').mkdir()
        files={'GuardDesk.exe':b'fixture','GuardDeskAgent.exe':b'fixture gui','_internal/runtime.dll':b'fixture lib'}
        for name,blob in files.items():(source/name).write_bytes(blob)
        (source/bundled.METADATA).write_text(json.dumps({'format':1,'version':__version__,'files':{k:hashlib.sha256(v).hexdigest() for k,v in files.items()}}))
        self.server.bundled_release.source=source
        self.api('/api/updates/bundled/prepare',{})
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            catalog=self.api('/api/updates')
            if catalog['bundled_release']['status']=='ready':break
            time.sleep(.02)
        self.assertEqual(catalog['bundled_release']['status'],'ready')
        self.assertEqual(catalog['latest_release_id'],catalog['bundled_release']['release_id']);self.assertFalse(catalog['jobs'])


class BundledReleaseTest(unittest.TestCase):
    def setUp(self):
        runtime=Path(__file__).resolve().parents[1]/'runtime'
        self.temp=tempfile.TemporaryDirectory(dir=runtime);self.addCleanup(self.temp.cleanup)
        self.root=secure_directory(Path(self.temp.name)/'private');self.source=self.root/'GuardDesk';self.source.mkdir()
        (self.source/'_internal').mkdir()
        for name,blob in {'GuardDesk.exe':b'not executed','GuardDeskAgent.exe':b'GUI fixture','_internal/lib.dll':b'library fixture'}.items():(self.source/name).write_bytes(blob)
        self.write_manifest();self.store=Store(self.root/'data/control.sqlite3');self.stop=threading.Event()
    def write_manifest(self):
        files={p.relative_to(self.source).as_posix():packages.file_hash(p) for p in self.source.rglob('*') if p.is_file() and p.relative_to(self.source).as_posix()!=bundled.METADATA}
        (self.source/bundled.METADATA).write_text(json.dumps({'format':1,'version':__version__,'files':files}),encoding='utf-8')
    def prepare(self):return bundled.prepare(self.store,self.source,__version__,self.stop)
    def test_registers_signed_application_and_no_job_then_reuses_on_restart(self):
        first=self.prepare();self.assertFalse(first['cached']);second=self.prepare();self.assertTrue(second['cached']);self.assertEqual(first['id'],second['id'])
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM update_jobs').fetchone()[0],0)
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE kind='update.bundled_release_prepared'").fetchone()[0],1)
            manifest=packages.verify(json.loads(db.execute('SELECT envelope FROM update_releases').fetchone()[0]),packages.public_key(packages.signer(self.store.path.parent)))
            catalog=updates.catalog(db);self.assertEqual(catalog['latest_release_id'],first['id'])
        with zipfile.ZipFile(updates.repository(self.store)/(first['id']+'.zip')) as archive:
            self.assertEqual(set(archive.namelist()),set(manifest['files']))
            self.assertIn(bundled.METADATA,archive.namelist())
            self.assertFalse(any(name.endswith(('.pem','.key','.sqlite3')) for name in archive.namelist()))
    def test_changed_missing_extra_and_wrong_version_are_never_registered(self):
        meta=self.source/bundled.METADATA;original=meta.read_bytes()
        (self.source/'GuardDesk.exe').write_bytes(b'changed')
        with self.assertRaises(bundled.BundleError):self.prepare()
        (self.source/'GuardDesk.exe').write_bytes(b'not executed');(self.source/'extra.txt').write_bytes(b'extra')
        with self.assertRaises(ValueError):self.prepare()
        (self.source/'extra.txt').unlink();meta.unlink()
        with self.assertRaises(bundled.BundleError):self.prepare()
        meta.write_bytes(original);data=json.loads(original);data['version']='0.4.11';meta.write_text(json.dumps(data))
        with self.assertRaises(bundled.BundleError):self.prepare()
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM update_releases').fetchone()[0],0)
    def test_same_version_different_bytes_do_not_replace_old_release(self):
        first=self.prepare();(self.source/'GuardDesk.exe').write_bytes(b'new contents');self.write_manifest()
        with self.assertRaises(bundled.BundleError) as conflict:self.prepare()
        self.assertEqual(conflict.exception.code,'version_conflict')
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT id FROM update_releases').fetchone()[0],first['id'])
    def test_missing_signing_material_is_not_recreated_for_existing_release(self):
        self.prepare();key=self.store.path.parent/'update-signing/private.key';key.unlink()
        with self.assertRaises(ValueError):self.prepare()
        self.assertFalse(key.exists())
    def test_existing_archive_corruption_is_reported_not_overwritten(self):
        result=self.prepare();archive=updates.repository(self.store)/(result['id']+'.zip');archive.write_bytes(b'corrupted')
        with self.assertRaises(bundled.BundleError) as error:self.prepare()
        self.assertEqual(error.exception.code,'storage_failed');self.assertEqual(archive.read_bytes(),b'corrupted')
    def test_cancel_and_source_permission_failure_do_not_publish(self):
        self.stop.set()
        with self.assertRaises(InterruptedError):self.prepare()
        self.stop.clear()
        with patch('guarddesk.source_permissions.check_source',side_effect=OSError('foreign writable')):
            if os.name=='nt':
                with self.assertRaises(bundled.BundleError) as error:self.prepare()
                self.assertEqual(error.exception.code,'source_not_private')
    def test_permission_diagnostic_contains_only_fixed_reason_and_source_location(self):
        from guarddesk.source_permissions import SourcePermissionError
        publisher=bundled.Publisher(self.store,threading.Lock());publisher.source=self.source;self.addCleanup(publisher.close)
        with patch('guarddesk.source_permissions.check_source',side_effect=SourcePermissionError(self.source,'untrusted_write')):
            publisher.start();publisher.thread.join(5)
        state=publisher.snapshot()
        self.assertEqual(state['code'],'source_not_private')
        self.assertEqual(state['diagnostic'],{'path':str(self.source),'reason':'untrusted_write'})
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM update_releases').fetchone()[0],0)

    def test_publisher_background_completion_and_cached_ready_no_restart(self):
        publisher=bundled.Publisher(self.store,threading.Lock());publisher.source=self.source
        self.addCleanup(publisher.close)
        self.assertTrue(publisher.start());publisher.thread.join(5)
        self.assertEqual(publisher.snapshot()['status'],'ready');self.assertFalse(publisher.start())
    def test_error_is_fixed_code_and_shutdown_interrupts_waiting_lock(self):
        lock=threading.Lock();publisher=bundled.Publisher(self.store,lock);publisher.source=self.source
        with patch('guarddesk.bundled_release.prepare',side_effect=RuntimeError('secret diagnostic')):
            publisher.start();publisher.thread.join(5)
        self.assertEqual(publisher.snapshot()['code'],'preparation_failed');self.assertNotIn('secret',json.dumps(publisher.snapshot()))
        lock.acquire()
        try:publisher.start();publisher.close();self.assertFalse(publisher.thread.is_alive())
        finally:lock.release()

    def test_automatic_browser_failure_does_not_block_normal_update_release(self):
        publisher=bundled.Publisher(self.store,threading.Lock());publisher.source=self.source
        self.addCleanup(publisher.close)
        with patch('guarddesk.browser_auto_publication.ensure',side_effect=OSError('private diagnostic')):
            publisher.start();publisher.thread.join(10)
        state=publisher.snapshot()
        self.assertEqual(state['status'],'ready')
        self.assertEqual(state['browser_publication'],{'status':'automatic_preparation_failed','error_type':'OSError'})
        self.assertNotIn('private diagnostic',json.dumps(state))


if __name__=='__main__':unittest.main()
