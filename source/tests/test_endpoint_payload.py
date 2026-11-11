"""Real ZIP/signature/projection boundaries; synthetic bytes, no installers."""
import hashlib
import json
import threading
import unittest
import zipfile
from pathlib import Path
from guarddesk import __version__,endpoint_payload as payload,update_packages as packages
from guarddesk import bundled_release as bundled,update_preflight,endpoint_package
import test_bundled_release

class EndpointPayloadTest(unittest.TestCase):
    setUp=test_bundled_release.BundledReleaseTest.setUp
    write_manifest=test_bundled_release.BundledReleaseTest.write_manifest
    prepare=test_bundled_release.BundledReleaseTest.prepare

    def add_mis(self):
        path=self.source/'_internal/GuardDeskMIS.exe';path.write_bytes(b'console only, never executed')
        self.write_manifest();return path

    def test_projection_preserves_source_and_all_endpoint_required_files(self):
        path=self.add_mis();raw=(self.source/payload.METADATA).read_bytes()
        original=bundled.inspect(self.source,__version__,threading.Event())
        files,overrides=payload.project(self.source,original)
        self.assertNotIn('_internal/GuardDeskMIS.exe',files)
        self.assertEqual(set(files),set(original)-payload.CONSOLE_ONLY)
        self.assertEqual(json.loads(overrides[payload.METADATA])['files'],{n:h for n,h in files.items() if n!=payload.METADATA})
        self.assertEqual((self.source/payload.METADATA).read_bytes(),raw);self.assertTrue(path.is_file())

    def test_no_console_file_is_byte_for_byte_compatible(self):
        original=bundled.inspect(self.source,__version__,threading.Event())
        files,overrides=payload.project(self.source,original)
        self.assertEqual(files,original);self.assertEqual(overrides,{})

    def test_excluded_file_corruption_still_fails_integrity(self):
        path=self.add_mis();original=bundled.inspect(self.source,__version__,threading.Event());path.write_bytes(b'corrupted')
        with self.assertRaises(ValueError):payload.project(self.source,original)
        with self.assertRaises(bundled.BundleError):self.prepare()

    def test_actual_publisher_signs_projected_manifest_and_preflight_counts_same_zip(self):
        self.add_mis();raw=(self.source/payload.METADATA).read_bytes();result=self.prepare()
        from guarddesk import updates
        archive=updates.repository(self.store)/(result['id']+'.zip')
        with self.store.connect() as db:envelope=json.loads(db.execute('SELECT envelope FROM update_releases').fetchone()[0])
        signed=packages.verify(envelope,packages.public_key(packages.signer(self.store.path.parent)))
        packages.validate_manifest(signed);self.assertEqual(packages.file_hash(archive),signed['sha256'])
        with zipfile.ZipFile(archive) as z:
            packages.inspect_zip(z,signed['files'])
            self.assertNotIn('_internal/GuardDeskMIS.exe',z.namelist())
            self.assertEqual(set(z.namelist()),set(signed['files']))
            inner=json.loads(z.read(payload.METADATA))
            for name,value in signed['files'].items():self.assertEqual(hashlib.sha256(z.read(name)).hexdigest(),value)
            self.assertEqual(inner['files'],{n:h for n,h in signed['files'].items() if n!=payload.METADATA})
            total=sum(i.file_size for i in z.infolist())
        sizes=update_preflight.candidate_size(self.source)
        self.assertEqual(sizes,{'compressed_bytes':archive.stat().st_size,'incoming_bytes':total,'files':len(signed['files'])})
        self.assertEqual((self.source/payload.METADATA).read_bytes(),raw)
        self.assertEqual(self.prepare()['id'],result['id'])

    def release(self,path):
        hashes={}
        with zipfile.ZipFile(path,'x',zipfile.ZIP_DEFLATED) as z:
            for item in self.source.rglob('*'):
                if item.is_file():
                    name='GuardDesk/'+item.relative_to(self.source).as_posix();z.write(item,name);hashes[name]=packages.file_hash(item)
            z.writestr('MANIFEST-SHA256.json',json.dumps(hashes));z.writestr('build-info.json',json.dumps({'GuardDesk':__version__}))

    def test_generic_release_import_projects_and_verifies_original_hashes(self):
        self.add_mis();source=self.root/'release.zip';self.release(source)
        repository=self.root/'import';repository.mkdir();manifest,archive=packages.import_release(source,repository)
        self.assertNotIn('_internal/GuardDeskMIS.exe',manifest['files'])
        with zipfile.ZipFile(archive) as z:
            inner=json.loads(z.read(payload.METADATA));self.assertEqual(inner['files'],{n:h for n,h in manifest['files'].items() if n!=payload.METADATA})
            for n,h in manifest['files'].items():self.assertEqual(hashlib.sha256(z.read(n)).hexdigest(),h)

    def test_new_install_bundle_has_same_projected_manifest_and_keeps_center_MIS(self):
        import test_endpoint_setup
        from guarddesk.server_setup import create
        import sys
        source=test_endpoint_setup.program(self.root/'new-program')
        (source/'_internal/GuardDeskMIS.exe').write_bytes(b'console MIS, not executed')
        files={p.relative_to(source).as_posix():packages.file_hash(p) for p in source.rglob('*') if p.is_file() and p.relative_to(source).as_posix()!=payload.METADATA}
        (source/payload.METADATA).write_text(json.dumps({'format':1,'version':__version__,'files':files}),encoding='utf-8')
        raw=(source/payload.METADATA).read_bytes();server=create(self.root/'connection','owned.guarddesk.test','mis','7',exe=sys.executable)
        output=self.root/'endpoint.zip';endpoint_package.build(source,server['connection_bundle'],output)
        with zipfile.ZipFile(output) as z:
            self.assertNotIn('GuardDesk/_internal/GuardDeskMIS.exe',z.namelist())
            entries=json.loads(z.read('endpoint-files.json'))['files'];inner=json.loads(z.read('GuardDesk/'+payload.METADATA))
            self.assertEqual(inner['files'],{n:h for n,h in entries.items() if n!=payload.METADATA})
            for n,h in entries.items():self.assertEqual(hashlib.sha256(z.read('GuardDesk/'+n)).hexdigest(),h)
        self.assertTrue((source/'_internal/GuardDeskMIS.exe').is_file());self.assertEqual((source/payload.METADATA).read_bytes(),raw)

if __name__=='__main__':unittest.main()
