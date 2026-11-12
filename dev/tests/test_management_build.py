from pathlib import Path
import copy,hashlib,json,os,subprocess,sys,tempfile,unittest,zipfile
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from build_management import output_path,build_lock,one_new,Pipeline,passing
from management_package import publish,verify_zip,clean_scan
from native_inputs import prepare
from worktree import digest,webrtc_source

class ManagementBuildTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='guarddesk-build-test-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);(self.root/'runtime').mkdir();(self.root/'source').mkdir()
        (self.root/'CURRENT-BASELINE.json').write_text(json.dumps({'version':'0.4.105','revision':'001'}))
        (self.root/'DEVELOPMENT-BASELINE.json').write_text(json.dumps({'accepted_version':'0.4.105','accepted_revision':'001'}))
    def test_sealed_version_and_invalid_versions_rejected(self):
        for value in ('0.4.105','0.4.99','0.4.0106','../106','106','0.4.106-beta'):
            with self.subTest(value=value),self.assertRaises(ValueError):output_path(self.root,value,'001')
        target,_=output_path(self.root,'0.4.106','001');self.assertEqual(target.name,'GuardDesk-Management-0.4.106-internal-001.zip')
    def test_scan_exit_zero_alone_is_not_a_clean_verdict(self):
        self.assertTrue(clean_scan(0,b'Scan finished. Found no threats.'))
        for code,raw in ((0,b'Threat remediated'),(0,b''),(2,b'found no threats.'),(0,'unknown localized result'.encode())):
            self.assertFalse(clean_scan(code,raw))
    def test_explicit_webrtc_checkout_requires_pinned_clean_tracked_source(self):
        vendor=self.root/'external'/'src';vendor.mkdir(parents=True);(vendor/'.git').mkdir()
        dependencies=self.root/'dependencies';dependencies.mkdir()
        revision='a'*40
        (dependencies/'toolchains.lock.json').write_text(json.dumps({'webrtc':{'revision':revision}}))
        success=subprocess.CompletedProcess([],0,revision+'\n','')
        clean=subprocess.CompletedProcess([],0,'','')
        with patch('worktree.subprocess.run',side_effect=[success,clean]) as run:
            self.assertEqual(webrtc_source(self.root,vendor),vendor.resolve())
            self.assertIn('safe.directory='+str(vendor.resolve()),run.call_args_list[0].args[0])
            self.assertIn('--quiet',run.call_args_list[1].args[0])
        with patch('worktree.subprocess.run',return_value=subprocess.CompletedProcess([],0,'b'*40+'\n','')):
            with self.assertRaisesRegex(ValueError,'revision differs'):webrtc_source(self.root,vendor)
        with patch('worktree.subprocess.run',side_effect=[success,subprocess.CompletedProcess([],1)]):
            with self.assertRaisesRegex(ValueError,'local changes'):webrtc_source(self.root,vendor)
        with self.assertRaises(ValueError):webrtc_source(self.root,self.root/'source')
    def test_existing_package_or_checksum_never_overwritten(self):
        target,_=output_path(self.root,'0.4.106','001');target.parent.mkdir()
        for path in (target,target.with_suffix('.zip.sha256')):
            path.write_text('SEALED')
            with self.assertRaises(ValueError):output_path(self.root,'0.4.106','001')
            self.assertEqual(path.read_text(),'SEALED');path.unlink()
    def test_contradictory_baseline_stops(self):
        (self.root/'DEVELOPMENT-BASELINE.json').write_text('{"accepted_version":"0.4.104","accepted_revision":"001"}')
        with self.assertRaises(ValueError):output_path(self.root,'0.4.106','001')
    def test_lock_is_exclusive_and_released_after_error(self):
        with self.assertRaisesRegex(RuntimeError,'OWNED'):
            with build_lock(self.root):
                with self.assertRaisesRegex(ValueError,'Another'): 
                    with build_lock(self.root):pass
                raise RuntimeError('OWNED')
        with build_lock(self.root):pass
    def test_failed_command_stops_and_does_not_use_previous_receipt(self):
        run=self.root/'runtime/run';run.mkdir();report={'stages':[]}
        (self.root/'runtime/prior.json').write_text('{"passed":true}')
        p=Pipeline(self.root,run,Path(sys.executable),self.root,os.environ.copy(),report)
        with self.assertRaisesRegex(ValueError,'failed'):p.new('owned-failure','*.json',[sys.executable,'-c','raise SystemExit(7)'])
        self.assertFalse(report['stages'][0]['passed']);self.assertFalse((self.root/'dist').exists())
    def test_new_receipt_selection_rejects_zero_or_ambiguous(self):
        folder=self.root/'runtime';old=set(folder.glob('*.json'))
        with self.assertRaises(ValueError):one_new(folder,'*.json',old)
        for name in ('a.json','b.json'):(folder/name).write_text('{}')
        with self.assertRaises(ValueError):one_new(folder,'*.json',old)
    def test_passing_gate_requires_explicit_boolean(self):
        path=self.root/'runtime/a.json';path.write_text('{"passed":1}')
        with self.assertRaises(ValueError):passing(path)
    def test_publish_checks_hash_and_preserves_existing(self):
        candidate=self.root/'runtime/candidate.zip';candidate.write_bytes(b'OWNED')
        out=self.root/'dist/out.zip'
        with self.assertRaises(ValueError):publish(candidate,out,'0'*64)
        self.assertFalse(out.exists());publish(candidate,out,digest(candidate));self.assertEqual(out.read_bytes(),b'OWNED')
        with self.assertRaises(ValueError):publish(candidate,out,digest(candidate))
        self.assertEqual(out.read_bytes(),b'OWNED')
    def test_archive_tamper_and_traversal_fail(self):
        expected={'data.txt':hashlib.sha256(b'GOOD').hexdigest()}
        for kind in ('content','traversal','duplicate','sums'):
            path=self.root/('owned-'+kind+'.zip')
            with zipfile.ZipFile(path,'x') as z:
                z.writestr('data.txt',b'BAD' if kind=='content' else b'GOOD')
                z.writestr('SHA256SUMS.txt',b'' if kind=='sums' else (expected['data.txt']+'  data.txt\n').encode())
                if kind=='traversal':z.writestr('../escape',b'bad')
                if kind=='duplicate':z.writestr('DATA.TXT',b'GOOD')
            with self.subTest(kind=kind),self.assertRaises(ValueError):verify_zip(path,expected)
    def cache(self):
        origin=self.root/'origin';origin.mkdir();source=self.root/'source'
        (source/'native/remote/webrtc').mkdir(parents=True)
        (source/'owned.cpp').write_text('OWNED_SOURCE');lock={}
        (source/'native/remote/owned.cpp').write_text('OWNED_SOURCE')
        for kind in ('CMake','WebRTC','service'):
            folder=origin/kind;folder.mkdir();artifact=folder/'Release';artifact.mkdir()
            name='GuardDeskService.exe' if kind=='service' else 'owned.exe';(artifact/name).write_bytes(b'OWNED_BINARY')
            body={'passed':True,'sources':{'owned.cpp':digest(source/'owned.cpp')},'stages':[0,0] if kind=='service' else [{'exit':0}],
                'source_stable':True,'sources_stable':True,'revision':'owned','artifacts':{name:{'sha256':digest(artifact/name)}},'sha256':digest(artifact/name)}
            receipt=folder/'receipt.json';receipt.write_text(json.dumps(body));lock[kind]={'receipt':kind+'/receipt.json',
                'sha256':digest(receipt),'artifacts':kind+'/Release','revision':'owned'}
        return origin,lock
    def test_cache_is_explicit_and_no_copy_until_all_hashes_match(self):
        origin,lock=self.cache();(origin/'WebRTC/Release/owned.exe').write_bytes(b'TAMPER')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):prepare(self.root,self.root/'source',origin,lock)
        self.assertFalse((self.root/'runtime/native-input-cache').exists())
    def test_cache_stale_source_and_receipt_are_rejected(self):
        origin,lock=self.cache();changed=copy.deepcopy(lock);changed['CMake']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'receipt mismatch'):prepare(self.root,self.root/'source',origin,changed)
        (self.root/'source/owned.cpp').write_text('NEW_SOURCE')
        with self.assertRaisesRegex(ValueError,'source changed'):prepare(self.root,self.root/'source',origin,lock)
    def test_cache_escape_rejected(self):
        origin,lock=self.cache();lock['CMake']['receipt']='../CURRENT-BASELINE.json'
        with self.assertRaisesRegex(ValueError,'escaped'):prepare(self.root,self.root/'source',origin,lock)
    def test_cmd_is_ascii_crlf_and_runs_actual_help_from_other_directory(self):
        root=Path(__file__).resolve().parents[2];cmd=root/'Build-Management.cmd';raw=cmd.read_bytes()
        self.assertTrue(raw.isascii());self.assertNotIn(b'\x08',raw);self.assertNotIn(b'\n',raw.replace(b'\r\n',b''))
        for cp in (437,950,65001):
            command=f'chcp {cp}>nul & call "{cmd}" --help'
            result=subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=self.root,capture_output=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn(b'--version',result.stdout);self.assertNotIn(b'not recognized',result.stdout+result.stderr)
if __name__=='__main__':unittest.main()
