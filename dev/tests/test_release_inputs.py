from pathlib import Path
import hashlib,sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from restore_release_inputs import restore
class ReleaseInputsTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='guarddesk-artifact-test-');self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.root=self.base/'checkout';self.root.mkdir()
        self.origin=self.base/'approved-inputs';(self.origin/'runtime/owned').mkdir(parents=True)
        (self.origin/'runtime/owned/file.txt').write_bytes(b'owned')
        self.lock={'files':{'runtime/owned/file.txt':hashlib.sha256(b'owned').hexdigest()}}
    def test_plan_makes_no_output(self):
        self.assertFalse(restore(self.root,self.origin,self.lock)['applied'])
        self.assertFalse((self.root/'runtime').exists())
    def test_apply_is_idempotent_and_scoped(self):
        for _ in range(2):restore(self.root,self.origin,self.lock,True)
        self.assertEqual((self.root/'runtime/owned/file.txt').read_bytes(),b'owned')
    def test_wrong_hash_stops_before_writes(self):
        self.lock['files']['runtime/owned/file.txt']='0'*64
        with self.assertRaises(ValueError):restore(self.root,self.origin,self.lock,True)
        self.assertFalse((self.root/'runtime').exists())
    def test_existing_different_input_is_preserved(self):
        dest=self.root/'runtime/owned';dest.mkdir(parents=True);(dest/'file.txt').write_bytes(b'keep')
        with self.assertRaisesRegex(ValueError,'preserve'):restore(self.root,self.origin,self.lock,True)
        self.assertEqual((dest/'file.txt').read_bytes(),b'keep')
    def test_escape_path_is_rejected(self):
        self.lock['files']={'runtime/../../outside.txt':'0'*64}
        with self.assertRaises(ValueError):restore(self.root,self.origin,self.lock,True)
if __name__=='__main__':unittest.main()
