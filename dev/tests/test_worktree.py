from pathlib import Path
import json,sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from worktree import stage,contained
class StageTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='guarddesk-checkout-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        (self.root/'source').mkdir();(self.root/'source/module.py').write_text('x=1\n')
    def test_stage_and_refresh_preserve_canonical_source(self):
        target,_=stage(self.root);self.assertEqual((target/'module.py').read_text(),'x=1\n')
        (self.root/'source/module.py').write_text('x=2\n');stage(self.root)
        self.assertEqual((target/'module.py').read_text(),'x=2\n')
        self.assertEqual((self.root/'source/module.py').read_text(),'x=2\n')
    def test_modified_stage_is_preserved_and_rejected(self):
        target,_=stage(self.root);(target/'module.py').write_text('owned_edit=1\n')
        with self.assertRaisesRegex(ValueError,'edited'):stage(self.root)
        self.assertEqual((target/'module.py').read_text(),'owned_edit=1\n')
    def test_unowned_stage_is_never_overwritten(self):
        target=self.root/'runtime/remote-next-src';target.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError,'Unowned'):stage(self.root)
    def test_removed_canonical_file_is_removed_only_from_unchanged_stage(self):
        target,_=stage(self.root);(self.root/'source/module.py').unlink();stage(self.root)
        self.assertFalse((target/'module.py').exists())
    def test_escape_is_rejected(self):
        with self.assertRaises(ValueError):contained(self.root,self.root/'../outside')
    def test_unmanaged_stage_file_is_preserved(self):
        target,_=stage(self.root);(target/'unexpected.py').write_text('new=True')
        with self.assertRaisesRegex(ValueError,'Unmanaged'):stage(self.root)
        self.assertTrue((target/'unexpected.py').exists())
if __name__=='__main__':unittest.main()
