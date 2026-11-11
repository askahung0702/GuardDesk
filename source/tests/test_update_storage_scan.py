"""Bounded metadata scans on owned trees; no installed endpoint is touched."""
import json,os,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from guarddesk import update_storage as storage
from guarddesk.update_client import failure_details


class CapacityScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def test_directory_chain_checked_before_and_after_scan_not_per_leaf(self):
        child=self.root/'nested';child.mkdir()
        for i in range(1200):(child/str(i)).write_bytes(b'owned')
        with patch.object(storage.packages,'plain',wraps=storage.packages.plain) as check:
            value=storage.budget([self.root],7)
        self.assertEqual(value['used_bytes'],6000);self.assertEqual(value['entries'],1201)
        self.assertEqual(value['projected_bytes'],6007)
        self.assertEqual(check.call_count,5) # root resolution plus two directory boundaries

    def test_timeout_includes_bounded_safe_progress(self):
        (self.root/'data').write_bytes(b'owned')
        with patch.object(storage,'SCAN_SECONDS',-1):
            with self.assertRaises(storage.CapacityError) as caught:storage.budget([self.root],9)
        detail=failure_details('capacity',caught.exception)
        self.assertEqual(detail['code'],'scan_timeout');self.assertEqual(detail['entries'],1)
        self.assertEqual(detail['root_index'],0);self.assertGreaterEqual(detail['elapsed_ms'],0)
        self.assertNotIn(str(self.root),json.dumps(detail));self.assertNotIn('token',json.dumps(detail))

    def test_timeout_after_last_entry_metadata_and_empty_directory(self):
        (self.root/'data').write_bytes(b'owned')
        with patch.object(storage,'time',SimpleNamespace(monotonic=iter([0,0,31,31]).__next__)):
            with self.assertRaises(storage.CapacityError):storage.budget([self.root],0)
        (self.root/'data').unlink()
        with patch.object(storage,'time',SimpleNamespace(monotonic=iter([0,31,31]).__next__)):
            with self.assertRaises(storage.CapacityError):storage.budget([self.root],0)

    def test_real_junction_never_descended_and_external_file_preserved(self):
        if os.name!='nt':self.skipTest('Windows junction boundary')
        with tempfile.TemporaryDirectory() as other:
            target=Path(other);file=target/'preserve';file.write_bytes(b'outside')
            link=self.root/'link'
            made=subprocess.run(['cmd','/d','/c','mklink','/J',str(link),str(target)],capture_output=True)
            self.assertEqual(made.returncode,0)
            try:
                with self.assertRaises(ValueError):storage.budget([self.root],0)
                self.assertEqual(file.read_bytes(),b'outside')
            finally:link.rmdir()

    def test_broken_symlink_metadata_is_rejected_without_following(self):
        # Windows symbolic-link creation may require privilege, so exercise
        # the same no-follow branch with an exact DirEntry metadata boundary.
        info=SimpleNamespace(st_mode=0o120777,st_file_attributes=0x400)
        entry=SimpleNamespace(path=str(self.root/'link'),stat=lambda **kw:info)
        class Entries:
            def __enter__(self):return iter([entry])
            def __exit__(self,*a):pass
        with patch.object(storage.os,'scandir',return_value=Entries()):
            with self.assertRaises(ValueError):storage.budget([self.root],0)

    def test_directory_replaced_by_junction_during_enumeration_is_rechecked(self):
        original=storage.packages.plain;calls=[]
        def plain(path):
            calls.append(path)
            if len(calls)==3:raise ValueError('owned ancestor replacement')
            return original(path)
        (self.root/'data').write_bytes(b'owned')
        with patch.object(storage.packages,'plain',side_effect=plain):
            with self.assertRaisesRegex(ValueError,'replacement'):storage.budget([self.root],0)
