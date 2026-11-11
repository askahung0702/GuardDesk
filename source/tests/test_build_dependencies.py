"""Build input rejection at the actual verifier boundary, without host mutation."""
import base64
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import build_dependencies as build


class BuildDependencyTests(unittest.TestCase):
    def fixture(self, root, data=b'owned fixture'):
        path=root/'module.py';path.write_bytes(data)
        entry=SimpleNamespace(hash=SimpleNamespace(mode='sha256',value=base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')),size=len(data))
        dist=SimpleNamespace(files=[entry],locate_file=lambda item:path)
        return path,entry,dist

    def test_record_accepts_exact_fixture(self):
        with TemporaryDirectory() as folder:
            root=Path(folder).resolve();_,_,dist=self.fixture(root)
            self.assertEqual(build.verify_record(root,dist),1)

    def test_record_rejects_same_length_changed_content(self):
        with TemporaryDirectory() as folder:
            root=Path(folder).resolve();path,_,dist=self.fixture(root,b'abc')
            path.write_bytes(b'abd')
            with self.assertRaisesRegex(ValueError,'differs from RECORD'):build.verify_record(root,dist)

    def test_record_rejects_outside_environment(self):
        with TemporaryDirectory() as folder:
            root=Path(folder).resolve();_,_,dist=self.fixture(root)
            with self.assertRaisesRegex(ValueError,'escapes'):build.verify_record(root/'venv',dist)

    def test_record_rejects_unhashed_python(self):
        with TemporaryDirectory() as folder:
            root=Path(folder).resolve();_,entry,dist=self.fixture(root);entry.hash=None
            with self.assertRaisesRegex(ValueError,'Unhashed'):build.verify_record(root,dist)

    def test_record_rejects_empty_distribution(self):
        with self.assertRaisesRegex(ValueError,'empty'):build.verify_record(Path.cwd(),SimpleNamespace(files=[]))

    def test_lock_is_mandatory(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(ValueError,'lock required'):build.verify(Path(__file__).resolve().parents[1])

    def test_user_site_environment_rejected(self):
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[3]/'runtime') as folder:
            lock=Path(folder)/'lock.json';lock.write_text('{}')
            with patch.dict(os.environ,{'GUARDDESK_BUILD_LOCK':str(lock)}),patch.object(build.site,'ENABLE_USER_SITE',True):
                with self.assertRaisesRegex(ValueError,'user site disabled'):build.verify(Path(__file__).resolve().parents[1])


if __name__=='__main__':unittest.main()
