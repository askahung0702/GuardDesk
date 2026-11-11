"""Real private file/secret ACLs, explicit outer-ancestor ACL fixture.

Managed workspace ancestors grant extra sandbox principals write access; they
must not be added to production trust. The product still checks all ancestors.
No live server configuration or installed directory is changed.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from guarddesk.remote_preview_config import parse,prepare
from guarddesk.server_setup import secure_directory
from test_remote_relay import POLICY
SECRET=b'owned-TURN-fixture-secret-never-product-key'

class PreviewConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]/'runtime');self.addCleanup(self.temp.cleanup)
        self.root=secure_directory(Path(self.temp.name)/'private');self.config=self.root/'server.json';self.config.write_text('{}',encoding='utf-8')
        if os.name=='nt':
            from guarddesk.source_permissions import WindowsSecurity,SYSTEM
            original=WindowsSecurity.descriptor
            def descriptor(api,path):
                if Path(path).is_relative_to(self.root):return original(api,path)
                return SYSTEM,[(0,0,2032127,SYSTEM)] # explicit outer fixture only
            self.outer=patch.object(WindowsSecurity,'descriptor',descriptor);self.outer.start();self.addCleanup(self.outer.stop)
    def value(self,relay=False):
        return parse({'enabled':True,'console_ipv4':['10.8.0.20'],**({'relay':POLICY,'secret_file':'remote-turn.secret'} if relay else {})},self.config)
    def test_disabled_opt_in_does_not_touch_config_or_secret_files(self):
        with patch('guarddesk.remote_preview_config.check_permissions',side_effect=AssertionError('No reads expected')):
            self.assertFalse(prepare(parse({'enabled':False},self.config))['enabled'])
            self.assertIsNone(prepare(None))
    def test_unknown_insecure_or_arbitrary_secret_paths_are_refused(self):
        for value in ({'enabled':1},{'enabled':True,'ignore_bad_certificate':True},
            {'enabled':True,'console_ipv4':['8.8.8.8']},{'enabled':True,'console_ipv4':['127.0.0.1']},
            {'enabled':True,'relay':POLICY,'secret_file':'../other.key'},
            {'enabled':True,'relay':POLICY,'secret_file':'C:\\other.key'},
            {'enabled':False,'relay':POLICY,'secret_file':'remote-turn.secret'},
            {'enabled':True,'secret_file':'remote-turn.secret'}):
            with self.subTest(value=value),self.assertRaises(ValueError):parse(value,self.config)
    def test_explicit_private_startup_config_and_secret_create_only_memory_authority(self):
        secret=self.root/'remote-turn.secret';secret.write_bytes(SECRET)
        original=self.config.read_bytes();prepared=prepare(self.value(True))
        self.assertTrue(prepared['enabled']);self.assertEqual(prepared['console_ipv4'],['10.8.0.20'])
        self.assertIsNotNone(prepared['authority']);self.assertEqual(self.config.read_bytes(),original);self.assertEqual(secret.read_bytes(),SECRET)
    def test_permission_check_does_not_scan_sibling_histories(self):
        with patch.object(Path,'rglob',side_effect=AssertionError('No tree scan')):self.assertTrue(prepare(self.value())['enabled'])
    def test_untrusted_outer_ancestor_is_refused_not_added_to_trust(self):
        if os.name!='nt':self.skipTest('Windows ACL boundary')
        from guarddesk.source_permissions import WindowsSecurity,SourcePermissionError
        with patch.object(WindowsSecurity,'descriptor',return_value=('S-1-5-18',[(0,0,2032127,'S-1-5-11')])):
            with self.assertRaises(SourcePermissionError):prepare(self.value())
    def test_other_account_read_permission_on_synthetic_secret_is_rejected(self):
        if os.name!='nt':self.skipTest('Windows ACL boundary')
        secret=self.root/'remote-turn.secret';secret.write_bytes(SECRET)
        result=subprocess.run(['icacls',str(secret),'/grant','*S-1-5-11:(R)'],capture_output=True)
        self.assertEqual(result.returncode,0)
        with self.assertRaises(ValueError):prepare(self.value(True))
    def test_missing_or_oversized_secret_never_falls_back_to_direct(self):
        with self.assertRaises((ValueError,FileNotFoundError)):prepare(self.value(True))
        secret=self.root/'remote-turn.secret'
        for data in (b'x'*31,b'x'*129,b'x'*31+b' ',b'\xef\xbb\xbf'+SECRET,SECRET+b'\n'*140):
            secret.write_bytes(data)
            with self.subTest(size=len(data)),self.assertRaises(ValueError):prepare(self.value(True))
    def test_server_load_preserves_old_config_and_parses_explicit_native_section(self):
        from guarddesk.server_config import load
        body={'host':'127.0.0.1','port':18787,'db':'control.sqlite3','cert':'server.crt','key':'server.key'}
        self.config.write_text(json.dumps(body),encoding='utf-8');self.assertNotIn('remote_native',load(self.config))
        self.config.write_text(json.dumps({**body,'remote_native':{'enabled':True}}),encoding='utf-8')
        self.assertTrue(load(self.config)['remote_native']['enabled'])

if __name__=='__main__':unittest.main()
