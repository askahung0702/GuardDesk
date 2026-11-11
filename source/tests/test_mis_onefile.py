"""Public connection envelope, optional reason and own tray window only."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from guarddesk.mis_onefile import append_connection,embedded,executable,defaults,MAGIC
from guarddesk.server_setup import certificates
from guarddesk.remote import optional_reason,RemoteError
from cryptography import x509
import ipaddress


class OnefileTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);tls=self.root/'tls';tls.mkdir();certificates(tls,x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
        self.ca=(tls/'ca.pem').read_bytes();self.exe=self.root/'renamed.exe'
    def tearDown(self):self.tmp.cleanup()
    def test_public_trailer_roundtrip_and_ephemeral_ca_cleanup(self):
        blob=append_connection(b'MZsynthetic-template','https://company.example:8787',self.ca);self.exe.write_bytes(blob)
        self.assertEqual(embedded(self.exe)['server'],'https://company.example:8787')
        with defaults(self.exe) as args:
            ca=Path(args[-1]);self.assertEqual(ca.read_bytes(),self.ca);self.assertNotIn('token',str(args))
        self.assertFalse(ca.exists())
    def test_bad_trailer_never_falls_back_to_another_server(self):
        blob=append_connection(b'MZsynthetic-template','https://company.example:8787',self.ca)
        for bad in (blob[:-len(MAGIC)-4]+struct.pack('<I',100001)+MAGIC,blob[:30]+b'!'+blob[31:]):
            self.exe.write_bytes(bad)
            with self.assertRaises((ValueError,UnicodeError)):embedded(self.exe)
        with self.assertRaises(ValueError):append_connection(b'MZ','http://company.example',self.ca)
        with self.assertRaises(ValueError):append_connection(b'MZ','https://company.example',b'PRIVATE KEY')
    def test_builder_exports_public_material_only(self):
        app=self.root/'app';(app/'_internal').mkdir(parents=True);template=app/'_internal/GuardDeskMIS.exe';template.write_bytes(b'MZtemplate')
        descriptor=json.dumps({'server':'https://company.example','deployment_code':'must-not-export'}).encode()
        with patch('guarddesk.endpoint_package.files',return_value=[template]),patch('guarddesk.endpoint_package.public_connection',return_value=(descriptor,self.ca)):
            blob=executable(self.root,app);self.assertNotIn(b'must-not-export',blob);self.assertNotIn(b'PRIVATE KEY',blob)
            self.assertEqual(executable(None,app),template.read_bytes())
    def test_optional_reason_retains_strict_input_boundary(self):
        for body in ({},{'reason':''},{'reason':'  '}):self.assertEqual(optional_reason(body),'')
        self.assertEqual(optional_reason({'reason':' help '}),'help')
        for value in (None,True,1,[],{},'a'*201,'line\nbreak'):
            with self.subTest(value=value),self.assertRaises(RemoteError):optional_reason({'reason':value})


@unittest.skipUnless(os.name=='nt','Windows own tray required')
class TrayTest(unittest.TestCase):
    def test_actual_own_notify_icon_callbacks_and_cleanup(self):
        from guarddesk.remote_tray import TrayIcon
        calls=[];tray=TrayIcon(lambda f:f(),lambda:calls.append('show'),lambda:calls.append('stop'),lambda:calls.append('exit'))
        try:
            self.assertTrue(tray.added);self.assertTrue(tray.hwnd)
            tray.message(tray.hwnd,tray.callback,0,0x400);tray.message(tray.hwnd,0x111,2,0)
            self.assertEqual(calls,['show','stop'])
        finally:tray.close()
        self.assertFalse(tray.added);self.assertIsNone(tray.hwnd)

if __name__=='__main__':unittest.main()
