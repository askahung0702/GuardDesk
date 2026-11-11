import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from guarddesk.deployment import prepare_connection
from guarddesk.endpoint_package import SETUP, server_installer
from guarddesk.server_setup import create
from guarddesk.store import Store
from test_endpoint_setup import program


class InstallerEntryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]/'runtime')
        self.addCleanup(self.temp.cleanup); self.root=Path(self.temp.name)

    def test_connection_only_click_explains_and_stops_before_installation(self):
        if os.name != 'nt': self.skipTest('Windows CMD required')
        folder=self.root/'只有連線設定';folder.mkdir()
        script=folder/'Connect-Endpoint.cmd';script.write_bytes(SETUP)
        result=subprocess.run([os.environ.get('COMSPEC','cmd.exe'),'/d','/c',str(script)],input=b'\r\n',capture_output=True,timeout=15)
        self.assertEqual(result.returncode,2)
        text=result.stdout.decode('utf-8',errors='replace')
        self.assertIn('GuardDesk-Endpoint.zip',text)
        self.assertIn('Endpoint-Connection.zip',text)
        self.assertNotIn('The system cannot find',text)
        self.assertFalse((folder/'runtime').exists())

    def prepare(self):
        source=program(self.root/'application')
        result=create(self.root/'data','guarddesk.test','mis','7',exe=source/'GuardDesk.exe')
        return source,result

    def test_real_application_layout_server_setup_builds_ready_installer(self):
        source,result=self.prepare();path=Path(result['endpoint_package'])
        self.assertEqual(path.name,'GuardDesk-Endpoint.zip')
        with zipfile.ZipFile(path) as z:
            for n in ['Setup-Endpoint.cmd','Connect-Endpoint.cmd','endpoint-files.json','GuardDesk/GuardDesk.exe','GuardDesk/GuardDeskAgent.exe','GuardDesk/_internal/runtime.dll','update-trust.json']:
                self.assertIn(n,z.namelist())
            self.assertEqual(z.read('Connect-Endpoint.cmd'),z.read('Setup-Endpoint.cmd'))
            before=json.loads(z.read('endpoint-connection.json'))
            self.assertTrue(before['deployment_code']);self.assertEqual(before['server'],result['endpoint'])
            self.assertFalse(any(n.endswith(('.key','.sqlite3')) for n in z.namelist()))
        self.assertEqual(server_installer(source/'GuardDesk.exe',result['connection_bundle']),path)
        with zipfile.ZipFile(path) as z: self.assertEqual(json.loads(z.read('endpoint-connection.json')),before)

    def test_failed_rebuild_preserves_previous_complete_package(self):
        source,result=self.prepare();path=Path(result['endpoint_package']);before=path.read_bytes()
        def broken(_source,_connection,target):
            Path(target).write_bytes(b'incomplete fixture');raise OSError('simulated disk failure')
        with patch('guarddesk.endpoint_package.build',side_effect=broken):
            with self.assertRaises(OSError):server_installer(source/'GuardDesk.exe',result['connection_bundle'])
        self.assertEqual(path.read_bytes(),before)
        self.assertFalse(list(path.parent.glob('endpoint-build-*')))

    def test_rebuild_after_rotation_embeds_new_code_only(self):
        source,result=self.prepare();path=Path(result['endpoint_package'])
        with zipfile.ZipFile(path) as z:before=json.loads(z.read('endpoint-connection.json'))
        prepare_connection(Store(path.parent/'control.sqlite3'),Path(result['connection_bundle']),'fixture',rotate=True)
        server_installer(source/'GuardDesk.exe',result['connection_bundle'])
        with zipfile.ZipFile(path) as z:after=json.loads(z.read('endpoint-connection.json'))
        self.assertNotEqual(before['deployment_code'],after['deployment_code'])
        self.assertEqual(before['server'],after['server'])
