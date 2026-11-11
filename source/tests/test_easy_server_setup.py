"""No system trust, firewall, task or real endpoint changes in these tests."""
import ctypes
import hashlib
import http.cookiejar
import json
import os
import secrets
import socket
import ssl
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch

from guarddesk.agent import Agent, enroll, request
from guarddesk.server import serve
from guarddesk.server_config import load, start
from guarddesk.server_setup import create, read_connection, secure_directory, server_name, destination_state, wizard
from guarddesk.store import Store
import test_system
from test_detailed_controls import frame


def ports():
    with socket.socket() as first, socket.socket() as second:
        first.bind(('127.0.0.1', 0)); second.bind(('127.0.0.1', 0))
        return first.getsockname()[1], second.getsockname()[1]


class EasySetupTest(unittest.TestCase):
    api = test_system.SystemTest.api

    def setUp(self):
        runtime = Path(__file__).resolve().parents[1] / 'runtime'
        runtime.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=runtime)
        self.root = Path(self.temp.name)
        self.password = secrets.token_urlsafe(20)
        self.servers = []; self.threads = []

    def tearDown(self):
        for server in self.servers: server.shutdown()
        for server in self.servers: server.server_close()
        for thread in self.threads: thread.join(5)
        self.temp.cleanup()

    def prepare(self, source=None):
        port, console_port = ports()
        return create(self.root / 'server data', 'guarddesk.test', 'mis', self.password,
                      source=source, exe=sys.executable, port=port, console_port=console_port)

    def test_full_internal_build_fresh_center_enables_native_and_pins_local_viewer_address(self):
        from guarddesk import machine_service
        with patch.object(machine_service,'ENABLED',True):
            port,console=ports()
            result=create(self.root/'full native center','10.20.30.40','mis',self.password,exe=sys.executable,port=port,console_port=console)
            value=load(result['config'])
            self.assertTrue(value['remote_native']['enabled'])
            self.assertEqual(value['remote_native']['console_ipv4'],['10.20.30.40'])
            from guarddesk.server_setup import native_settings
            self.assertEqual(native_settings('guarddesk.test',['192.168.1.30'])['console_ipv4'],['192.168.1.30'])
            with self.assertRaises(ValueError):native_settings('guarddesk.test',['8.8.8.8'])

    def test_bad_native_settings_fail_before_new_center_is_created(self):
        from guarddesk import machine_service
        target=self.root/'must stay absent'
        with patch.object(machine_service,'ENABLED',True),self.assertRaises(ValueError):
            create(target,'10.20.30.40','mis',self.password,exe=sys.executable,native_console_ipv4=['127.0.0.1'])
        self.assertFalse(target.exists())

    def test_private_acl_and_export_contains_only_public_connection_material(self):
        result = self.prepare()
        data = self.root / 'server data'
        with zipfile.ZipFile(result['connection_bundle']) as bundle:
            self.assertEqual(set(bundle.namelist()), {'GuardDesk-CA.pem', 'endpoint-connection.json', 'Connect-Endpoint.cmd', 'README-Connection.txt','update-trust.json','browser-trust.json'})
            from guarddesk.browser_trust import verify
            body=json.loads(bundle.read('endpoint-connection.json'))
            verify(json.loads(bundle.read('browser-trust.json')),json.loads(bundle.read('update-trust.json'))['public_key'],body['server'],bundle.read('GuardDesk-CA.pem'),body['browser_deployment'])
            combined = b''.join(bundle.read(name) for name in bundle.namelist())
            self.assertNotIn(b'PRIVATE KEY', combined)
            self.assertNotIn(self.password.encode(), combined)
            exported = self.root / 'export'; exported.mkdir(); bundle.extractall(exported)
        url, ca = read_connection(exported / 'endpoint-connection.json')
        self.assertEqual(url, result['endpoint'])
        self.assertEqual(Path(ca).read_bytes(), (data / 'tls/ca.pem').read_bytes())
        self.assertIn('endpoint-setup', (exported / 'Connect-Endpoint.cmd').read_text(encoding='utf-8'))
        descriptor=json.loads((exported / 'endpoint-connection.json').read_text())
        self.assertEqual(descriptor['version'],3)
        self.assertIn('browser_deployment_authorization',descriptor)
        if os.name == 'nt':
            from ctypes import wintypes as w
            advapi = ctypes.WinDLL('advapi32', use_last_error=True)
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            advapi.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, ctypes.c_int, w.DWORD,
                w.LPVOID, w.LPVOID, w.LPVOID, w.LPVOID, ctypes.POINTER(w.LPVOID)]
            advapi.GetNamedSecurityInfoW.restype = w.DWORD
            advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [w.LPVOID, w.DWORD, w.DWORD, ctypes.POINTER(w.LPWSTR), w.LPVOID]
            advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = w.BOOL
            kernel.LocalFree.argtypes = [w.LPVOID]
            for path in (data, data / 'tls/server.key', data / 'tls/ca.key', data / 'control.sqlite3', data / 'deployment', data / 'deployment/credentials.json', data/'update-signing',data/'update-signing/private.key'):
                descriptor = w.LPVOID(); text = w.LPWSTR()
                try:
                    self.assertEqual(advapi.GetNamedSecurityInfoW(str(path), 1, 4, None, None, None, None, ctypes.byref(descriptor)), 0)
                    self.assertTrue(advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 4, ctypes.byref(text), None))
                    self.assertEqual(text.value.count('(A;'), 3, text.value)
                    self.assertNotIn(';;;WD)', text.value); self.assertNotIn(';;;AU)', text.value)
                    if path == data: self.assertIn('D:P', text.value)
                finally:
                    if text: kernel.LocalFree(ctypes.cast(text, w.LPVOID))
                    if descriptor: kernel.LocalFree(descriptor)

    def test_invalid_address_existing_directory_and_untrusted_connection_rejected(self):
        for value in ['127.0.0.1', '0.0.0.0', 'localhost', 'http://server', 'server:8787', 'server&bad', '-bad', 'a..b', '999.1.2.3']:
            with self.assertRaises(ValueError, msg=value): server_name(value)
        existing = self.root / 'existing'; existing.mkdir(); marker = existing / 'keep.txt'; marker.write_text('keep')
        with self.assertRaises(ValueError): secure_directory(existing)
        self.assertEqual(marker.read_text(), 'keep')
        result = self.prepare()
        with zipfile.ZipFile(result['connection_bundle']) as bundle:
            exported = self.root / 'export'; exported.mkdir(); bundle.extractall(exported)
        manifest = exported / 'endpoint-connection.json'
        (exported / 'GuardDesk-CA.pem').write_text('tampered')
        with self.assertRaises(ValueError): read_connection(manifest)

    def test_import_preserves_old_accounts_and_source_and_refuses_overwrite(self):
        source = self.root / 'old.sqlite3'
        old = Store(source); old.add_user('original-mis', self.password)
        with old.connect() as db: Store.event(db, 'server', 'test.migration', 'info', {'fixture': True})
        before = source.read_bytes()
        result = self.prepare(source)
        migrated = Store(load(result['config'])['db'])
        with migrated.connect() as db:
            self.assertEqual(db.execute('SELECT username FROM users').fetchall()[0][0], 'original-mis')
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE kind='test.migration'").fetchone()[0], 1)
        self.assertEqual(source.read_bytes(), before)
        with self.assertRaises(ValueError): self.prepare(source)
        self.assertTrue(migrated.verify()['valid'])

    def test_precreated_empty_server_folder_is_accepted_with_private_acl(self):
        data = self.root / 'server data'; data.mkdir()
        self.assertEqual(destination_state(data), 'empty')
        self.test_private_acl_and_export_contains_only_public_connection_material()
        self.assertEqual(destination_state(data), 'installed')

    def test_existing_install_is_detected_without_password_or_reinitialization(self):
        result = self.prepare()
        data = self.root / 'server data'
        from test_endpoint_setup import program
        application = program(self.root/'wizard application')
        exports = {'Endpoint-Connection.zip','GuardDesk-Endpoint.zip'}
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in data.rglob('*') if p.is_file() and p.name not in exports}
        with patch('builtins.input', side_effect=AssertionError('unexpected prompt')), patch('guarddesk.server_setup.getpass.getpass', side_effect=AssertionError('unexpected password prompt')), patch('sys.executable', str(application/'GuardDesk.exe')), patch('sys.frozen', True, create=True):
            wizard(str(data))
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in data.rglob('*') if p.is_file() and p.name not in exports})
        with zipfile.ZipFile(data/'GuardDesk-Endpoint.zip') as bundle:
            self.assertIn('GuardDesk/GuardDeskAgent.exe', bundle.namelist())
            self.assertIn('Setup-Endpoint.cmd', bundle.namelist())
        self.assertEqual(load(result['config'])['db'], data / 'control.sqlite3')

    def test_nonempty_folder_stops_before_password_and_preserves_files(self):
        data = self.root / 'unfinished'; data.mkdir()
        marker = data / 'control.sqlite3'; marker.write_bytes(b'preserve existing data')
        with patch('builtins.input', side_effect=AssertionError('unexpected prompt')), patch('guarddesk.server_setup.getpass.getpass', side_effect=AssertionError('unexpected password prompt')):
            with self.assertRaisesRegex(ValueError, '資料夾已有資料'): wizard(str(data))
        self.assertEqual(marker.read_bytes(), b'preserve existing data')
        with self.assertRaises(ValueError): secure_directory(data, allow_empty=True)
        self.assertEqual(marker.read_bytes(), b'preserve existing data')

    def test_split_console_policy_and_remote_frames_share_state_over_verified_tls(self):
        result = self.prepare()
        settings = load(result['config'])
        self.servers = start(settings)
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start(); self.threads.append(thread)
        self.url = result['console']
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = self.api('/api/login', {'username': 'mis', 'password': self.password})['csrf']
        code = self.api('/api/enrollments', {})['token']
        watch = self.root / 'docs'; watch.mkdir()
        ca = str(self.root / 'server data/tls/ca.pem')
        original = socket.getaddrinfo
        def resolve(host, *args, **kwargs):
            return original('127.0.0.1' if host == 'guarddesk.test' else host, *args, **kwargs)
        with patch('socket.getaddrinfo', side_effect=resolve):
            config = self.root / 'agent/config.json'
            did = enroll(config, result['endpoint'], code, watch, name='SIMULATED-PC', ca=ca)
            agent = Agent(config)
            agent.assets = {'hostname': 'SIMULATED-PC', 'agent_version': 'fixture', 'user_accounts': ['EXAMPLE\\tester']}
            policy = self.api('/api/state')['policy']
            self.api('/api/policy', {'base_version': policy['version'], 'body': {**policy['body'], 'usb_mode': 'read_only'}})
            agent.heartbeat(refresh_inventory=False); agent.heartbeat(refresh_inventory=False)
            self.assertTrue(self.api('/api/state')['devices'][0]['policy_received'])
            self.assertEqual(agent.cached_policy()['body']['usb_mode'], 'read_only')
            agent.queue('web.navigation', {'url': 'https://example.com/test', 'title': 'Fixture'})
            agent.flush()
            self.assertEqual(self.api('/api/events?category=web')['total'], 1)
            self.api('/api/remote/grant', {'username': 'mis', 'device_id': did, 'can_control': True, 'enabled': True, 'days': 1})
            agent.call('/api/agent/remote/poll', {'account': 'EXAMPLE\\tester', 'ready': True})
            session = self.api('/api/remote/request', {'device_id': did, 'mode': 'control', 'reason': 'Local MIS test'})
            with self.assertRaises(ConnectionError):
                agent.call('/api/agent/remote/update', {'session_id': session['id'], 'action': 'frame', 'frame': frame()})
            agent.call('/api/agent/remote/update', {'session_id': session['id'], 'action': 'approve', 'account': 'EXAMPLE\\tester'})
            agent.call('/api/agent/remote/update', {'session_id': session['id'], 'action': 'frame', 'frame': frame()})
            self.assertIn('frame', self.api('/api/remote/session?id=' + session['id']))
            self.api('/api/remote/input', {'session_id': session['id'], 'actions': [{'type': 'click', 'x': .5, 'y': .5}]})
            packet = agent.call('/api/agent/remote/update', {'session_id': session['id'], 'action': 'frame', 'frame': frame()})
            self.assertEqual(len(packet['commands']), 1)
            self.api('/api/remote/stop', {'session_id': session['id']})
            self.assertNotIn(session['id'], self.servers[0].remote_memory)
            self.assertIs(self.servers[0].remote_memory, self.servers[1].remote_memory)
            client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
            for path in ['/', '/app.js', '/api/state', '/api/remote/catalog']:
                with self.assertRaises(urllib.error.HTTPError) as error: client.open(result['endpoint'] + path)
                self.assertEqual(error.exception.code, 403)
            with self.assertRaises(ConnectionError):
                request(result['endpoint'], '/api/login', {'username': 'mis', 'password': self.password}, ca=ca)
            with self.assertRaises(ConnectionError): request(result['endpoint'], '/api/agent/heartbeat', {})
            with self.assertRaises(ConnectionError): request(result['console'], '/api/agent/heartbeat', {}, token=agent.config['token'])
        spoof = urllib.request.Request(self.url + '/', headers={'Host': 'hostile.example'})
        with self.assertRaises(urllib.error.HTTPError) as denied: self.client.open(spoof)
        self.assertEqual(denied.exception.code, 403)

    def test_console_bind_failure_closes_endpoint_listener(self):
        result = self.prepare(); settings = load(result['config'])
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', settings['local_console_port'])); occupied.listen()
            with self.assertRaises(OSError): start(settings)
        # The first listener must not remain half-started after the second fails.
        with socket.socket() as probe:
            probe.bind(('0.0.0.0', settings['port']))
        with self.assertRaises(ValueError): serve(settings['db'], '0.0.0.0', 0, surface='console')


if __name__ == '__main__': unittest.main()
