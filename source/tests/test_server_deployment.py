"""Isolated deployment/cutover tests; no company DB or native system changes."""
import datetime
import http.cookiejar
import ipaddress
import json
import secrets
import socket
import ssl
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from guarddesk.agent import Agent, request
from guarddesk.server import serve, Server
from guarddesk.server_backup import snapshot
from guarddesk.server_config import load, check
from guarddesk.store import Store
import test_system
from test_detailed_controls import frame
import test_management


def certificate(directory, expired=False):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'localhost')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(private.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + datetime.timedelta(days=-1 if expired else 1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private, hashes.SHA256()))
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / 'server.crt', directory / 'server.key'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(private.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / 'separate data' / 'control.sqlite3'
        self.store = Store(self.db)
        self.store.add_user('mis', secrets.token_urlsafe(20))
        self.cert, self.key = certificate(self.root / 'program' / 'tls')
        self.path = self.root / 'program' / 'server.json'
        self.settings = {'db': '../separate data/control.sqlite3', 'host': '0.0.0.0',
                         'port': 8787, 'cert': 'tls/server.crt', 'key': 'tls/server.key'}
        self.path.write_text(json.dumps(self.settings), encoding='utf-8')

    def tearDown(self):
        self.temp.cleanup()

    def test_config_paths_and_preflight_do_not_depend_on_working_directory(self):
        settings = load(self.path)
        self.assertEqual(settings['db'], self.db)
        before = self.db.read_bytes()
        result = check(settings)
        self.assertTrue(result['passed'])
        self.assertEqual(result['roles'], {'admin': 1})
        self.assertEqual(before, self.db.read_bytes())
        self.assertEqual(list(self.db.parent.glob('guarddesk-preflight-*')), [])

    def test_missing_database_does_not_create_an_empty_replacement(self):
        settings = load(self.path)
        settings['db'] = self.db.parent / 'misspelled.sqlite3'
        with self.assertRaisesRegex(ValueError, '找不到既有資料庫'):
            check(settings)
        self.assertFalse(settings['db'].exists())

    def test_bad_settings_rejected(self):
        for changes in ({'port': True}, {'port': 0}, {'db': ''}, {'password': 'not-allowed'},
                        {'key': 'tls/server.crt'}):
            self.path.write_text(json.dumps({**self.settings, **changes}))
            with self.assertRaises(ValueError):
                load(self.path)
        self.path.write_text('{"host":"a","host":"b"}')
        with self.assertRaisesRegex(ValueError, '重複'):
            load(self.path)

    def test_invalid_tls_has_no_database_or_listener_side_effect(self):
        missing = self.root / 'not-created.sqlite3'
        with self.assertRaises(OSError):
            serve(missing, port=0, cert=self.root / 'absent.crt', key=self.key)
        with self.assertRaises(ValueError):
            serve(missing, port=0, cert=self.cert)
        with self.assertRaises(ValueError):
            serve(missing, host='0.0.0.0', port=0)
        self.assertFalse(missing.exists())

    def test_expired_mismatched_tls_empty_db_and_disk_space_rejected(self):
        settings = load(self.path)
        cert, key = certificate(self.root / 'expired', expired=True)
        with self.assertRaisesRegex(ValueError, '過期'):
            check({**settings, 'cert': cert, 'key': key})
        with self.assertRaises(ssl.SSLError):
            check({**settings, 'key': key})
        with patch('guarddesk.server_config.shutil.disk_usage', return_value=type('Space', (), {'free': 1})()):
            with self.assertRaisesRegex(ValueError, '空間不足'):
                check(settings)
        empty = self.root / 'empty.sqlite3'
        empty.touch()
        with self.assertRaisesRegex(ValueError, '不是 GuardDesk'):
            check({**settings, 'db': empty})

    def test_encrypted_private_key_fails_without_prompting_for_a_password(self):
        private = serialization.load_pem_private_key(self.key.read_bytes(), password=None)
        encrypted = self.root / 'encrypted.key'
        encrypted.write_bytes(private.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b'test-only-password')))
        with self.assertRaisesRegex(ValueError, '互動密碼'):
            check({**load(self.path), 'key': encrypted})

    def test_silent_tls_client_cannot_block_other_endpoints(self):
        server = serve(self.db, host='0.0.0.0', port=0, cert=self.cert, key=self.key)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        silent = socket.create_connection(('127.0.0.1', server.server_port), timeout=2)
        try:
            client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(self.cert))))
            with client.open(f'https://127.0.0.1:{server.server_port}/api/health', timeout=2) as response:
                self.assertEqual(json.load(response)['status'], 'ok')
        finally:
            silent.close()
            server.shutdown(); server.server_close(); thread.join(5)

    def test_connection_limit_releases_capacity_after_disconnection(self):
        with patch.object(Server, 'max_request_threads', 2):
            server = serve(self.db, host='0.0.0.0', port=0, cert=self.cert, key=self.key)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        sockets = []
        try:
            for _ in range(2):
                sockets.append(socket.create_connection(('127.0.0.1', server.server_port), timeout=2))
            # Two silent TLS clients occupy the bounded slots; the third is closed.
            third = socket.create_connection(('127.0.0.1', server.server_port), timeout=2)
            sockets.append(third)
            self.assertEqual(third.recv(1), b'')
            sockets[0].close()
            client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(self.cert))))
            for attempt in range(20):
                try:
                    with client.open(f'https://127.0.0.1:{server.server_port}/api/health', timeout=2) as response:
                        self.assertEqual(json.load(response)['status'], 'ok')
                    break
                except (urllib.error.URLError, OSError):
                    time.sleep(.05)
            else:
                self.fail('Connection capacity was not released')
        finally:
            for connection in sockets: connection.close()
            server.shutdown(); server.server_close(); thread.join(5)


class MigrationHTTPSFlowTest(unittest.TestCase):
    setUp = test_system.SystemTest.setUp
    tearDown = test_system.SystemTest.tearDown
    api = test_system.SystemTest.api
    make_agent = test_system.SystemTest.make_agent
    group = test_management.ManagementTest.group
    policy = test_management.ManagementTest.policy
    assign = test_management.ManagementTest.assign
    move = test_management.ManagementTest.move

    def login(self, username):
        self.csrf = self.api('/api/login', {'username': username, 'password': self.password})['csrf']

    def test_cutover_preserves_identity_groups_policies_audit_and_remote_authorization(self):
        agent, did, _ = self.make_agent()
        group = self.group('Pilot team')
        self.move(did, group['id'])
        policy = self.policy('Read-only USB', {'usb_mode': 'read_only'})
        self.assign(policy, 'group', group['id'])
        agent.heartbeat(); agent.heartbeat()
        self.store.add_user('mis2', self.password, 'admin')
        self.api('/api/remote/account', {'username': 'helper', 'password': self.password})
        self.api('/api/remote/grant', {'username': 'helper', 'device_id': did,
            'can_control': True, 'enabled': True, 'days': 1})
        self.api('/api/remote/grant', {'username': 'mis2', 'device_id': did,
            'can_control': True, 'enabled': True, 'days': 1})
        agent.call('/api/agent/remote/poll', {'account': 'EXAMPLE\\tester', 'ready': True})
        self.login('helper')
        old_session = self.api('/api/remote/request', {'device_id': did, 'mode': 'view', 'reason': 'Before cutover'})
        # Remains offline durably during cutover; use a new event ID for retry/dedup checks.
        agent.queue('file.moved', {'source_path': 'C:\\Pilot\\before.txt', 'destination_path': 'C:\\Pilot\\after.txt'})
        self.server.shutdown(); self.server.server_close(); self.thread.join(5)
        with self.assertRaises(ConnectionError): agent.flush()
        target = self.root / 'separate data' / 'control.sqlite3'
        target.parent.mkdir()
        snapshot(self.db, target, migration=True)
        self.assertTrue(check({**dict(zip(('cert', 'key'), certificate(self.root / 'server' / 'tls'))),
                               'host': '0.0.0.0', 'db': target})['passed'])
        cert, key = self.root / 'server/tls/server.crt', self.root / 'server/tls/server.key'
        self.server = serve(target, host='0.0.0.0', port=0, cert=cert, key=key)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.url = f'https://127.0.0.1:{self.server.server_port}'
        self.store = self.server.store
        context = ssl.create_default_context(cafile=str(cert))
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.cookie), urllib.request.HTTPSHandler(context=context))
        with self.assertRaises(urllib.error.HTTPError): self.api('/api/state')  # Old session invalidated.
        self.login('mis2')
        self.assertTrue(all(c.secure and c.has_nonstandard_attr('HttpOnly') for c in self.cookie if c.name == 'gd_session'))
        row = self.api('/api/state')['devices'][0]
        self.assertEqual(row['id'], did); self.assertEqual(row['group_path'], ['Pilot team'])
        self.assertEqual(self.api('/api/device-detail?device_id=' + did)['effective_policy']['body']['usb_mode'], 'read_only')
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT status,ended_reason FROM remote_sessions WHERE id=?', (old_session['id'],)).fetchone()[:], ('closed', 'server_migration'))
        settings = json.loads(agent.config_path.read_text())
        settings.update(server=self.url, ca=str(cert))
        agent.config_path.write_text(json.dumps(settings))
        agent = Agent(agent.config_path)
        agent.heartbeat(refresh_inventory=False); agent.heartbeat(refresh_inventory=False)
        self.assertTrue(self.api('/api/state')['devices'][0]['policy_received'])
        agent.flush(); agent.flush()
        rows = self.api('/api/events?category=files&kind=file.moved')['items']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['details']['destination_path'], 'C:\\Pilot\\after.txt')
        self.assertTrue(self.api('/api/integrity')['valid'])
        agent.call('/api/agent/remote/poll', {'account': 'EXAMPLE\\tester', 'ready': True})
        session = self.api('/api/remote/request', {'device_id': did, 'mode': 'control', 'reason': 'After cutover'})
        with self.assertRaises(ConnectionError):
            agent.call('/api/agent/remote/update', {'session_id': session['id'], 'action': 'frame', 'frame': frame()})
        agent.call('/api/agent/remote/update', {'session_id': session['id'], 'action': 'approve', 'account': 'EXAMPLE\\tester'})
        agent.call('/api/agent/remote/update', {'session_id': session['id'], 'action': 'frame', 'frame': frame()})
        self.assertIn('frame', self.api('/api/remote/session?id=' + session['id']))
        self.api('/api/remote/input', {'session_id': session['id'], 'actions': [{'type': 'click', 'x': .5, 'y': .5}]})
        result = agent.call('/api/agent/remote/update', {'session_id': session['id'], 'action': 'frame', 'frame': frame()})
        self.assertEqual(len(result['commands']), 1)
        self.api('/api/remote/stop', {'session_id': session['id']})
        self.assertNotIn(session['id'], self.server.remote_memory)
        self.login('reader')
        self.assertEqual(self.api('/api/state')['devices'][0]['id'], did)
        with self.assertRaises(urllib.error.HTTPError): self.api('/api/enrollments', {})
        self.login('helper')
        with self.assertRaises(urllib.error.HTTPError): self.api('/api/state')
        with self.assertRaises(urllib.error.HTTPError): self.api('/api/remote/grant', {})
        self.login('admin')
        with self.assertRaises(urllib.error.HTTPError):
            self.api('/api/remote/request', {'device_id': did, 'mode': 'view', 'reason': 'No explicit grant'})
        with self.assertRaises(ConnectionError): request(self.url, '/api/agent/heartbeat', {})
        with self.assertRaises(ConnectionError):
            request(self.url.replace('127.0.0.1', '127.0.0.2'), '/api/agent/heartbeat', {}, ca=str(cert))


if __name__ == '__main__':
    unittest.main()
