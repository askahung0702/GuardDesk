import http.cookiejar
import json
import datetime
import ipaddress
import os
import secrets
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from guarddesk.agent import Agent, enroll, request
from guarddesk.policy import DEFAULT_POLICY, evaluate
from guarddesk.server import serve
from guarddesk.store import Store, canonical
from guarddesk.vault import load_key, encrypt, decrypt


class SystemTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        # Real automatic publication now keeps the org CRX signer beside DB.
        # Use the same private Server data boundary as the real installer.
        from guarddesk.server_setup import secure_directory
        secure_directory(self.root,allow_empty=True)
        self.watch = self.root / 'managed'
        self.watch.mkdir()
        self.db = self.root / 'control.sqlite3'
        self.store = Store(self.db)
        self.password = secrets.token_urlsafe(20)
        self.store.add_user('admin', self.password)
        self.store.add_user('reader', self.password, 'auditor')
        self.server = serve(self.db, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'
        self.cookie = http.cookiejar.CookieJar()
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.cookie))
        self.csrf = self.api('/api/login', {'username':'admin','password':self.password})['csrf']

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        self.temp.cleanup()

    def api(self, path, body=None, csrf=True, client=None):
        headers = {'Content-Type':'application/json'}
        if csrf and hasattr(self, 'csrf'):
            headers['X-CSRF-Token'] = self.csrf
        req = urllib.request.Request(self.url + path, data=None if body is None else canonical(body).encode(), headers=headers)
        # Packaging/rotation may spend up to ten seconds retrying a transient
        # Windows ZIP lock. Give only these operations their bounded IO budget.
        timeout=20 if path in ('/api/endpoint-package','/api/deployment/rotate') else 5
        with (client or self.client).open(req, timeout=timeout) as response:
            data = response.read()
            return json.loads(data) if 'application/json' in response.headers['Content-Type'] else data

    def make_agent(self):
        code = self.api('/api/enrollments', {})['token']
        config = self.root / 'agent' / 'config.json'
        eid = enroll(config, self.url, code, self.watch, name='test-endpoint')
        return Agent(config), eid, code

    def publish(self, **changes):
        current = self.api('/api/state')['policy']
        policy = {**current['body'], **changes}
        return self.api('/api/policy', {'base_version':current['version'],'body':policy})

    def test_enrollment_one_use_policy_ack_and_revoke(self):
        agent, eid, code = self.make_agent()
        with self.assertRaises(ConnectionError):
            request(self.url, '/api/agent/enroll', {'token':code,'name':'other','department':'test'})
        p = self.publish(mode='enforce')
        agent.heartbeat()
        agent.heartbeat()
        row = self.api('/api/state')['devices'][0]
        self.assertEqual(row['policy_version'], p['version'])
        self.assertEqual(row['status'], 'online')
        self.assertIn('disk_total', row['inventory'])
        self.assertNotIn('token', row)
        self.api('/api/devices/revoke', {'device_id':eid})
        with self.assertRaises(ConnectionError):
            agent.heartbeat()

    def test_real_file_events_restart_and_retry_idempotence(self):
        agent, eid, _ = self.make_agent()
        path = self.watch / 'example.txt'
        path.write_text('alpha', encoding='utf-8')
        agent.scan()
        self.assertEqual(Agent(agent.config_path).scan()['files'], 1)
        path.write_text('beta', encoding='utf-8')
        agent.scan()
        path.unlink()
        agent.scan()
        with agent.db() as db:
            payload = json.loads(db.execute('SELECT payload FROM outbox LIMIT 1').fetchone()[0])
        agent.call('/api/agent/events', {'events':[payload]})
        agent.flush()  # Replay after simulated lost response must not duplicate.
        rows = self.api('/api/events?device='+eid)['items']
        self.assertEqual(sum(r['kind']=='file.created' for r in rows), 1)
        self.assertEqual(sum(r['kind']=='file.modified' for r in rows), 0)
        self.assertEqual(sum(r['kind']=='file.deleted' for r in rows), 1)
        self.assertTrue(self.store.verify()['valid'])

    def test_export_blocks_sensitive_allows_clean_and_monitor(self):
        agent, _, _ = self.make_agent()
        sensitive, clean = self.watch / 'secret.txt', self.watch / 'clean.txt'
        sensitive.write_text('CONFIDENTIAL test', encoding='utf-8')
        clean.write_text('ordinary text', encoding='utf-8')
        self.publish(mode='enforce')
        blocked = self.root / 'blocked.txt'
        with self.assertRaises(PermissionError):
            agent.export(sensitive, blocked)
        self.assertFalse(blocked.exists())
        agent.export(clean, self.root / 'allowed.txt')
        self.assertEqual((self.root/'allowed.txt').read_bytes(), clean.read_bytes())
        self.publish(mode='monitor')
        result = agent.export(sensitive, self.root/'observed.txt')
        self.assertTrue(result['allowed'] and result['matched'])
        self.assertEqual(self.api('/api/state')['stats']['blocked'], 1)

    def test_export_unreachable_revoked_outside_and_no_overwrite(self):
        agent, eid, _ = self.make_agent()
        source = self.watch/'test.txt'
        source.write_text('hello')
        outside = self.root/'outside.txt'
        outside.write_text('outside')
        with self.assertRaises(ValueError):
            agent.export(outside, self.root/'bad.txt')
        target = self.root/'existing.txt'
        target.write_text('preserve')
        with self.assertRaises(FileExistsError):
            agent.export(source, target)
        self.assertEqual(target.read_text(), 'preserve')
        agent.config['server']='http://127.0.0.1:1'
        with self.assertRaises(ConnectionError):
            agent.export(source, self.root/'offline.txt')
        self.assertFalse((self.root/'offline.txt').exists())
        agent.config['server']=self.url
        self.api('/api/devices/revoke', {'device_id':eid})
        with self.assertRaises(ConnectionError):
            agent.export(source, self.root/'revoked.txt')

    def test_auth_csrf_readonly_and_optimistic_conflict(self):
        anonymous = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.api('/api/state', client=anonymous)
        self.assertEqual(e.exception.code,401)
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.api('/api/enrollments',{},csrf=False)
        self.assertEqual(e.exception.code,403)
        p=self.api('/api/state')['policy']
        self.publish(mode='enforce')
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.api('/api/policy',{'base_version':p['version'],'body':p['body']})
        self.assertEqual(e.exception.code,409)
        self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        self.assertTrue(self.api('/api/state'))
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.api('/api/enrollments',{})
        self.assertEqual(e.exception.code,403)

    def test_csv_search_and_tamper_detection(self):
        agent, eid, _ = self.make_agent()
        agent.queue('file.created',{'path':'=FORMULA.txt'})
        agent.flush()
        result=self.api('/api/events?q=FORMULA')
        self.assertEqual(result['total'],1)
        csv_data=self.api('/api/events.csv?q=FORMULA').decode('utf-8-sig')
        self.assertIn('FORMULA.txt',csv_data)
        with self.store.connect() as db:
            db.execute("UPDATE events SET details='{}' WHERE kind='file.created'")
        self.assertFalse(self.store.verify()['valid'])

    def test_offline_queue_survives_restart(self):
        agent, _, _ = self.make_agent()
        (self.watch/'queued.txt').write_text('persist')
        agent.scan()
        agent.config['server']='http://127.0.0.1:1'
        with self.assertRaises(ConnectionError):
            agent.flush()
        restarted=Agent(agent.config_path)
        restarted.flush()
        self.assertEqual(self.api('/api/events?q=queued.txt')['total'],1)
        with restarted.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0],0)

    def test_browser_and_network_offline_reconnect_upload(self):
        from guarddesk.browser_host import handle_message
        agent,eid,_=self.make_agent()
        agent.config['server']='http://127.0.0.1:1'
        message={'type':'navigation','event_id':'browser-durable-test','url':'https://example.com/folder?test=1','tab_id':3,'browser':'chrome'}
        handle_message(agent,message)
        agent.queue('file.opened',{'path':r'C:\Documents\offline.txt','user':'COMPANY\\alice','source':'test_fixture'})
        agent.queue('network.upload',{'domain':'example.com','outgoing_bytes':4096,'source':'test_fixture'})
        with self.assertRaises(ConnectionError):agent.flush()
        restarted=Agent(agent.config_path)
        self.assertEqual(restarted.queue_status()['pending'],3)
        restarted.flush()
        handle_message(restarted,message) # Browser retried a committed event after ack loss.
        restarted.flush()
        rows=self.api('/api/events?device='+eid)['items']
        for kind in ('web.navigation','network.upload','file.opened'):
            self.assertEqual(sum(r['kind']==kind for r in rows),1)
        self.assertEqual(restarted.queue_status()['pending'],0)

    def test_clock_skew_does_not_poison_offline_batch(self):
        agent,eid,_=self.make_agent()
        agent.queue('file.opened',{'path':'clock-test.txt'},occurred=time.time()+3600)
        agent.queue('web.navigation',{'url':'https://example.com'})
        agent.flush()
        rows=self.api('/api/events?device='+eid)['items']
        future=next(row for row in rows if row['kind']=='file.opened')
        self.assertEqual(future['details']['clock_warning'],'agent_timestamp_in_future')
        self.assertEqual(agent.queue_status()['pending'],0)

    def test_wrong_host_origin_and_non_finite_json(self):
        for headers in ({'Host':'attacker.example'},{'Origin':'https://attacker.example'}):
            req=urllib.request.Request(self.url+'/api/health',headers=headers)
            with self.assertRaises(urllib.error.HTTPError) as e:
                self.client.open(req)
            self.assertEqual(e.exception.code,403)
        req=urllib.request.Request(self.url+'/api/login',data=b'{"username":"admin","password":NaN}',headers={'Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.client.open(req)
        self.assertEqual(e.exception.code,400)

    def test_tls_agent_trust_validation(self):
        token=self.api('/api/enrollments',{})['token']
        private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        now=datetime.datetime.now(datetime.timezone.utc)
        name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'localhost')])
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
              .not_valid_after(now+datetime.timedelta(days=1))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
              .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(private,hashes.SHA256()))
        cert_path,key_path=self.root/'cert.pem',self.root/'key.pem'
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        tls_server=serve(self.db,port=0,cert=cert_path,key=key_path,shared=self.server)
        tls_thread=threading.Thread(target=tls_server.serve_forever,daemon=True);tls_thread.start()
        url=f'https://127.0.0.1:{tls_server.server_port}'
        payload={'token':token,'name':'tls-device','department':'test'}
        try:
            with self.assertRaises(ConnectionError):
                request(url,'/api/agent/enroll',payload)
            result=request(url,'/api/agent/enroll',payload,ca=str(cert_path))
            self.assertIn('device_id',result)
            with self.assertRaises(ValueError):
                serve(self.db,host='0.0.0.0',port=0)
        finally:
            tls_server.shutdown();tls_server.server_close();tls_thread.join(5)


class CryptoAndPolicyTest(unittest.TestCase):
    def test_encryption_roundtrip_wrong_key_tamper_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            source, sealed, restored=root/'source.pdf',root/'sealed.gdesk',root/'restored.pdf'
            source.write_bytes(b'%PDF-1.7\nTest binary\x00\xff')
            key=load_key(root/'key',create=True)
            encrypt(source,sealed,key)
            self.assertNotIn(source.read_bytes(),sealed.read_bytes())
            decrypt(sealed,restored,key)
            self.assertEqual(restored.read_bytes(),source.read_bytes())
            with self.assertRaises(FileExistsError):
                decrypt(sealed,restored,key)
            with self.assertRaises(InvalidTag):
                decrypt(sealed,root/'wrong.pdf',os.urandom(32))
            self.assertFalse((root/'wrong.pdf').exists())
            modified=bytearray(sealed.read_bytes());modified[-1]^=1;sealed.write_bytes(modified)
            with self.assertRaises(InvalidTag):
                decrypt(sealed,root/'tampered.pdf',key)
            self.assertFalse((root/'tampered.pdf').exists())

    def test_policy_extension_utf16_and_mode(self):
        p={**DEFAULT_POLICY,'mode':'enforce'}
        self.assertFalse(evaluate(p,'secret.KEY',b'test')['allowed'])
        self.assertFalse(evaluate(p,'note.txt','CONFIDENTIAL'.encode('utf-16-le'))['allowed'])
        self.assertTrue(evaluate(DEFAULT_POLICY,'note.txt',b'CONFIDENTIAL')['allowed'])
        self.assertFalse(evaluate({**p,'allow_export':False},'plain.txt',b'hello')['allowed'])


if __name__=='__main__':
    unittest.main()
