"""Scoped workstation HTTPS simulation, synthetic frames, no desktop input."""
import datetime,hashlib,http.cookiejar,io,ipaddress,json,ssl,threading,unittest,urllib.error,urllib.request,zipfile
from pathlib import Path
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from guarddesk.server_setup import certificates
from guarddesk.server import serve
from guarddesk.agent import Agent,enroll
from guarddesk.remote_client import RemoteClient,RemoteClientError
from guarddesk.mis_support import server_url,connection,package,write_launcher
from test_native_remote import frame
import test_system

class MISSupportTest(unittest.TestCase):
    api=test_system.SystemTest.api
    def setUp(self):
        test_system.SystemTest.setUp(self)
        tls=self.root/'tls';tls.mkdir();certificates(tls,x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
        self.ca=tls/'ca.pem';self.tls=serve(self.db,'127.0.0.1',0,tls/'server.crt',tls/'server.key',surface='agent',shared=self.server)
        self.tls_thread=threading.Thread(target=self.tls.serve_forever,daemon=True);self.tls_thread.start()
        self.endpoint='https://127.0.0.1:'+str(self.tls.server_port)
        self.clients=[]
        self.api('/api/remote/account',{'username':'helper','password':self.password})
    def tearDown(self):
        for c in self.clients:c.logout()
        self.tls.shutdown();self.tls.server_close();self.tls_thread.join(5)
        test_system.SystemTest.tearDown(self)
    def workstation_client(self,name='helper',ca=None):
        c=RemoteClient(self.endpoint,workstation=True,ca=str(ca or self.ca));c.login(name,self.password);self.clients.append(c);return c
    def endpoint_agent(self):
        code=self.api('/api/enrollments',{})['token'];config=self.root/'agent/config.json'
        did=enroll(config,self.endpoint,code,self.watch,ca=str(self.ca));a=Agent(config)
        a.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})
        return a,did
    def grant(self,did,enabled=True):
        return self.api('/api/remote/grant',{'username':'helper','device_id':did,'enabled':enabled,'can_control':True,'days':1})
    def direct(self,base,path,*,cookie=None,csrf=None,body=None):
        headers={'Content-Type':'application/json'}
        if cookie:headers['Cookie']=cookie
        if csrf:headers['X-CSRF-Token']=csrf
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(self.ca))))
        return opener.open(urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers=headers),timeout=5)

    def test_full_https_consent_frame_input_stop_and_revocation(self):
        a,did=self.endpoint_agent();c=self.workstation_client();self.assertEqual(c.catalog()['devices'],[])
        self.grant(did);s=c.request(did,'control','synthetic workstation assistance')
        with self.assertRaises(ConnectionError):a.call('/api/agent/remote/update',{'session_id':s['id'],'action':'frame','frame':frame()})
        a.call('/api/agent/remote/update',{'session_id':s['id'],'action':'approve','account':r'TEST\employee'})
        a.call('/api/agent/remote/update',{'session_id':s['id'],'action':'frame','frame':frame()})
        self.assertIn('jpeg',c.call('/api/remote/session?id='+s['id'])['frame'])
        c.call('/api/remote/input',{'session_id':s['id'],'actions':[{'type':'release_all'}]})
        self.assertEqual(a.call('/api/agent/remote/update',{'session_id':s['id'],'action':'commands'})['commands'][0]['type'],'release_all')
        self.grant(did,False);self.assertEqual(c.call('/api/remote/session?id='+s['id'])['status'],'closed')
        self.assertNotIn(s['id'],self.server.remote_memory)
        self.grant(did);a.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})
        s=c.request(did,'view','logout closes own session');c.logout()
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT status FROM remote_sessions WHERE id=?',(s['id'],)).fetchone()[0],'closed')

    def test_blank_or_missing_reason_still_requires_grant_and_consent(self):
        a,did=self.endpoint_agent();c=self.workstation_client()
        with self.assertRaises(RemoteClientError):c.request(did,'view','')
        self.grant(did)
        for body in ({'reason':''},{}):
            a.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})
            session=c.call('/api/remote/request',{'device_id':did,'mode':'view','viewer':'desktop',**body})
            self.assertEqual(session['reason'],'');self.assertEqual(session['status'],'requested')
            self.assertEqual(a.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':3})['session']['id'],session['id'])
            with self.assertRaises(ConnectionError):a.call('/api/agent/remote/update',{'session_id':session['id'],'action':'frame','frame':frame()})
            c.call('/api/remote/stop',{'session_id':session['id']})

    def test_namespace_isolation_csrf_roles_and_no_management_surface(self):
        c=self.workstation_client('admin');catalog=c.catalog();self.assertEqual(catalog['users'],[])
        cookie=next(iter(c.cookies));self.assertEqual(cookie.name,'gd_mis');self.assertTrue(cookie.secure);self.assertEqual(cookie.path,'/api/support')
        for base,path,raw in [(self.url,'/api/state','gd_session='+cookie.value),(self.endpoint,'/api/state','gd_mis='+cookie.value),
                              (self.endpoint,'/api/support/catalog',next(iter(self.cookie)).name+'='+next(iter(self.cookie)).value),
                              (self.endpoint,'/api/support/grant','gd_mis='+cookie.value)]:
            with self.assertRaises(urllib.error.HTTPError) as e:self.direct(base,path,cookie=raw)
            self.assertIn(e.exception.code,(401,403,404));e.exception.close()
        with self.assertRaises(urllib.error.HTTPError) as e:self.direct(self.endpoint,'/api/support/stop',cookie='gd_mis='+cookie.value,body={'session_id':'a'*32})
        self.assertEqual(e.exception.code,403);e.exception.close()
        with self.assertRaises(urllib.error.HTTPError) as e:self.direct(self.url,'/api/support/login',body={'username':'helper','password':self.password})
        self.assertEqual(e.exception.code,403);e.exception.close()
        with self.assertRaises(RemoteClientError):self.workstation_client('reader')
        with self.store.connect() as db:db.execute("UPDATE users SET role='auditor' WHERE username='admin'")
        with self.assertRaises(RemoteClientError):c.catalog()

    def test_tls_untrusted_wrong_hostname_and_session_binding(self):
        with self.assertRaises(RemoteClientError):RemoteClient(self.endpoint,workstation=True).login('helper',self.password)
        other=self.endpoint.replace('127.0.0.1','localhost')
        with self.assertRaises(RemoteClientError):RemoteClient(other,workstation=True,ca=str(self.ca)).login('helper',self.password)
        a,did=self.endpoint_agent();self.grant(did);one=self.workstation_client();two=self.workstation_client();s=one.request(did,'view','binding')
        with self.assertRaises(RemoteClientError):two.call('/api/remote/session?id='+s['id'])
        one.call('/api/remote/stop',{'session_id':s['id']});self.assertNotIn(s['id'],self.server.remote_memory)

    def test_download_role_csrf_and_package_busy(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/mis-support-package',{},csrf=False)
        self.assertEqual(e.exception.code,403);e.exception.close()
        self.server.package_lock.acquire()
        try:
            with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/mis-support-package',{})
            self.assertEqual(e.exception.code,429);e.exception.close()
        finally:self.server.package_lock.release()
        self.csrf=self.api('/api/login',{'username':'helper','password':self.password})['csrf']
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/mis-support-package',{})
        self.assertEqual(e.exception.code,403);e.exception.close()

    def test_expired_tls_and_redirect_are_rejected(self):
        tls=self.root/'tls';leaf=x509.load_pem_x509_certificate((tls/'server.crt').read_bytes())
        issuer=x509.load_pem_x509_certificate(self.ca.read_bytes());key=serialization.load_pem_private_key((tls/'ca.key').read_bytes(),password=None)
        now=datetime.datetime.now(datetime.timezone.utc)
        expired=x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(issuer.subject).public_key(leaf.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=2)).not_valid_after(now-datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).sign(key,hashes.SHA256())
        expired_path=tls/'expired.crt';expired_path.write_bytes(expired.public_bytes(serialization.Encoding.PEM)+self.ca.read_bytes())
        hits=[]
        class Redirect(BaseHTTPRequestHandler):
            def do_POST(inner):
                hits.append(inner.path);inner.send_response(302);inner.send_header('Location','https://127.0.0.1:'+str(inner.server.server_port)+'/unexpected');inner.end_headers()
            def log_message(self,*args):pass
        for cert in (expired_path,tls/'server.crt'):
            server=ThreadingHTTPServer(('127.0.0.1',0),Redirect);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,tls/'server.key');server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                with self.assertRaises(RemoteClientError):RemoteClient('https://127.0.0.1:'+str(server.server_port),workstation=True,ca=str(self.ca)).login('helper',self.password)
            finally:server.shutdown();server.server_close();thread.join(5)
        self.assertEqual(hits,['/api/support/login'])

class MISConnectionTest(unittest.TestCase):
    def test_https_parser_rejects_plaintext_credentials_paths_and_bad_ports(self):
        self.assertEqual(server_url('https://company.example:8787/'),'https://company.example:8787')
        for value in ('http://company.example','https://user:pw@company.example','https://company.example/path','https://company.example?token=x','https://company.example:bad','https://company.example:0',' https://company.example','https://company.example\\bad'):
            with self.assertRaises(ValueError,msg=value):server_url(value)
    def test_public_package_connection_has_no_enrollment_or_private_material(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);tls=root/'tls';tls.mkdir();certificates(tls,x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
            app=root/'app';internal=app/'_internal';internal.mkdir(parents=True)
            viewer=internal/'GuardDeskRemote.exe';viewer.write_bytes(b'viewer fixture')
            data={'version':1,'server':'https://company.example:8787','deployment_code':'must-not-export'};ca=(tls/'ca.pem').read_bytes()
            with patch('guarddesk.endpoint_package.files',return_value=[viewer]),patch('guarddesk.endpoint_package.public_connection',return_value=(json.dumps(data).encode(),ca)):
                blob=package(root,app)
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                self.assertNotIn(b'must-not-export',z.read('mis-connection.json'))
                z.extractall(root/'bundle')
                m=json.loads(z.read('MANIFEST-SHA256.json'))
                self.assertTrue(all(hashlib.sha256(z.read(n)).hexdigest()==h for n,h in m.items()))
                self.assertNotIn(b'\n',z.read('Start-MIS-Remote.cmd').replace(b'\r\n',b''))
            server,capath=connection(root/'bundle/mis-connection.json');self.assertEqual(server,data['server'])
            c=root/'bundle/mis-connection.json';bad=json.loads(c.read_text());bad['ca']='../tls/ca.pem';c.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):connection(c)
            write_launcher(root,app,root/'agent/config.json');self.assertIn(b'--agent-config',(root/'Start-MIS-Remote.cmd').read_bytes())

if __name__=='__main__':unittest.main()
