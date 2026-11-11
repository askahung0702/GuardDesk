"""Owned fixture identity only: production CRX private key is not available."""
import base64
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from guarddesk.update_packages import public_key
from guarddesk import browser_host as host,browser_release as release,browser_publication as pub
from guarddesk.browser_deployment import execute,authorize,verify_authorization
from guarddesk.deployment import validate_body
from test_document_audit import RegistryFixture
import test_system


class AutomaticStatusTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api

    def test_missing_original_update_signer_is_failed_not_endless_preparing(self):
        publisher=self.server.bundled_release
        publisher.source=self.root
        with publisher.lock:publisher.state={'status':'failed','code':'signing_unavailable'}
        result=self.api('/api/browser-publication')
        self.assertEqual(result['automatic_preparation'],{'status':'blocked_by_release_preparation','code':'signing_unavailable'})
        self.assertEqual(result['status'],'publication_required')
        self.assertFalse((self.root/'BrowserSigner').exists())
        self.assertEqual(self.api('/api/health')['status'],'ok')


class PublicationTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        ext=self.root/'extension';shutil.copytree(host.EXTENSION,ext)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        manifest=json.loads((ext/'manifest.json').read_text(encoding='utf-8'))
        manifest['key']=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        (ext/'manifest.json').write_text(json.dumps(manifest),encoding='utf-8')
        self.key=self.root/'fixture-only.pem';self.key.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        for module in (host,release):
            context=patch.object(module,'EXTENSION',ext);context.start();self.addCleanup(context.stop)
        self.output=self.root/'release';release.build(self.output,'https://server.test:8787/browser-extension/',self.key)
        self.payload=(self.output/'GuardDesk-Browser-Publication.zip').read_bytes()
        self.data=self.root/'server';self.data.mkdir()
    def test_verified_publication_serves_only_exact_files_and_pins_identity(self):
        state=pub.install(self.data,self.payload)
        self.assertEqual(state['status'],'published_await_browser_acceptance');self.assertEqual(state['browser_trust'],'not_verified')
        xml,mime=pub.public_file(self.data,'updates.xml');self.assertEqual(mime,'application/xml');self.assertIn(b':8787/browser-extension/',xml)
        name='guarddesk-'+state['extension_version']+'.crx'
        crx,mime=pub.public_file(self.data,name);self.assertEqual(mime,'application/x-chrome-extension');self.assertTrue(crx.startswith(b'Cr24'))
        for name in ('../server.sqlite3','current.json','browser-deployment.json',self.key.name):
            with self.assertRaises(FileNotFoundError):pub.public_file(self.data,name)
        self.assertFalse(any(p.suffix=='.pem' for p in pub.directory(self.data).rglob('*')))
    def changed(self,name,transform):
        stream=io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(self.payload)) as source,zipfile.ZipFile(stream,'w') as target:
            for entry in source.namelist():target.writestr(entry,transform(source.read(entry)) if entry==name else source.read(entry))
        return stream.getvalue()
    def test_rejects_corrupt_signature_source_version_xml_and_retain_previous(self):
        pub.install(self.data,self.payload);selector=(pub.directory(self.data)/'current.json').read_bytes()
        version=json.loads((host.EXTENSION/'manifest.json').read_text(encoding='utf-8'))['version']
        for bad in (self.changed('guarddesk-'+version+'.crx',lambda b:b[:-1]+bytes([b[-1]^1])),self.changed('updates.xml',lambda b:b.replace(b'8787',b'4433')),b'not zip'):
            with self.assertRaises((ValueError,zipfile.BadZipFile)):pub.install(self.data,bad)
            self.assertEqual((pub.directory(self.data)/'current.json').read_bytes(),selector)
    def test_duplicate_traversal_oversize_and_mismatched_identity_rejected(self):
        for name in ('../private','updates.xml'):
            data=io.BytesIO(self.payload)
            with zipfile.ZipFile(data,'a') as z:z.writestr(name,b'bad')
            with self.assertRaises(ValueError):pub.inspect_bundle(data.getvalue())
        with self.assertRaises(ValueError):pub.inspect_bundle(b'x'*(pub.MAX_BUNDLE+1))
        manifest=host.EXTENSION/'manifest.json';body=json.loads(manifest.read_text(encoding='utf-8'));body['version']='0.5.1';manifest.write_text(json.dumps(body),encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'source/version'):pub.inspect_bundle(self.payload)
    def test_reimport_same_generation_and_resume_interrupted_copy_without_overwrite(self):
        a=pub.install(self.data,self.payload);self.assertEqual(pub.install(self.data,self.payload)['generation'],a['generation'])
        generation=pub.directory(self.data)/a['generation'];(generation/'updates.xml').unlink()
        pub.install(self.data,self.payload);self.assertTrue((generation/'updates.xml').exists())
        (generation/'updates.xml').write_bytes(b'corrupt')
        with self.assertRaises(ValueError):pub.public_file(self.data,'updates.xml')
        with self.assertRaises(ValueError):pub.install(self.data,self.payload)
    def test_old_connection_valid_new_connection_has_only_validated_public_policy(self):
        original={'version':2,'server':'https://server.test:8787','ca':'GuardDesk-CA.pem','ca_sha256':'x','deployment_code':'a'*43}
        validate_body(original)
        settings=pub.inspect_bundle(self.payload)[0]
        validate_body({**original,'version':3,'browser_deployment':settings,'browser_deployment_authorization':authorize(settings,Ed25519PrivateKey.generate())})
        for bad in ({**settings,'extension_id':'a'*32},{**settings,'chrome_update_url':'http://bad/updates.xml'}):
            with self.assertRaises(ValueError):validate_body({**original,'version':3,'browser_deployment':bad})
    def test_policy_retries_and_recovery_preserve_other_enterprise_extensions(self):
        settings=pub.inspect_bundle(self.payload)[0];registry=RegistryFixture();before=copy.deepcopy(registry.values)
        state=self.root/'policy';state.mkdir()
        execute(settings,'apply',state,registry);execute(settings,'apply',state,registry)
        registry.values['edge'].pop('2');execute(settings,'apply',state,registry)
        self.assertEqual(registry.values['chrome']['1'],before['chrome']['1'])
        registry.values['edge']['2']='external'
        with self.assertRaises(OSError):execute(settings,'apply',state,registry)
        registry.values['edge']['2']=settings['extension_id']+';'+settings['edge_update_url']
        execute(None,'restore',state,registry);self.assertEqual(registry.values,before)

    def test_managed_company_identity_is_explicit_stable_private_and_legacy_compatible(self):
        from guarddesk.server_setup import secure_directory
        root=self.root/'company';secure_directory(root)
        first=pub.create_managed(root,'https://company.test:8787/browser-extension/')
        key=root/'BrowserSigner/extension-signing.pem';before=key.read_bytes()
        self.assertNotEqual(first['extension_id'],host.extension_id())
        self.assertEqual(pub.create_managed(root,'https://company.test:8787/browser-extension/')['generation'],first['generation'])
        self.assertEqual(key.read_bytes(),before)
        anchor=Ed25519PrivateKey.generate();authorization=authorize(first['settings'],anchor)
        config=self.root/'endpoint-config.json';config.write_text(json.dumps({'browser_deployment':first['settings'],'browser_deployment_authorization':authorization,'update_key':public_key(anchor)}),encoding='utf-8')
        self.assertEqual(host.allowed_extension_ids(config),[host.extension_id(),first['extension_id']])
        policy=self.root/'company-policy';policy.mkdir();registry=RegistryFixture();baseline=copy.deepcopy(registry.values)
        execute(first['settings'],'apply',policy,registry);execute(None,'restore',policy,registry);self.assertEqual(registry.values,baseline)
        self.assertFalse(any(b'PRIVATE KEY' in p.read_bytes() for p in pub.directory(root).rglob('*') if p.is_file()))
        with self.assertRaisesRegex(ValueError,'身分或來源'):pub.create_managed(root,'https://changed.test/browser-extension/')
        self.assertEqual(key.read_bytes(),before);self.assertEqual(pub.status(root)['generation'],first['generation'])
        # External identity is never silently replaced by clicking Create.
        pub.install(self.data,self.payload)
        with self.assertRaisesRegex(ValueError,'外部金鑰'):pub.create_managed(self.data,'https://company.test/browser-extension/')

    def test_organization_authorization_rejects_tampering_and_different_signer(self):
        settings=pub.inspect_bundle(self.payload)[0];anchor=Ed25519PrivateKey.generate();authorization=authorize(settings,anchor)
        self.assertEqual(verify_authorization(settings,authorization,public_key(anchor)),settings)
        for changed,proof,key in ((settings,None,public_key(anchor)),({**settings,'edge_update_url':'https://evil.test/updates.xml'},authorization,public_key(anchor)),(settings,authorization,public_key(Ed25519PrivateKey.generate()))):
            with self.assertRaises(ValueError):verify_authorization(changed,proof,key)

    def test_real_tls_public_download_console_import_csrf_roles_and_surface(self):
        import http.cookiejar,ipaddress,ssl,threading,urllib.request,urllib.error
        from cryptography import x509
        from guarddesk.server_setup import certificates
        from guarddesk.server import serve
        from guarddesk.store import Store
        certs=self.root/'tls';certs.mkdir();certificates(certs,x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
        store=Store(self.data/'control.sqlite3');store.add_user('mis','fixture-password');store.add_user('reader','fixture-password','auditor')
        agent=serve(store.path,'127.0.0.1',0,certs/'server.crt',certs/'server.key',surface='agent')
        console=serve(store.path,'127.0.0.1',0,surface='console',shared=agent)
        threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (agent,console)]
        for thread in threads:thread.start()
        try:
            cookies=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(cookies))
            url='http://127.0.0.1:'+str(console.server_port)
            def call(path,body=None,headers=None):
                with client.open(urllib.request.Request(url+path,data=body,headers=headers or {}),timeout=10) as r:return json.loads(r.read())
            with self.assertRaises(urllib.error.HTTPError) as error:call('/api/browser-publication')
            self.assertEqual(error.exception.code,401)
            login=call('/api/login',json.dumps({'username':'mis','password':'fixture-password'}).encode(),{'Content-Type':'application/json'})
            headers={'X-CSRF-Token':login['csrf'],'X-GuardDesk-Authorize':'browser-publication','Content-Type':'application/zip'}
            with self.assertRaises(urllib.error.HTTPError) as error:call('/api/browser-publication',self.payload,{**headers,'X-CSRF-Token':'invalid'})
            self.assertEqual(error.exception.code,403)
            self.assertEqual(call('/api/browser-publication',self.payload,headers)['status'],'published_await_browser_acceptance')
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=certs/'ca.pem')))
            base='https://127.0.0.1:'+str(agent.server_port)
            # Existing endpoints receive a signed deployment without enrollment
            # or rerunning Setup; both user heartbeat and native policy agree.
            from guarddesk.store import digest
            from guarddesk.update_packages import signer
            from guarddesk.browser_dispatch import adopt
            from types import SimpleNamespace
            anchor=signer(self.data)
            with store.connect() as db:
                db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',('d'*24,digest('fixture-agent-token'),'fixture-endpoint','test',0))
            def agent_call(path,body):
                req=urllib.request.Request(base+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer fixture-agent-token','X-Device-ID':'d'*24})
                with opener.open(req,timeout=10) as response:return json.loads(response.read())
            heartbeat=agent_call('/api/agent/heartbeat',{'inventory':{},'policy_version':0})
            native=agent_call('/api/agent/extended-policy',{})
            self.assertEqual(heartbeat['browser_dispatch'],native['browser_dispatch'])
            projection=heartbeat['browser_dispatch'];self.assertEqual(projection['status'],'published')
            verify_authorization(projection['settings'],projection['authorization'],public_key(anchor))
            endpoint=self.root/'existing-config.json';old={'device_id':'d'*24,'token':'fixture-agent-token','update_key':public_key(anchor)}
            endpoint.write_text(json.dumps(old),encoding='utf-8')
            current=SimpleNamespace(config=old,config_path=endpoint)
            adopt(current,projection);self.assertEqual(current.config['device_id'],old['device_id'])
            with opener.open(base+'/browser-extension/updates.xml',timeout=5) as response:
                self.assertEqual(response.headers['Content-Type'],'application/xml');self.assertIn(host.extension_id().encode(),response.read())
            for path,code in (('/api/browser-publication',403),('/browser-extension/../server.key',404),('/browser-extension/current.json',404)):
                with self.assertRaises(urllib.error.HTTPError) as error:opener.open(base+path,timeout=5)
                self.assertEqual(error.exception.code,code)
            with self.assertRaises(urllib.error.HTTPError) as error:client.open(url+'/browser-extension/updates.xml',timeout=5)
            self.assertEqual(error.exception.code,403)
            call('/api/login',json.dumps({'username':'reader','password':'fixture-password'}).encode(),{'Content-Type':'application/json'})
            with self.assertRaises(urllib.error.HTTPError) as error:call('/api/browser-publication')
            self.assertEqual(error.exception.code,403)
        finally:
            for s in (console,agent):s.shutdown();s.server_close()
            for thread in threads:thread.join(5)


if __name__=='__main__':unittest.main()
