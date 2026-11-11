import hashlib,io,json,shutil,tempfile,unittest,zipfile
from pathlib import Path
from guarddesk import browser_auto_publication as auto,browser_publication as pub
from guarddesk.deployment import prepare_connection
from guarddesk.server_setup import secure_directory
from guarddesk.store import Store


class AutomaticPublicationTest(unittest.TestCase):
    def setUp(self):
        runtime=Path(__file__).resolve().parents[1]/'runtime'
        self.tmp=tempfile.TemporaryDirectory(dir=runtime);self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'private-server';secure_directory(self.root)
        self.store=Store(self.root/'control.sqlite3')
        self.connection=self.root/'Endpoint-Connection.zip'
        self.make_connection()

    def make_connection(self,server='https://company.test:8787'):
        ca=b'owned public fixture CA'
        body={'version':1,'server':server,'ca':'GuardDesk-CA.pem','ca_sha256':hashlib.sha256(ca).hexdigest()}
        with zipfile.ZipFile(self.connection,'w') as z:z.writestr('endpoint-connection.json',json.dumps(body));z.writestr('GuardDesk-CA.pem',ca)

    def test_automatic_new_publication_and_connection_bundle_need_no_extra_admin_form(self):
        prepare_connection(self.store,self.connection,'setup')
        first=pub.selected(self.root);key=self.root/'BrowserSigner/extension-signing.pem';original=key.read_bytes()
        self.assertEqual(first['settings']['chrome_update_url'],'https://company.test:8787/browser-extension/updates.xml')
        with zipfile.ZipFile(self.connection) as z:
            descriptor=json.loads(z.read('endpoint-connection.json'))
            self.assertEqual(descriptor['version'],3)
            self.assertEqual(descriptor['browser_deployment'],first['settings'])
            self.assertIn('browser_deployment_authorization',descriptor)
            self.assertFalse(any('PRIVATE KEY' in z.read(n).decode('utf-8',errors='ignore') for n in z.namelist()))
        secret=(self.root/'deployment/credentials.json').read_bytes()
        prepare_connection(self.store,self.connection,'download')
        self.assertEqual(pub.selected(self.root),first);self.assertEqual(key.read_bytes(),original)
        self.assertEqual((self.root/'deployment/credentials.json').read_bytes(),secret)
        with self.store.connect() as db:
            receipt=db.execute('SELECT settings,managed FROM browser_publication_identity').fetchone()
            self.assertEqual(json.loads(receipt['settings']),first['settings']);self.assertEqual(receipt['managed'],1)

    def test_lost_managed_key_or_selector_never_rekeys(self):
        auto.ensure(self.store,'setup');key=self.root/'BrowserSigner/extension-signing.pem'
        original=key.read_bytes();key.unlink()
        with self.assertRaisesRegex(ValueError,'金鑰遺失'):auto.ensure(self.store,'restart')
        self.assertFalse(key.exists());key.write_bytes(original)
        selector=self.root/'BrowserPublication/current.json';selector.unlink()
        with self.assertRaisesRegex(ValueError,'身分或來源'):auto.ensure(self.store,'restart')
        self.assertEqual(key.read_bytes(),original);self.assertFalse(selector.exists())

    def test_receipt_survives_file_loss_and_prevents_identity_reinitialization(self):
        auto.ensure(self.store,'setup')
        self.assertTrue((self.root/'BrowserPublication').resolve().is_relative_to(self.root.resolve()))
        self.assertTrue((self.root/'BrowserSigner').resolve().is_relative_to(self.root.resolve()))
        shutil.rmtree(self.root/'BrowserPublication');shutil.rmtree(self.root/'BrowserSigner')
        with self.assertRaisesRegex(ValueError,'身分或來源'):auto.ensure(self.store,'restart')
        self.assertFalse((self.root/'BrowserSigner').exists())

    def test_corrupt_selected_file_preserved_and_existing_connection_not_replaced(self):
        prepare_connection(self.store,self.connection,'setup');before=self.connection.read_bytes()
        state=pub.selected(self.root);path=self.root/'BrowserPublication'/state['generation']/'updates.xml'
        path.write_bytes(b'corrupt fixture')
        with self.assertRaises(ValueError):prepare_connection(self.store,self.connection,'download')
        self.assertEqual(self.connection.read_bytes(),before);self.assertEqual(path.read_bytes(),b'corrupt fixture')

    def test_external_identity_and_custom_source_are_preserved(self):
        other=self.root/'external-source';secure_directory(other)
        state=pub.create_managed(other,'https://approved.test/browser-extension/')
        selected=pub.selected(other);stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:
            for name in selected['hashes']:z.writestr(name,pub.public_file(other,name)[0])
            z.writestr('browser-deployment.json',json.dumps(selected['settings']))
        pub.install(self.root,stream.getvalue());before=pub.selected(self.root)
        result=auto.ensure(self.store,'upgrade')
        self.assertEqual(pub.selected(self.root),before);self.assertEqual(result['extension_id'],state['extension_id'])
        self.assertFalse((self.root/'BrowserSigner').exists())
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT managed FROM browser_publication_identity').fetchone()[0],0)

    def test_invalid_or_missing_connection_has_no_new_signer_or_publication(self):
        self.make_connection('http://untrusted.test')
        with self.assertRaises(ValueError):auto.ensure(self.store,'download')
        self.assertFalse((self.root/'BrowserSigner').exists())
        self.connection.unlink();self.assertEqual(auto.ensure(self.store,'startup'),{'status':'connection_required'})
        self.assertFalse((self.root/'BrowserSigner').exists())


if __name__=='__main__':unittest.main()
