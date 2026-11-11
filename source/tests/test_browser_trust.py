"""Owned certificate fixtures; unit cases never mutate the Windows store."""
import copy,json,tempfile,unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,ed25519
from cryptography.x509.oid import NameOID
from guarddesk import browser_trust as trust
from guarddesk.browser_host import extension_id
from guarddesk.update_packages import public_key


def fixture_ca():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'GuardDesk disposable trust test')])
    now=datetime.now(timezone.utc)
    return x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


class Roots:
    def __init__(self,present=False):self.present=present;self.adds=0;self.removes=0
    def contains(self,der):return self.present
    def add(self,der):self.adds+=1;self.present=True;return True
    def remove(self,der):self.removes+=1;self.present=False


class BrowserTrustTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.pem=fixture_ca();self.ca=self.root/'company-ca.pem';self.ca.write_bytes(self.pem)
        self.key=ed25519.Ed25519PrivateKey.generate();self.server='https://company.test:8787'
        self.settings={'extension_id':extension_id(),'chrome_update_url':self.server+'/browser-extension/updates.xml','edge_update_url':self.server+'/browser-extension/updates.xml'}
        self.packet=trust.authorize(self.server,self.pem,self.key)
        self.config={'server':self.server,'ca':str(self.ca),'update_key':public_key(self.key),'browser_deployment':self.settings,'browser_trust':self.packet,'device_id':'a'*24,'token':'owned-test'}
        self.path=self.root/'config.json';self.path.write_text(json.dumps(self.config))

    def test_rejects_wrong_pin_ca_origin_signature_and_extra_fields_without_mutation(self):
        for mutation in ('pin','ca','server','settings','signature','extra'):
            config=copy.deepcopy(self.config)
            if mutation=='pin':config['update_key']=public_key(ed25519.Ed25519PrivateKey.generate())
            if mutation=='ca':self.ca.write_bytes(fixture_ca())
            if mutation=='server':config['server']='https://foreign.test'
            if mutation=='settings':config['browser_deployment']['edge_update_url']='https://foreign.test/updates.xml'
            if mutation=='signature':config['browser_trust']['signature']='AAAA'
            if mutation=='extra':config['browser_trust']['extra']=True
            roots=Roots()
            with self.subTest(mutation=mutation),self.assertRaises((ValueError,TypeError)):trust.execute(config,'apply',self.root,roots)
            self.assertEqual(roots.adds,0);self.assertFalse((self.root/trust.LEDGER).exists());self.ca.write_bytes(self.pem)

    def test_add_retry_restore_exact_owned_certificate(self):
        roots=Roots();trust.execute(self.config,'apply',self.root,roots)
        before=(self.root/trust.LEDGER).read_bytes()
        trust.execute(self.config,'apply',self.root,roots)
        self.assertEqual((self.root/trust.LEDGER).read_bytes(),before);self.assertEqual(roots.adds,1)
        trust.execute(self.config,'restore',self.root,roots)
        self.assertEqual(roots.removes,1);self.assertFalse(roots.present);self.assertFalse((self.root/trust.LEDGER).exists())
        self.assertEqual(trust.execute(self.config,'restore',self.root,roots)['status'],'not_managed')

    def test_preexisting_certificate_never_removed(self):
        roots=Roots(True);trust.execute(self.config,'apply',self.root,roots);trust.execute(self.config,'restore',self.root,roots)
        self.assertTrue(roots.present);self.assertEqual((roots.adds,roots.removes),(0,0))

    def test_crash_between_add_and_commit_preserves_uncertain_ownership(self):
        roots=Roots(True)
        (self.root/trust.LEDGER).write_text(json.dumps({'format':1,'sha256':self.packet['data']['ca_sha256'],'state':'pending'}))
        self.assertEqual(trust.execute(self.config,'restore',self.root,roots)['status'],'preserved_after_interruption')
        trust.execute(self.config,'apply',self.root,roots);trust.execute(self.config,'restore',self.root,roots)
        self.assertTrue(roots.present);self.assertEqual(roots.removes,0)

    def test_conflicting_journal_leaves_store_unchanged(self):
        roots=Roots(True)
        (self.root/trust.LEDGER).write_text(json.dumps({'format':1,'sha256':'0'*64,'state':'added'}))
        with self.assertRaises(ValueError):trust.execute(self.config,'restore',self.root,roots)
        self.assertEqual(roots.removes,0)

    def test_native_sync_keeps_original_identity_and_bounds_store_checks(self):
        original=copy.deepcopy(self.config);original.pop('browser_trust');self.path.write_text(json.dumps(original))
        agent=SimpleNamespace(config=copy.deepcopy(original),config_path=self.path);roots=Roots()
        def protected(path):return json.loads(path.read_text()),self.root
        with patch.object(trust,'protected',side_effect=protected),patch.object(trust,'WindowsRoots',return_value=roots) as factory:
            result=trust.sync(agent,self.packet);self.assertEqual(result['status'],'trusted')
            self.assertEqual(trust.sync(agent,self.packet),result);factory.assert_called_once()
        self.assertEqual({k:agent.config[k] for k in original},original)

    def test_no_authorization_and_unprivileged_runtime_do_not_open_store(self):
        agent=SimpleNamespace(config=self.config,config_path=self.path)
        with patch.object(trust,'WindowsRoots') as roots:
            self.assertEqual(trust.sync(agent,None)['status'],'trust_authorization_unavailable')
            with patch('guarddesk.windows_privilege.is_admin',return_value=False):self.assertEqual(trust.sync(agent,self.packet)['status'],'trust_failed')
            roots.assert_not_called()

    def test_bad_connection_archive_does_not_block_ordinary_policy_projection(self):
        (self.root/'Endpoint-Connection.zip').write_bytes(b'broken owned fixture')
        with patch('guarddesk.browser_publication.selected',return_value={'settings':self.settings}):
            self.assertIsNone(trust.projection(self.root))

    def test_extension_authorization_cannot_be_replayed_as_tls_authority(self):
        from guarddesk.browser_deployment import authorize
        packet={**self.packet,'signature':authorize(self.settings,self.key)['signature']}
        with self.assertRaisesRegex(ValueError,'organization pin'):
            trust.verify(packet,self.config['update_key'],self.server,self.pem,self.settings)


if __name__=='__main__':unittest.main()
