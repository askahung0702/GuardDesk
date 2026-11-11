"""Elevated, short-lived OWN CA test. Never installs the company CA.

User authorized this UAC fixture. This script changes only its unique generated
certificate, removes it in finally, and compares the entire default root store.
No private key or certificate bytes are retained in public evidence.
"""
import ctypes,hashlib,json,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from guarddesk import browser_trust as trust
from guarddesk.browser_host import extension_id
from guarddesk.update_packages import public_key
from guarddesk.server_setup import secure_directory
from guarddesk.windows_controls import is_admin
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_browser_trust import fixture_ca


def snapshot(store):
    c=ctypes;api=store.api
    api.CertEnumCertificatesInStore.argtypes=[c.c_void_p,c.c_void_p];api.CertEnumCertificatesInStore.restype=c.c_void_p
    handle=store._open(True);ctx=None;result=set()
    try:
        for _ in range(10000):
            ctx=api.CertEnumCertificatesInStore(handle,ctx)
            if not ctx:
                if c.get_last_error()&0xffffffff!=0x80092004:raise c.WinError(c.get_last_error())
                return result
            data=c.cast(ctx,c.POINTER(store.Context)).contents
            result.add(hashlib.sha256(c.string_at(data.data,data.size)).hexdigest())
        raise ValueError('Root store exceeds bounded snapshot')
    finally:
        if ctx:api.CertFreeCertificateContext(ctx)
        api.CertCloseStore(handle,0)


def main():
    if not is_admin():raise PermissionError('Explicit fixture UAC approval required')
    from PyInstaller.archive.readers import CArchiveReader
    exe=ROOT/'dist/GuardDesk/GuardDesk.exe'
    code=CArchiveReader(str(exe)).open_embedded_archive('PYZ.pyz').extract('guarddesk.browser_trust')
    assert code==compile((ROOT/'guarddesk/browser_trust.py').read_bytes(),str(ROOT/'guarddesk/browser_trust.py'),'exec')
    exec(code,trust.__dict__)
    store=trust.WindowsRoots();before=snapshot(store);pem=fixture_ca();der=trust.certificate(pem);digest=hashlib.sha256(der).hexdigest()
    assert digest not in before
    started=time.monotonic();report={'passed':False,'company_ca_installed':False,'frozen_module_used':True,'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'trust_source_sha256':hashlib.sha256((ROOT/'guarddesk/browser_trust.py').read_bytes()).hexdigest()}
    with tempfile.TemporaryDirectory(prefix='browser-trust-owned-',dir=ROOT/'runtime') as temporary:
        root=Path(temporary);secure_directory(root,allow_empty=True)
        ca=root/'company-ca.pem';ca.write_bytes(pem);key=Ed25519PrivateKey.generate();server='https://owned-fixture.invalid'
        settings={'extension_id':extension_id(),'chrome_update_url':server+'/updates.xml','edge_update_url':server+'/updates.xml'}
        config={'ca':str(ca),'server':server,'browser_deployment':settings,'update_key':public_key(key),'browser_trust':trust.authorize(server,pem,key)}
        try:
            assert not store.contains(der)
            trust.execute(config,'apply',root,store);assert store.contains(der)
            assert snapshot(store)==before|{digest}
            journal=(root/trust.LEDGER).read_bytes()
            trust.execute(config,'apply',root,store);assert (root/trust.LEDGER).read_bytes()==journal
            trust.execute(config,'restore',root,store);assert not store.contains(der)
            # A root that predates our installer remains trusted on uninstall.
            assert store.add(der)
            trust.execute(config,'apply',root,store);trust.execute(config,'restore',root,store)
            assert store.contains(der)
            store.remove(der)
            assert snapshot(store)==before
            report.update(passed=True,root_store_restored=True,fixture_ca_sha256=digest,preexisting_preserved=True,only_fixture_certificate_changed=True,elapsed_seconds=round(time.monotonic()-started,3),checks=['Real LocalMachine Root add and exact DER readback','Repeated apply makes no journal/store mutation','Owned restore removes only exact fixture certificate','Preexisting root survives installer restore','Before/after full default store hash sets equal'])
        finally:
            if store.contains(der):store.remove(der)
            report['cleanup_verified']=snapshot(store)==before
            (ROOT/'evidence/browser-trust-windows-0.4.59.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        import traceback
        (ROOT/'runtime/browser-trust-fixture-error.txt').write_text(traceback.format_exc(),encoding='utf-8')
        raise
