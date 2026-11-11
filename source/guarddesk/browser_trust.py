"""Company-authorized browser TLS root, separate from extension policy authority.

Only the existing transport CA is eligible. No certificate/private key is fetched
from policy traffic, and the existing organization update pin cannot be replaced.
Privileged callers must validate their protected installation before execute().
"""
import base64
import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

PURPOSE=b'GuardDesk browser TLS trust v1\0'
LEDGER='browser-trust-owned.json'


def origin(value):
    p=urlsplit(value)
    if p.scheme!='https' or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise ValueError('Browser trust requires the original HTTPS origin')
    return (p.hostname.lower(),p.port or 443)


def certificate(pem,*,current=True):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    if not isinstance(pem,bytes) or len(pem)>65536 or pem.count(b'-----BEGIN CERTIFICATE-----')!=1 or b'PRIVATE KEY' in pem:
        raise ValueError('One public CA certificate required')
    cert=x509.load_pem_x509_certificate(pem)
    try:is_ca=cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound as exc:raise ValueError('CA constraints required') from exc
    if not is_ca:
        raise ValueError('Browser trust certificate must be a CA')
    if cert.subject!=cert.issuer:raise ValueError('Only the original self-signed root is supported')
    try:cert.verify_directly_issued_by(cert)
    except Exception as exc:raise ValueError('Invalid self-signed CA') from exc
    now=datetime.now(timezone.utc)
    if current and not cert.not_valid_before_utc<=now<=cert.not_valid_after_utc:raise ValueError('CA certificate is not currently valid')
    return cert.public_bytes(Encoding.DER)


def authorize(server,pem,private):
    from .serialization import canonical
    origin(server)
    data={'format':1,'server':server,'ca_sha256':hashlib.sha256(certificate(pem)).hexdigest()}
    return {'data':data,'signature':base64.b64encode(private.sign(PURPOSE+canonical(data).encode())).decode()}


def verify(packet,public,server,pem,settings,*,current=True):
    from .serialization import canonical
    from .update_packages import key_id
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from .browser_deployment import validate
    if not isinstance(packet,dict) or set(packet)!={'data','signature'}:raise ValueError('Invalid browser trust authorization')
    data=packet['data']
    if not isinstance(data,dict) or set(data)!={'format','server','ca_sha256'} or type(data['format']) is not int or data['format']!=1 or data['server']!=server:raise ValueError('Browser trust origin differs from pinned transport')
    der=certificate(pem,current=current)
    if data['ca_sha256']!=hashlib.sha256(der).hexdigest():raise ValueError('Browser trust CA differs from pinned transport')
    validate(settings)
    if any(origin(settings[b+'_update_url'])!=origin(server) for b in ('chrome','edge')):raise ValueError('External extension origin requires its own company TLS trust')
    try:
        key_id(public)
        if not isinstance(packet['signature'],str) or len(packet['signature'])>128:raise ValueError('Invalid signature size')
        sig=base64.b64decode(packet['signature'],validate=True)
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public,validate=True)).verify(sig,PURPOSE+canonical(data).encode())
    except Exception as exc:raise ValueError('Browser TLS trust authorization does not match organization pin') from exc
    return der


def projection(root):
    from .endpoint_package import public_connection
    from .browser_publication import selected
    from .update_packages import signer
    try:
        root=Path(root);state=selected(root)
        if not state:return None
        raw,pem=public_connection(root/'Endpoint-Connection.zip');server=json.loads(raw)['server']
        if any(origin(state['settings'][b+'_update_url'])!=origin(server) for b in ('chrome','edge')):return None
        if not (root/'update-signing/private.key').is_file():return None
        return authorize(server,pem,signer(root))
    except (OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile):return None


class WindowsRoots:
    """Exact DER comparison; SHA-1 is only a Windows lookup, never identity."""
    def __init__(self):
        import ctypes as c
        from ctypes import wintypes as w
        self.c=c
        class Blob(c.Structure):_fields_=[('size',w.DWORD),('data',c.POINTER(c.c_ubyte))]
        class Context(c.Structure):_fields_=[('encoding',w.DWORD),('data',c.POINTER(c.c_ubyte)),('size',w.DWORD),('info',c.c_void_p),('store',c.c_void_p)]
        self.Blob=Blob;self.Context=Context;self.api=c.WinDLL('crypt32',use_last_error=True)
        specs={'CertOpenStore':([c.c_void_p,w.DWORD,c.c_void_p,w.DWORD,c.c_void_p],c.c_void_p),
               'CertFindCertificateInStore':([c.c_void_p,w.DWORD,w.DWORD,w.DWORD,c.c_void_p,c.c_void_p],c.c_void_p),
               'CertFreeCertificateContext':([c.c_void_p],w.BOOL),'CertCloseStore':([c.c_void_p,w.DWORD],w.BOOL),
               'CertAddEncodedCertificateToStore':([c.c_void_p,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,c.c_void_p],w.BOOL),
               'CertDeleteCertificateFromStore':([c.c_void_p],w.BOOL)}
        for name,(args,result) in specs.items():getattr(self.api,name).argtypes=args;getattr(self.api,name).restype=result

    def _open(self,readonly):
        # System registry provider opens only LocalMachine\\Root's default
        # physical store; never delete a certificate from a GPO collection.
        value=self.c.c_wchar_p('ROOT')
        handle=self.api.CertOpenStore(self.c.c_void_p(13),0,None,0x20000|0x4000|(0x8000 if readonly else 0),self.c.cast(value,self.c.c_void_p))
        if not handle:raise self.c.WinError(self.c.get_last_error())
        return handle

    def _find(self,handle,der):
        c=self.c;raw=(c.c_ubyte*20).from_buffer_copy(hashlib.sha1(der).digest());blob=self.Blob(20,raw)
        ctx=self.api.CertFindCertificateInStore(handle,0x10001,0,0x10000,c.byref(blob),None)
        if not ctx:
            error=c.get_last_error()&0xffffffff
            if error!=0x80092004:raise c.WinError(error)
            return None
        data=c.cast(ctx,c.POINTER(self.Context)).contents
        if data.size!=len(der) or c.string_at(data.data,data.size)!=der:
            self.api.CertFreeCertificateContext(ctx);raise ValueError('Certificate lookup collision')
        return ctx

    def contains(self,der):
        handle=self._open(True)
        try:
            ctx=self._find(handle,der)
            if ctx:self.api.CertFreeCertificateContext(ctx)
            return bool(ctx)
        finally:self.api.CertCloseStore(handle,0)

    def add(self,der):
        handle=self._open(False)
        try:
            raw=self.c.create_string_buffer(der)
            if not self.api.CertAddEncodedCertificateToStore(handle,0x10001,raw,len(der),1,None):
                error=self.c.get_last_error()&0xffffffff
                if error==0x80092005:return False # concurrent existing certificate
                raise self.c.WinError(error)
            return True
        finally:self.api.CertCloseStore(handle,0)

    def remove(self,der):
        handle=self._open(False)
        try:
            ctx=self._find(handle,der)
            if ctx and not self.api.CertDeleteCertificateFromStore(ctx):raise self.c.WinError(self.c.get_last_error())
        finally:self.api.CertCloseStore(handle,0)


def execute(config,action,directory,store):
    from .update_client import save
    ledger=Path(directory)/LEDGER
    if action not in ('apply','restore','status'):raise ValueError('Invalid browser trust action')
    if action=='restore' and not ledger.exists():return {'status':'not_managed'}
    ca=Path(config['ca'])
    if ca.stat().st_size>65536:raise ValueError('CA too large')
    der=verify(config.get('browser_trust'),config.get('update_key'),config['server'],ca.read_bytes(),config.get('browser_deployment'),current=action!='restore')
    digest=hashlib.sha256(der).hexdigest()
    saved=None
    if ledger.exists():
        if ledger.stat().st_size>4096:raise ValueError('Invalid trust ownership journal')
        saved=json.loads(ledger.read_text(encoding='utf-8'))
        if not isinstance(saved,dict) or set(saved)!={'format','sha256','state'} or saved.get('format')!=1 or saved.get('sha256')!=digest or saved.get('state') not in ('pending','added','preexisting','preserved_after_interruption'):raise ValueError('Conflicting trust ownership journal')
    present=store.contains(der)
    if action=='status':return {'status':'trusted' if present else 'trust_required','ca_sha256':digest}
    if action=='restore':
        if saved['state']=='added' and present:store.remove(der)
        elif saved['state'] in ('pending','preserved_after_interruption') and present:
            # A crash between add and commit cannot prove who installed it.
            if saved['state']=='pending':save(ledger,{**saved,'state':'preserved_after_interruption'})
            return {'status':'preserved_after_interruption','ca_sha256':digest}
        ledger.unlink();return {'status':'restored','ca_sha256':digest}
    if present:
        if saved is None:save(ledger,{'format':1,'sha256':digest,'state':'preexisting'})
        elif saved['state']=='pending':save(ledger,{**saved,'state':'preserved_after_interruption'})
        return {'status':'trusted','ca_sha256':digest,'browser_installation_verified':False}
    # Journal before mutation. Each retry preserves the same exact CA/pin.
    save(ledger,{'format':1,'sha256':digest,'state':'pending'})
    added=store.add(der)
    save(ledger,{'format':1,'sha256':digest,'state':'added' if added else 'preexisting'})
    if not store.contains(der):raise OSError('Browser CA trust readback failed')
    return {'status':'trusted','ca_sha256':digest,'browser_installation_verified':False}


def protected(config_path):
    """Fixed installed native code/config/CA/journal, admin, no writable input."""
    from .custom_windows import trusted_native
    from .update_native import protected_tree
    from .windows_privilege import is_admin
    if os.name!='nt' or not is_admin():raise PermissionError('Administrator browser trust operation required')
    config_path=Path(config_path).resolve()
    config=json.loads(config_path.read_text(encoding='utf-8'))
    root=trusted_native(config)
    if config_path!=root/'config.json' or Path(config.get('ca',''))!=root/'company-ca.pem':raise PermissionError('Protected native CA/configuration required')
    for p in (root,config_path,root/'company-ca.pem'):
        protected_tree(p,recursive=False)
    if (root/LEDGER).exists():protected_tree(root/LEDGER,recursive=False)
    return config,root


def sync(agent,packet):
    """Optional new-version projection. Never blocks unrelated collection."""
    if packet is None:return {'status':'trust_authorization_unavailable'}
    try:
        config,root=protected(agent.config_path)
        if Path(config['ca']).stat().st_size>65536:raise ValueError('CA too large')
        verify(packet,config.get('update_key'),config['server'],Path(config['ca']).read_bytes(),config.get('browser_deployment'))
        if config.get('browser_trust') not in (None,packet):raise ValueError('Browser trust change requires MIS migration')
        if config.get('browser_trust')!=packet:
            from .update_client import save
            config['browser_trust']=packet;save(agent.config_path,config);agent.config=config
        import time
        previous=getattr(agent,'_browser_trust_check',None)
        if previous and previous[0]==packet and time.monotonic()-previous[1]<300:return previous[2]
        result=execute(config,'apply',root,WindowsRoots())
        agent._browser_trust_check=(packet,time.monotonic(),result)
        return result
    except (OSError,ValueError,KeyError,TypeError) as exc:
        return {'status':'trust_failed','error_type':type(exc).__name__,'winerror':getattr(exc,'winerror',None)}
