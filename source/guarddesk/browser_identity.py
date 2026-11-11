"""Public extension identity validation; no key generation or secret storage."""
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def identity(public):
    if not isinstance(public,str) or not 1<=len(public)<=2048:raise ValueError('Invalid extension public key')
    try:
        der=base64.b64decode(public,validate=True);key=serialization.load_der_public_key(der)
    except Exception as exc:raise ValueError('Invalid extension public key') from exc
    if not isinstance(key,rsa.RSAPublicKey) or not 2048<=key.key_size<=4096 or key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)!=der:raise ValueError('Invalid extension RSA key')
    return ''.join(chr(97+int(c,16)) for c in hashlib.sha256(der).hexdigest()[:32])
