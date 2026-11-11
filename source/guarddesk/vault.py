"""Explicit encrypted package; never mutates the original file."""
import base64
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .policy import MAX_FILE

MAGIC = b"GDESK01\n"


def load_key(path, create=False):
    path = Path(path)
    if create and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(base64.b64encode(AESGCM.generate_key(bit_length=256)))
        if os.name != "nt":
            path.chmod(0o600)
    key = base64.b64decode(path.read_bytes().strip(), validate=True)
    if len(key) != 32:
        raise ValueError("金鑰必須是 256 bits")
    return key


def encrypt(source, target, key):
    source, target = Path(source), Path(target)
    if source.stat().st_size > MAX_FILE:
        raise ValueError("加密封裝單檔上限 10 MB")
    data = source.read_bytes()
    if len(data) > MAX_FILE:
        raise ValueError("加密封裝單檔上限 10 MB")
    nonce = os.urandom(12)
    package = MAGIC + nonce + AESGCM(key).encrypt(nonce, data, MAGIC)
    with target.open("xb") as stream:
        stream.write(package)
    return target


def decrypt(source, target, key):
    source, target = Path(source), Path(target)
    if source.stat().st_size > MAX_FILE + 100:
        raise ValueError("封裝大小超過上限")
    package = source.read_bytes()
    if not package.startswith(MAGIC) or len(package) < len(MAGIC) + 28:
        raise ValueError("不是 GuardDesk 加密檔")
    start = len(MAGIC)
    data = AESGCM(key).decrypt(package[start:start+12], package[start+12:], MAGIC)
    with target.open("xb") as stream:
        stream.write(data)
    return target
