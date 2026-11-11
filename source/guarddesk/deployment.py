from .connection_contract import validate_body
"""Explicit reusable bootstrap code. Never an endpoint or management credential."""
import json
import os
import re
import secrets
import threading
import time
import zipfile
from pathlib import Path
from .store import Store, digest

LOCK = threading.Lock()


class DeploymentError(ValueError): pass


def replace_with_retry(source,target):
    """Bounded Windows sharing/access retry; never delete the old bundle first."""
    deadline=time.monotonic()+10
    while True:
        plain(source);plain(target)
        try:
            os.replace(source,target)
            return
        except OSError as exc:
            if getattr(exc,'winerror',None) not in (5,32,33) or time.monotonic()>=deadline:raise
            time.sleep(.2)


def plain(path):
    for p in (Path(path), *Path(path).parents):
        if os.path.lexists(p) and (p.is_symlink() or getattr(p.lstat(), 'st_file_attributes', 0) & 0x400):
            raise DeploymentError('部署資料不可包含 junction／符號連結')


def status(db):
    row = db.execute('SELECT id,created,revoked,uses FROM deployment_codes ORDER BY rowid DESC LIMIT 1').fetchone()
    return {'created': bool(row), 'active': bool(row and not row['revoked']), 'code': dict(row) if row else None}


def code(store, root, actor, rotate=False):
    from .endpoint_files import secure_directory
    root = Path(root).resolve(); folder = root / 'deployment'; plain(folder)
    with LOCK, store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        current = db.execute('SELECT * FROM deployment_codes WHERE revoked=0').fetchone()
        secret = folder / 'credentials.json'; plain(secret)
        if current and not rotate:
            if not secret.is_file() or secret.stat().st_size > 4096:
                raise DeploymentError('共用部署碼資料遺失，請 MIS 在部署碼管理更換；不自動啟用新碼')
            saved = json.loads(secret.read_text(encoding='utf-8'))
            if not isinstance(saved, dict) or set(saved) != {'id','code'} or saved['id'] != current['id'] or not isinstance(saved['code'],str) or digest(saved['code']) != current['token_hash']:
                raise DeploymentError('部署碼資料與資料庫不符，請 MIS 更換部署碼')
            return saved['code']
        prior = bool(db.execute('SELECT 1 FROM deployment_codes LIMIT 1').fetchone())
        if not rotate and prior:
            raise DeploymentError('共用部署碼已停用，請 MIS 先在部署碼管理重新產生')
        if not folder.exists(): secure_directory(folder)
        elif not folder.is_dir() or not prior: raise DeploymentError('部署資料目錄已有其他資料，請 MIS 核對後處理')
        value = secrets.token_urlsafe(32); identifier = secrets.token_hex(12)
        temporary = folder / 'credentials.tmp'; plain(temporary)
        # Only an installer-created private directory receives the raw bootstrap.
        with temporary.open('x', encoding='utf-8') as stream:
            json.dump({'id':identifier,'code':value}, stream)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, secret)
        db.execute('UPDATE deployment_codes SET revoked=1 WHERE revoked=0')
        db.execute('INSERT INTO deployment_codes(id,token_hash,created) VALUES (?,?,?)',(identifier,digest(value),time.time()))
        Store.event(db,'console','deployment.rotated' if rotate else 'deployment.created','info',{'actor':actor,'code_id':identifier})
        return value


def prepare_connection(store, connection, actor, rotate=False):
    """Atomically update the server's own connection ZIP; never accept uploads."""
    from .endpoint_package import public_connection
    connection = Path(connection); plain(connection)
    manifest, ca = public_connection(connection)
    # The existing MIS connection already names the company's endpoint URL.
    # Prepare publication before emitting a package; no separate setup page.
    from .browser_auto_publication import ensure
    from .remote_trial import enabled
    trial=enabled()
    if not trial:ensure(store,actor)
    value = code(store, connection.parent, actor, rotate)
    body = json.loads(manifest); body.update(version=2, deployment_code=value)
    # Private signing keys never travel. Extension settings and TLS trust have
    # separate purpose-bound authorization under the existing organization pin.
    from .browser_publication import selected,public_file
    publication=None if trial else selected(connection.parent)
    body.pop('browser_deployment',None)
    body.pop('browser_deployment_authorization',None)
    from .update_packages import signer,public_key
    private=signer(connection.parent)
    if publication:
        for name in publication['hashes']:public_file(connection.parent,name)
        from .browser_deployment import authorize
        body.update(version=3,browser_deployment=publication['settings'],browser_deployment_authorization=authorize(publication['settings'],private))
    update_trust={'format':1,'public_key':public_key(private)}
    from .browser_trust import projection as trust_projection
    browser_trust=None if trial else trust_projection(connection.parent)
    temporary = connection.with_name(connection.name + '.tmp'); plain(temporary)
    created = False
    try:
        with temporary.open('xb') as stream:
            created = True
            with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('endpoint-connection.json',json.dumps(body,indent=2))
                archive.writestr('GuardDesk-CA.pem',ca)
                archive.writestr('update-trust.json',json.dumps(update_trust))
                if browser_trust:archive.writestr('browser-trust.json',json.dumps(browser_trust))
                from .endpoint_package import SETUP
                archive.writestr('Connect-Endpoint.cmd',SETUP)
                archive.writestr('README-Connection.txt','這是連線設定包，不含 Agent，不能單獨安裝。請使用 Server 產生的 GuardDesk-Endpoint.zip，或由管理畫面下載「端點安裝包」，完整解壓後執行 Setup-Endpoint.cmd。\n本包包含共用註冊祕密，只交內部授權人員保管；不包含 Server 私鑰或資料庫。停止／更換部署碼會阻止舊包新增註冊，不影響既有端點。\n')
        replace_with_retry(temporary,connection)
    except BaseException:
        # Only remove a regular file created by this attempt.
        if created and temporary.exists() and not temporary.is_symlink(): temporary.unlink()
        raise


def consume(db, value):
    row = db.execute('SELECT id FROM deployment_codes WHERE token_hash=? AND revoked=0',(digest(value),)).fetchone()
    if not row: return None
    db.execute('UPDATE deployment_codes SET uses=uses+1 WHERE id=?',(row['id'],))
    return row['id']


