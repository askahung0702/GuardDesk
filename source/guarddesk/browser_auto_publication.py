"""Use the installed Server's existing connection, never HTTP Host input.

Automatic preparation is part of MIS setup/update/download, not agent ingestion.
Only public identity is journaled in SQLite; signing keys stay in private files.
"""
import json
from pathlib import Path
from .store import Store,canonical
from . import browser_publication as publication


def ensure(store,actor):
    root=store.path.resolve().parent
    connection=root/'Endpoint-Connection.zip'
    if not connection.exists():return {'status':'connection_required'}
    from .endpoint_package import public_connection
    manifest,_=public_connection(connection)
    body=json.loads(manifest)
    base=body['server'].rstrip('/')+publication.PUBLIC_PREFIX
    # Receipt survives DB backups and prevents lost files becoming a new ID.
    with store.connect() as db:
        db.execute('CREATE TABLE IF NOT EXISTS browser_publication_identity (id INTEGER PRIMARY KEY CHECK(id=1),settings TEXT NOT NULL,managed INTEGER NOT NULL)')
        saved=db.execute('SELECT settings,managed FROM browser_publication_identity WHERE id=1').fetchone()
    prior=publication.selected(root)
    key=root/'BrowserSigner/extension-signing.pem'
    if saved:
        expected=json.loads(saved['settings'])
        if not prior or prior['settings']!=expected:raise ValueError('公司擴充發布身分或來源遺失／不符；請還原原資料，不自動建立替代身分')
        if saved['managed'] and not key.is_file():raise ValueError('原公司擴充簽署金鑰遺失；保留原身分，請從備份還原')
    if prior and (root/'BrowserSigner').exists() and not key.is_file():raise ValueError('原公司擴充簽署金鑰遺失；不自動替換身分')
    if prior:
        # Preserve external publication and custom approved URLs. Never move
        # endpoints to another source as a side effect of a Server update.
        if key.is_file() and prior['settings']['chrome_update_url']==base+'updates.xml' and prior['settings']['edge_update_url']==base+'updates.xml':
            result=publication.create_managed(root,base)
        else:
            for name in prior['hashes']:publication.public_file(root,name)
            result=publication.status(root)
    else:result=publication.create_managed(root,base)
    state=publication.selected(root)
    if not state:raise OSError('Automatic publication did not select a generation')
    if saved and state['settings']!=json.loads(saved['settings']):raise OSError('Company identity changed during automatic preparation')
    with store.connect() as db:
        if not saved:
            db.execute('INSERT OR IGNORE INTO browser_publication_identity VALUES (1,?,?)',(canonical(state['settings']),int(key.is_file())))
            receipt=db.execute('SELECT settings FROM browser_publication_identity WHERE id=1').fetchone()
            if json.loads(receipt['settings'])!=state['settings']:raise OSError('Company identity changed concurrently; preserve publication for review')
        if not prior or prior['generation']!=state['generation']:
            Store.event(db,'console','browser.publication_prepared','info',{'actor':actor,'generation':state['generation'],'extension_id':state['settings']['extension_id'],'mode':'automatic_existing_connection','browser_installation_verified':False})
    return {**result,'preparation':'automatic','browser_installation_verified':False}
