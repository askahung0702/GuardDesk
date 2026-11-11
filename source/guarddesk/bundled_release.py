from .bundle_manifest import BundleError, inspect
"""Prepare the installed server's bundled Agent once, without an upload or deploy."""
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from . import __version__,update_packages as packages
from .serialization import canonical
from . import updates

METADATA='_internal/agent-release.json'






def prepare(store,source,version,stop):
    """No DB transaction during filesystem scanning or compression."""
    expected=inspect(Path(source),version,stop)
    from .endpoint_payload import project,entry
    expected,overrides=project(source,expected);root=store.path.resolve().parent
    with store.connect() as db:
        prior=db.execute('SELECT * FROM update_releases WHERE version=?',(version,)).fetchone()
        used=db.execute('SELECT count(*) FROM update_releases').fetchone()[0]
        enrolled=db.execute('SELECT count(*) FROM devices').fetchone()[0]
    if not (root/'update-signing').exists() and (used or enrolled):raise BundleError('signing_unavailable')
    private=packages.signer(root)
    if prior:
        existing=packages.validate_manifest(packages.verify(json.loads(prior['envelope']),packages.public_key(private)))
        if existing['files']!=expected:raise BundleError('version_conflict')
        archive=packages.plain(updates.repository(store)/(existing['sha256']+'.zip'))
        if not archive.is_file() or archive.stat().st_size!=existing['bytes'] or packages.file_hash(archive)!=existing['sha256']:raise BundleError('storage_failed')
        return {'id':prior['id'],'version':version,'cached':True}
    if used>=100:raise BundleError('repository_full')
    with tempfile.TemporaryDirectory(prefix='bundled-release-',dir=root) as temp:
        from .endpoint_files import secure_directory
        scratch=Path(temp);secure_directory(scratch,allow_empty=True)
        archive=scratch/'agent.zip'
        with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as package:
            for name,wanted in sorted(expected.items()):
                if stop.is_set():raise InterruptedError('stopped')
                digest=hashlib.sha256()
                with entry(source,name,overrides) as stream,package.open(name,'w') as output:
                    while chunk:=stream.read(65536):
                        if stop.is_set():raise InterruptedError('stopped')
                        digest.update(chunk);output.write(chunk)
                if digest.hexdigest()!=wanted:raise BundleError('integrity_failed')
        if stop.is_set():raise InterruptedError('stopped')
        manifest={'format':1,'version':version,'architecture':'windows-x64','sha256':packages.file_hash(archive),'bytes':archive.stat().st_size,'files':expected}
        packages.validate_manifest(manifest)
        result=updates.register_package(store,manifest,archive,'installed-server',bundled=True)
        return {**result,'cached':False}


class Publisher:
    def __init__(self,store,package_lock,*,manual_endpoint=False):
        self.store=store;self.package_lock=package_lock;self.lock=threading.Lock();self.stop=threading.Event();self.thread=None
        self.source=Path(sys.executable).resolve().parent if getattr(sys,'frozen',False) else None
        self.state={'status':'preparing' if self.source else 'not_packaged','version':__version__}
        if manual_endpoint:
            self.source=None
            self.state={'status':'remote_trial_manual_only','version':__version__,'automatic_dispatch':False}
    def snapshot(self):
        with self.lock:return dict(self.state)
    def start(self):
        with self.lock:
            if self.source is None or self.stop.is_set() or self.state.get('status') in ('ready','server_only') or self.thread and self.thread.is_alive():return False
            self.state={'status':'preparing','version':__version__}
            self.thread=threading.Thread(target=self.work,name='GuardDesk-BundledAgent',daemon=True);self.thread.start()
            return True
    def work(self):
        from .performance import background_work
        try:
            with background_work():
                while not self.package_lock.acquire(timeout=.2):
                    if self.stop.is_set():raise InterruptedError('stopped')
                try:
                    if self.stop.is_set():raise InterruptedError('stopped')
                    from .release_scope import profile
                    scope=profile(__version__)
                    result=None if scope['scope']=='server_only' else prepare(self.store,self.source,__version__,self.stop)
                    if self.stop.is_set():raise InterruptedError('stopped')
                    try:
                        from .browser_auto_publication import ensure
                        browser=ensure(self.store,'installed-server')
                    except (OSError,ValueError,sqlite3.Error) as exc:
                        # Browser publication failure must not stop existing
                        # data ingestion, the UI, or ordinary Agent updates.
                        browser={'status':'automatic_preparation_failed','error_type':type(exc).__name__}
                finally:self.package_lock.release()
            state={'status':'ready' if result else 'server_only','version':__version__,'browser_publication':browser,'deployment':scope}
            if result:state['release_id']=result['id']
        except InterruptedError:state={'status':'stopped','version':__version__}
        except BundleError as exc:
            state={'status':'failed','version':__version__,'code':exc.code}
            if exc.diagnostic:state['diagnostic']=exc.diagnostic
        except Exception:state={'status':'failed','version':__version__,'code':'preparation_failed'}
        with self.lock:self.state=state
    def close(self):
        self.stop.set()
        if self.thread:self.thread.join(5)
