"""Remote-only machine identity/state; no collectors, policy application or export.

Use the existing config.sqlite3 and removal state. Never migrate, flush or erase
an audit queue from a full installation. Authorization remains in the compiled
profile, protected installer, SYSTEM broker and authenticated session router.
"""
import json
import sqlite3
from contextlib import contextmanager, closing
from pathlib import Path
from .endpoint_transport import request, transport

ROUTES=frozenset({'/api/agent/heartbeat','/api/agent/remote/poll',
    '/api/agent/remote/update','/api/agent/remote/native',
    '/api/agent/uninstall/poll','/api/agent/uninstall/status'})


class RemoteEndpointState:
    def __init__(self,config):
        self.config_path=Path(config).resolve()
        self.config=json.loads(self.config_path.read_text(encoding='utf-8'))
        from .remote_trial import require_profile
        from .remote_trial_install import check_settings
        require_profile(self.config)
        check_settings(self.config)
        if self.config.get('machine_session'):
            raise PermissionError('Machine credentials may not be used by a user-session collector')
        self.state=self.config_path.with_suffix('.sqlite3')
        self.feature_status={}
        self.machine_session_policy=None
        self._opener=None
        from .remote_trial import no_control_files
        no_control_files(self.config_path)
        # Refuse a legacy queue before any schema/WAL change. mode=ro avoids
        # creating a new database if an existing file disappears during checks.
        if self.state.exists():
            with closing(sqlite3.connect(self.state.as_uri()+'?mode=ro',uri=True,timeout=15)) as db:
                self._empty_outbox(db)
        with self.db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS outbox(event_id TEXT PRIMARY KEY,payload TEXT NOT NULL,created REAL NOT NULL)')
            self._empty_outbox(db)
        from .remote_trial import no_control_ledgers
        no_control_ledgers(self)

    @staticmethod
    def _empty_outbox(db):
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='outbox'").fetchone():
            if db.execute('SELECT 1 FROM outbox LIMIT 1').fetchone():
                raise PermissionError('Existing audit outbox cannot be adopted by remote-only trial')

    @contextmanager
    def db(self):
        connection=sqlite3.connect(self.state,timeout=15)
        try:
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('PRAGMA cache_size=-512')
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:connection.close()

    @contextmanager
    def wal_session(self):
        with self.db() as anchor:
            anchor.execute('SELECT key FROM state LIMIT 1').fetchall()
            yield

    def call(self,path,body,timeout=10):
        if path not in ROUTES:
            raise PermissionError('Non-remote endpoint route disabled in trial')
        if self._opener is None:
            self._opener=transport(self.config['server'],self.config.get('ca'))
        return request(self.config['server'],path,body,self.config['token'],
                       self.config.get('ca'),opener=self._opener,timeout=timeout)

    def flush(self,**_):
        # Shared decommission handshake asks whether a queue is empty. It must
        # not acquire an events upload capability, even when a legacy DB appears.
        with self.db() as db:self._empty_outbox(db)
        return {'sent':0,'pending':False}
