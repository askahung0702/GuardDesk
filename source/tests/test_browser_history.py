import hashlib
from contextlib import contextmanager, closing
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from guarddesk.agent import Agent
from guarddesk.browser_history import BrowserHistory, chrome_time, BATCH, discover_profiles, snapshot_history, SnapshotUnavailable
import threading
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.store import canonical


@contextmanager
def history_db(path):
    with closing(sqlite3.connect(path)) as db:
        with db:
            yield db


def make_history(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with history_db(path) as db:
        db.executescript('CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT);'
                         'CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER,transition INTEGER,originator_cache_guid TEXT);'
                         'CREATE INDEX visits_time_index ON visits(visit_time);'
                         'CREATE TABLE visit_source(id INTEGER PRIMARY KEY,source INTEGER);')


def visit(path, ident, url='https://example.test/doc?q=review', title='測試文件', occurred=None, remote=''):
    with history_db(path) as db:
        db.execute('INSERT INTO urls VALUES (?,?,?)', (ident, url, title))
        db.execute('INSERT INTO visits VALUES (?,?,?,?,?)', (ident, ident, chrome_time(occurred or time.time()), 0, remote))


class BrowserHistoryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]/'runtime'); self.root = Path(self.temp.name)
        self.config = self.root/'config.json'
        self.config.write_text(json.dumps({'watch': str(self.root), 'server': 'http://127.0.0.1:1', 'device_id': 'fixture', 'token': 'fixture'}))
        self.agent = Agent(self.config); self.history = self.root/'Default/History'; make_history(self.history)
        self.collector = BrowserHistory(self.agent)
        self.discovery = patch('guarddesk.browser_history.discover_profiles', return_value=([('chrome', 'Default', self.history)], False)); self.discovery.start()
        self.policy(True)

    def tearDown(self):
        self.collector.close(); self.discovery.stop(); self.temp.cleanup()

    def policy(self, enabled):
        with self.agent.db() as db:
            db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)", (canonical({'version': 1, 'body': {**DEFAULT_POLICY, 'browser_audit': enabled}}),))

    def events(self):
        with self.agent.db() as db:
            return [json.loads(r[0]) for r in db.execute("SELECT payload FROM outbox WHERE json_extract(payload,'$.kind')='web.navigation'")]

    def test_new_visits_repeat_restart_redaction_and_read_only(self):
        visit(self.history, 1, occurred=time.time()-600)
        self.collector.poll(); self.assertEqual(self.events(), [])
        for ident in (2, 3):
            visit(self.history, ident, 'https://user:pass@example.test/doc?token=secret&q=review#fragment')
        before = hashlib.sha256(self.history.read_bytes()).hexdigest()
        self.collector.poll(); events = self.events(); self.assertEqual(len(events), 2)
        self.assertEqual(events[0]['details']['title'], '測試文件')
        self.assertNotIn('secret', canonical(events)); self.assertNotIn('user:pass', canonical(events))
        self.assertNotIn('#fragment', canonical(events)); self.assertIn('q=review', canonical(events))
        self.assertEqual(hashlib.sha256(self.history.read_bytes()).hexdigest(), before)
        BrowserHistory(Agent(self.config)).poll(); self.assertEqual(len(self.events()), 2)

    def test_disabled_user_policy_and_no_backfill(self):
        self.collector.poll(); self.policy(False); self.collector.poll()
        visit(self.history, 1); self.policy(True); self.collector.poll()
        self.assertEqual(self.events(), [])
        visit(self.history, 2); self.collector.poll(); self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.agent.feature_status['browser_history']['status'], 'collecting')

    def test_user_override(self):
        with self.agent.db() as db:
            packet = {'version': 2, 'body': DEFAULT_POLICY, 'user_policies': {self.collector.user.casefold(): {'version': 2, 'body': {**DEFAULT_POLICY, 'browser_audit': False}}}}
            db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)", (canonical(packet),))
        self.collector.poll(); self.assertEqual(self.agent.feature_status['browser_history']['status'], 'disabled')

    def test_lock_retry_and_atomic_cursor(self):
        self.collector.poll(); visit(self.history, 1); visit(self.history, 2)
        with history_db(self.history) as db:
            db.execute('BEGIN EXCLUSIVE'); db.execute("UPDATE urls SET title='write in progress' WHERE id=1"); self.collector.poll()
            self.assertEqual(self.agent.feature_status['browser_history']['status'], 'partial')
        queue = self.agent.queue
        def fail_second(kind, details, **kwargs):
            if details['visit_id'] == 2: raise OSError('simulated disk full')
            return queue(kind, details, **kwargs)
        with patch.object(self.agent, 'queue', side_effect=fail_second): self.collector.poll()
        self.assertEqual(self.events(), [])
        self.collector.poll(); self.assertEqual(len(self.events()), 2)

    def test_reset_import_sync_internal_and_invalid_url(self):
        self.collector.poll(); visit(self.history, 10); self.collector.poll()
        self.history.unlink(); make_history(self.history); visit(self.history, 1)
        self.collector.poll(); self.assertEqual(len(self.events()), 2)
        visit(self.history, 2, remote='another-device'); visit(self.history, 3, 'chrome://settings')
        visit(self.history, 4, 'https://x.test:wrong/'); visit(self.history, 5)
        with history_db(self.history) as db: db.execute('INSERT INTO visit_source VALUES (5,0)')
        self.collector.poll(); self.assertEqual(len(self.events()), 2)

    def test_bounded_batches_and_schema_failure(self):
        self.collector.poll()
        with history_db(self.history) as db:
            db.executemany('INSERT INTO urls VALUES (?,?,?)', [(i, 'https://example.test/'+str(i), 'page') for i in range(1, BATCH+20)])
            db.executemany('INSERT INTO visits VALUES (?,?,?,?,?)', [(i, i, chrome_time(time.time()), 0, '') for i in range(1, BATCH+20)])
        self.collector.poll(); self.assertEqual(len(self.events()), BATCH)
        self.collector.poll(); self.assertEqual(len(self.events()), BATCH+19)
        with history_db(self.history) as db: db.execute('ALTER TABLE visits RENAME TO unsupported')
        self.collector.poll(); self.assertEqual(self.agent.feature_status['browser_history']['status'], 'partial')

    def test_no_policy_no_collection_and_discovery_both_browsers(self):
        with self.agent.db() as db: db.execute("DELETE FROM state WHERE key='policy'")
        self.collector.poll(); self.assertEqual(self.agent.feature_status['browser_history']['status'], 'waiting_policy')
        self.discovery.stop()
        for parts in [('Google', 'Chrome', 'User Data', 'Default'), ('Microsoft', 'Edge', 'User Data', 'Profile 2')]:
            make_history(self.root.joinpath(*parts)/'History')
        with patch.dict('os.environ', {'LOCALAPPDATA': str(self.root)}):
            profiles, truncated = discover_profiles()
        self.assertEqual({p[0] for p in profiles}, {'chrome', 'edge'}); self.assertFalse(truncated)

    def test_snapshot_is_bounded_read_only_and_rejects_busy_wal(self):
        visit(self.history, 1)
        target = self.root/'snapshot'; before = self.history.read_bytes()
        snapshot_history(self.history, target, threading.Event())
        self.assertEqual(target.read_bytes(), before); self.assertEqual(self.history.read_bytes(), before)
        Path(str(self.history)+'-wal').write_bytes(b'not checkpointed')
        with self.assertRaisesRegex(SnapshotUnavailable, 'wal_checkpoint'):
            snapshot_history(self.history, self.root/'never-created', threading.Event())
        self.assertFalse((self.root/'never-created').exists())
        Path(str(self.history)+'-wal').unlink()
        with self.history.open('wb') as stream: stream.truncate(64*1024*1024+1)
        with self.assertRaisesRegex(SnapshotUnavailable, '64_mib'):
            snapshot_history(self.history, self.root/'never-created', threading.Event())

    def test_existing_large_history_is_not_backfilled(self):
        old = chrome_time(time.time()-600)
        with history_db(self.history) as db:
            db.executemany('INSERT INTO urls VALUES (?,?,?)', ((i, 'https://old.test/', 'old') for i in range(1,50001)))
            db.executemany('INSERT INTO visits VALUES (?,?,?,?,?)', ((i,i,old,0,'') for i in range(1,50001)))
        self.collector.poll(); visit(self.history,50001); self.collector.poll()
        self.assertEqual(len(self.events()),1); self.assertEqual(self.events()[0]['details']['visit_id'],50001)
