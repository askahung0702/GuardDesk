"""Disclosed, read-only Chrome/Edge history audit for the interactive user.

No browser configuration, extension, debug port, process injection or TLS
interception. History is evidence of a saved visit, not a live tab observer.
"""
from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import tempfile
import threading
import time

from .identity import current_account
from .serialization import canonical

EPOCH = 11644473600
INTERVAL = 10
MAX_PROFILES = 64
BATCH = 100
MAX_SNAPSHOT = 64 * 1024 * 1024


def chrome_time(value):
    return int((value + EPOCH) * 1_000_000)


def discover_profiles():
    local = os.environ.get('LOCALAPPDATA')
    if not local or os.name != 'nt':
        return [], False
    found = []; truncated = False
    for browser, parts in [('chrome', ('Google', 'Chrome', 'User Data')),
                           ('edge', ('Microsoft', 'Edge', 'User Data'))]:
        root = Path(local).joinpath(*parts)
        if not root.exists():
            continue
        if any(getattr(p.stat(), 'st_file_attributes', 0) & 0x400 for p in (root, *root.parents) if p.exists()):
            continue
        # Only standard profiles, never recurse into caches/cookies/credentials.
        with os.scandir(root) as entries:
            for entry in entries:
                if entry.name != 'Default' and not entry.name.startswith('Profile '):
                    continue
                if entry.is_dir(follow_symlinks=False) and not getattr(entry.stat(follow_symlinks=False), 'st_file_attributes', 0) & 0x400:
                    history = Path(entry.path) / 'History'
                    if history.is_file() and not getattr(history.stat(), 'st_file_attributes', 0) & 0x400:
                        if len(found) >= MAX_PROFILES:
                            truncated = True
                        else:
                            found.append((browser, entry.name, history))
    return sorted(found, key=lambda item: (item[0], item[1])), truncated


class BrowserHistory:
    def __init__(self, agent):
        self.agent = agent
        self.stop = threading.Event()
        self.thread = None
        self.offset = 0
        self.last_discovery = 0
        self.profiles = []
        self.truncated = False
        self.results = {}
        self.snapshots = {}
        self.user = current_account()

    def start(self):
        self.thread = threading.Thread(target=self.run, name='GuardDesk-BrowserHistory', daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(2)

    def run(self):
        from .performance import background_work
        with background_work():
            while not self.stop.is_set():
                try:
                    self.poll()
                except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
                    # Paths, URLs and database exception text can contain secrets.
                    self.agent.feature_status['browser_history'] = {'status': 'failed', 'reason': 'collector_error'}
                self.stop.wait(INTERVAL)

    def poll(self):
        if self.user.casefold().endswith(('\\system', '\\local service', '\\network service')):
            self.agent.feature_status['browser_history'] = {'status': 'interactive_user_required'}
            return
        from .decommission import saved
        with self.agent.db() as db:
            has_policy = db.execute("SELECT 1 FROM state WHERE key='policy'").fetchone()
            raw = db.execute("SELECT value FROM state WHERE key='browser_history_session'").fetchone()
            session = json.loads(raw[0]) if raw else None
            if not has_policy:
                self.agent.feature_status['browser_history'] = {'status': 'waiting_policy'}
                return
        enabled = self.agent.policy_for_user(self.user)['body']['browser_audit'] and not saved(self.agent)
        from .custom_client import effective_body,build_number
        from .custom_settings import compatibility_modules
        if 'browser_history' in compatibility_modules(effective_body(self.agent),build_number()):enabled=False
        if not session or session['enabled'] != enabled:
            session = {'enabled': enabled, 'since': time.time(), 'generation': secrets.token_hex(12)}
            with self.agent.db() as db:
                db.execute("INSERT OR REPLACE INTO state VALUES ('browser_history_session',?)", (canonical(session),))
        if not enabled:
            self.agent.feature_status['browser_history'] = {'status': 'disabled'}
            return
        if not self.last_discovery or time.monotonic() - self.last_discovery >= 60:
            self.profiles, self.truncated = discover_profiles()
            self.last_discovery = time.monotonic()
            allowed = {(b, p) for b, p, _ in self.profiles}
            self.results = {k: v for k, v in self.results.items() if k in allowed}
        # Four profiles per cycle; round-robin, no unbounded catch-up loop.
        for _ in range(min(4, len(self.profiles))):
            if self.stop.is_set():
                break
            browser, profile, path = self.profiles[self.offset % len(self.profiles)]
            self.offset += 1
            try:
                self.results[(browser, profile)] = self.read_profile(browser, profile, path, session)
            except SnapshotUnavailable as exc:
                previous = self.results.get((browser, profile), {})
                if str(exc) == 'snapshot_retry_30_seconds' and previous.get('status') == 'collecting':
                    self.results[(browser, profile)] = {**previous, 'waiting_snapshot': True, 'queued': 0}
                else:
                    self.results[(browser, profile)] = {'status': 'unavailable', 'reason': str(exc)}
            except (OSError, sqlite3.Error, ValueError, TypeError, OverflowError):
                # Keep the cursor for retry; never silently acknowledge unread rows.
                self.results[(browser, profile)] = {'status': 'unavailable', 'reason': 'locked_denied_or_unsupported'}
        statuses = [{'browser': b, 'profile': p, **self.results.get((b, p), {'status': 'pending'})}
                    for b, p, _ in self.profiles]
        status = 'collecting' if statuses and all(s['status'] == 'collecting' for s in statuses) else 'partial' if statuses else 'no_profiles'
        self.agent.feature_status['browser_history'] = {
            'status': status, 'checked_at': time.time(), 'profiles': statuses,
            'profiles_truncated': self.truncated, 'interval_seconds': INTERVAL,
            'source': 'browser_history', 'coverage': 'saved_normal_visits_only',
            'since': session['since'], 'manual_browser_setup': False,
        }

    def read_profile(self, browser, profile, path, session):
        identity = hashlib.sha256((self.user + '\0' + browser + '\0' + str(path)).encode()).hexdigest()
        key = 'browser_history:' + identity
        with self.agent.db() as db:
            saved = db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        cursor = json.loads(saved[0]) if saved else {}
        if cursor.get('session') != session['generation']:
            cursor = {'session': session['generation'], 'last_id': 0, 'since': session['since'],
                      'generation': secrets.token_hex(12), 'anchor_time': 0}
        # Retain SQLite locking/WAL semantics. immutable/nolock would be unsafe
        # for a live browser database. Uncertain images leave the cursor intact.
        with self.open_history(path) as source:
            deadline = time.monotonic() + .15
            source.execute('PRAGMA query_only=ON')
            source.execute('PRAGMA trusted_schema=OFF')
            source.execute('PRAGMA cache_size=-256')
            source.execute('PRAGMA mmap_size=0')
            source.set_progress_handler(lambda: int(time.monotonic() > deadline or self.stop.is_set()), 1000)
            source.execute('BEGIN')
            columns = {r[1] for r in source.execute('PRAGMA table_info(visits)')}
            has_source = source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='visit_source'").fetchone()
            # Browser Sync/import history must not be attributed to this endpoint.
            remote = "COALESCE(v.originator_cache_guid,'')='' AND " if 'originator_cache_guid' in columns else ''
            join = ' LEFT JOIN visit_source s ON s.id=v.id' if has_source else ''
            local = ' AND s.id IS NULL' if has_source else ''
            reset = False
            if cursor['last_id']:
                anchor = source.execute('SELECT visit_time FROM visits WHERE id=?', (cursor['last_id'],)).fetchone()
                maximum = source.execute('SELECT max(id) FROM visits').fetchone()[0] or 0
                if maximum < cursor['last_id'] or (anchor and anchor[0] != cursor['anchor_time']):
                    reset = True
                    cursor.update(last_id=0, generation=secrets.token_hex(12))
                    # Previously acknowledged visits are not backfilled on reset.
                    cursor['since'] = max(cursor['since'], cursor.get('last_time', session['since']))
            # A new profile starts on the time index; then use the primary key.
            # substr bounds values at the SQLite boundary even for malformed DBs.
            first_id = None
            if not cursor['last_id']:
                first_id = source.execute('SELECT min(id) FROM visits WHERE visit_time>=?', (chrome_time(cursor['since']),)).fetchone()[0]
            where = 'v.id>?'
            value = cursor['last_id'] if cursor['last_id'] else (first_id-1 if first_id is not None else 9223372036854775807)
            rows = source.execute(
                'SELECT v.id,v.visit_time,substr(u.url,1,8193),substr(u.title,1,500),v.transition '
                'FROM visits v JOIN urls u ON u.id=v.url' + join +
                ' WHERE ' + where + ' AND ' + remote + 'v.visit_time>=?' + local +
                ' ORDER BY v.id LIMIT ?', (value, chrome_time(cursor['since']), BATCH)).fetchall()
        from .browser_host import sanitize_url
        count = 0
        with self.agent.db() as db:
            for visit_id, timestamp, url, title, transition in rows:
                occurred = timestamp / 1_000_000 - EPOCH
                cursor.update(last_id=visit_id, anchor_time=timestamp)
                cursor['last_time'] = max(cursor.get('last_time', cursor['since']), occurred)
                # Exclude subframes and generated keyword result visits.
                if (transition & 255) in (3, 4, 10) or not 0 <= occurred <= time.time() + 300:
                    continue
                try:
                    safe = sanitize_url(url)
                except (ValueError, TypeError):
                    continue
                if not safe:
                    continue
                safe_url, domain = safe
                eid = 'history-' + hashlib.sha256((identity + cursor['generation'] + str(visit_id)).encode()).hexdigest()
                self.agent.queue('web.navigation', {'url': safe_url, 'domain': domain, 'title': title or '',
                    'user': self.user, 'browser': browser, 'profile': profile,
                    'source': 'browser_history', 'coverage': 'saved_visit', 'visit_id': visit_id},
                    occurred=occurred, event_id=eid, db=db)
                count += 1
            db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', (key, canonical(cursor)))
        return {'status': 'collecting', 'last_poll': time.time(), 'queued': count, 'more': len(rows) == BATCH,
                'database_reset': reset, 'last_visit_time': cursor.get('last_time')}

    @contextmanager
    def open_history(self, path):
        source = sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True, timeout=.05)
        try:
            source.execute('PRAGMA query_only=ON')
            source.execute('PRAGMA trusted_schema=OFF')
            source.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024*1024)
            deadline = time.monotonic()+.15
            source.set_progress_handler(lambda: int(time.monotonic()>deadline or self.stop.is_set()), 1000)
            source.execute('SELECT id FROM visits LIMIT 1').fetchone()
        except sqlite3.OperationalError as exc:
            source.close()
            if 'locked' not in str(exc).lower() and 'busy' not in str(exc).lower():
                raise
        except BaseException:
            source.close()
            raise
        else:
            try:
                yield source
            finally:
                source.close()
            return
        # Chromium on Windows can hold SQLite EXCLUSIVE locks while idle.
        # Never bypass locks on a live DB. Observe a private, bounded image only
        # when rollback journal/WAL are idle and two streamed reads agree.
        last = self.snapshots.get(str(path), 0)
        if time.monotonic() - last < 30:
            raise SnapshotUnavailable('snapshot_retry_30_seconds')
        self.snapshots = {k:v for k,v in self.snapshots.items() if time.monotonic()-v < 120}
        self.snapshots[str(path)] = time.monotonic()
        with tempfile.TemporaryDirectory(prefix='browser-snapshot-', dir=self.agent.config_path.parent) as folder:
            from .server_setup import secure_directory
            secure_directory(Path(folder), allow_empty=True)
            if shutil.disk_usage(folder).free < 128*1024*1024:
                raise SnapshotUnavailable('snapshot_insufficient_disk_space')
            target = Path(folder)/'History'
            snapshot_history(path, target, self.stop)
            with closing(sqlite3.connect(target.as_uri()+'?mode=ro', uri=True, timeout=.05)) as snapshot:
                snapshot.execute('PRAGMA query_only=ON')
                snapshot.execute('PRAGMA trusted_schema=OFF')
                snapshot.execute('PRAGMA cache_size=-256')
                snapshot.execute('PRAGMA mmap_size=0')
                deadline = time.monotonic()+.5
                snapshot.set_progress_handler(lambda: int(time.monotonic()>deadline or self.stop.is_set()), 1000)
                if snapshot.execute('PRAGMA quick_check(1)').fetchone() != ('ok',):
                    raise SnapshotUnavailable('snapshot_integrity_failed')
                yield snapshot


class SnapshotUnavailable(OSError):
    pass


def snapshot_history(source, target, stop):
    def signature(path):
        info = path.stat()
        return info.st_size, info.st_mtime_ns, info.st_ino

    def idle():
        for suffix in ('-wal', '-journal'):
            p = Path(str(source)+suffix)
            if p.exists() and p.stat().st_size:
                if suffix == '-wal':
                    raise SnapshotUnavailable('snapshot_waiting_for_wal_checkpoint')
                with p.open('rb') as journal:
                    if any(journal.read(28)):
                        raise SnapshotUnavailable('snapshot_waiting_for_idle_journal')

    idle(); before = signature(source)
    if before[0] > MAX_SNAPSHOT:
        raise SnapshotUnavailable('history_over_64_mib_snapshot_limit')
    # Two matching reads detect concurrent page changes without loading the DB
    # into RAM. Rate-limit aggregate read IO to ~8 MiB/s with 64 KiB chunks.
    def read(output=None):
        digest = hashlib.sha256(); size = 0; started = time.monotonic()
        with source.open('rb') as stream:
            while True:
                block = stream.read(65536)
                if not block:
                    break
                size += len(block)
                if size > MAX_SNAPSHOT or stop.is_set():
                    raise SnapshotUnavailable('snapshot_cancelled_or_size_changed')
                digest.update(block)
                if output:
                    output.write(block)
                if stop.wait(max(0, size/(8*1024*1024)-(time.monotonic()-started))):
                    raise SnapshotUnavailable('snapshot_cancelled')
        return digest.digest(), size
    with target.open('xb') as output:
        first = read(output)
    idle()
    if signature(source) != before:
        raise SnapshotUnavailable('snapshot_changed_retry')
    second = read()
    idle()
    if signature(source) != before or first != second:
        raise SnapshotUnavailable('snapshot_changed_retry')
