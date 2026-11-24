"""Local audit upload scheduling and receipts. The center protocol stays unchanged."""
import hashlib
import json
import logging
import random
import sqlite3
import time
from contextlib import closing, contextmanager

from .document_writes import excluded_unconfirmed_write
from .file_exclusions import TMP_FILE_RULE, excluded_activity, tmp_file
from . import audit_collection
from .serialization import canonical
from .transport_errors import Backoff, link_retry_floor, link_state


LOG = logging.getLogger('guarddesk.agent')
NORMAL_MIN = 60
NORMAL_MAX = 120
RECEIPT_SECONDS = 120
MAX_RECEIPTS = 8192
URGENT = "json_extract(payload,'$.severity') IN ('warning','critical')"
SCHEMA = f"""
    CREATE INDEX IF NOT EXISTS outbox_urgent_created ON outbox(created,event_id) WHERE {URGENT};
    CREATE TABLE IF NOT EXISTS upload_receipts(
        observation TEXT PRIMARY KEY, wire_id TEXT NOT NULL, acknowledged REAL);
    CREATE INDEX IF NOT EXISTS upload_receipts_time ON upload_receipts(acknowledged);
    CREATE INDEX IF NOT EXISTS upload_reserved_ids ON upload_receipts(wire_id) WHERE acknowledged IS NULL;
    CREATE TRIGGER IF NOT EXISTS upload_release_reservation AFTER DELETE ON outbox BEGIN
        DELETE FROM upload_receipts WHERE wire_id=OLD.event_id AND acknowledged IS NULL;
    END;
"""


@contextmanager
def sender(state, wait):
    """Use an OS-released SQLite writer lock without blocking writes to the real outbox."""
    with closing(sqlite3.connect(str(state) + '.upload-lock', timeout=15 if wait else 0)) as lock:
        try:
            lock.execute('BEGIN IMMEDIATE')
        except sqlite3.OperationalError as exc:
            if getattr(exc, 'sqlite_errorcode', None) not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise
            if wait:
                raise ConnectionError('另一個程序正在上傳；事件保留於端點') from exc
            yield False
        else:
            yield True


class UploadSchedule:
    def __init__(self):
        self.retry = Backoff(5, 60)
        self.next_batch = time.monotonic() + random.uniform(NORMAL_MIN, NORMAL_MAX)
        self.next_probe = 0
        self.expedited = False

    def poll(self, agent, stop=None):
        now = time.monotonic()
        if now < self.next_probe or not self.retry.ready():
            return
        self.next_probe = now + 2
        try:
            if now < self.next_batch:
                with agent.db() as db:
                    urgent = db.execute(f'SELECT 1 FROM outbox WHERE {URGENT} LIMIT 1').fetchone()
                    if not urgent:
                        if not self.expedited and db.execute('SELECT 1 FROM outbox LIMIT 1 OFFSET 99').fetchone():
                            self.next_batch = min(self.next_batch, now + random.uniform(5, 25))
                            self.expedited = True
                        return
            result = agent.flush(max_batches=1, require_empty=False, stop=stop)
        except (OSError, ValueError, sqlite3.Error) as exc:
            state = {'state':'local_queue_error'} if isinstance(exc, sqlite3.Error) else link_state(exc)
            if not self.retry.failures:
                LOG.warning('事件補送未完成（%s）；紀錄保留本機待補送', state['state'])
            self.retry.failure(link_retry_floor(state))
            self.next_batch = now
            return
        self.retry.success()
        self.expedited = result['pending']
        delay = random.uniform(2, 8) if result['pending'] else random.uniform(NORMAL_MIN, NORMAL_MAX)
        self.next_batch = time.monotonic() + delay


def observation(event):
    """Only correlate independent envelopes when the collector identifies the operation."""
    details = event['details']
    kind = event['kind']
    source = details.get('source')
    windows_record = (source in ('windows_security', 'windows_applocker')
                      and type(details.get('record_id')) is int
                      and type(details.get('windows_event_id')) is int)
    write_burst = (source == 'windows_etw_file_io' and kind == 'file.written'
                   and details.get('aggregation') == 'completed_write_burst'
                   and all(details.get(k) is not None for k in
                           ('native_open_id', 'process_id', 'first_write_observed', 'last_write_observed')))
    upload = (source == 'browser_webrequest' and details.get('upload_id')
              and kind in ('web.upload_response', 'web.upload_failed', 'web.upload_interrupted'))
    if windows_record or write_burst or upload:
        evidence = [kind, event['severity'], event['occurred'], details]
        return 'obs:' + hashlib.sha256(canonical(evidence).encode('utf-8')).hexdigest()
    return 'id:' + event['event_id']


def queued_policy(db):
    from .policy import decode_agent_policy
    row = db.execute("SELECT value FROM state WHERE key='policy'").fetchone()
    if row:
        return decode_agent_policy(json.loads(row[0]))
    # The protected worker keeps its own machine policy in the same transaction.
    options = db.execute("SELECT value FROM state WHERE key='extended_collection_options'").fetchone()
    legacy = db.execute("SELECT value FROM state WHERE key='extended_policy'").fetchone()
    packet = {'body': json.loads(legacy[0]) if legacy else {}}
    if options:
        packet['collection_options'] = json.loads(options[0])
    return decode_agent_policy(packet)


def prepare(db, rows, device_id):
    """Reserve the first wire ID before I/O so a lost ACK or restart retries the same ID."""
    now = time.time()
    outgoing = []
    keys = {}
    local_ids = []
    excluded_ids = []
    policy_packet = None
    db.execute('BEGIN IMMEDIATE')
    for local_id, payload in rows:
        event = json.loads(payload)
        kind, details = event['kind'], event['details']
        path = (details.get('path') or details.get('source_path') or details.get('destination_path')) if isinstance(details,dict) else None
        if kind.startswith('file.') and isinstance(path,str) and tmp_file(path):
            if policy_packet is None:
                policy_packet = queued_policy(db)
            rules = policy_packet['body']['file_audit']['exclude_paths']
            if TMP_FILE_RULE in rules and excluded_activity(kind,details,(TMP_FILE_RULE,),event['severity']):
                excluded_ids.append((local_id,))
                continue
        if kind == 'application.stopped' or audit_collection.browser_kind(kind):
            if policy_packet is None:
                policy_packet = queued_policy(db)
            policy = policy_packet['body']
            if audit_collection.browser_kind(kind):
                account = audit_collection.browser_account(kind, details)
                policy = policy_packet.get('user_policies', {}).get(account, policy_packet)['body']
                event['details'] = audit_collection.browser_details(kind, details, policy)
            if event['details'] is None or audit_collection.excluded_stop(kind, event['severity'], details, policy):
                excluded_ids.append((local_id,))
                continue
        if excluded_unconfirmed_write(event['kind'], event['severity'], event['details']):
            excluded_ids.append((local_id,))
            continue
        local_ids.append((local_id,))
        identity = observation(event)
        key = canonical([device_id, identity])
        if key in keys:
            continue
        receipt = db.execute('SELECT wire_id,acknowledged FROM upload_receipts WHERE observation=?',
                             (key,)).fetchone()
        if receipt and receipt[1] is not None and now - RECEIPT_SECONDS <= receipt[1] <= now:
            keys[key] = receipt[0]
            continue
        if identity.startswith('obs:'):
            if receipt and receipt[1] is None:
                event['event_id'] = receipt[0]
            else:
                db.execute('INSERT OR REPLACE INTO upload_receipts VALUES (?,?,NULL)', (key, event['event_id']))
        keys[key] = event['event_id']
        outgoing.append(event)
    # Apply the current collection policy to older queued writes before any
    # request. Unsent exclusions should never create an upload receipt.
    if excluded_ids:
        db.executemany('DELETE FROM outbox WHERE event_id=?', excluded_ids)
        db.executemany('DELETE FROM outbox_priority WHERE event_id=?', excluded_ids)
    return outgoing, keys, local_ids


def confirm(db, keys, accepted):
    stamp = time.time()
    db.executemany('INSERT OR REPLACE INTO upload_receipts VALUES (?,?,?)',
                   ((key, eid, stamp) for key, eid in keys.items() if eid in accepted))
    db.execute('DELETE FROM upload_receipts WHERE rowid IN (SELECT rowid FROM upload_receipts '
               'WHERE acknowledged < ? ORDER BY acknowledged LIMIT 200)', (stamp - RECEIPT_SECONDS,))
    db.execute('DELETE FROM upload_receipts WHERE rowid IN (SELECT rowid FROM upload_receipts '
               'WHERE acknowledged IS NOT NULL ORDER BY acknowledged DESC LIMIT -1 OFFSET ?)', (MAX_RECEIPTS,))
