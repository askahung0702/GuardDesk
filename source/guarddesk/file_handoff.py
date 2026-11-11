"""Native receiver evidence and bounded background admission.

The cooperating-receiver prototype is NOT a Chrome/Edge integration. No
extension/native-message or network input can call this through a new API.
Research callers opt in explicitly. A separate verified-connector queue is
owned by the Agent runtime; no deployable browser source is available yet.
Paths are evidence only: never open a reported file or invent a request URL.
"""
import ctypes
import hashlib
import json
import math
import ntpath
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit, urlunsplit
import uuid

KIND = 'file.web_handoff'
MAX_PENDING = 4096
MAX_BUFFER = 256
MAX_BATCH = 64
FILETIME_EPOCH = 11644473600
FIELDS = frozenset(('operation_id', 'occurred', 'process_id', 'thread_id',
                    'file_index', 'file_count', 'effect', 'path', 'site_origin'))


def handoff_details(record, *, now=None):
    if not isinstance(record, dict) or set(record) != FIELDS:
        raise ValueError('Invalid native handoff metadata')
    now = time.time() if now is None else now
    operation = record['operation_id']
    if not isinstance(operation, str) or not re.fullmatch('[0-9a-f]{32}', operation):
        raise ValueError('Invalid handoff operation identity')
    occurred = record['occurred']
    if type(occurred) not in (int, float) or not math.isfinite(occurred) or not 0 <= occurred <= now + 300:
        raise ValueError('Invalid handoff timestamp')
    for field in ('process_id', 'thread_id'):
        if type(record[field]) is not int or not 4 < record[field] < 2**32:
            raise ValueError('Invalid native receiver identity')
    count, index, effect = (record[k] for k in ('file_count', 'file_index', 'effect'))
    if type(count) is not int or not 1 <= count <= 32 or type(index) is not int or not 0 <= index < count:
        raise ValueError('Invalid handoff file index')
    if type(effect) is not int or not 1 <= effect <= 7:
        raise ValueError('Drop was not accepted')
    path = record['path']
    if not isinstance(path, str) or not 1 <= len(path) < 4096 or any(ord(c) < 32 for c in path):
        raise ValueError('Invalid native handoff path')
    drive, tail = ntpath.splitdrive(path)
    if (not re.fullmatch('[A-Za-z]:', drive) or not tail.startswith(('\\', '/'))
            or any(c in tail for c in ':*?<>"|')
            or any(p in ('.', '..', 'fakepath') for p in tail.replace('/', '\\').casefold().split('\\'))
            or not ntpath.basename(path)):
        raise ValueError('Unsupported or ambiguous handoff path')
    origin = record['site_origin']
    if not isinstance(origin, str) or not 1 <= len(origin) < 512 or any(ord(c) <= 32 for c in origin) or '\\' in origin:
        raise ValueError('Invalid receiver origin')
    try:
        parsed = urlsplit(origin)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
            raise ValueError('Invalid receiver origin')
        # Accessing port also validates range and malformed IPv6 syntax.
        port = parsed.port
        host = parsed.hostname.encode('idna').decode('ascii').lower()
        if not re.fullmatch(r'[a-z0-9.:-]+', host):
            raise ValueError('Invalid receiver host')
        authority = ('[' + host + ']' if ':' in host else host) + (':' + str(port) if port is not None else '')
        origin = urlunsplit((parsed.scheme, authority, '', '', ''))
    except (UnicodeError, ValueError):
        raise ValueError('Invalid receiver origin') from None
    details = {'handoff_id': operation, 'source': 'windows_ole_cooperating_receiver',
               'evidence': 'receiver_accepted_drop', 'integration': 'cooperating_receiver_prototype',
               'origin_evidence': 'receiver_callback_not_browser_attested',
               'source_path': path, 'file_name': ntpath.basename(path), 'site_origin': origin,
               'process_id': record['process_id'], 'thread_id': record['thread_id'],
               'file_index': index, 'file_count': count, 'drop_effect': effect,
               'action': 'drag_and_drop', 'user': None,
               'human_read_confirmed': False, 'network_transfer': 'not_observed',
               'application_success': 'unknown'}
    if len(json.dumps(details, ensure_ascii=False).encode('utf-8')) > 15000:
        raise ValueError('Handoff metadata exceeds event budget')
    identity = hashlib.sha256(f"ole-v1:{record['process_id']}:{operation}:{index}".encode()).hexdigest()
    return details, occurred, 'handoff-' + identity


class HandoffQueue:
    """Background-only, transactionally bounded queue with separate source modes.

    Replays have stable IDs across restarts; distinct drops of the same file do
    not share an ID. Overflow never evicts unrelated events. SQLite failures
    retain the in-memory batch until retry, without acknowledging it.
    """
    def __init__(self, agent, *, experimental=False, verified_connector=False):
        if (type(experimental) is not bool or type(verified_connector) is not bool
                or (experimental and verified_connector) or not (experimental or verified_connector)):
            raise ValueError('Native browser integration is not available; prototype opt-in required')
        self.verified_connector = verified_connector
        self.agent = agent
        self.buffer = []
        self.loss = 0
        self.report = {'status': 'queue_ready' if verified_connector else 'experimental_receiver_only', 'browser_connected': False}
        self.next_check = 0
        with self.agent.db() as db:
            row = db.execute("SELECT value FROM state WHERE key='file_handoff_loss_v1'").fetchone()
        self.unreported = bool(row and int(row[0]))

    def add(self, record):
        if self.verified_connector:
            raise ValueError('Cooperating receiver is not a verified browser source')
        value = handoff_details(record)
        return self._admit(value)

    def add_connector(self, value):
        # Internal metadata adapter only. No network/API endpoint accepts this
        # tuple. Research and verified sources cannot mix queue modes.
        if not isinstance(value, tuple) or len(value) != 3:
            raise ValueError('Invalid connector admission')
        details, occurred, eid = value
        integration = 'verified_native_connector' if self.verified_connector else 'isolated_connector_research'
        if (not isinstance(details, dict) or details.get('integration') != integration
                or not isinstance(eid, str) or not re.fullmatch('connector-[0-9a-f]{64}', eid)
                or type(occurred) not in (int, float) or not math.isfinite(occurred) or occurred < 0):
            raise ValueError('Unverified connector admission')
        return self._admit(value)

    def _admit(self, value):
        if len(self.buffer) >= MAX_BUFFER:
            self.gap(1)
            return False
        self.buffer.append(value)
        return True

    def gap(self, count):
        if type(count) is not int or not 0 <= count <= 2**53 - 1:
            raise ValueError('Invalid handoff loss count')
        self.loss = min(2**53 - 1, self.loss + count)

    def drain_native(self, trace):
        """One malformed record must not discard valid peers in a polled batch."""
        records, losses = trace.poll()
        self.gap(losses)
        admitted = invalid = 0
        for record in records:
            try:
                admitted += bool(self.add(record))
            except ValueError:
                invalid += 1
                self.gap(1)
        return {'admitted': admitted, 'invalid': invalid, 'native_loss': losses}

    def flush(self):
        if not self.buffer and not self.loss and (not self.unreported or time.monotonic() < self.next_check):
            return self.report
        policy = self.agent.cached_policy()['body']
        from .decommission import saved
        enabled = policy['browser_audit'] and policy['file_audit']['enabled'] and not saved(self.agent)
        batch = self.buffer[:MAX_BATCH]
        loss = self.loss
        from .document_scope import permits
        eligible = [value for value in batch if enabled and permits(value[0]['source_path'], policy['file_audit'],
                    self.agent.config.get('audit_watch', str(self.agent.root)), self.agent.audit_runtime)]
        with self.agent.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS file_handoff_outbox(event_id TEXT PRIMARY KEY)')
            db.execute('DELETE FROM file_handoff_outbox WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE outbox.event_id=file_handoff_outbox.event_id)')
            pending = db.execute('SELECT count(*) FROM file_handoff_outbox').fetchone()[0]
            row = db.execute("SELECT value FROM state WHERE key='file_handoff_loss_v1'").fetchone()
            total_loss = min(2**53 - 1, (int(row[0]) if row else 0) + loss)
            if total_loss and pending < MAX_PENDING:
                eid = self.agent.queue('agent.audit_gap', {'source': 'native_file_handoff',
                    'reason': 'bounded_handoff_collection', 'lost_records': total_loss,
                    'integration': 'verified_native_connector' if self.verified_connector else 'experimental_native_handoff'}, 'warning', db=db)
                db.execute('INSERT INTO file_handoff_outbox VALUES (?)', (eid,))
                pending += 1
                total_loss = 0
            for details, occurred, eid in eligible:
                if db.execute('SELECT 1 FROM outbox WHERE event_id=?', (eid,)).fetchone():
                    continue
                if pending >= MAX_PENDING:
                    total_loss = min(2**53 - 1, total_loss + 1)
                    continue
                queued = self.agent.queue(KIND, details, db=db, occurred=occurred, event_id=eid)
                if queued:
                    db.execute('INSERT INTO file_handoff_outbox VALUES (?)', (queued,))
                    pending += 1
            db.execute("INSERT OR REPLACE INTO state VALUES ('file_handoff_loss_v1',?)", (str(total_loss),))
        del self.buffer[:len(batch)]
        self.loss -= loss
        self.unreported = bool(total_loss)
        self.next_check = time.monotonic() + 5
        self.report = {'status': 'queue_ready' if self.verified_connector else 'experimental_receiver_only', 'browser_connected': False,
                       'pending': pending, 'pending_limit': MAX_PENDING, 'unreported_loss': total_loss,
                       'policy_filtered': len(batch) - len(eligible)}
        return self.report


class NativeHandoff:
    """Process-local polling. The DLL must already be loaded by its receiver.

    Loading this into the Agent cannot observe another process's drop queue.
    No automatic registration/injection or deployment is performed here.
    """
    class Record(ctypes.Structure):
        _fields_ = [('abi', ctypes.c_uint32), ('size', ctypes.c_uint32),
                    ('operation', ctypes.c_ubyte * 16), ('occurred', ctypes.c_uint64),
                    ('process_id', ctypes.c_uint32), ('thread_id', ctypes.c_uint32),
                    ('file_index', ctypes.c_uint32), ('file_count', ctypes.c_uint32),
                    ('effect', ctypes.c_uint32), ('path', ctypes.c_wchar * 4096),
                    ('origin', ctypes.c_wchar * 512)]

    def __init__(self, directory, *, experimental=False):
        if experimental is not True or os.name != 'nt':
            raise OSError('Explicit Windows cooperating-receiver prototype required')
        directory = Path(directory).resolve()
        metadata = json.loads((directory/'build.json').read_text(encoding='utf-8'))
        item = next(p for p in metadata['products'] if p['dll'] == 'GuardDeskFileHandoff.dll')
        dll = directory / item['dll']
        if hashlib.sha256(dll.read_bytes()).hexdigest() != item['dll_sha256']:
            raise OSError('Native handoff binary integrity mismatch')
        self.api = ctypes.WinDLL(str(dll), winmode=0x1100)
        self.api.gd_handoff_abi.restype = ctypes.c_uint32
        self.api.gd_handoff_record_size.restype = ctypes.c_uint32
        if self.api.gd_handoff_abi() != 1 or self.api.gd_handoff_record_size() != ctypes.sizeof(self.Record):
            raise OSError('Native handoff ABI mismatch')
        self.api.gd_handoff_poll.argtypes = [ctypes.POINTER(self.Record), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64)]
        self.api.gd_handoff_poll.restype = ctypes.c_uint32
        self.records = (self.Record * MAX_BATCH)()
        self.last_loss = 0

    def poll(self):
        losses = ctypes.c_uint64()
        count = self.api.gd_handoff_poll(self.records, MAX_BATCH, ctypes.byref(losses))
        if count > MAX_BATCH:
            raise OSError('Invalid native handoff batch')
        delta = max(0, losses.value - self.last_loss)
        self.last_loss = losses.value
        result = []
        for r in self.records[:count]:
            if r.abi != 1 or r.size != ctypes.sizeof(self.Record):
                raise OSError('Native handoff record ABI mismatch')
            result.append({'operation_id': uuid.UUID(bytes_le=bytes(r.operation)).hex,
                           'occurred': r.occurred / 10000000 - FILETIME_EPOCH,
                           'process_id': r.process_id, 'thread_id': r.thread_id,
                           'file_index': r.file_index, 'file_count': r.file_count, 'effect': r.effect,
                           'path': r.path, 'site_origin': r.origin})
        return result, delta
