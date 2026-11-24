"""Reduce proven temporary-file saves in the endpoint's durable upload queue."""
import json
import ntpath
import re
import time
from collections import defaultdict
from dataclasses import dataclass

from .document_writes import confirmed_write_process
from .file_exclusions import tmp_file
from .serialization import canonical


WINDOW = 5
# Native write bursts close after up to ten seconds. Keep the rename and
# the preceding names available while the separate collector queues its evidence.
SETTLE = 15
HOLD = SETTLE + WINDOW + 2
LIMIT = 512
SCHEMA = """
    CREATE TABLE IF NOT EXISTS document_save_pending(
        event_id TEXT PRIMARY KEY, file_ref TEXT, size INTEGER, queued REAL NOT NULL, created_path TEXT);
    CREATE INDEX IF NOT EXISTS document_save_age ON document_save_pending(queued);
    CREATE INDEX IF NOT EXISTS document_save_birth ON document_save_pending(created_path)
        WHERE created_path IS NOT NULL;
    CREATE TRIGGER IF NOT EXISTS document_save_forget AFTER DELETE ON outbox BEGIN
        DELETE FROM document_save_pending WHERE event_id=OLD.event_id;
    END;
"""


def scratch(path):
    name = ntpath.basename(path).lower()
    return (name.endswith(('.tmp', '.temp', '~')) or name.startswith('~$')
            or re.fullmatch('[a-f0-9]{8}', name) is not None)


def temp_cleanup(source, dest):
    """Recognize only a move into the same profile's local temporary directory."""
    drive, tail = ntpath.splitdrive(source)
    parts = tail.split('\\')
    if not re.fullmatch('[a-z]:', drive) or len(parts) < 4 or parts[1] != 'users':
        return False
    return (scratch(dest)
            and ntpath.dirname(dest) == drive + '\\users\\' + parts[2] + r'\appdata\local\temp')


def candidate(kind, severity, details, identity):
    if severity != 'info' or not isinstance(details, dict) or not isinstance(details.get('path'), str):
        return False
    if kind == 'file.written':
        return (details.get('source') == 'windows_etw_file_io' and confirmed_write_process(details)
                and type(details.get('written_bytes')) is int and details['written_bytes'] > 0
                and not details.get('collection_interrupted'))
    if details.get('source') != 'ReadDirectoryChangesW':
        return False
    if kind in ('file.renamed','file.moved') and not isinstance(details.get('destination_path'), str):
        return False
    if kind == 'file.moved':
        return bool((details.get('file_id') or identity and identity[0])
                    and temp_cleanup(ntpath.normcase(details['path']), ntpath.normcase(details['destination_path'])))
    return bool(identity and identity[0] and (kind in ('file.created', 'file.deleted')
                or kind == 'file.renamed' and details.get('correlation') == 'adjacent_native_rename_pair'))


def track(db, eid, identity, stamp, kind, path):
    key = ntpath.normcase(path)
    if kind == 'file.written' and not scratch(key) and not db.execute(
            'SELECT 1 FROM document_save_pending WHERE created_path=? AND queued>=? LIMIT 1',
            (key, stamp - HOLD)).fetchone():
        return
    # A released row remains an ordinary, retryable event in the original outbox.
    if db.execute('SELECT count(*) FROM document_save_pending').fetchone()[0] >= LIMIT:
        db.execute('DELETE FROM document_save_pending WHERE rowid=(SELECT min(rowid) FROM document_save_pending)')
    ref, size = identity
    db.execute('INSERT INTO document_save_pending VALUES (?,?,?,?,?)',
               (eid, str(ref) if ref else None, size, stamp, key if kind == 'file.created' else None))


@dataclass
class Row:
    event: dict
    ref: str
    size: int
    queued: float
    seq: int

    def __post_init__(self):
        self.details = self.event['details']
        self.path = ntpath.normcase(self.details['path'])
        self.dest = ntpath.normcase(self.details.get('destination_path', ''))
        self.when = self.event['occurred']
        self.kind = self.event['kind']
        self.eid = self.event['event_id']


def summarize(commit, by_path):
    def nearby(path):
        return [row for row in by_path[path] if abs(row.when - commit.when) <= WINDOW]

    stage = nearby(commit.path)
    final = nearby(commit.dest)
    # Competing renames, a reused staging name, or a second candidate writer
    # make attribution ambiguous. Send the independent evidence in those cases.
    if [r for r in stage if r.kind == 'file.renamed'] != [commit]:
        return
    if [r for r in final if r.kind == 'file.renamed' and r.dest == commit.dest] != [commit]:
        return
    if any(r.kind == 'file.deleted' for r in stage):
        return
    births = [r for r in stage if r.kind == 'file.created']
    if births and (len(births) != 1 or births[0].ref != commit.ref or births[0].seq >= commit.seq):
        return
    writes = [r for r in stage if r.kind == 'file.written']
    actors = {(r.details['process_id'], r.details.get('process_created'), r.details['process'],
               r.details.get('user')) for r in writes}
    if (len(actors) > 1 or writes and (not births or any(
            not births[0].when - 1 <= r.when <= commit.when + 1 for r in writes))):
        return

    originals = [r for r in final if r.kind == 'file.renamed' and r.path == commit.dest]
    prior_names = [r for r in final if r.kind in ('file.created', 'file.deleted') and r.seq < commit.seq]
    members = [commit, *births, *writes]
    kind = 'file.saved'
    evidence = 'temporary_file_published'
    if originals:
        if len(originals) != 1:
            return
        old = originals[0]
        if (old.ref == commit.ref or old.seq >= commit.seq or old.dest == commit.path
                or ntpath.dirname(old.dest) != ntpath.dirname(commit.dest)):
            return
        if prior_names and prior_names[-1].seq > old.seq:
            return
        backup = nearby(old.dest)
        if any(r.kind == 'file.renamed' and r is not old for r in backup):
            return
        cleanup = [r for r in backup if r.ref == old.ref and r.seq > old.seq and r.path == old.dest
                   and (r.kind == 'file.deleted' or r.kind == 'file.moved' and temp_cleanup(r.path, r.dest))]
        # For arbitrary staging names (including extensionless ones) require
        # their creation AND confirmed write; an ordinary pair of renames is meaningful.
        # With *.tmp enabled there is no standalone temp birth, write, or cleanup.
        # The two verified renames still establish which objects left and entered
        # the same visible filename. Never infer that the backup was deleted.
        filtered_swap = (old.details.get('tmp_exclusion_boundary') and commit.details.get('tmp_exclusion_boundary')
                         and tmp_file(old.dest) and tmp_file(commit.path) and not tmp_file(commit.dest))
        if not filtered_swap and (not cleanup or not ((scratch(old.dest) and scratch(commit.path)) or births and writes)):
            return
        evidence = 'same_directory_replacement'
        members.extend([old, *cleanup])
        for move in cleanup:
            if move.kind == 'file.moved':
                members.extend(r for r in nearby(move.dest) if r.path == move.dest and r.kind == 'file.created'
                               and r.ref == old.ref and r.when >= old.when)
        if prior_names and prior_names[-1].kind == 'file.created' and prior_names[-1].ref == old.ref:
            kind = 'file.created'
            members.append(prior_names[-1])
            # Only absorb a preceding empty placeholder when both notifications identify it.
            if (len(prior_names) == 3 and [r.kind for r in prior_names[:2]] == ['file.created', 'file.deleted']
                    and prior_names[0].ref == prior_names[1].ref and prior_names[0].size == prior_names[1].size == 0):
                members.extend(prior_names[:2])
    elif len(prior_names) == 1 and prior_names[0].kind == 'file.deleted':
        # Some editors finish writing a sibling file before unlinking the old
        # destination. Require a fresh staged file and two distinct file IDs.
        removed = prior_names[0]
        if (not scratch(commit.path) or not births or not writes or removed.ref == commit.ref or commit.when - removed.when > 1
                or births[0].seq >= removed.seq or max(r.when for r in writes) > removed.when):
            return
        evidence = 'same_directory_replacement'
        members.append(removed)
    elif not (scratch(commit.path) and not scratch(commit.dest) and births and writes and not prior_names):
        return

    details = {'path':commit.details['destination_path'], 'source':'ReadDirectoryChangesW',
               'evidence':evidence, 'observations':len(members)}
    if writes:
        # The process attribution belongs to the staging-file write.
        for key in ('process','process_id','process_created','process_identity_status','user'):
            if writes[0].details.get(key) is not None:
                details[key] = writes[0].details[key]
    return {**commit.event, 'kind':kind, 'details':details}, members


def settle(db, force=False):
    """Commit final payloads and IDs before transport, including on a lost-ACK retry."""
    now = time.time()
    earliest = db.execute('SELECT min(queued) FROM document_save_pending').fetchone()[0]
    if earliest is None or not force and 0 <= now - earliest < SETTLE:
        return
    db.execute('BEGIN IMMEDIATE')
    rows = [Row(json.loads(payload), ref, size, queued, seq) for payload, ref, size, queued, seq in db.execute(
        'SELECT o.payload,p.file_ref,p.size,p.queued,p.rowid FROM document_save_pending p '
        'JOIN outbox o ON o.event_id=p.event_id ORDER BY p.rowid')]
    by_path = defaultdict(list)
    for row in rows:
        by_path[row.path].append(row)
        if row.dest and row.dest != row.path:
            by_path[row.dest].append(row)
    used = set()
    for commit in rows:
        if (commit.kind != 'file.renamed' or commit.path == commit.dest
                or ntpath.dirname(commit.path) != ntpath.dirname(commit.dest)
                or not force and now - commit.queued < SETTLE):
            continue
        result = summarize(commit, by_path)
        if not result:
            continue
        event, members = result
        ids = {row.eid for row in members}
        if used.intersection(ids):
            continue
        used.update(ids)
        db.execute('UPDATE outbox SET payload=? WHERE event_id=?', (canonical(event), commit.eid))
        db.execute('DELETE FROM document_save_pending WHERE event_id=?', (commit.eid,))
        db.executemany('DELETE FROM outbox WHERE event_id=?', ((eid,) for eid in ids - {commit.eid}))
    db.executemany('DELETE FROM document_save_pending WHERE event_id=?',
                   ((r.eid,) for r in rows if force or now < r.queued or now - r.queued >= HOLD))
