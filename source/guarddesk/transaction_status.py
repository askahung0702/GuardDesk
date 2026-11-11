"""Small handoff state, with streaming compatibility for legacy journals.

These files inherit the protected update directory's ACL. The checksum detects
corruption, not an attacker who can write that directory. Recovery journals stay
unchanged so an older broker can still recover/roll back the same transaction.
"""
from collections import OrderedDict
import hashlib
import json
import re
import stat
import threading
import time
from . import update_packages as packages
from .serialization import canonical

JOURNALS = frozenset(('transaction-native.json', 'updater-refresh.json'))
CONTROL_LIMIT = 4096
SCAN_SECONDS = 2
_cache = OrderedDict()
_lock = threading.Lock()
_special = re.compile(r'["\\\x00-\x1f]')
_space = re.compile(r'[ \t\r\n]*')
_number = re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z')


class JournalStateError(OSError):
    def __init__(self, code):
        self.code = code
        super().__init__('更新交易狀態：' + code)


def control_path(path):
    if path.name not in JOURNALS: raise ValueError('Not a handoff journal')
    return path.with_name(path.name + '.state.json')


def fingerprint(path):
    path = packages.plain(path)
    try: info = path.stat()
    except FileNotFoundError: return None
    if not stat.S_ISREG(info.st_mode): raise JournalStateError('journal_not_file')
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _phase(value):
    if not isinstance(value, str) or not re.fullmatch('[a-z_]{1,64}', value):
        raise JournalStateError('journal_invalid_phase')
    return value


def _unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate control key')
        result[key]=value
    return result


def _control(path, phase, source, state):
    value = dict(format=1, journal=path.name, state=state, phase=_phase(phase), source=source)
    value['checksum'] = hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()
    return value


def publish(path, body, atomic):
    """Called only by the owning transaction writer/recovery, never by readers."""
    if path.name not in JOURNALS: return
    control=packages.plain(control_path(path))
    value=_control(path, body.get('phase'), fingerprint(path), 'ready')
    # Recovery runs periodically, including for terminal transactions. Do not
    # rewrite an unchanged summary or create permanent background audit churn.
    try:
        with control.open('rb') as stream: current=stream.read(CONTROL_LIMIT+1)
    except FileNotFoundError:current=None
    if current==canonical(value).encode('utf-8'):return
    atomic(control,value)


def write(path, body, atomic):
    # An interrupted write cannot leave an older terminal summary authorizing a
    # new switch. Publish intent first, then the backward-compatible full record.
    phase = _phase(body.get('phase'))
    atomic(control_path(path), _control(path, phase, fingerprint(path), 'writing'))
    atomic(path, body)
    publish(path, body, atomic)


class _LegacyPhase:
    """Validate JSON while keeping only the root phase and a 64 KiB chunk.

    No manifest strings, lists or dictionaries are materialized. Bounded depth,
    token length and elapsed work protect the legacy compatibility path. A stable
    result (including a budget failure) is cached, avoiding repeated large scans.
    """
    def __init__(self, stream):
        self.stream = stream; self.buf = ''; self.pos = 0
        self.deadline = time.monotonic() + SCAN_SECONDS

    def check(self):
        if time.monotonic() > self.deadline: raise JournalStateError('journal_scan_budget')

    def peek(self):
        if self.pos == len(self.buf):
            self.check(); self.buf = self.stream.read(65536); self.pos = 0
        return self.buf[self.pos:self.pos + 1]

    def take(self, expected):
        if self.peek() != expected: raise JournalStateError('journal_invalid_json')
        self.pos += 1

    def space(self):
        while self.peek():
            end = _space.match(self.buf, self.pos).end()
            if end == self.pos: break
            self.pos = end

    def string(self, capture=False):
        self.take('"'); result = [] if capture else None; size = 0
        while self.peek():
            match = _special.search(self.buf, self.pos)
            end = match.start() if match else len(self.buf)
            if capture:
                size += end - self.pos
                if size > 256: raise JournalStateError('journal_token_limit')
                result.append(self.buf[self.pos:end])
            self.pos = end
            if match is None: continue
            if not self.peek(): break
            c = self.buf[self.pos]; self.pos += 1
            if c == '"': return json.loads('"' + ''.join(result) + '"') if capture else None
            if c != '\\': raise JournalStateError('journal_invalid_json')
            c = self.peek()
            if not c or c not in '"\\/bfnrtu': raise JournalStateError('journal_invalid_json')
            self.pos += 1; escape = '\\' + c
            if c == 'u':
                for _ in range(4):
                    c = self.peek()
                    if not c or c not in '0123456789abcdefABCDEF': raise JournalStateError('journal_invalid_json')
                    self.pos += 1; escape += c
            if capture:
                size += len(escape)
                if size > 256: raise JournalStateError('journal_token_limit')
                result.append(escape)
        raise JournalStateError('journal_invalid_json')

    def value(self, depth=0):
        self.check(); self.space()
        if depth > 64: raise JournalStateError('journal_depth_limit')
        c = self.peek()
        if c == '"': self.string(); return
        if c in ('{', '['):
            close = '}' if c == '{' else ']'; self.pos += 1; self.space()
            if self.peek() == close: self.pos += 1; return
            while True:
                if c == '{': self.string(); self.space(); self.take(':')
                self.value(depth + 1); self.space()
                if self.peek() == close: self.pos += 1; return
                self.take(','); self.space()
        if c in ('t', 'f', 'n'):
            for letter in {'t':'true', 'f':'false', 'n':'null'}[c]: self.take(letter)
            return
        token = ''
        while self.peek() and self.peek() in '-+0123456789.eE':
            token += self.peek(); self.pos += 1
            if len(token) > 128: raise JournalStateError('journal_token_limit')
        if not _number.fullmatch(token): raise JournalStateError('journal_invalid_json')

    def phase(self):
        self.space(); self.take('{'); self.space(); found = None; keys = set()
        if self.peek() != '}':
            while True:
                key = self.string(True)
                if key in keys or len(keys) >= 128: raise JournalStateError('journal_duplicate_or_excess_keys')
                keys.add(key); self.space(); self.take(':'); self.space()
                if key == 'phase': found = _phase(self.string(True))
                else: self.value()
                self.space()
                if self.peek() == '}': break
                self.take(','); self.space()
        self.take('}'); self.space()
        if self.peek() or found is None: raise JournalStateError('journal_invalid_json')
        return found


def read_phase(path):
    path = packages.plain(path); control = packages.plain(control_path(path))
    before = fingerprint(path); summary_before = fingerprint(control)
    if before is None and summary_before is None: return None
    if summary_before is not None:
        with control.open('rb') as stream: raw = stream.read(CONTROL_LIMIT + 1)
        try:
            if len(raw) > CONTROL_LIMIT: raise ValueError()
            value = json.loads(raw.decode('utf-8'),object_pairs_hook=_unique)
            if not isinstance(value, dict) or set(value) != {'format','journal','state','phase','source','checksum'}: raise ValueError()
            checksum = value.pop('checksum')
            if value['format'] != 1 or type(value['format']) is not int or value['journal'] != path.name or value['state'] not in ('writing','ready'): raise ValueError()
            if checksum != hashlib.sha256(canonical(value).encode('utf-8')).hexdigest(): raise ValueError()
            phase = _phase(value['phase'])
            source = value['source']
            if source is not None and (not isinstance(source,list) or len(source)!=5 or any(type(n) is not int or n<0 for n in source)): raise ValueError()
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise JournalStateError('journal_control_invalid') from None
        if source == before:
            if value['state'] == 'writing': raise JournalStateError('journal_writing')
            if before is None: raise JournalStateError('journal_missing')
            if fingerprint(path) != before or fingerprint(control) != summary_before: raise JournalStateError('journal_changed')
            return phase
        # An older writer atomically replaced the journal without knowing about
        # the summary. Ignore its stale terminal phase and validate the real file.
    if before is None: raise JournalStateError('journal_missing')
    key = (str(path), tuple(before), tuple(summary_before or ()))
    with _lock:
        cached = _cache.get(key)
        if cached and cached[0] > time.monotonic():
            _cache.move_to_end(key)
            if cached[2]: raise JournalStateError(cached[1])
            return cached[1]
    error = None
    try:
        with path.open('r', encoding='utf-8-sig', newline='') as stream: phase = _LegacyPhase(stream).phase()
    except (ValueError, UnicodeError): error = 'journal_invalid_json'
    except JournalStateError as exc: error = exc.code
    if fingerprint(path) != before or fingerprint(control) != summary_before: raise JournalStateError('journal_changed')
    with _lock:
        _cache[key] = (time.monotonic() + (30 if error else 300), error or phase, bool(error))
        _cache.move_to_end(key)
        while len(_cache) > 16: _cache.popitem(last=False)
    if error: raise JournalStateError(error)
    return phase
