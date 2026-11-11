"""Bounded FILE_ATTACHED metadata adapter for a verified connector transport.

No listener is installed or started by importing this module. The only current
caller is the isolated browser probe. A production provider and authenticated
browser lifecycle are still required before installed Agents may enable it.
This is attachment evidence, never proof of network delivery or storage.
"""
from dataclasses import dataclass
import hashlib
import itertools
import math
import ntpath
import re
import threading
import time
from collections import deque
from urllib.parse import urlsplit, urlunsplit

MAX_MESSAGE = 32768
MAX_FIELDS = 256
MAX_INBOX = 64


def _fields(data):
    """Return views, not copies of unknown/content fields; no recursion."""
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_MESSAGE:
        raise ValueError('Invalid connector message size')
    view, cursor, result = memoryview(data), 0, {}

    def integer():
        nonlocal cursor
        value = 0
        for i in range(10):
            if cursor >= len(view):
                raise ValueError('Truncated connector integer')
            byte = view[cursor]
            cursor += 1
            if i == 9 and byte > 1:
                raise ValueError('Connector integer overflow')
            value |= (byte & 127) << (i*7)
            if byte < 128:
                return value
        raise ValueError('Connector integer overflow')

    for _ in range(MAX_FIELDS):
        if cursor == len(view):
            return result
        key = integer()
        number, wire = key >> 3, key & 7
        if not 0 < number < 2**29:
            raise ValueError('Invalid connector field')
        if wire == 0:
            value = integer()
        elif wire in (1, 2, 5):
            size = integer() if wire == 2 else 8 if wire == 1 else 4
            if size > len(view)-cursor:
                raise ValueError('Truncated connector field')
            value = view[cursor:cursor+size]
            cursor += size
        else:
            raise ValueError('Unsupported connector wire type')
        result.setdefault(number, []).append((wire, value))
    if cursor != len(view):
        raise ValueError('Too many connector fields')
    return result


def _one(fields, number, wire, *, required=True):
    values = fields.get(number, [])
    if not values and not required:
        return None
    if len(values) != 1 or values[0][0] != wire:
        raise ValueError('Missing, repeated or mistyped connector field')
    return values[0][1]


def _text(fields, number, limit, *, required=True):
    raw = _one(fields, number, 2, required=required)
    if raw is None:
        return None
    if not 0 < len(raw) <= limit:
        raise ValueError('Invalid connector text length')
    text = raw.tobytes().decode('utf-8', errors='strict')
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in text):
        raise ValueError('Invalid connector text')
    return text


def _integer(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _blob(number, payload):
    return _integer(number*8+2)+_integer(len(payload))+payload


def request_envelope(message):
    """Extract only a request and safe reply; ACK/cancel never create events."""
    envelope = _fields(message)
    if 1 not in envelope:
        return None, None
    # An envelope containing multiple operation kinds is not an unambiguous request.
    if 2 in envelope or 3 in envelope:
        raise ValueError('Ambiguous connector envelope')
    payload = _one(envelope, 1, 2).tobytes()
    request = _fields(payload)
    token = _text(request, 5, 1024).encode('utf-8')
    verdict = _blob(1, _blob(1, token)+_blob(4, _blob(1, b'dlp')+b'\x10\x01'))
    return request, verdict


@dataclass(frozen=True)
class BrowserPeer:
    """OS-observed identity, supplied by transport, never by the request body.

    Current test scope is intentionally mandatory. This object is not a browser
    signature verifier and must not be presented as production attestation.
    """
    pid: int
    created_filetime: int
    session: int
    image: str
    scope: str = 'isolated_browser_probe'

    def validate(self):
        if (type(self.pid) is not int or not 4 < self.pid < 2**32
                or type(self.created_filetime) is not int or self.created_filetime <= 0
                or type(self.session) is not int or not 0 < self.session < 2**32
                or not isinstance(self.image, str) or len(self.image) > 4096
                or not re.fullmatch(r'[A-Za-z]:[\\/].+', self.image)
                or ntpath.basename(self.image).casefold() not in ('chrome.exe','msedge.exe')
                or any(ord(c) < 32 for c in self.image)
                or self.scope != 'isolated_browser_probe'):
            raise ValueError('Unverified connector transport identity')


class VerifiedBrowserPeer:
    """A live OS/Authenticode lease, not identity fields supplied in a message.

    Verifying the executable is a transport building block. A supported
    provider and pipe-token binding remain the responsibility of the source.
    """
    def __init__(self, lease):
        from .native_browser_identity import BrowserLease
        if not isinstance(lease, BrowserLease) or not lease.authenticated():
            raise ValueError('Verified browser lease required')
        self.lease = lease

    @property
    def pid(self):
        return self.lease.identity.pid

    @property
    def created_filetime(self):
        return self.lease.identity.created_filetime

    @property
    def session(self):
        return self.lease.identity.session

    @property
    def image(self):
        return self.lease.identity.image

    def validate(self):
        if not self.lease.authenticated():
            raise ValueError('Browser lease expired')


def owned_browser_peer(process_handle, pid, expected_image):
    """Inspect the retained handle of our own test browser, not a PID lookup."""
    import ctypes
    import os
    from ctypes import wintypes as w
    if os.name != 'nt':
        raise OSError('Windows owned browser handle required')
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.GetProcessId.argtypes=[w.HANDLE]
    api.GetProcessId.restype=w.DWORD
    api.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD]
    api.WaitForSingleObject.restype=w.DWORD
    api.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)]
    api.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(w.FILETIME)]*4)]
    api.ProcessIdToSessionId.argtypes=[w.DWORD,ctypes.POINTER(w.DWORD)]
    if api.GetProcessId(process_handle)!=pid or api.WaitForSingleObject(process_handle,0)!=258:
        raise OSError('Owned browser exited or handle identity differs')
    image=ctypes.create_unicode_buffer(32768)
    length=w.DWORD(len(image))
    created,exited,kernel,user=(w.FILETIME() for _ in range(4))
    session=w.DWORD()
    if not (api.QueryFullProcessImageNameW(process_handle,0,image,ctypes.byref(length))
            and api.GetProcessTimes(process_handle,*[ctypes.byref(x) for x in (created,exited,kernel,user)])
            and api.ProcessIdToSessionId(pid,ctypes.byref(session))):
        raise ctypes.WinError(ctypes.get_last_error())
    if ntpath.normcase(ntpath.normpath(image.value))!=ntpath.normcase(ntpath.normpath(expected_image)):
        raise OSError('Owned browser image differs')
    peer=BrowserPeer(pid,(created.dwHighDateTime<<32)|created.dwLowDateTime,session.value,image.value)
    peer.validate()
    return peer


def attachment_details(request, peer, *, now=None):
    if not isinstance(peer, (BrowserPeer, VerifiedBrowserPeer)):
        raise ValueError('Unverified connector peer type')
    peer.validate()
    now = time.time() if now is None else now
    if type(now) not in (int,float) or not math.isfinite(now) or now < 0:
        raise ValueError('Invalid connector observation time')
    if _one(request, 9, 0) != 2 or 13 in request or 18 in request:
        raise ValueError('Not a file attachment metadata request')
    token = _text(request, 5, 1024)
    path = _text(request, 14, 12288)
    expiry = _one(request, 15, 0)
    if not now-5 <= expiry <= now+3600:
        raise ValueError('Stale or invalid connector request deadline')
    reason = _one(request, 19, 0)
    if reason not in (1,2,3):
        raise ValueError('Unknown attachment entry point')
    action = _text(request, 16, 1024, required=False)
    count = _one(request, 17, 0, required=False)
    if count is not None and not 1 <= count <= 10000:
        raise ValueError('Invalid connector action count')
    metadata = _fields(_one(request,10,2).tobytes())
    url = _text(metadata, 1, 8192)
    # Do not retain URL path, query, fragment, userinfo, filename hints, digest,
    # email, tab title or client metadata. The source path is validated using
    # the same conservative native evidence contract as the cooperating receiver.
    if '\\' in url or url != url.strip():
        raise ValueError('Ambiguous attachment URL')
    parsed = urlsplit(url)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError('Unsupported attachment origin')
    port = parsed.port
    host = parsed.hostname.encode('idna').decode('ascii').lower()
    authority = ('['+host+']' if ':' in host else host)+((':'+str(port)) if port is not None else '')
    origin = urlunsplit((parsed.scheme,authority,'','',''))
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    from .file_handoff import handoff_details
    details, _, _ = handoff_details({'operation_id':token_hash[:32], 'occurred':now,
        'process_id':peer.pid,'thread_id':peer.pid,'file_index':0,'file_count':1,
        'effect':1,'path':path,'site_origin':origin},now=now)
    # Never invent an OLE effect/thread/file index for connector observations.
    for key in ('drop_effect','thread_id','file_index','file_count'):
        details.pop(key)
    details.update(source='chromium_content_analysis_connector', evidence='browser_file_attached',
        integration='isolated_connector_research', origin_evidence='browser_request_metadata',
        origin_role='attachment_page',
        process=peer.image, process_created_filetime=peer.created_filetime, session=peer.session,
        action={1:'file_paste',2:'drag_and_drop',3:'file_picker'}[reason],
        time_evidence='connector_received', request_token_hash=token_hash,
        request_deadline=expiry)
    if isinstance(peer, VerifiedBrowserPeer):
        details.update(integration='verified_native_connector',
                       process_identity_evidence='windows_token_authenticode_live_handle',
                       process_publisher=peer.lease.identity.publisher)
    # Action IDs may correlate several files, but no order/index is guaranteed.
    group = f'action:{action}' if action else f'token:{token_hash}'
    details['handoff_id'] = hashlib.sha256(f'{peer.pid}:{peer.created_filetime}:{group}'.encode()).hexdigest()
    if count is not None:
        details['action_file_count'] = count
    eid = 'connector-'+hashlib.sha256(f'{peer.pid}:{peer.created_filetime}:{token_hash}'.encode()).hexdigest()
    return details, now, eid


class NativeAttachmentSession:
    """Allow-only parsing on a source's authenticated IPC worker.

    No DB or HTTP here. The caller must hold the verified process lease for
    this exact connection and cancel outstanding IPC on stop/disconnect.
    This class opens no listener and changes no browser policy.
    """
    def __init__(self, lease, inbox):
        self.peer = VerifiedBrowserPeer(lease)
        self.inbox = inbox
        self.accepted = self.rejected = 0

    def receive(self, raw, reply):
        try:
            self.peer.validate()
            request, verdict = request_envelope(raw)
            if request is None:
                return False
            reply(verdict)  # Allow before metadata conversion/queue admission.
            value = attachment_details(request, self.peer)
        except (OSError, ValueError, UnicodeError):
            self.rejected += 1
            return False
        admitted = self.inbox.offer(value)
        self.accepted += bool(admitted)
        return admitted


class ConnectorInbox:
    """Try-lock admission; bounded memory with multiple IPC producers.

    itertools.count advances atomically in the pinned CPython GIL build. A
    consumer marker consumes one number too, subtracted from the difference;
    no read/modify/write loss counter is shared across producer threads.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._items = deque()
        self._loss_sequence = itertools.count()
        self._reported_marker = -1

    def offer(self, value):
        if not self._lock.acquire(blocking=False):
            # Lock contention means an explicit observable collection gap.
            next(self._loss_sequence)
            return False
        try:
            if len(self._items) >= MAX_INBOX:
                next(self._loss_sequence)
                return False
            self._items.append(value)
            return True
        finally:
            self._lock.release()

    def drain(self, queue):
        # Called by one background worker; producer never waits for this lock.
        with self._lock:
            items = list(self._items)
            self._items.clear()
            # Each producer loss and each drain marker occupies one position.
            # Subtract this marker; never reset a concurrently incremented count.
            snapshot = next(self._loss_sequence)
            loss = min(2**53-1,snapshot-self._reported_marker-1)
            self._reported_marker = snapshot
        queue.gap(loss)
        invalid = 0
        for value in items:
            try:
                queue.add_connector(value)
            except (TypeError, ValueError, KeyError):
                invalid += 1
                queue.gap(1)
        return {'received':len(items)-invalid,'lost':loss+invalid}
