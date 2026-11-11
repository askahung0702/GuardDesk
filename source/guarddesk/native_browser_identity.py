"""Read-only Windows identity checks for future native browser transports.

These checks attest the on-disk signed image, token and process lifetime, not
browser contents or an attachment. No process is injected, launched or changed.
Call on a collector worker, never on a browser UI/IPC acknowledgement thread.
Only machine-wide browser installs are admitted; per-user writable installs
remain unsupported. No production provider is selected by this module.
"""
from contextlib import contextmanager
import ctypes
from ctypes import wintypes as w
from dataclasses import dataclass
import ntpath
import os
from pathlib import Path
import re
import uuid

_LEASE_PROOF = object()

class IdentityError(OSError):
    def __init__(self, code, *, native_code=None):
        self.code, self.native_code = code, native_code
        # Do not embed user paths, SIDs, certificates or request bodies in logs.
        super().__init__(code)


def _windows():
    if os.name != 'nt':
        raise IdentityError('windows_required')
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    api.OpenProcess.restype = w.HANDLE
    api.CloseHandle.argtypes = [w.HANDLE]
    api.GetProcessId.argtypes = [w.HANDLE]
    api.GetProcessId.restype = w.DWORD
    api.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    api.WaitForSingleObject.restype = w.DWORD
    api.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)]
    api.GetProcessTimes.argtypes = [w.HANDLE, *([ctypes.POINTER(w.FILETIME)] * 4)]
    api.ProcessIdToSessionId.argtypes = [w.DWORD, ctypes.POINTER(w.DWORD)]
    return api


def _process_sid(handle):
    from .document_context import token_sid
    adv = ctypes.WinDLL('advapi32', use_last_error=True)
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    token = w.HANDLE()
    if not adv.OpenProcessToken(handle, 8, ctypes.byref(token)):
        raise IdentityError('token_unreadable', native_code=ctypes.get_last_error())
    try:
        return token_sid(token)
    finally:
        _windows().CloseHandle(token)


def _snapshot(api, handle):
    if api.WaitForSingleObject(handle, 0) != 258:
        raise IdentityError('browser_exited')
    pid = api.GetProcessId(handle)
    image = ctypes.create_unicode_buffer(32768)
    size, session = w.DWORD(len(image)), w.DWORD()
    times = [w.FILETIME() for _ in range(4)]
    if not (pid and api.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size))
            and api.GetProcessTimes(handle, *[ctypes.byref(t) for t in times])
            and api.ProcessIdToSessionId(pid, ctypes.byref(session))):
        raise IdentityError('process_unreadable', native_code=ctypes.get_last_error())
    created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    return pid, created, session.value, image.value


def machine_browser_paths():
    """Known-folder APIs, not PATH, registry commands or user environment."""
    _windows()
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.SHGetFolderPathW.argtypes = [w.HWND, ctypes.c_int, w.HANDLE, w.DWORD, w.LPWSTR]
    shell.SHGetFolderPathW.restype = w.LONG
    paths = {}
    for csidl in (38, 42):  # Program Files, Program Files (x86)
        buffer = ctypes.create_unicode_buffer(32768)
        if shell.SHGetFolderPathW(None, csidl, None, 0, buffer) != 0:
            raise IdentityError('known_folder_unavailable')
        for relative, vendor in ((r'Google\Chrome\Application\chrome.exe', 'Google LLC'),
                                 (r'Microsoft\Edge\Application\msedge.exe', 'Microsoft Corporation')):
            paths[ntpath.normcase(str(Path(buffer.value) / relative))] = vendor
    return paths


def protected_browser_image(path):
    from .source_permissions import WindowsSecurity, validate_descriptor, SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER
    from .update_packages import plain
    candidate = plain(path)
    security = WindowsSecurity()
    trusted = {SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER}
    if len(candidate.parents) > 16:
        raise IdentityError('image_path_too_deep')
    try:
        for entry in (candidate, *candidate.parents):
            validate_descriptor(entry, *security.descriptor(entry), trusted, ancestor=entry != candidate)
    except OSError:
        raise IdentityError('image_permissions_untrusted') from None


def signed_publisher(path):
    """Authenticode + cached chain revocation, no UI or network retrieval.

    WinVerifyTrust must return exactly zero. Missing cached revocation data is
    an explicit failure, never a fallback to unchecked signature text.
    Uses provider state to read the certificate of the verified primary signer.
    """
    _windows()
    trust = ctypes.WinDLL('wintrust', use_last_error=True)
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    class Guid(ctypes.Structure):
        _fields_ = [('value', ctypes.c_ubyte * 16)]
    class File(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('path', w.LPCWSTR), ('handle', w.HANDLE), ('subject', w.LPVOID)]
    class Data(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('callback', w.LPVOID), ('client', w.LPVOID),
                    ('ui', w.DWORD), ('revocation', w.DWORD), ('choice', w.DWORD),
                    ('file', ctypes.POINTER(File)), ('action', w.DWORD), ('state', w.HANDLE),
                    ('url', w.LPWSTR), ('flags', w.DWORD), ('context', w.DWORD), ('settings', w.LPVOID)]
    class CertPrefix(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('certificate', w.LPVOID)]
    trust.WinVerifyTrust.argtypes = [w.HWND, ctypes.POINTER(Guid), ctypes.POINTER(Data)]
    trust.WinVerifyTrust.restype = w.LONG
    trust.WTHelperProvDataFromStateData.argtypes = [w.HANDLE]
    trust.WTHelperProvDataFromStateData.restype = w.LPVOID
    trust.WTHelperGetProvSignerFromChain.argtypes = [w.LPVOID, w.DWORD, w.BOOL, w.DWORD]
    trust.WTHelperGetProvSignerFromChain.restype = w.LPVOID
    trust.WTHelperGetProvCertFromChain.argtypes = [w.LPVOID, w.DWORD]
    trust.WTHelperGetProvCertFromChain.restype = ctypes.POINTER(CertPrefix)
    crypt.CertGetNameStringW.argtypes = [w.LPVOID, w.DWORD, w.DWORD, w.LPVOID, w.LPWSTR, w.DWORD]
    crypt.CertGetNameStringW.restype = w.DWORD
    action = Guid((ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID('00aac56b-cd44-11d0-8cc2-00c04fc295ee').bytes_le))
    file = File(ctypes.sizeof(File), str(path), None, None)
    data = Data()
    data.size, data.ui, data.choice, data.action = ctypes.sizeof(Data), 2, 1, 1
    data.file = ctypes.pointer(file)
    data.flags = 0x1000 | 0x80  # CACHE_ONLY_URL_RETRIEVAL, CHAIN_EXCLUDE_ROOT
    try:
        result = trust.WinVerifyTrust(w.HWND(-1), ctypes.byref(action), ctypes.byref(data))
        if result != 0:
            raise IdentityError('signature_not_trusted', native_code=result & 0xffffffff)
        provider = trust.WTHelperProvDataFromStateData(data.state)
        signer = trust.WTHelperGetProvSignerFromChain(provider, 0, False, 0) if provider else None
        certificate = trust.WTHelperGetProvCertFromChain(signer, 0) if signer else None
        if not certificate or certificate.contents.size < ctypes.sizeof(CertPrefix) or not certificate.contents.certificate:
            raise IdentityError('signer_unavailable')
        text = ctypes.create_unicode_buffer(256)
        oid = ctypes.create_string_buffer(b'2.5.4.10')  # organizationName, not display text
        length = crypt.CertGetNameStringW(certificate.contents.certificate, 3, 0, oid, text, len(text))
        if not 1 < length < len(text):
            raise IdentityError('signer_unavailable')
        return text.value
    finally:
        data.action = 2
        trust.WinVerifyTrust(w.HWND(-1), ctypes.byref(action), ctypes.byref(data))


@dataclass(frozen=True)
class BrowserIdentity:
    pid: int
    created_filetime: int
    session: int
    image: str
    publisher: str


class BrowserLease:
    """Retains the actual process handle; closed on disconnect/session exit."""
    def __init__(self, api, handle, identity, sid, *, _proof=None):
        self.api, self.handle, self.identity, self.sid = api, handle, identity, sid
        self._proof = _proof

    def authenticated(self):
        return self._proof is _LEASE_PROOF and self.alive()

    def alive(self):
        if not self.handle:
            return False
        try:
            p, c, s, image = _snapshot(self.api, self.handle)
            return (p, c, s, ntpath.normcase(image)) == (
                self.identity.pid, self.identity.created_filetime, self.identity.session, ntpath.normcase(self.identity.image))
        except OSError:
            return False

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


@contextmanager
def verify_browser(pid, *, session, sid):
    """Caller supplies expected authenticated session/SID, never request fields.

    The transport must obtain pid from GetNamedPipeClientProcessId, and bind
    its impersonated pipe token to sid. This alone does not authenticate an
    arbitrary message channel or establish a supported browser provider.
    """
    if type(pid) is not int or not 4 < pid < 2**32 or type(session) is not int or session <= 0:
        raise IdentityError('invalid_process_scope')
    if not isinstance(sid, str) or not re.fullmatch(r'S-1-(?:\d+-)*\d+', sid):
        raise IdentityError('invalid_user_scope')
    api = _windows()
    handle = api.OpenProcess(0x1000 | 0x100000, False, pid)
    if not handle:
        raise IdentityError('process_unreadable', native_code=ctypes.get_last_error())
    lease = None
    try:
        actual_pid, created, actual_session, image = _snapshot(api, handle)
        if actual_pid != pid or actual_session != session or _process_sid(handle) != sid:
            raise IdentityError('process_scope_mismatch')
        vendor = machine_browser_paths().get(ntpath.normcase(image))
        if not vendor:
            raise IdentityError('image_not_supported')
        protected_browser_image(image)
        if signed_publisher(image) != vendor:
            raise IdentityError('publisher_mismatch')
        identity = BrowserIdentity(pid, created, session, image, vendor)
        lease = BrowserLease(api, handle, identity, sid, _proof=_LEASE_PROOF)
        if not lease.alive():
            raise IdentityError('process_identity_changed')
        yield lease
    finally:
        if lease:
            lease.close()
        else:
            api.CloseHandle(handle)
