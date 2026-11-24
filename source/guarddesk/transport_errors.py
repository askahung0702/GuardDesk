"""Sanitized transport categories; never turn an unknown error into a retry."""
import ssl


NATIVE_HEARTBEAT_RETRIES=2
NATIVE_HEARTBEAT_RESERVE_MS=250
NATIVE_HEARTBEAT_BACKOFF_SECONDS=.1
NATIVE_AUTHORITY_REASONS=frozenset(('native_binding_expired','native_consent_expired',
    'native_short_lease_expired','native_handshake_timeout','native_authority_lost'))


def native_authority_error(reason, message='Native authority expired'):
    if reason not in NATIVE_AUTHORITY_REASONS:raise ValueError('Unknown native authority reason')
    error=PermissionError(message)
    error.remote_diagnostic=reason
    return error


class CenterTransportError(ConnectionError):
    def __init__(self, category, *, http_status=None):
        self.category = category
        self.http_status = http_status
        self.remote_diagnostic = 'center_' + category
        message = (f'管理中心拒絕請求：HTTP {http_status}' if category == 'http'
                   else 'Management center transport: ' + category)
        super().__init__(message)


def network_error(reason):
    # Certificate/protocol errors take precedence over generic socket errors.
    if isinstance(reason, ssl.SSLError):
        return CenterTransportError('tls')
    if isinstance(reason, (TimeoutError, ConnectionResetError, ConnectionAbortedError)):
        return CenterTransportError('temporary_network')
    return CenterTransportError('network_unclassified')


class Backoff:
    """Bounded exponential retry gate with jitter for one center lane.

    Reconnect scheduling only: it never restarts a process, re-enrolls or
    drops queued data. Each lane (heartbeat, upload, native sync) owns one
    instance so a failing lane cannot delay another beyond its own limit.
    """
    def __init__(self, first=5, limit=60, clock=None, jitter=None):
        import random, time
        if not 0 < first <= limit: raise ValueError('Invalid backoff bounds')
        self.first, self.limit = first, limit
        self.clock = clock or time.monotonic
        self.jitter = jitter or random.random
        self.delay = first; self.at = 0; self.failures = 0

    def ready(self): return self.clock() >= self.at

    def success(self):
        self.delay = self.first; self.at = 0; self.failures = 0

    def failure(self, minimum=0):
        # Up to +50% jitter so a recovered center is not hit by every endpoint
        # in the same second; the wait never exceeds 1.5 * limit.
        wait = max(self.delay, min(minimum, 3600)) * (1 + .5 * min(max(self.jitter(), 0), 1))
        self.at = self.clock() + wait
        self.delay = min(self.delay * 2, self.limit); self.failures += 1
        return wait


LINK_SLOW_RETRY_SECONDS = 300


def link_state(error):
    """Fixed scalar reason for local diagnostics; never the exception text."""
    if isinstance(error, CenterTransportError):
        if error.category == 'http':
            status = error.http_status if type(error.http_status) is int else 0
            state = ('center_rejected_identity' if status in (401, 403) else
                     'center_busy' if status == 429 else
                     'center_unavailable' if status in (502, 503, 504) else 'center_http_error')
            return {'state': state, 'http_status': status}
        return {'state': {'tls': 'tls_failed', 'temporary_network': 'network_temporary'}.get(
            error.category, 'network_unclassified')}
    # Not a center verdict: local pipe/DB/inventory work failed before or
    # after the request, so do not report it as "center unavailable".
    if isinstance(error, TimeoutError): return {'state': 'local_timeout'}
    if isinstance(error, PermissionError): return {'state': 'local_rejected'}
    if isinstance(error, ConnectionError): return {'state': 'center_reply_invalid'}
    if isinstance(error, OSError):
        code = getattr(error, 'winerror', None)
        return {'state': 'local_error', **({'winerror': code} if type(code) is int else {})}
    return {'state': 'invalid_reply'}


def link_retry_floor(state):
    # A revoked identity or a certificate mismatch is not fixed by fast
    # retries; keep trying slowly without re-enrolling or changing the CA.
    return LINK_SLOW_RETRY_SECONDS if state.get('state') in ('center_rejected_identity', 'tls_failed') else 0


def transient_heartbeat(error):
    return (isinstance(error, CenterTransportError) and
            (error.category == 'temporary_network' or
             (error.category == 'http' and error.http_status in (502, 503, 504))))
