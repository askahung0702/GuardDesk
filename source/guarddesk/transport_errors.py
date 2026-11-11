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


def transient_heartbeat(error):
    return (isinstance(error, CenterTransportError) and
            (error.category == 'temporary_network' or
             (error.category == 'http' and error.http_status in (502, 503, 504))))
