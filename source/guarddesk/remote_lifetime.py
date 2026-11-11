"""Session consent has no elapsed-time cap; short authorization leases still do.

This sentinel is never a lease and must not be passed to SendInput authority.
Finite consent remains accepted for old/owned fixtures. Exact native cohorts
must match before the new no-cap contract may be used.
"""
NO_SESSION_DEADLINE = (1 << 63) - 1


def consent_tick(seconds, started):
    import math
    if seconds is None:
        return NO_SESSION_DEADLINE
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= 600:
        raise ValueError('Native consent contract')
    return started + int(seconds * 1000)
