"""Explicit Server bootstrap defaults; never implicit endpoint/cache defaults."""
import copy
import ntpath
import time

ROAMING = r'C:\Users\{user}\AppData\Roaming'
APPLICATIONS = ('conhost.exe', 'docker.exe')
MARKER = 'audit-default-exclusions-v1'


def server_policy():
    from .remote_trial import enabled
    if enabled():
        from .remote_trial_install import policy
        return policy()
    from .policy import DEFAULT_POLICY
    body = copy.deepcopy(DEFAULT_POLICY)
    body['file_audit']['exclude_paths'] = [ROAMING]
    body['application_audit_exclusions'] = list(APPLICATIONS)
    return body


def migrate(db):
    """One transactional baseline revision, preserving explicit scoped policies.

    Called only at Server Store initialization under BEGIN IMMEDIATE. Never
    merge during policy reads, decoding, form rendering, or ordinary restarts.
    """
    from .store import Store, canonical
    from .management import validate_active_combinations, ControlPlane, bump, ManagementError
    if not db.in_transaction:
        raise RuntimeError('Default policy migration requires a write transaction')
    if db.execute('SELECT 1 FROM control_meta WHERE key=?', (MARKER,)).fetchone():
        return
    current = Store.policy(db)
    body = copy.deepcopy(current['body'])
    additions = {}
    skipped = []
    for key, rules, defaults in (
        ('file_audit.exclude_paths', body['file_audit']['exclude_paths'], [ROAMING]),
        ('application_audit_exclusions', body['application_audit_exclusions'], APPLICATIONS),
    ):
        known = {ntpath.normcase(ntpath.normpath(p)) for p in rules}
        missing = [p for p in defaults if ntpath.normcase(ntpath.normpath(p)) not in known]
        if len(rules) + len(missing) > 100:
            skipped.append(key)
        elif missing:
            rules.extend(missing)
            additions[key] = missing
    if additions:
        db.execute('SAVEPOINT audit_default_exclusions')
        try:
            version = current['version'] + 1
            db.execute('INSERT INTO policies VALUES (?,?,?,?)',
                       (version, canonical(body), time.time(), 'system-audit-defaults'))
            validate_active_combinations(db)
            # Include empty groups: future endpoints must not inherit an
            # overflowing append just because no machine exists there yet.
            plane = ControlPlane(db)
            for group_id in (None, *plane.groups):
                plane.resolve({'id': '', 'group_id': group_id})
            bump(db)
        except (ValueError, ManagementError):
            # A scoped append can exceed limits after a baseline grows. Preserve
            # the complete old policy graph instead of truncating custom rules.
            db.execute('ROLLBACK TO audit_default_exclusions')
            skipped = sorted(set(skipped) | set(additions))
            additions = {}
        finally:
            db.execute('RELEASE audit_default_exclusions')
        if additions:
            Store.event(db, 'console', 'policy.published', 'warning',
                        {'actor': 'system-audit-defaults', 'version': version,
                         'reason': MARKER, 'added': additions, 'skipped_fields': skipped})
    if skipped:
        Store.event(db, 'console', 'policy.defaults_skipped', 'warning',
                    {'reason': MARKER, 'fields': skipped,
                     'note': 'Existing limits or scoped combinations require MIS review; custom rules preserved'})
    db.execute('INSERT INTO control_meta VALUES (?,1)', (MARKER,))
