"""Explicit Server bootstrap defaults; never implicit endpoint/cache defaults."""
import copy
import ntpath
import time

from .file_exclusions import FILENAME_PREFIX_RULE

ROAMING = r'C:\Users\{user}\AppData\Roaming'
SYSTEM32 = 'C:\\Windows\\System32\\'
LEGACY_APPLICATIONS = ('conhost.exe', 'docker.exe')
APPLICATIONS = (*LEGACY_APPLICATIONS, SYSTEM32)
MARKER = 'audit-default-exclusions-v1'
SYSTEM32_MARKER = 'application-system32-default-v1'

CLAUDE_TEMP = FILENAME_PREFIX_RULE + r'C:\Users\{user}\.claude.json.tmp.*'


def server_policy():
    from .remote_trial import enabled
    if enabled():
        from .remote_trial_install import policy
        return policy()
    from .policy import DEFAULT_POLICY
    body = copy.deepcopy(DEFAULT_POLICY)
    body['file_audit']['exclude_paths'] = [ROAMING, CLAUDE_TEMP]
    body['application_stop_mode'] = 'selected'
    body['browser_upload_mode'] = 'enabled'
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
    legacy_pending=not db.execute('SELECT 1 FROM control_meta WHERE key=?',(MARKER,)).fetchone()
    system32_pending=not db.execute('SELECT 1 FROM control_meta WHERE key=?',(SYSTEM32_MARKER,)).fetchone()
    if not legacy_pending and not system32_pending:return
    current = Store.policy(db)
    body = copy.deepcopy(current['body'])
    additions = {}
    skipped = []
    # Respect an explicitly cleared baseline after the original defaults were
    # installed. Scoped overrides/empty lists remain untouched by this migration.
    apps=list(LEGACY_APPLICATIONS) if legacy_pending else []
    if system32_pending and (legacy_pending or body['application_audit_exclusions']):apps.append(SYSTEM32)
    reason=MARKER if legacy_pending else SYSTEM32_MARKER
    for key, rules, defaults in (
        ('file_audit.exclude_paths', body['file_audit']['exclude_paths'], [ROAMING] if legacy_pending else []),
        ('application_audit_exclusions', body['application_audit_exclusions'], apps),
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
                         'reason': reason, 'added': additions, 'skipped_fields': skipped})
    if skipped:
        Store.event(db, 'console', 'policy.defaults_skipped', 'warning',
                    {'reason': reason, 'fields': skipped,
                     'note': 'Existing limits or scoped combinations require MIS review; custom rules preserved'})
    if legacy_pending:db.execute('INSERT INTO control_meta VALUES (?,1)',(MARKER,))
    if system32_pending:db.execute('INSERT INTO control_meta VALUES (?,1)',(SYSTEM32_MARKER,))
