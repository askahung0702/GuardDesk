"""Keep the five newest verified release payloads available for new jobs."""
import re
import stat
import threading
import time
from collections import OrderedDict

from . import release_scope, update_packages as packages
from .store import Store

KEEP = 5
_checks = OrderedDict()
_checks_lock = threading.Lock()


def published(db):
    rows = db.execute('SELECT r.id,r.version,r.created,r.actor FROM update_releases r '
                      'LEFT JOIN update_retired_packages p ON p.release_id=r.id WHERE p.release_id IS NULL')
    releases = [dict(row) for row in rows]
    return sorted(releases, key=lambda row: packages.version(row['version']), reverse=True)


def count(db):
    return db.execute('SELECT count(*) FROM update_releases r WHERE NOT EXISTS '
                      '(SELECT 1 FROM update_retired_packages p WHERE p.release_id=r.id)').fetchone()[0]


def available(db, store=None, releases=None):
    if releases is None:
        releases = published(db)
    result = []
    for row in releases:
        deployment = release_scope.stored(db, row['id'], row['version'])
        if deployment['scope'] != 'endpoint':
            continue
        if store is not None:
            path = packages.plain(store.path.resolve().parent/'update-packages'/(row['id']+'.zip'))
            size=db.execute("SELECT json_extract(envelope,'$.payload.bytes') FROM update_releases WHERE id=?", (row['id'],)).fetchone()[0]
            try:
                info=path.stat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_size!=size:
                continue
            with _checks_lock:
                if _checks.get((path,row['id'],fingerprint(info))) is False:continue
        result.append({**row, 'deployment':deployment})
        if len(result) == KEEP:
            break
    return result


def fingerprint(info):
    return info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns


def intact(path, release_id, identity):
    key=(path,release_id,identity)
    with _checks_lock:
        if key in _checks:return _checks[key]
    valid=packages.file_hash(path)==release_id
    if fingerprint(packages.plain(path).stat())!=identity:return False
    with _checks_lock:
        _checks[key]=valid
        if len(_checks)>32:_checks.popitem(last=False)
    return valid


def cleanup(store):
    from .updates import repository
    now = time.time()
    # Verify replacement archives outside the writer transaction. Recheck their
    # identities and the five selected IDs under the writer before unlinking.
    with store.connect() as db:
        db.execute('DELETE FROM update_downloads WHERE expires<=?', (now,))
        releases=published(db)
        keep=available(db,store,releases)
    if len(keep)<KEEP or not any(packages.version(row['version'])<packages.version(keep[-1]['version']) for row in releases):
        return 0
    verified={}
    for row in keep:
        path=packages.plain(repository(store)/(row['id']+'.zip'))
        identity=fingerprint(path.stat())
        if not intact(path,row['id'],identity):return 0
        verified[row['id']]=(path,identity)
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        releases = published(db)
        keep = available(db, store, releases)
        if [row['id'] for row in keep]!=list(verified) or any(fingerprint(packages.plain(path).stat())!=identity for path,identity in verified.values()):
            return 0
        cutoff = packages.version(keep[-1]['version'])
        removed = 0
        for row in releases:
            rid = row['id']
            if packages.version(row['version']) >= cutoff or not re.fullmatch('[0-9a-f]{64}', rid):
                continue
            if db.execute(
                "SELECT 1 FROM update_jobs j WHERE release_id=? AND ("
                "(status IN ('pending','reserved') AND expires>?) OR "
                "(status='pending' AND EXISTS(SELECT 1 FROM update_status s WHERE s.job_id=j.id AND s.state IN ('applying','restarting'))) OR "
                "EXISTS(SELECT 1 FROM updater_refresh u WHERE u.job_id=j.id AND u.state='active' AND u.expires>?) OR "
                "EXISTS(SELECT 1 FROM update_downloads d WHERE d.job_id=j.id AND d.expires>?)) LIMIT 1",
                (rid, now, now, now)).fetchone():
                continue
            try:
                packages.plain(repository(store)/(rid+'.zip')).unlink(missing_ok=True)
            except (OSError, ValueError):
                continue
            db.execute('INSERT INTO update_retired_packages VALUES (?,?)', (rid,now))
            Store.event(db,'console','update.release_package_removed','info',{'release_id':rid,'version':row['version']})
            removed += 1
            if removed == 8:
                break
        return removed
