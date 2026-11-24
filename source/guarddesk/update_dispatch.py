"""Previewed, durable dispatch with per-endpoint admission on updater poll."""
import json
import re
import secrets
import time

from . import updates
from .management import ManagementError
from .serialization import canonical
from .update_packages import version

MAX_TARGETS = 1000
PREVIEW_SECONDS = 600
RESULT_SECONDS = 7 * 86400
MAX_PREVIEWS = 1000


def broker_state(db, did, required, now):
    row = db.execute('SELECT version,received FROM update_broker_presence WHERE device_id=?', (did,)).fetchone()
    if not required:
        return 'ready'
    if not row or not 0 <= now - row['received'] < 90:
        return 'waiting'
    return 'ready' if version(row['version']) >= version(required) else 'needs_check'


def observe(db, did, broker, now):
    db.execute('INSERT INTO update_broker_presence VALUES (?,?,?) ON CONFLICT(device_id) DO UPDATE '
               'SET version=excluded.version,received=excluded.received', (did, broker, now))


def activity_conflict(db, did):
    from .software import active as software_active
    from .updater_maintenance import active as maintenance_active
    if software_active(db, did):
        return '端點有軟體安裝工作'
    if maintenance_active(db, did):
        return '端點正在維護更新器'
    if db.execute("SELECT 1 FROM endpoint_removals WHERE device_id=? AND status IN ('queued','running','failed')", (did,)).fetchone():
        return '端點有移除工作'
    return ''


def conflicts(db, did, now, exclude=''):
    other=activity_conflict(db,did)
    if other:return other
    if db.execute("SELECT 1 FROM update_jobs j WHERE device_id=? AND id<>? "
                  "AND ((status IN ('pending','reserved') AND expires>?) OR "
                  "(status='pending' AND EXISTS(SELECT 1 FROM update_status s WHERE s.job_id=j.id AND s.state IN ('applying','restarting'))))",
                  (did, exclude, now)).fetchone():
        return '端點已有更新工作'
    return ''


def select_ids(db, body):
    ids, group, all_devices = body.get('device_ids'), body.get('group_id'), body.get('all_endpoints')
    if sum(value is not None for value in (ids, group, all_devices)) != 1:
        raise ManagementError(400, '請選擇一種派送範圍')
    if all_devices is not None:
        if all_devices is not True:
            raise ManagementError(400, '全部端點選項不正確')
        ids = [row[0] for row in db.execute('SELECT id FROM devices WHERE revoked=0 ORDER BY id LIMIT ?', (MAX_TARGETS+1,))]
    if group is not None:
        if not isinstance(group, str) or not db.execute('SELECT 1 FROM endpoint_groups WHERE id=?', (group,)).fetchone():
            raise ManagementError(400, '更新群組不正確')
        ids = [row[0] for row in db.execute(
            'WITH RECURSIVE descendants(id) AS (SELECT ? UNION SELECT g.id FROM endpoint_groups g '
            'JOIN descendants p ON g.parent_id=p.id) SELECT d.id FROM devices d WHERE d.revoked=0 '
            'AND d.group_id IN (SELECT id FROM descendants) ORDER BY d.id LIMIT ?', (group, MAX_TARGETS+1))]
    if (not isinstance(ids, list) or not 1 <= len(ids) <= MAX_TARGETS
            or any(not isinstance(i, str) or not re.fullmatch('[0-9a-f]{24}', i) for i in ids)
            or len(set(ids)) != len(ids)):
        raise ManagementError(400, '請選擇 1–1,000 台不同端點')
    return ids


def classify(db, did, release, now, attested):
    device = db.execute('SELECT name,last_seen FROM devices WHERE id=? AND revoked=0', (did,)).fetchone()
    if not device:
        return {'device_id':did, 'name':'', 'state':'conflict', 'reason':'端點已撤銷或不存在'}
    broker = db.execute('SELECT version,received FROM update_broker_presence WHERE device_id=?', (did,)).fetchone()
    online = 0 <= now - device['last_seen'] < 90 or bool(broker and 0 <= now - broker['received'] < 90)
    result = {'device_id':did, 'name':device['name'], 'online':online,
              'broker_version':broker['version'] if broker else None,
              'broker_received':broker['received'] if broker else None}
    conflict = conflicts(db, did, now)
    if conflict:
        return {**result, 'state':'conflict', 'reason':conflict}
    required = release['deployment']['required_updater']
    state = 'ready' if attested else broker_state(db, did, required, now)
    if not online and not attested:
        return {**result, 'state':'waiting', 'reason':'等候端點上線'}
    if state == 'waiting':
        return {**result, 'state':state, 'reason':'等候獨立更新器回報'}
    if state == 'needs_check':
        return {**result, 'state':state, 'reason':f'更新器須為 {required} 或以上，請先檢查單台'}
    target = release['version']
    live = db.execute('SELECT count(*) FROM update_presence WHERE device_id=? AND received>? AND version=?',
                      (did, now-90, target)).fetchone()[0]
    if live == 2 and db.execute("SELECT 1 FROM update_jobs WHERE device_id=? AND release_id=? AND status='completed' LIMIT 1",
                                (did, release['id'])).fetchone():
        return {**result, 'state':'current', 'reason':'已確認兩個元件運作於目標版本'}
    return {**result, 'state':'ready', 'reason':'MIS 已確認單台試用' if attested else '可安排更新'}


def preview(db, user, body, store=None):
    if set(body) - {'release_id','not_before','allow_downgrade','legacy_preflight_confirmed',
                    'device_ids','group_id','all_endpoints'}:
        raise ManagementError(400, '預覽參數不正確')
    release = updates.target_release(db, body.get('release_id'), store=store)
    ids = select_ids(db, body)
    attested = body.get('legacy_preflight_confirmed', False)
    if type(attested) is not bool or attested and (len(ids) != 1 or 'device_ids' not in body):
        raise ManagementError(400, '舊更新器檢查僅適用於明確選取的單台端點')
    now = time.time()
    when, downgrade = updates.schedule_options(body, now)
    rows = [classify(db, did, release, now, attested) for did in ids]
    db.execute('DELETE FROM update_dispatch_previews WHERE id IN '
               '(SELECT id FROM update_dispatch_previews WHERE expires<=? ORDER BY expires LIMIT 100)', (now,))
    if db.execute('SELECT count(*) FROM update_dispatch_previews').fetchone()[0] >= MAX_PREVIEWS:
        raise ManagementError(429, '派送預覽過多，請待舊預覽到期')
    token = secrets.token_hex(16)
    plan = dict(release_id=release['id'], not_before=when, allow_downgrade=downgrade, legacy_preflight=attested,
                targets={row['device_id']:row['state'] for row in rows if row['state'] in ('ready','waiting')})
    plan['excluded']=len(rows)-len(plan['targets'])
    db.execute('INSERT INTO update_dispatch_previews VALUES (?,?,?,?,NULL)',
               (token, user['username'], now+PREVIEW_SECONDS, canonical(plan)))
    return {'preview_id':token, 'version':release['version'], 'not_before':when,
            'expires':when+RESULT_SECONDS, 'allow_downgrade':downgrade, 'targets':rows}


def confirm(db, user, body, store=None):
    token, ready_only = body.get('preview_id'), body.get('ready_only')
    if (set(body) != {'preview_id','ready_only','confirm'} or body['confirm'] != 'deploy'
            or not isinstance(token, str) or not re.fullmatch('[0-9a-f]{32}', token) or type(ready_only) is not bool):
        raise ManagementError(400, '請確認派送預覽')
    now = time.time()
    saved = db.execute('SELECT * FROM update_dispatch_previews WHERE id=? AND actor=? AND expires>?',
                       (token, user['username'], now)).fetchone()
    if not saved:
        raise ManagementError(409, '派送預覽已過期，請重新預覽')
    if saved['result']:
        return json.loads(saved['result'])
    plan = json.loads(saved['plan'])
    release = updates.target_release(db, plan['release_id'], store=store)
    when = plan['not_before']
    if when + RESULT_SECONDS <= now:
        raise ManagementError(409, '更新工作已過期')
    summary = {'job_ids':[], 'scheduled':0, 'reserved':0, 'skipped':plan['excluded']}
    for did, state in plan['targets'].items():
        row = classify(db, did, release, now, plan['legacy_preflight'])
        if row['state'] not in ('ready','waiting') or ready_only and (state != 'ready' or row['state'] != 'ready'):
            summary['skipped'] += 1
            continue
        job = updates.record_job(db, did, release['id'], user, now, when, plan['allow_downgrade'],
                                 plan['legacy_preflight'], status='reserved')
        db.execute('INSERT INTO update_dispatch_jobs VALUES (?,?)', (job, int(plan['legacy_preflight'])))
        summary['job_ids'].append(job)
        summary['reserved' if row['state']=='waiting' else 'scheduled'] += 1
    db.execute('UPDATE update_dispatch_previews SET result=?,expires=? WHERE id=?',
               (canonical(summary), now+RESULT_SECONDS, token))
    return summary


def admit(db, job, now, scope, reported=True):
    options = db.execute('SELECT legacy_preflight FROM update_dispatch_jobs WHERE job_id=?', (job['id'],)).fetchone()
    if not options:
        return 'needs_check'
    if conflicts(db, job['device_id'], now, job['id']):
        return 'work_conflict'
    if options['legacy_preflight']:
        return 'ready'
    if scope['required_updater'] and not reported:
        return 'waiting'
    return broker_state(db, job['device_id'], scope['required_updater'], now)
