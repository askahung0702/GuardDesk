"""Per-device heartbeat-only administration and authenticated policy responses."""
import copy
import time

from . import custom_settings, document_settings, removal
from .management import ManagementError
from .policy import heartbeat_policy
from .store import Store, canonical, digest


def change(db, user, body):
    from .endpoint_purge import identifier
    if user['role'] != 'admin':
        raise ManagementError(403, '需要管理員權限')
    if (set(body) != {'device_id', 'enabled', 'revision'} or type(body['enabled']) is not bool
            or type(body['revision']) is not int or body['revision'] < 0):
        raise ManagementError(400, '端點模式欄位不正確')
    did = identifier(body['device_id'])
    row = db.execute('SELECT revoked,heartbeat_only,mode_revision FROM devices WHERE id=?', (did,)).fetchone()
    if not row or row['revoked']:
        raise ManagementError(409, '端點已撤銷或退役')
    enabled = body['enabled']
    if row['mode_revision'] != body['revision']:
        raise ManagementError(409, '端點模式已變更，請重新開啟端點明細')
    if bool(row['heartbeat_only']) == enabled:
        return {'ok': True}
    if enabled:
        job = removal.latest(db, did)
        from .updater_maintenance import active as refreshing
        # Queued deployments may wait normally for this device to resume.
        software_work = db.execute("SELECT 1 FROM software_jobs WHERE device_id=? AND "
                                   "(state IN ('installing','review_required') OR (state='downloading' AND expires>?)) LIMIT 1",
                                   (did,time.time())).fetchone()
        update_work = db.execute("SELECT 1 FROM update_jobs j JOIN update_status s ON s.job_id=j.id "
                                 "WHERE j.device_id=? AND j.status='pending' AND s.state IN "
                                 "('downloading','verifying','applying','restarting') LIMIT 1", (did,)).fetchone()
        assisting = db.execute("SELECT 1 FROM remote_sessions WHERE device_id=? AND status='active' AND expires>? LIMIT 1",
                               (did,time.time())).fetchone()
        if ((job and job['status'] not in ('closed', 'expired')) or software_work or update_work or assisting
                or refreshing(db,did) or custom_settings.action_leased(db, did)):
            raise ManagementError(409, '端點有移除、派送或協助工作，請先核對工作狀態')
    now = time.time()
    if enabled:
        db.execute('INSERT INTO heartbeat_only_periods(device_id,started) VALUES (?,?)', (did, now))
    else:
        db.execute('UPDATE heartbeat_only_periods SET ended=? WHERE device_id=? AND ended IS NULL', (now, did))
    db.execute('UPDATE devices SET heartbeat_only=?, mode_revision=mode_revision+1, mode_ack=0 WHERE id=?', (enabled, did))
    Store.event(db, did, 'device.heartbeat_mode', 'warning', {'actor': user['username'], 'heartbeat_only': enabled})
    return {'ok': True}


def suppressed_at(db, did, occurred):
    row = db.execute('SELECT ended FROM heartbeat_only_periods WHERE device_id=? AND started<=? '
                     'ORDER BY started DESC LIMIT 1', (did, occurred)).fetchone()
    return row is not None and (row[0] is None or occurred < row[0])


def paused_reply(db, device, path, body):
    did, revision = device['id'], device['mode_revision']
    if path == '/api/agent/heartbeat':
        from .policy_progress import touch
        ack = body.get('native_idle_revision')
        mode_ack = device['mode_ack']
        if type(ack) is int and ack in (0,revision):
            mode_ack=ack
        now = time.time()
        touch(db,device,now)
        db.execute('UPDATE devices SET last_seen=?, last_contact=?, mode_ack=? WHERE id=?', (now, now, mode_ack, did))
        return {'policy': heartbeat_policy(revision), 'server_time': now}
    if path == '/api/agent/native-usb-policy':
        return {'device_id': did, 'version': 0, 'usb_mode': 'allow', 'heartbeat_only': revision}
    if path == '/api/agent/extended-policy':
        return {**heartbeat_policy(revision), 'device_id': did, 'user_upload_required': False}
    if path == '/api/agent/custom-settings' and body.get('protocol') in (1, 2):
        settings = copy.deepcopy(custom_settings.DEFAULT)
        return {'device_id': did, 'protocol': body['protocol'], 'schema': 'named-items-v1', 'generation': revision,
                'version': revision, 'body': settings, 'fingerprint': digest(canonical(settings)),
                'documents': document_settings.packet([]), 'busy': True}
    if path in ('/api/agent/extended-status', '/api/agent/native-usb-status', '/api/agent/custom-status'):
        return {'ok': True}
    if path in ('/api/agent/uninstall/poll', '/api/agent/software/poll', '/api/agent/updates/poll'):
        return {'job': None}
    raise ManagementError(409, '此端點目前只回報心跳')
