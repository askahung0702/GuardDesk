"""Bounded capability reporting, separate from immutable audit evidence.

Never query event history to decide whether a collector is installed. A native
handshake is a connectivity observation, not proof of complete upload coverage.
"""
import json
import math
import re
import time

SESSION_KEY='document_browser_sessions_v1'
FRESH_SECONDS=180


def fresh_timestamp(now,value):
    return type(value) in (float,int) and math.isfinite(value) and 0<=now-value<=FRESH_SECONDS


def browser_handshake(agent,message,now=None):
    """One entry per supported browser; no profile paths, URLs or user guessing."""
    now=time.time() if now is None else now
    browser=message.get('browser')
    version=message.get('extension_version')
    if browser not in ('chrome','edge') or not isinstance(version,str) or not re.fullmatch(r'\d{1,5}(?:\.\d{1,5}){1,3}',version):
        raise ValueError('Invalid browser handshake')
    with agent.db() as db:
        row=db.execute('SELECT value FROM state WHERE key=?',(SESSION_KEY,)).fetchone()
        saved=json.loads(row[0]) if row else {}
        old=saved.get(browser,{})
        # MV3 status requests can be frequent. Do not create file/audit noise or
        # write per web request; two small rows share the existing durable DB.
        if old.get('version')!=version or now-old.get('seen',0)>=60:
            saved={k:v for k,v in saved.items() if k in ('chrome','edge')}
            saved[browser]={'version':version,'seen':now}
            db.execute('INSERT OR REPLACE INTO state VALUES (?,?)',(SESSION_KEY,json.dumps(saved)))


def browser_status(agent,enabled=True,now=None):
    now=time.time() if now is None else now
    with agent.db() as db:
        row=db.execute('SELECT value FROM state WHERE key=?',(SESSION_KEY,)).fetchone()
    saved=json.loads(row[0]) if row else {}
    browsers=[]
    for browser in ('chrome','edge'):
        record=saved.get(browser,{})
        seen=record.get('seen',0)
        fresh=fresh_timestamp(now,seen)
        browsers.append({'browser':browser,'status':'disabled' if not enabled else 'connected_limited' if fresh else 'stale' if seen else 'not_observed',
                         'extension_version':record.get('version'),'last_seen':seen or None})
    return {'status':'disabled' if not enabled else 'connected_limited' if any(b['status']=='connected_limited' for b in browsers) else 'awaiting_extension',
            'browsers':browsers,'coverage':'regular_profiles_request_metadata_only','checked_at':now}


def readiness(device,policy,now=None,documents=None):
    now=time.time() if now is None else now
    ext=device.get('extended_status') or {}
    fresh=0<=now-ext.get('received',0)<=FRESH_SECONDS
    read=ext.get('document_read') if fresh and isinstance(ext.get('document_read'),dict) else None
    if not policy['file_audit']['enabled']:read={'status':'disabled'}
    elif not read:read={'status':'worker_not_reported' if not ext else 'stale'}
    collectors=(device.get('inventory') or {}).get('collectors',{})
    upload=collectors.get('document_upload') if isinstance(collectors,dict) else None
    if not policy['browser_audit']:upload={'status':'disabled'}
    elif not isinstance(upload,dict):upload={'status':'agent_not_reported'}
    elif not fresh_timestamp(now,upload.get('checked_at',0)):upload={**upload,'status':'stale'}
    if policy['browser_audit'] and isinstance(collectors,dict) and isinstance(collectors.get('browser_native_host'),dict) and collectors['browser_native_host'].get('status')=='failed':
        upload={**upload,'status':'host_registration_failed'}
    provisioning=ext.get('document_provisioning') if fresh else None
    native_read=ext.get('document_native_read') if fresh else None
    if isinstance(native_read,dict) and policy['file_audit']['enabled']:
        read={**native_read,'security_collector_status':read['status']}
        if provisioning:read['provisioning']=provisioning
    elif provisioning and policy['file_audit']['enabled']:read={**read,'collector_status':read['status'],'provisioning':provisioning,'status':provisioning.get('status',read['status'])}
    copy=ext.get('document_copy') if fresh else None
    if not policy['file_audit']['enabled']:copy={'status':'disabled'}
    elif not isinstance(copy,dict):copy={'status':'worker_not_reported','coverage':'directory_notifications_do_not_prove_copy'}
    handoff=collectors.get('native_file_handoff') if isinstance(collectors,dict) else None
    if not policy['browser_audit'] or not policy['file_audit']['enabled']:handoff={'status':'disabled'}
    elif not isinstance(handoff,dict):handoff={'status':'agent_not_reported'}
    elif not fresh_timestamp(now,handoff.get('checked_at',0)):handoff={**handoff,'status':'stale'}
    result={'read':read,'copy':copy,'upload':upload,'handoff':handoff,'checked_at':now}
    if documents is not None:
        # Desired scope is separate from observations. A nonempty assignment
        # never proves that a native worker has applied it or collected a read.
        rules=documents.get('rules',[])
        result['configuration']={'status':'general_policy_enabled' if policy['file_audit']['enabled'] else 'disabled',
                                 'source':'general_file_policy','scope':policy['file_audit']['scope'],
                                 'read_roots':sum(bool(r.get('read')) for r in rules),
                                 'copy_roots':sum(bool(r.get('copy')) for r in rules),
                                 'minimum_version':'0.4.51','custom_document_rules_optional':True}
    return result
