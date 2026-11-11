from .remote_errors import RemoteError
"""Consent-based support sessions; short leases and explicit per-device grants."""
import base64
import math
import re
import secrets
import time
from urllib.parse import parse_qs
from .store import Store,canonical,password_hash,validate_password




def require(value,message='遠端操作未授權',status=403):
    if not value:raise RemoteError(status,message)


def text(body,key,limit=200):
    value=body.get(key)
    require(isinstance(value,str) and 0<len(value.strip())<=limit and not any(ord(c)<32 for c in value),key+' 不正確',400)
    return value.strip()


def optional_reason(body):
    value=body.get('reason','')
    require(isinstance(value,str) and len(value)<=200 and not any(ord(c)<32 for c in value),'協助原因最多 200 字，可留空',400)
    return value.strip()


def close(server,db,row,reason):
    with server.remote_lock:memory=server.remote_memory.pop(row['id'],{})
    if memory.get('native'):memory['native'].close()
    if row['status'] in ('requested','active'):
        db.execute('UPDATE remote_sessions SET status=?,ended_reason=? WHERE id=?',('closed',reason,row['id']))
        Store.event(db,row['device_id'],'remote.closed','info',{'operator':row['operator'],'session_id':row['id'],'reason':reason,'input_batches':memory.get('input_batches',0),'input_events':memory.get('input_events',0)})


def admin_grant(db,username,did,scope='device'):
    row=db.execute('SELECT enabled FROM remote_admin_grants WHERE username=? AND device_id=?',(username,'*' if scope=='all' else did)).fetchone()
    return bool(row and row['enabled'])


def effective_grant(db,username,did,now):
    """An active device rule overrides the account's all-endpoint default."""
    account=db.execute("SELECT 1 FROM users WHERE username=? AND role IN ('admin','support')",(username,)).fetchone()
    if not account:return None
    row=db.execute('SELECT * FROM remote_grants WHERE username=? AND device_id=? AND expires>?',(username,did,now)).fetchone()
    if row:return {**dict(row),'can_elevate':admin_grant(db,username,did)}
    row=db.execute('SELECT * FROM remote_all_grants WHERE username=? AND (expires=0 OR expires>?)',(username,now)).fetchone()
    if not row:return None
    return {**dict(row),'device_id':did,'scope':'all','can_elevate':admin_grant(db,username,did,'all'),'permanent':row['expires']==0,'expires':row['expires'] or 253402300799}


def catalog_grants(db,username,admin,devices,now):
    """Expand defaults for protocol-2 viewers, without per-device DB writes."""
    specific=[{**dict(row),'scope':'device'} for row in db.execute('SELECT * FROM remote_grants')]
    all_rules=[{**dict(row),'device_id':'*','scope':'all','permanent':row['expires']==0} for row in db.execute('SELECT * FROM remote_all_grants')]
    eligible={r['username'] for r in db.execute("SELECT username FROM users WHERE role IN ('admin','support')")}
    rules=[r for r in specific+all_rules if r['username'] in eligible and (admin or r['username']==username)]
    grants={(r['username'],r['device_id']):r for r in rules if r['scope']=='device' and r['expires']>now}
    for rule in rules:
        if rule['scope']!='all' or (rule['expires']!=0 and rule['expires']<=now):continue
        for device in devices:
            key=(rule['username'],device['id'])
            if key not in grants:grants[key]={**rule,'device_id':device['id'],'expires':rule['expires'] or 253402300799}
    for rule in rules:rule['can_elevate']=admin_grant(db,rule['username'],rule['device_id'],rule['scope'])
    for rule in grants.values():rule['can_elevate']=admin_grant(db,rule['username'],rule['device_id'],rule['scope'])
    return list(grants.values()),rules


def sweep(server,db):
    now=time.time()
    for row in db.execute("SELECT * FROM remote_sessions WHERE status IN ('requested','active')").fetchall():
        grant=effective_grant(db,row['operator'],row['device_id'],now)
        device=db.execute('SELECT revoked FROM devices WHERE id=?',(row['device_id'],)).fetchone()
        login=db.execute('SELECT 1 FROM sessions WHERE token=? AND expires>?',(row['login_token'],now)).fetchone()
        reason=None
        if not grant or (row['mode']=='control' and not grant['can_control']):reason='permission_revoked'
        elif is_admin_session(db,row['id']) and (not grant.get('can_elevate') or row['id'] not in server.remote_memory):reason='admin_permission_revoked'
        elif not device or device['revoked'] or not login:reason='device_or_login_revoked'
        elif row['expires']!=0 and row['expires']<=now:reason='expired'
        elif row['status']=='active' and (now-row['viewer_seen']>8 or now-row['agent_seen']>8):reason='participant_disconnected'
        if reason:close(server,db,row,reason)


def is_admin_session(db,sid):
    return bool(db.execute('SELECT 1 FROM remote_admin_sessions WHERE session_id=?',(sid,)).fetchone())


def public(row,db):return {**{k:row[k] for k in ('id','device_id','operator','status','mode','reason','created','expires','ended_reason')},'admin_control':is_admin_session(db,row['id'])}


def operator_session(server,db,user,sid):
    sweep(server,db)
    row=db.execute('SELECT * FROM remote_sessions WHERE id=?',(sid,)).fetchone()
    require(row and row['operator']==user['username'] and row['login_token']==user['token'])
    return row


def update_busy(db,did,now):
    from .update_progress import ACTIVE
    return bool(db.execute(f"SELECT 1 FROM update_jobs j JOIN update_status s ON s.job_id=j.id WHERE j.device_id=? AND j.status='pending' AND j.expires>? AND s.state IN {ACTIVE} LIMIT 1",(did,now)).fetchone()
        or db.execute("SELECT 1 FROM updater_refresh WHERE device_id=? AND state='active' AND expires>?",(did,now)).fetchone())


def route(server,db,user,method,path,body,query):
    sweep(server,db);now=time.time()
    if path=='/api/remote/native' and method=='POST':
        row=operator_session(server,db,user,text(body,'session_id',100))
        require(row['status']=='active','尚未取得本次使用者同意',409)
        with server.remote_lock:
            state=server.remote_memory.get(row['id'],{}).get('native')
            require(state is not None,'原生會話已失效，請重新要求同意',409)
            result=state.exchange('viewer',body)
        db.execute('UPDATE remote_sessions SET viewer_seen=? WHERE id=?',(now,row['id']))
        return result
    if path=='/api/remote/catalog' and method=='GET':
        admin=user['role']=='admin'
        devices=[dict(r) for r in db.execute('SELECT d.id,d.name,p.account,p.ready,p.received,COALESCE(c.protocol,1) AS protocol,r.reason AS readiness FROM devices d LEFT JOIN remote_presence p ON p.device_id=d.id LEFT JOIN remote_capabilities c ON c.device_id=d.id LEFT JOIN remote_readiness r ON r.device_id=d.id WHERE d.revoked=0')]
        grants,rules=catalog_grants(db,user['username'],admin,devices,now)
        if not admin:
            grants=[r for r in grants if r['username']==user['username'] and r['expires']>now]
            devices=[d for d in devices if any(g['device_id']==d['id'] for g in grants)]
        for d in devices:
            fresh=d['received'] is not None and now-d['received']<12
            d['ready']=bool(d['ready'] and fresh)
            d['readiness']='no_desktop_report' if not fresh else 'ready' if d['ready'] else d['readiness'] or 'not_ready'
            from .remote_native import reported
            d['native']=reported(server,d['id'],now)
        from .remote_trial import enabled as trial_enabled
        return {'native_only_trial':trial_enabled(),'desktop_protocol':2,'clarity_protocol':3,'admin_protocol':6,'devices':devices,'grants':grants,'grant_rules':rules,'all_endpoints_grant':True,'users':[dict(r) for r in db.execute('SELECT username,role FROM users')] if admin else [],'sessions':[public(r,db) for r in db.execute('SELECT * FROM remote_sessions WHERE operator=? ORDER BY created DESC LIMIT 20',(user['username'],))]}
    if path=='/api/remote/account' and method=='POST':
        require(user['role']=='admin');name=text(body,'username',80)
        password=validate_password(body.get('password'))
        db.execute('INSERT INTO users VALUES (?,?,?)',(name,password_hash(password),'support'))
        Store.event(db,'console','remote.account_created','warning',{'actor':user['username'],'username':name})
        return {'ok':True}
    if path=='/api/remote/grant' and method=='POST':
        require(user['role']=='admin');name=text(body,'username',80);did=text(body,'device_id',100)
        require(db.execute('SELECT 1 FROM users WHERE username=? AND role IN (?,?)',(name,'admin','support')).fetchone(),'請選擇管理員或專用支援帳號',400)
        if did!='*':require(db.execute('SELECT 1 FROM devices WHERE id=? AND revoked=0',(did,)).fetchone(),'端點不存在',400)
        require(type(body.get('enabled')) is bool and type(body.get('can_control')) is bool,'授權設定不正確',400)
        elevate=body.get('can_elevate',False)
        require(type(elevate) is bool and (not elevate or body['can_control']),'管理員協助必須同時授權控制',400)
        db.execute('INSERT OR REPLACE INTO remote_admin_grants VALUES (?,?,?)',(name,did,int(elevate and body['enabled'])))
        if body['enabled']:
            days=body.get('days',0 if did=='*' else 1)
            require(type(days) is int and (0 if did=='*' else 1)<=days<=30,'全部端點可填 0（直到撤銷）；其他有效天數須為 1–30',400)
            expires=0 if days==0 else now+days*86400
            if did=='*':db.execute('INSERT OR REPLACE INTO remote_all_grants VALUES (?,?,?)',(name,int(body['can_control']),expires))
            else:db.execute('INSERT OR REPLACE INTO remote_grants VALUES (?,?,?,?)',(name,did,int(body['can_control']),expires))
        elif did=='*':db.execute('DELETE FROM remote_all_grants WHERE username=?',(name,))
        else:db.execute('DELETE FROM remote_grants WHERE username=? AND device_id=?',(name,did))
        Store.event(db,'console' if did=='*' else did,'remote.permission_changed','warning',{'actor':user['username'],'username':name,'enabled':body['enabled'],'can_control':body['can_control'],'can_elevate':elevate,'scope':'all' if did=='*' else 'device','expires':expires if body['enabled'] else None})
        sweep(server,db);return {'ok':True}
    if path=='/api/remote/request' and method=='POST':
        require(user['role'] in ('admin','support'));did=text(body,'device_id',100);reason=optional_reason(body);mode=body.get('mode','view')
        require(db.execute('SELECT 1 FROM devices WHERE id=? AND revoked=0',(did,)).fetchone(),'端點不存在或已撤銷',404)
        require(not update_busy(db,did,now),'端點正在更新，請待更新完成後再要求遠端協助',409)
        removal=db.execute('SELECT status,expires FROM endpoint_removals WHERE device_id=? ORDER BY created DESC LIMIT 1',(did,)).fetchone()
        require(not removal or removal['status']=='expired' or (removal['status']=='queued' and removal['expires']<now),'端點正在移除或已移除，不能發起遠端協助',409)
        require(mode in ('view','control'),'遠端模式不正確',400)
        grant=effective_grant(db,user['username'],did,now)
        require(grant and (mode=='view' or grant['can_control']))
        presence=db.execute('SELECT * FROM remote_presence WHERE device_id=?',(did,)).fetchone()
        require(presence and presence['ready'] and now-presence['received']<12,'端點未處於可協助的互動桌面',409)
        viewer=body.get('viewer','browser');require(viewer in ('browser','desktop'),'檢視器類型不正確',400)
        quality=body.get('quality','balanced');require(quality in ('balanced','economy','clarity'),'畫質模式不正確',400)
        if quality=='clarity':
            capability=db.execute('SELECT protocol FROM remote_capabilities WHERE device_id=?',(did,)).fetchone()
            require(viewer=='desktop' and capability and capability['protocol']>=3,'原始解析度模式需要 Server、桌面程式及端點 Agent 更新至 0.4.19',409)
        if viewer=='desktop':
            capability=db.execute('SELECT protocol FROM remote_capabilities WHERE device_id=?',(did,)).fetchone()
            require(capability and capability['protocol']>=2,'請先將端點 Agent 更新至 0.4.14 以使用桌面遠端協助',409)
        admin_control=body.get('admin_control',False)
        require(type(admin_control) is bool,'管理員協助模式不正確',400)
        if admin_control:
            require(type(body.get('admin_wire')) is int and body['admin_wire']==6,'請更新 MIS 管理員協助元件',409)
            require(mode=='control' and viewer=='desktop' and grant.get('can_elevate'),'未授權管理員協助',403)
            require(capability and capability['protocol']>=6,'請更新全機原生元件與 MIS 程式，才能操作 UAC',409)
        transport=body.get('transport','legacy_images')
        require(transport in ('legacy_images','native_webrtc'),'遠端傳輸類型不正確',400)
        from .remote_trial import enabled as trial_enabled
        require(not trial_enabled() or transport=='native_webrtc','此測試中心僅支援「原生即時 · 內部預覽」，請更換傳輸模式',409)
        native_network=None
        if transport=='native_webrtc':
            from .remote_native import reported
            features=reported(server,did,now)
            require(viewer=='desktop' and features is not None and body.get('native_wire')==1,'原生即時遠端尚未就緒',409)
            require(body.get('native_cohort_sha256')==features['cohort_sha256'],'MIS 與端點原生元件組合不同，請先使用相同組合',409)
            require(not admin_control or features['secure_desktop'],'此原生組合尚未提供安全桌面',409)
            from .remote_native import approved_network
            native_network=approved_network(server,user,dict(db.execute('SELECT last_address FROM devices WHERE id=?',(did,)).fetchone()))
        from .custom_settings import action_leased
        require(not action_leased(db,did),'端點正在執行已授權排程，請稍後重試',409)
        require(not db.execute("SELECT 1 FROM remote_sessions WHERE device_id=? AND status IN ('requested','active')",(did,)).fetchone(),'端點已有協助請求',409)
        require(db.execute("SELECT count(*) FROM remote_sessions WHERE status IN ('requested','active')").fetchone()[0]<4,'最多同時 4 個協助工作階段',409)
        sid=secrets.token_hex(16)
        db.execute('INSERT INTO remote_sessions(id,device_id,operator,login_token,status,mode,reason,created,expires,viewer_seen,agent_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?)',(sid,did,user['username'],user['token'],'requested',mode,reason,now,now+120,now,now))
        if admin_control:db.execute('INSERT INTO remote_admin_sessions VALUES (?)',(sid,))
        with server.remote_lock:server.remote_memory[sid]={'viewer':viewer,'quality':quality,'admin_control':admin_control,'transport':transport,'native_network':native_network,
            'native_cohort_sha256':body.get('native_cohort_sha256') if transport=='native_webrtc' else None}
        Store.event(db,did,'remote.requested','warning',{'operator':user['username'],'session_id':sid,'mode':mode,'admin_control':admin_control,'reason':reason,'permission_scope':grant.get('scope','device'),'operator_origin':'mis_workstation' if user['token'].startswith('mis:') else 'server_console'})
        return {**public(db.execute('SELECT * FROM remote_sessions WHERE id=?',(sid,)).fetchone(),db),'transport':transport}
    if path=='/api/remote/session' and method=='GET':
        sid=parse_qs(query).get('id',[''])[0];row=operator_session(server,db,user,sid)
        if row['status'] in ('requested','active'):db.execute('UPDATE remote_sessions SET viewer_seen=? WHERE id=?',(now,sid))
        result=public(row,db)
        with server.remote_lock:
            memory=server.remote_memory.get(sid,{});frame=memory.get('frame')
            result['viewer']=memory.get('viewer','browser')
            result['transport']=memory.get('transport','legacy_images')
            native=memory.get('native')
            if native and row['status']=='active':
                result.update(native_wire=1,transport_generation=native.transport,native_cohort_sha256=native.cohort_sha256,native_network=native.public_network('viewer'),native_consent_seconds=None)
            if result['admin_control']:result.update(desktop_epoch=memory.get('desktop_epoch'),desktop=memory.get('desktop'))
            if row['status']=='active' and frame and now-frame['time']<3:
                result.update(frame_time=frame['time'],frame_seq=frame.get('seq',0))
                after=parse_qs(query).get('after',['-1'])[0]
                require(re.fullmatch(r'-1|[0-9]{1,10}',after) is not None,'畫面序號不正確',400)
                if int(after)<frame.get('seq',0):result['frame']=dict(frame)
        return result
    if path=='/api/remote/stop' and method=='POST':
        row=operator_session(server,db,user,text(body,'session_id',100));close(server,db,row,'operator_stopped');return {'ok':True}
    if path=='/api/remote/presented' and method=='POST':
        row=operator_session(server,db,user,text(body,'session_id',100))
        require(row['status']=='active' and is_admin_session(db,row['id']),'管理員協助未啟用',409)
        epoch=body.get('desktop_epoch');sequence=body.get('frame_seq')
        require(isinstance(epoch,str) and re.fullmatch('[0-9a-f]{32}',epoch)
            and type(sequence) is int and sequence>0,'畫面確認不正確',400)
        with server.remote_lock:
            memory=server.remote_memory.get(row['id'],{})
            frame=memory.get('frame',{})
            accepted=bool(epoch==memory.get('desktop_epoch') and now-frame.get('time',0)<3
                and memory.get('epoch_frame_start',0)<=sequence<=frame.get('seq',0))
            if accepted:memory['presented_epoch']=epoch
        return {'ok':True,'accepted':accepted}
    if path=='/api/remote/input' and method=='POST':
        row=operator_session(server,db,user,text(body,'session_id',100))
        with server.remote_lock:require(server.remote_memory.get(row['id'],{}).get('transport')!='native_webrtc','原生輸入必須使用已協商的加密資料通道',409)
        require(row['status']=='active' and row['mode']=='control','尚未同意控制或端點未回應',409)
        actions=body.get('actions');require(isinstance(actions,list) and 1<=len(actions)<=20,'輸入批次不正確',400)
        with server.remote_lock:
            memory=server.remote_memory.get(row['id'],{})
            desktop=memory.get('viewer')=='desktop'
            admin=is_admin_session(db,row['id'])
            fresh=bool(memory.get('frame') and now-memory['frame']['time']<3)
            if admin and (now-row['agent_seen']>=3 or not fresh or not memory.get('desktop_epoch')
                or memory.get('presented_epoch')!=memory['desktop_epoch'] or body.get('desktop_epoch')!=memory['desktop_epoch']):
                return {'ok':True,'accepted':0,'resync':True}
            require(now-row['agent_seen']<3,'尚未同意控制或端點未回應',409)
            if desktop:require(fresh,'畫面已過期，暫停操作',409)
        clean=[]
        for action in actions:
            require(isinstance(action,dict),'輸入格式不正確',400);kind=action.get('type')
            if kind in ('move','click','button','scroll'):
                require(kind in ('move','click') or desktop,'此操作需要桌面檢視器',400)
                fields={'type','x','y','button'} if kind in ('move','click') else {'type','x','y','button','down'} if kind=='button' else {'type','x','y','delta'}
                require(set(action)<=fields,'輸入欄位不正確',400)
                require(all(type(action.get(k)) in (int,float) and math.isfinite(action[k]) and 0<=action[k]<=1 for k in ('x','y')),'游標範圍不正確',400)
                require(action.get('button','left') in ('left','right','middle') if desktop else action.get('button','left') in ('left','right'),'滑鼠按鍵不正確',400)
                if kind=='button':require(type(action.get('down')) is bool,'滑鼠狀態不正確',400)
                if kind=='scroll':require(type(action.get('delta')) is int and 0<abs(action['delta'])<=1200 and action['delta']%120==0,'滾輪範圍不正確',400)
            elif kind=='key':
                from .remote_codec import KEYS
                require(set(action)=={'type','key','down'} and type(action['key']) is int and action['key'] in KEYS and type(action['down']) is bool,'鍵盤事件不正確',400)
            elif kind=='release_all':require(desktop and set(action)=={'type'},'輸入欄位不正確',400)
            else:raise RemoteError(400,'不支援的遠端輸入')
            clean.append(dict(action))
        with server.remote_lock:
            memory=server.remote_memory.get(row['id'],{})
            # A pause/new frame can arrive while the batch is validated. Never
            # relabel old input with the new desktop epoch when enqueuing it.
            if admin and (not memory.get('frame') or time.time()-memory['frame']['time']>=3
                or not memory.get('desktop_epoch') or memory.get('presented_epoch')!=memory['desktop_epoch']
                or body.get('desktop_epoch')!=memory['desktop_epoch']):
                return {'ok':True,'accepted':0,'resync':True}
            pending=memory.setdefault('commands',[])
            require(len(pending)+len(clean)<=40,'輸入佇列已滿',429)
            pending.extend({'time':now,**({'desktop_epoch':memory['desktop_epoch']} if memory.get('admin_control') else {}),**a} for a in clean)
            memory['input_batches']=memory.get('input_batches',0)+1;memory['input_events']=memory.get('input_events',0)+len(clean)
        # Log batch counts, never keystroke contents or screenshots.
        return {'ok':True,'accepted':len(clean)}
    raise RemoteError(404,'找不到遠端協助 API')


def agent_route(server,db,device,path,body):
    if path=='/api/agent/remote/test-readiness':
        # Authenticated read-only readiness: do not sweep/create/approve a
        # remote session or update presence while an installer is inspecting.
        require(body=={},'測試檢查不接受設定或遠端指令',400)
        from .remote_native import enabled,WIRE
        from . import __version__
        now=time.time()
        busy=bool(update_busy(db,device['id'],now) or db.execute(
            "SELECT 1 FROM update_jobs WHERE device_id=? AND status='pending' AND expires>? LIMIT 1",(device['id'],now)).fetchone())
        remote_busy=bool(db.execute("SELECT 1 FROM remote_sessions WHERE device_id=? AND status IN ('requested','active') LIMIT 1",(device['id'],)).fetchone())
        return {'enabled':enabled(server),'wire':WIRE,'version':__version__,
                'update_busy':busy,'remote_busy':remote_busy}
    sweep(server,db);now=time.time();did=device['id']
    if path=='/api/agent/remote/poll':
        account=text(body,'account',240);require(type(body.get('ready')) is bool,'桌面狀態不正確',400)
        protocol=body.get('protocol',1);require(type(protocol) is int and protocol in (1,2,3,4,5,6),'遠端協定不正確',400)
        from .remote_readiness import REASONS
        readiness=body.get('readiness','ready' if body['ready'] else 'not_ready')
        require(isinstance(readiness,str) and readiness in REASONS,'遠端就緒狀態不正確',400)
        db.execute('INSERT OR REPLACE INTO remote_presence(device_id,account,ready,received) VALUES (?,?,?,?)',(did,account,int(body['ready']),now))
        db.execute('INSERT OR REPLACE INTO remote_readiness VALUES (?,?)',(did,'ready' if body['ready'] else readiness))
        db.execute('INSERT OR REPLACE INTO remote_capabilities VALUES (?,?)',(did,protocol))
        if 'native' in body:
            from .remote_native import presence
            presence(server,did,body['native'],now)
        row=db.execute("SELECT * FROM remote_sessions WHERE device_id=? AND status IN ('requested','active') ORDER BY created LIMIT 1",(did,)).fetchone()
        session=public(row,db) if row else None
        if session:
            with server.remote_lock:memory=server.remote_memory.get(row['id'],{})
            session.update(viewer=memory.get('viewer','browser'),quality=memory.get('quality','balanced'),transport=memory.get('transport','legacy_images'))
            if session['transport']=='native_webrtc':session['native_cohort_sha256']=memory.get('native_cohort_sha256')
        return {'session':session,'desktop_protocol':2}
    sid=text(body,'session_id',100);row=db.execute('SELECT * FROM remote_sessions WHERE id=? AND device_id=?',(sid,did)).fetchone();require(row,'工作階段不存在',404)
    if path=='/api/agent/remote/native':
        require(row['status']=='active','原生協助已結束',409)
        with server.remote_lock:
            state=server.remote_memory.get(sid,{}).get('native')
            require(state is not None,'原生會話已失效，請重新要求同意',409)
            result=state.exchange('endpoint',body)
        db.execute('UPDATE remote_sessions SET agent_seen=? WHERE id=?',(now,sid))
        return result
    if row['status'] not in ('requested','active'):return {'status':row['status'],'commands':[]}
    action=body.get('action')
    with server.remote_lock:native_transport=server.remote_memory.get(sid,{}).get('transport')=='native_webrtc'
    require(not native_transport or action in ('approve','deny','stop','admin_watch'),'原生媒體不能回退到圖片／命令輪詢',409)
    if action=='approve':
        require(row['status']=='requested','請求已處理',409)
        # A job can start while the user is reading the consent dialog. This
        # check and activation share the POST's BEGIN IMMEDIATE transaction.
        if update_busy(db,did,now):
            close(server,db,row,'update_in_progress');return {'status':'closed','commands':[]}
        # The interactive endpoint owns the consent UI. A server request alone
        # can never create an active desktop session.
        with server.remote_lock:memory=server.remote_memory.get(sid,{})
        native=None
        if memory.get('transport')=='native_webrtc':
            from .remote_native import NativeSession
            from .remote_native import reported
            features=reported(server,did,now)
            require(features and features['cohort_sha256']==memory.get('native_cohort_sha256'),'原生組合已變更，請重新取得同意',409)
            native=NativeSession(body.get('native_logon'),can_control=row['mode']=='control',can_elevate=is_admin_session(db,sid),network=memory.get('native_network'),cohort_sha256=features['cohort_sha256'],relay_authority=getattr(server,'remote_native_relay_authority',None),session_id=sid)
        db.execute("UPDATE remote_sessions SET status='active',expires=?,agent_seen=? WHERE id=?",(0 if native else now+600,now,sid))
        admin=is_admin_session(db,sid)
        Store.event(db,did,'remote.approved','warning',{'operator':row['operator'],'user':text(body,'account',240),'session_id':sid,'mode':row['mode'],'admin_control':admin})
        result={'status':'active','commands':[]}
        if native:
            with server.remote_lock:server.remote_memory[sid]['native']=native
            result.update(native_nonce=native.nonce,native_wire=1,transport_generation=native.transport,session_lifetime='until_stopped')
        if admin:
            nonce=secrets.token_hex(32)
            with server.remote_lock:server.remote_memory[sid]['admin_nonce']=nonce
            result.update(admin_nonce=nonce,expires=now+600,session=public(db.execute('SELECT * FROM remote_sessions WHERE id=?',(sid,)).fetchone(),db))
        return result
    if action in ('deny','stop'):
        close(server,db,row,'user_denied' if action=='deny' else 'endpoint_stopped');return {'status':'closed','commands':[]}
    if action=='admin_watch':
        require((native_transport or is_admin_session(db,sid)) and row['status']=='active','管理員協助未啟用',409)
        return {'status':row['status'],'commands':[]}
    if is_admin_session(db,sid):
        with server.remote_lock:memory=server.remote_memory.get(sid,{})
        nonce=body.get('admin_nonce')
        require(row['status']=='active' and isinstance(nonce,str) and re.fullmatch('[0-9a-f]{64}',nonce)
            and secrets.compare_digest(nonce,memory.get('admin_nonce','')),'管理員接管未驗證')
        if action=='admin_failure':
            phase=body.get('failure_phase');kind=body.get('error_type');code=body.get('native_code')
            require(phase in ('authorize','capture','frame_transport','commands_transport','input','desktop_transition')
                and kind in ('OSError','PermissionError','ValueError','InputFailure','ConnectionError','TimeoutError')
                and (code is None or type(code) is int and 0<=code<=0xffffffff),'元件錯誤欄位不正確',400)
            Store.event(db,did,'remote.component_failed','warning',{'session_id':sid,'phase':phase,'error_type':kind,'native_code':code})
            close(server,db,row,'component_'+phase)
            return {'status':'closed','commands':[]}
        if action=='admin_validate':
            # The child checks this before each capture. An older/rolled-back
            # Server must not accept a secure frame as an ordinary PNG session.
            db.execute('UPDATE remote_sessions SET agent_seen=? WHERE id=?',(now,sid))
            return {'status':'active','admin_protocol':6,'commands':[]}
        if action=='admin_pause':
            with server.remote_lock:
                for key in ('frame','commands','desktop_epoch','desktop','presented_epoch'):memory.pop(key,None)
            db.execute('UPDATE remote_sessions SET agent_seen=? WHERE id=?',(now,sid))
            return {'status':'active','commands':[]}
        epoch=body.get('desktop_epoch');desktop=body.get('desktop')
        require(isinstance(epoch,str) and re.fullmatch('[0-9a-f]{32}',epoch) and desktop in ('default','winlogon'),'桌面識別不正確',400)
        generation=body.get('desktop_generation')
        require(type(generation) is int and 0<generation<2**64,'桌面世代不正確',400)
        if action=='commands' and (epoch!=memory.get('desktop_epoch') or generation!=memory.get('desktop_generation')):return {'status':'active','commands':[]}
    if action=='commands':
        require(row['status']=='active','尚未同意操作',409)
        with server.remote_lock:
            memory=server.remote_memory.get(sid,{})
            require(memory.get('viewer')=='desktop','此功能需要桌面檢視器',409)
            commands=[a for a in memory.pop('commands',[]) if now-a['time']<2]
        db.execute('UPDATE remote_sessions SET agent_seen=? WHERE id=?',(now,sid))
        return {'status':'active','commands':commands}
    if action=='repeat_frame':
        require(row['status']=='active','尚未同意分享畫面',409)
        with server.remote_lock:
            memory=server.remote_memory.get(sid,{})
            require(memory.get('viewer')=='desktop' and memory.get('frame'),'沒有可重用的畫面',409)
            if is_admin_session(db,sid):require(body.get('desktop_epoch')==memory.get('desktop_epoch') and body.get('desktop_generation')==memory.get('desktop_generation'),'桌面已切換',409)
            memory['frame']['time']=now
        db.execute('UPDATE remote_sessions SET agent_seen=? WHERE id=?',(now,sid))
        return {'status':'active','commands':[]}
    require(action=='frame' and row['status']=='active','尚未同意分享畫面',409)
    frame=body.get('frame')
    from .remote_codec import validate_frame
    with server.remote_lock:
        memory=server.remote_memory.get(sid,{})
        desktop=memory.get('viewer')=='desktop';clarity=desktop and memory.get('quality')=='clarity'
    try:validate_frame(frame,jpeg=desktop,high_resolution=clarity)
    except (ValueError,TypeError):raise RemoteError(400,'畫面格式、尺寸或大小不正確') from None
    with server.remote_lock:
        memory=server.remote_memory.setdefault(sid,{})
        if is_admin_session(db,sid):
            previous=memory.get('desktop_generation',0);generation=body['desktop_generation']
            same_epoch=memory.get('desktop_epoch')==body['desktop_epoch']
            # Random epoch IDs cannot order delayed media. A monotonic counter
            # also survives pause (which clears pixels/ACK but not this fence).
            if generation<previous or generation==previous and not same_epoch or generation>previous and same_epoch:
                return {'status':'active','commands':[],'resync':True}
            if generation>previous:
                memory.pop('commands',None);memory.pop('presented_epoch',None)
                memory['epoch_frame_start']=memory.get('frame_sequence',0)+1
            memory.update(desktop_epoch=body['desktop_epoch'],desktop_generation=generation,desktop=body['desktop'])
        # Pausing invalidates pixels, never the monotonically increasing cursor.
        # Resetting this to 1 would hide the resumed secure desktop from a
        # viewer whose `after` still points to the preceding desktop's frame.
        sequence=memory.get('frame_sequence',memory.get('frame',{}).get('seq',0))+1
        memory['frame_sequence']=sequence
        memory['frame']={**frame,'time':now,'seq':sequence}
        commands=[] if desktop else [a for a in memory.pop('commands',[]) if now-a['time']<2]
    db.execute('UPDATE remote_sessions SET agent_seen=? WHERE id=?',(now,sid))
    return {'status':'active','commands':commands}
