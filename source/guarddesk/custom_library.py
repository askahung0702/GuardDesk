"""Named typed custom items and explainable scope bindings. Protocol 1 is retained.

Bindings are device/group scopes; a person's endpoint is not an AD user policy.
All dry runs are in memory; publishing and audit share the caller's transaction.
"""
import copy
import json
import re
import time
from . import custom_settings as custom
from .management import ManagementError, generation as scope_generation
from .store import Store, canonical, digest

PROTOCOL=2
MIN_VERSION='0.4.39'
KINDS=tuple(custom.DEFAULT)+('documents',)


def install(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS custom_items(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,body TEXT NOT NULL,description TEXT NOT NULL,enabled INTEGER NOT NULL,revision INTEGER NOT NULL,archived INTEGER NOT NULL DEFAULT 0,origin TEXT NOT NULL DEFAULT '',updated REAL NOT NULL,actor TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS custom_item_versions(id TEXT NOT NULL,revision INTEGER NOT NULL,snapshot TEXT NOT NULL,updated REAL NOT NULL,actor TEXT NOT NULL,PRIMARY KEY(id,revision));
    CREATE TABLE IF NOT EXISTS custom_bindings(id TEXT PRIMARY KEY,item_id TEXT NOT NULL REFERENCES custom_items(id),target_type TEXT NOT NULL,target_id TEXT NOT NULL,state TEXT NOT NULL,priority INTEGER NOT NULL,mode TEXT NOT NULL,revision INTEGER NOT NULL,updated REAL NOT NULL,actor TEXT NOT NULL,UNIQUE(item_id,target_type,target_id));
    CREATE INDEX IF NOT EXISTS custom_bindings_scope ON custom_bindings(target_type,target_id);
    CREATE TABLE IF NOT EXISTS custom_legacy_imports(scope TEXT NOT NULL,target TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(scope,target));
    CREATE TABLE IF NOT EXISTS custom_migration_notes(scope TEXT NOT NULL,target TEXT NOT NULL,revision INTEGER NOT NULL,message TEXT NOT NULL,PRIMARY KEY(scope,target));
    ''')
    for row in db.execute('SELECT * FROM custom_settings').fetchall():
        try:import_legacy_profile(db,row['scope'],row['target'],row['revision'],json.loads(row['body']),row['actor'],row['updated'])
        except ManagementError:
            # A rollback to an older Server may have edited its old profile.
            # Do not overwrite newer named items or prevent Server startup.
            db.execute('INSERT OR REPLACE INTO custom_migration_notes VALUES(?,?,?,?)',(row['scope'],row['target'],row['revision'],'偵測到舊版來源有新修改；保留目前設定庫，未覆寫新版項目。舊 profile 與歷史仍保留，請核對回退期間的變更。'))
            db.execute('INSERT OR REPLACE INTO custom_legacy_imports VALUES(?,?,?)',(row['scope'],row['target'],row['revision']))


def uid(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{24}',value):raise ManagementError(400,'項目／指派識別碼不正確')
    return value


def bump(db):db.execute("UPDATE control_meta SET value=value+1 WHERE key='custom_generation'")


def row_item(row):
    value=dict(row);value['body']=json.loads(value['body']);value['enabled']=bool(value['enabled']);return value


def state(db):
    return {'items':{r['id']:row_item(r) for r in db.execute('SELECT * FROM custom_items WHERE archived=0')},'bindings':[dict(r) for r in db.execute('SELECT * FROM custom_bindings')],'groups':{r['id']:dict(r) for r in db.execute('SELECT id,parent_id,name FROM endpoint_groups')}}


def save_snapshot(db,item):
    db.execute('INSERT INTO custom_item_versions VALUES(?,?,?,?,?)',(item['id'],item['revision'],canonical(item),item['updated'],item['actor']))


def import_legacy_profile(db,scope,target,revision,body,actor,stamp):
    old=db.execute('SELECT revision FROM custom_legacy_imports WHERE scope=? AND target=?',(scope,target)).fetchone()
    if old and old[0]>=revision:return
    names={'schedules':'排程','network':'網路','compatibility':'相容性例外','software':'軟體限制'}
    # Validate the whole profile before any writes so a conflict cannot leave
    # a half-imported group when startup deliberately preserves newer items.
    for kind in custom.DEFAULT:
        iid=digest('legacy-custom|'+scope+'|'+target+'|'+kind)[:24]
        existing=db.execute('SELECT origin FROM custom_items WHERE id=?',(iid,)).fetchone()
        if existing and existing['origin']!='legacy:'+scope+':'+target:raise ManagementError(409,'舊設定已在新版設定庫修改，請使用新版設定庫管理')
    for kind in custom.DEFAULT:
        iid=digest('legacy-custom|'+scope+'|'+target+'|'+kind)[:24]
        existing=db.execute('SELECT * FROM custom_items WHERE id=?',(iid,)).fetchone()
        if existing and existing['origin']!='legacy:'+scope+':'+target:raise ManagementError(409,'舊設定已在新版設定庫修改，請使用新版設定庫管理')
        if kind not in body:
            db.execute('DELETE FROM custom_bindings WHERE item_id=?',(iid,))
            if existing:db.execute('UPDATE custom_items SET archived=1 WHERE id=?',(iid,))
            continue
        name='舊設定・'+names[kind]+'・'+('全體' if scope=='global' else target[:40])
        item={'id':iid,'name':name,'kind':kind,'body':body[kind],'description':'由原自訂設定匯入，保留整分類取代及空清單效果。','enabled':True,'revision':existing['revision']+1 if existing else 1,'archived':0,'origin':'legacy:'+scope+':'+target,'updated':stamp,'actor':actor}
        db.execute('INSERT OR REPLACE INTO custom_items VALUES(?,?,?,?,?,?,?,?,?,?,?)',(iid,name,kind,canonical(item['body']),item['description'],1,item['revision'],0,item['origin'],stamp,actor))
        save_snapshot(db,item)
        aid=digest('legacy-custom-binding|'+iid)[:24]
        binding=db.execute('SELECT revision FROM custom_bindings WHERE id=?',(aid,)).fetchone()
        db.execute('INSERT OR REPLACE INTO custom_bindings VALUES(?,?,?,?,?,?,?,?,?,?)',(aid,iid,scope,target,'apply',0,'replace',binding[0]+1 if binding else 1,stamp,actor))
    db.execute('INSERT OR REPLACE INTO custom_legacy_imports VALUES(?,?,?)',(scope,target,revision));bump(db)


def chain(data,device):
    result=[];gid=device.get('group_id')
    while gid:
        if gid in result or len(result)>=8 or gid not in data['groups']:raise ManagementError(409,'群組階層不完整')
        result.append(gid);gid=data['groups'][gid]['parent_id']
    return [('global','')]+[('group',g) for g in reversed(result)]+[('device',device['id'])]


def resolve(db,device,data=None):
    data=data or state(db);layers=chain(data,device);ranks={value:i for i,value in enumerate(layers)}
    selected={};excluded={};overridden=[]
    matches=[a for a in data['bindings'] if (a['target_type'],a['target_id']) in ranks and a['item_id'] in data['items']]
    matches.sort(key=lambda a:(ranks[(a['target_type'],a['target_id'])],0 if a['mode']=='replace' else 1,a['priority'],a['id']))
    for binding in matches:
        iid=binding['item_id'];item=data['items'][iid];rank=ranks[(binding['target_type'],binding['target_id'])]
        source={**binding,'name':item['name'],'kind':item['kind'],'item_revision':item['revision'],'rank':rank}
        if binding['state']=='exclude':
            selected.pop(iid,None);excluded[iid]=source;continue
        if not item['enabled']:selected.pop(iid,None);continue
        excluded.pop(iid,None)
        if binding['mode']=='replace':
            for old_id in [key for key,value in selected.items() if value['kind']==item['kind']]:overridden.append(selected.pop(old_id))
        selected[iid]=source
    result=copy.deepcopy(custom.DEFAULT);documents=[]
    active=list(selected.values());networks=[a for a in active if a['kind']=='network']
    if networks:
        score=max((a['rank'],a['priority']) for a in networks);winners=[a for a in networks if (a['rank'],a['priority'])==score]
        if len({canonical(data['items'][a['item_id']]['body']) for a in winners})>1:raise ManagementError(409,'網路設定衝突：'+ '、'.join(a['name'] for a in winners[:5])+'；請調整指派優先序或排除其中一項')
        result['network']=copy.deepcopy(data['items'][winners[-1]['item_id']]['body'])
        losing=[a for a in networks if a not in winners]
        overridden.extend({**a,'reason':'network_priority'} for a in losing)
        active=[a for a in active if a not in losing]
    for source in active:
        item=data['items'][source['item_id']];kind=item['kind']
        if kind=='network':continue
        for rule in item['body']:
            rule=copy.deepcopy(rule)
            if kind=='schedules' and not item['origin'].startswith(('legacy:','edited-legacy:')):rule['id']=digest(item['id']+'|'+rule['id'])[:32]
            destination=documents if kind=='documents' else result[kind]
            if rule not in destination:destination.append(rule)
    try:custom.validate(result)
    except ValueError as exc:raise ManagementError(409,'有效設定衝突／超限：'+str(exc)) from None
    from . import document_settings
    try:document_packet=document_settings.packet(documents)
    except ValueError as exc:raise ManagementError(409,'文件稽核設定衝突／超限：'+str(exc)) from None
    return {'protocol':PROTOCOL,'schema':'named-items-v1','minimum_version':'0.4.49' if documents else MIN_VERSION,'device_id':device['id'],'generation':custom.generation(db),'body':result,'documents':document_packet,'sources':active,'excluded':list(excluded.values()),'overridden':overridden,'fingerprint':digest(canonical(result))}


def target(db,kind,value):
    scope,value=custom.scope_input(db,{'scope':kind,'target':value})
    return scope,value


def devices(db):return [dict(r) for r in db.execute('SELECT id,name,group_id,inventory FROM devices WHERE revoked=0')]


def validate_item(request,data):
    if not isinstance(request,dict) or set(request)!={'id','name','kind','body','description','enabled','revision'}:raise ManagementError(400,'設定項目欄位不正確')
    iid=uid(request['id']);old=data['items'].get(iid)
    if type(request['revision']) is not int or request['revision']!=(old['revision'] if old else 0):raise ManagementError(409,'項目已更新，請重新載入；未覆寫草稿')
    if old and request['kind']!=old['kind']:raise ManagementError(400,'已建立項目的分類不可更換，請複製為新項目')
    kind=request['kind']
    if not isinstance(kind,str) or kind not in KINDS:raise ManagementError(400,'設定分類不正確')
    try:
        custom.text(request['name'],100)
        if kind=='documents':
            from .document_settings import validate
            validate(request['body'])
        else:custom.validate({**copy.deepcopy(custom.DEFAULT),kind:request['body']})
    except ValueError as exc:raise ManagementError(400,str(exc)) from None
    if not isinstance(request['description'],str) or len(request['description'])>1000 or type(request['enabled']) is not bool:raise ManagementError(400,'說明或啟用狀態不正確')
    if not old and len(data['items'])>=512:raise ManagementError(400,'設定庫最多 512 個項目')
    if not old and kind!='network' and not request['body']:raise ManagementError(400,'請至少新增一條規則；暫停請使用項目啟用開關')
    if any(r['id']!=iid and r['name'].casefold()==request['name'].strip().casefold() for r in data['items'].values()):raise ManagementError(409,'設定名稱已存在')
    origin=('edited-'+old['origin']) if old and old['origin'].startswith('legacy:') else old['origin'] if old else ''
    return {**request,'name':request['name'].strip(),'revision':request['revision']+1,'origin':origin,'archived':0,'updated':time.time(),'actor':''}


def candidate(db,request,actor=''):
    if not isinstance(request,dict) or request.get('op') not in ('save_item','binding','remove_binding','archive'):raise ManagementError(400,'自訂設定庫操作不正確')
    if set(request)-{'op','item','binding','id','revision','expected_generation','expected_scope_generation','confirm','network_ack'}:raise ManagementError(400,'不支援的設定庫欄位')
    before=state(db);after=copy.deepcopy(before);op=request['op'];value=None
    if op=='save_item':
        if isinstance(request.get('item'),dict):uid(request['item'].get('id'))
        if isinstance(request.get('item'),dict) and request['item'].get('id') not in after['items'] and db.execute('SELECT 1 FROM custom_items WHERE id=?',(request['item'].get('id'),)).fetchone():raise ManagementError(409,'封存項目的識別碼不可重用；請建立新項目')
        value=validate_item(request.get('item'),after);value['actor']=actor;after['items'][value['id']]=value
    elif op=='binding':
        value=request.get('binding')
        keys={'id','item_id','target_type','target_id','state','priority','mode','revision'}
        if not isinstance(value,dict) or set(value)!=keys:raise ManagementError(400,'指派欄位不正確')
        value=copy.deepcopy(value);uid(value['id']);uid(value['item_id'])
        if value['item_id'] not in after['items']:raise ManagementError(404,'找不到設定項目')
        value['target_type'],value['target_id']=target(db,value['target_type'],value['target_id'])
        old=next((r for r in after['bindings'] if r['id']==value['id']),None)
        if type(value['revision']) is not int or value['revision']!=(old['revision'] if old else 0):raise ManagementError(409,'指派已更新，請重新載入')
        if value['state'] not in ('apply','exclude') or value['mode'] not in ('merge','replace') or type(value['priority']) is not int or not 0<=value['priority']<=1000:raise ManagementError(400,'指派狀態／優先序不正確')
        if value['mode']=='replace' and (not old or old['mode']!='replace' or old['item_id']!=value['item_id']):raise ManagementError(400,'只有遷移的舊指派可保留整分類取代；新項目以逐項方式管理')
        if not old and len(after['bindings'])>=2048:raise ManagementError(400,'最多 2048 筆自訂指派')
        if any(r['id']!=value['id'] and (r['item_id'],r['target_type'],r['target_id'])==(value['item_id'],value['target_type'],value['target_id']) for r in after['bindings']):raise ManagementError(409,'這個對象已有此項指派，請編輯或恢復繼承')
        value.update(revision=value['revision']+1,updated=time.time(),actor=actor)
        after['bindings']=[r for r in after['bindings'] if r['id']!=value['id']]+[value]
    else:
        uid(request.get('id'));old=after['items'].get(request['id']) if op=='archive' else next((r for r in after['bindings'] if r['id']==request['id']),None)
        if not old:raise ManagementError(404,'找不到項目或指派')
        if type(request.get('revision')) is not int or request['revision']!=old['revision']:raise ManagementError(409,'資料已更新，請重新載入')
        if op=='archive':
            if any(r['item_id']==request['id'] for r in after['bindings']):raise ManagementError(409,'請先移除所有指派；要暫停全部對象請停用項目')
            after['items'].pop(request['id'])
        else:after['bindings']=[r for r in after['bindings'] if r['id']!=request['id']]
        value=old
    return before,after,value


def preview(db,request):
    before,after,value=candidate(db,request);changed=[]
    from .management import ControlPlane
    from .category_rules import merge_publishers
    plane=ControlPlane(db)
    for device in devices(db):
        old=resolve(db,device,before);new=resolve(db,device,after)
        merge_publishers(new['body']['software'],plane.resolve(device)['body']['application_publishers'])
        if old['fingerprint']!=new['fingerprint'] or old['documents']['fingerprint']!=new['documents']['fingerprint']:
            inventory=json.loads(device['inventory'])
            changed.append({'id':device['id'],'name':device['name'],'agent_version':inventory.get('agent_version','unknown'),'changed':[k for k in custom.DEFAULT if old['body'][k]!=new['body'][k]]+(['documents'] if old['documents']['fingerprint']!=new['documents']['fingerprint'] else [])})
    # Validate every assigned scope even when no endpoint is enrolled yet.
    for group in after['groups']:
        device={'id':'preview-unenrolled','group_id':group}
        merge_publishers(resolve(db,device,after)['body']['software'],plane.resolve(device)['body']['application_publishers'])
    device={'id':'preview-unenrolled','group_id':None}
    merge_publishers(resolve(db,device,after)['body']['software'],plane.resolve(device)['body']['application_publishers'])
    network_change=any('network' in d['changed'] for d in changed)
    document_change=value.get('kind')=='documents' or after['items'].get(value.get('item_id'),{}).get('kind')=='documents' or any('documents' in d['changed'] for d in changed)
    if request['op']=='save_item' and value['kind']=='network' and value['body']['ipv6']!='unchanged':network_change=True
    if request['op']=='binding' and after['items'][value['item_id']]['kind']=='network' and value['state']=='apply' and after['items'][value['item_id']]['body']['ipv6']!='unchanged':network_change=True
    return {'generation':custom.generation(db),'scope_generation':scope_generation(db),'affected_count':len(changed),'devices':changed[:50],'minimum_version':'0.4.49' if document_change else MIN_VERSION,'network_ack_required':network_change,'op':request['op'],'summary':value.get('name') or after['items'].get(value.get('item_id'),{}).get('name',value['id'])}


def publish(db,request,actor):
    result=preview(db,request)
    if type(request.get('expected_generation')) is not int or request['expected_generation']!=result['generation'] or type(request.get('expected_scope_generation')) is not int or request['expected_scope_generation']!=result['scope_generation']:raise ManagementError(409,'內容或群組範圍已改變，請重新預覽')
    if request.get('confirm')!='publish_custom_library':raise ManagementError(400,'請確認發布自訂設定')
    if result['network_ack_required'] and request.get('network_ack') is not True:raise ManagementError(400,'請先核對 IPv4 管理通道、DNS／AD／VPN 與重啟安排')
    _,_,value=candidate(db,request,actor);op=request['op']
    if op=='save_item':
        db.execute('INSERT INTO custom_items VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,body=excluded.body,description=excluded.description,enabled=excluded.enabled,revision=excluded.revision,origin=excluded.origin,updated=excluded.updated,actor=excluded.actor',(value['id'],value['name'],value['kind'],canonical(value['body']),value['description'],int(value['enabled']),value['revision'],0,value['origin'],value['updated'],actor));save_snapshot(db,value)
    elif op=='binding':
        db.execute('INSERT INTO custom_bindings VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET item_id=excluded.item_id,target_type=excluded.target_type,target_id=excluded.target_id,state=excluded.state,priority=excluded.priority,mode=excluded.mode,revision=excluded.revision,updated=excluded.updated,actor=excluded.actor',tuple(value[k] for k in ('id','item_id','target_type','target_id','state','priority','mode','revision','updated','actor')))
    elif op=='remove_binding':db.execute('DELETE FROM custom_bindings WHERE id=?',(request['id'],))
    else:db.execute('UPDATE custom_items SET archived=1,enabled=0 WHERE id=?',(request['id'],))
    bump(db)
    Store.event(db,'console','custom_library.'+op,'warning',{'actor':actor,'id':value['id'],'name':result['summary'],'affected_count':result['affected_count']})
    return {'ok':True,'generation':custom.generation(db),'id':value['id']}


def catalog(db):
    data=state(db);cache={};reports=[]
    by_device={r['id']:dict(r) for r in db.execute('SELECT id,name,group_id FROM devices')}
    for row in db.execute('SELECT * FROM custom_status ORDER BY device_id,role'):
        row=dict(row);body=json.loads(row['body']);row['body']=body;did=row['device_id']
        if did not in by_device:continue
        if did not in cache:
            try:cache[did]=resolve(db,by_device[did],data)
            except ManagementError:cache[did]=None
        resolved=cache[did]
        doc_rules=resolved['documents']['rules'] if resolved else []
        row['minimum_version']='0.4.49' if doc_rules else MIN_VERSION
        row['matches_current']=body.get('protocol')==PROTOCOL and bool(resolved) and body['fingerprint']==resolved['fingerprint']
        row['needs_upgrade']=body.get('protocol')!=PROTOCOL or tuple(int(x) for x in body['version'].split('.'))<((0,4,49) if doc_rules else (0,4,39))
        if doc_rules:
            ext=db.execute('SELECT body,received FROM extended_status WHERE device_id=?',(did,)).fetchone()
            status=json.loads(ext['body']) if ext else {}
            row['document_state']=status.get('document_provisioning',{}).get('status','not_reported')
            row['matches_documents']=bool(ext and 0<=time.time()-ext['received']<=180 and status.get('document_fingerprint')==resolved['documents']['fingerprint'] and status.get('document_applied') is True)
            row['matches_current']=row['matches_current'] and not row['needs_upgrade'] and row['matches_documents']
        reports.append(row)
    notes=[dict(r) for r in db.execute('SELECT * FROM custom_migration_notes ORDER BY scope,target')]
    return {'items':list(data['items'].values()),'bindings':data['bindings'],'reports':reports,'migration_notes':notes,'generation':custom.generation(db),'scope_generation':scope_generation(db),'minimum_version':MIN_VERSION,'server_time':time.time()}


def history(db,iid):
    uid(iid)
    return {'versions':[json.loads(r[0]) for r in db.execute('SELECT snapshot FROM custom_item_versions WHERE id=? ORDER BY revision DESC LIMIT 50',(iid,))]}


def target_view(db,scope,target_id):
    scope,target_id=target(db,scope,target_id)
    device={'id':target_id if scope=='device' else 'preview-unenrolled','group_id':target_id if scope=='group' else None}
    if scope=='device':device=dict(db.execute('SELECT id,group_id,name FROM devices WHERE id=?',(target_id,)).fetchone())
    return resolve(db,device)


def validate_groups(db):
    data=state(db)
    from .management import ControlPlane
    from .category_rules import merge_publishers
    plane=ControlPlane(db)
    for device in devices(db)+[{'id':'preview-unenrolled','group_id':g} for g in (None,*data['groups'])]:
        settings=resolve(db,device,data)
        merge_publishers(settings['body']['software'],plane.resolve(device)['body']['application_publishers'])
