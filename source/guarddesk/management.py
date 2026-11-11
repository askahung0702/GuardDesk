"""Named policies, explicit scope resolution, and explainable management APIs."""
import copy
import json
import re
import secrets
import sqlite3
import time
from urllib.parse import parse_qs,urlsplit
from .policy import DEFAULT_POLICY,validate_policy
from .store import Store,canonical,digest
from .policy_operations import apply_operations,validate_operations,policy_keys,get_value,PATHS

EXPORT_KEYS={'mode','allow_export','blocked_extensions','keywords','max_export_mb'}
USER_KEYS=EXPORT_KEYS|{'browser_audit'}


class ManagementError(Exception):
    def __init__(self,status,message):self.status,self.message=status,message


def text(value,label,limit=120):
    if not isinstance(value,str) or not value.strip() or len(value)>limit or any(ord(c)<32 for c in value):raise ManagementError(400,label+'不正確')
    return value.strip()


def principal(value):
    value=text(value,'Windows 帳號',240)
    if not re.fullmatch(r'[^\\/]+\\[^\\/]+',value):raise ManagementError(400,'Windows 帳號請使用 DOMAIN\\account 格式')
    return value.casefold()


def generation(db):return db.execute("SELECT value FROM control_meta WHERE key='generation'").fetchone()[0]


def bump(db):
    db.execute("UPDATE control_meta SET value=value+1 WHERE key='generation'")
    return generation(db)


def validate_overrides(value):
    if not isinstance(value,dict) or not value or not set(value)<=set(DEFAULT_POLICY):raise ManagementError(400,'至少選擇一項支援的策略設定')
    validate_policy({**copy.deepcopy(DEFAULT_POLICY),**value})
    return value


class ControlPlane:
    def __init__(self,db):
        self.db=db
        self.baseline=Store.policy(db)
        self.version=generation(db)
        self.groups={r['id']:dict(r) for r in db.execute('SELECT * FROM endpoint_groups ORDER BY name COLLATE NOCASE')}
        self.sets={r['id']:dict(r) for r in db.execute('SELECT * FROM policy_sets WHERE archived=0 ORDER BY name COLLATE NOCASE')}
        for item in self.sets.values():
            item['overrides']=json.loads(item['overrides']);item['operations']=json.loads(item.get('operations','[]'))
        from .category_library import rows,compile_policy
        self.categories=rows(db,published=True)
        for item in self.sets.values():
            item['category_refs']=json.loads(item.get('category_refs','{}'))
            compile_policy(item,self.categories)
        self.assignments=[dict(r) for r in db.execute('SELECT * FROM policy_assignments ORDER BY created,id')]

    def chain(self,group_id):
        result=[];seen=set()
        while group_id:
            if group_id in seen:raise ManagementError(400,'群組不能移到自己的子群組，否則會形成循環')
            if group_id not in self.groups:raise ManagementError(409,'群組階層不完整')
            seen.add(group_id);result.append(self.groups[group_id]);group_id=result[-1]['parent_id']
            if len(result)>8:raise ManagementError(400,'群組最多 8 層')
        return list(reversed(result))

    def resolve(self,device,account=None):
        body=copy.deepcopy(self.baseline['body'])
        chain=self.chain(device.get('group_id'))
        ranks={g['id']:10+i for i,g in enumerate(chain)}
        account=principal(account) if account else None
        layers=[]
        for assignment in self.assignments:
            policy=self.sets.get(assignment['set_id'])
            if not assignment['enabled'] or not policy or not policy['enabled']:continue
            kind,target=assignment['target_type'],assignment['target_id']
            if kind=='global':rank=0;scope='全部端點'
            elif kind=='group' and target in ranks:rank=ranks[target];scope=self.groups[target]['name']
            elif kind=='device' and target==device['id']:rank=100;scope=device['name']
            elif kind=='user' and account and target==account:rank=200;scope=account
            else:continue
            layers.append((rank,assignment['priority'],assignment['created'],assignment['id'],assignment,policy,scope))
        layers.sort(key=lambda item:item[:4])
        baseline={'kind':'baseline','name':'全域預設','revision':self.baseline['version'],'scope':'全部端點','priority':0,'assignment_id':None,'rank':-1}
        sources=[{**baseline,'fields':list(body)}]
        field_sources={key:baseline.copy() for key in body};conflicts=[]
        setting_sources={key:baseline.copy() for key in PATHS}
        for rank,priority,_,aid,assignment,policy,scope in layers:
            from .category_library import compile_policy
            policy,category_sources=compile_policy(policy,self.categories)
            source={'category_sources':category_sources,'kind':assignment['target_type'],'name':policy['name'],'revision':policy['revision'],'scope':scope,'priority':priority,'assignment_id':aid,'set_id':policy['id'],'rank':rank,'assigned_at':assignment['created']}
            for key,value in policy['overrides'].items():
                old=field_sources[key]
                if old['rank']==rank and old['priority']==priority and body[key]!=value:
                    conflicts.append({'field':key,'previous':old['name'],'winner':policy['name'],'reason':'同層同優先序，後建立的指派覆寫','previous_assignment':old['assignment_id'],'winner_assignment':aid})
                body[key]=copy.deepcopy(value);field_sources[key]=source.copy()
                for path in PATHS:
                    if path.split('.')[0]==key:setting_sources[path]=source.copy()
            for operation in policy.get('operations',[]):
                path=operation['path'];old=setting_sources[path]
                updated=apply_operations(body,[operation],validate=False)
                if old['rank']==rank and old['priority']==priority and get_value(body,path)!=get_value(updated,path):
                    conflicts.append({'field':path,'previous':old['name'],'winner':policy['name'],'reason':'同層同優先序欄位覆寫','previous_assignment':old['assignment_id'],'winner_assignment':aid})
                body=updated;setting_sources[path]={**source,'operation':operation['op']}
                field_sources[path.split('.')[0]]=source.copy()
            sources.append({**source,'fields':list(policy['overrides'])+[op['path'] for op in policy.get('operations',[])]})
        validate_policy(body)
        result={'version':self.version,'base_version':self.baseline['version'],'body':body,'sources':sources,'field_sources':field_sources,'setting_sources':setting_sources,'conflicts':conflicts,'group_path':[g['name'] for g in chain]}
        result['fingerprint']=digest(canonical({'body':body,'sources':sources,'account':account}))
        return result

    def bundle(self,device):
        result=self.resolve(device)
        assets=device.get('inventory',{})
        if isinstance(assets,str):assets=json.loads(assets)
        accounts=assets.get('user_accounts',[])
        if not isinstance(accounts,list):accounts=[]
        users={}
        for account in accounts[:32]:
            try:key=principal(account)
            except ManagementError:continue
            if any(a['target_type']=='user' and a['target_id']==key and a['enabled'] for a in self.assignments):users[key]=self.resolve(device,key)
        result['user_policies']=users
        result['fingerprint']=digest(canonical({'machine':result['fingerprint'],'users':{k:v['fingerprint'] for k,v in sorted(users.items())}}))
        return result

    def catalog(self,devices):
        groups=[]
        for group in self.groups.values():
            members=[d for d in devices if group['id'] in [g['id'] for g in self.chain(d.get('group_id'))]]
            groups.append({**group,'path':[g['name'] for g in self.chain(group['id'])],'device_count':len(members),'online_count':sum(d.get('status')=='online' for d in members)})
        sets=[]
        for policy in self.sets.values():sets.append({**policy,'assignment_count':sum(a['set_id']==policy['id'] for a in self.assignments),'user_compatible':policy_keys(policy)<=USER_KEYS})
        assignments=[]
        for item in self.assignments:
            target=item['target_id'];kind=item['target_type']
            label='全部端點' if kind=='global' else self.groups.get(target,{}).get('name',target) if kind=='group' else next((d['name'] for d in devices if d['id']==target),target) if kind=='device' else target
            policy=self.sets.get(item['set_id'],{})
            assignments.append({**item,'target_label':label,'set_name':policy.get('name','已封存策略'),'set_enabled':policy.get('enabled',0),'set_revision':policy.get('revision',0)})
        accounts=set()
        for d in devices:
            assets=d.get('inventory',{})
            if isinstance(assets,str):assets=json.loads(assets)
            for account in assets.get('user_accounts',[])[:32] if isinstance(assets.get('user_accounts'),list) else []:
                if isinstance(account,str):accounts.add(account)
        return {'generation':self.version,'groups':groups,'policy_sets':sets,'assignments':assignments,'known_users':sorted(accounts)[:400]}


def devices_for_management(db):
    result=[]
    for row in db.execute('SELECT id,name,group_id,inventory,revoked,last_seen FROM devices'):
        item=dict(row);item['inventory']=json.loads(item['inventory']);result.append(item)
    return result


def check_revision(body,row):
    if type(body.get('revision')) is not int or body['revision']!=row['revision']:raise ManagementError(409,'資料已被其他管理員修改，請重新整理')


def save_group(db,body,actor):
    name=text(body.get('name'),'群組名稱',80);parent=body.get('parent_id') or None
    group_id=body.get('id');plane=ControlPlane(db)
    if parent and parent not in plane.groups:raise ManagementError(404,'找不到父群組')
    if group_id:
        old=plane.groups.get(group_id)
        if not old:raise ManagementError(404,'找不到群組')
        check_revision(body,old)
        db.execute('UPDATE endpoint_groups SET name=?,parent_id=?,revision=revision+1 WHERE id=?',(name,parent,group_id))
    else:
        if len(plane.groups)>=200:raise ManagementError(400,'試用版最多 200 個群組')
        group_id=secrets.token_hex(12)
        db.execute('INSERT INTO endpoint_groups VALUES (?,?,?,1,?)',(group_id,name,parent,time.time()))
    changed=ControlPlane(db)
    for key in changed.groups:changed.chain(key)
    validate_active_combinations(db)
    bump(db);Store.event(db,'console','group.saved','info',{'actor':actor,'id':group_id,'name':name,'parent_id':parent})
    return changed.groups[group_id]


def save_set(db,body,actor,dry_run=False):
    name=text(body.get('name'),'策略名稱',100);description=body.get('description','')
    if not isinstance(description,str) or len(description)>1000:raise ManagementError(400,'說明最多 1000 字')
    sid=body.get('id');old=db.execute('SELECT * FROM policy_sets WHERE id=? AND archived=0',(sid,)).fetchone() if sid else None
    if sid and not old:raise ManagementError(404,'找不到策略集')
    overrides=body.get('overrides',{})
    from .category_library import validate_refs,rows,compile_policy
    refs=validate_refs(body.get('category_refs',json.loads(old['category_refs']) if old else {}),rows(db,published=True))
    compiled,_=compile_policy({'overrides':overrides,'category_refs':refs},rows(db,published=True))
    if overrides:validate_overrides(compiled['overrides'])
    elif overrides!={}:raise ManagementError(400,'策略覆寫結構不正確')
    operations=validate_operations(body.get('operations',json.loads(old['operations']) if old else []),compiled['overrides'])
    if not overrides and not operations:raise ManagementError(400,'至少設定一個欄位')
    enabled=body.get('enabled',True)
    if type(enabled) is not bool:raise ManagementError(400,'啟用狀態不正確')
    keys=set(overrides)|{op['path'].split('.')[0] for op in operations};now=time.time()
    if sid:
        check_revision(body,old)
        if not keys<=USER_KEYS and db.execute("SELECT 1 FROM policy_assignments WHERE set_id=? AND target_type='user'",(sid,)).fetchone():raise ManagementError(400,'此策略已有個人指派，不能加入機器層控制')
    if dry_run:
        return {'id':sid or 'preview-new','name':name,'description':description,'revision':old['revision']+1 if old else 1,'enabled':int(enabled),'archived':0,'overrides':overrides,'operations':operations,'category_refs':refs,'created':now,'actor':actor}

    if sid:
        check_revision(body,old);revision=old['revision']+1
        if not keys<=USER_KEYS and db.execute("SELECT 1 FROM policy_assignments WHERE set_id=? AND target_type='user'",(sid,)).fetchone():raise ManagementError(400,'此策略已有個人指派，不能加入機器層控制')
        db.execute('UPDATE policy_sets SET name=?,description=?,revision=?,enabled=?,overrides=?,operations=?,created=?,actor=? WHERE id=?',(name,description,revision,int(enabled),canonical(overrides),canonical(operations),now,actor,sid))
    else:
        if db.execute('SELECT count(*) FROM policy_sets WHERE archived=0').fetchone()[0]>=100:raise ManagementError(400,'試用版最多 100 個策略集')
        sid=secrets.token_hex(12);revision=1
        db.execute('INSERT INTO policy_sets(id,name,description,revision,enabled,overrides,operations,created,actor) VALUES (?,?,?,?,?,?,?,?,?)',(sid,name,description,revision,int(enabled),canonical(overrides),canonical(operations),now,actor))
    db.execute('INSERT INTO policy_set_versions(set_id,revision,name,description,enabled,overrides,operations,created,actor) VALUES (?,?,?,?,?,?,?,?,?)',(sid,revision,name,description,int(enabled),canonical(overrides),canonical(operations),now,actor))
    db.execute('UPDATE policy_sets SET category_refs=? WHERE id=?',(canonical(refs),sid))
    db.execute('UPDATE policy_set_versions SET category_refs=? WHERE set_id=? AND revision=?',(canonical(refs),sid,revision))
    db.execute('DELETE FROM policy_category_refs WHERE set_id=?',(sid,))
    db.executemany('INSERT INTO policy_category_refs VALUES(?,?,?,?)',[(sid,use,r['id'],int(r['include_descendants'])) for use,items in refs.items() for r in items])
    validate_active_combinations(db)
    bump(db);Store.event(db,'console','policy_set.published','warning',{'actor':actor,'set_id':sid,'name':name,'revision':revision,'overrides':overrides,'operations':operations,'enabled':enabled})
    return {'id':sid,'revision':revision,'generation':generation(db)}


def validate_active_combinations(db):
    plane=ControlPlane(db)
    for group in (None,*plane.groups):plane.resolve({'id':'preview-unenrolled','group_id':group})
    for device in devices_for_management(db):
        if not device['revoked']:plane.bundle(device)
    if db.execute('SELECT 1 FROM custom_bindings LIMIT 1').fetchone():
        from .custom_library import validate_groups
        validate_groups(db)


def assignment_input(db,body):
    plane=ControlPlane(db);sid=body.get('set_id');policy=plane.sets.get(sid)
    if not policy:raise ManagementError(404,'找不到策略集')
    kind=body.get('target_type');target=body.get('target_id','')
    if kind=='global':target=''
    elif kind=='group':
        if target not in plane.groups:raise ManagementError(404,'找不到群組')
    elif kind=='device':
        if not db.execute('SELECT 1 FROM devices WHERE id=? AND revoked=0',(target,)).fetchone():raise ManagementError(404,'找不到有效端點')
    elif kind=='user':
        target=principal(target)
        if not policy_keys(policy)<=USER_KEYS:raise ManagementError(400,'個人指派目前支援外發規則及網址稽核；USB／檔案／上傳模組請指派到端點或群組')
    else:raise ManagementError(400,'指派對象必須是全域、群組、端點或使用者')
    priority=body.get('priority',100);enabled=body.get('enabled',True)
    if type(priority) is not int or not 0<=priority<=1000 or type(enabled) is not bool:raise ManagementError(400,'優先序須為 0–1000')
    return {'set_id':sid,'target_type':kind,'target_id':target,'priority':priority,'enabled':int(enabled)}


def assignment_preview(db,body):
    item=assignment_input(db,body);plane=ControlPlane(db);devices=devices_for_management(db)
    kind,target=item['target_type'],item['target_id'];matches=[]
    for device in devices:
        if device['revoked']:continue
        accounts=[a.casefold() for a in device['inventory'].get('user_accounts',[]) if isinstance(a,str)]
        if kind=='global' or (kind=='device' and target==device['id']) or (kind=='group' and target in [g['id'] for g in plane.chain(device.get('group_id'))]) or (kind=='user' and target in accounts):matches.append(device)
    from .policy_preview import assignment_after,compare_planes
    result=compare_planes(plane,assignment_after(plane,item,body.get('id')),matches,target if kind=='user' else None,preview_offset(body),50)
    result.update(effective_affected_count=result['affected_count'],affected_count=len(matches),assignment=item,generation=plane.version,scope_count=len(matches),devices=[{'id':d['id'],'name':d['name']} for d in matches[:20]],fields=list(policy_keys(plane.sets[item['set_id']])),note='個人指派也會在該帳號之後登入並回報的端點生效' if kind=='user' else '群組包含全部子群組；離線端點恢復連線後接收')
    return result


def preview_offset(body):
    value=body.get('preview_offset',0)
    if type(value) is not int or not 0<=value<=100000:raise ManagementError(400,'預覽分頁不正確')
    return value


def set_preview(db,body,actor):
    import copy
    from .policy_preview import compare_planes
    draft=save_set(db,body,actor,dry_run=True);before=ControlPlane(db);after=copy.copy(before)
    after.sets={**before.sets,draft['id']:draft}
    devices=devices_for_management(db)
    # Preview every known personal assignment as a separate scope, rather than
    # misleadingly showing a machine-only comparison for personal policies.
    accounts={a['target_id'] for a in before.assignments if a['set_id']==draft['id'] and a['target_type']=='user'}
    result=compare_planes(before,after,devices,None,preview_offset(body),50)
    result['personal_scope_count']=len(accounts)
    account=body.get('preview_account')
    if account is not None and account not in accounts:raise ManagementError(400,'找不到此個人指派範圍')
    result['personal_accounts']=sorted(accounts)
    selected=[account] if account is not None else sorted(accounts)[:1]
    result['personal_scopes']=[{'account':a,**compare_planes(before,after,devices,a,preview_offset(body),50)} for a in selected]
    result.update(generation=before.version,revision=draft['revision'],set_id=draft['id'],assignment_count=sum(a['set_id']==draft['id'] for a in before.assignments))
    return result


def route(db,method,path,body,actor,query_string=''):
    query=parse_qs(query_string)
    if method=='GET' and path=='/api/policy-sets/history':
        sid=query.get('id',[''])[0]
        rows=[dict(r) for r in db.execute('SELECT * FROM policy_set_versions WHERE set_id=? ORDER BY revision DESC',(sid,))]
        for r in rows:
            r['overrides']=json.loads(r['overrides']);r['operations']=json.loads(r.get('operations','[]'));r['category_refs']=json.loads(r.get('category_refs','{}'))
        return {'items':rows}
    if method=='POST' and path=='/api/groups':return save_group(db,body,actor)
    if method=='POST' and path=='/api/groups/delete':
        row=db.execute('SELECT * FROM endpoint_groups WHERE id=?',(body.get('id'),)).fetchone()
        if not row:raise ManagementError(404,'找不到群組')
        check_revision(body,row)
        custom=db.execute("SELECT body FROM custom_settings WHERE scope='group' AND target=?",(row['id'],)).fetchone()
        if db.execute("SELECT 1 FROM custom_bindings WHERE target_type='group' AND target_id=?",(row['id'],)).fetchone():raise ManagementError(409,'請先移除這個群組的自訂設定指派，再刪除群組')
        if custom and json.loads(custom['body']) and not db.execute("SELECT 1 FROM custom_legacy_imports WHERE scope='group' AND target=?",(row['id'],)).fetchone():raise ManagementError(409,'請先將此群組的自訂設定全部改為繼承，再刪除群組')
        if db.execute('SELECT 1 FROM endpoint_groups WHERE parent_id=?',(row['id'],)).fetchone() or db.execute('SELECT 1 FROM devices WHERE group_id=?',(row['id'],)).fetchone() or db.execute("SELECT 1 FROM policy_assignments WHERE target_type='group' AND target_id=?",(row['id'],)).fetchone():raise ManagementError(409,'請先移出子群組／端點，並移除群組指派')
        db.execute("DELETE FROM custom_settings WHERE scope='group' AND target=?",(row['id'],))
        db.execute('DELETE FROM endpoint_groups WHERE id=?',(row['id'],));bump(db)
        Store.event(db,'console','group.deleted','warning',{'actor':actor,'group':dict(row)});return {'ok':True}
    if method=='POST' and path=='/api/devices/move-many':
        items=body.get('items');gid=body.get('group_id') or None
        if not isinstance(items,list) or not 1<=len(items)<=200 or any(not isinstance(item,dict) for item in items):raise ManagementError(400,'請選擇 1–200 台端點')
        if gid and not db.execute('SELECT 1 FROM endpoint_groups WHERE id=?',(gid,)).fetchone():raise ManagementError(404,'找不到群組')
        rows=[];seen=set()
        for item in items:
            row=db.execute('SELECT * FROM devices WHERE id=?',(item.get('id'),)).fetchone()
            if not row or row['id'] in seen:raise ManagementError(400,'端點不存在或重複')
            if type(item.get('revision')) is not int or item['revision']!=row['management_revision']:raise ManagementError(409,'其中端點已被移動；此次批次操作未套用，請重新整理')
            seen.add(row['id']);rows.append(row)
        for row in rows:
            db.execute('UPDATE devices SET group_id=?,management_revision=management_revision+1 WHERE id=?',(gid,row['id']))
            Store.event(db,row['id'],'device.moved','warning',{'actor':actor,'from':row['group_id'],'to':gid,'batch':True})
        validate_active_combinations(db)
        bump(db);return {'ok':True,'moved':len(rows)}
    if method=='POST' and path=='/api/devices/move':
        row=db.execute('SELECT * FROM devices WHERE id=?',(body.get('device_id'),)).fetchone();gid=body.get('group_id') or None
        if not row:raise ManagementError(404,'找不到端點')
        if type(body.get('revision')) is not int or body['revision']!=row['management_revision']:raise ManagementError(409,'端點已被其他管理員移動，請重新整理')
        if gid and not db.execute('SELECT 1 FROM endpoint_groups WHERE id=?',(gid,)).fetchone():raise ManagementError(404,'找不到群組')
        db.execute('UPDATE devices SET group_id=?,management_revision=management_revision+1 WHERE id=?',(gid,row['id']));validate_active_combinations(db);bump(db)
        Store.event(db,row['id'],'device.moved','warning',{'actor':actor,'from':row['group_id'],'to':gid});return {'ok':True}
    if method=='POST' and path=='/api/policy-sets/preview':return set_preview(db,body,actor)
    if method=='POST' and path=='/api/policy-sets':
        if 'expected_generation' in body and body['expected_generation']!=generation(db):raise ManagementError(409,'策略來源已變更，請重新預覽')
        return save_set(db,body,actor)
    if method=='POST' and path=='/api/policy-sets/archive':
        row=db.execute('SELECT * FROM policy_sets WHERE id=? AND archived=0',(body.get('id'),)).fetchone()
        if not row:raise ManagementError(404,'找不到策略集')
        check_revision(body,row)
        if db.execute('SELECT 1 FROM policy_assignments WHERE set_id=?',(row['id'],)).fetchone():raise ManagementError(409,'請先移除所有指派；若要暫停，請停用策略集')
        db.execute('UPDATE policy_sets SET archived=1,enabled=0 WHERE id=?',(row['id'],));bump(db)
        Store.event(db,'console','policy_set.archived','warning',{'actor':actor,'set_id':row['id'],'name':row['name']});return {'ok':True}
    if method=='POST' and path=='/api/assignments/preview':return assignment_preview(db,body)
    if method=='POST' and path=='/api/assignments':
        item=assignment_input(db,body)
        if type(body.get('expected_generation')) is not int or body['expected_generation']!=generation(db):raise ManagementError(409,'指派範圍已改變，請重新預覽')
        aid=body.get('id')
        if aid:
            old=db.execute('SELECT * FROM policy_assignments WHERE id=?',(aid,)).fetchone()
            if not old:raise ManagementError(404,'找不到指派')
            check_revision(body,old)
            db.execute('UPDATE policy_assignments SET set_id=?,target_type=?,target_id=?,priority=?,enabled=?,revision=revision+1 WHERE id=?',(*item.values(),aid))
        else:
            if db.execute('SELECT count(*) FROM policy_assignments').fetchone()[0]>=500:raise ManagementError(400,'試用版最多 500 個指派')
            aid=secrets.token_hex(12)
            db.execute('INSERT INTO policy_assignments VALUES (?,?,?,?,?,?,1,?,?)',(aid,*item.values(),time.time(),actor))
        validate_active_combinations(db)
        bump(db);Store.event(db,'console','assignment.saved','warning',{'actor':actor,'id':aid,**item});return {'id':aid,'generation':generation(db)}
    if method=='POST' and path=='/api/assignments/delete':
        row=db.execute('SELECT * FROM policy_assignments WHERE id=?',(body.get('id'),)).fetchone()
        if not row:raise ManagementError(404,'找不到指派')
        check_revision(body,row);db.execute('DELETE FROM policy_assignments WHERE id=?',(row['id'],));validate_active_combinations(db);bump(db)
        Store.event(db,'console','assignment.deleted','warning',{'actor':actor,'assignment':dict(row)});return {'ok':True}
    raise ManagementError(404,'找不到此管理功能')
