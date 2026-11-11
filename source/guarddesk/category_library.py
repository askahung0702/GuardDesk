"""Versioned reusable targets. Drafts never change effective endpoint policy."""
import copy
import json
import re
import secrets
import time
import threading
from collections import OrderedDict
from .store import canonical,digest,Store
from .category_rules import member,identity,compile_member

USES={'website_blocked':'website','website_allowed':'website','application_deny':'application'}
_published_cache=OrderedDict()
_cache_lock=threading.Lock()


class PublishedCategories(dict):
    """Immutable during resolution; compiled layers share the bounded snapshot."""
    def __init__(self):super().__init__();self.compiled={}


def install(db):
    with _cache_lock:_published_cache.clear()
    db.executescript('''
    CREATE TABLE IF NOT EXISTS categories(id TEXT PRIMARY KEY,kind TEXT NOT NULL,revision INTEGER NOT NULL,published_revision INTEGER NOT NULL DEFAULT 0,draft TEXT NOT NULL,published TEXT,archived INTEGER NOT NULL DEFAULT 0,actor TEXT NOT NULL,updated REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS category_versions(category_id TEXT NOT NULL,revision INTEGER NOT NULL,snapshot TEXT NOT NULL,hash TEXT NOT NULL,actor TEXT NOT NULL,updated REAL NOT NULL,PRIMARY KEY(category_id,revision));
    CREATE TABLE IF NOT EXISTS category_members(category_id TEXT NOT NULL,revision INTEGER NOT NULL,member_id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(category_id,revision,member_id));
    CREATE TABLE IF NOT EXISTS policy_category_refs(set_id TEXT NOT NULL,use TEXT NOT NULL,category_id TEXT NOT NULL,include_descendants INTEGER NOT NULL,PRIMARY KEY(set_id,use,category_id));
    CREATE INDEX IF NOT EXISTS category_ref_reverse ON policy_category_refs(category_id,set_id);
    ''')
    for table in ('policy_sets','policy_set_versions'):
        if 'category_refs' not in {r[1] for r in db.execute('PRAGMA table_info('+table+')')}:
            db.execute("ALTER TABLE "+table+" ADD COLUMN category_refs TEXT NOT NULL DEFAULT '{}' ")


def error(status,message):
    from .management import ManagementError
    raise ManagementError(status,message)


def rows(db,published=False):
    cache_key=None
    # Never cache uncommitted publication/preview data. A fresh API connection
    # with no writes reads a consistent committed generation inside its txn.
    if published and db.total_changes==0:
        filename=db.execute('PRAGMA database_list').fetchone()[2]
        gen=db.execute("SELECT value FROM control_meta WHERE key='generation'").fetchone()[0]
        cache_key=(filename,gen)
        with _cache_lock:
            if cache_key in _published_cache:return _published_cache[cache_key]
    result=PublishedCategories() if published else {}
    for r in db.execute('SELECT * FROM categories WHERE archived=0'):
        value=dict(r)
        if published and value['published'] is None:continue
        value.update(json.loads(value['published' if published else 'draft']))
        value.pop('draft',None);value.pop('published',None)
        result[value['id']]=value
    if cache_key:
        with _cache_lock:
            for key in list(_published_cache):
                if key[0]==cache_key[0]:del _published_cache[key]
            _published_cache[cache_key]=result
            while len(_published_cache)>4:_published_cache.popitem(last=False)
    return result


def tree(values):
    names=set()
    for cid,item in values.items():
        key=(item['kind'],item['parent_id'],item['name'].casefold())
        if key in names:error(409,'同層分類名稱不可重複')
        names.add(key);seen={cid};parent=item['parent_id']
        while parent:
            if parent in seen:error(400,'分類不能形成循環')
            if parent not in values or values[parent]['kind']!=item['kind']:error(400,'父分類不存在或類型不同')
            seen.add(parent)
            if len(seen)>8:error(400,'分類最多八層')
            parent=values[parent]['parent_id']


def validate_draft(value,kind):
    if not isinstance(value,dict) or set(value)!={'name','description','parent_id','members'}:error(400,'分類草稿欄位不正確')
    name=value['name'];desc=value['description'];parent=value['parent_id'];items=value['members']
    if not isinstance(name,str) or not name.strip() or len(name)>100 or any(ord(c)<32 for c in name):error(400,'分類名稱須為 1–100 字')
    if not isinstance(desc,str) or len(desc)>1000:error(400,'分類說明最多 1000 字')
    if parent is not None and (not isinstance(parent,str) or not re.fullmatch('[0-9a-f]{24}',parent)):error(400,'父分類 ID 不正確')
    if not isinstance(items,list) or len(items)>1000:error(400,'分類最多 1000 個成員')
    normalized=[member(kind,m) for m in items]
    if len({m['id'] for m in normalized})!=len(items) or len({identity(m) for m in normalized})!=len(items):error(400,'分類成員重複')
    if len(canonical(normalized))>500000:error(400,'分類內容過大')
    return {**value,'name':name.strip(),'members':normalized}


def validate_refs(refs,categories):
    if not isinstance(refs,dict) or not set(refs)<=set(USES):error(400,'分類引用用途不正確')
    result={}
    for use,items in refs.items():
        if not isinstance(items,list) or len(items)>50:error(400,'每個用途最多引用 50 個分類')
        seen=set();result[use]=[]
        for item in items:
            if not isinstance(item,dict) or set(item)!={'id','include_descendants'} or type(item['include_descendants']) is not bool:error(400,'分類引用格式不正確')
            cid=item['id']
            if not isinstance(cid,str) or cid not in categories or categories[cid]['kind']!=USES[use]:error(400,'分類不存在、未發布或類型不符')
            if cid in seen:error(400,'分類引用不可重複')
            seen.add(cid);result[use].append(copy.deepcopy(item))
    return result


def expand(refs,categories):
    validate_refs(refs,categories);result={};sources=[]
    for use,items in refs.items():
        members=[];seen=set()
        for ref in items:
            ids={ref['id']}
            if ref['include_descendants']:
                for _ in range(8):
                    ids.update(cid for cid,c in categories.items() if c['parent_id'] in ids)
            for cid in sorted(ids):
                category=categories[cid]
                sources.append({'use':use,'id':cid,'name':category['name'],'revision':category['published_revision'],'hash':digest(canonical(category['members']))})
                for m in category['members']:
                    key=identity(m)
                    if key not in seen:members.append(m);seen.add(key)
                    if len(members)>1000:error(400,'展開分類超過 1000 筆')
        result[use]=members
    return result,sources


def compile_policy(policy,categories):
    """Compile this layer before inheritance; direct child overrides stay final."""
    from .policy import DEFAULT_POLICY,validate_policy
    refs=policy.get('category_refs',{})
    if not refs:return policy,[]
    cache_key=digest(canonical(policy))
    cache=getattr(categories,'compiled',None)
    if cache is not None:
        with _cache_lock:
            if cache_key in cache:return copy.deepcopy(cache[cache_key])
    result=copy.deepcopy(policy);expanded,sources=expand(refs,categories)
    overrides=result['overrides']
    if not isinstance(overrides,dict):error(400,'策略覆寫格式不正確')
    from .category_rules import website,publishers
    from .policy import validate_app_control
    if 'website_control' in overrides:website(overrides['website_control'])
    if 'application_control' in overrides:validate_app_control(overrides['application_control'],allow_empty=True)
    if 'application_publishers' in overrides:publishers(overrides['application_publishers'])
    for use,items in expanded.items():
        if use.startswith('website_'):
            if 'website_control' not in overrides:error(400,'引用網站分類須在同策略設定網站存取管制')
            key='blocked' if use=='website_blocked' else 'allowed'
            compiled=[]
            for m in items:
                value=compile_member(m)
                compiled.extend(value if isinstance(value,list) else [value])
                if len(set(compiled))>1000:error(400,'展開網站分類超過 1000 筆實際規則，不可截斷')
            overrides['website_control'][key]=sorted(set(overrides['website_control'][key]+compiled))
        else:
            control=overrides.get('application_control')
            if control is None or control['mode']!='denylist':error(400,'應用分類須搭配同策略的程式黑名單')
            if not control['enabled']:error(400,'應用分類須搭配已啟用的程式執行管制')
            rules=control['rules'];pubs=list(overrides.get('application_publishers',[]))
            for m in items:
                target=pubs if m['type']=='publisher' else rules;compiled=compile_member(m)
                # Names describe a rule; they do not change its matching identity.
                key=lambda x:canonical({k:v for k,v in x.items() if k!='name'}).casefold()
                if key(compiled) not in {key(existing) for existing in target}:target.append(compiled)
            overrides['application_publishers']=pubs
    validate_policy({**copy.deepcopy(DEFAULT_POLICY),**overrides})
    if cache is not None:
        with _cache_lock:
            if len(cache)>=128:cache.clear()
            cache[cache_key]=(result,sources)
    return result,sources


def save(db,body,actor):
    from .management import bump
    cid=body.get('id');old=db.execute('SELECT * FROM categories WHERE id=? AND archived=0',(cid,)).fetchone() if cid else None
    if cid and not old:error(404,'找不到分類')
    if old and (type(body.get('revision')) is not int or body['revision']!=old['revision']):error(409,'分類已更新，請重新載入')
    kind=body.get('kind')
    if kind not in ('website','application') or old and old['kind']!=kind:error(400,'分類類型不可變更')
    if not old and db.execute('SELECT count(*) FROM categories WHERE archived=0').fetchone()[0]>=200:error(400,'最多 200 個分類')
    draft=validate_draft(body.get('draft'),kind);cid=cid or secrets.token_hex(12)
    size=db.execute('SELECT COALESCE(SUM(length(draft)),0) FROM categories WHERE archived=0 AND id<>?',(cid,)).fetchone()[0]
    if size+len(canonical(draft))>8000000:error(400,'分類庫草稿總量最多 8 MB')
    values=rows(db);values[cid]={'id':cid,'kind':kind,**draft};tree(values)
    revision=old['revision']+1 if old else 1;stamp=time.time()
    if old:db.execute('UPDATE categories SET draft=?,revision=?,actor=?,updated=? WHERE id=?',(canonical(draft),revision,actor,stamp,cid))
    else:db.execute('INSERT INTO categories(id,kind,revision,draft,actor,updated) VALUES(?,?,?,?,?,?)',(cid,kind,revision,canonical(draft),actor,stamp))
    bump(db);Store.event(db,'console','category.draft_saved','info',{'actor':actor,'id':cid,'revision':revision})
    return {'id':cid,'revision':revision}


def affected(db,cid):
    # Ancestor references can include the changed subtree; bound by 200 categories.
    result=[];categories=rows(db,published=True)
    for row in db.execute('SELECT id,name,category_refs FROM policy_sets WHERE archived=0'):
        refs=json.loads(row['category_refs']);matches=False
        for items in refs.values():
            for ref in items:
                current=cid
                for _ in range(8):
                    if current==ref['id'] and (current==cid or ref['include_descendants']):matches=True
                    current=categories.get(current,{}).get('parent_id')
                    if not current:break
        if matches:result.append({'id':row['id'],'name':row['name']})
    return result


def publish(db,body,actor,preview=False):
    from .management import ControlPlane,devices_for_management,generation,bump,validate_active_combinations
    from .policy_preview import compare_planes
    if type(body.get('expected_generation')) is not int or body['expected_generation']!=generation(db):error(409,'分類或指派已改變，請重新預覽')
    row=db.execute('SELECT * FROM categories WHERE id=? AND archived=0',(body.get('id'),)).fetchone()
    if not row:error(404,'找不到分類')
    if type(body.get('revision')) is not int or body['revision']!=row['revision']:error(409,'分類已更新，請重新載入')
    before=ControlPlane(db);old_refs=affected(db,row['id']);draft=json.loads(row['draft']);revision=row['revision']+1
    db.execute('SAVEPOINT category_publication')
    try:
        db.execute('UPDATE categories SET published=?,published_revision=?,revision=?,actor=?,updated=? WHERE id=?',(canonical(draft),revision,revision,actor,time.time(),row['id']))
        tree(rows(db,published=True));validate_active_combinations(db)
        if sum(len(c['members']) for c in rows(db,True).values())>10000:error(400,'已發布分類庫最多 10000 個成員')
        after=ControlPlane(db)
        offset=body.get('offset',0)
        if type(offset) is not int or not 0<=offset<=100000:error(400,'分頁位置不正確')
        result=compare_planes(before,after,devices_for_management(db),None,offset,50)
        refs={r['id']:r for r in old_refs+affected(db,row['id'])}
        result.update(id=row['id'],revision=row['revision'],generation=generation(db),references=list(refs.values()))
        if preview:db.execute('ROLLBACK TO category_publication')
        else:
            stamp=time.time();snapshot={**draft,'kind':row['kind']}
            db.execute('INSERT INTO category_versions VALUES(?,?,?,?,?,?)',(row['id'],revision,canonical(snapshot),digest(canonical(snapshot)),actor,stamp))
            db.executemany('INSERT INTO category_members VALUES(?,?,?,?)',[(row['id'],revision,m['id'],canonical(m)) for m in draft['members']])
            bump(db);Store.event(db,'console','category.published','warning',{'actor':actor,'id':row['id'],'revision':revision,'policy_ids':sorted(refs)})
            result.update(revision=revision,generation=generation(db))
    except Exception:
        db.execute('ROLLBACK TO category_publication');raise
    finally:db.execute('RELEASE category_publication')
    return result


def catalog(db,query):
    values=rows(db);published=rows(db,True);items=[]
    for value in values.values():
        members=value.pop('members');value['member_count']=len(members)
        value['published_name']=published.get(value['id'],{}).get('name')
        value['published_parent_id']=published.get(value['id'],{}).get('parent_id')
        items.append(value)
    cid=query.get('id',[''])[0];q=query.get('q',[''])[0].casefold()
    try:offset=int(query.get('offset',['0'])[0])
    except ValueError:error(400,'分頁位置不正確')
    if not 0<=offset<=100000 or len(q)>200:error(400,'查詢條件不正確')
    selected=None
    if cid:
        row=db.execute('SELECT * FROM categories WHERE id=? AND archived=0',(cid,)).fetchone()
        if not row:error(404,'找不到分類')
        selected={**dict(row),**json.loads(row['draft'])};selected.pop('draft');selected.pop('published')
        members=selected['members'];members=[m for m in members if q in canonical(m).casefold()]
        selected.update(members=members[offset:offset+50],total=len(members),offset=offset,limit=50)
    from .management import generation
    return {'items':items,'selected':selected,'generation':generation(db)}


def route(db,method,path,body,actor,query):
    from .management import bump,generation
    if method=='GET' and path=='/api/categories':return catalog(db,query)
    if method=='POST' and path=='/api/categories/match':
        from .category_rules import match_preview
        return match_preview(body)
    if method=='POST' and path=='/api/categories/import':
        from .category_rules import import_members
        return import_members(body.get('kind'),body.get('text'),body.get('include_subdomains',True))
    if method=='GET' and path=='/api/categories/export':
        from .category_rules import export_members
        row=db.execute('SELECT draft FROM categories WHERE id=? AND archived=0',(query.get('id',[''])[0],)).fetchone()
        if not row:error(404,'找不到分類')
        return {'filename':'guarddesk-category.csv','content':export_members(json.loads(row['draft'])['members'])}
    if method=='POST' and path=='/api/categories/draft':return save(db,body,actor)
    if method=='POST' and path in ('/api/categories/preview','/api/categories/publish'):return publish(db,body,actor,preview=path.endswith('preview'))
    cid=query.get('id',[''])[0]
    if method=='GET' and path=='/api/categories/history':
        revision=query.get('revision',[''])[0]
        if revision:
            if not revision.isascii() or not revision.isdigit() or len(revision)>10:error(400,'版本不正確')
            row=db.execute('SELECT snapshot FROM category_versions WHERE category_id=? AND revision=?',(cid,int(revision))).fetchone()
            if not row:error(404,'找不到分類版本')
            return {'snapshot':json.loads(row['snapshot'])}
        return {'items':[dict(r) for r in db.execute('SELECT category_id,revision,hash,actor,updated,length(CAST(snapshot AS BLOB)) AS bytes FROM category_versions WHERE category_id=? ORDER BY revision DESC LIMIT 50',(cid,))]}
    if method=='GET' and path=='/api/categories/references':return {'items':affected(db,cid)}
    if method=='POST' and path=='/api/categories/archive':
        row=db.execute('SELECT * FROM categories WHERE id=? AND archived=0',(body.get('id'),)).fetchone()
        if not row:error(404,'找不到分類')
        if body.get('revision')!=row['revision'] or type(body.get('revision')) is not int:error(409,'分類已更新')
        if affected(db,row['id']) or any(c['parent_id']==row['id'] for c in list(rows(db).values())+list(rows(db,True).values())):error(409,'請先移除策略引用及子分類')
        db.execute('UPDATE categories SET archived=1 WHERE id=?',(row['id'],));bump(db)
        Store.event(db,'console','category.archived','warning',{'actor':actor,'id':row['id']});return {'ok':True,'generation':generation(db)}
    error(404,'找不到分類操作')
