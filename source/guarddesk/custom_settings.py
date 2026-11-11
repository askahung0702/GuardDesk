"""Versioned, typed custom controls, independent of the legacy policy wire schema."""
import copy
import datetime as dt
import json
import math
import re
import time
from .store import Store, canonical, digest
from .management import ControlPlane, ManagementError

PROTOCOL=1
MIN_VERSION='0.4.37'
DEFAULT={'schedules':[], 'network':{'ipv6':'unchanged'}, 'compatibility':[], 'software':[]}
ACTIONS=('shutdown','restart','sleep','hibernate','logoff','lock')
MODULES=('browser_history','directory_notifications','security_file_events','process_events')

def install(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS custom_settings(scope TEXT NOT NULL,target TEXT NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL,actor TEXT NOT NULL,updated REAL NOT NULL,PRIMARY KEY(scope,target));
    CREATE TABLE IF NOT EXISTS custom_settings_history(scope TEXT NOT NULL,target TEXT NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL,actor TEXT NOT NULL,updated REAL NOT NULL,PRIMARY KEY(scope,target,revision));
    CREATE TABLE IF NOT EXISTS custom_status(device_id TEXT NOT NULL REFERENCES devices(id),role TEXT NOT NULL,body TEXT NOT NULL,received REAL NOT NULL,PRIMARY KEY(device_id,role));
    CREATE TABLE IF NOT EXISTS custom_action_leases(device_id TEXT PRIMARY KEY REFERENCES devices(id),token TEXT NOT NULL,expires REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS custom_executions(device_id TEXT NOT NULL REFERENCES devices(id),rule_id TEXT NOT NULL,occurrence TEXT NOT NULL,authorized REAL NOT NULL,PRIMARY KEY(device_id,rule_id,occurrence));
    CREATE INDEX IF NOT EXISTS custom_execution_time ON custom_executions(authorized);
    INSERT OR IGNORE INTO control_meta VALUES ('custom_generation',0);
    ''')

def text(value,limit=120):
    if not isinstance(value,str) or not value.strip() or len(value)>limit or any(ord(c)<32 for c in value):raise ValueError('自訂設定文字格式或長度不正確')
    return value

def integer(value,low,high):
    if type(value) is not int or not low<=value<=high:raise ValueError('自訂設定數值超出範圍')
    return value

def version(value):
    if not isinstance(value,str) or not re.fullmatch(r'\d{1,5}(?:\.\d{1,5}){3}',value) or any(int(x)>65535 for x in value.split('.')):raise ValueError('版本須為四段數字，例如 1.0.0.0')
    return tuple(map(int,value.split('.')))

def validate(body,partial=False):
    if not isinstance(body,dict) or (not set(body)<=set(DEFAULT) if partial else set(body)!=set(DEFAULT)):raise ValueError('自訂設定欄位不正確')
    for key in ('schedules','compatibility','software'):
        if key in body and (not isinstance(body[key],list) or len(body[key])>32):raise ValueError('每類自訂規則最多 32 筆')
    seen=set()
    for item in body.get('schedules',[]):
        keys={'id','name','action','days','times','delay_seconds','allow_cancel','defer_minutes','idle_minutes','message'}
        if not isinstance(item,dict) or not keys<=set(item) or set(item)-keys-{'repeat'}:raise ValueError('排程欄位不正確')
        if not re.fullmatch('[a-zA-Z0-9_-]{1,48}',text(item['id'],48)) or item['id'] in seen:raise ValueError('排程識別碼重複或無效')
        seen.add(item['id']);text(item['name']);text(item['message'],500)
        if item['action'] not in ACTIONS or type(item['allow_cancel']) is not bool:raise ValueError('排程動作不正確')
        days=item['days'];times=item['times']
        if not isinstance(days,list) or not 1<=len(days)<=7 or any(type(x) is not int or x not in range(1,8) for x in days) or len(set(days))!=len(days):raise ValueError('星期須為 1–7，且不可重複')
        if not isinstance(times,list) or not 1<=len(times)<=8 or any(not isinstance(x,str) or not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d',x) for x in times) or len(set(times))!=len(times):raise ValueError('排程時間請使用 HH:MM，最多 8 個')
        integer(item['delay_seconds'],60,3600);integer(item['defer_minutes'],0,120);integer(item['idle_minutes'],0,240)
        if 'repeat' in item:
            repeat=item['repeat']
            if not isinstance(repeat,dict) or set(repeat)!={'interval_minutes','until'} or not isinstance(repeat['until'],str) or not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d',repeat['until']):raise ValueError('反覆提醒須指定間隔與截止時間 HH:MM')
            integer(repeat['interval_minutes'],1,240)
            if item['allow_cancel'] is not True or item['defer_minutes']!=0:raise ValueError('反覆提醒使用獨立間隔，不可同時設定延後一次或不可取消')
    if 'network' in body:
        network=body['network']
        if not isinstance(network,dict) or set(network)!={'ipv6'} or network['ipv6'] not in ('unchanged','prefer_ipv4','disable'):raise ValueError('IPv6 設定不正確')
    intervals=[]
    for item in body.get('schedules',[]):
        duration=item['delay_seconds']+30
        if item['allow_cancel'] and item['defer_minutes']:duration+=item['defer_minutes']*60+item['delay_seconds']
        for day in item['days']:
            for value in item['times']:
                hour,minute=map(int,value.split(':'));start=(day-1)*86400+hour*3600+minute*60
                if 'repeat' in item:
                    end_hour,end_minute=map(int,item['repeat']['until'].split(':'));end=(day-1)*86400+end_hour*3600+end_minute*60
                    if end<=start:end+=86400
                    if end-start<item['delay_seconds']+30:raise ValueError('截止時間須晚於第一輪倒數結束')
                else:end=start+duration
                intervals.append((start,end))
    intervals.sort()
    if intervals and (any(a[1]>b[0] for a,b in zip(intervals,intervals[1:])) or intervals[-1][1]>intervals[0][0]+7*86400):raise ValueError('排程倒數／最長延後區間重疊，請調整時間或延後長度')
    for item in body.get('compatibility',[]):
        if not isinstance(item,dict) or set(item)!={'module','min_build','max_build','expires','reason'} or item['module'] not in MODULES:raise ValueError('相容性例外模組不正確')
        integer(item['min_build'],0,999999);integer(item['max_build'],0,999999)
        if item['min_build']>item['max_build']:raise ValueError('Windows build 範圍不正確')
        if type(item['expires']) not in (int,float) or not math.isfinite(item['expires']) or not 0<item['expires']<253402300800:raise ValueError('請指定有效到期日')
        text(item['reason'],300)
    for item in body.get('software',[]):
        if not isinstance(item,dict) or set(item)!={'name','collection','publisher','product','binary','min_version','max_version'} or item['collection'] not in ('Exe','Msi','Appx'):raise ValueError('軟體限制欄位不正確')
        text(item['name']);text(item['publisher'],500);text(item['product'],200);text(item['binary'],200)
        if not item['publisher'].startswith('CN=') or any(c in item['publisher']+item['product'] for c in '*?'):raise ValueError('發行者與產品必須精確指定，不可使用萬用字元')
        if '?' in item['binary'] or ('*' in item['binary'] and item['binary']!='*'):raise ValueError('檔名須精確指定，或使用 * 表示該產品所有檔案')
        low=version(item['min_version']);high=item['max_version']
        if high!='*' and version(high)<low:raise ValueError('軟體版本上下限不正確')
        if any(s in item['product'].casefold() for s in ('guarddesk','windows','powershell')):raise ValueError('不能以自訂限制封鎖系統或維運產品')
    if len(canonical(body))>48000:raise ValueError('自訂設定內容過大')
    return body

def scope_input(db,body):
    scope=body.get('scope');target=body.get('target','')
    if not isinstance(target,str) or not isinstance(scope,str):raise ValueError('設定對象格式不正確')
    if scope=='global':target=''
    elif scope=='group':
        if not db.execute('SELECT 1 FROM endpoint_groups WHERE id=?',(target,)).fetchone():raise ManagementError(404,'找不到群組')
    elif scope=='device':
        if not db.execute('SELECT 1 FROM devices WHERE id=? AND revoked=0',(target,)).fetchone():raise ManagementError(404,'找不到有效端點')
    else:raise ValueError('自訂設定對象須為全體、群組或端點')
    return scope,target

def generation(db):return db.execute("SELECT value FROM control_meta WHERE key='custom_generation'").fetchone()[0]

def resolve(db,device,rows=None,groups=None):
    rows=rows if rows is not None else [dict(r) for r in db.execute('SELECT * FROM custom_settings')]
    groups=groups if groups is not None else {r['id']:dict(r) for r in db.execute('SELECT id,parent_id,name FROM endpoint_groups')}
    chain=[];gid=device.get('group_id')
    while gid:
        if gid in chain or len(chain)>=8 or gid not in groups:raise ValueError('群組階層不完整')
        chain.append(gid);gid=groups[gid]['parent_id']
    result=copy.deepcopy(DEFAULT);sources={k:'default' for k in result}
    for scope,target in [('global','')]+[('group',g) for g in reversed(chain)]+[('device',device['id'])]:
        row=next((r for r in rows if r['scope']==scope and r['target']==target),None)
        if row:
            patch=validate(json.loads(row['body']),partial=True)
            for key,value in patch.items():result[key]=copy.deepcopy(value);sources[key]={'scope':scope,'target':target,'revision':row['revision']}
    validate(result)
    return {'protocol':PROTOCOL,'minimum_version':MIN_VERSION,'device_id':device['id'],'generation':generation(db),'body':result,'sources':sources,'fingerprint':digest(canonical(result))}

def catalog(db):
    profiles=[{**dict(r),'body':json.loads(r['body'])} for r in db.execute('SELECT * FROM custom_settings ORDER BY scope,target')]
    reports=[{**dict(r),'body':json.loads(r['body'])} for r in db.execute('SELECT * FROM custom_status ORDER BY device_id,role')]
    devices={r['id']:dict(r) for r in db.execute('SELECT id,group_id FROM devices')}
    groups={r['id']:dict(r) for r in db.execute('SELECT id,parent_id,name FROM endpoint_groups')}
    cache={}
    for report in reports:
        did=report['device_id']
        if did not in cache:cache[did]=resolve(db,devices[did],[{**p,'body':canonical(p['body'])} for p in profiles],groups)['fingerprint']
        report['matches_current']=report['body']['fingerprint']==cache[did]
    return {'generation':generation(db),'defaults':DEFAULT,'profiles':profiles,'reports':reports,'minimum_version':MIN_VERSION,'server_time':time.time()}

def preview(db,body):
    scope,target=scope_input(db,body);patch=validate(body.get('body'),partial=True)
    rows=[dict(r) for r in db.execute('SELECT * FROM custom_settings')]
    old=next((r for r in rows if r['scope']==scope and r['target']==target),None)
    if type(body.get('revision')) is not int or body.get('revision')!=(old['revision'] if old else 0):raise ManagementError(409,'設定已更新，請重新載入')
    candidate={'scope':scope,'target':target,'revision':(old['revision'] if old else 0)+1,'body':canonical(patch)}
    newer=[r for r in rows if (r['scope'],r['target'])!=(scope,target)]+[candidate]
    groups={r['id']:dict(r) for r in db.execute('SELECT id,parent_id,name FROM endpoint_groups')}
    changes=[]
    for row in db.execute('SELECT id,name,group_id,inventory FROM devices WHERE revoked=0'):
        d=dict(row);before=resolve(db,d,rows,groups);after=resolve(db,d,newer,groups)
        if before['fingerprint']!=after['fingerprint']:
            changes.append({'id':d['id'],'name':d['name'],'agent_version':json.loads(d['inventory']).get('agent_version','unknown'),'changed':[k for k in DEFAULT if before['body'][k]!=after['body'][k]]})
    from .management import generation as scope_generation
    return {'generation':generation(db),'scope_generation':scope_generation(db),'scope':scope,'target':target,'revision':body['revision'],'affected_count':len(changes),'devices':changes[:50],'minimum_version':MIN_VERSION,'body':patch}

def publish(db,body,actor):
    result=preview(db,body)
    if any('repeat' in r for r in result['body'].get('schedules',[])):raise ValueError('反覆提醒請使用新版設定庫，需要 0.4.39 元件')
    if result['body'].get('network',{}).get('ipv6','unchanged')!='unchanged' and body.get('network_ack') is not True:raise ValueError('請先核對網路依賴與重啟安排')
    if body.get('expected_generation')!=result['generation'] or body.get('expected_scope_generation')!=result['scope_generation']:raise ManagementError(409,'預覽已過期，請重新預覽')
    if body.get('confirm')!='publish_custom':raise ValueError('請確認發布自訂設定')
    scope,target=result['scope'],result['target'];revision=result['revision']+1;now=time.time();payload=canonical(result['body'])
    db.execute('INSERT OR REPLACE INTO custom_settings VALUES (?,?,?,?,?,?)',(scope,target,revision,payload,actor,now))
    db.execute('INSERT INTO custom_settings_history VALUES (?,?,?,?,?,?)',(scope,target,revision,payload,actor,now))
    from .custom_library import import_legacy_profile,validate_groups
    import_legacy_profile(db,scope,target,revision,result['body'],actor,now)
    validate_groups(db)
    db.execute("UPDATE control_meta SET value=value+1 WHERE key='custom_generation'")
    Store.event(db,'console','custom.published','warning',{'actor':actor,'scope':scope,'target':target,'revision':revision,'fields':list(result['body']),'affected_count':result['affected_count']})
    return {'revision':revision,'generation':generation(db)}

def accept_status(db,device,body):
    if set(body)!={'protocol','role','version','fingerprint','report'} or type(body['protocol']) is not int or body['protocol'] not in (PROTOCOL,2) or body['role'] not in ('main','native'):raise ValueError('自訂設定回報格式不正確')
    if not isinstance(body['version'],str) or len(body['version'])>32 or not re.fullmatch(r'\d+\.\d+\.\d+',body['version']) or not isinstance(body['fingerprint'],str) or not re.fullmatch('[0-9a-f]{64}',body['fingerprint']):raise ValueError('自訂設定版本不正確')
    report=body['report']
    if not isinstance(report,dict) or len(canonical(report))>12000:raise ValueError('自訂設定回報過大')
    # Only typed, bounded outcomes; never arbitrary endpoint diagnostic strings.
    if not set(report)<={'state','network','software','compatibility','schedule','error'}:raise ValueError('不支援的自訂設定回報欄位')
    if any(not isinstance(v,(str,list,dict)) for v in report.values()):raise ValueError('自訂回報型別不正確')
    safe={**body,'report':report};old=db.execute('SELECT body FROM custom_status WHERE device_id=? AND role=?',(device['id'],body['role'])).fetchone()
    if not old or json.loads(old[0])!=safe:Store.event(db,device['id'],'agent.custom_status','info',{'role':body['role'],'fingerprint':body['fingerprint'],'report':report})
    db.execute('INSERT OR REPLACE INTO custom_status VALUES (?,?,?,?)',(device['id'],body['role'],canonical(safe),time.time()))
    return {'ok':True}

def compatibility_modules(settings,build,now=None):
    now=time.time() if now is None else now
    return {r['module'] for r in settings.get('compatibility',[]) if r['min_build']<=build<=r['max_build'] and now<r['expires']}

def compatible_policy(policy,settings,build):
    result=copy.deepcopy(policy);modules=compatibility_modules(settings,build)
    if 'browser_history' in modules:result['browser_audit']=False
    if 'directory_notifications' in modules:result['_custom_skip_directory']=True
    if 'process_events' in modules:result['application_audit']=False
    if 'security_file_events' in modules:result['_custom_skip_security_files']=True
    return result

def due_schedules(settings,now):
    # Explicit Taiwan schedule, independent of endpoint timezone/DST.
    local=dt.datetime.fromtimestamp(now,dt.timezone(dt.timedelta(hours=8)))
    minute=local.strftime('%H:%M');day=local.strftime('%Y-%m-%d')
    return [(r,day+'T'+minute+'+08:00') for r in settings['schedules'] if local.isoweekday() in r['days'] and minute in r['times']]

def busy(db,device_id):
    from .software import active as software_active
    if software_active(db,device_id):return True
    now=time.time()
    if db.execute("SELECT 1 FROM updater_refresh WHERE device_id=? AND state='active' AND expires>?",(device_id,now)).fetchone():return True
    return bool(db.execute("SELECT 1 FROM remote_sessions WHERE device_id=? AND status IN ('requested','active') AND expires>?",(device_id,now)).fetchone() or db.execute("SELECT 1 FROM update_jobs WHERE device_id=? AND status='pending' AND not_before<=? AND expires>?",(device_id,now,now)).fetchone() or db.execute("SELECT 1 FROM endpoint_removals WHERE device_id=? AND status IN ('queued','running','failed')",(device_id,)).fetchone())

def action_leased(db,device_id):
    return bool(db.execute('SELECT 1 FROM custom_action_leases WHERE device_id=? AND expires>?',(device_id,time.time())).fetchone())

def authorize_action(db,device,body,packet=None):
    packet=packet or resolve(db,device)
    if set(body)!={'fingerprint','rule_id','occurrence'} or body['fingerprint']!=packet['fingerprint'] or busy(db,device['id']) or action_leased(db,device['id']):raise ManagementError(409,'設定已變更或端點忙碌，本次動作已取消')
    if not isinstance(body['occurrence'],str) or len(body['occurrence'])>40:raise ValueError('動作時間格式不正確')
    when=dt.datetime.fromisoformat(body['occurrence'])
    if when.utcoffset()!=dt.timedelta(hours=8):raise ValueError('動作須使用台北時間')
    rule=next((r for r,occ in due_schedules(packet['body'],when.timestamp()) if r['id']==body['rule_id'] and occ==body['occurrence']),None)
    if not rule or not when.timestamp()<=time.time()<schedule_expiry(rule,when.timestamp()):raise ManagementError(409,'排程已過期')
    import secrets
    if db.execute('SELECT 1 FROM custom_executions WHERE device_id=? AND rule_id=? AND occurrence=?',(device['id'],rule['id'],body['occurrence'])).fetchone():raise ManagementError(409,'此排程時段已授權，不重複執行')
    token=secrets.token_hex(16)
    db.execute('INSERT INTO custom_executions VALUES (?,?,?,?)',(device['id'],rule['id'],body['occurrence'],time.time()))
    db.execute('DELETE FROM custom_executions WHERE rowid IN (SELECT rowid FROM custom_executions WHERE authorized<? LIMIT 1000)',(time.time()-14*86400,))
    db.execute('INSERT OR REPLACE INTO custom_action_leases VALUES (?,?,?)',(device['id'],token,time.time()+90))
    Store.event(db,device['id'],'agent.custom_action_authorized','warning',{'rule_id':rule['id'],'action':rule['action'],'occurrence':body['occurrence']})
    return {'token':token,'action':rule['action']}


def schedule_expiry(rule,started):
    if 'repeat' not in rule:return started+2*rule['delay_seconds']+rule['defer_minutes']*60+120
    local=dt.datetime.fromtimestamp(started,dt.timezone(dt.timedelta(hours=8)))
    hour,minute=map(int,rule['repeat']['until'].split(':'))
    end=local.replace(hour=hour,minute=minute,second=0,microsecond=0)
    if end<=local:end+=dt.timedelta(days=1)
    return end.timestamp()
