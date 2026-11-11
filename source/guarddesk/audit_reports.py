"""Incremental derived statistics; original audit records remain immutable."""
import datetime as dt
import json
import sqlite3
import threading
import time
from collections import Counter
from .performance import background_work
from .endpoint_purge import serialized

TAIPEI=dt.timezone(dt.timedelta(hours=8))
ACTIONS={'file.created':'created','file.modified':'modified','file.deleted':'deleted','file.moved':'moved','file.renamed':'renamed','file.opened':'opened'}
MUTATIONS=('created','modified','deleted','moved','renamed')


class AuditError(Exception):
    def __init__(self,status,message):self.status=status;self.message=message;super().__init__(message)


def dates(start,end):
    try:
        first=dt.date.fromisoformat(start);last=dt.date.fromisoformat(end)
        if first.isoformat()!=start or last.isoformat()!=end or first.year<1970 or last.year>9998 or not 0<=(last-first).days<3660:raise ValueError()
    except (TypeError,ValueError):raise AuditError(400,'請選有效日期區間，結束不可早於開始，最多 3660 天')
    return first,last


def day_bounds(day):
    return dt.datetime.combine(day,dt.time(),TAIPEI).timestamp(),dt.datetime.combine(day+dt.timedelta(days=1),dt.time(),TAIPEI).timestamp()


def person(details):
    if not isinstance(details,dict):return '',''
    value=details.get('user','')
    if not isinstance(value,str) or not value.strip() or value.strip() in ('—','---','\\') or value.strip().endswith('\\'):return '',''
    value=value.strip()[:512]
    return value.casefold(),value


def action_filter(value):
    if value=='changes':return MUTATIONS
    if value=='all':return (*MUTATIONS,'opened')
    if value in (*MUTATIONS,'opened'):return (value,)
    raise AuditError(400,'操作類型不正確')


@serialized
def index_batch(store,stop=None):
    with store.connect() as db:
        cursor=db.execute("SELECT value FROM audit_rollup_meta WHERE key='cursor'").fetchone()[0]
        # Non-file events do not need payload reads just to advance the cursor.
        headers=list(db.execute('SELECT id,kind,device_id FROM event_headers WHERE id>? ORDER BY id LIMIT 500',(cursor,)))
        retired={did for did in {h['device_id'] for h in headers}
                 if db.execute('SELECT 1 FROM endpoint_purges WHERE device_id=?',(did,)).fetchone()}
        batch=[];size=0;last_cursor=cursor
        for header in headers:
            last_cursor=header['id']
            if header['device_id'] in retired:continue
            if header['kind'] in ACTIONS:
                row=dict(db.execute('SELECT id,device_id,kind,severity,occurred,details FROM events WHERE id=?',(header['id'],)).fetchone())
                batch.append(row);size+=len(row['details'].encode('utf-8'))
                if size>=2*1024*1024:break
    if not headers:return False
    counts=Counter();labels={};latest={};indexed=[]
    for row in batch:
        action=ACTIONS.get(row['kind'])
        if not action:continue
        details=json.loads(row['details']);key,label=person(details)
        try:day=dt.datetime.fromtimestamp(row['occurred'],TAIPEI).date().isoformat()
        except (ValueError,OverflowError,OSError):day='9999-12-31'
        group=(day,row['device_id'],key,action,row['severity'])
        counts[group]+=1;labels[group]=label;latest[group]=max(latest.get(group,0),row['occurred'])
        indexed.append((row['id'],key,action))
    if stop and stop.is_set():return False
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute("SELECT value FROM audit_rollup_meta WHERE key='cursor'").fetchone()[0]!=cursor:return True
        for group,n in counts.items():
            day,device,key,action,severity=group
            db.execute('INSERT INTO audit_daily VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(day,device_id,person,action,severity) DO UPDATE SET n=n+excluded.n,last_occurred=max(last_occurred,excluded.last_occurred)',(day,device,key,labels[group],action,severity,n,latest[group]))
        db.executemany('INSERT INTO audit_file_index VALUES (?,?,?)',indexed)
        db.execute("UPDATE audit_rollup_meta SET value=? WHERE key='cursor'",(last_cursor,))
    return True


class AuditService:
    def __init__(self,store):
        self.store=store;self.stop=threading.Event();self.error='';self.index_thread=threading.Thread(target=self._index,daemon=True,name='GuardDesk-AuditSummary')
        from .audit_archive import ArchiveWorker
        self.archive=ArchiveWorker(store);self.index_thread.start()

    def _index(self):
        with background_work():
            # A connection without a transaction avoids a WAL checkpoint on
            # every small batch; it never pins a read snapshot or writer lock.
            keeper=sqlite3.connect(self.store.path,timeout=15)
            try:
                while not self.stop.is_set():
                    try:
                        changed=index_batch(self.store,self.stop);self.error=''
                    except (sqlite3.Error,ValueError,OSError):changed=False;self.error='統計索引暫時無法更新，稍後重試'
                    self.stop.wait(.05 if changed else 2)
            finally:keeper.close()

    def close(self):
        self.stop.set();self.archive.close()
        if self.index_thread.is_alive():self.index_thread.join(3)


def summary(db,params,error=''):
    first,last=dates(params.get('start',[''])[0],params.get('end',[''])[0]);mode=params.get('action',['changes'])[0];actions=action_filter(mode)
    device=params.get('device',[''])[0][:100]
    # Keep the original person API available for existing clients; the MIS
    # summary explicitly selects device grouping, including actor-less logs.
    grouping=params.get('group_by',['person'])[0]
    if grouping not in ('device','person'):raise AuditError(400,'統計分組不正確')
    clause='day>=? AND day<=? AND action IN ('+','.join('?' for _ in actions)+')'
    values=[first.isoformat(),last.isoformat(),*actions]
    if device:clause+=' AND device_id=?';values.append(device)
    from .event_storage import head as source_head
    cursor=db.execute("SELECT value FROM audit_rollup_meta WHERE key='cursor'").fetchone()[0];head=source_head(db)[0]
    if grouping=='device':
        rows=[dict(r) for r in db.execute("SELECT a.device_id,COALESCE(NULLIF(trim(d.name),''),a.device_id) label,sum(n) n,sum(CASE WHEN action='deleted' THEN n ELSE 0 END) deleted,sum(CASE WHEN action='created' THEN n ELSE 0 END) created,max(last_occurred) last_seen FROM audit_daily a LEFT JOIN devices d ON d.id=a.device_id WHERE "+clause+' GROUP BY a.device_id ORDER BY n DESC,a.device_id LIMIT 1001',values)]
    else:
        rows=[dict(r) for r in db.execute('SELECT person,max(label) label,sum(n) n,sum(CASE WHEN action=\'deleted\' THEN n ELSE 0 END) deleted,max(last_occurred) last_seen,count(DISTINCT device_id) devices FROM audit_daily WHERE '+clause+' GROUP BY person ORDER BY n DESC,person LIMIT 1001',values)]
    truncated=len(rows)>1000;rows=rows[:1000]
    total=db.execute('SELECT COALESCE(sum(n),0) FROM audit_daily WHERE '+clause,values).fetchone()[0]
    device_total=db.execute('SELECT count(DISTINCT device_id) FROM audit_daily WHERE '+clause,values).fetchone()[0]
    people=db.execute("SELECT count(DISTINCT person) FROM audit_daily WHERE "+clause+" AND person<>''",values).fetchone()[0] if grouping=='person' else 0
    unknown=db.execute("SELECT COALESCE(sum(n),0) FROM audit_daily WHERE "+clause+" AND person=''",values).fetchone()[0] if grouping=='person' else 0
    buckets={r['day']:r['n'] for r in db.execute('SELECT day,sum(n) n FROM audit_daily WHERE '+clause+' GROUP BY day ORDER BY day',values)}
    trend=[{'day':(first+dt.timedelta(days=i)).isoformat(),'n':buckets.get((first+dt.timedelta(days=i)).isoformat(),0)} for i in range((last-first).days+1)]
    breakdown=[dict(r) for r in db.execute('SELECT action,sum(n) n FROM audit_daily WHERE '+clause+' GROUP BY action ORDER BY n DESC',values)]
    for i,r in enumerate(rows):r['rank']=i+1;r['label']=r['label'] or ('未提供電腦識別碼' if grouping=='device' else '未識別帳號')
    return {'start':first.isoformat(),'end':last.isoformat(),'action':mode,'device':device,'group_by':grouping,'items':rows,'device_total':device_total,'people':rows,'people_total':people,'total':total,'unknown':unknown,'trend':trend,'breakdown':breakdown,
            'truncated':truncated,'cursor':cursor,'source_head':head,'caught_up':cursor>=head,'error':error,
            'meaning':'按 Agent 註冊電腦分組的日誌筆數；同名電腦依端點識別碼分開計算。不同收集器可能記錄同一次動作，不等於不同檔案數或員工操作次數' if grouping=='device' else '日誌筆數；不同收集器可能記錄同一次動作，不等於不同檔案數或人員績效'}
