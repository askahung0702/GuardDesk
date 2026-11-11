"""Server-only daily file-mutation mail. No endpoint credentials or raw paths leave.

External calls run in one bounded worker, never in an HTTP/SQLite transaction.
A send with an ambiguous outcome is not retried automatically.
"""
import base64
import colorsys
import ctypes
import datetime as dt
import html
from functools import lru_cache
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .audit_reports import AuditError, TAIPEI, dates
from .store import Store, canonical

DEFAULT = {'enabled': False, 'time': '08:00', 'recipients': [], 'sender': '', 'tenant_id': '', 'client_id': ''}
ACTIONS = ('created', 'deleted', 'moved', 'renamed')
MAX_DEVICES = 1000
SECRET_ENV = 'GUARDDESK_MAIL_CLIENT_SECRET'


def install(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS mail_report_config(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,body TEXT NOT NULL,secret TEXT NOT NULL,updated REAL NOT NULL,actor TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS mail_report_jobs(id TEXT PRIMARY KEY,dedupe TEXT UNIQUE NOT NULL,day TEXT NOT NULL,kind TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,actor TEXT NOT NULL,result TEXT NOT NULL DEFAULT '{}');
    CREATE INDEX IF NOT EXISTS mail_report_jobs_state ON mail_report_jobs(state,created);
    CREATE INDEX IF NOT EXISTS mail_report_jobs_time ON mail_report_jobs(created);
    ''')


def config(db):
    row = db.execute('SELECT * FROM mail_report_config WHERE id=1').fetchone()
    return ({**DEFAULT, **json.loads(row['body'])}, row['revision'], row['secret']) if row else (dict(DEFAULT), 0, '')


def email(value):
    if not isinstance(value, str) or len(value) > 254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}", value):
        raise AuditError(400, '請填入有效信箱，不接受顯示名稱或換行')
    return value


def validate(body):
    if not isinstance(body, dict) or set(body) != set(DEFAULT):
        raise AuditError(400, '郵件設定欄位不正確')
    if type(body['enabled']) is not bool or not isinstance(body['time'], str) or not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', body['time']):
        raise AuditError(400, '請填入台北時間 HH:mm')
    if not isinstance(body['recipients'], list) or len(body['recipients']) > 20:
        raise AuditError(400, '最多設定 20 個收件信箱，可使用 MIS 群組信箱')
    recipients = list(dict.fromkeys(email(x.strip()) if isinstance(x, str) else email(x) for x in body['recipients']))
    out = {**body, 'recipients': recipients}
    for key in ('sender', 'tenant_id', 'client_id'):
        if not isinstance(body[key], str): raise AuditError(400, 'M365 欄位不正確')
        out[key] = body[key].strip()
    if out['sender']: email(out['sender'])
    for key in ('tenant_id', 'client_id'):
        if out[key] and not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', out[key]):
            raise AuditError(400, '租戶與應用程式 ID 必須是 GUID')
    if out['enabled'] and (not recipients or not all(out[k] for k in ('sender', 'tenant_id', 'client_id'))):
        raise AuditError(400, '啟用前請完成 M365 寄件與收件設定')
    return out


def protect(value, decrypt=False):
    """DPAPI CurrentUser: server identity only. Never a plaintext fallback."""
    if os.name != 'nt': raise AuditError(409, '此主機請使用 GUARDDESK_MAIL_CLIENT_SECRET 環境變數')
    from ctypes import wintypes as w
    class Blob(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [w.HLOCAL]; kernel.LocalFree.restype = w.HLOCAL
    raw = base64.b64decode(value, validate=True) if decrypt else value.encode('utf-8')
    buf = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    source = Blob(len(raw), buf); target = Blob()
    if decrypt:
        fn = crypt.CryptUnprotectData
        fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, w.DWORD, ctypes.POINTER(Blob)]
        ok = fn(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target))
    else:
        fn = crypt.CryptProtectData
        fn.argtypes = [ctypes.POINTER(Blob), w.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, w.DWORD, ctypes.POINTER(Blob)]
        ok = fn(ctypes.byref(source), 'GuardDesk M365 daily report', None, None, None, 1, ctypes.byref(target))
    fn.restype = w.BOOL
    try:
        if not ok: raise AuditError(409, 'M365 密鑰無法由目前 Server 帳號加密／解密，請重新設定')
        data = ctypes.string_at(target.data, target.size)
        return data.decode('utf-8') if decrypt else base64.b64encode(data).decode('ascii')
    finally:
        ctypes.memset(buf, 0, len(raw))
        if target.data:
            ctypes.memset(target.data, 0, target.size); kernel.LocalFree(target.data)


def catalog(db):
    body, revision, secret = config(db)
    source = 'environment' if os.environ.get(SECRET_ENV) else 'dpapi' if secret else 'missing'
    jobs = [dict(r) for r in db.execute('SELECT id,day,kind,state,created,updated,actor,result FROM mail_report_jobs ORDER BY created DESC LIMIT 50')]
    for row in jobs: row['result'] = json.loads(row['result'])
    return {'body': body, 'revision': revision, 'secret_source': source, 'jobs': jobs, 'timezone': 'Asia/Taipei'}


def save(db, request, actor):
    if not isinstance(request, dict) or set(request) - {'body', 'revision', 'client_secret', 'clear_secret'}: raise AuditError(400, '郵件設定請求不正確')
    value = validate(request.get('body'))
    _, revision, secret = config(db)
    if type(request.get('revision')) is not int or request['revision'] != revision: raise AuditError(409, '設定已變更，請重新載入')
    raw = request.get('client_secret', '')
    if not isinstance(raw, str) or len(raw) > 4096 or (raw and (raw.strip() != raw or any(ord(c) < 32 for c in raw))): raise AuditError(400, 'M365 密鑰格式不正確')
    if type(request.get('clear_secret', False)) is not bool: raise AuditError(400, '密鑰設定不正確')
    if raw and request.get('clear_secret'): raise AuditError(400, '不可同時清除與設定密鑰')
    if request.get('clear_secret'): secret = ''
    if raw: secret = protect(raw)
    if value['enabled'] and not (secret or os.environ.get(SECRET_ENV)): raise AuditError(400, '啟用前請設定 M365 Client Secret')
    now = time.time()
    db.execute('INSERT INTO mail_report_config VALUES(1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,body=excluded.body,secret=excluded.secret,updated=excluded.updated,actor=excluded.actor', (revision+1, canonical(value), secret, now, actor))
    # Only configuration metadata goes to audit; no credential or report body.
    Store.event(db, 'console', 'mail_report.configured', 'info', {'actor': actor, 'revision': revision+1, 'enabled': value['enabled']})
    return catalog(db)


def report_day(value, now=None):
    day, _ = dates(value, value)
    today = dt.datetime.fromtimestamp(time.time() if now is None else now, TAIPEI).date()
    if day >= today: raise AuditError(400, '請選今天以前的日期；每日報表只統計完整日')
    return day.isoformat()


def snapshot(db, day):
    """One consistent read snapshot over rollups, not original event payloads."""
    from .event_storage import head
    cursor = db.execute("SELECT value FROM audit_rollup_meta WHERE key='cursor'").fetchone()[0]
    source_head = head(db)[0]
    if cursor < source_head: raise AuditError(409, '稽核彙總索引尚未追上，請稍後再試；不寄送不完整統計')
    clause = ','.join('?' for _ in ACTIONS)
    counts = {r['device_id']: dict(r) for r in db.execute('SELECT device_id,sum(n) n,sum(CASE WHEN action=\'created\' THEN n ELSE 0 END) created,sum(CASE WHEN action=\'deleted\' THEN n ELSE 0 END) deleted,sum(CASE WHEN action=\'moved\' THEN n ELSE 0 END) moved,sum(CASE WHEN action=\'renamed\' THEN n ELSE 0 END) renamed FROM audit_daily WHERE day=? AND action IN ('+clause+') GROUP BY device_id', (day, *ACTIONS))}
    devices = list(db.execute('SELECT id,name,last_seen,revoked FROM devices ORDER BY id LIMIT ?', (MAX_DEVICES+1,)))
    rows = []
    for d in devices:
        count = counts.pop(d['id'], None)
        if not d['revoked'] or count:
            rows.append({'device_id': d['id'], 'name': (d['name'] or d['id'])[:200], 'last_seen': d['last_seen'], 'revoked': bool(d['revoked']), **(count or dict(n=0, created=0, deleted=0, moved=0, renamed=0))})
    for did, count in counts.items(): rows.append({'device_id': did, 'name': did[:200], 'last_seen': 0, 'revoked': True, **count})
    if len(devices) > MAX_DEVICES or len(rows) > MAX_DEVICES: raise AuditError(409, '超過每日報表 1000 台端點上限，未截斷寄送，請調整容量')
    rows.sort(key=lambda r: (-r['n'], r['name'].casefold(), r['device_id']))
    for i, row in enumerate(rows):
        row['rank'] = i+1
        rgb = colorsys.hsv_to_rgb((i*.61803398875)%1, .55+(i%3)*.1, .72+(i%2)*.14)
        row['color'] = '#'+''.join(f'{round(c*255):02x}' for c in rgb)
    return {'day': day, 'rows': rows, 'total': sum(r['n'] for r in rows), 'generated': time.time(), 'cursor': cursor, 'source_head': source_head}


@lru_cache(maxsize=8)
def font(size):
    from PIL import ImageFont
    for name in (str(Path(os.environ.get('WINDIR', r'C:\Windows'))/'Fonts/msjh.ttc'), 'DejaVuSans.ttf'):
        try: return ImageFont.truetype(name, size)
        except OSError: pass
    return ImageFont.load_default(size=size)


def charts(data):
    from PIL import Image, ImageDraw
    result = []
    def png(image, name):
        out = io.BytesIO(); image.save(out, 'PNG', optimize=True)
        result.append((name, out.getvalue()))
    rows = data['rows']; maximum = max((r['n'] for r in rows), default=1) or 1
    for start in range(0, max(len(rows), 1), 40):
        chunk = rows[start:start+40]
        image = Image.new('RGB', (1100, 90+max(len(chunk), 1)*34), 'white'); draw = ImageDraw.Draw(image)
        draw.text((22, 16), f"{data['day']}  File mutations / device  ({start+1}-{start+len(chunk)})", fill='#17323a', font=font(22))
        for i, row in enumerate(chunk):
            y = 65+i*34
            label = f"{row['rank']}. {row['name']}"
            while draw.textlength(label, font=font(17)) > 330: label = label[:-2]+'…'
            draw.text((22, y), label, fill='#17323a', font=font(17))
            width = round(570*row['n']/maximum)
            if width: draw.rectangle((370, y, 370+width, y+22), fill=row['color'])
            draw.text((950, y), f"{row['n']:,}", fill='#17323a', font=font(17))
        if not chunk: draw.text((22, 65), 'No registered devices', fill='#17323a', font=font(17))
        png(image, f'bars-{start//40+1}.png')
    image = Image.new('RGB', (900, 700), 'white'); draw = ImageDraw.Draw(image)
    draw.text((22, 15), f"{data['day']}  All-device distribution", fill='#17323a', font=font(24))
    angle = -90; total = data['total']
    if total:
        for row in rows:
            if not row['n']: continue
            end = angle+360*row['n']/total
            draw.pieslice((140, 70, 760, 690), angle, end, fill=row['color']); angle = end
    else:
        draw.ellipse((140, 70, 760, 690), outline='#cbd5e0', width=3)
        draw.text((380, 335), '0 events', fill='#17323a', font=font(27))
    png(image, 'pie.png')
    if sum(len(content) for _, content in result) > 1800000: raise AuditError(409, '報表圖片超過郵件容量上限，未截斷寄送')
    return result


def render(data, images, preview=False):
    # Preview and attachment share the same self-contained document. Keep the
    # preview keyword compatible with existing management callers.
    esc = lambda s: html.escape(str(s), quote=True)
    def table(rows):
        return '<div style="overflow-x:auto"><table role="table" cellpadding="7" cellspacing="0" border="1" style="border-collapse:collapse;width:100%;border-color:#dce4e9"><thead><tr>'+''.join('<th>'+x+'</th>' for x in ('排名', '電腦名稱', '異動筆數', '占比', '新增', '刪除', '移動', '重新命名'))+'</tr></thead><tbody>'+''.join('<tr><td>'+str(r['rank'])+'</td><td><span style="color:'+r['color']+'">●</span> '+esc(r['name'])+'<br><small>'+esc(r['device_id'])+'</small></td><td>'+format(r['n'], ',')+'</td><td>'+f"{r['n']/data['total']*100 if data['total'] else 0:.2f}%"+'</td>'+''.join('<td>'+format(r[k], ',')+'</td>' for k in ACTIONS)+'</tr>' for r in rows)+'</tbody></table></div>'
    def image(name, content):
        src = 'data:image/png;base64,'+base64.b64encode(content).decode('ascii')
        return '<img alt="'+('全部電腦異動圓餅圖' if name=='pie.png' else '全部電腦異動長條圖')+'" src="'+src+'" style="max-width:100%;height:auto;display:block">'
    return '<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>GuardDesk 每日檔案異動總表 '+esc(data['day'])+'</title></head><body style="font-family:Arial,Microsoft JhengHei,sans-serif;color:#17323a;max-width:1100px;margin:24px auto"><h1>GuardDesk 每日檔案異動總表</h1><p>'+esc(data['day'])+' 00:00–24:00（台北時間） · '+str(len(data['rows']))+' 台電腦 · '+format(data['total'], ',')+' 筆異動</p><p>僅統計新增、刪除、移動、重新命名；不包含開啟請求、內容／屬性變更及程式啟停。筆數不等於不同檔案數、員工人數或績效；同名電腦依識別碼分列。</p><h2>前二十名</h2>'+table(data['rows'][:20])+'<h2>全部電腦長條圖</h2>'+''.join(image(n,c) for n,c in images if n!='pie.png')+'<h2>全部電腦圓餅圖</h2>'+''.join(image(n,c) for n,c in images if n=='pie.png')+'<h2>完整數據與圖例（含零筆）</h2>'+table(data['rows'])+'<p>統計截止：'+esc(dt.datetime.fromtimestamp(data['generated'], TAIPEI).strftime('%Y-%m-%d %H:%M:%S'))+'。已確認中心彙總索引追上目前接收進度；離線、停收或待補送的端點仍可能缺資料，零筆不代表沒有活動。晚到資料不會自動重寄，可由 MIS 預覽後補寄該日期。</p></body></html>'


def enqueue(db, request, actor, now=None):
    if not isinstance(request, dict) or set(request) != {'day','revision','confirm','request_id'} or request.get('confirm') != 'send_report': raise AuditError(400, '請確認會實際寄出報表')
    request_id = request.get('request_id')
    if not isinstance(request_id, str) or not re.fullmatch('[0-9a-f]{32}', request_id): raise AuditError(400, '寄送請求識別碼不正確')
    day = report_day(request.get('day'), now)
    body, revision, secret = config(db)
    if not body['recipients'] or not all(body[k] for k in ('sender', 'tenant_id', 'client_id')) or not (secret or os.environ.get(SECRET_ENV)):
        raise AuditError(409, '請先儲存完整 M365 寄件設定與 MIS 收件信箱')
    if type(request.get('revision')) is not int or request['revision'] != revision: raise AuditError(409, '寄件設定已改變，請重新確認')
    previous = db.execute('SELECT * FROM mail_report_jobs WHERE dedupe=?', ('manual:'+request_id,)).fetchone()
    if previous:
        if previous['day'] != day or previous['revision'] != revision or previous['actor'] != actor: raise AuditError(409, '寄送請求識別碼已用於其他工作')
        return {'id': previous['id'], 'state': previous['state']}
    if db.execute("SELECT count(*) FROM mail_report_jobs WHERE state IN ('queued','preparing','sending')").fetchone()[0] >= 10: raise AuditError(409, '寄件佇列已滿，請等候目前工作完成')
    jid = secrets.token_hex(16); stamp = time.time() if now is None else now
    db.execute('INSERT INTO mail_report_jobs(id,dedupe,day,kind,state,revision,created,updated,actor) VALUES(?,?,?,?,?,?,?,?,?)', (jid, 'manual:'+request_id, day, 'manual', 'queued', revision, stamp, stamp, actor))
    Store.event(db, 'console', 'mail_report.queued', 'info', {'actor': actor, 'day': day, 'job_id': jid})
    return {'id': jid, 'state': 'queued'}


class MailFailure(Exception):
    def __init__(self, state, message): self.state = state; self.message = message; super().__init__(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def post(url, data, headers):
    request = urllib.request.Request(url, data=data, headers=headers, method='POST')
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
        content = response.read(65537)
        if len(content) > 65536: raise ValueError('response too large')
        return response.status, content


def token(body, secret):
    payload = urllib.parse.urlencode({'grant_type': 'client_credentials', 'client_id': body['client_id'], 'client_secret': secret, 'scope': 'https://graph.microsoft.com/.default'}).encode('ascii')
    try:
        status, raw = post('https://login.microsoftonline.com/'+body['tenant_id']+'/oauth2/v2.0/token', payload, {'Content-Type': 'application/x-www-form-urlencoded'})
        value = json.loads(raw).get('access_token')
        if status != 200 or not isinstance(value, str) or not value or len(value) > 60000 or any(ord(c)<33 for c in value): raise ValueError()
        return value
    except urllib.error.HTTPError as exc:
        code = exc.code; exc.close()
        raise MailFailure('failed', f'M365 認證未成功（HTTP {code}），請核對租戶、應用程式與密鑰') from None
    except Exception:
        raise MailFailure('failed', 'M365 認證連線失敗；尚未呼叫寄信 API') from None


def send(body, access_token, data, images):
    filename = 'GuardDesk-File-Changes-'+data['day']+'.html'
    document = render(data, images).encode('utf-8')
    message = {'subject': 'GuardDesk｜'+data['day']+' 每日檔案異動總表',
        'body': {'contentType': 'Text', 'content': '報表日期：'+data['day']+'（台北時間）\n每日檔案異動總表請見附件 '+filename+'。\n請下載後以瀏覽器開啟；圖表已內嵌，可離線查看。'},
        'toRecipients': [{'emailAddress': {'address': x}} for x in body['recipients']],
        'attachments': [{'@odata.type': '#microsoft.graph.fileAttachment', 'name': filename, 'contentType': 'text/html', 'isInline': False, 'contentBytes': base64.b64encode(document).decode('ascii')}]}
    raw = canonical({'message': message, 'saveToSentItems': True}).encode('utf-8')
    if len(raw) > 2800000: raise MailFailure('failed', '郵件超過 2.8 MB 上限，尚未呼叫寄信 API')
    try:
        status, _ = post('https://graph.microsoft.com/v1.0/users/'+urllib.parse.quote(body['sender'], safe='')+'/sendMail', raw, {'Content-Type': 'application/json', 'Authorization': 'Bearer '+access_token})
        if status != 202: raise MailFailure('unknown', 'M365 回應不是預期 202，寄送結果待確認，未自動重試')
    except urllib.error.HTTPError as exc:
        code = exc.code; exc.close()
        if 400 <= code < 500: raise MailFailure('failed', f'M365 拒絕寄送（HTTP {code}）；請核對 Mail.Send、寄件信箱範圍、群組收件與節流') from None
        raise MailFailure('unknown', f'M365 HTTP {code}，寄送結果待確認，未自動重試') from None
    except MailFailure: raise
    except Exception: raise MailFailure('unknown', 'M365 連線中斷或逾時，寄送結果待確認，未自動重試') from None


class MailWorker:
    def __init__(self, store, start=True):
        self.store = store; self.stop = threading.Event(); self.error = ''
        self.preview_slots = threading.BoundedSemaphore(2)
        self.thread = threading.Thread(target=self.run, daemon=True, name='GuardDesk-DailyMail')
        # Only the owning console starts one worker; shared HTTPS server reuses it.
        with store.connect() as db:
            db.execute("UPDATE mail_report_jobs SET state='unknown',result=?,updated=? WHERE state='sending'", (canonical({'message': 'Server 在寄送期間停止，請先查 M365 寄件備份與追蹤，未自動重寄'}), time.time()))
            db.execute("UPDATE mail_report_jobs SET state='queued' WHERE state='preparing'")
        if start: self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread.is_alive(): self.thread.join(2)

    def schedule(self, now):
        local = dt.datetime.fromtimestamp(now, TAIPEI)
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            body, revision, _ = config(db)
            # Metadata-only bounded retention, never removes source audit records.
            db.execute("DELETE FROM mail_report_jobs WHERE id IN (SELECT id FROM mail_report_jobs WHERE created<? AND state NOT IN ('queued','preparing','sending') ORDER BY created LIMIT 100)", (now-90*86400,))
            if not body['enabled'] or local.strftime('%H:%M') < body['time']: return
            day = (local.date()-dt.timedelta(days=1)).isoformat()
            db.execute('INSERT OR IGNORE INTO mail_report_jobs(id,dedupe,day,kind,state,revision,created,updated,actor) VALUES(?,?,?,?,?,?,?,?,?)', (secrets.token_hex(16), 'daily:'+day, day, 'daily', 'queued', revision, now, now, 'daily-scheduler'))

    def finish(self, job, state, message, data=None, body=None):
        result = {'message': message}
        if data: result.update(total=data['total'], devices=len(data['rows']), cursor=data['cursor'], generated=data['generated'])
        if body: result['recipients'] = body['recipients']; result['sender'] = body['sender']
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE mail_report_jobs SET state=?,result=?,updated=? WHERE id=?', (state, canonical(result), time.time(), job['id']))
            Store.event(db, 'console', 'mail_report.'+state, 'info' if state=='accepted' else 'warning', {'job_id': job['id'], 'day': job['day'], 'message': message})

    def process(self, now=None):
        now = time.time() if now is None else now
        self.schedule(now)
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT 1 FROM mail_report_jobs WHERE state IN ('preparing','sending') LIMIT 1").fetchone(): return False
            row = db.execute("SELECT * FROM mail_report_jobs WHERE state='queued' ORDER BY created LIMIT 1").fetchone()
            if not row: return False
            job = dict(row); body, revision, encrypted = config(db)
            today = dt.datetime.fromtimestamp(now, TAIPEI).date()
            if job['revision'] != revision or (job['kind']=='daily' and (not body['enabled'] or job['day'] != (today-dt.timedelta(days=1)).isoformat())):
                db.execute("UPDATE mail_report_jobs SET state='cancelled',result=?,updated=? WHERE id=?", (canonical({'message': '設定已改變或排程已過期，請重新預覽後補寄'}), now, job['id'])); return True
            # Wait for the existing asynchronous index without blocking requests.
            try: data = snapshot(db, job['day'])
            except AuditError as exc:
                if '索引' in exc.message:
                    if now-job['created'] > 6*3600:
                        db.execute("UPDATE mail_report_jobs SET state='failed',result=?,updated=? WHERE id=?", (canonical({'message': '彙總索引等待超過六小時，請檢查後補寄'}), now, job['id']))
                    return False
                db.execute("UPDATE mail_report_jobs SET state='failed',result=?,updated=? WHERE id=?", (canonical({'message': exc.message}), now, job['id'])); return True
            db.execute("UPDATE mail_report_jobs SET state='preparing',updated=? WHERE id=?", (now, job['id']))
        try:
            images = charts(data)
            credential = os.environ.get(SECRET_ENV) or (protect(encrypted, decrypt=True) if encrypted else '')
            if not credential: raise MailFailure('failed', '尚未設定 M365 Client Secret')
            access_token = token(body, credential); credential = ''
            with self.store.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                current, current_revision, _ = config(db)
                if self.stop.is_set() or current_revision != revision:
                    db.execute("UPDATE mail_report_jobs SET state='cancelled',result=?,updated=? WHERE id=?", (canonical({'message': '寄出前停止或設定已改變，未呼叫寄信 API'}), time.time(), job['id'])); return True
                db.execute("UPDATE mail_report_jobs SET state='sending',updated=? WHERE id=?", (time.time(), job['id']))
            send(current, access_token, data, images)
            self.finish(job, 'accepted', 'M365 已接受（202）；不代表已送達，請依寄件備份／郵件追蹤確認', data, body)
        except MailFailure as exc: self.finish(job, exc.state, exc.message, data, body)
        except AuditError as exc: self.finish(job, 'failed', exc.message, data, body)
        except Exception:
            # No exception text/Graph body is logged: they may contain credentials.
            with self.store.connect() as db:
                state = db.execute('SELECT state FROM mail_report_jobs WHERE id=?', (job['id'],)).fetchone()[0]
            self.finish(job, 'unknown' if state=='sending' else 'failed', '報表處理未完成，請檢查設定與 Server 狀態；未自動重寄', data, body)
        return True

    def run(self):
        from .performance import background_work
        with background_work():
            while not self.stop.is_set():
                try: changed = self.process(); self.error = ''
                except Exception: changed = False; self.error = '每日報表背景處理暫時失敗，稍後重試'
                self.stop.wait(2 if changed else 30)
