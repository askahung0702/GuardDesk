"""Additive named-library document policy, deliberately outside legacy body.

Old protocol 1/2 clients retain the exact four-category body/fingerprint. New
clients validate this separately signed-by-transport, versioned projection.
"""
import ntpath
from .serialization import canonical, digest

MAX_ROOTS=8
SCHEMA='document-audit-v1'


def validate(rules):
    if not isinstance(rules,list) or len(rules)>MAX_ROOTS:raise ValueError('文件稽核最多 8 個指定目錄')
    seen=set()
    for rule in rules:
        if not isinstance(rule,dict) or set(rule)!={'path','recursive','read','copy'}:raise ValueError('文件稽核欄位不正確')
        path=rule['path']
        if not isinstance(path,str) or not 5<=len(path)<=240 or any(c in path for c in '*?<>|"\x00\r\n') or any(ord(c)<32 for c in path):raise ValueError('請指定本機資料夾絕對路徑；不支援萬用字元')
        drive,tail=ntpath.splitdrive(path)
        if len(drive)!=2 or drive[1]!=':' or not drive[0].isascii() or not drive[0].isalpha() or not tail.startswith('\\') or ':' in tail or '/' in path or any(p in ('.','..','') for p in tail.strip('\\').split('\\')):raise ValueError('只接受本機磁碟上的明確資料夾，不接受根目錄、UNC 或相對路徑')
        parts=tail.strip('\\').casefold().split('\\')
        if any(p.endswith(('.', ' ')) or p.split('.')[0] in ('con','prn','aux','nul',*(f'com{i}' for i in range(1,10)),*(f'lpt{i}' for i in range(1,10))) for p in parts):raise ValueError('路徑含 Windows 別名或保留名稱')
        if len(parts)<2 or parts[0] in ('windows','program files','program files (x86)','programdata','$recycle.bin','system volume information'):raise ValueError('不可將磁碟、使用者集合或系統目錄整體納入文件稽核')
        if parts[0]=='users' and len(parts)<3:raise ValueError('請選文件子目錄，不可稽核整個使用者設定檔')
        if any(type(rule[k]) is not bool for k in ('recursive','read','copy')) or not (rule['read'] or rule['copy']):raise ValueError('請啟用讀取或複製關聯收集')
        key=ntpath.normcase(ntpath.normpath(path))
        if key in seen:raise ValueError('重複的文件稽核目錄')
        if any(key.startswith(old.rstrip('\\')+'\\') or old.startswith(key.rstrip('\\')+'\\') for old in seen):raise ValueError('文件稽核目錄重疊；請保留一個明確範圍')
        seen.add(key)
    return rules


def packet(rules):
    validate(rules)
    return {'schema':SCHEMA,'minimum_version':'0.4.49','rules':rules,'fingerprint':digest(canonical(rules))}


def check(value):
    if not isinstance(value,dict) or value.get('schema')!=SCHEMA:raise ValueError('文件稽核協定不相容')
    validate(value.get('rules'))
    if value.get('fingerprint')!=digest(canonical(value['rules'])):raise ValueError('文件稽核內容驗證失敗')
    return value['rules']


def covers(path,rule):
    path=ntpath.normcase(ntpath.normpath(path));root=ntpath.normcase(ntpath.normpath(rule['path'])).rstrip('\\')
    return path.startswith(root+'\\') and (rule['recursive'] or ntpath.dirname(path)==root)
