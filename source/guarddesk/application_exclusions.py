"""Explicit process identity filters for ordinary start/stop audit events."""
import ntpath
import re


def process_path(value):
    value=ntpath.normcase(ntpath.normpath(value))
    if value.startswith(('\\\\?\\','\\??\\')) and len(value)>6 and value[5]==':':value=value[4:]
    return value


def directory_rule(value):
    """A trailing backslash denotes an absolute local directory and descendants."""
    if not isinstance(value,str) or not value.endswith('\\'):return None
    p=process_path(value).rstrip('\\');drive,tail=ntpath.splitdrive(p)
    if len(drive)==2 and drive[1]==':' and drive[0].isascii() and drive[0].isalpha() and tail.startswith('\\') and tail!='\\' and ':' not in tail:return p+'\\'
    return None


def validate_exclusions(rules,*,allow_directories=True):
    if not isinstance(rules,list) or len(rules)>100:raise ValueError('啟停日誌排除清單最多 100 項')
    seen=set()
    for value in rules:
        if not isinstance(value,str) or not value or value!=value.strip() or len(value)>500 or any(ord(c)<32 for c in value) or any(c in value for c in '*?"<>|%/'):
            raise ValueError('請填程式檔名或完整 Windows 路徑，不支援萬用字元、環境變數或命令參數')
        p=process_path(value);drive,tail=ntpath.splitdrive(p)
        if value.endswith('\\') and not (allow_directories and directory_rule(value)):
            raise ValueError('程式目錄排除須使用非根目錄的完整本機資料夾路徑')
        if not (allow_directories and directory_rule(value)) and (ntpath.splitext(p)[1] not in ('.exe','.com') or ':' in tail or not (ntpath.basename(p)==p or (len(drive)==2 and drive[1]==':' and tail.startswith('\\')) or (drive.startswith('\\\\') and tail.startswith('\\')))):
            raise ValueError('請填 app.exe、完整 Windows 程式路徑，或以反斜線結尾的本機資料夾路徑')
        if p in seen:raise ValueError('啟停日誌排除項目不可重複')
        seen.add(p)
    return rules


def excluded_application(kind,severity,details,rules):
    # Unusual severity/unknown identity stays visible. This never suppresses
    # AppLocker blocks, installation, files, uploads or audit-gap warnings.
    if kind not in ('application.started','application.stopped') or severity!='info' or not rules:return False
    identities=[details[k] for k in ('process','path') if k in details and details[k] not in (None,'')]
    if not identities or any(not isinstance(v,str) for v in identities):return False
    paths=[process_path(v) for v in identities]
    if len(set(paths))!=1:return False
    p=paths[0]
    for rule in rules:
        directory=directory_rule(rule)
        if directory:
            if p.startswith(directory) and ntpath.splitext(p)[1] in ('.exe','.com') and ':' not in ntpath.splitdrive(p)[1] and not any(ord(c)<32 or c in '*?"<>|' for c in p):return True
        elif (p==process_path(rule) if ntpath.basename(rule)!=rule else ntpath.basename(p)==rule.casefold()):return True
    return False
