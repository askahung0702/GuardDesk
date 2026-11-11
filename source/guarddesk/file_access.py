"""File-open collection filters; legacy-compatible reserved policy rules.

These rules filter ordinary open/read observations only. They never change
Defender, application execution, file mutations, upload evidence or warnings.
"""
import collections
import ctypes
import ntpath
import os
import time
from .application_exclusions import validate_exclusions,process_path

PREFIX='@guarddesk:file-access:v1:'
PROCESS=PREFIX+'process:'
SERVICES=PREFIX+'include-services'
ALL_ACCESSES=PREFIX+'include-background'
INTERVAL=PREFIX+'interaction-seconds:'


def options(rules):
    programs=[];include=False;mode='interactive';seconds=30;interval_seen=False
    for value in rules:
        if value==SERVICES:include=True
        elif value==ALL_ACCESSES:
            if mode=='all':raise ValueError('文件存取記錄方式只能設定一次')
            mode='all'
        elif value.startswith(INTERVAL):
            raw=value[len(INTERVAL):]
            if interval_seen or not raw.isascii() or not raw.isdecimal() or str(int(raw))!=raw or not 5<=int(raw)<=600:raise ValueError('互動有效秒數須為 5～600 的整數，且只能設定一次')
            seconds=int(raw);interval_seen=True
        elif value.startswith(PROCESS):programs.append(value[len(PROCESS):])
        elif value.startswith('@guarddesk:file-access:'):raise ValueError('檔案讀取排除設定版本或格式不正確')
    validate_exclusions(programs)
    if any('{' in p or '}' in p for p in programs):raise ValueError('讀取排除程式請使用精確檔名或路徑，不使用使用者路徑模板')
    return {'exclude_services':not include,'exclude_processes':programs,'mode':mode,'interaction_seconds':seconds}


def background_path(path,image):
    """Exact known cache layouts, only ordinary access; no extension guesses."""
    from .file_exclusions import normalized_path
    if not isinstance(path,str) or not path:return False
    p=normalized_path(path);process=ntpath.basename(image).casefold() if isinstance(image,str) else ''
    # Explicit Windows/profile caches. A business document called History or
    # Cache elsewhere must survive. General policy exclusions still apply.
    if '\\appdata\\roaming\\microsoft\\windows\\themes\\' in p:return True
    if any(marker in p for marker in ('\\appdata\\local\\microsoft\\windows\\inetcache\\','\\appdata\\local\\microsoft\\windows\\webcache\\')):return True
    if process in ('chrome.exe','msedge.exe','brave.exe'):
        profiles=('\\google\\chrome\\user data\\','\\microsoft\\edge\\user data\\','\\bravesoftware\\brave-browser\\user data\\','\\edge_profile\\','\\chrome_profile\\')
        for marker in profiles:
            if marker not in p:continue
            tail=p.split(marker,1)[1].split('\\')
            if len(tail)>=2 and (tail[0]=='default' or tail[0].startswith('profile ')):
                name=tail[1]
                if name in ('history','history1','history-journal','cookies','network','cache','code cache','gpucache','session storage','local storage','sessions','preferences','secure preferences','visited links','web data','web data-journal'):return True
    return False


def reason(details,rules,settings=None):
    path=details.get('path','')
    if isinstance(path,str):
        drive,tail=ntpath.splitdrive(ntpath.normpath(path))
        if drive and (tail=='\\' or (drive.startswith('\\\\') and not tail)):return 'directory'
    if details.get('object_type')=='directory':return 'directory'
    if background_path(path,details.get('process')):return 'known_background_cache'
    settings=options(rules) if settings is None else settings
    if details.get('process_identity_status')=='creation_time_checked':
        if settings['exclude_services'] and type(details.get('process_session_id')) is int and details['process_session_id']==0:return 'noninteractive_service'
        image=details.get('process')
        if isinstance(image,str) and image:
            image=process_path(image)
            base=process_path(os.environ.get('ProgramFiles',r'C:\Program Files')+r'\GuardDeskPilot')
            if image in (base+r'\usbcontrol\guarddesk.exe',base+r'\updater\guarddesk.exe'):return 'guarddesk_component'
            for rule in settings['exclude_processes']:
                if (image==process_path(rule) if ntpath.basename(rule)!=rule else ntpath.basename(image)==rule.casefold()):return 'excluded_process'
    return None


def excluded_event(kind,severity,details,rules):
    return kind=='file.opened' and severity=='info' and reason(details,rules) is not None


def attributes(path):
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.GetFileAttributesW.argtypes=[ctypes.c_wchar_p];api.GetFileAttributesW.restype=ctypes.c_uint32
    value=api.GetFileAttributesW(path)
    return None if value==0xffffffff else value


class Filter:
    def __init__(self,context=None):
        self.cache=collections.OrderedDict();self.window=0;self.queries=0;self.context=context
        self.rules_snapshot=None;self.settings=None

    def policy_options(self,rules):
        # One immutable policy snapshot per collector, not a path/event cache.
        # Compare contents so in-place MIS changes and explicit clears apply on
        # the very next observation. Invalid replacements never poison a cache.
        snapshot=tuple(rules)
        if snapshot!=self.rules_snapshot:
            settings=options(snapshot)
            self.rules_snapshot=snapshot;self.settings=settings
        return self.settings

    def check(self,details,rules,occurred=None):
        if details.get('process_id')==os.getpid():return 'collector_self'
        settings=self.policy_options(rules)
        why=reason(details,rules,settings)
        if why:return why
        if self.context is not None and settings['mode']=='interactive':
            why,context=self.context.classify(details,occurred if occurred is not None else time.time(),settings['interaction_seconds'])
            if why:return why
            details.update(context)
        else:details['interaction']='not_assessed'
        # ReadData already supplies stronger evidence than a later path query.
        if details.get('evidence')=='completed_native_read':details['object_type']='file';return None
        if details.get('object_type')=='file':return None
        path=details['path'];now=time.monotonic()
        while self.cache and now-next(iter(self.cache.values()))[0]>2:self.cache.popitem(last=False)
        cached=self.cache.get(path)
        if cached is not None:value=cached[1]
        else:
            if now-self.window>=1:self.window=now;self.queries=0
            if self.queries>=64:return 'type_query_budget'
            self.queries+=1
            try:value=attributes(path)
            except OSError:value=None
            self.cache[path]=(now,value)
            while len(self.cache)>512:self.cache.popitem(last=False)
        if value is None:return 'object_type_unconfirmed'
        if value&0x10:return 'directory'
        details['object_type']='file';details['object_type_evidence']='post_event_attributes'
        return None


class OpenReducer:
    """Consolidate native opens associated with the same input generation.

    One logical open per (process birth, path, session logon, last-input tick).
    New input and a new native open remain a separate observation. No inference
    merges different processes/files, and a trace gap discards all associations.
    """
    def __init__(self):self.seen=collections.OrderedDict();self.merged=0
    def gap(self):self.seen.clear()
    def admit(self,details):
        interaction=details.pop('_interaction_key',None)
        if interaction is None:return True
        born=details.get('process_created')
        if type(born) not in (int,float):return True
        key=(details['process_id'],born,ntpath.normcase(details['path']),tuple(interaction))
        now=time.monotonic()
        while self.seen and now-next(iter(self.seen.values()))>600:self.seen.popitem(last=False)
        if key in self.seen:
            self.seen.move_to_end(key);self.seen[key]=now;self.merged+=1;return False
        self.seen[key]=now
        while len(self.seen)>4096:self.seen.popitem(last=False)
        details['deduplication']='process_file_input_generation'
        return True
