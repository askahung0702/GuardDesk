"""Bounded, endpoint-only Windows hidden-attribute classification.

No enumeration/content reads, UNC probes, reparse traversal or Server lookup.
Unknown attributes retain an event. Names starting with '.' are not evidence.
"""
import collections
import ctypes
import ntpath
import os
import threading
import time

HIDDEN_RULE='@guarddesk:hidden-files:v1'
HIDDEN=2
REPARSE=0x400
_local=threading.local()


class WindowsMetadata:
    def __init__(self):
        self.api=ctypes.WinDLL('kernel32',use_last_error=True)
        self.api.GetFileAttributesW.argtypes=[ctypes.c_wchar_p]
        self.api.GetFileAttributesW.restype=ctypes.c_uint32
        self.api.GetDriveTypeW.argtypes=[ctypes.c_wchar_p]
        self.api.GetDriveTypeW.restype=ctypes.c_uint32

    def attributes(self,path):
        value=self.api.GetFileAttributesW(path)
        return None if value==0xffffffff else value

    def fixed(self,root):return self.api.GetDriveTypeW(root)==3


class HiddenPaths:
    def __init__(self,metadata=None,clock=time.monotonic):
        self.metadata=metadata;self.clock=clock;self.cache=collections.OrderedDict()
        self.drives={};self.window=None;self.queries=0;self.limited=0

    def remember(self,path,attributes):
        from .file_exclusions import normalized_path
        if type(attributes) is not int or not 0<=attributes<0xffffffff:return
        key=normalized_path(path)
        self.cache[key]=(self.clock()+2,attributes);self.cache.move_to_end(key)
        while len(self.cache)>2048:self.cache.popitem(last=False)

    def get(self,path):
        now=self.clock();saved=self.cache.get(path)
        if saved and saved[0]>now:
            self.cache.move_to_end(path);return saved[1]
        if self.window is None or now-self.window>=1:self.window=now;self.queries=0
        if self.queries>=128:self.limited+=1;return None
        self.queries+=1
        try:value=self.metadata.attributes(path)
        except OSError:value=None
        self.cache[path]=(now+(2 if value is not None else .2),value);self.cache.move_to_end(path)
        while len(self.cache)>2048:self.cache.popitem(last=False)
        return value

    def hidden(self,path):
        from .file_exclusions import normalized_path
        path=normalized_path(path);drive,tail=ntpath.splitdrive(path)
        # Device/UNC and relative paths must never initiate remote I/O.
        if len(drive)!=2 or drive[1]!=':' or not tail.startswith('\\'):return False
        parts=tail.strip('\\').split('\\')
        if parts==[''] or len(parts)>64:return False
        if self.metadata is None:
            if os.name!='nt':return False
            try:self.metadata=WindowsMetadata()
            except OSError:return False
        now=self.clock();saved=self.drives.get(drive)
        if not saved or saved[0]<=now:
            try:fixed=self.metadata.fixed(drive+'\\')
            except OSError:fixed=False
            self.drives[drive]=(now+60,fixed)
        else:fixed=saved[1]
        if not fixed:return False
        # Walk only lexical ancestors; stop at a junction before querying any
        # child that could resolve to another volume or a network target.
        current=drive
        for part in parts:
            current+='\\'+part
            value=self.get(current)
            if value is None:return False
            if value&HIDDEN:return True
            if value&REPARSE:return False
        return False


def resolver():
    if not hasattr(_local,'resolver'):_local.resolver=HiddenPaths()
    return _local.resolver


def hidden(path):return resolver().hidden(path)


def remember(path,attributes):resolver().remember(path,attributes)
