"""Bounded working set budget; single package limits remain in update_packages."""
import os
from pathlib import Path
import shutil
import stat
import time
from . import update_packages as packages

MAX_WORKING_BYTES=3*1024*1024*1024
MAX_ENTRIES=40000
RESERVE_BYTES=1024*1024*1024
SCAN_SECONDS=30


class CapacityError(OSError):
    def __init__(self,code,used,incoming,free=None,*,entries=None,elapsed_ms=None,root_index=None):
        self.code=code;self.used_bytes=used;self.incoming_bytes=incoming
        self.limit_bytes=MAX_WORKING_BYTES;self.free_bytes=free
        self.entries=entries;self.elapsed_ms=elapsed_ms;self.root_index=root_index
        labels={'working_set_limit':'更新工作集超過保留上限','entry_limit':'更新保留項目超過上限',
            'scan_timeout':'更新容量檢查超時','disk_space':'更新磁碟可用空間不足'}
        super().__init__(labels[code]+'；舊版持續運作，尚未停止')


def budget(roots,incoming):
    if type(incoming) is not int or not 0<=incoming<=packages.MAX_TOTAL:raise ValueError('更新候選大小不正確')
    if not 1<=len(roots)<=4:raise ValueError('更新容量範圍不正確')
    paths=[]
    for root in roots:
        path=packages.plain(root).resolve()
        if not any(path.is_relative_to(p) for p in paths):paths=[p for p in paths if not p.is_relative_to(path)]+[path]
    total=0;count=0;start=time.monotonic()
    def fail(code,free=None):
        raise CapacityError(code,total,incoming,free,entries=count,
            elapsed_ms=max(0,int((time.monotonic()-start)*1000)),root_index=root_index)
    for root_index,root in enumerate(paths):
        if not root.exists():continue
        todo=[root]
        while todo:
            directory=todo.pop();packages.plain(directory)
            with os.scandir(directory) as entries:
                for entry in entries:
                    count+=1
                    if count>MAX_ENTRIES:fail('entry_limit')
                    if time.monotonic()-start>SCAN_SECONDS:fail('scan_timeout')
                    # Recheck the complete ancestor chain per directory, not
                    # per file. DirEntry supplies no-follow metadata in one
                    # lookup; a reparse entry is rejected before descent.
                    info=entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
                        raise ValueError('更新路徑不可包含 junction／符號連結')
                    path=Path(entry.path)
                    if stat.S_ISDIR(info.st_mode):todo.append(path)
                    elif stat.S_ISREG(info.st_mode):total+=info.st_size
                    else:raise ValueError('更新管理範圍含非一般檔案')
                    if total+incoming>MAX_WORKING_BYTES:fail('working_set_limit')
            packages.plain(directory)
            if time.monotonic()-start>SCAN_SECONDS:fail('scan_timeout')
    destination=Path(roots[0])
    while not destination.exists():
        if destination==destination.parent:raise OSError('無法取得更新磁碟可用空間')
        destination=destination.parent
    free=shutil.disk_usage(destination).free
    if free<incoming+RESERVE_BYTES:fail('disk_space',free)
    return {'used_bytes':total,'incoming_bytes':incoming,'projected_bytes':total+incoming,
        'limit_bytes':MAX_WORKING_BYTES,'free_bytes':free,'entries':count,
        'elapsed_ms':max(0,int((time.monotonic()-start)*1000))}
