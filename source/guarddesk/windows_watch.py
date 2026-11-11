"""ReadDirectoryChangesW change notifications, complementing Security opens."""
import ctypes
import os
import struct
import threading
import time
import ntpath
from pathlib import Path
from .windows_events import excluded

# Names only: content, size and attribute changes are outside collection scope.
NOTIFY_FILTER = 0x1 | 0x2


def fixed_drives():
    if os.name!='nt': return []
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.GetDriveTypeW.argtypes=[ctypes.c_wchar_p];api.GetDriveTypeW.restype=ctypes.c_uint
    mask=api.GetLogicalDrives()
    return [f'{chr(65+i)}:\\' for i in range(26) if mask&(1<<i) and api.GetDriveTypeW(f'{chr(65+i)}:\\')==3]


def decode_notifications(data):
    items=[];offset=0
    while offset+12<=len(data):
        advance,action,length=struct.unpack_from('<III',data,offset)
        if length%2 or offset+12+length>len(data):raise ValueError('Invalid directory notification')
        name=data[offset+12:offset+12+length].decode('utf-16-le')
        items.append((action,name))
        if not advance:break
        if advance<12 or offset+advance>len(data):raise ValueError('Invalid directory notification offset')
        offset+=advance
    return items


def decode_extended(data):
    items=[];offset=0
    while offset+84<=len(data):
        advance,action=struct.unpack_from('<II',data,offset);length=struct.unpack_from('<I',data,offset+80)[0]
        if length%2 or offset+84+length>len(data):raise ValueError('Invalid extended directory notification')
        file_id=struct.unpack_from('<Q',data,offset+64)[0];attrs=struct.unpack_from('<I',data,offset+56)[0]
        items.append((action,data[offset+84:offset+84+length].decode('utf-16-le'),file_id,attrs))
        if not advance:break
        if advance<84 or offset+advance>len(data):raise ValueError('Invalid extended notification offset')
        offset+=advance
    return items


class FileIdMoves:
    def __init__(self,attributes=False):self.removed={};self.with_attributes=attributes
    def consume(self,items,now=None):
        now=time.monotonic() if now is None else now
        self.removed={k:v for k,v in self.removed.items() if now-v[1]<=2};moves=[]
        for action,path,file_id,attrs in items:
            if not file_id or attrs&0x10:continue
            if action==2:
                if len(self.removed)>=256:self.removed.pop(next(iter(self.removed)))
                self.removed[file_id]=(path,now,attrs)
            elif action==1:
                old=self.removed.pop(file_id,None)
                if old and ntpath.normcase(old[0])!=ntpath.normcase(path):
                    moves.append(('file.moved',{'path':old[0],'source_path':old[0],'destination_path':path,'file_id':str(file_id),'correlation':'same_volume_file_id_remove_add',**({'_path_attributes':{old[0]:old[2],path:attrs}} if self.with_attributes else {})}))
        return moves


class RenamePairs:
    """Pair only adjacent old/new notifications on the same directory handle."""
    def __init__(self):self.pending=None

    def consume(self,items,now=None):
        now=time.monotonic() if now is None else now;result=[]
        for item in items:
            action,path=item[:2];attributes=item[2] if len(item)>2 else None
            if self.pending:
                old,stamp,old_attributes=self.pending;self.pending=None
                if action==5 and now-stamp<=2:
                    kind='file.renamed' if ntpath.normcase(ntpath.dirname(old))==ntpath.normcase(ntpath.dirname(path)) else 'file.moved'
                    result.append((kind,{'path':old,'source_path':old,'destination_path':path,'correlation':'adjacent_native_rename_pair',**({'_path_attributes':{old:old_attributes,path:attributes}} if old_attributes is not None or attributes is not None else {})}));continue
                result.append(('file.rename_from',{'path':old,'correlation':'unpaired_old_name',**({'_path_attributes':{old:old_attributes}} if old_attributes is not None else {})}))
            if action==4:self.pending=(path,now,attributes);continue
            kind={1:'file.created',2:'file.deleted',5:'file.rename_to'}.get(action)
            if kind:result.append((kind,{'path':path,**({'correlation':'unpaired_new_name'} if action==5 else {}),**({'_path_attributes':{path:attributes}} if attributes is not None else {})}))
        return result


class DirectoryMonitor:
    def __init__(self,agent,policy):
        self.agent,self.policy=agent,policy
        self.stop_event=threading.Event();self.handles=[];self.threads=[]

    def start(self):
        if os.name!='nt':raise OSError('Windows native watcher unavailable')
        from ctypes import wintypes as w
        self.w=w;self.api=ctypes.WinDLL('kernel32',use_last_error=True)
        self.api.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE];self.api.CreateFileW.restype=w.HANDLE
        self.api.ReadDirectoryChangesW.argtypes=[w.HANDLE,w.LPVOID,w.DWORD,w.BOOL,w.DWORD,ctypes.POINTER(w.DWORD),w.LPVOID,w.LPVOID];self.api.ReadDirectoryChangesW.restype=w.BOOL
        if hasattr(self.api,'ReadDirectoryChangesExW'):
            self.api.ReadDirectoryChangesExW.argtypes=self.api.ReadDirectoryChangesW.argtypes+[w.DWORD];self.api.ReadDirectoryChangesExW.restype=w.BOOL
        self.api.CancelIoEx.argtypes=[w.HANDLE,w.LPVOID];self.api.CancelIoEx.restype=w.BOOL
        self.api.CloseHandle.argtypes=[w.HANDLE];self.api.CloseHandle.restype=w.BOOL
        self.api.GetFileAttributesW.argtypes=[w.LPCWSTR];self.api.GetFileAttributesW.restype=w.DWORD
        roots=fixed_drives() if self.policy['file_audit']['scope']=='all_local' else [str(self.agent.root)]
        for root in roots:
            handle=self.api.CreateFileW(root,1,7,None,3,0x02000000,None)
            if handle==ctypes.c_void_p(-1).value:
                self.agent.queue('agent.audit_watch_failed',{'root':root,'error':ctypes.get_last_error()},'critical');continue
            self.handles.append(handle)
            thread=threading.Thread(target=self.watch,args=(root,handle),daemon=True)
            thread.start();self.threads.append(thread)
        return {'roots':roots,'active':len(self.handles)}

    def watch(self,root,handle):
        from .performance import background_work
        with background_work():self._watch_background(root,handle)

    def _watch_background(self,root,handle):
        buffer=ctypes.create_string_buffer(65536)
        pairs=RenamePairs()
        file_ids=FileIdMoves(attributes='@guarddesk:hidden-files:v1' in self.policy['file_audit']['exclude_paths']);extended=hasattr(self.api,'ReadDirectoryChangesExW')
        while not self.stop_event.is_set():
            count=self.w.DWORD()
            args=(handle,buffer,len(buffer),True,NOTIFY_FILTER,ctypes.byref(count),None,None)
            ok=self.api.ReadDirectoryChangesExW(*args,2) if extended else self.api.ReadDirectoryChangesW(*args)
            if not ok:
                error=ctypes.get_last_error()
                if extended and error in (1,50,87):extended=False;continue
                if not self.stop_event.is_set():self.agent.queue('agent.audit_watch_failed',{'root':root,'error':error},'critical')
                break
            if not count.value:
                pairs.pending=None
                file_ids.removed.clear()
                self.agent.queue('agent.audit_gap',{'root':root,'reason':'directory_notification_buffer_overflow'},'critical');continue
            try:
                # Classify one bounded notification buffer before acquiring an
                # outbox write transaction; slow filesystem metadata must not
                # hold SQLite's writer while heartbeat/other collectors wait.
                entries=[];ready=[]
                raw=decode_extended(buffer.raw[:count.value]) if extended else [(action,name,0,0) for action,name in decode_notifications(buffer.raw[:count.value])]
                extended_items=[]
                for action,name,file_id,attrs in raw:
                    path=str(Path(root)/name)
                    extended_items.append((action,path,file_id,attrs))
                    # Keep event-time extended attributes separate from a
                    # current lookup: names can be deleted/reused in one batch.
                    if action==3:
                        attributes=attrs if extended else self.api.GetFileAttributesW(path)
                        if attributes!=0xffffffff and attributes&0x10:continue
                    if action==1:
                        current_attributes=self.api.GetFileAttributesW(path)
                        if current_attributes!=0xffffffff and current_attributes&0x10:continue
                    entries.append((action,path,attrs) if extended and '@guarddesk:hidden-files:v1' in self.policy['file_audit']['exclude_paths'] else (action,path))
                for kind,details in pairs.consume(entries)+file_ids.consume(extended_items):
                    observed=details.pop('_path_attributes',{})
                    if '@guarddesk:hidden-files:v1' in self.policy['file_audit']['exclude_paths']:
                        from .hidden_files import remember
                        for observed_path,observed_attributes in observed.items():remember(observed_path,observed_attributes)
                    relevant=[details.get('source_path',details['path']),details.get('destination_path',details['path'])]
                    if all(excluded(p,self.policy['file_audit']['exclude_paths'],self.agent.audit_runtime) for p in relevant):continue
                    ready.append((kind,details))
                if ready:
                    with self.agent.db() as db:
                        for kind,details in ready:
                            self.agent.queue(kind,{**details,'source':'ReadDirectoryChangesW','user':None,'process':None,'identity':'see_corresponding_security_event'},db=db)
            except (OSError,ValueError) as exc:
                self.agent.queue('agent.audit_gap',{'root':root,'reason':str(exc)[:200]},'critical')

    def close(self):
        self.stop_event.set()
        for handle in self.handles:self.api.CancelIoEx(handle,None)
        # CancelSynchronousIo is needed for synchronous ReadDirectoryChangesW.
        if os.name=='nt':
            self.api.OpenThread.argtypes=[self.w.DWORD,self.w.BOOL,self.w.DWORD];self.api.OpenThread.restype=self.w.HANDLE
            self.api.CancelSynchronousIo.argtypes=[self.w.HANDLE]
            for thread in self.threads:
                if thread.native_id:
                    token=self.api.OpenThread(1,False,thread.native_id)
                    if token:
                        self.api.CancelSynchronousIo(token);self.api.CloseHandle(token)
        for thread in self.threads:thread.join(3)
        for handle in self.handles:self.api.CloseHandle(handle)
        self.handles=[]
