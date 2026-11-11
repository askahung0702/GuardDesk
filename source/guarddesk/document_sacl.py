"""Handle-bound, non-inheriting, bounded File System SACL provisioning.

Never changes DACL/owner, never uses automatic recursive ACL propagation.
The protected journal is committed BEFORE each mutation. Restoration requires
the same file identity and exact applied ACL; external changes are preserved.
"""
import base64
import contextlib
import ctypes
import json
import os
import sqlite3
import struct
import time
from pathlib import Path
from .document_settings import validate, covers
from .serialization import canonical,digest

FILE_SYSTEM='{0CCE921D-69AE-11D9-BED3-505054503030}'
MAX_OBJECTS=50000
MAX_DIRS=4096
MAX_DATABASE=64*1024*1024


def add_audit(acl,mask):
    """Append one non-inheriting Everyone success ACE; preserve every old byte."""
    ace=struct.pack('<BBHI',2,0x40,20,mask)+bytes.fromhex('010100000000000100000000')
    if acl is None:acl=struct.pack('<BBHHH',2,0,8,0,0)
    if len(acl)<8:raise ValueError('Invalid SACL')
    rev,_,size,count,_=struct.unpack_from('<BBHHH',acl)
    if rev not in (2,4) or size!=len(acl) or size+len(ace)>65535:raise ValueError('SACL size/revision unsupported')
    offset=8
    for _ in range(count):
        if offset+4>size:raise ValueError('Invalid SACL ACE')
        n=struct.unpack_from('<H',acl,offset+2)[0]
        if n<4 or offset+n>size:raise ValueError('Invalid SACL ACE size')
        raw=acl[offset:offset+n]
        if raw[:2]==b'\x02\x40' and n==20 and raw[8:]==ace[8:] and struct.unpack_from('<I',raw,4)[0]&mask==mask:return acl
        offset+=n
    # Drop only free ACL allocation padding, never an ACE.
    result=bytearray(acl[:offset]+ace)
    struct.pack_into('<H',result,2,len(result));struct.pack_into('<H',result,4,count+1)
    return bytes(result)


class WindowsSacl:
    def __init__(self):
        if os.name!='nt':raise OSError('Windows required')
        from ctypes import wintypes as w
        self.w=w;self.a=ctypes.WinDLL('advapi32',use_last_error=True);self.k=ctypes.WinDLL('kernel32',use_last_error=True)
        self.k.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE];self.k.CreateFileW.restype=w.HANDLE
        self.k.CloseHandle.argtypes=[w.HANDLE];self.k.CloseHandle.restype=w.BOOL
        self.k.GetFileInformationByHandle.argtypes=[w.HANDLE,w.LPVOID];self.k.GetFileInformationByHandle.restype=w.BOOL
        self.k.GetFinalPathNameByHandleW.argtypes=[w.HANDLE,w.LPWSTR,w.DWORD,w.DWORD];self.k.GetFinalPathNameByHandleW.restype=w.DWORD
        self.a.GetKernelObjectSecurity.argtypes=[w.HANDLE,w.DWORD,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)];self.a.GetKernelObjectSecurity.restype=w.BOOL
        self.a.GetSecurityDescriptorSacl.argtypes=[w.LPVOID,ctypes.POINTER(w.BOOL),ctypes.POINTER(w.LPVOID),ctypes.POINTER(w.BOOL)];self.a.GetSecurityDescriptorSacl.restype=w.BOOL
        self.a.SetSecurityInfo.argtypes=[w.HANDLE,ctypes.c_int,w.DWORD,w.LPVOID,w.LPVOID,w.LPVOID,w.LPVOID];self.a.SetSecurityInfo.restype=w.DWORD

    @contextlib.contextmanager
    def open(self,path,root):
        from .process_audit import security_privilege
        w=self.w
        class Info(ctypes.Structure):
            _fields_=[('attrs',w.DWORD),('created',w.FILETIME),('access',w.FILETIME),('written',w.FILETIME),('volume',w.DWORD),('size_hi',w.DWORD),('size_lo',w.DWORD),('links',w.DWORD),('id_hi',w.DWORD),('id_lo',w.DWORD)]
        with security_privilege(self.a):
            # The file SetSecurityInfo path also reads descriptor control.
            # A real fixture denied SACL writes without READ_CONTROL; this adds
            # no DACL/owner write rights and no permission to read file content.
            handle=self.k.CreateFileW(str(path),0x01020080,7,None,3,0x02200000,None)
            if handle==w.HANDLE(-1).value:raise ctypes.WinError(ctypes.get_last_error())
            try:
                info=Info()
                if not self.k.GetFileInformationByHandle(handle,ctypes.byref(info)):raise ctypes.WinError(ctypes.get_last_error())
                if info.attrs&0x400:raise OSError('Reparse objects are not managed')
                buffer=ctypes.create_unicode_buffer(32768);n=self.k.GetFinalPathNameByHandleW(handle,buffer,len(buffer),0)
                if not 0<n<len(buffer):raise OSError('Cannot resolve handle path')
                final=buffer.value.removeprefix('\\\\?\\')
                if final.casefold()!=str(root).rstrip('\\').casefold() and not covers(final,{'path':str(root),'recursive':True}):raise OSError('Resolved path escaped selected root')
                if final.casefold()!=str(Path(path).absolute()).casefold():raise OSError('Path traverses an alias or reparse ancestor')
                yield handle,{'identity':f'{info.volume:08x}:{info.id_hi:08x}{info.id_lo:08x}','directory':bool(info.attrs&16),'links':info.links}
            finally:self.k.CloseHandle(handle)

    def get(self,handle):
        w=self.w;needed=w.DWORD()
        self.a.GetKernelObjectSecurity(handle,8,None,0,ctypes.byref(needed))
        if not 20<=needed.value<=65536:raise OSError('Security descriptor size invalid')
        sd=ctypes.create_string_buffer(needed.value)
        if not self.a.GetKernelObjectSecurity(handle,8,sd,len(sd),ctypes.byref(needed)):raise ctypes.WinError(ctypes.get_last_error())
        present=w.BOOL();defaulted=w.BOOL();acl=w.LPVOID()
        if not self.a.GetSecurityDescriptorSacl(sd,ctypes.byref(present),ctypes.byref(acl),ctypes.byref(defaulted)):raise ctypes.WinError(ctypes.get_last_error())
        if not acl:return None
        size=ctypes.c_ushort.from_address(acl.value+2).value
        if not 8<=size<=65535:raise OSError('Invalid SACL length')
        return ctypes.string_at(acl,size)

    def set(self,handle,acl):
        raw=ctypes.create_string_buffer(acl) if acl is not None else None
        code=self.a.SetSecurityInfo(handle,1,8,None,None,None,raw)
        if code:raise ctypes.WinError(code)

    def flags(self):
        from .process_audit import read_flags
        return read_flags(None,(FILE_SYSTEM,))[FILE_SYSTEM]

    def set_flags(self,flags):
        from .process_audit import auditpol
        auditpol('/set','/subcategory:'+FILE_SYSTEM,'/success:'+('enable' if flags&1 else 'disable'),'/failure:'+('enable' if flags&2 else 'disable'))


class Manager:
    """One worker owns this manager. Every tick is bounded, resumable on restart."""
    def __init__(self,directory,backend=None,excluded=lambda p:False,clock=time.monotonic):
        self.directory=Path(directory);self.directory.mkdir(exist_ok=True)
        self.path=self.directory/'document-sacl.sqlite3';self.backend=backend or WindowsSacl();self.excluded=excluded;self.clock=clock
        self.iterator=None;self.current=None;self.next_scan=0;self.rules=[];self.signature=None;self.errors=0;self.last_error=None
        self.next_policy_check=0
        self.db=sqlite3.connect(self.path,timeout=0.05);self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('CREATE TABLE IF NOT EXISTS objects(path TEXT PRIMARY KEY,root TEXT NOT NULL,identity TEXT NOT NULL,before BLOB,after BLOB NOT NULL,state TEXT NOT NULL); CREATE TABLE IF NOT EXISTS dirs(path TEXT PRIMARY KEY,root TEXT NOT NULL,recursive INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);')
        active=self.db.execute("SELECT value FROM meta WHERE key='active'").fetchone()
        if active:
            self.rules=validate(json.loads(active[0]));self.signature=digest(canonical(self.rules))

    def close(self):
        if self.iterator:self.iterator.close();self.iterator=None
        self.db.close()

    def policy(self,enable):
        row=self.db.execute("SELECT value FROM meta WHERE key='audit_baseline'").fetchone()
        if not enable and not row:return
        current=self.backend.flags()
        baseline=int(row[0]) if row else current
        if current not in (baseline,baseline|1):raise OSError('File System audit policy changed externally; preserved')
        if not row:
            with self.db:self.db.execute("INSERT INTO meta VALUES ('audit_baseline',?)",(str(baseline),))
        desired=baseline|1 if enable else baseline
        if current!=desired:self.backend.set_flags(desired)
        if self.backend.flags()!=desired:raise OSError('File System audit readback mismatch')
        if not enable:
            with self.db:self.db.execute("DELETE FROM meta WHERE key='audit_baseline'")

    def restore_one(self,row):
        try:
            with self.backend.open(row['path'],row['root']) as (h,info):
                if info['identity']!=row['identity']:raise OSError('File identity changed; journal preserved')
                current=self.backend.get(h)
                if current not in (row['before'],row['after']):raise OSError('SACL changed externally; preserved')
                if current==row['after']:
                    self.backend.set(h,row['before'])
                    if self.backend.get(h)!=row['before']:raise OSError('SACL restore readback mismatch')
            with self.db:self.db.execute('DELETE FROM objects WHERE path=?',(row['path'],))
        except FileNotFoundError:
            # Deleted object cannot retain our ACE. A replacement with same path
            # is handled above as a distinct file identity, never reset.
            with self.db:self.db.execute('DELETE FROM objects WHERE path=?',(row['path'],))

    def apply_one(self,path,root,mask):
        if self.excluded(path):return
        with self.backend.open(path,root) as (h,info):
            if info['directory']:return
            if info.get('links',1)>1:raise OSError('Hard-linked files are not managed')
            old=self.db.execute('SELECT * FROM objects WHERE path=?',(str(path),)).fetchone()
            current=self.backend.get(h)
            if old:
                if old['identity']!=info['identity'] or current not in (old['before'],old['after']):raise OSError('SACL/file identity conflict; preserved')
                desired=old['after']
            else:
                if self.db.execute('SELECT count(*) FROM objects').fetchone()[0]>=MAX_OBJECTS:raise OSError('SACL object capacity reached')
                desired=add_audit(current,mask)
                if current==desired:return # already covered; do not claim ownership
                with self.db:self.db.execute('INSERT INTO objects VALUES (?,?,?,?,?,?)',(str(path),str(root),info['identity'],current,desired,'pending'))
            if current!=desired:
                if self.backend.get(h)!=current:raise OSError('SACL changed during journaling; preserved')
                self.backend.set(h,desired)
            if self.backend.get(h)!=desired:raise OSError('SACL apply readback mismatch')
            with self.db:self.db.execute("UPDATE objects SET state='applied' WHERE path=?",(str(path),))

    def tick(self,rules,enabled=True,budget=32,seconds=0.025):
        validate(rules);rules=rules if enabled else [];signature=digest(canonical(rules));start=self.clock();work=0
        if signature!=self.signature:
            if self.iterator:self.iterator.close();self.iterator=None
            self.current=None
            with self.db:self.db.execute('DELETE FROM dirs')
            # Restore old policy before applying any new scope/mask. A conflict
            # blocks new mutations and remains inspectable across restarts.
            for row in self.db.execute('SELECT * FROM objects LIMIT ?',(budget,)).fetchall():
                try:self.restore_one(row)
                except OSError as exc:self.errors+=1;self.last_error=str(exc)[:160];return self.status('restore_conflict')
                work+=1
                if self.clock()-start>=seconds:break
            if self.db.execute('SELECT 1 FROM objects LIMIT 1').fetchone():return self.status('restoring')
            self.policy(bool(rules))
            with self.db:self.db.execute("INSERT OR REPLACE INTO meta VALUES ('active',?)",(canonical(rules),))
            self.signature=signature;self.rules=rules;self.next_scan=0
        if not rules:return self.status('restored')
        if self.clock()>=self.next_policy_check:
            baseline=self.db.execute("SELECT value FROM meta WHERE key='audit_baseline'").fetchone()
            if not baseline or self.backend.flags()!=(int(baseline[0])|1):raise OSError('File System audit changed externally; no automatic policy reassertion')
            self.next_policy_check=self.clock()+900
        if self.path.stat().st_size>MAX_DATABASE:return self.status('capacity_reached')
        if not self.current and not self.db.execute('SELECT 1 FROM dirs LIMIT 1').fetchone():
            if self.clock()<self.next_scan:return self.status('monitoring_periodic')
            with self.db:
                for rule in rules:self.db.execute('INSERT OR IGNORE INTO dirs VALUES (?,?,?)',(rule['path'],rule['path'],rule['recursive']))
            self.next_scan=self.clock()+600
        while work<budget and self.clock()-start<seconds:
            work+=1
            try:
                if not self.current:
                    row=self.db.execute('SELECT * FROM dirs ORDER BY rowid LIMIT 1').fetchone()
                    if not row:break
                    self.current=dict(row)
                    # Check the directory handle before enumerating. Every file
                    # is separately handle-checked again before any ACL write.
                    with self.backend.open(row['path'],row['root']) as (_,info):
                        if not info['directory']:raise OSError('Selected audit root is not a directory')
                    self.iterator=os.scandir(row['path'])
                entry=next(self.iterator)
                if entry.is_symlink() or getattr(entry.stat(follow_symlinks=False),'st_file_attributes',0)&0x400 or self.excluded(entry.path):continue
                if entry.is_dir(follow_symlinks=False):
                    if self.current['recursive']:
                        if self.db.execute('SELECT count(*) FROM dirs').fetchone()[0]>=MAX_DIRS:raise OSError('Directory capacity reached')
                        with self.db:self.db.execute('INSERT OR IGNORE INTO dirs VALUES (?,?,1)',(entry.path,self.current['root']))
                elif entry.is_file(follow_symlinks=False):
                    rule=next(r for r in rules if r['path']==self.current['root'])
                    self.apply_one(entry.path,self.current['root'],1)
            except StopIteration:
                self.iterator.close();self.iterator=None
                with self.db:self.db.execute('DELETE FROM dirs WHERE path=?',(self.current['path'],))
                self.current=None
            except OSError as exc:
                self.errors+=1;self.last_error=str(exc)[:160]
                if self.iterator:self.iterator.close();self.iterator=None
                if self.current:
                    with self.db:self.db.execute('DELETE FROM dirs WHERE path=?',(self.current['path'],))
                self.current=None
        return self.status('provisioning' if self.current or self.db.execute('SELECT 1 FROM dirs LIMIT 1').fetchone() else 'monitoring_with_gaps' if self.errors else 'monitoring_periodic')

    def status(self,state):
        return {'status':state,'managed_objects':self.db.execute('SELECT count(*) FROM objects').fetchone()[0],'pending_directories':self.db.execute('SELECT count(*) FROM dirs').fetchone()[0],'errors':self.errors,'last_error':self.last_error,'scan_interval_seconds':600,'coverage':'selected_local_regular_files_periodic_no_reparse_no_hardlinks','new_file_gap_possible':True}
