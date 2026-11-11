"""Resumable fallback audit of new/deleted files; existing contents are not reread."""
import hashlib
import json
import os
import time
from pathlib import Path
from .policy import MAX_FILE
from .serialization import canonical
from .file_exclusions import excluded


class Snapshot:
    def __init__(self,agent,exclude_paths=()):
        self.agent=agent;self.errors=[];self.error_count=0;self.files=0;self.phase='walk'
        self.exclude_paths=list(exclude_paths)
        self.entries=self.walk(agent.root)
        with agent.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS scan_seen(path TEXT PRIMARY KEY)')
            db.execute('DELETE FROM scan_seen')

    def error(self,error):
        self.error_count+=1
        if len(self.errors)<5:self.errors.append(str(error)[:200])

    def walk(self,root,depth=0):
        if excluded(str(root),self.exclude_paths):return
        if depth>64:
            self.error('目錄超過 64 層，保留既有紀錄');return
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    try:
                        if excluded(entry.path,self.exclude_paths):
                            yield None;continue
                        if entry.is_symlink() or entry.is_junction():
                            yield None;continue
                        if entry.is_dir(follow_symlinks=False):
                            yield None
                            yield from self.walk(Path(entry.path),depth+1)
                        elif entry.is_file(follow_symlinks=False):yield entry
                    except OSError as exc:
                        self.error(exc);yield None
        except OSError as exc:self.error(exc)

    def record(self,db,entry):
        path=Path(entry.path);relative=str(path.relative_to(self.agent.root))
        stat=entry.stat(follow_symlinks=False)
        old=db.execute('SELECT signature FROM files WHERE path=?',(relative,)).fetchone()
        before=json.loads(old[0]) if old else {}
        metadata={'size':stat.st_size,'mtime_ns':stat.st_mtime_ns,'ctime_ns':stat.st_ctime_ns}
        unchanged=all(before.get(k)==v for k,v in metadata.items())
        if not unchanged:
            # Existing files need only a presence/metadata baseline for deletes.
            # Keep the original discovery hash as historical metadata, not as
            # a claim about the current content; do not periodically rehash.
            sha=before.get('sha256')
            if not old and stat.st_size<=MAX_FILE:
                digest=hashlib.sha256();read=0
                # Bound peak allocation even when a file grows while being hashed.
                with path.open('rb') as stream:
                    while read<=MAX_FILE:
                        data=stream.read(min(65536,MAX_FILE+1-read))
                        if not data:break
                        read+=len(data);digest.update(data)
                after=path.stat()
                if (after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=(stat.st_size,stat.st_mtime_ns,stat.st_ctime_ns) or read!=stat.st_size:
                    self.error('檔案掃描期間變動，留待下輪：'+relative);return
                if read<=MAX_FILE:sha=digest.hexdigest()
            signature=canonical({**metadata,'sha256':sha,'verified_at':time.time()})
            if not old:self.agent.queue('file.created',{'path':str(path.absolute()),'relative_path':relative,**metadata,'sha256':sha,'source':'fallback_snapshot'},db=db)
            db.execute('INSERT OR REPLACE INTO files VALUES (?,?)',(relative,signature))
        db.execute('INSERT OR IGNORE INTO scan_seen VALUES (?)',(relative,));self.files+=1

    def step(self,max_entries=200,time_budget=.05):
        started=time.monotonic();processed=0;complete=False
        with self.agent.db() as db:
            while processed<max_entries and (processed==0 or time.monotonic()-started<time_budget):
                if self.phase=='walk':
                    try:entry=next(self.entries)
                    except StopIteration:
                        self.phase='delete'
                        if self.error_count:complete=True;break
                        continue
                    processed+=1
                    if entry is not None:
                        try:self.record(db,entry)
                        except OSError as exc:self.error(exc)
                else:
                    # Delete only after a complete successful traversal, in bounded slices.
                    rows=db.execute('SELECT path FROM files WHERE NOT EXISTS (SELECT 1 FROM scan_seen WHERE scan_seen.path=files.path) LIMIT ?',(max_entries-processed,)).fetchall()
                    if not rows:complete=True;break
                    for (path,) in rows:
                        full_path=str((self.agent.root/path).absolute())
                        if not excluded(full_path,self.exclude_paths):
                            self.agent.queue('file.deleted',{'path':full_path,'relative_path':path,'source':'fallback_snapshot'},'warning',db=db)
                        db.execute('DELETE FROM files WHERE path=?',(path,));processed+=1
                    break
            if complete and self.error_count:self.agent.queue('agent.scan_partial',{'errors':self.errors,'error_count':self.error_count},'warning',db=db)
        return {'files':self.files,'partial':bool(self.error_count),'in_progress':not complete,'entries_this_slice':processed,'slice_ms':round((time.monotonic()-started)*1000,2)}

    def close(self):self.entries.close()
