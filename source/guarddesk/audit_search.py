"""Metadata-first bounded substring search; no persistent duplicate payload index."""
import sqlite3
import time
import threading
import re

class SearchTimeout(Exception):pass
class SearchCancelled(Exception):pass
class SearchDuplicate(Exception):pass

class Registry:
    def __init__(self):self.lock=threading.Lock();self.active={};self.cancelled={}
    def cancel(self,owner,identifier):
        if not isinstance(identifier,str) or not re.fullmatch('[0-9a-f]{32}',identifier):raise ValueError('搜尋識別碼不正確')
        with self.lock:
            now=time.monotonic();self.cancelled={k:v for k,v in self.cancelled.items() if now-v<30}
            key=(owner,identifier)
            if key in self.active:self.active[key].set()
            if len(self.cancelled)<128:self.cancelled[key]=now
    def start(self,owner,identifier):
        if not re.fullmatch('[0-9a-f]{32}',identifier):raise ValueError('搜尋識別碼不正確')
        with self.lock:
            key=(owner,identifier)
            if key in self.active:raise SearchDuplicate()
            for (person,_),event in self.active.items():
                if person==owner:event.set()
            event=threading.Event()
            if time.monotonic()-self.cancelled.get(key,-1000)<30:event.set()
            if len(self.active)>=64:raise SearchDuplicate()
            self.active[key]=event;return event
    def finish(self,owner,identifier,event):
        with self.lock:
            if self.active.get((owner,identifier)) is event:self.active.pop((owner,identifier))

def identifiers(db,clause,values,person_join,term,limit,offset=0,count=False,seconds=10,time_filtered=False,cancel=None,indexed=False,sort='id',direction='desc',anchor=None):
    deadline=time.monotonic()+seconds;pattern='%'+term+'%';result=[];total=0
    def interrupted():return bool(cancel and cancel.is_set()) or time.monotonic()>=deadline
    db.set_progress_handler(lambda:int(interrupted()),1000)
    try:
        if cancel and cancel.is_set():raise SearchCancelled()
        if time.monotonic()>=deadline:raise SearchTimeout()
        # Sort metadata/derived keys only, never the compressed payload UNION.
        source='event_headers_time' if time_filtered else 'event_headers'
        from .audit_sort import order
        join,seek,params,ordering=order(db,sort,direction,anchor)
        if seek:
            clause+=(' AND ' if clause else 'WHERE ')+seek;values=tuple(values)+params
        if not term:
            base=' FROM '+source+' e LEFT JOIN devices d ON e.device_id=d.id '+person_join+join+clause
            total=db.execute('SELECT count(*)'+base,values).fetchone()[0] if count else None
            result=[r[0] for r in db.execute('SELECT e.id'+base+' ORDER BY '+ordering+' LIMIT ? OFFSET ?',tuple(values)+(limit,offset))]
            return result,total
        if indexed:
            from .audit_search_index import match
            expression=match(term)
            if expression:
                clause+=(' AND ' if clause else 'WHERE ')+"(e.kind LIKE ? OR COALESCE(d.name,'') LIKE ? OR EXISTS (SELECT 1 FROM audit_search_rows sr WHERE sr.id=e.id AND (sr.document_id=0 OR sr.document_id IN (SELECT rowid FROM audit_search_grams WHERE audit_search_grams MATCH ?))))"
                values=tuple(values)+(pattern,pattern,expression)
        rows=db.execute("SELECT e.id,e.kind,COALESCE(d.name,'') AS device_name FROM "+source+' e LEFT JOIN devices d ON e.device_id=d.id '+person_join+join+clause+' ORDER BY '+ordering,values)
        for row in rows:
            if cancel and cancel.is_set():raise SearchCancelled()
            if time.monotonic()>=deadline:raise SearchTimeout()
            matched=db.execute('SELECT 1 WHERE ? LIKE ? OR ? LIKE ?',(row['kind'],pattern,row['device_name'],pattern)).fetchone()
            if not matched:
                matched=db.execute('SELECT 1 WHERE (SELECT details FROM events WHERE id=?) LIKE ?',(row['id'],pattern)).fetchone()
            if not matched:continue
            if total>=offset and len(result)<limit:result.append(row['id'])
            total+=1
            if not count and len(result)>=limit:break
        return result,total if count else None
    except sqlite3.OperationalError:
        if cancel and cancel.is_set():raise SearchCancelled() from None
        if time.monotonic()>=deadline:raise SearchTimeout() from None
        raise
    finally:db.set_progress_handler(None,0)
