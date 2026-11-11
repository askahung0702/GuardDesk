"""Windows Security channel ingestion with durable cursor + handle correlation.

4656 is an open request, 4663 ReadData is an actual read, and 4660 confirms
deletion. These distinctions are intentionally preserved in the audit stream.
"""
import ctypes
import datetime
import json
import ntpath
import os
import xml.etree.ElementTree as ET
from .file_exclusions import excluded
from .application_exclusions import excluded_application

NS={'e':'http://schemas.microsoft.com/win/2004/08/events/event'}


def parse_event(xml):
    root=ET.fromstring(xml)
    data={n.attrib.get('Name'):n.text or '' for n in root.findall('e:EventData/e:Data',NS)}
    for node in root.findall('e:UserData//*',NS):
        if not list(node):data.setdefault(node.tag.rsplit('}',1)[-1],node.text or '')
    system=root.find('e:System',NS)
    timestamp=system.find('e:TimeCreated',NS).attrib['SystemTime']
    # Windows can emit seven fractional digits; datetime accepts and truncates.
    occurred=datetime.datetime.fromisoformat(timestamp.replace('Z','+00:00')).timestamp()
    return {'record_id':int(system.findtext('e:EventRecordID',namespaces=NS)),
            'event_id':int(system.findtext('e:EventID',namespaces=NS)), 'occurred':occurred,'data':data}


class EventLog:
    def __init__(self,channel='Security',event_ids=(4656,4663,4660,4658,4688,4689,1102)):
        self.channel=channel;self.event_ids=tuple(int(i) for i in event_ids)
        if os.name!='nt':
            raise OSError('Windows Event Log 只適用於 Windows')
        from ctypes import wintypes as w
        self.w=w
        self.api=ctypes.WinDLL('wevtapi',use_last_error=True)
        self.api.EvtQuery.argtypes=[w.HANDLE,w.LPCWSTR,w.LPCWSTR,w.DWORD];self.api.EvtQuery.restype=w.HANDLE
        self.api.EvtNext.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE),w.DWORD,w.DWORD,ctypes.POINTER(w.DWORD)];self.api.EvtNext.restype=w.BOOL
        self.api.EvtRender.argtypes=[w.HANDLE,w.HANDLE,w.DWORD,w.DWORD,w.LPVOID,ctypes.POINTER(w.DWORD),ctypes.POINTER(w.DWORD)];self.api.EvtRender.restype=w.BOOL
        self.api.EvtClose.argtypes=[w.HANDLE];self.api.EvtClose.restype=w.BOOL

    def read(self, query='*', limit=512, reverse=False):
        handle=self.api.EvtQuery(None,self.channel,query,1|(512 if reverse else 256))
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        results=[]
        try:
            while len(results)<limit:
                count=self.w.DWORD();items=(self.w.HANDLE*min(64,limit-len(results)))()
                ok=self.api.EvtNext(handle,len(items),items,0,0,ctypes.byref(count))
                if not ok:
                    error=ctypes.get_last_error()
                    if error==259: break
                    raise ctypes.WinError(error)
                try:
                    for index in range(count.value):
                        used,properties=self.w.DWORD(),self.w.DWORD()
                        self.api.EvtRender(None,items[index],1,0,None,ctypes.byref(used),ctypes.byref(properties))
                        if ctypes.get_last_error()!=122:
                            raise ctypes.WinError(ctypes.get_last_error())
                        buffer=ctypes.create_unicode_buffer((used.value+1)//2)
                        if not self.api.EvtRender(None,items[index],1,ctypes.sizeof(buffer),buffer,ctypes.byref(used),ctypes.byref(properties)):
                            raise ctypes.WinError(ctypes.get_last_error())
                        results.append(parse_event(buffer.value))
                finally:
                    for index in range(count.value): self.api.EvtClose(items[index])
        finally:
            self.api.EvtClose(handle)
        return results

    def bounds(self):
        first=self.read(limit=1)
        last=self.read(limit=1,reverse=True)
        return (first[0]['record_id'],last[0]['record_id']) if first and last else (0,0)

    def after(self, cursor):
        ids=' or '.join('EventID='+str(i) for i in self.event_ids)
        return self.read(f'*[System[({ids}) and EventRecordID>{int(cursor)}]]')


class SecurityCollector:
    def __init__(self,agent,source=None):
        self.agent=agent
        self.source=source or EventLog()
        with agent.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS audit_handles(key TEXT PRIMARY KEY, payload TEXT NOT NULL, record_id INTEGER NOT NULL)')

    def poll(self,policy):
        low,high=self.source.bounds()
        with self.agent.db() as db:
            saved=db.execute("SELECT value FROM state WHERE key='security_cursor'").fetchone()
            if not saved:
                # Start from installation/run time rather than uploading historical logs.
                db.execute("INSERT INTO state VALUES ('security_cursor',?)",(str(high),))
                return {'cursor':high,'baseline':True}
            cursor=int(saved[0])
            if (high<cursor) or (low>cursor+1):
                self.agent.queue('agent.audit_gap',{'old_cursor':cursor,'oldest':low,'newest':high,'reason':'security_log_cleared_or_overwritten'},'critical',db=db)
                cursor=max(low-1,0)
                db.execute('DELETE FROM audit_handles')
            rows=self.source.after(cursor)
            for event in rows:
                self.ingest(db,event,policy)
                cursor=event['record_id']
            # If no matching events exist advance across other Security event families.
            if not rows: cursor=high
            db.execute("INSERT OR REPLACE INTO state VALUES ('security_cursor',?)",(str(cursor),))
            db.execute('DELETE FROM audit_handles WHERE record_id<?',(max(0,cursor-100000),))
        return {'cursor':cursor,'read':len(rows)}

    def ingest(self,db,event,policy):
        d=event['data'];eid=event['event_id'];rid=event['record_id']
        if eid in (4688,4689):
            if not policy.get('application_audit',False):return
            started=eid==4688
            target=d.get('NewProcessName' if started else 'ProcessName','')
            domain=d.get('TargetDomainName') or d.get('SubjectDomainName','')
            account=d.get('TargetUserName') or d.get('SubjectUserName','')
            if account=='-':domain=d.get('SubjectDomainName','');account=d.get('SubjectUserName','')
            details={'path':target,'process':target,'process_id':d.get('NewProcessId' if started else 'ProcessId'),
                     'user':domain+'\\'+account,'user_sid':d.get('TargetUserSid') or d.get('SubjectUserSid'),
                     'parent_process':d.get('ParentProcessName'),'parent_process_id':d.get('ProcessId') if started else None,
                     'exit_status':d.get('Status') if not started else None,'windows_event_id':eid,'record_id':rid,'source':'windows_security'}
            # Command lines can contain credentials; never forward them.
            kind='application.started' if started else 'application.stopped'
            if not excluded_application(kind,'info',details,policy.get('application_audit_exclusions',[])):
                self.agent.queue(kind,details,db=db,occurred=event['occurred'],event_id='security-process-'+str(rid)+'-'+str(event['occurred']))
            return
        if eid!=1102 and (not policy['file_audit']['enabled'] or policy.get('_custom_skip_security_files')):return
        key='|'.join(d.get(n,'') for n in ('SubjectLogonId','ProcessId','HandleId'))
        if eid==1102:
            self.agent.queue('agent.audit_log_cleared',{'record_id':rid},'critical',db=db);return
        if eid==4658:
            db.execute('DELETE FROM audit_handles WHERE key=?',(key,));return
        path=d.get('ObjectName','')
        if eid==4660:
            old=db.execute('SELECT payload FROM audit_handles WHERE key=?',(key,)).fetchone()
            if not old:
                self.agent.queue('agent.audit_unresolved_delete',{'record_id':rid,'process_id':d.get('ProcessId'),'user':d.get('SubjectUserName')},'warning',db=db)
                return
            previous=json.loads(old[0])
            if previous.get('_excluded'):
                db.execute('DELETE FROM audit_handles WHERE key=?',(key,));return
            path=previous.get('ObjectName','');d={**previous,**d,'ObjectName':path}
        if d.get('ObjectType','File')!='File' or not path or not ntpath.isabs(path): return
        if excluded(path,policy['file_audit']['exclude_paths'],self.agent.audit_runtime):
            if eid in (4656,4663):
                # Correlate a later 4660 without keeping the excluded path or
                # reporting a false unresolved-delete warning. Normal bounded
                # handle-close/cursor cleanup removes this metadata marker.
                db.execute('INSERT OR REPLACE INTO audit_handles VALUES (?,?,?)',(key,'{"_excluded":true}',rid))
            return
        if policy['file_audit']['scope']=='managed':
            root=ntpath.normcase(self.agent.config.get('audit_watch',str(self.agent.root))).rstrip('\\')
            if not ntpath.normcase(path).startswith(root+'\\'): return
        if eid in (4656,4663):
            db.execute('INSERT OR REPLACE INTO audit_handles VALUES (?,?,?)',(key,json.dumps(d),rid))
        details={'path':path,'user':d.get('SubjectDomainName','')+'\\'+d.get('SubjectUserName',''),
                 'user_sid':d.get('SubjectUserSid'),'process':d.get('ProcessName'),'process_id':d.get('ProcessId'),
                 'windows_event_id':eid,'record_id':rid,'source':'windows_security','access_mask':d.get('AccessMask')}
        if eid==4656:
            # Request is never falsely described as a successful open/read.
            kinds=['file.open_requested']
            mask=int(d.get('AccessMask','0'),0)
            if policy.get('_native_interactive_open_primary') and mask and not mask&~0x120089:kinds=[]
        elif eid==4660: kinds=['file.deleted']
        else:
            mask=int(d.get('AccessMask','0'),0);kinds=[]
            if mask&1 and not policy.get('_native_interactive_open_primary'):kinds.append('file.opened')
            if mask&0x10000:kinds.append('file.delete_requested')
        for kind in kinds:
            self.agent.queue(kind,details,'info',db=db,occurred=event['occurred'],event_id='security-file-'+str(rid)+'-'+str(event['occurred'])+'-'+kind)
            if kind=='file.opened':
                db.execute("INSERT OR REPLACE INTO state VALUES ('document_last_read',?)",(str(event['occurred']),))


class AppLockerCollector:
    def __init__(self,agent):self.agent=agent;self.sources={}
    def poll(self):
        count=0
        for suffix,ids in [('EXE and DLL',(8003,8004)),('MSI and Script',(8006,8007))]:
            source=self.sources.setdefault(suffix,EventLog('Microsoft-Windows-AppLocker/'+suffix,ids))
            low,high=source.bounds();key='applocker_cursor_'+suffix
            with self.agent.db() as db:
                saved=db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()
                cursor=int(saved[0]) if saved else high
                if high<cursor or (low and low>cursor+1):
                    self.agent.queue('agent.audit_gap',{'channel':suffix,'old_cursor':cursor,'oldest':low,'newest':high},'warning',db=db);cursor=max(0,low-1)
                events=source.after(cursor)
                for event in events:
                    d=event['data'];eid=event['event_id'];kind='application.blocked' if eid in (8004,8007) else 'application.audit_would_block'
                    self.agent.queue(kind,{'path':d.get('FilePath',''),'process':d.get('FilePath',''),'user':d.get('TargetUser',d.get('SubjectUserName','')),'process_id':d.get('TargetProcessId'),'rule_name':d.get('RuleName'),'rule_id':d.get('RuleId'),'source':'windows_applocker','windows_event_id':eid,'record_id':event['record_id']},'warning',db=db,occurred=event['occurred'],event_id='applocker-'+str(eid)+'-'+str(event['record_id'])+'-'+str(event['occurred']))
                    cursor=event['record_id'];count+=1
                if not events:cursor=high
                db.execute('INSERT OR REPLACE INTO state VALUES (?,?)',(key,str(cursor)))
        return {'status':'collecting','read':count}
