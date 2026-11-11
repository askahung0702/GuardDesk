import base64
import copy
import http.cookiejar
import json
import os
import struct
import time
import unittest
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zlib
from unittest.mock import patch
import test_system
from guarddesk.application_control import applocker_xml
from guarddesk.policy import DEFAULT_POLICY,validate_policy
from guarddesk.windows_events import SecurityCollector
from guarddesk.windows_watch import RenamePairs,DirectoryMonitor
from guarddesk.browser_host import handle_message
from guarddesk import remote


def frame():
    def chunk(tag,data):return struct.pack('>I',len(data))+tag+data+struct.pack('>I',zlib.crc32(tag+data)&0xffffffff)
    data=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',1,1,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b'\0\0\0\0'))+chunk(b'IEND',b'')
    return {'width':1,'height':1,'png':base64.b64encode(data).decode()}


class DetailedControlsTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent
    publish=test_system.SystemTest.publish

    def test_process_events_keep_identity_and_drop_commandline(self):
        agent,eid,_=self.make_agent();collector=SecurityCollector(agent,source=object());policy=copy.deepcopy(DEFAULT_POLICY)
        start={'record_id':55,'event_id':4688,'occurred':time.time(),'data':{'SubjectDomainName':'ACME','SubjectUserName':'alice','NewProcessName':r'C:\Apps\editor.exe','NewProcessId':'0x123','ProcessId':'0x100','ParentProcessName':r'C:\Windows\explorer.exe','CommandLine':'password=should-never-upload'}}
        with agent.db() as db:
            collector.ingest(db,start,policy)
            collector.ingest(db,{**start,'record_id':56,'event_id':4689,'data':{'SubjectDomainName':'ACME','SubjectUserName':'alice','ProcessName':r'C:\Apps\editor.exe','ProcessId':'0x123','Status':'0x0'}},policy)
        agent.flush();rows=self.api('/api/events?category=applications')['items']
        self.assertEqual({r['kind'] for r in rows},{'application.started','application.stopped'})
        self.assertTrue(all(r['details']['user']==r'ACME\alice' for r in rows))
        self.assertNotIn('should-never-upload',json.dumps(rows))
        self.assertEqual(self.api('/api/events?category=files')['total'],0)
        self.assertEqual(self.api('/api/events?kind=application.started')['total'],1)
        self.assertEqual(self.api('/api/events?start='+str(time.time()+1))['total'],0)
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/events?category=invalid')

    def test_rename_pairs_preserve_full_source_destination_without_guessing(self):
        pairs=RenamePairs();self.assertEqual(pairs.consume([(4,r'C:\Docs\a.txt')],now=10),[])
        result=pairs.consume([(5,r'C:\Archive\a.txt')],now=10.1)
        self.assertEqual(result[0][0],'file.moved');self.assertEqual(result[0][1]['destination_path'],r'C:\Archive\a.txt')
        self.assertEqual(pairs.consume([(4,r'C:\Docs\a.txt'),(5,r'C:\Docs\b.txt')],now=11)[0][0],'file.renamed')
        result=pairs.consume([(4,r'C:\Docs\a.txt'),(1,r'D:\Docs\a.txt'),(5,r'C:\Docs\b.txt')],now=12)
        self.assertNotIn('file.moved',[kind for kind,_ in result]);self.assertEqual(len(result),3)

    @unittest.skipUnless(os.name=='nt','Windows native watcher')
    def test_real_native_move_reports_both_paths(self):
        agent,_,_=self.make_agent();policy=copy.deepcopy(DEFAULT_POLICY);policy['file_audit']['scope']='managed'
        agent.audit_runtime=agent.config_path.parent
        first=self.watch/'before';second=self.watch/'after';first.mkdir();second.mkdir();source=first/'move.txt';source.write_text('test')
        monitor=DirectoryMonitor(agent,policy);monitor.start();time.sleep(.15)
        try:
            source.rename(second/'move.txt');deadline=time.monotonic()+4;rows=[]
            while time.monotonic()<deadline:
                with agent.db() as db:rows=[json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox')]
                if any(r['kind']=='file.moved' for r in rows):break
                time.sleep(.05)
            self.assertTrue(any(r['kind']=='file.moved' for r in rows),rows)
            moved=next(r for r in rows if r['kind']=='file.moved')
            self.assertEqual(moved['details']['source_path'],str(source));self.assertEqual(moved['details']['destination_path'],str(second/'move.txt'))
        finally:monitor.close()

    def test_application_policy_is_deterministic_and_has_safety_baseline(self):
        control={'enabled':True,'mode':'denylist','block_msi':True,'rules':[{'name':'Blocked editor','collection':'Exe','type':'sha256','value':'a'*64}]}
        xml=applocker_xml(control);self.assertEqual(xml,applocker_xml(control));tree=ET.fromstring(xml)
        self.assertEqual(tree.find('.//FileHashRule').attrib['Action'],'Deny')
        msi=tree.find("RuleCollection[@Type='Msi']");self.assertEqual({r.attrib['UserOrGroupSid'] for r in msi},{'S-1-5-18','S-1-5-32-544'})
        control['mode']='allowlist';tree=ET.fromstring(applocker_xml(control));self.assertEqual(tree.find('.//FileHashRule').attrib['Action'],'Allow')
        policy=copy.deepcopy(DEFAULT_POLICY);policy['application_control']={'enabled':True,'mode':'denylist','block_msi':False,'rules':[{'name':'Unsafe','collection':'Exe','type':'path','value':r'*\GuardDesk.exe'}]}
        with self.assertRaises(ValueError):validate_policy(policy)

    def test_browser_title_and_sensitive_url_redaction(self):
        agent,_,_=self.make_agent();handle_message(agent,{'type':'page_title','url':'https://example.com/report?access_token=secret&q=review#fragment','title':'Report <test>'})
        with agent.db() as db:row=json.loads(db.execute('SELECT payload FROM outbox').fetchone()[0])
        self.assertEqual(row['kind'],'web.page_title');self.assertEqual(row['details']['title'],'Report <test>')
        self.assertNotIn('secret',row['details']['url']);self.assertIn('q=review',row['details']['url'])

    def support(self):
        self.api('/api/remote/account',{'username':'helper','password':self.password})
        client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        login=self.api('/api/login',{'username':'helper','password':self.password},client=client)
        def call(path,body=None):
            req=urllib.request.Request(self.url+path,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json','X-CSRF-Token':login['csrf']})
            with client.open(req,timeout=5) as response:return json.load(response)
        return call

    def prepare_remote(self,control=False):
        agent,eid,_=self.make_agent();support=self.support();agent.call('/api/agent/remote/poll',{'account':r'ACME\alice','ready':True})
        self.api('/api/remote/grant',{'username':'helper','device_id':eid,'can_control':control,'enabled':True,'days':1})
        session=support('/api/remote/request',{'device_id':eid,'mode':'control' if control else 'view','reason':'test support'})
        return agent,eid,support,session

    def test_remote_permission_consent_and_view_only_cannot_control(self):
        agent,eid,support,s=self.prepare_remote()
        with self.assertRaises(urllib.error.HTTPError):support('/api/state')
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/remote/request',{'device_id':eid,'mode':'view','reason':'admin lacks explicit grant'})
        with self.assertRaises(ConnectionError):agent.call('/api/agent/remote/update',{'session_id':s['id'],'action':'frame','frame':frame()})
        agent.call('/api/agent/remote/update',{'session_id':s['id'],'action':'approve','account':r'ACME\alice'})
        agent.call('/api/agent/remote/update',{'session_id':s['id'],'action':'frame','frame':frame()})
        self.assertIn('frame',support('/api/remote/session?id='+s['id']))
        with self.assertRaises(urllib.error.HTTPError):support('/api/remote/input',{'session_id':s['id'],'actions':[{'type':'key','key':65,'down':True}]})
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/remote/session?id='+s['id'])
        support('/api/remote/stop',{'session_id':s['id']});self.assertNotIn(s['id'],self.server.remote_memory)
        self.assertNotIn('png',self.db.read_bytes().decode('latin1'))

    def test_remote_input_bounds_grant_revoke_and_disconnect_cleanup(self):
        agent,eid,support,s=self.prepare_remote(control=True);sid=s['id']
        agent.call('/api/agent/remote/update',{'session_id':sid,'action':'approve','account':r'ACME\alice'})
        for action in [{'type':'shell','command':'bad'},{'type':'click','x':2,'y':0},{'type':'key','key':9999,'down':True}]:
            with self.assertRaises(urllib.error.HTTPError):support('/api/remote/input',{'session_id':sid,'actions':[action]})
        support('/api/remote/input',{'session_id':sid,'actions':[{'type':'click','x':.5,'y':.5}]})
        result=agent.call('/api/agent/remote/update',{'session_id':sid,'action':'frame','frame':frame()});self.assertEqual(len(result['commands']),1)
        self.api('/api/remote/grant',{'username':'helper','device_id':eid,'can_control':False,'enabled':False})
        self.assertEqual(support('/api/remote/session?id='+sid)['status'],'closed');self.assertNotIn(sid,self.server.remote_memory)
        self.api('/api/remote/grant',{'username':'helper','device_id':eid,'can_control':False,'enabled':True,'days':1})
        s=support('/api/remote/request',{'device_id':eid,'mode':'view','reason':'second'});sid=s['id']
        agent.call('/api/agent/remote/update',{'session_id':sid,'action':'approve','account':r'ACME\alice'})
        agent.call('/api/agent/remote/update',{'session_id':sid,'action':'frame','frame':frame()})
        with self.store.connect() as db:
            db.execute('UPDATE remote_sessions SET viewer_seen=? WHERE id=?',(time.time()-9,sid));remote.sweep(self.server,db)
        self.assertNotIn(sid,self.server.remote_memory);self.assertEqual(support('/api/remote/session?id='+sid)['ended_reason'],'participant_disconnected')


if __name__=='__main__':unittest.main()
