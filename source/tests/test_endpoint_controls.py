import copy
import io
import json
import os
import socket
import socketserver
import struct
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from guarddesk.agent import Agent,private_write
from guarddesk.browser_host import handle_message,native_read,native_write,run_host,extension_id
from guarddesk.policy import DEFAULT_POLICY,normalize_policy,validate_policy
from guarddesk.store import canonical
from guarddesk.upload_proxy import GuardProxy,SharedLimiter,domain_matches,matching_rate,pac_script
from guarddesk.windows_controls import qos_plan
from guarddesk.windows_controls import WindowsControls,USB_KEY
from guarddesk.windows_events import SecurityCollector,excluded,parse_event
from guarddesk.windows_watch import DirectoryMonitor,decode_notifications


def event(record,event_id,path=r'C:\Users\employee\report.txt',mask='0x1'):
    data={'SubjectDomainName':'COMPANY','SubjectUserName':'employee','SubjectUserSid':'S-1-5-21-1','SubjectLogonId':'0x20','ProcessId':'0x14','HandleId':'0x30','ProcessName':r'C:\Windows\notepad.exe'}
    if event_id!=4660:data.update(ObjectName=path,ObjectType='File',AccessMask=mask)
    return {'record_id':record,'event_id':event_id,'occurred':time.time()-1,'data':data}


class EndpointTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.watch=self.root/'documents';self.watch.mkdir()
        self.config=self.root/'runtime'/'agent'/'config.json'
        private_write(self.config,{'server':'http://127.0.0.1:1','token':'test-token','device_id':'test-device','watch':str(self.watch)})
        self.agent=Agent(self.config)
        self.policy=copy.deepcopy(DEFAULT_POLICY)

    def tearDown(self):
        self.agent.close_collectors();self.temp.cleanup()

    def queued(self):
        with self.agent.db() as db:return [json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox ORDER BY created')]

    def save_policy(self):
        with self.agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)",(canonical({'version':2,'body':self.policy}),))

    def test_browser_offline_native_framing_and_stable_identity(self):
        message={'type':'navigation','event_id':'browser-test-1','url':'https://name:password@example.com/upload?q=123#fragment','browser':'edge','tab_id':2,'timestamp':(time.time()-60)*1000,'request_id':'one'}
        source=io.BytesIO();native_write(source,message);source.seek(0)
        reply=io.BytesIO();run_host(self.config,source,reply);reply.seek(0)
        result=native_read(reply)
        self.assertTrue(result['recorded']);self.assertEqual(result['request_id'],'one')
        handle_message(self.agent,message) # Lost ack retry must not duplicate outbox.
        rows=self.queued();self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['details']['url'],'https://example.com/upload?q=123')
        self.assertIn('user',rows[0]['details']);self.assertLess(rows[0]['occurred'],time.time()-50)
        self.assertEqual(Agent(self.config).queue_status()['pending'],1)
        with self.assertRaises(ConnectionError):self.agent.flush()
        self.assertEqual(self.agent.queue_status()['pending'],1)
        self.assertEqual(len(extension_id()),32)

    def test_native_rejects_oversize_invalid_and_disabled_logging(self):
        with self.assertRaises(ValueError):native_read(io.BytesIO(struct.pack('<I',1024*1024+1)))
        with self.assertRaises(ValueError):native_read(io.BytesIO(b'\x01\x00'))
        with self.assertRaises(ValueError):handle_message(self.agent,{'type':'exec','command':'not-allowed'})
        self.policy['browser_audit']=False;self.save_policy()
        self.assertFalse(handle_message(self.agent,{'type':'navigation','url':'https://example.com'})['recorded'])
        self.assertEqual(self.queued(),[])

    def test_usb_registry_read_only_block_and_restore_adapter(self):
        class Key:
            def __enter__(inner):return inner
            def __exit__(inner,*args):pass
        values={}
        class Registry:
            HKEY_LOCAL_MACHINE=1;KEY_SET_VALUE=2;KEY_QUERY_VALUE=4;REG_DWORD=4
            @staticmethod
            def OpenKey(*args):return Key()
            @staticmethod
            def CreateKeyEx(*args):return Key()
            @staticmethod
            def QueryValueEx(key,name):
                if name not in values:raise FileNotFoundError(name)
                return values[name]
            @staticmethod
            def SetValueEx(key,name,reserved,kind,value):values[name]=(value,kind)
            @staticmethod
            def DeleteValue(key,name):
                if name not in values:raise FileNotFoundError(name)
                del values[name]
        controls=WindowsControls(self.agent);controls.directory.mkdir(parents=True)
        with patch.dict('sys.modules',{'winreg':Registry}):
            controls.apply_usb('read_only')
            self.assertEqual(values['Deny_Read'][0],0);self.assertEqual(values['Deny_Write'][0],1)
            controls.apply_usb('block')
            self.assertEqual(values['Deny_Read'][0],1)
            controls.apply_usb('allow')
            self.assertEqual(values,{})

    def test_security_events_read_write_delete_and_exclusions(self):
        rows=[event(10,4656),event(11,4663,mask='0x3'),event(12,4660),event(13,4663,path=r'C:\Windows\secret.txt'),event(14,4663,path=r'C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.txt')]
        class Source:
            def bounds(inner):return 1,14
            def after(inner,cursor):return [e for e in rows if e['record_id']>cursor]
        with self.agent.db() as db:db.execute("INSERT INTO state VALUES ('security_cursor','9')")
        collector=SecurityCollector(self.agent,Source());collector.poll(self.policy)
        queued=self.queued()
        self.assertEqual([r['kind'] for r in queued],['file.open_requested','file.opened','file.deleted'])
        self.assertTrue(all(r['details']['user']=='COMPANY\\employee' for r in queued))
        self.assertEqual(queued[-1]['details']['path'],r'C:\Users\employee\report.txt')
        SecurityCollector(Agent(self.config),Source()).poll(self.policy)
        self.assertEqual(len(self.queued()),3)

    def test_security_cursor_rollback_and_log_gap(self):
        class Source:
            def bounds(inner):return 1,10
            def after(inner,cursor):return [event(10,4663)] if cursor<10 else []
        with self.agent.db() as db:db.execute("INSERT INTO state VALUES ('security_cursor','9')")
        collector=SecurityCollector(self.agent,Source())
        with patch.object(self.agent,'queue',side_effect=OSError('disk full')):
            with self.assertRaises(OSError):collector.poll(self.policy)
        with self.agent.db() as db:self.assertEqual(db.execute("SELECT value FROM state WHERE key='security_cursor'").fetchone()[0],'9')
        self.assertEqual(self.queued(),[])
        with self.agent.db() as db:db.execute("UPDATE state SET value='1000' WHERE key='security_cursor'")
        collector.poll(self.policy)
        self.assertIn('agent.audit_gap',[r['kind'] for r in self.queued()])

    @unittest.skipUnless(os.name=='nt','Windows only')
    def test_real_native_directory_create_modify_delete(self):
        self.policy['file_audit']['scope']='managed'
        monitor=DirectoryMonitor(self.agent,self.policy)
        try:
            self.assertEqual(monitor.start()['active'],1)
            time.sleep(.15)
            path=self.watch/'native.txt';path.write_text('first');time.sleep(.15)
            path.write_text('second');time.sleep(.15);path.unlink()
            deadline=time.monotonic()+4
            while time.monotonic()<deadline:
                kinds={r['kind'] for r in self.queued()}
                if {'file.created','file.deleted'}<=kinds:break
                time.sleep(.05)
            self.assertTrue({'file.created','file.deleted'}<=kinds,kinds)
            self.assertNotIn('file.modified',kinds)
        finally:monitor.close()

    def test_http_proxy_really_throttles_upload_and_records_bytes(self):
        class Echo(BaseHTTPRequestHandler):
            def do_POST(inner):
                body=inner.rfile.read(int(inner.headers['Content-Length']))
                result=json.dumps({'received':len(body)}).encode()
                inner.send_response(200);inner.send_header('Content-Length',str(len(result)));inner.end_headers();inner.wfile.write(result)
            def log_message(*args):pass
        upstream=ThreadingHTTPServer(('127.0.0.1',0),Echo)
        thread=threading.Thread(target=upstream.serve_forever,daemon=True);thread.start()
        port=upstream.server_port
        self.policy['upload_rules']=[{'type':'domain','target':'test.local','rate_kbps':64}];self.save_policy()
        proxy=GuardProxy(('127.0.0.1',0),self.agent,allow_loopback=True,ports=(port,))
        proxy_thread=threading.Thread(target=proxy.serve_forever,daemon=True);proxy_thread.start()
        original=socket.getaddrinfo
        def resolve(host,*args,**kwargs):return original('127.0.0.1' if host=='test.local' else host,*args,**kwargs)
        try:
            with patch('guarddesk.upload_proxy.socket.getaddrinfo',side_effect=resolve):
                with socket.create_connection(proxy.server_address,timeout=10) as client:
                    content=b'x'*8192
                    request=(f'POST http://test.local:{port}/upload HTTP/1.1\r\nHost: test.local\r\nContent-Length: {len(content)}\r\n\r\n').encode()+content
                    started=time.monotonic();client.sendall(request);client.shutdown(socket.SHUT_WR);response=b''
                    while True:
                        chunk=client.recv(4096)
                        if not chunk:break
                        response+=chunk
                    elapsed=time.monotonic()-started
            self.assertIn(b'"received": 8192',response)
            self.assertGreater(elapsed,.95)
            self.assertLess(elapsed,8)
            records=[r for r in self.queued() if r['kind']=='network.upload']
            self.assertTrue(records)
            self.assertGreater(records[0]['details']['outgoing_bytes'],8192)
        finally:
            proxy.close();upstream.shutdown();upstream.server_close();thread.join(3)

    def test_connect_tunnel_preserves_opaque_bytes(self):
        class Echo(socketserver.BaseRequestHandler):
            def handle(inner):
                while True:
                    data=inner.request.recv(4096)
                    if not data:return
                    inner.request.sendall(data)
        upstream=socketserver.ThreadingTCPServer(('127.0.0.1',0),Echo)
        thread=threading.Thread(target=upstream.serve_forever,daemon=True);thread.start()
        self.policy['upload_rules']=[{'type':'domain','target':'test.local','rate_kbps':1000}];self.save_policy()
        proxy=GuardProxy(('127.0.0.1',0),self.agent,allow_loopback=True,ports=(upstream.server_address[1],))
        proxy_thread=threading.Thread(target=proxy.serve_forever,daemon=True);proxy_thread.start()
        original=socket.getaddrinfo
        def resolve(host,*args,**kwargs):return original('127.0.0.1' if host=='test.local' else host,*args,**kwargs)
        try:
            with patch('guarddesk.upload_proxy.socket.getaddrinfo',side_effect=resolve):
                with socket.create_connection(proxy.server_address,timeout=5) as client:
                    client.sendall(f'CONNECT test.local:{upstream.server_address[1]} HTTP/1.1\r\nHost: test.local\r\n\r\n'.encode())
                    self.assertIn(b'200 Connection Established',client.recv(4096))
                    opaque=b'\x16\x03\x01\x00\x05opaque';client.sendall(opaque)
                    self.assertEqual(client.recv(len(opaque)),opaque)
        finally:proxy.close();upstream.shutdown();upstream.server_close();thread.join(3)


class PureControlsTest(unittest.TestCase):
    def test_policy_migration_validation_and_three_rule_types(self):
        old={k:v for k,v in DEFAULT_POLICY.items() if k in ('mode','allow_export','blocked_extensions','keywords','max_export_mb')}
        self.assertEqual(normalize_policy(old)['usb_mode'],'allow')
        p=copy.deepcopy(DEFAULT_POLICY)
        p['upload_rules']=[{'type':'domain','target':'*.example.com','rate_kbps':500},{'type':'app','target':'OneDrive.exe','rate_kbps':1000},{'type':'user','target':'COMPANY\\alice','rate_kbps':2000}]
        validate_policy(p)
        self.assertEqual(len(qos_plan(p['upload_rules'])),3)
        combination=qos_plan(p['upload_rules'])[-1]
        self.assertEqual(combination['rate_bps'],1000000);self.assertEqual(combination['precedence'],200)
        self.assertEqual(combination['user'],'COMPANY\\alice')
        for invalid in ['https://example.com/a','example.com;evil','*.example.com/path']:
            p['upload_rules'][0]['target']=invalid
            with self.assertRaises(ValueError):validate_policy(p)

    def test_shared_limiter_domain_matching_and_pac(self):
        limiter=SharedLimiter(clock=lambda:0)
        self.assertEqual(limiter.delay('rule',1000,8000),1)
        self.assertEqual(limiter.delay('rule',1000,8000),2)
        self.assertEqual(limiter.delay('other',1000,8000),1)
        self.assertTrue(domain_matches('upload.EXAMPLE.com','*.example.com'))
        self.assertFalse(domain_matches('example.com.attacker.org','*.example.com'))
        self.assertFalse(domain_matches('example.com','*.example.com'))
        rules=[{'type':'domain','target':'example.com','rate_kbps':100}]
        self.assertEqual(matching_rate('example.com',rules),100)
        script=pac_script(rules,17879)
        self.assertIn('PROXY 127.0.0.1:17879',script);self.assertNotIn('PROXY 127.0.0.1:17879; DIRECT',script)

    def test_native_notification_decoder_and_system_exclusion(self):
        name='測試.txt'.encode('utf-16-le')
        self.assertEqual(decode_notifications(struct.pack('<III',0,1,len(name))+name),[(1,'測試.txt')])
        with self.assertRaises(ValueError):decode_notifications(struct.pack('<III',0,1,999)+b'x')
        self.assertTrue(excluded(r'C:\Windows\System32\abc.dll'))
        self.assertTrue(excluded(r'D:\System Volume Information\abc'))
        self.assertFalse(excluded(r'D:\Documents\report.docx'))

    def test_windows_event_xml_identity_and_timestamp(self):
        xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4663</EventID><EventRecordID>7</EventRecordID><TimeCreated SystemTime="2026-10-16T00:01:02.1234567Z"/></System><EventData><Data Name="SubjectUserName">alice</Data><Data Name="AccessMask">0x1</Data></EventData></Event>'
        record=parse_event(xml)
        self.assertEqual(record['record_id'],7);self.assertEqual(record['data']['SubjectUserName'],'alice')


if __name__=='__main__':unittest.main()
