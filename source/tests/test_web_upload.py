import copy
import json
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk.agent import Agent,private_write
from guarddesk.browser_host import handle_message
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.store import canonical
from guarddesk.upload_proxy import GuardProxy


class WebUploadTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        (self.root/'documents').mkdir();self.config=self.root/'runtime/agent/config.json'
        private_write(self.config,{'server':'http://127.0.0.1:1','token':'fixture-token','device_id':'fixture','watch':str(self.root/'documents')})
        self.agent=Agent(self.config)

    def tearDown(self):
        self.agent.close_collectors();self.temp.cleanup()

    def message(self,phase='started',**extra):
        return {'type':'web_upload','phase':phase,'upload_id':'test-flow','event_id':'browser-test-'+phase,
                'url':'https://name:secret@example.com/upload?token=secret&q=report#fragment','method':'POST',
                'files':[{'path':r'C:\Users\employee\Documents\report.pdf'}],'timestamp':time.time()*1000,'browser':'chrome',**extra}

    def rows(self):
        with self.agent.db() as db:return [json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox')]

    def test_unavailable_body_gap_discarded_before_policy_url_or_queue(self):
        message={'type':'upload_gap','reason':'request_body_unavailable','url':'https://example.com/collect?token=private'}
        with patch('guarddesk.browser_host.current_account',side_effect=AssertionError('ignored diagnostics must not resolve identity')),patch.object(self.agent,'policy_for_user',side_effect=AssertionError('ignored diagnostics must not read policy')),patch.object(self.agent,'queue') as queue:
            reply=handle_message(self.agent,message);queue.assert_not_called()
        self.assertEqual(reply,{'ok':True,'discarded':True})
        # Legacy flush stops only on recorded===false. Omission acknowledges
        # consumption without claiming that the event was actually stored.
        self.assertNotIn('recorded',reply);self.assertFalse(self.rows())

    def test_ignored_gap_retries_preserve_existing_outbox_after_restart(self):
        handle_message(self.agent,self.message());before=self.rows()
        message={'type':'upload_gap','reason':'request_body_unavailable','url':'https://example.com/collect','event_id':'browser-ignored-gap'}
        for _ in range(3):self.assertTrue(handle_message(self.agent,message)['discarded'])
        restarted=Agent(self.config)
        try:self.assertTrue(handle_message(restarted,message)['discarded'])
        finally:restarted.close_collectors()
        self.assertEqual(self.rows(),before)

    def test_direct_agent_queue_discards_same_reason_without_database_access(self):
        with patch.object(self.agent,'db',side_effect=AssertionError('ignored diagnostic must not touch SQLite')):
            self.assertIsNone(self.agent.queue('web.upload_gap',{'reason':'request_body_unavailable','url':'https://example.com/collect'}))
        self.assertFalse(self.rows())

    def test_other_gap_reasons_remain_durable_and_validated(self):
        reasons=('queue_capacity','request_capacity','body_metadata_unresolved')
        for reason in reasons:
            reply=handle_message(self.agent,{'type':'upload_gap','reason':reason,'lost_count':7,'event_id':'browser-gap-'+reason,'url':'https://example.com/collect?token=private'})
            self.assertTrue(reply['recorded'])
        self.assertEqual([row['details']['reason'] for row in self.rows()],list(reasons))
        self.assertTrue(all('private' not in row['details']['url'] for row in self.rows()))
        for reason in ('request_body_unavailable_extra','REQUEST_BODY_UNAVAILABLE','unknown'):
            with self.assertRaises(ValueError):handle_message(self.agent,{'type':'upload_gap','reason':reason,'url':'https://example.com'})
        with self.assertRaises(ValueError):handle_message(self.agent,{'type':'upload_gap','reason':'queue_capacity','lost_count':-1,'url':'https://example.com'})
        self.assertEqual(len(self.rows()),3)

    def test_same_reason_text_on_real_upload_is_not_discarded(self):
        reply=handle_message(self.agent,self.message(reason='request_body_unavailable'))
        self.assertTrue(reply['recorded']);self.assertEqual(len(self.rows()),1)
        self.assertEqual(self.rows()[0]['kind'],'web.upload_started')

    def test_exact_request_evidence_durable_redacted_and_deduplicated(self):
        message=self.message();handle_message(self.agent,message);handle_message(self.agent,message)
        self.assertEqual(len(self.rows()),1);details=self.rows()[0]['details']
        self.assertEqual(details['source_path'],message['files'][0]['path'])
        self.assertEqual(details['correlation'],'same_browser_request_id')
        self.assertNotIn('secret',details['url']);self.assertNotIn('#',details['url'])
        self.assertEqual(Agent(self.config).queue_status()['pending'],1)
        self.assertNotIn('content',details);self.assertEqual(details['application_success'],'unknown')

    def test_http_error_network_error_redirect_and_incomplete_not_success(self):
        for phase,extra in [('response',{'status_code':200,'response_url':'https://example.net/done?sig=secret'}),
                            ('failed',{'error':'net::ERR_CONNECTION_RESET'}),('redirected',{'redirect_url':'https://other.example/?password=secret'}),('interrupted',{})]:
            handle_message(self.agent,self.message(phase,**extra))
        for row in self.rows():self.assertEqual(row['details']['application_success'],'unknown');self.assertNotIn('secret',canonical(row['details']))
        handle_message(self.agent,self.message('response',event_id='browser-http-error',status_code=413))
        self.assertEqual(self.rows()[-1]['details']['status_code'],413)

    def test_no_fake_full_path_and_metadata_only(self):
        for i,path in enumerate([r'C:\fakepath\report.pdf','report.pdf',r'\\?\C:\device.txt']):
            handle_message(self.agent,self.message(event_id='browser-path-'+str(i),files=[{'path':path}]))
        self.assertTrue(all(r['details']['source_path']=='' and r['details']['path_evidence']=='filename_only' for r in self.rows()))
        for extra in [{'files':[{'path':'name','bytes':'private'}]}, {'files':[{'path':'x\ny'}]}, {'status_code':True,'phase':'response'}, {'files':[]}, {'files':[{'path':'x'}]*33}, {'upload_id':'../command'}, {'method':'GET'}, {'phase':'success'}]:
            with self.assertRaises(ValueError):handle_message(self.agent,self.message(**extra))

    def test_user_policy_disable_independently_enforced(self):
        policy=copy.deepcopy(DEFAULT_POLICY);policy['browser_audit']=False
        with self.agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)",(canonical({'version':2,'body':policy}),))
        self.assertFalse(handle_message(self.agent,self.message())['recorded'])
        self.assertFalse(handle_message(self.agent,{'type':'status'})['web_upload_audit']);self.assertFalse(self.rows())

    def test_candidates_and_large_metadata_do_not_block_server_batch_limit(self):
        handle_message(self.agent,self.message(files=[{'path':r'C:\invented\report.pdf','evidence':'selected_filename_match'}]))
        d=self.rows()[0]['details'];self.assertEqual(d['source_path'],'');self.assertEqual(d['correlation'],'selected_filename_candidate')
        message=self.message('redirected',files=[{'path':'C:\\'+('測'*500)+str(i)+'.pdf'} for i in range(32)],
                             url='https://example.com/'+('測'*2000),response_url='https://example.com/'+('測'*2000),redirect_url='https://other.example/'+('測'*2000))
        handle_message(self.agent,message);d=self.rows()[-1]['details']
        self.assertLess(len(canonical(d).encode('utf-8')),16000);self.assertTrue(d['files_truncated']);self.assertTrue(d['url_truncated'])

    def test_duplex_response_during_throttled_backlog_and_early_rejection(self):
        class Upstream(socketserver.BaseRequestHandler):
            def handle(inner):
                inner.request.settimeout(4)
                inner.request.recv(1024)
                inner.request.sendall(b'early-response')
                while inner.request.recv(65536):pass
        server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Upstream)
        server.daemon_threads=True;thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        policy=copy.deepcopy(DEFAULT_POLICY);policy['upload_rules']=[{'type':'domain','target':'test.local','rate_kbps':16}]
        with self.agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)",(canonical({'version':2,'body':policy}),))
        proxy=GuardProxy(('127.0.0.1',0),self.agent,allow_loopback=True,ports=(server.server_address[1],))
        threading.Thread(target=proxy.serve_forever,daemon=True).start()
        resolve=socket.getaddrinfo
        try:
            with patch('guarddesk.upload_proxy.socket.getaddrinfo',side_effect=lambda host,*a,**k:resolve('127.0.0.1' if host=='test.local' else host,*a,**k)):
                with socket.create_connection(proxy.server_address,timeout=3) as client:
                    client.sendall(f'CONNECT test.local:{server.server_address[1]} HTTP/1.1\r\nHost: test.local\r\n\r\n'.encode())
                    self.assertIn(b'200',client.recv(4096));started=time.monotonic();client.sendall(b'x'*16384)
                    self.assertEqual(client.recv(100),b'early-response')
                    # Old drain-first relay waits ~8 seconds at this rate.
                    self.assertLess(time.monotonic()-started,2)
        finally:proxy.close();server.shutdown();server.server_close();thread.join(3)

    def test_page_candidate_never_becomes_full_path_and_site_is_separate(self):
        handle_message(self.agent,self.message(files=[{'path':r'C:\invented\report.pdf','evidence':'page_body_metadata_candidate'}],site_origin='https://chatgpt.com'))
        details=self.rows()[0]['details']
        self.assertEqual(details['source_path'],'');self.assertEqual(details['file_name'],'report.pdf')
        self.assertEqual(details['correlation'],'page_body_metadata_candidate');self.assertEqual(details['site_origin'],'https://chatgpt.com')
        self.assertIn('not_browser_attested',details['evidence_limit'])
        self.assertTrue(handle_message(self.agent,{'type':'status'})['memory_upload_v1'])
        for origin in ('https://user:password@chatgpt.com','https://chatgpt.com/path?token=secret','javascript:alert(1)'):
            with self.assertRaises(ValueError):handle_message(self.agent,self.message(site_origin=origin))


if __name__=='__main__':unittest.main()
