import copy
import base64
import datetime as dt
import http.cookiejar
import io
import json
import os
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import test_system
from guarddesk import mail_reports as mail
from guarddesk.audit_reports import index_batch, TAIPEI, AuditError
from guarddesk.store import Store, canonical

GUID='12345678-1234-1234-1234-123456789012'
BODY={**mail.DEFAULT,'sender':'reports@example.test','recipients':['mis@example.test'],'tenant_id':GUID,'client_id':GUID}


class MailReportsTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.store=Store(self.root/'control.sqlite3')
        self.now=dt.datetime(2026,10,20,8,0,tzinfo=TAIPEI).timestamp()
        self.day='2026-10-19'
        self.worker=mail.MailWorker(self.store,start=False)
        self.env=patch.dict(os.environ,{mail.SECRET_ENV:'synthetic-credential'});self.env.start()

    def tearDown(self):self.env.stop();self.worker.close();self.temp.cleanup()

    def settings(self,enabled=False):
        with self.store.connect() as db:return mail.save(db,{'body':{**BODY,'enabled':enabled},'revision':mail.config(db)[1]},'fixture')

    def device(self,did,name,revoked=0):
        with self.store.connect() as db:db.execute('INSERT INTO devices(id,token,name,department,last_seen,revoked) VALUES(?,?,?,?,?,?)',(did,did,name,'Fixture',self.now,revoked))

    def event(self,kind='file.created',did='dev',when=None):
        with self.store.connect() as db:Store.event(db,did,kind,'info',{'path':'PRIVATE-PATH-DO-NOT-MAIL','user':'PRIVATE-USER'},occurred=when or self.now-3600*10)

    def indexed(self):
        while index_batch(self.store):pass

    def queue(self,revision=1,rid='a'*32):
        with self.store.connect() as db:return mail.enqueue(db,{'day':self.day,'revision':revision,'confirm':'send_report','request_id':rid},'fixture',self.now)

    def job(self):
        with self.store.connect() as db:return dict(db.execute('SELECT * FROM mail_report_jobs ORDER BY created DESC LIMIT 1').fetchone())

    def test_default_disabled_empty_and_no_scheduled_job(self):
        self.worker.schedule(self.now)
        with self.store.connect() as db:
            self.assertFalse(mail.catalog(db)['body']['enabled']);self.assertEqual(mail.catalog(db)['jobs'],[])

    def test_validate_rejects_bad_addresses_ids_time_and_unknown_fields(self):
        for change in ({'sender':'a@example.test\r\nBcc: x@y.test'},{'recipients':['Name <mis@example.test>']},{'recipients':'mis@example.test'},{'recipients':['a@b.test']*21},{'tenant_id':'../../other'},{'client_id':'not-guid'},{'time':'24:00'},{'enabled':1},{'unexpected':'x'}):
            with self.subTest(change=change),self.assertRaises(AuditError):mail.validate({**BODY,**change})

    def test_recipients_are_deduplicated_and_enable_requires_complete_config(self):
        self.assertEqual(mail.validate({**BODY,'recipients':['mis@example.test',' mis@example.test ']})['recipients'],['mis@example.test'])
        with self.assertRaises(AuditError):mail.validate({**BODY,'enabled':True,'sender':''})

    def test_save_revision_conflict_and_secret_not_returned_or_audited(self):
        with patch.object(mail,'protect',return_value='encrypted-fixture'):
            with self.store.connect() as db:r=mail.save(db,{'body':BODY,'revision':0,'client_secret':'DO-NOT-LOG'},'fixture')
        self.assertNotIn('DO-NOT-LOG',canonical(r));self.assertNotIn('encrypted-fixture',canonical(r))
        with self.store.connect() as db:
            with self.assertRaises(AuditError):mail.save(db,{'body':BODY,'revision':0},'fixture')
            self.assertNotIn('DO-NOT-LOG',''.join(x[0] for x in db.execute('SELECT details FROM events')))

    def test_clear_secret_and_missing_credential_refuse_enable(self):
        with patch.dict(os.environ,{mail.SECRET_ENV:''}):
            with self.store.connect() as db:
                with self.assertRaises(AuditError):mail.save(db,{'body':{**BODY,'enabled':True},'revision':0},'fixture')
                with patch.object(mail,'protect',return_value='cipher'):mail.save(db,{'body':BODY,'revision':0,'client_secret':'fake'},'fixture')
                mail.save(db,{'body':BODY,'revision':1,'clear_secret':True},'fixture')
                self.assertEqual(mail.catalog(db)['secret_source'],'missing')

    @unittest.skipUnless(os.name=='nt','DPAPI is Windows-only')
    def test_real_dpapi_roundtrip_never_plaintext(self):
        secret='synthetic-dpapi-test-'+('x'*40)
        sealed=mail.protect(secret)
        self.assertNotIn(secret,sealed);self.assertEqual(mail.protect(sealed,decrypt=True),secret)

    def test_complete_day_and_taipei_midnight(self):
        self.assertEqual(mail.report_day('2026-10-19',self.now),'2026-10-19')
        for value in ('2026-10-20','2026-10-21','2026-02-30','2026-1-1'):
            with self.assertRaises(AuditError):mail.report_day(value,self.now)
        # 16:00 UTC begins the next Taipei day, regardless of OS timezone.
        self.settings(True);self.worker.schedule(dt.datetime(2026,10,20,0,0,tzinfo=TAIPEI).timestamp())
        with self.store.connect() as db:self.assertEqual(mail.catalog(db)['jobs'],[])

    def test_snapshot_computer_names_zero_and_identical_names_not_merged(self):
        self.device('dev','user1');self.device('other','user1');self.device('zero','ZERO');self.device('retired','RETIRED',1)
        for did in ('dev','dev','other','retired'):self.event(did=did)
        self.event(did='missing');self.indexed()
        with self.store.connect() as db:r=mail.snapshot(db,self.day)
        self.assertEqual(r['total'],5);self.assertEqual(len(r['rows']),5)
        self.assertEqual(r['rows'][0]['n'],2);self.assertEqual(sum(x['name']=='user1' for x in r['rows']),2)
        self.assertEqual(next(x for x in r['rows'] if x['name']=='ZERO')['n'],0)
        self.assertEqual(len(set(x['color'] for x in r['rows'])),5)

    def test_day_boundaries_and_only_business_mutations(self):
        start=dt.datetime(2026,10,19,tzinfo=TAIPEI).timestamp()
        self.event(when=start);self.event('file.deleted',when=start+86399)
        self.event(when=start-1);self.event(when=start+86400)
        for kind in ('file.modified','file.opened','file.open_requested','application.started','web.navigation'):self.event(kind,when=start+60)
        self.indexed()
        with self.store.connect() as db:r=mail.snapshot(db,self.day)
        self.assertEqual(r['total'],2);self.assertEqual(r['rows'][0]['created'],1);self.assertEqual(r['rows'][0]['deleted'],1)

    def test_snapshot_waits_for_index_and_does_not_rewrite_hashes(self):
        self.event()
        with self.store.connect() as db:
            before=list(db.execute('SELECT hash FROM events'))
            with self.assertRaises(AuditError):mail.snapshot(db,self.day)
        self.indexed()
        with self.store.connect() as db:
            mail.snapshot(db,self.day);self.assertEqual([r[0] for r in db.execute('SELECT hash FROM events')],[r[0] for r in before])
        self.assertTrue(self.store.verify()['valid'])

    def test_charts_include_all_250_devices_and_html_top20_no_sensitive_fields(self):
        for i in range(250):self.device(str(i),f'PC-{i:03}')
        self.event(did='3');self.event(did='3');self.event(did='20');self.indexed()
        with self.store.connect() as db:data=mail.snapshot(db,self.day)
        images=mail.charts(data);content=mail.render(data,images)
        self.assertEqual(len(images),8);self.assertTrue(all(raw.startswith(b'\x89PNG') for _,raw in images))
        self.assertIn('PC-249',content);self.assertIn('前二十名',content);self.assertNotIn('PRIVATE-PATH',content);self.assertNotIn('PRIVATE-USER',content)
        self.assertEqual(content.count('data:image/png;base64,'),8)
        self.assertNotIn('cid:',content)
        self.assertIn('data:image/png;base64,',mail.render(data,images,preview=True))
        with self.store.connect() as db:self.assertEqual(mail.catalog(db)['jobs'],[])

    def test_html_device_name_escaped_and_zero_chart(self):
        self.device('unsafe','<img src=x onerror=alert(1)>');self.indexed()
        with self.store.connect() as db:data=mail.snapshot(db,self.day)
        content=mail.render(data,mail.charts(data))
        self.assertIn('&lt;img',content);self.assertNotIn('<img src=x',content);self.assertEqual(data['total'],0)

    def test_schedule_once_across_restarts_and_only_yesterday(self):
        self.settings(True);self.worker.schedule(self.now);self.worker.schedule(self.now+3600)
        other=mail.MailWorker(self.store,start=False);other.schedule(self.now)
        with self.store.connect() as db:
            rows=list(db.execute('SELECT * FROM mail_report_jobs'));self.assertEqual(len(rows),1);self.assertEqual(rows[0]['day'],self.day)
        other.schedule(self.now+7*86400)
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM mail_report_jobs').fetchone()[0],2)

    def test_finished_metadata_retention_works_even_when_daily_mail_disabled(self):
        self.settings();self.queue()
        with self.store.connect() as db:
            db.execute("UPDATE mail_report_jobs SET state='accepted',created=?",(self.now-91*86400,))
            before=[r[0] for r in db.execute('SELECT hash FROM events')]
        self.worker.schedule(self.now)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM mail_report_jobs').fetchone()[0],0)
            self.assertEqual([r[0] for r in db.execute('SELECT hash FROM events')],before)

    def test_capacity_is_explicit_error_without_silently_truncated_report(self):
        with self.store.connect() as db:
            db.executemany('INSERT INTO devices(id,token,name,department,last_seen) VALUES(?,?,?,?,?)',[(str(i),str(i),str(i),'Synthetic',self.now) for i in range(1001)])
            with self.assertRaises(AuditError) as error:mail.snapshot(db,self.day)
            self.assertIn('未截斷',error.exception.message)

    def test_expired_queued_daily_job_does_not_send_two_days_late(self):
        self.settings(True);self.worker.schedule(self.now);self.indexed()
        with patch.object(mail,'send') as sender:
            self.worker.process(self.now+2*86400);sender.assert_not_called()
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT state FROM mail_report_jobs WHERE day=?',(self.day,)).fetchone()[0],'cancelled')

    def test_queue_idempotent_and_bound_and_explicit_confirmation(self):
        self.settings();first=self.queue();self.assertEqual(self.queue(),first)
        for i in range(9):self.queue(rid=f'{i:032x}')
        with self.assertRaises(AuditError):self.queue(rid='f'*32)
        with self.store.connect() as db:
            with self.assertRaises(AuditError):mail.enqueue(db,{'day':self.day},'fixture',self.now)

    def test_manual_job_cancelled_when_config_revision_changes(self):
        self.settings();self.queue();self.settings();self.worker.process(self.now)
        self.assertEqual(self.job()['state'],'cancelled')

    def test_queued_job_waits_until_index_is_ready(self):
        self.settings();self.queue();self.event()
        self.assertFalse(self.worker.process(self.now));self.assertEqual(self.job()['state'],'queued')
        self.worker.process(self.now+7*3600);self.assertEqual(self.job()['state'],'failed')

    def test_send_is_outside_sqlite_transaction_and_records_accepted_not_delivered(self):
        self.settings();self.queue();self.event();self.indexed()
        def fake_token(*args):
            with self.store.connect() as db:db.execute('BEGIN IMMEDIATE')
            return 'fake-access'
        def fake_send(body,token,data,images):
            with self.store.connect() as db:
                db.execute('BEGIN IMMEDIATE');self.assertEqual(db.execute('SELECT state FROM mail_report_jobs').fetchone()[0],'sending')
            self.assertEqual(data['total'],1);self.assertEqual(token,'fake-access')
        with patch.object(mail,'token',side_effect=fake_token),patch.object(mail,'send',side_effect=fake_send) as sender:
            self.assertTrue(self.worker.process(self.now));self.worker.process(self.now);self.assertEqual(sender.call_count,1)
        self.assertEqual(self.job()['state'],'accepted');self.assertIn('不代表已送達',self.job()['result'])

    def test_final_revision_recheck_cancels_before_send(self):
        self.settings();self.queue();self.indexed()
        def changed(*args):self.settings();return 'fake'
        with patch.object(mail,'token',side_effect=changed),patch.object(mail,'send') as send:
            self.worker.process(self.now);send.assert_not_called()
        self.assertEqual(self.job()['state'],'cancelled')

    def test_timeout_is_unknown_and_not_retried(self):
        self.settings();self.queue();self.indexed()
        with patch.object(mail,'token',return_value='fake'),patch.object(mail,'send',side_effect=mail.MailFailure('unknown','synthetic ambiguous outcome')) as send:
            self.worker.process(self.now);self.worker.process(self.now);self.assertEqual(send.call_count,1)
        self.assertEqual(self.job()['state'],'unknown')

    def test_crash_recovery_sending_unknown_preparing_retryable(self):
        self.settings();self.queue()
        with self.store.connect() as db:db.execute("UPDATE mail_report_jobs SET state='sending'")
        mail.MailWorker(self.store,start=False);self.assertEqual(self.job()['state'],'unknown')
        with self.store.connect() as db:db.execute("UPDATE mail_report_jobs SET state='preparing'")
        mail.MailWorker(self.store,start=False);self.assertEqual(self.job()['state'],'queued')

    def test_token_and_send_use_fixed_hosts_and_html_attachment(self):
        data={'day':self.day,'rows':[],'total':0,'generated':self.now,'cursor':0};images=mail.charts(data)
        with patch.object(mail,'post',return_value=(200,b'{"access_token":"fake-token"}')) as post:
            self.assertEqual(mail.token(BODY,'secret'),'fake-token');args=post.call_args.args
            self.assertEqual(args[0],f'https://login.microsoftonline.com/{GUID}/oauth2/v2.0/token');self.assertNotIn(b'secret',args[0].encode())
        with patch.object(mail,'post',return_value=(202,b'')) as post:
            mail.send(BODY,'fake',data,images);url,raw,headers=post.call_args.args;message=json.loads(raw)
            self.assertTrue(url.startswith('https://graph.microsoft.com/v1.0/users/'));self.assertTrue(message['saveToSentItems'])
            self.assertEqual(headers['Authorization'],'Bearer fake')
            envelope=message['message'];self.assertEqual(envelope['body']['contentType'],'Text')
            self.assertEqual(len(envelope['attachments']),1);attachment=envelope['attachments'][0]
            self.assertFalse(attachment['isInline']);self.assertEqual(attachment['contentType'],'text/html')
            self.assertEqual(attachment['name'],'GuardDesk-File-Changes-'+self.day+'.html')
            self.assertNotIn('contentId',attachment)
            document=base64.b64decode(attachment['contentBytes'],validate=True).decode('utf-8')
            self.assertEqual(document,mail.render(data,images,preview=True))
            self.assertNotIn('PC-',envelope['body']['content']);self.assertNotIn('<img',envelope['body']['content'])
            self.assertNotIn('<table',envelope['body']['content'])

    def test_html_attachment_250_active_devices_keeps_all_charts_and_data_within_budget(self):
        rows=[dict(device_id=f'owned-{i}',name=f'PC-{i:04}-辦公電腦',rank=i+1,color='#15746f',n=250-i,created=250-i,deleted=0,moved=0,renamed=0) for i in range(250)]
        data=dict(day=self.day,rows=rows,total=sum(r['n'] for r in rows),generated=self.now)
        images=mail.charts(data)
        with patch.object(mail,'post',return_value=(202,b'')) as post:
            mail.send(BODY,'fake',data,images)
            raw=post.call_args.args[1];self.assertLessEqual(len(raw),2800000)
            attachment=json.loads(raw)['message']['attachments'][0]
            document=base64.b64decode(attachment['contentBytes'],validate=True).decode('utf-8')
        self.assertEqual(document.count('data:image/png;base64,'),8)
        for row in rows:self.assertIn(row['name'],document)
        self.assertIn("default-src 'none'",document);self.assertNotIn('<script',document)
        self.assertNotIn('cid:',document);self.assertNotIn('src="http',document)
        print('HTML_ATTACHMENT_CAPACITY '+json.dumps({'devices':250,'charts':len(images),'html_utf8_bytes':len(document.encode('utf-8')),'graph_json_bytes':len(raw)}))

    def test_html_attachment_budget_counts_both_base64_layers_before_send(self):
        data=dict(day=self.day,rows=[],total=0,generated=self.now)
        with patch.object(mail,'post') as post:
            with self.assertRaises(mail.MailFailure) as error:
                mail.send(BODY,'fake',data,[('pie.png',b'a'*1600000)])
            self.assertEqual(error.exception.state,'failed');post.assert_not_called()

    def test_auth_failure_is_safe_failed_and_send_transport_is_ambiguous(self):
        with patch.object(mail,'post',side_effect=ValueError('SECRET-ERROR')):
            with self.assertRaises(mail.MailFailure) as error:mail.token(BODY,'x')
            self.assertEqual(error.exception.state,'failed');self.assertNotIn('SECRET',str(error.exception))
            with self.assertRaises(mail.MailFailure) as error:mail.send(BODY,'fake',{'day':self.day,'rows':[],'total':0,'generated':self.now},[])
            self.assertEqual(error.exception.state,'unknown')

    def test_graph_4xx_known_failed_5xx_unknown_and_no_redirects(self):
        for code,state in ((403,'failed'),(429,'failed'),(500,'unknown'),(302,'unknown')):
            response=urllib.error.HTTPError('https://graph.microsoft.com',code,'private raw response',{},io.BytesIO(b'PRIVATE'))
            with patch.object(mail,'post',side_effect=response),self.assertRaises(mail.MailFailure) as error:mail.send(BODY,'fake',{'day':self.day,'rows':[],'total':0,'generated':self.now},[])
            self.assertEqual(error.exception.state,state);self.assertNotIn('PRIVATE',str(error.exception))
        self.assertIsNone(mail.NoRedirect().redirect_request(None,None,302,'',{},'https://evil.test'))


class MailApiTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api

    def assert_http(self,code,fn):
        with self.assertRaises(urllib.error.HTTPError) as error:fn()
        self.assertEqual(error.exception.code,code);error.exception.close()

    def test_api_roles_csrf_preview_and_settings(self):
        self.server.mail_worker.close()
        self.assertFalse(self.api('/api/mail-reports')['body']['enabled'])
        self.assert_http(403,lambda:self.api('/api/mail-reports/config',{'body':BODY,'revision':0},csrf=False))
        saved=self.api('/api/mail-reports/config',{'body':BODY,'revision':0});self.assertEqual(saved['revision'],1)
        while index_batch(self.store):pass
        yesterday=(dt.datetime.now(TAIPEI).date()-dt.timedelta(days=1)).isoformat()
        preview=self.api('/api/mail-reports/preview?day='+yesterday);self.assertIn('每日檔案異動總表',preview['html']);self.assertEqual(self.api('/api/mail-reports')['jobs'],[])
        self.assert_http(400,lambda:self.api('/api/mail-reports/send',{'day':yesterday}))
        self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        self.assert_http(403,lambda:self.api('/api/mail-reports'))
        self.assert_http(403,lambda:self.api('/api/mail-reports/preview?day='+yesterday))
        self.assert_http(403,lambda:self.api('/api/mail-reports/config',{'body':BODY,'revision':1}))

    def test_anonymous_and_endpoint_token_cannot_read_mail_settings(self):
        clean=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.assert_http(401,lambda:self.api('/api/mail-reports',client=clean))
        self.assert_http(401,lambda:self.api('/api/mail-reports/preview?day=2026-10-19',client=clean))


if __name__=='__main__':unittest.main()
