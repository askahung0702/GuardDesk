import http.cookiejar
import json
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from guarddesk import update_progress,updates
import test_updates as fixtures


class ProgressTest(unittest.TestCase):
    setUp=fixtures.UpdateServerTest.setUp
    tearDown=fixtures.UpdateServerTest.tearDown
    api=fixtures.UpdateServerTest.api
    make_agent=fixtures.UpdateServerTest.make_agent
    upload=fixtures.UpdateServerTest.upload
    poll=fixtures.UpdateServerTest.poll

    def seed(self,count=1):
        release=self.upload(fixtures.release(self.root/'progress.zip',version='0.4.50'))
        agent,did,_=self.make_agent();now=time.time();ids=[]
        with self.store.connect() as db:
            for i in range(count):
                jid=f'{i+1:032x}';ids.append(jid)
                db.execute('INSERT INTO update_jobs VALUES(?,?,?,?,?,?,?,?,?)',(jid,did,release['id'],'admin',now+i*.0001,now-1,now+3600,0,'pending'))
                db.executemany('INSERT INTO update_status VALUES(?,?,?,?,?,?)',[(jid,role,'queued','','',0) for role in ('native','main')])
        return release,agent,did,ids

    def query(self,**values):return self.api('/api/updates?'+urllib.parse.urlencode(values))
    def preview(self,**values):return self.api('/api/updates/cancel-waiting/preview?'+urllib.parse.urlencode(values))
    def cancel(self,ids):return self.api('/api/updates/cancel-waiting',{'job_ids':ids,'confirm':'cancel_waiting'})

    def test_global_paging_is_stable_fifty_and_does_not_read_event_payloads(self):
        release,agent,did,ids=self.seed(123)
        pages=[self.query(page=p) for p in (1,2,3)]
        self.assertEqual([len(p['jobs']) for p in pages],[50,50,23]);self.assertTrue(all(p['progress']['total']==123 for p in pages))
        all_ids=[j['id'] for p in pages for j in p['jobs']];self.assertEqual(len(set(all_ids)),123);self.assertEqual(all_ids,list(reversed(ids)))
        self.assertEqual(self.query(page=100)['progress']['page'],3)
        with self.store.connect() as db:
            statements=[];db.set_trace_callback(statements.append)
            catalog=updates.catalog(db,params={'page':['2']})
        self.assertEqual(len(catalog['jobs']),50)
        self.assertFalse(any('event_value' in s or 'FROM events' in s for s in statements))

    def test_waiting_filter_includes_retry_but_bulk_only_cancels_unclaimed(self):
        release,agent,did,ids=self.seed(8);now=time.time()
        with self.store.connect() as db:
            for jid,state,received in ((ids[1],'downloading',now),(ids[2],'applying',now),(ids[3],'waiting',now),(ids[4],'healthy',now)):
                db.execute("UPDATE update_status SET state=?,received=? WHERE job_id=? AND role='native'",(state,received,jid))
            db.execute("UPDATE update_jobs SET expires=? WHERE id=?",(now-1,ids[5]))
            db.execute("UPDATE update_jobs SET status='cancelled' WHERE id=?",(ids[6],))
            db.execute("UPDATE update_jobs SET not_before=? WHERE id=?",(now+1800,ids[7]))
        waiting=self.query(state='waiting');self.assertEqual({j['id'] for j in waiting['jobs']},{ids[0],ids[3],ids[4],ids[7]})
        preview=self.preview(state='waiting');self.assertEqual(set(preview['job_ids']),{ids[0],ids[7]})
        result=self.cancel(ids);self.assertEqual(result['cancelled'],2);self.assertEqual(result['skipped'],6)
        self.assertEqual(self.cancel(ids)['cancelled'],0)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT state FROM update_status WHERE job_id=? AND role='native'",(ids[2],)).fetchone()[0],'applying')
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE kind='update.cancelled'").fetchone()[0],2)

    def test_preview_freezes_all_pages_and_confirmation_skips_newly_claimed(self):
        release,agent,did,ids=self.seed(61)
        preview=self.preview(state='waiting',page=2);self.assertEqual(preview['total'],61)
        claimed=self.poll(agent)['job']['payload']['id']
        with self.store.connect() as db:
            row=list(db.execute('SELECT * FROM update_jobs WHERE id=?',(ids[0],)).fetchone());row[0]='f'*32;row[4]=time.time()+1
            db.execute('INSERT INTO update_jobs VALUES(?,?,?,?,?,?,?,?,?)',row)
            db.executemany('INSERT INTO update_status VALUES(?,?,?,?,?,?)',[('f'*32,r,'queued','','',0) for r in ('native','main')])
        result=self.cancel(preview['job_ids']);self.assertEqual(result['cancelled'],60);self.assertEqual(result['skipped'],1)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT status FROM update_jobs WHERE id=?',(claimed,)).fetchone()[0],'pending')
            self.assertEqual(db.execute("SELECT status FROM update_jobs WHERE id=?",('f'*32,)).fetchone()[0],'pending')
        self.assertEqual(self.query(state='waiting')['progress']['total'],1)

    def test_not_updated_includes_never_sent_unknown_and_uses_numeric_latest_observation(self):
        release,agent,did,ids=self.seed()
        second,other,_=self.make_agent();third,third_id,_=self.make_agent()
        now=time.time()
        with self.store.connect() as db:
            db.execute('UPDATE devices SET inventory=?,last_seen=? WHERE id=?',(json.dumps({'agent_version':'0.4.50','user_accounts':['EXAMPLE\\new-user']}),now,did))
            for target in (did,other):
                db.execute('INSERT INTO update_presence VALUES(?,?,?,?,?)',(target,'main','0.4.9',now-10,''))
                db.execute('INSERT INTO update_presence VALUES(?,?,?,?,?)',(target,'native','0.4.9',now-10,''))
            db.execute('INSERT INTO native_usb_status VALUES(?,?,?)',(did,json.dumps({'worker_version':'0.4.51'}),now))
        result=self.query(state='not_updated',release=release['id'])
        self.assertEqual({d['id'] for d in result['pending_devices']},{other,third_id})
        self.assertTrue(all(d['latest_job'] is None for d in result['pending_devices']))
        self.assertIn('',[d['native_version'] for d in result['pending_devices']])
        found=self.query(state='not_updated',q='fixture1');self.assertEqual(found['progress']['total'],1)
        self.assertEqual(self.query(q='EXAMPLE\\new-user')['progress']['total'],1)

    def test_group_descendants_release_scope_and_invalid_parameters(self):
        release,agent,did,ids=self.seed(2)
        parent=self.api('/api/groups',{'name':'IT','parent_id':None});child=self.api('/api/groups',{'name':'MIS','parent_id':parent['id']})
        self.api('/api/devices/move',{'device_id':did,'group_id':child['id'],'revision':1})
        self.assertEqual(self.query(group=parent['id'],release=release['id'])['progress']['total'],2)
        self.assertEqual(self.preview(group='unassigned')['total'],0)
        for values in ({'state':'bad'},{'page':0},{'page':'x'},{'group':'missing'},{'release':'a'*64},{'q':'x'*201},{'limit':500}):
            with self.assertRaises(urllib.error.HTTPError) as e:self.query(**values)
            self.assertEqual(e.exception.code,400)
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/updates?state=all&state=waiting')

    def test_auth_csrf_validation_cap_and_no_silent_truncation(self):
        release,agent,did,ids=self.seed(1001)
        preview=self.preview(state='waiting');self.assertFalse(preview['can_confirm']);self.assertEqual(preview['job_ids'],[]);self.assertEqual(preview['total'],1001)
        with self.assertRaises(urllib.error.HTTPError) as e:self.cancel(ids)
        self.assertEqual(e.exception.code,400)
        for payload in ({'job_ids':[ids[0]],'confirm':'no'},{'job_ids':[ids[0],ids[0]],'confirm':'cancel_waiting'},{'job_ids':[],'confirm':'cancel_waiting'}):
            with self.assertRaises(urllib.error.HTTPError):self.api('/api/updates/cancel-waiting',payload)
        request=urllib.request.Request(self.url+'/api/updates/cancel-waiting',data=json.dumps({'job_ids':[ids[0]],'confirm':'cancel_waiting'}).encode(),headers={'Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as e:self.client.open(request)
        self.assertEqual(e.exception.code,403)
        reader=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.api('/api/login',{'username':'reader','password':self.password},client=reader)
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/updates/cancel-waiting/preview',client=reader)
        self.assertEqual(e.exception.code,403)

    def test_poll_and_cancel_writer_serialization_never_cancels_claimed_download(self):
        release,agent,did,ids=self.seed()
        barrier=threading.Barrier(2);responses=[];errors=[]
        def poll():
            try:barrier.wait();responses.append(self.poll(agent))
            except Exception as e:errors.append(e)
        worker=threading.Thread(target=poll);worker.start();barrier.wait();result=self.cancel(ids);worker.join(10)
        self.assertFalse(worker.is_alive());self.assertFalse(errors)
        with self.store.connect() as db:
            status=db.execute('SELECT status FROM update_jobs WHERE id=?',(ids[0],)).fetchone()[0]
            state=db.execute("SELECT state FROM update_status WHERE job_id=? AND role='native'",(ids[0],)).fetchone()[0]
        if result['cancelled']:self.assertEqual((status,state),('cancelled','queued'));self.assertIsNone(responses[0]['job'])
        else:self.assertEqual((status,state),('pending','downloading'));self.assertIsNotNone(responses[0]['job'])

    def test_active_updater_maintenance_is_never_bulk_cancelled(self):
        release,agent,did,ids=self.seed(2);now=time.time()
        with self.store.connect() as db:db.execute('INSERT INTO updater_refresh VALUES(?,?,?,?,?,?,?)',(did,'a'*32,ids[0],'0.4.50',now,now+300,'active'))
        self.assertEqual(self.preview(state='waiting')['total'],0)
        self.assertEqual(self.cancel(ids)['cancelled'],0)
        self.assertIn(ids[0],{j['id'] for j in self.query(state='running')['jobs']})

    def test_malformed_inventory_versions_are_unknown_with_bounded_output(self):
        release,agent,did,ids=self.seed()
        with self.store.connect() as db:db.execute('UPDATE devices SET inventory=? WHERE id=?',(json.dumps({'agent_version':'x'*10000,'user_accounts':['account-'+str(i) for i in range(100)]}),did))
        row=self.query(state='not_updated')['pending_devices'][0]
        self.assertEqual(row['main_version'],'');self.assertEqual(len(row['accounts']),32)
        with self.store.connect() as db:db.execute('UPDATE devices SET inventory=? WHERE id=?',(json.dumps({'agent_version':123,'user_accounts':{'unexpected':'shape'}}),did))
        row=self.query(state='not_updated')['pending_devices'][0];self.assertEqual(row['main_version'],'');self.assertEqual(row['accounts'],[])


if __name__=='__main__':unittest.main()
