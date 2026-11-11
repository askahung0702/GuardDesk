import datetime as dt
import json
import time
import unittest
import urllib.error
from urllib.parse import urlencode
from unittest.mock import patch
import test_system
from guarddesk import pagination,policy_progress
from guarddesk.store import Store
from guarddesk.audit_reports import index_batch


class ImprovementsIntegrationTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def enable(self):
        self.api('/api/audit/storage/enable',{'confirm':'enable_daily'})
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            status=self.api('/api/audit/storage')
            if status['migration']['state']=='completed' and status['mode']=='daily-v1':return status
            if status['migration']['state']=='failed':self.fail(status)
            time.sleep(.02)
        self.fail('Activation did not finish')

    def test_daily_api_search_csv_summary_and_old_rows_remain_visible(self):
        agent,did,_=self.make_agent()
        base=dt.datetime(2026,10,19,tzinfo=dt.timezone(dt.timedelta(hours=8))).timestamp()
        try:
            with self.store.connect() as db:Store.event(db,did,'file.deleted','info',{'path':r'C:\Owned\legacy.docx'},'old-event',base)
            status=self.enable();self.assertEqual(status['mode'],'daily-v1')
            with self.store.connect() as db:
                Store.event(db,did,'file.moved','info',{'source_path':r'C:\Owned\new.docx','destination_path':r'D:\Owned\new.docx'},'new-event',base+1)
            rows=self.api('/api/events?'+urlencode({'device':did,'category':'files','q':'Owned'}))
            self.assertEqual(rows['total'],2)
            self.assertEqual(rows['items'][0]['details']['destination_path'],r'D:\Owned\new.docx')
            csv=self.api('/api/events.csv?'+urlencode({'device':did,'category':'files'})).decode('utf-8-sig')
            self.assertIn('legacy.docx',csv);self.assertIn('new.docx',csv)
            while index_batch(self.store):pass
            summary=self.api('/api/audit/summary?start=2026-10-19&end=2026-10-19&action=changes&group_by=device')
            self.assertEqual(summary['total'],2)
            self.assertTrue(self.api('/api/integrity')['valid'])
            self.assertGreaterEqual(len(self.api('/api/audit/storage')['days']),1)
        finally:agent.close_collectors()

    def test_cursor_snapshot_excludes_new_arrivals_and_rejects_changed_filter(self):
        _,did,_=self.make_agent()
        with self.store.connect() as db:
            for i in range(70):Store.event(db,did,'file.deleted','info',{'path':str(i)},'cursor-'+str(i))
        q={'cursor_mode':1,'device':did,'category':'files','limit':20}
        first=self.api('/api/events?'+urlencode(q));self.assertIsNone(first['total']);self.assertTrue(first['has_more'])
        with self.store.connect() as db:Store.event(db,did,'file.deleted','info',{'path':'new'},'after-snapshot')
        second=self.api('/api/events?'+urlencode({**q,'cursor':first['next_cursor']}))
        self.assertFalse({r['id'] for r in first['items']}&{r['id'] for r in second['items']})
        self.assertTrue(all(r['id']<=first['snapshot'] for r in second['items']))
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/events?'+urlencode({**q,'q':'changed','cursor':first['next_cursor']}))
        self.assertEqual(e.exception.code,400);e.exception.close()

    def test_cursor_session_binding_and_expiration(self):
        key=b'owned-test-key';token=pagination.encode(key,'session-a','filter',50,30)
        self.assertEqual(pagination.decode(key,token,'session-a','filter'),(50,30))
        import base64
        self.assertNotIn(b'session-a',base64.urlsafe_b64decode(token+'='*(-len(token)%4)))
        with self.assertRaises(ValueError):pagination.decode(key,token,'session-b','filter')
        with patch('guarddesk.pagination.time.time',return_value=time.time()+1000):
            with self.assertRaises(ValueError):pagination.decode(key,token,'session-a','filter')

    def test_receipt_is_not_reported_as_enforcement(self):
        agent,did,_=self.make_agent()
        try:
            agent.heartbeat();agent.heartbeat()
            row=self.api('/api/device-detail?device_id='+did)['device']
            self.assertTrue(row['policy_received'])
            self.assertTrue(all(not r['hardware_tested'] for r in row['policy_progress']))
            self.assertEqual(next(r for r in row['policy_progress'] if r['key']=='usb_mode')['state'],'pending')
            # Untrusted inventory subfields cannot make the management page fail.
            with self.store.connect() as db:
                db.execute('UPDATE devices SET inventory=? WHERE id=?',(json.dumps({'collectors':{'directory_notifications':{'active':'bad'}}}),did))
            self.assertEqual(self.api('/api/device-detail?device_id='+did)['device']['id'],did)
        finally:agent.close_collectors()

    def test_storage_write_requires_admin_csrf_and_confirmation(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/audit/storage/enable',{})
        self.assertEqual(e.exception.code,400);e.exception.close()
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/audit/storage/enable',{'confirm':'enable_daily'},csrf=False)
        self.assertEqual(e.exception.code,403);e.exception.close()
        self.assertEqual(self.api('/api/audit/storage')['mode'],'legacy')

    def test_daily_export_preserves_all_rows_and_group_filter(self):
        import test_audit_archive
        from guarddesk.audit_archive import verify_directory
        from pathlib import Path
        self.enable()
        base=dt.datetime(2026,10,19,tzinfo=dt.timezone(dt.timedelta(hours=8))).timestamp()
        with self.store.connect() as db:
            db.execute("INSERT INTO endpoint_groups VALUES ('testgroup','synthetic',NULL,1,?)",(time.time(),))
            db.execute("INSERT INTO devices(id,token,name,department,group_id,last_seen) VALUES ('owned','owned-token','owned','fixture','testgroup',0)")
            for i in range(3):Store.event(db,'owned','file.deleted','info',{'path':r'C:\Owned\test.docx'},'owned-export-'+str(i),base+i)
        rows=self.api('/api/events?group=testgroup&category=files&cursor_mode=1')
        self.assertEqual(len(rows['items']),3)
        jid=self.api('/api/audit/exports',{'start':'2026-10-19','end':'2026-10-19','csv':True})['id']
        job=test_audit_archive.AuditArchiveTest.wait(self,jid)
        self.assertEqual(job['state'],'completed',job)
        self.assertEqual(verify_directory(Path(job['folder']))['rows'],3)
        self.assertTrue(self.store.verify()['valid'])

    def test_preflight_accepts_daily_view_and_rejects_missing_day(self):
        from guarddesk.server_config import check
        from guarddesk.event_storage import day_file
        from test_server_deployment import certificate
        self.enable()
        cert,key=certificate(self.root/'preflight-tls')
        settings={'host':'127.0.0.1','port':8787,'db':self.store.path,'cert':cert,'key':key}
        self.assertTrue(check(settings)['passed'])
        with self.store.connect() as db:day=db.execute('SELECT day FROM event_catalog LIMIT 1').fetchone()[0]
        # Cached WAL writers intentionally hold the file open on Windows.
        # Simulate offline day loss after the server has released its handles.
        self.server.shutdown();self.server.server_close();self.thread.join(5)
        day_file(self.store.path,day).unlink()
        with self.assertRaisesRegex(ValueError,'日檔缺失'):check(settings)

    def test_250_fleet_paging_health_search_and_compact_state(self):
        with self.store.connect() as db:
            db.execute("INSERT INTO endpoint_groups VALUES ('fleetgroup','synthetic',NULL,1,?)",(time.time(),))
            for i in range(250):
                inventory={'user_accounts':[r'EXAMPLE\fixture'],'agent_version':'0.4.28','software':['Synthetic software']*200,'outbox':{'pending':i}}
                db.execute('INSERT INTO devices(id,token,name,department,last_seen,inventory,group_id) VALUES (?,?,?,?,?,?,?)',(f'owned-{i}',f'owned-token-{i}',f'Owned-{i:03d}','synthetic',time.time() if i%2 else 0,json.dumps(inventory),'fleetgroup'))
        first=self.api('/api/fleet?group=fleetgroup&sort=name')
        last=self.api('/api/fleet?group=fleetgroup&sort=name&offset=200')
        self.assertEqual((first['total'],len(first['items']),len(last['items'])),(250,50,50))
        self.assertFalse({d['id'] for d in first['items']}&{d['id'] for d in last['items']})
        self.assertEqual(self.api('/api/fleet?group=fleetgroup&health=offline')['total'],125)
        self.assertEqual(self.api('/api/fleet?group=fleetgroup&q=Owned-249')['total'],1)
        self.assertNotIn('software',self.api('/api/state?compact=1')['devices'][0]['inventory'])
        self.assertIn('software',self.api('/api/state')['devices'][0]['inventory'])
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/fleet?group=unknown')
        self.assertEqual(e.exception.code,400);e.exception.close()
