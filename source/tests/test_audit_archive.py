import datetime as dt
import gzip
import json
import shutil
import sqlite3
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode
import test_system
from guarddesk.audit_reports import day_bounds,index_batch,TAIPEI,AuditError
from guarddesk.audit_archive import verify_directory,sha_file
from guarddesk.store import Store,canonical


class AuditArchiveTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api

    def add(self,n=6):
        base=day_bounds(dt.date(2026,10,17))[0]
        with self.store.connect() as db:
            for i in range(n):Store.event(db,'fixture','file.modified' if i%2 else 'file.deleted','info',{'user':r'ACME\Alice' if i%2 else '', 'path':'=untrusted.csv','url':'https://fixture.invalid/report','n':i},occurred=int(base+i))
        return base

    def wait(self,jid):
        until=time.monotonic()+20
        while time.monotonic()<until:
            job=next(j for j in self.api('/api/audit/exports')['jobs'] if j['id']==jid)
            if job['state'] not in ('queued','running','cancelling'):return job
            time.sleep(.05)
        self.fail('Export did not complete')

    def test_date_partition_snapshot_split_csv_and_source_preservation(self):
        base=self.add()
        with self.store.connect() as db:before=[tuple(r) for r in db.execute('SELECT id,hash FROM events ORDER BY id')]
        with patch('guarddesk.audit_archive.MAX_PART_ROWS',2):
            jid=self.api('/api/audit/exports',{'start':'2026-10-17','end':'2026-10-18','csv':True})['id']
            with self.store.connect() as db:Store.event(db,'fixture','file.modified','info',{'user':r'ACME\Alice','late':True},occurred=base+50)
            job=self.wait(jid);self.assertEqual(job['state'],'completed',job);self.assertEqual(job['rows'],6)
        folder=Path(job['folder']);self.assertEqual(len(list((folder/'202610/20261017').glob('*.jsonl.gz'))),3)
        self.assertTrue((folder/'202610/20261018/manifest-day.json').is_file());self.assertEqual(verify_directory(folder)['rows'],6)
        csv=(folder/'202610/20261017/events-20261017-0001.csv').read_text(encoding='utf-8-sig');self.assertIn("'=untrusted.csv",csv)
        data=self.api('/api/audit/exports/download?id='+jid);self.assertEqual(data[:2],b'PK')
        with self.store.connect() as db:self.assertEqual([tuple(r) for r in db.execute('SELECT id,hash FROM events WHERE id<=? ORDER BY id',(before[-1][0],))],before)
        self.assertTrue(self.store.verify()['valid'])
        corrupted=self.root/'corrupted';shutil.copytree(folder,corrupted)
        path=next(corrupted.glob('*/*/*.csv'));path.write_text('changed',encoding='utf-8')
        with self.assertRaises(AuditError):verify_directory(corrupted)
        # Even recomputing a file checksum cannot hide altered event content.
        corrupted2=self.root/'corrupted-event';shutil.copytree(folder,corrupted2);path=next(corrupted2.glob('*/*/*.jsonl.gz'))
        with gzip.open(path,'rt',encoding='utf-8') as f:rows=[json.loads(line) for line in f]
        rows[0]['details']['path']='altered'
        with gzip.open(path,'wt',encoding='utf-8') as f:
            for row in rows:f.write(canonical(row)+'\n')
        manifest=json.loads((corrupted2/'manifest.json').read_text())
        for entry in manifest['files']:
            if entry['path']==path.relative_to(corrupted2).as_posix():entry.update(bytes=path.stat().st_size,sha256=sha_file(path))
        (corrupted2/'manifest.json').write_text(canonical(manifest),encoding='utf-8')
        with self.assertRaises(AuditError):verify_directory(corrupted2)

    def test_more_than_5000_rows_and_person_drilldown(self):
        base=self.add(5101)
        jid=self.api('/api/audit/exports',{'start':'2026-10-17','end':'2026-10-17','csv':False})['id'];job=self.wait(jid)
        self.assertEqual(job['state'],'completed',job);self.assertEqual(job['rows'],5101)
        # Background and manual indexing race safely at a transactional cursor.
        while index_batch(self.store):pass
        params={'person_filter':'1','person':r'acme\alice','file_action':'changes','start':base,'end':base+86400,'end_exclusive':'1'}
        rows=self.api('/api/events?'+urlencode(params));self.assertEqual(rows['total'],2550)
        self.assertTrue(all(r['details']['user']==r'ACME\Alice' for r in rows['items']))
        params['person']='';self.assertEqual(self.api('/api/events?'+urlencode(params))['total'],2551)

    def test_permissions_csrf_cancel_and_invalid_paths(self):
        reader=self.api('/api/login',{'username':'reader','password':self.password});self.csrf=reader['csrf']
        self.assertRaises(urllib.error.HTTPError,lambda:self.api('/api/audit/exports'))
        self.assertRaises(urllib.error.HTTPError,lambda:self.api('/api/audit/exports',{'start':'2026-10-17','end':'2026-10-17'}))
        self.csrf=self.api('/api/login',{'username':'admin','password':self.password})['csrf']
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/audit/exports',{'start':'2026-10-17','end':'2026-10-17'},csrf=False)
        self.assertEqual(e.exception.code,403)
        self.server.audit_service.archive.close()
        jid=self.api('/api/audit/exports',{'start':'2026-10-17','end':'2026-10-17'})['id']
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/audit/exports/download?id='+jid)
        self.assertEqual(e.exception.code,409)
        self.api('/api/audit/exports/cancel',{'id':jid});self.assertEqual(self.wait(jid)['state'],'cancelled')
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/audit/exports/download?id=../../secret')
        self.assertEqual(e.exception.code,400)
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/audit/exports',{'start':'2026-10-17','end':'2026-10-17','root':str(self.root)})

    def test_received_date_zero_day_and_manifest_traversal_rejected(self):
        self.add(1);today=dt.datetime.now(TAIPEI).date().isoformat()
        jid=self.api('/api/audit/exports',{'start':today,'end':today,'basis':'received','csv':True})['id'];job=self.wait(jid)
        self.assertEqual(job['state'],'completed',job);self.assertGreaterEqual(job['rows'],2)
        folder=Path(job['folder']);manifest=json.loads((folder/'manifest.json').read_text());manifest['files'][0]['path']='../../secret'
        (folder/'manifest.json').write_text(canonical(manifest),encoding='utf-8')
        with self.assertRaises(AuditError):verify_directory(folder)

    def test_disk_reserve_and_transient_failure_status_retry(self):
        self.add(2);worker=self.server.audit_service.archive
        usage=shutil._ntuple_diskusage(total=1024**3,used=1024**3,free=0)
        original=worker._record_failure;attempts=[]
        def transient(job,error):
            attempts.append(job['id'])
            if len(attempts)==1:raise sqlite3.OperationalError('fixture temporary writer failure')
            return original(job,error)
        with patch('guarddesk.audit_archive.shutil.disk_usage',return_value=usage),patch.object(worker,'_record_failure',side_effect=transient):
            jid=self.api('/api/audit/exports',{'start':'2026-10-17','end':'2026-10-17'})['id'];job=self.wait(jid)
        self.assertEqual(job['state'],'failed');self.assertGreaterEqual(len(attempts),2);self.assertIn('空間',job['error']);self.assertTrue(self.store.verify()['valid'])

    def test_zip_needs_additional_space_after_valid_partition_files(self):
        self.add(2)
        usage=shutil._ntuple_diskusage(total=1024**3,used=512*1024*1024,free=512*1024*1024+128)
        with patch('guarddesk.audit_archive.shutil.disk_usage',return_value=usage):
            jid=self.api('/api/audit/exports',{'start':'2026-10-17','end':'2026-10-17'})['id'];job=self.wait(jid)
        self.assertEqual(job['state'],'failed');self.assertIn('ZIP 空間',job['error'])
        self.assertTrue(list(Path(job['folder']).glob('*/*/*.jsonl.gz')));self.assertFalse((Path(job['folder'])/'archive.zip').exists())
        self.assertTrue(self.store.verify()['valid'])


if __name__=='__main__':unittest.main()
