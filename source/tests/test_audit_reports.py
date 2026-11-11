import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from guarddesk.audit_reports import TAIPEI,AuditError,dates,day_bounds,index_batch,summary
from guarddesk.store import Store


class AuditReportsTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.store=Store(self.root/'db.sqlite3')
    def tearDown(self):self.temp.cleanup()
    def add(self,kind,user,day='2026-10-18',eid=None,offset=0,device='fixture'):
        occurred=day_bounds(dt.date.fromisoformat(day))[0]+offset
        with self.store.connect() as db:Store.event(db,device,kind,'info',{'user':user,'path':r'C:\Owned\report.txt'},event_id=eid,occurred=occurred)
    def result(self,**params):
        with self.store.connect() as db:return summary(db,{k:[v] for k,v in {'start':'2026-10-18','end':'2026-10-18',**params}.items()})

    def test_incremental_rank_unknown_casefold_and_no_duplicate_counts(self):
        self.add('file.modified',r'ACME\Alice',eid='same');self.add('file.modified',r'ACME\Alice',eid='same')
        self.add('file.created',r'acme\alice');self.add('file.deleted',r'ACME\Bob');self.add('file.modified','')
        self.add('file.opened',r'ACME\Bob');self.add('file.open_requested',r'ACME\Bob');self.add('file.delete_requested',r'ACME\Bob')
        self.assertFalse(self.result()['caught_up'])
        while index_batch(self.store):pass
        result=self.result();self.assertEqual(result['total'],4);self.assertEqual(result['people_total'],2);self.assertEqual(result['unknown'],1)
        self.assertEqual(result['people'][0]['person'],r'acme\alice');self.assertEqual(result['people'][0]['n'],2)
        self.assertTrue(result['caught_up']);self.assertFalse(index_batch(self.store));self.assertEqual(self.result()['total'],4)
        self.assertEqual(self.result(action='opened')['total'],1);self.assertEqual(self.result(action='all')['total'],5)
        self.add('file.moved',r'ACME\Bob');index_batch(self.store);self.assertEqual(self.result()['total'],5)
        self.assertTrue(self.store.verify()['valid'])

    def test_taipei_midnight_and_device_scope(self):
        self.add('file.created','alice',offset=0);self.add('file.created','alice',offset=86399.999)
        self.add('file.created','alice',day='2026-10-19');self.add('file.created','alice',day='2026-10-17',offset=86399.999)
        while index_batch(self.store):pass
        self.assertEqual(self.result()['total'],2)
        self.assertEqual(self.result(device='unknown')['total'],0)
        self.assertEqual(self.result(start='2026-10-17',end='2026-10-19')['total'],4)
        for start,end in [('2026-02-30','2026-03-01'),('2026-10-19','2026-10-18'),('2026-1-1','2026-01-02'),('1970-01-01','2026-10-19')]:
            with self.assertRaises(AuditError):dates(start,end)

    def test_device_rank_includes_missing_actors_and_keeps_same_names_separate(self):
        with self.store.connect() as db:
            for did,name in [('host-dev','DEV-01'),('host-user1','user1'),('other-user1','user1')]:
                db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',(did,did,name,'Fixture',0))
        for user in ('',None,r'ACME\Alice',r'ACME\Bob'):
            self.add('file.created',user,device='host-dev')
        self.add('file.deleted','',device='host-user1');self.add('file.renamed',r'ACME\Alice',device='other-user1')
        self.add('file.opened','',device='host-dev');self.add('file.open_requested','',device='host-dev')
        while index_batch(self.store):pass
        result=self.result(group_by='device')
        self.assertEqual(result['group_by'],'device');self.assertEqual(result['device_total'],3);self.assertEqual(result['total'],6)
        self.assertEqual([(r['label'],r['n']) for r in result['items']],[('DEV-01',4),('user1',1),('user1',1)])
        self.assertEqual(len({r['device_id'] for r in result['items']}),3)
        self.assertEqual(result['items'][0]['created'],4)
        self.assertEqual(self.result(group_by='device',device='host-dev',action='all')['total'],5)
        self.assertEqual(self.result(group_by='device',device='host-user1')['items'][0]['deleted'],1)
        self.assertTrue(self.store.verify()['valid'])

    def test_device_names_resolve_without_reindexing_or_rewriting_old_logs(self):
        self.add('file.created','');index_batch(self.store)
        self.assertEqual(self.result(group_by='device')['items'][0]['label'],'fixture')
        with self.store.connect() as db:
            original=dict(db.execute('SELECT * FROM events LIMIT 1').fetchone())
            db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',('fixture','fixture','user1','Fixture',0))
        self.assertFalse(index_batch(self.store))
        self.assertEqual(self.result(group_by='device')['items'][0]['label'],'user1')
        with self.store.connect() as db:self.assertEqual(dict(db.execute('SELECT * FROM events LIMIT 1').fetchone()),original)
        with self.assertRaises(AuditError):self.result(group_by='invalid')


if __name__=='__main__':unittest.main()
