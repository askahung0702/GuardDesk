import datetime as dt
import unittest
import urllib.error
from urllib.parse import urlencode
import test_system
from guarddesk.audit_reports import day_bounds,index_batch
from guarddesk.store import Store


class DeviceReportDrilldownTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def test_same_device_all_actors_exact_actions_dates_and_csv(self):
        _,did,_=self.make_agent();_,other,_=self.make_agent_second()
        base=day_bounds(dt.date(2026,10,18))[0]
        with self.store.connect() as db:
            for device,kind,user,offset in [(did,'file.created','',0),(did,'file.deleted','alice',20),
                    (did,'file.renamed','bob',86399),(did,'file.opened','alice',5),
                    (did,'file.open_requested','',6),(other,'file.created','',7),(did,'file.created','',86400)]:
                Store.event(db,device,kind,'info',{'path':r'C:\Owned\fixture.txt','user':user},occurred=base+offset)
        while index_batch(self.store):pass
        summary=self.api('/api/audit/summary?'+urlencode({'start':'2026-10-18','end':'2026-10-18','group_by':'device','device':did}))
        self.assertEqual(summary['total'],3);self.assertEqual(summary['device_total'],1)
        params={'device':did,'category':'files','file_action':'changes','start':base,'end':base+86400,'end_exclusive':'1'}
        rows=self.api('/api/events?'+urlencode(params))
        self.assertEqual(rows['total'],summary['total'])
        self.assertEqual({r['kind'] for r in rows['items']},{'file.created','file.deleted','file.renamed'})
        self.assertTrue(all(r['device_id']==did for r in rows['items']))
        self.assertEqual(len(self.api('/api/events.csv?'+urlencode(params)).decode('utf-8-sig').splitlines()),4)
        params['file_action']='all';self.assertEqual(self.api('/api/events?'+urlencode(params))['total'],4)
        params['file_action']='invalid'
        with self.assertRaises(urllib.error.HTTPError):self.api('/api/events?'+urlencode(params))
        self.assertTrue(self.store.verify()['valid'])

    def make_agent_second(self):
        # A second endpoint has an independent config and immutable identity.
        from guarddesk.agent import Agent,enroll
        code=self.api('/api/enrollments',{})['token'];config=self.root/'second-agent'/'config.json'
        did=enroll(config,self.url,code,self.watch,name='Other endpoint')
        return Agent(config),did,code
