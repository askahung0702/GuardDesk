import json
import time
import unittest
from urllib.parse import urlencode
import test_system
from guarddesk.store import Store


class AuditQueriesTest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def test_filtered_pagination_search_time_and_csv_preserve_results(self):
        agent,eid,_=self.make_agent();now=time.time()-10
        try:
            with self.store.connect() as db:
                for i in range(150):
                    Store.event(db,eid,['file.opened','web.navigation','web.upload_started'][i%3], 'warning' if i%2 else 'info',
                                {'source_path':r'C:\Documents\報告.pdf','url':'https://example.com/upload','user':r'ACME\alice','n':i},occurred=now+i/1000)
            def fetch(**q):return self.api('/api/events?'+urlencode(q))
            all_rows=fetch(device=eid,limit=200)['items'];self.assertEqual(len(all_rows),151) # enrolled event
            for category,prefix in [('files','file.'),('web','web.navigation'),('uploads','web.upload_')]:
                result=fetch(device=eid,category=category,limit=20,offset=10)
                matching=[r for r in all_rows if r['kind'].startswith(prefix)]
                self.assertEqual(result['total'],len(matching));self.assertEqual([r['id'] for r in result['items']],[r['id'] for r in matching[10:30]])
            searched=fetch(q='報告',device=eid,kind='web.upload_started',severity='warning',start=now+.02,end=now+.1,limit=200)
            expected=[r for r in all_rows if r['kind']=='web.upload_started' and r['severity']=='warning' and now+.02<=r['occurred']<=now+.1]
            self.assertEqual([r['id'] for r in searched['items']],[r['id'] for r in expected])
            self.assertEqual(fetch(q="' OR 1=1 --")['total'],0)
            csv=self.api('/api/events.csv?'+urlencode({'device':eid,'category':'uploads'})).decode('utf-8-sig')
            self.assertIn('web.upload_started',csv);self.assertNotIn('web.navigation',csv)
        finally:agent.close_collectors()


if __name__=='__main__':unittest.main()
