"""Actual authenticated HTTP boundary and endpoint wire; no machine policies."""
import copy
import urllib.error
import unittest
import test_system
from guarddesk.policy import DEFAULT_POLICY


class CategoryAPITest(unittest.TestCase):
    setUp=test_system.SystemTest.setUp
    tearDown=test_system.SystemTest.tearDown
    api=test_system.SystemTest.api
    make_agent=test_system.SystemTest.make_agent

    def category(self,members=None):
        c=self.api('/api/categories/draft',{'kind':'website','draft':{'name':'Cloud','description':'test','parent_id':None,'members':members or [{'name':'Example','type':'domain','domain':'example.com','include_subdomains':True,'scheme':'any'}]}})
        gen=self.api('/api/categories')['generation'];preview=self.api('/api/categories/preview',{**c,'expected_generation':gen})
        self.assertEqual(self.api('/api/categories')['items'][0]['published_revision'],0)
        return self.api('/api/categories/publish',{**c,'expected_generation':preview['generation']})

    def test_http_category_policy_assignment_and_agent_decode(self):
        agent,eid,_=self.make_agent();c=self.category()
        p=self.api('/api/policy-sets',{'name':'Cloud block','overrides':{'website_control':{**copy.deepcopy(DEFAULT_POLICY['website_control']),'enabled':True}},'category_refs':{'website_blocked':[{'id':c['id'],'include_descendants':False}]}})
        assignment={'set_id':p['id'],'target_type':'device','target_id':eid,'enabled':True,'priority':100}
        preview=self.api('/api/assignments/preview',assignment)
        self.api('/api/assignments',{**assignment,'expected_generation':preview['generation']})
        got=agent.heartbeat();self.assertEqual(got['body']['website_control']['blocked'],['example.com'])
        from guarddesk.agent import request
        packet=request(self.url,'/api/agent/extended-policy',{},token=agent.config['token'])
        self.assertNotIn('website_control',packet['body']);self.assertEqual(packet['target_controls']['format'],1)
        history=self.api('/api/policy-sets/history?id='+p['id'])['items']
        self.assertIsInstance(history[0]['category_refs'],dict)
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/assignments/preview',{**assignment,'target_type':'user','target_id':r'COMPANY\alice'})
        self.assertEqual(e.exception.code,400);e.exception.close()

    def test_reader_and_csrf_cannot_publish_or_save(self):
        c=self.category();self.api('/api/logout',{})
        self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        self.assertEqual(len(self.api('/api/categories')['items']),1)
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/categories/publish',{**c,'expected_generation':self.api('/api/categories')['generation']})
        self.assertEqual(e.exception.code,403);e.exception.close()
        self.api('/api/logout',{});self.csrf=self.api('/api/login',{'username':'admin','password':self.password})['csrf']
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/categories/archive',c,csrf=False)
        self.assertEqual(e.exception.code,403);e.exception.close()

    def test_members_paged_search_and_bad_import_no_partial_save(self):
        c=self.category([{'name':f'Site {i}','type':'domain','domain':f's{i}.example.com','include_subdomains':False,'scheme':'any'} for i in range(51)])
        first=self.api('/api/categories?id='+c['id']);second=self.api('/api/categories?id='+c['id']+'&offset=50')
        self.assertEqual(len(first['selected']['members']),50);self.assertEqual(len(second['selected']['members']),1)
        self.assertEqual(self.api('/api/categories?id='+c['id']+'&q=Site%2050')['selected']['total'],1)
        before=self.api('/api/categories')['generation']
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/categories/draft',{'kind':'website','draft':{'name':'Bad','description':'','parent_id':None,'members':[{'name':'Bad','type':'domain','domain':'https://bad.test/path','include_subdomains':True,'scheme':'any'}]}})
        self.assertEqual(e.exception.code,400);e.exception.close();self.assertEqual(self.api('/api/categories')['generation'],before)

    def test_glob_save_publish_match_and_mapping_roundtrip(self):
        rules=self.api('/api/categories/import',{'kind':'website','text':'*.box.com\n*.dropbox.*\n*documentcloud*'})['members']
        self.assertEqual([m['type'] for m in rules],['host_glob']*3)
        c=self.category(rules)
        got=self.api('/api/categories?id='+c['id'])['selected']['members'];self.assertEqual(got,rules)
        preview=self.api('/api/categories/match',{'members':got,'urls':['https://box.com/','https://www.dropbox.com/private?token=synthetic','https://unrelated.test/']})
        self.assertTrue(preview['results'][0]['matches'][0]['native_covered'])
        self.assertFalse(preview['results'][1]['matches'][0]['native_covered'])
        self.assertEqual(preview['results'][2]['matches'],[])
        self.assertNotIn('synthetic',str(preview));self.assertNotIn('private',str(preview))
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/policy-sets',{'name':'Incomplete','overrides':{'website_control':{**copy.deepcopy(DEFAULT_POLICY['website_control']),'enabled':True}},'category_refs':{'website_blocked':[{'id':c['id'],'include_descendants':False}]}})
        self.assertEqual(e.exception.code,400);e.exception.close()
        got[1]['enforcement_domains']=['dropbox.com'];got[2]['enforcement_domains']=['documentcloud.adobe.com']
        saved=self.api('/api/categories/draft',{'id':c['id'],'revision':c['revision'],'kind':'website','draft':{'name':'Cloud','description':'','parent_id':None,'members':got}})
        self.api('/api/categories/publish',{**saved,'expected_generation':self.api('/api/categories')['generation']})
        p=self.api('/api/policy-sets',{'name':'Mapped','overrides':{'website_control':{**copy.deepcopy(DEFAULT_POLICY['website_control']),'enabled':True}},'category_refs':{'website_blocked':[{'id':c['id'],'include_descendants':False}]}})
        agent,eid,_=self.make_agent();a={'set_id':p['id'],'target_type':'device','target_id':eid,'enabled':True,'priority':100}
        self.api('/api/assignments',{**a,'expected_generation':self.api('/api/assignments/preview',a)['generation']})
        self.assertEqual(agent.heartbeat()['body']['website_control']['blocked'],['box.com','documentcloud.adobe.com','dropbox.com'])

    def test_glob_match_retains_role_csrf_and_limits(self):
        body={'members':[],'urls':['https://example.com/']}
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/categories/match',body,csrf=False)
        self.assertEqual(e.exception.code,403);e.exception.close()
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/categories/match',{**body,'urls':body['urls']*11})
        self.assertEqual(e.exception.code,400);e.exception.close()
        self.api('/api/logout',{});self.csrf=self.api('/api/login',{'username':'reader','password':self.password})['csrf']
        with self.assertRaises(urllib.error.HTTPError) as e:self.api('/api/categories/match',body)
        self.assertEqual(e.exception.code,403);e.exception.close()


if __name__=='__main__':unittest.main()
