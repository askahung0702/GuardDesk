"""Host-pattern contract and safe projection; no company browser policy writes."""
import unittest
from guarddesk.category_rules import member,import_members,export_members,compile_member,match_preview,host_pattern,pattern_matches,website_capability


def rule(pattern,domains=None,scheme='any'):
    return member('website',{'name':pattern,'type':'host_glob','pattern':pattern,'scheme':scheme,'enforcement_domains':domains or []})


class WildcardTest(unittest.TestCase):
    def test_screenshot_rules_import_save_and_export_exact_patterns(self):
        patterns=['*.wetransfer.com.*','*.primedrive.jp.*','*.hennge.com.*','*.dropbox.*','*.box.com','*.boxcloud.com','*.boxlocalhost.com','*.box.net','*.boxcdn.net','*.box.org','*.boxenterprise.net','*.amazonaws.com.*','*.file.core.windows.net.*','*.blob.core.chinacloudapi.cn','*.blob.core.windows.net','*.blob.core.cloudapi.de','*.drive.google.com*','*.filemail.com.*','*.documentcloud.adobe.com','*documentcloud*','*.directcloud.co.jp','*.directcloud.jp','*.icloud*','*.imap.mail.me.com','*.mxhero*.*']
        got=import_members('website','\n'.join(patterns));self.assertEqual(got['errors'],[])
        self.assertEqual([m['pattern'] for m in got['members']],patterns)
        self.assertEqual(import_members('website',export_members(got['members']))['members'],got['members'])

    def test_explicit_semantics_boundary_and_no_path_matching(self):
        cases=[('*.box.com','box.com',True),('*.box.com','deep.www.box.com',True),('*.box.com','badbox.com',False),('*.box.com','box.com.evil.test',False),('*.dropbox.*','dropbox.com',True),('*.dropbox.*','www.dropbox.co.jp',True),('*.dropbox.*','badropbox.com',False),('*.dropbox.*','dropbox.com.evil.test',True),('*documentcloud*','documentcloud.adobe.com',True),('*.icloud*','icloud.com',True),('*.icloud*','www.icloud.example',True)]
        for pattern,host,want in cases:
            with self.subTest(pattern=pattern,host=host):self.assertEqual(pattern_matches(host_pattern(pattern),host),want)
        r=match_preview({'members':[rule('*documentcloud*')],'urls':['https://example.com/documentcloud?x=documentcloud']})
        self.assertEqual(r['results'][0]['matches'],[])

    def test_scheme_unicode_and_normalization(self):
        self.assertEqual(host_pattern('*.BOX.COM.'),'*.box.com')
        self.assertEqual(host_pattern('**documentcloud**'),'*documentcloud*')
        item=rule('*.例子.測試',scheme='https');self.assertIn('xn--',item['pattern'])
        got=match_preview({'members':[item],'urls':['https://例子.測試/','http://例子.測試/']})
        self.assertEqual(len(got['results'][0]['matches']),1);self.assertEqual(got['results'][1]['matches'],[])

    def test_invalid_globs_and_input_limits(self):
        for bad in ['*','*.*','https://*.box.com','*.box.com/path','*.box.com?x','*.box.com#x','[ab]*.com','?.com','*.bad..com','*.a.com\n','*例子*','a'*254+'*',[],{},None,'*a'*17]:
            with self.subTest(bad=bad),self.assertRaises(ValueError):host_pattern(bad)
        for url in ['file:///test','https://user:pass@box.com/','https://box.com:999999/','https://box.com/\n','https://127.0.0.1/']:
            with self.subTest(url=url),self.assertRaises(ValueError):match_preview({'members':[],'urls':[url]})
        with self.assertRaises(ValueError):match_preview({'members':[],'urls':['https://box.com/']*11})

    def test_no_unconfigured_wildcard_can_reach_browser_policy(self):
        self.assertEqual(compile_member(rule('*.box.com')),['box.com'])
        for p in ['*.dropbox.*','*documentcloud*','*.amazonaws.com.*']:
            with self.subTest(p=p),self.assertRaisesRegex(ValueError,'尚未設定實際封鎖網域'):compile_member(rule(p))
        self.assertEqual(compile_member(rule('*.dropbox.*',['dropbox.com','dropbox.jp'])),['dropbox.com','dropbox.jp'])
        self.assertEqual(compile_member(rule('drive.*',['drive.example'],scheme='https')),['https://.drive.example'])
        self.assertEqual(website_capability(rule('*.com'))['mode'],'unavailable')
        self.assertEqual(compile_member(rule('*.com',['example.com'])),['example.com'])
        with self.assertRaises(ValueError):rule('*.dropbox.*',['unrelated.test'])
        with self.assertRaises(ValueError):rule('*.box.com',['box.com'])
        with self.assertRaises(ValueError):rule('*cloud*',['cloud.test']*101)

    def test_preview_distinguishes_pattern_hit_and_finite_coverage(self):
        item=rule('*.dropbox.*',['dropbox.com'])
        got=match_preview({'members':[item],'urls':['https://sub.dropbox.com/','https://dropbox.jp/','https://outside.test/']})['results']
        self.assertTrue(got[0]['matches'][0]['native_covered']);self.assertFalse(got[1]['matches'][0]['native_covered'])
        self.assertEqual(got[0]['matches'][0]['coverage'],'selected_domains_only');self.assertEqual(got[2]['matches'],[])
        got=match_preview({'members':[rule('drive.*',['drive.example'])],'urls':['https://drive.example/','https://sub.drive.example/']})['results']
        self.assertTrue(got[0]['matches'][0]['native_covered']);self.assertEqual(got[1]['matches'],[])

    def test_import_remains_atomic_and_checks_mapping_json(self):
        got=import_members('website','*.box.com\nhttps://bad.test/path');self.assertEqual(got['members'],[]);self.assertEqual(got['errors'][0]['line'],2)
        for mapping in ['{}','"abc"','[1]','not json']:
            import csv,io
            buf=io.StringIO();writer=csv.writer(buf);writer.writerow(['name','type','pattern','scheme','enforcement_domains']);writer.writerow(['test','host_glob','*cloud*','any',mapping])
            got=import_members('website',buf.getvalue());self.assertFalse(got['publishable']);self.assertEqual(got['members'],[])


if __name__=='__main__':unittest.main()
