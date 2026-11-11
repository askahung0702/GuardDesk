import copy
import tempfile
import unittest
from pathlib import Path
from guarddesk.website_control import WebsiteController,EMPTY,ROOTS
from guarddesk.category_rules import WEBSITE_DEFAULT


class RegistryFixture:
    def __init__(self):self.data={b:copy.deepcopy(EMPTY) for b in ROOTS};self.writes=0;self.fail=None;self.crash=None
    def read(self,b):return copy.deepcopy(self.data[b])
    def value(self,b,k,s,v):
        self.writes+=1
        if self.writes==self.crash:raise KeyboardInterrupt('fixture crash')
        if self.writes==self.fail:raise OSError('fixture write failure')
        if v is None:
            if self.data[b][k] is not None:self.data[b][k].pop(s,None)
        else:
            if self.data[b][k] is None:self.data[b][k]={}
            self.data[b][k][s]=v
    def prune(self,b,k):
        if not self.data[b][k]:self.data[b][k]=None


class WebsiteControlTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.registry=RegistryFixture();self.worker=WebsiteController(self.root,self.registry)
        self.control={**copy.deepcopy(WEBSITE_DEFAULT),'enabled':True,'blocked':['example.com','cloud.test'],'allowed':['.approved.example.com']}
    def tearDown(self):self.tmp.cleanup()
    def test_apply_idempotent_readback_and_restore_both_browsers(self):
        result=self.worker.apply(self.control)
        self.assertTrue(all(v['state']=='registry_verified' and not v['browser_verified'] for v in result['browsers'].values()))
        count=self.registry.writes;self.worker.apply(self.control);self.assertEqual(count,self.registry.writes)
        self.worker.restore();self.assertEqual(self.registry.data,{b:EMPTY for b in ROOTS})
        self.assertEqual(list(self.root.glob('website-policy-*.json')),[])
    def test_existing_policy_and_empty_company_key_preserved(self):
        self.registry.data['chrome']['URLBlocklist']={'1':'company.test'}
        self.registry.data['edge']['URLAllowlist']={}
        before=copy.deepcopy(self.registry.data);result=self.worker.apply(self.control)
        self.assertEqual(result['state'],'partial_or_failed');self.assertEqual(before,self.registry.data);self.assertEqual(self.registry.writes,0)
    def test_partial_write_rolls_back_and_other_browser_reports_separately(self):
        self.registry.fail=2;r=self.worker.apply(self.control)
        self.assertEqual(r['browsers']['chrome']['state'],'conflict_or_failed');self.assertEqual(self.registry.data['chrome'],EMPTY)
        self.assertEqual(r['browsers']['edge']['state'],'registry_verified')
        self.worker.apply(self.control);self.assertNotEqual(self.registry.data['chrome'],EMPTY)
    def test_crash_recovery_resume_is_exact(self):
        self.registry.crash=2
        with self.assertRaises(KeyboardInterrupt):self.worker.apply(self.control)
        self.registry.crash=None;r=WebsiteController(self.root,self.registry).apply(self.control)
        self.assertEqual(r['browsers']['chrome']['state'],'registry_verified');self.worker.restore()
        self.assertEqual(self.registry.data['chrome'],EMPTY)
    def test_external_change_after_apply_is_not_overwritten_on_update_or_uninstall(self):
        self.worker.apply(self.control);self.registry.data['chrome']['URLBlocklist']['1']='company.test';before=copy.deepcopy(self.registry.data['chrome'])
        self.assertEqual(self.worker.restore()['state'],'partial_or_failed');self.assertEqual(self.registry.data['chrome'],before)
        self.assertTrue((self.root/'website-policy-chrome.json').exists())
    def test_remove_one_browser_restores_only_owned_rules(self):
        self.worker.apply(self.control);r=self.worker.apply({**self.control,'browsers':['edge']})
        self.assertEqual(self.registry.data['chrome'],EMPTY);self.assertEqual(r['browsers']['edge']['state'],'registry_verified')
    def test_bad_journal_and_oversized_policy_cannot_write(self):
        (self.root/'website-policy-chrome.json').write_text('{"format":1}',encoding='utf-8')
        r=self.worker.apply(self.control);self.assertEqual(r['browsers']['chrome']['state'],'conflict_or_failed')
        self.assertEqual(self.registry.data['chrome'],EMPTY)
        with self.assertRaises(ValueError):self.worker.apply({**self.control,'blocked':['example.com']*1001})
    def test_offline_has_no_expiring_unlock(self):
        self.worker.apply(self.control)
        self.assertNotIn('expires',(self.root/'website-policy-chrome.json').read_text())
        self.assertEqual(WebsiteController(self.root,self.registry).apply(self.control)['browsers']['chrome']['state'],'registry_verified')
    def test_second_writer_cannot_mutate_during_owned_transaction(self):
        with self.worker.exclusive():
            with self.assertRaises(OSError):WebsiteController(self.root,self.registry).apply(self.control)
        self.assertEqual(self.registry.writes,0)


if __name__=='__main__':unittest.main()
