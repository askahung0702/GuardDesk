"""Product trigger correction; no desktop input or browser attachment."""
import copy
import json
from pathlib import Path
import unittest

from tools.probe_owned_browser_drop_hook import drop_case_passed, DROP_RECORDING_CONTRACT

ROOT = Path(__file__).resolve().parents[1]


class BrowserDropContractTest(unittest.TestCase):
    def setUp(self):
        self.path = r'C:\Owned\fixture.txt'
        self.origin = 'https://receiver.example.test'
        self.pid = 100
        self.row = {'path':self.path,'origin':self.origin,'process_id':100,'file_index':0,'file_count':1}
        self.helper = {'hresult':262400,'effect':1,'target_pid':100,'scope':'owned_real_ole_drag'}

    def check(self, case='accepted_drop', **changes):
        args = {'helper_exit':0,'helper_stdout':json.dumps(self.helper),'records':[self.row],
                'received':[],'fixture_path':self.path,'expected_origin':self.origin,'expected_pid':self.pid}
        args.update(changes)
        return drop_case_passed(case,**args)

    def test_retained_real_no_handler_case_meets_corrected_product_trigger(self):
        # Preserve the earlier failure and reevaluate only its observation.
        path = ROOT/'evidence/owned-browser-native-drop-88b8c026b4884e7da9f6638f7f01bb50.json'
        original = path.read_bytes()
        result = json.loads(original)
        case = result['cases'][0]
        self.assertFalse(result['passed'])
        self.assertEqual(case['page_received'],[])
        self.assertEqual(case['native_status']['count'],1)
        self.assertTrue(drop_case_passed(case['case'],case['helper_exit'],case['helper_stdout'],
            case['records'],case['page_received'],fixture_path=case['records'][0]['path'],
            expected_origin=case['expected_origin'],expected_pid=result['peer']['pid']))
        self.assertEqual(path.read_bytes(),original)
        self.assertFalse(DROP_RECORDING_CONTRACT['network_completion_required'])
        self.assertFalse(DROP_RECORDING_CONTRACT['final_submit_required'])

    def test_native_drop_does_not_require_page_read_or_attachment_handler(self):
        for case in ('accepted_drop','default_navigation_control'):
            with self.subTest(case=case):self.assertTrue(self.check(case))

    def test_cancel_after_drop_keeps_original_record_but_pre_drop_cancel_has_none(self):
        original = copy.deepcopy(self.row)
        self.assertTrue(self.check('accepted_then_removed',removal_preserved=True))
        self.assertEqual(self.row,original)
        self.assertFalse(self.check('accepted_then_removed',removal_preserved=False))
        cancelled = {**self.helper,'hresult':262401,'effect':0}
        args = {'helper_stdout':json.dumps(cancelled),'records':[]}
        self.assertTrue(self.check('cancel_before_drop',**args))
        self.assertFalse(self.check('cancel_before_drop',**{**args,'records':[self.row]}))
        self.assertFalse(self.check(helper_stdout=json.dumps(cancelled)))

    def test_no_native_acceptance_or_wrong_path_site_pid_cannot_pass(self):
        for change in ({'path':r'C:\Owned\other.txt'},{'origin':'https://other.example.test'},
                       {'process_id':101},{'file_count':2},{'file_index':1}):
            with self.subTest(change=change):
                self.assertFalse(self.check(records=[{**self.row,**change}]))
        for change in ({'hresult':0},{'effect':0},{'effect':8},{'target_pid':101},
                       {'scope':'file_read'},{'hresult':True}):
            with self.subTest(change=change):
                self.assertFalse(self.check(helper_stdout=json.dumps({**self.helper,**change})))
        self.assertFalse(self.check(records=[]))
        self.assertFalse(self.check(helper_exit=12))
        self.assertFalse(self.check(helper_stdout='{}'))

    def test_restored_receiver_still_accepts_file_without_new_capture(self):
        self.assertTrue(self.check('restored_receiver',restored=True,records=[],received=['fixture.txt']))
        self.assertFalse(self.check('restored_receiver',restored=False,records=[],received=['fixture.txt']))
        self.assertFalse(self.check('restored_receiver',restored=True,received=['fixture.txt']))


if __name__=='__main__':unittest.main()
