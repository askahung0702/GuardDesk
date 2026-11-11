"""A failed capacity scan is not an active directory switch; no journal reset."""
import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from guarddesk.native_installer import assert_quiescent
from guarddesk.update_client import save
from guarddesk.transaction_status import JournalStateError


class CapacityRepairGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.updates=self.root/'updates';self.updates.mkdir()
        self.path=self.updates/'transaction-native.json';self.failure=self.updates/'last-update-failure-native.json'
        self.detail={'code':'scan_timeout','incoming_bytes':74507311,'limit_bytes':3221225472,
            'stage':'capacity','type':'OSError','used_bytes':113846082}
        self.record={'job':{'id':'5b50231242922366ae9b2a3173da4e3b'},'phase':'failed','reported':True,
            'old_version':'0.4.99','target':'0.4.100','version':'0.4.99','failure':self.detail,
            'manifest_fixture':'x'*150000}
        self.latest={'failure':self.detail,'job_id':self.record['job']['id'],'target':'0.4.100','time':1794195035.388333}
        self.write()
    def write(self):
        save(self.path,self.record);self.failure.write_text(json.dumps(self.latest))
    def test_exact_reported_timeout_is_quiescent_without_changing_evidence(self):
        before={p.name:p.read_bytes() for p in self.updates.iterdir()}
        assert_quiescent(self.root)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.updates.iterdir()})
    def test_no_failure_file_or_unacknowledged_failure_does_not_authorize_repair(self):
        self.failure.unlink()
        with self.assertRaises(JournalStateError):assert_quiescent(self.root)
        self.record['reported']=False;self.write()
        with self.assertRaises(JournalStateError):assert_quiescent(self.root)
    def test_active_or_switch_failure_and_other_failure_code_remain_blocked(self):
        for phase,stage,code in [('switching','capacity','scan_timeout'),('failed','switching','scan_timeout'),
                ('failed','capacity','disk_space'),('failed','preflight','scan_timeout')]:
            self.record.update(phase=phase,failure={**self.detail,'stage':stage,'code':code});self.latest['failure']=self.record['failure'];self.write()
            with self.subTest(phase=phase,stage=stage,code=code),self.assertRaises(JournalStateError):assert_quiescent(self.root)
    def test_mismatching_job_or_target_or_versions_and_stage_remain_blocked(self):
        original=copy.deepcopy(self.record)
        for key,value in [('version','0.4.100'),('old_version','invalid'),('target','invalid'),('stage','owned-stage')]:
            self.record={**copy.deepcopy(original),key:value};self.write()
            with self.subTest(key=key),self.assertRaises(JournalStateError):assert_quiescent(self.root)
        self.record=original
        for key,value in [('job_id','b'*32),('target','0.4.101')]:
            prior=self.latest[key];self.latest[key]=value;self.write()
            with self.subTest(key=key),self.assertRaises(JournalStateError):assert_quiescent(self.root)
            self.latest[key]=prior
    def test_changed_fingerprint_oversized_record_or_refresh_failure_is_rejected(self):
        from guarddesk import transaction_status
        original=transaction_status.fingerprint;counts={}
        def fingerprint(path):
            result=original(path);counts[str(path)]=counts.get(str(path),0)+1
            if Path(path)==self.failure and counts[str(path)]>1:return [1,2,3,4,5]
            return result
        with patch.object(transaction_status,'fingerprint',side_effect=fingerprint):
            with self.assertRaises(JournalStateError):assert_quiescent(self.root)
        self.record['manifest_fixture']='x'*(4*1024*1024);self.write()
        with self.assertRaises(JournalStateError):assert_quiescent(self.root)
        self.path.unlink();self.path.with_name(self.path.name+'.state.json').unlink()
        save(self.updates/'updater-refresh.json',{'phase':'failed'})
        with self.assertRaises(JournalStateError):assert_quiescent(self.root)
