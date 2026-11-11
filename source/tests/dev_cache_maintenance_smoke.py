"""Real owned NTFS rename/ACL/hash tests, no installed task or company data."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.native_installer import Windows
from guarddesk.windows_controls import is_admin
from tools import maintain_dev_cache_20261029 as tool


@unittest.skipUnless(os.name=='nt' and is_admin(),'Owned protected NTFS test requires approved admin')
class OwnedArchiveTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='dev-archive-test-',dir=ROOT/'runtime')
        self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name)
        assert self.base.resolve().parent==(ROOT/'runtime').resolve()
        self.win=Windows();self.win.protect(self.base)
        self.data=self.base/'data';self.program=self.base/'program';self.updates=self.data/'updates'
        for p in (self.data,self.program,self.updates):self.win.protect(p,create=True)
        self.payloads={tool.OLD_JOB:b'owned-old-ZIP',tool.JOB:b'owned-new-ZIP'}
        self.pins={job:(len(raw),hashlib.sha256(raw).hexdigest()) for job,raw in self.payloads.items()}
        self.patcher=patch.object(tool,'PINS',self.pins);self.patcher.start();self.addCleanup(self.patcher.stop)
        self.write(self.data/'config.json',{'device_id':tool.DID,'token':'owned-private-preserve'})
        self.write(self.data/'install-transaction.json',{'phase':'complete'})
        self.write(self.updates/'transaction-native.json',{'phase':'downloading','old_version':'0.4.64','target':'0.4.66',
                  'job':{'id':tool.JOB,'release_id':self.pins[tool.JOB][1]}})
        self.write(self.updates/'updater-refresh.json',{'phase':'healthy','reported':True,'target':'0.4.60',
                  'job_id':'22900d93ff9a78d48b1669875d53f952'})
        for job,raw in self.payloads.items():
            p=self.updates/job;self.win.protect(p,create=True)
            (p/'package.zip').write_bytes(raw);self.win.protect(p/'package.zip')
        owner=self
        class Fixture(tool.WindowsPlatform):
            stopped_count=0;restarted=0;fail_second=False;bad_budget=False;bad_health=False;change_state=False
            def check_task(self):pass  # No task is created, queried or ended.
            @contextmanager
            def stopped(self):
                self.stopped_count+=1
                try:
                    if self.change_state:owner.write(owner.updates/'transaction-native.json',{'phase':'switching'})
                    yield
                finally:self.restarted+=1
            def move(self,source,destination):
                if self.fail_second and source.parent==owner.updates and source.name==tool.JOB:raise OSError('Owned injected second-move failure')
                super().move(source,destination)
            def usage(self):return {'program':{'bytes':tool.CAP if self.bad_budget else 1000},'updates':{'bytes':1000}}
            def healthy(self):return not self.bad_health
        self.platform=Fixture(self.program,self.data,self.base/'RepairArchive'/tool.DID)
        self.original=tool.unchanged_files(self.data)

    def write(self,p,body):
        p.write_text(json.dumps(body),encoding='utf-8');self.win.protect(p)

    def test_check_only_no_archive_stop_or_content_changes(self):
        result=tool.maintain(self.platform)
        self.assertEqual(result['result'],'CHECKED');self.assertFalse(self.platform.archive_parent.exists())
        self.assertEqual(self.platform.stopped_count,0);self.assertEqual(tool.unchanged_files(self.data),self.original)

    def test_real_ntfs_archive_preserves_inode_hash_owner_dacl_and_json(self):
        result=tool.maintain(self.platform,True,True);archive=Path(result['archive'])
        self.assertEqual(result['result'],'READY_FOR_FRESH_JOB');self.assertTrue(result['fresh_broker_health'])
        self.assertEqual(self.platform.stopped_count,1);self.assertEqual(self.platform.restarted,1)
        self.assertEqual(tool.unchanged_files(self.data),self.original)
        for job in tool.PINS:
            self.assertFalse((self.updates/job).exists())
            self.assertEqual(self.platform.snapshot(archive/job),result['sources'][job])

    def test_apply_without_center_attestation_is_refused_before_stop(self):
        with self.assertRaises(ValueError):tool.maintain(self.platform,True,False)
        self.assertEqual(self.platform.stopped_count,0)

    def test_changed_state_after_stop_aborts_and_restarts_without_move(self):
        self.platform.change_state=True
        with self.assertRaises(ValueError):tool.maintain(self.platform,True,True)
        self.assertEqual(self.platform.restarted,1);self.assertFalse(self.platform.archive_parent.exists())
        self.assertTrue(all((self.updates/j/'package.zip').exists() for j in tool.PINS))

    def test_second_move_failure_restores_first_without_overwrite(self):
        self.platform.fail_second=True
        before={j:self.platform.snapshot(self.updates/j) for j in tool.PINS}
        with self.assertRaises(OSError):tool.maintain(self.platform,True,True)
        self.assertEqual(before,{j:self.platform.snapshot(self.updates/j) for j in tool.PINS})
        self.assertEqual(tool.unchanged_files(self.data),self.original);self.assertEqual(self.platform.restarted,1)

    def test_budget_failure_after_moves_restores_both(self):
        self.platform.bad_budget=True
        with self.assertRaises(ValueError):tool.maintain(self.platform,True,True)
        self.assertTrue(all((self.updates/j/'package.zip').exists() for j in tool.PINS))
        self.assertEqual(tool.unchanged_files(self.data),self.original);self.assertEqual(self.platform.restarted,1)

    def test_bad_health_never_claims_ready(self):
        self.platform.bad_health=True
        result=tool.maintain(self.platform,True,True)
        self.assertEqual(result['result'],'ARCHIVED_REVIEW_HEALTH')

    def test_extra_source_file_or_bad_package_refused_before_stop(self):
        (self.updates/tool.OLD_JOB/'unexpected').write_text('owned')
        with self.assertRaises(ValueError):tool.maintain(self.platform,True,True)
        self.assertEqual(self.platform.stopped_count,0)

    def test_move_boundary_rejects_wrong_source_destination_and_existing_target(self):
        archive=self.platform.create_archive();source=self.updates/tool.JOB
        with self.assertRaises(ValueError):tool.validate_move(source,archive/'wrong',self.updates,archive)
        with self.assertRaises(ValueError):tool.validate_move(self.updates/'wrong',archive/tool.JOB,self.updates,archive)
        self.win.protect(archive/tool.JOB,create=True)
        with self.assertRaises(FileExistsError):tool.validate_move(source,archive/tool.JOB,self.updates,archive)


def main():
    import time
    started=time.monotonic();suite=unittest.defaultTestLoader.loadTestsFromTestCase(OwnedArchiveTest)
    log=ROOT/'runtime'/('dev-cache-tests-'+str(os.getpid())+'.log')
    with log.open('x',encoding='utf-8') as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    proof=dict(passed=result.wasSuccessful() and not result.skipped,tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),
               skipped=result.skipped,seconds=time.monotonic()-started,log=str(log.relative_to(ROOT)),
               scope='Owned protected NTFS fixtures; fixed production task and installed data never touched',company_changed=False,
               source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),ROOT/'tools/maintain_dev_cache_20261029.py']})
    path=ROOT/'evidence/maintenance'/('dev-cache-tests-'+str(os.getpid())+'.json')
    path.write_text(json.dumps(proof,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(proof),flush=True)
    return 0 if proof['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
