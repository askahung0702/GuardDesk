"""Signed owned fixtures and actual NTFS cohort renames/rollback, no install.

The real ACL reader allows only this fixture owner's SID in addition to SYSTEM
and Administrators. Task/process/health boundaries are explicit local fixtures;
this does not establish old frozen updater or SYSTEM/field acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

from guarddesk.agent import Agent
from guarddesk import update_packages as packages
from guarddesk import update_native
from guarddesk.update_client import Transaction
from guarddesk.server_setup import secure_directory
from test_updates import release
from guarddesk.remote_components import REMOTE_FILES,COHORT_MANIFEST,cohort_manifest


def tree_hashes(root):
    return {p.relative_to(root).as_posix():packages.file_hash(p) for p in root.rglob('*') if p.is_file()}


class OwnedAdapter(update_native.NativeAdapter):
    def __init__(self,program,agent,cohorts):
        self.program=program;self.native=program/'USBControl';self.agent=agent
        self.cohorts=cohorts;self.stops=0;self.starts=0;self.fail_target=None
    def current(self):return self.probe(self.native)
    def probe(self,path):return json.loads((path/'_internal/remote/cohort-version.json').read_text())['version']
    def stop(self):self.stops+=1 # no installed process, mutex or scheduled task
    def start(self,state,rollback):self.starts+=1 # never execute fixture bytes
    def health(self,version,started,timeout):
        return version!=self.fail_target and self.native.exists() and tree_hashes(self.native)==self.cohorts[version]


@unittest.skipUnless(os.name=='nt','Actual Windows ACL and directory rename fixtures')
class CohortRolloutTest(unittest.TestCase):
    def setUp(self):
        workspace=Path(__file__).resolve().parents[3];runtime=workspace/'runtime'
        self.temp=tempfile.TemporaryDirectory(prefix='remote-cohort-owned-',dir=runtime)
        self.root=Path(self.temp.name).resolve()
        if not self.root.is_relative_to(runtime.resolve()):raise RuntimeError('Owned cleanup scope escaped workspace')
        self.addCleanup(self.temp.cleanup)
        self.program=secure_directory(self.root/'owned-program')
        state=secure_directory(self.root/'owned-state');config=state/'config.json'
        self.private=packages.signer(self.root);key=packages.public_key(self.private)
        config.write_text(json.dumps({'server':'http://127.0.0.1:1','device_id':'a'*24,'token':'owned-test-only',
            'watch':str(state),'update_key':key}))
        self.agent=Agent(config);self.agent.queue('file.created',{'owned_fixture':True})
        self.original=config.read_bytes();self.reports=[]
        self.agent.call=lambda path,body:self.reports.append(body) or {'ok':True}
        self.cohorts={};self.number=0
        native=self.program/'USBControl';native.mkdir()
        for name,value in self.contents('0.4.11').items():
            path=native/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value)
        self.cohorts['0.4.11']=tree_hashes(native)
        self.adapter=OwnedAdapter(self.program,self.agent,self.cohorts)
        self.tx=Transaction(self.agent,'native',self.adapter)
        actual_guard=update_native.protected_tree
        def owned_guard(path,allow_current_user=False,recursive=True):
            if not Path(path).resolve().is_relative_to(self.root):raise AssertionError('ACL fixture escaped owned root')
            return actual_guard(path,allow_current_user=True,recursive=recursive)
        guard=patch.object(update_native,'protected_tree',side_effect=owned_guard);guard.start();self.addCleanup(guard.stop)
        download=patch('guarddesk.update_client.download',side_effect=lambda agent,job,manifest,target:shutil.copyfile(self.archive,target))
        download.start();self.addCleanup(download.stop)
    def contents(self,version):
        result={name:f'owned non-executable fixture {name} {version}'.encode() for name in (
            'GuardDesk.exe','GuardDeskAgent.exe','_internal/runtime.dll',
            '_internal/remote/GuardDeskRemoteWorker.exe','_internal/remote/GuardDeskRemoteMedia.exe',
            '_internal/remote/GuardDeskRemoteBridge.dll',
            '_internal/remote/GuardDeskMisNative.dll',
            '_internal/remote/codec-runtime.dll')}
        result['_internal/remote/cohort-version.json']=json.dumps({'version':version}).encode()
        hashes={name:hashlib.sha256(result['_internal/remote/'+name]).hexdigest() for name in REMOTE_FILES}
        result['_internal/remote/'+COHORT_MANIFEST]=json.dumps(cohort_manifest(hashes,build_id='c'*64)).encode()
        return result
    def job(self,version='0.4.12'):
        self.number+=1;contents=self.contents(version)
        self.cohorts[version]={name:hashlib.sha256(value).hexdigest() for name,value in contents.items()}
        original=release(self.root/f'owned-release-{self.number}.zip',version,
            {'GuardDesk/'+name:value for name,value in contents.items()})
        repository=self.root/f'import-{self.number}';repository.mkdir()
        manifest,self.archive=packages.import_release(original,repository)
        created=time.time();job={'id':f'{self.number:032x}','device_id':'a'*24,'release_id':manifest['sha256'],
            'created':created,'not_before':created,'expires':created+86400,'allow_downgrade':0,
            'release':packages.sign(self.private,manifest)}
        return packages.sign(self.private,job),job,manifest
    def unchanged_identity_queue(self):
        self.assertEqual(self.agent.config_path.read_bytes(),self.original)
        self.assertEqual(self.agent.queue_status()['pending'],1)
    def test_signed_cohort_switch_removes_transaction_old_version_after_health(self):
        envelope,job,_=self.job();self.tx.apply(envelope)
        self.assertEqual(tree_hashes(self.adapter.native),self.cohorts['0.4.12'])
        backup=self.program/('USBControl.rollback-'+job['id'])
        self.assertFalse(backup.exists())
        self.assertEqual(self.adapter.stops,1);self.assertEqual(self.adapter.starts,1)
        self.unchanged_identity_queue()
    def test_old_version_cleanup_is_refused_before_health_confirmation(self):
        _,job,_=self.job()
        backup=self.program/('USBControl.rollback-'+job['id']);backup.mkdir()
        (backup/'keep').write_bytes(b'OWNED OLD VERSION')
        with self.assertRaisesRegex(OSError,'更新未確認成功'):
            self.adapter.cleanup({'phase':'switching','job':job})
        self.assertEqual((backup/'keep').read_bytes(),b'OWNED OLD VERSION')
    def test_failed_health_rolls_back_whole_cohort_then_next_upgrade_succeeds(self):
        envelope,job,_=self.job();self.adapter.fail_target='0.4.12';self.tx.apply(envelope)
        self.assertEqual(json.loads(self.tx.journal.read_text(encoding='utf-8'))['phase'],'rolled_back')
        self.assertEqual(tree_hashes(self.adapter.native),self.cohorts['0.4.11'])
        failed=self.program/('USBControl.failed-'+job['id'])
        self.assertEqual(tree_hashes(failed),self.cohorts['0.4.12'])
        envelope,_,_=self.job('0.4.13');self.tx.apply(envelope)
        self.assertEqual(json.loads(self.tx.journal.read_text(encoding='utf-8'))['phase'],'healthy')
        self.assertEqual(tree_hashes(self.adapter.native),self.cohorts['0.4.13'])
        self.unchanged_identity_queue()
    def test_cached_stage_missing_media_is_rejected_before_stopping(self):
        envelope,job,manifest=self.job();stage=self.adapter.stage(job)
        packages.extract(self.archive,manifest,stage)
        (stage/'_internal/remote/GuardDeskRemoteMedia.exe').unlink()
        with self.assertRaises(ValueError):self.tx.apply(envelope)
        self.assertEqual(self.adapter.stops,0)
        self.assertEqual(tree_hashes(self.adapter.native),self.cohorts['0.4.11'])
        self.assertEqual(json.loads(self.tx.journal.read_text(encoding='utf-8'))['failure']['stage'],'verify')
        self.unchanged_identity_queue()
    def test_second_rename_failure_restores_every_old_file_and_preserves_stage(self):
        envelope,job,_=self.job();stage=self.adapter.stage(job);actual=Path.rename
        def rename(path,target):
            if path==stage:raise OSError('Owned injected second directory switch failure')
            return actual(path,target)
        with patch.object(Path,'rename',rename):self.tx.apply(envelope)
        self.assertEqual(json.loads(self.tx.journal.read_text(encoding='utf-8'))['phase'],'rolled_back')
        self.assertEqual(tree_hashes(self.adapter.native),self.cohorts['0.4.11'])
        self.assertEqual(tree_hashes(stage),self.cohorts['0.4.12'])
        self.unchanged_identity_queue()


if __name__=='__main__':unittest.main()
