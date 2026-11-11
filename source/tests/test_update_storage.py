"""Owned NTFS budgets, terminal cache retention and failures before stopping."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import test_updates
from tools.reproduce_native_budget_failure import sparse
from guarddesk import update_cache,update_storage
from guarddesk.update_client import Transaction,save,storage_budget,RetryUpdate


class StorageBudgetTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_observed_DEV_retained_working_set_and_incoming_fit_new_separate_budget(self):
        sparse(self.root/'retained.bin',383895008+110556142)
        value=storage_budget([self.root],85922867)
        self.assertEqual(value['projected_bytes'],580374017)
        self.assertEqual(value['used_bytes'],494451150)
        self.assertGreater(value['limit_bytes'],value['projected_bytes'])

    def test_workspace_entry_space_and_package_limits_remain_enforced(self):
        sparse(self.root/'large.bin',update_storage.MAX_WORKING_BYTES)
        with self.assertRaises(update_storage.CapacityError) as error:storage_budget([self.root],1)
        self.assertEqual(error.exception.code,'working_set_limit')
        sparse(self.root/'large.bin',1)
        with patch.object(update_storage,'MAX_ENTRIES',0),self.assertRaises(update_storage.CapacityError) as error:storage_budget([self.root],1)
        self.assertEqual(error.exception.code,'entry_limit')
        with patch.object(update_storage.shutil,'disk_usage',return_value=SimpleNamespace(free=1)),self.assertRaises(update_storage.CapacityError) as error:storage_budget([self.root],1)
        self.assertEqual(error.exception.code,'disk_space')
        with self.assertRaises(ValueError):storage_budget([self.root],512*1024*1024+1)
        with self.assertRaises(ValueError):storage_budget([self.root],-1)

    def test_overlapping_roots_are_not_double_counted(self):
        nested=self.root/'nested';nested.mkdir();(nested/'data').write_bytes(b'abc')
        self.assertEqual(storage_budget([self.root,nested],0)['used_bytes'],3)

    def test_receipted_cache_keeps_current_and_latest_terminal_unknown_legacy_untouched(self):
        for i in range(5):
            directory=self.root/(str(i)*32);directory.mkdir();(directory/'package.zip').write_bytes(b'owned')
            value={'job':{'id':directory.name,'created':i,'release_id':hashlib.sha256(b'owned').hexdigest()},'phase':'failed'}
            update_cache.record(self.root,value,save)
        unknown=self.root/('f'*32);unknown.mkdir();(unknown/'package.zip').write_bytes(b'legacy')
        self.assertEqual(update_cache.prune(self.root,'4'*32),3)
        self.assertTrue((self.root/('3'*32)).exists());self.assertTrue((self.root/('4'*32)).exists());self.assertTrue(unknown.exists())

    def test_cache_tamper_unexpected_files_and_nan_never_authorize_deletion(self):
        for i in range(2):
            directory=self.root/(str(i)*32);directory.mkdir();(directory/'package.zip').write_bytes(b'owned')
            update_cache.record(self.root,{'job':{'id':directory.name,'created':i,'release_id':'0'*64},'phase':'failed'},save)
        with self.assertRaises(ValueError):update_cache.prune(self.root,'2'*32)
        old=self.root/('0'*32);self.assertTrue(old.exists());(old/'keep.txt').write_text('preserve')
        self.assertEqual(update_cache.prune(self.root,'2'*32),0)
        receipt=self.root/('1'*32)/update_cache.RECEIPT;body=json.loads(receipt.read_text());body['created']=float('nan');receipt.write_text(json.dumps(body))
        with self.assertRaises(ValueError):update_cache.prune(self.root,'2'*32)


class StorageTransactionTest(unittest.TestCase):
    setUp=test_updates.UpdateTransactionTest.setUp

    def test_lost_completion_ACK_recovery_creates_receipt_once_without_restarting(self):
        adapter=test_updates.Adapter(self.root);tx=Transaction(self.agent,'main',adapter);original=self.agent.call
        def offline(path,body):
            if body.get('state')=='healthy':raise ConnectionError('owned lost ACK')
            return original(path,body)
        self.agent.call=offline
        with self.assertRaises(ConnectionError):tx.apply(self.envelope)
        self.assertFalse(json.loads(tx.journal.read_text())['reported'])
        self.agent.call=original;tx.recover()
        receipt=tx.root/self.payload['id']/update_cache.RECEIPT
        self.assertTrue(receipt.is_file());before=receipt.stat().st_mtime_ns
        tx.recover();self.assertEqual(receipt.stat().st_mtime_ns,before)
        self.assertEqual(adapter.stops,1)

    def test_capacity_failure_has_precise_safe_terminal_record_and_never_stops(self):
        adapter=test_updates.Adapter(self.root);adapter.budget=lambda incoming:(_ for _ in ()).throw(update_storage.CapacityError('working_set_limit',4*1024**3,incoming))
        tx=Transaction(self.agent,'native',adapter)
        with self.assertRaises(update_storage.CapacityError):tx.apply(self.envelope)
        state=json.loads(tx.journal.read_text(encoding='utf-8'))
        self.assertEqual(state['phase'],'failed');self.assertEqual(state['failure']['stage'],'capacity')
        self.assertEqual(state['failure']['code'],'working_set_limit');self.assertEqual(adapter.stops,0)
        self.assertIn('3072 MiB',state['error']);self.assertNotIn('已回復',state['error'])
        self.assertTrue((tx.root/'last-update-failure-native.json').is_file())

    def test_retryable_network_interruption_keeps_waiting_path_and_does_not_stop(self):
        adapter=test_updates.Adapter(self.root);tx=Transaction(self.agent,'native',adapter)
        with patch('guarddesk.update_client.download',side_effect=RetryUpdate('temporary')),self.assertRaises(RetryUpdate):tx.apply(self.envelope)
        self.assertEqual(json.loads(tx.journal.read_text())['phase'],'downloading');self.assertEqual(adapter.stops,0)

    def test_12_sequential_signed_updates_keep_cache_and_latest_recovery_bounded(self):
        # Shared transaction/cache logic with a user-owned filesystem. The
        # native ACL rejection remains covered separately; this is not SYSTEM.
        adapter=test_updates.Adapter(self.root);tx=Transaction(self.agent,'main',adapter)
        for i in range(12):
            version=f'0.4.{20+i}';manifest={**test_updates.packages.verify(self.payload['release'],self.agent.config['update_key']),'version':version}
            payload={**self.payload,'id':f'{i:032x}','created':time.time()+i/1000,'release':test_updates.packages.sign(self.private,manifest)}
            adapter.probe=lambda path,version=version:version
            tx.apply(test_updates.packages.sign(self.private,payload))
            directories=[p for p in tx.root.iterdir() if p.is_dir()]
            self.assertEqual(len(directories),1);self.assertEqual(adapter.value,version)
        self.assertEqual(adapter.stops,12)
