"""Real document thread, exact sealed73 --once failure, new runtime handoff."""
import copy
import io
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
import unittest
from contextlib import ExitStack,redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch
from guarddesk.application_control import ExtendedWorker
from guarddesk.document_worker import DocumentWorker
from guarddesk.policy import DEFAULT_POLICY
from guarddesk import __main__ as cli


class InitialPolicyLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.agent=SimpleNamespace(config_path=self.root/'config.json',custom_packet=None)
        self.entered=threading.Event();self.release=threading.Event();self.created=[];self.reports=[]
        self.real_start=DocumentWorker.start
    def tearDown(self):
        self.release.set()
        for worker in self.created:
            if worker.thread:worker.thread.join(5)
        self.temp.cleanup()
    def blocked_cycle(self,worker):self.entered.set();self.release.wait(30)
    def start(self,worker):self.created.append(worker);return self.real_start(worker)
    def source_module(self,name):
        from PyInstaller.archive.readers import CArchiveReader
        repository=Path(os.environ.get('GUARDDESK_REPOSITORY_ROOT',Path(__file__).resolve().parents[1]))
        exe=repository/'runtime/center73-src/dist/GuardDesk/GuardDesk.exe'
        module=types.ModuleType('guarddesk.owned73_'+name);module.__package__='guarddesk'
        exec(CArchiveReader(str(exe)).open_embedded_archive('PYZ.pyz').extract('guarddesk.'+name),module.__dict__)
        return module
    def run_once(self,entry,worker_type,failed=False):
        class Usb:
            def __init__(child,config):child.agent=self.agent
            def cycle(child,require_online):self.assertTrue(require_online);return {'status':'configured'}
        def configure(worker):
            worker.policy=copy.deepcopy(DEFAULT_POLICY);worker.configure_documents()
            if worker.documents and worker.documents.thread:self.assertTrue(self.entered.wait(2))
            self.reports.append(worker.documents.status() if worker.documents else None)
            return {'status':'configured'}
        with ExitStack() as stack:
            stack.enter_context(patch('guarddesk.native_usb.UsbWorker',Usb))
            stack.enter_context(patch('guarddesk.application_control.ExtendedWorker',worker_type))
            stack.enter_context(patch.object(worker_type,'configure',configure))
            stack.enter_context(patch('guarddesk.custom_client.load_custom'))
            stack.enter_context(patch.object(DocumentWorker,'cycle',lambda worker:self.blocked_cycle(worker)))
            stack.enter_context(patch.object(DocumentWorker,'start',lambda worker:self.start(worker)))
            stack.enter_context(patch('signal.signal'))
            stack.enter_context(patch.object(sys,'argv',['GuardDesk.exe','usb-worker','--extended','--config',str(self.agent.config_path),'--once']))
            stack.enter_context(redirect_stdout(io.StringIO()))
            if failed:
                with self.assertRaisesRegex(OSError,'Document audit is still stopping'):entry.main()
            else:entry.main()

    def test_exact_sealed73_once_starts_and_times_out_real_thread(self):
        old_cli=self.source_module('__main__');old_control=self.source_module('application_control')
        started=time.monotonic()
        self.run_once(old_cli,old_control.ExtendedWorker,failed=True)
        self.assertGreaterEqual(time.monotonic()-started,7.5)
        self.assertEqual(len(self.created),1);self.assertTrue(self.created[0].thread.is_alive())

    def test_new_once_does_not_start_trace_or_context_thread_and_reports_pending(self):
        with patch('guarddesk.document_io.NativeTrace',side_effect=AssertionError('one-shot ETW forbidden')),patch('guarddesk.document_context.launch',side_effect=AssertionError('one-shot session helper forbidden')):
            self.run_once(cli,ExtendedWorker)
        self.assertFalse(self.entered.is_set());self.assertEqual(self.created,[])
        self.assertEqual(self.reports[0]['provisioning']['status'],'waiting_persistent_worker')
        self.assertEqual(self.reports[0]['read']['status'],'waiting_persistent_worker')
        self.assertFalse(self.reports[0]['applied']);self.assertIsNone(self.reports[0]['fingerprint'])

    def test_normal_persistent_worker_still_starts_once_and_can_close(self):
        worker=ExtendedWorker(self.agent);worker.policy=copy.deepcopy(DEFAULT_POLICY)
        with patch('guarddesk.custom_client.load_custom'),patch.object(DocumentWorker,'cycle',lambda worker:self.blocked_cycle(worker)),patch.object(DocumentWorker,'start',lambda child:self.start(child)):
            worker.configure_documents();worker.configure_documents()
            self.assertTrue(self.entered.wait(2));self.assertEqual(len(self.created),1)
            self.assertIs(worker.documents.policy,worker.policy)
            self.release.set();worker.close();self.assertFalse(worker.documents.thread.is_alive())

    def test_one_shot_keeps_sacl_restore_pending_without_touching_ledger(self):
        worker=ExtendedWorker(self.agent,start_documents=False);worker.policy=copy.deepcopy(DEFAULT_POLICY)
        worker.policy['file_audit']['enabled']=False
        ledger=worker.directory/'document-sacl.sqlite3';ledger.write_bytes(b'OWNED LEDGER PRESERVE')
        with patch('guarddesk.custom_client.load_custom'),patch('guarddesk.document_sacl.Manager',side_effect=AssertionError('no transient SACL manager')):
            worker.configure_documents();worker.close()
        self.assertIsNone(worker.documents.thread);self.assertFalse(worker.documents.status()['applied'])
        self.assertEqual(ledger.read_bytes(),b'OWNED LEDGER PRESERVE')

    def test_disabled_policy_without_rules_or_ledger_needs_no_worker(self):
        worker=ExtendedWorker(self.agent,start_documents=False);worker.policy=copy.deepcopy(DEFAULT_POLICY);worker.policy['file_audit']['enabled']=False
        with patch('guarddesk.custom_client.load_custom'),patch('guarddesk.document_worker.DocumentWorker',side_effect=AssertionError('disabled')):
            worker.configure_documents();worker.close()
        self.assertIsNone(worker.documents)

    def test_restore_and_real_runtime_keep_refusing_live_stopping_thread(self):
        worker=DocumentWorker(self.agent,self.root)
        with patch.object(worker,'close',side_effect=OSError('Document audit is still stopping')),patch.object(worker,'verify_installation') as verify:
            with self.assertRaisesRegex(OSError,'still stopping'):worker.restore()
            verify.assert_not_called()


if __name__=='__main__':unittest.main()
